"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NetworkManager = void 0;
const command_runner_1 = require("../../node-agent/command-runner");
const middleware_1 = require("../../security/middleware");
const RESERVED_SYSTEM_PORTS = new Set([22, 53, 67, 68, 80, 443, 3000, 5055]);
class NetworkManager {
    db;
    constructor(db) {
        this.db = db;
    }
    // --- Network Pools & IP Allocations ---
    async listNetworkPools(nodeId) {
        const sql = nodeId !== undefined
            ? `SELECT p.*, n.name AS node_name FROM network_pools p LEFT JOIN nodes n ON n.id = p.node_id WHERE p.node_id = ? ORDER BY p.id ASC`
            : `SELECT p.*, n.name AS node_name FROM network_pools p LEFT JOIN nodes n ON n.id = p.node_id ORDER BY p.id ASC`;
        return this.db.all(sql, nodeId !== undefined ? [nodeId] : []);
    }
    async createNetworkPool(input) {
        const safeBridge = middleware_1.SafeValidators.bridgeOrIface(input.bridgeName);
        const ins = await this.db.run(`INSERT INTO network_pools
         (node_id, name, network_type, bridge_name, cidr, gateway, ipv6_cidr, ipv6_gateway, vlan_id, dns_servers, enabled)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`, [
            input.nodeId,
            input.name.trim(),
            input.networkType,
            safeBridge,
            input.cidr?.trim() || null,
            input.gateway ? middleware_1.SafeValidators.ipv4(input.gateway) : null,
            input.ipv6Cidr ? middleware_1.SafeValidators.ipv6OrCidr(input.ipv6Cidr) : null,
            input.ipv6Gateway ? middleware_1.SafeValidators.ipv6OrCidr(input.ipv6Gateway) : null,
            input.vlanId ? Number(input.vlanId) : null,
            JSON.stringify(input.dnsServers || ['1.1.1.1', '8.8.8.8']),
        ]);
        return this.db.get(`SELECT * FROM network_pools WHERE id = ?`, [ins.lastID]);
    }
    async addIpAddressesToPool(poolId, addresses) {
        let added = 0;
        await this.db.transaction(async () => {
            for (const item of addresses) {
                const ver = item.version || (item.ip.includes(':') ? 6 : 4);
                const cleanIp = ver === 6 ? middleware_1.SafeValidators.ipv6OrCidr(item.ip) : middleware_1.SafeValidators.ipv4(item.ip);
                const res = await this.db.run(`INSERT OR IGNORE INTO ip_allocations (pool_id, ip_address, version, status)
           VALUES (?, ?, ?, 'available')`, [poolId, cleanIp, ver]);
                if (res.changes > 0)
                    added++;
            }
        });
        return added;
    }
    async listIpAllocations(poolId) {
        if (poolId !== undefined) {
            return this.db.all(`SELECT a.*, p.name AS pool_name FROM ip_allocations a LEFT JOIN network_pools p ON p.id = a.pool_id WHERE a.pool_id = ? ORDER BY a.id ASC`, [poolId]);
        }
        return this.db.all(`SELECT a.*, p.name AS pool_name FROM ip_allocations a LEFT JOIN network_pools p ON p.id = a.pool_id ORDER BY a.id ASC`);
    }
    // --- User Port Allocations & NAT Port Forwarding (iptables / nftables with rollback) ---
    async getUserPortAllocation(userId) {
        const row = await this.db.get(`SELECT * FROM port_allocations WHERE user_id = ?`, [userId]);
        const actualUsed = await this.db.get(`SELECT COUNT(*) AS cnt FROM port_forwards WHERE user_id = ?`, [userId]);
        const used = actualUsed?.cnt || 0;
        const allocated = row?.allocated_ports ?? 10;
        if (!row) {
            await this.db.run(`INSERT OR IGNORE INTO port_allocations (user_id, allocated_ports, used_ports) VALUES (?, ?, ?)`, [userId, allocated, used]);
        }
        else if (row.used_ports !== used) {
            await this.db.run(`UPDATE port_allocations SET used_ports = ? WHERE user_id = ?`, [
                used,
                userId,
            ]);
        }
        return { userId, allocatedPorts: allocated, usedPorts: used, remainingPorts: Math.max(0, allocated - used) };
    }
    async setUserPortQuota(userId, allocatedPorts) {
        const quota = Math.max(0, Math.floor(Number(allocatedPorts)));
        const used = await this.db.get(`SELECT COUNT(*) AS cnt FROM port_forwards WHERE user_id = ?`, [userId]);
        await this.db.run(`INSERT INTO port_allocations (user_id, allocated_ports, used_ports, updated_at)
       VALUES (?, ?, ?, datetime('now'))
       ON CONFLICT(user_id) DO UPDATE SET allocated_ports = excluded.allocated_ports, used_ports = excluded.used_ports, updated_at = datetime('now')`, [userId, quota, used?.cnt || 0]);
    }
    async listPortForwards(filter) {
        if (filter?.userId !== undefined) {
            return this.db.all(`SELECT pf.*, u.username FROM port_forwards pf LEFT JOIN users u ON u.id = pf.user_id WHERE pf.user_id = ? ORDER BY pf.id DESC`, [filter.userId]);
        }
        return this.db.all(`SELECT pf.*, u.username FROM port_forwards pf LEFT JOIN users u ON u.id = pf.user_id ORDER BY pf.id DESC`);
    }
    async createPortForward(input) {
        const guestPort = middleware_1.SafeValidators.portNumber(input.guestPort, 1, 65535);
        const guestIp = middleware_1.SafeValidators.ipv4(input.guestIp);
        const protocol = input.protocol || 'tcp,udp';
        if (!input.isAdmin) {
            const quota = await this.getUserPortAllocation(input.userId);
            if (quota.remainingPorts <= 0) {
                throw new Error(`Port allocation limit reached (${quota.usedPorts}/${quota.allocatedPorts} ports used).`);
            }
        }
        let hostPort;
        if (input.hostPort) {
            hostPort = middleware_1.SafeValidators.portNumber(input.hostPort, 1024, 65535);
            if (RESERVED_SYSTEM_PORTS.has(hostPort)) {
                throw new Error(`Host port ${hostPort} is reserved for system services.`);
            }
        }
        else {
            hostPort = await this.findAvailableHostPort(input.nodeId);
        }
        const conflict = await this.db.get(`SELECT id FROM port_forwards WHERE node_id = ? AND host_port = ?`, [input.nodeId, hostPort]);
        if (conflict) {
            throw new Error(`Host port ${hostPort} is already allocated on node #${input.nodeId}.`);
        }
        // Apply real NAT DNAT rules with automatic rollback on failure if host supports iptables
        const appliedKernelRule = await this.applyNatRuleWithRollback('add', guestIp, guestPort, hostPort, protocol);
        const ins = await this.db.run(`INSERT INTO port_forwards
         (user_id, node_id, instance_type, instance_ref_id, container_name, guest_ip, guest_port, host_port, protocol, description, is_custom, created_by_admin)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
            input.userId,
            input.nodeId,
            input.instanceType,
            input.instanceRefId,
            input.containerOrVmName,
            guestIp,
            guestPort,
            hostPort,
            protocol,
            input.description?.slice(0, 200) || '',
            input.hostPort ? 1 : 0,
            input.isAdmin ? 1 : 0,
        ]);
        await this.getUserPortAllocation(input.userId);
        const record = await this.db.get(`SELECT * FROM port_forwards WHERE id = ?`, [ins.lastID]);
        return { portForward: record, kernelNatApplied: appliedKernelRule };
    }
    async deletePortForward(forwardId, actorUserId, isAdmin) {
        const pf = await this.db.get(`SELECT * FROM port_forwards WHERE id = ?`, [forwardId]);
        if (!pf)
            throw new Error('Port forwarding rule not found.');
        if (!isAdmin && pf.user_id !== actorUserId) {
            throw new Error('Not authorized to delete this port forward.');
        }
        if (pf.guest_ip) {
            await this.applyNatRuleWithRollback('remove', pf.guest_ip, pf.guest_port, pf.host_port, pf.protocol || 'tcp,udp').catch(() => undefined);
        }
        await this.db.run(`DELETE FROM port_forwards WHERE id = ?`, [forwardId]);
        await this.getUserPortAllocation(pf.user_id);
    }
    async findAvailableHostPort(nodeId, min = 10000, max = 60000) {
        const usedRows = await this.db.all(`SELECT host_port FROM port_forwards WHERE node_id = ?`, [nodeId]);
        const used = new Set(usedRows.map((r) => r.host_port));
        for (let attempt = 0; attempt < 200; attempt++) {
            const candidate = Math.floor(Math.random() * (max - min + 1)) + min;
            if (!used.has(candidate) && !RESERVED_SYSTEM_PORTS.has(candidate)) {
                return candidate;
            }
        }
        throw new Error('Unable to find a free host port in range 10000-60000.');
    }
    /**
     * Snapshots current `iptables-save` state before mutating NAT rules and restores automatically
     * if any protocol rule fails validation/application.
     */
    async applyNatRuleWithRollback(mode, guestIp, guestPort, hostPort, protocol) {
        if (!(0, command_runner_1.isBinaryAvailable)('iptables'))
            return false;
        const saveRes = await (0, command_runner_1.runAllowlistedCommand)('iptables-save', [], { timeoutMs: 5000 });
        const previousState = saveRes.exitCode === 0 ? saveRes.stdout : null;
        const protos = protocol.includes(',') ? ['tcp', 'udp'] : [protocol];
        const flag = mode === 'add' ? '-A' : '-D';
        try {
            for (const proto of protos) {
                if (proto !== 'tcp' && proto !== 'udp')
                    continue;
                const dnatRes = await (0, command_runner_1.runAllowlistedCommand)('iptables', [
                    '-t',
                    'nat',
                    flag,
                    'PREROUTING',
                    '-p',
                    proto,
                    '--dport',
                    String(hostPort),
                    '-j',
                    'DNAT',
                    '--to-destination',
                    `${guestIp}:${guestPort}`,
                ], { timeoutMs: 5000 });
                if (dnatRes.exitCode !== 0 && mode === 'add') {
                    // Non-root or container without CAP_NET_ADMIN: report cleanly without corrupting state
                    if (dnatRes.stderr.includes('Permission denied') ||
                        dnatRes.stderr.includes('can\'t initialize iptables')) {
                        return false;
                    }
                    throw new Error(dnatRes.stderr || 'iptables DNAT command failed');
                }
            }
            return true;
        }
        catch (err) {
            if (previousState && (0, command_runner_1.isBinaryAvailable)('iptables-restore')) {
                await (0, command_runner_1.runAllowlistedCommand)('iptables-restore', [], {
                    stdinData: previousState,
                    timeoutMs: 5000,
                });
            }
            throw err;
        }
    }
    // --- Firewall Rules Manager (Part 11) ---
    async listFirewallRules(nodeId) {
        if (nodeId !== undefined) {
            return this.db.all(`SELECT f.*, n.name AS node_name FROM firewall_rules f LEFT JOIN nodes n ON n.id = f.node_id WHERE f.node_id = ? ORDER BY f.priority ASC, f.id ASC`, [nodeId]);
        }
        return this.db.all(`SELECT f.*, n.name AS node_name FROM firewall_rules f LEFT JOIN nodes n ON n.id = f.node_id ORDER BY f.priority ASC, f.id ASC`);
    }
    async createFirewallRule(input) {
        if (!['in', 'out'].includes(input.direction))
            throw new Error('Invalid firewall direction.');
        if (!['ACCEPT', 'DROP', 'REJECT'].includes(input.action))
            throw new Error('Invalid firewall action.');
        if (!['tcp', 'udp', 'icmp', 'all'].includes(input.protocol)) {
            throw new Error('Invalid firewall protocol.');
        }
        if (input.destPort && !/^\d{1,5}(:\d{1,5})?$/.test(input.destPort)) {
            throw new Error('Destination port must be a valid port or range (e.g. 443 or 8000:8010).');
        }
        const ins = await this.db.run(`INSERT INTO firewall_rules
         (node_id, instance_type, instance_ref_id, direction, action, protocol, source_cidr, dest_port, priority, enabled, comment)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`, [
            input.nodeId,
            input.instanceType || null,
            input.instanceRefId || null,
            input.direction,
            input.action,
            input.protocol,
            input.sourceCidr?.trim() || null,
            input.destPort?.trim() || null,
            Number(input.priority || 100),
            input.comment?.slice(0, 200) || null,
        ]);
        return this.db.get(`SELECT * FROM firewall_rules WHERE id = ?`, [ins.lastID]);
    }
    async deleteFirewallRule(ruleId) {
        await this.db.run(`DELETE FROM firewall_rules WHERE id = ?`, [ruleId]);
    }
}
exports.NetworkManager = NetworkManager;
