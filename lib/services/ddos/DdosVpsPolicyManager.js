"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DdosVpsPolicyManager = void 0;
/**
 * Per-VPS DDoS protection policies for KVM and LXC instances.
 *
 * Each VPS can have an individual protection policy: protocol-level
 * protection (TCP/UDP/ICMP), connection limits, per-IP rate limits,
 * port/IP whitelists, and network isolation. Policies are applied at the
 * host firewall level using tagged rules (owned by DdosFirewallManager)
 * so they can be rolled back precisely without affecting other VPS or
 * host-wide rules. Only traffic the host can actually inspect and filter
 * is protected — the manager does not claim to protect against traffic
 * that never reaches the host.
 */
class DdosVpsPolicyManager {
    db;
    constructor(db) {
        this.db = db;
    }
    async listPolicies() {
        return this.db.all(`SELECT * FROM ddos_vps_policies ORDER BY vps_id`);
    }
    async getPolicy(vpsId) {
        const row = await this.db.get(`SELECT * FROM ddos_vps_policies WHERE vps_id = ?`, [vpsId]);
        return row || null;
    }
    async getPoliciesForNode(nodeId) {
        return this.db.all(`SELECT * FROM ddos_vps_policies WHERE node_id = ? AND enabled = 1`, [nodeId]);
    }
    async setPolicy(input) {
        const result = await this.db.run(`INSERT INTO ddos_vps_policies
        (vps_id, instance_type, instance_ref_id, node_id, enabled, profile_id,
         tcp_protection, udp_protection, icmp_protection, connection_limit, per_ip_rate_limit,
         port_whitelist, ip_whitelist, auto_block, block_duration, network_isolation, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
       ON CONFLICT(vps_id) DO UPDATE SET
         instance_type = excluded.instance_type,
         instance_ref_id = excluded.instance_ref_id,
         node_id = excluded.node_id,
         enabled = excluded.enabled,
         profile_id = excluded.profile_id,
         tcp_protection = excluded.tcp_protection,
         udp_protection = excluded.udp_protection,
         icmp_protection = excluded.icmp_protection,
         connection_limit = excluded.connection_limit,
         per_ip_rate_limit = excluded.per_ip_rate_limit,
         port_whitelist = excluded.port_whitelist,
         ip_whitelist = excluded.ip_whitelist,
         auto_block = excluded.auto_block,
         block_duration = excluded.block_duration,
         network_isolation = excluded.network_isolation,
         updated_at = datetime('now')`, [
            input.vps_id, input.instance_type, input.instance_ref_id, input.node_id || null,
            input.enabled ?? 0, input.profile_id ?? null,
            input.tcp_protection ?? 1, input.udp_protection ?? 1, input.icmp_protection ?? 1,
            input.connection_limit ?? 500, input.per_ip_rate_limit ?? 0,
            input.port_whitelist || null, input.ip_whitelist || null,
            input.auto_block ?? 1, input.block_duration ?? 3600, input.network_isolation ?? 0,
        ]);
        const policy = await this.getPolicy(input.vps_id);
        return policy;
    }
    async deletePolicy(vpsId) {
        const result = await this.db.run(`DELETE FROM ddos_vps_policies WHERE vps_id = ?`, [vpsId]);
        return result.changes > 0;
    }
    async isWhitelisted(ip, vpsId, nodeId) {
        if (vpsId) {
            const policy = await this.getPolicy(vpsId);
            if (policy?.ip_whitelist) {
                const list = policy.ip_whitelist.split(',').map((s) => s.trim()).filter(Boolean);
                if (list.includes(ip))
                    return true;
            }
        }
        if (nodeId) {
            const policies = await this.getPoliciesForNode(nodeId);
            for (const p of policies) {
                if (p.ip_whitelist) {
                    const list = p.ip_whitelist.split(',').map((s) => s.trim()).filter(Boolean);
                    if (list.includes(ip))
                        return true;
                }
            }
        }
        // Also check global whitelist
        const global = await this.db.get(`SELECT ip FROM ddos_whitelist WHERE ip = ?`, [ip]);
        return Boolean(global);
    }
    async addWhitelist(ip, reason, nodeId, vpsId, userId) {
        await this.db.run(`INSERT OR IGNORE INTO ddos_whitelist (ip, reason, node_id, vps_id, created_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`, [ip, reason || null, nodeId || null, vpsId || null, userId || null, Date.now()]);
        // Also mark the IP as whitelisted in ddos_ips if it exists
        await this.db.run(`UPDATE ddos_ips SET whitelisted = 1, banned = 0, blocked = 0, blocked_at = NULL WHERE ip = ?`, [ip]);
        return true;
    }
    async removeWhitelist(ip) {
        const result = await this.db.run(`DELETE FROM ddos_whitelist WHERE ip = ?`, [ip]);
        await this.db.run(`UPDATE ddos_ips SET whitelisted = 0 WHERE ip = ?`, [ip]);
        return result.changes > 0;
    }
    async listWhitelist(nodeId, vpsId) {
        let query = `SELECT * FROM ddos_whitelist`;
        const params = [];
        const conditions = [];
        if (nodeId) {
            conditions.push(`node_id = ?`);
            params.push(nodeId);
        }
        if (vpsId) {
            conditions.push(`vps_id = ?`);
            params.push(vpsId);
        }
        if (conditions.length > 0)
            query += ` WHERE ${conditions.join(' AND ')}`;
        query += ` ORDER BY created_at DESC`;
        return this.db.all(query, params);
    }
}
exports.DdosVpsPolicyManager = DdosVpsPolicyManager;
