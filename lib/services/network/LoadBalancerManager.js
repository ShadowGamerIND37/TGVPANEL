"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.LoadBalancerManager = void 0;
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const command_runner_1 = require("../../node-agent/command-runner");
const middleware_1 = require("../../security/middleware");
const ALLOWED_PROTOCOLS = new Set(['tcp', 'http']);
const ALLOWED_ALGORITHMS = new Set(['roundrobin', 'leastconn', 'source']);
/**
 * HAProxy load balancer registry and lifecycle manager.
 *
 * The panel renders a complete HAProxy configuration from the registered
 * frontend + backend rows, validates it with `haproxy -c`, and starts/reloads
 * (or stops) the process on the target node via allowlisted host commands.
 * Nodes without the `haproxy` binary fail honestly — nothing is faked.
 */
class LoadBalancerManager {
    db;
    nodeManager;
    constructor(db, nodeManager) {
        this.db = db;
        this.nodeManager = nodeManager;
    }
    getConfigDir() {
        const dataDir = process.env.TGVPANEL_DATA_DIR || path.join(os.homedir(), 'vms');
        return path.join(dataDir, 'haproxy');
    }
    configPath(name) {
        return path.join(this.getConfigDir(), `${name}.cfg`);
    }
    pidPath(name) {
        return path.join(this.getConfigDir(), `${name}.pid`);
    }
    // --- Registry ---
    async listLoadBalancers() {
        return this.db.all(`SELECT lb.*, n.name AS node_name,
              (SELECT COUNT(*) FROM load_balancer_backends b WHERE b.load_balancer_id = lb.id) AS backend_count
       FROM load_balancers lb
       LEFT JOIN nodes n ON n.id = lb.node_id
       ORDER BY lb.id ASC`);
    }
    async getLoadBalancer(id) {
        const lb = await this.db.get(`SELECT lb.*, n.name AS node_name FROM load_balancers lb
       LEFT JOIN nodes n ON n.id = lb.node_id WHERE lb.id = ?`, [id]);
        if (!lb)
            return null;
        lb.backends = await this.db.all(`SELECT * FROM load_balancer_backends WHERE load_balancer_id = ? ORDER BY position ASC, id ASC`, [id]);
        return lb;
    }
    validateBackends(backends) {
        if (!Array.isArray(backends))
            throw new Error('backends must be an array.');
        backends.forEach((backend, i) => {
            const label = `Backend ${i + 1}`;
            const name = String(backend.name || '').trim();
            if (!name || name.length > 60)
                throw new Error(`${label}: name is required (max 60 chars).`);
            const target = String(backend.target || '').trim();
            if (!target || target.length > 253)
                throw new Error(`${label}: target is required.`);
            if (!/^[0-9a-zA-Z._:-]+$/.test(target))
                throw new Error(`${label}: invalid target.`);
            const port = Number(backend.port);
            if (!Number.isInteger(port) || port < 1 || port > 65535) {
                throw new Error(`${label}: port must be between 1 and 65535.`);
            }
            const weight = Number(backend.weight ?? 1);
            if (!Number.isInteger(weight) || weight < 1 || weight > 256) {
                throw new Error(`${label}: weight must be between 1 and 256.`);
            }
        });
    }
    async createLoadBalancer(input) {
        const name = middleware_1.SafeValidators.loadBalancerName(String(input.name || ''));
        const protocol = String(input.protocol || 'tcp').toLowerCase();
        if (!ALLOWED_PROTOCOLS.has(protocol))
            throw new Error('protocol must be tcp or http.');
        const algorithm = String(input.algorithm || 'roundrobin').toLowerCase();
        if (!ALLOWED_ALGORITHMS.has(algorithm)) {
            throw new Error('algorithm must be roundrobin, leastconn or source.');
        }
        const listenPort = Number(input.listenPort);
        if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) {
            throw new Error('listenPort must be between 1 and 65535.');
        }
        const listenIp = String(input.listenIp || '0.0.0.0').trim() || '0.0.0.0';
        const backends = Array.isArray(input.backends) ? input.backends : [];
        this.validateBackends(backends);
        const ins = await this.db.run(`INSERT INTO load_balancers (name, node_id, listen_ip, listen_port, protocol, algorithm, enabled)
       VALUES (?, ?, ?, ?, ?, ?, 1)`, [name, Number(input.nodeId || 1), listenIp, listenPort, protocol, algorithm]);
        const id = Number(ins.lastID);
        await this.replaceBackends(id, backends);
        return this.getLoadBalancer(id);
    }
    async updateLoadBalancer(id, input) {
        const existing = await this.getLoadBalancer(id);
        if (!existing)
            throw new Error('Load balancer does not exist.');
        const name = input.name !== undefined ? middleware_1.SafeValidators.loadBalancerName(String(input.name)) : existing.name;
        const protocol = input.protocol !== undefined
            ? String(input.protocol).toLowerCase()
            : String(existing.protocol);
        if (!ALLOWED_PROTOCOLS.has(protocol))
            throw new Error('protocol must be tcp or http.');
        const algorithm = input.algorithm !== undefined
            ? String(input.algorithm).toLowerCase()
            : String(existing.algorithm);
        if (!ALLOWED_ALGORITHMS.has(algorithm)) {
            throw new Error('algorithm must be roundrobin, leastconn or source.');
        }
        const listenPort = input.listenPort !== undefined ? Number(input.listenPort) : Number(existing.listen_port);
        if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) {
            throw new Error('listenPort must be between 1 and 65535.');
        }
        const listenIp = input.listenIp !== undefined ? String(input.listenIp).trim() || '0.0.0.0' : existing.listen_ip;
        const nodeId = input.nodeId !== undefined ? Number(input.nodeId) : Number(existing.node_id);
        await this.db.run(`UPDATE load_balancers
       SET name = ?, node_id = ?, listen_ip = ?, listen_port = ?, protocol = ?, algorithm = ?, enabled = ?
       WHERE id = ?`, [
            name,
            nodeId,
            listenIp,
            listenPort,
            protocol,
            algorithm,
            input.enabled === false ? 0 : 1,
            id,
        ]);
        if (input.backends !== undefined) {
            this.validateBackends(input.backends);
            await this.replaceBackends(id, input.backends);
        }
        return this.getLoadBalancer(id);
    }
    async replaceBackends(lbId, backends) {
        await this.db.run(`DELETE FROM load_balancer_backends WHERE load_balancer_id = ?`, [lbId]);
        for (let i = 0; i < backends.length; i++) {
            const backend = backends[i];
            await this.db.run(`INSERT INTO load_balancer_backends
           (load_balancer_id, name, target, port, weight, enabled, position)
         VALUES (?, ?, ?, ?, ?, ?, ?)`, [
                lbId,
                String(backend.name).trim(),
                String(backend.target).trim(),
                Number(backend.port),
                Number(backend.weight ?? 1),
                backend.enabled === false ? 0 : 1,
                i,
            ]);
        }
    }
    async deleteLoadBalancer(id) {
        const existing = await this.getLoadBalancer(id);
        if (!existing)
            return;
        // Best-effort stop so the host process does not keep serving stale config.
        await this.applyLoadBalancer(existing, 'stop').catch(() => undefined);
        await this.db.run(`DELETE FROM load_balancer_backends WHERE load_balancer_id = ?`, [id]);
        await this.db.run(`DELETE FROM load_balancers WHERE id = ?`, [id]);
    }
    // --- Config rendering & lifecycle ---
    renderConfig(lb) {
        const backends = Array.isArray(lb.backends) ? lb.backends : [];
        const enabledBackends = backends.filter((b) => Number(b.enabled) === 1);
        const lines = [
            '# Managed by TGVPANEL — do not edit while the process is running.',
            'global',
            '    log stdout format raw local0',
            '    daemon',
            '    user haproxy',
            '    group haproxy',
            '',
            'defaults',
            '    log global',
            `    mode ${lb.protocol}`,
            '    option redispatch',
            '    retries 3',
            '    timeout connect 5s',
            '    timeout client 50s',
            '    timeout server 50s',
            '',
            `frontend ${lb.name}_fe`,
            `    bind ${lb.listen_ip}:${lb.listen_port}`,
            `    mode ${lb.protocol}`,
        ];
        if (lb.protocol === 'http') {
            lines.push(`    default_backend ${lb.name}_be`);
        }
        else {
            // TCP mode: frontends forward to backends via use_backend rules.
            for (const backend of enabledBackends) {
                lines.push(`    use_backend ${lb.name}_be_${backend.id}`);
            }
        }
        lines.push('');
        for (const backend of enabledBackends) {
            lines.push(`backend ${lb.name}_be_${backend.id}`);
            lines.push(`    mode ${lb.protocol}`);
            lines.push(`    balance ${lb.algorithm}`);
            lines.push(`    server ${backend.name} ${backend.target}:${backend.port} weight ${backend.weight} check`);
            lines.push('');
        }
        return lines.join('\n');
    }
    async isRemoteNode(nodeId) {
        if (!this.nodeManager)
            return false;
        const node = await this.nodeManager.getNodeById(nodeId);
        return Boolean(node && !node.is_local);
    }
    /**
     * Validates the rendered config and starts/reloads/stops the HAProxy
     * process on the target node. Records honest validation/apply results on
     * the load balancer row.
     */
    async applyLoadBalancer(lb, mode = 'start') {
        const name = String(lb.name);
        const config = this.renderConfig(lb);
        const nodeId = Number(lb.node_id || 1);
        if (await this.isRemoteNode(nodeId)) {
            const node = await this.nodeManager.getNodeById(nodeId);
            if (!node || node.status !== 'online') {
                await this.recordResult(lb.id, false, null, 'Target node is not online.');
                return { applied: false, validated: false, error: 'Target node is not online.' };
            }
            const res = await this.nodeManager.requestRemoteNode(nodeId, 'POST', '/api/v1/load-balancers/apply', { name, config, mode }, 15_000);
            const validated = Boolean(res?.validated);
            const applied = Boolean(res?.applied);
            await this.recordResult(lb.id, applied, validated, res?.error || (!validated ? 'Remote HAProxy config validation failed.' : null));
            return { applied, validated, error: res?.error || null };
        }
        if (!(0, command_runner_1.isBinaryAvailable)('haproxy')) {
            const error = 'The haproxy binary is not available on this node.';
            await this.recordResult(lb.id, false, null, error);
            return { applied: false, validated: false, error };
        }
        fs.mkdirSync(this.getConfigDir(), { recursive: true });
        const cfgPath = this.configPath(name);
        const pidPath = this.pidPath(name);
        fs.writeFileSync(cfgPath, config, { mode: 0o640 });
        // 1. Validate the rendered configuration before touching a running process.
        const check = await (0, command_runner_1.runAllowlistedCommand)('haproxy', ['-c', '-f', cfgPath], {
            asRoot: true,
            timeoutMs: 10_000,
        });
        if (check.exitCode !== 0) {
            const error = `HAProxy config validation failed: ${(check.stderr || check.stdout).trim()}`;
            await this.recordResult(lb.id, false, false, error);
            return { applied: false, validated: false, error };
        }
        // 2. Start / reload / stop the process.
        let applyRes;
        if (mode === 'stop') {
            applyRes = await this.stopLocalProcess(pidPath);
        }
        else if (mode === 'reload') {
            applyRes = await (0, command_runner_1.runAllowlistedCommand)('haproxy', ['-sf', '-p', pidPath, '-f', cfgPath], {
                asRoot: true,
                timeoutMs: 10_000,
            });
        }
        else {
            applyRes = await (0, command_runner_1.runAllowlistedCommand)('haproxy', ['-D', '-f', cfgPath, '-p', pidPath], {
                asRoot: true,
                timeoutMs: 10_000,
            });
        }
        const applied = applyRes.exitCode === 0;
        await this.recordResult(lb.id, applied, true, applied ? null : `HAProxy ${mode} failed: ${(applyRes.stderr || applyRes.stdout).trim()}`);
        return { applied, validated: true, error: applied ? null : `HAProxy ${mode} failed.` };
    }
    async stopLocalProcess(pidPath) {
        try {
            if (!fs.existsSync(pidPath))
                return { exitCode: 0, stdout: '', stderr: '' };
            const pid = Number(fs.readFileSync(pidPath, 'utf8').trim());
            if (!Number.isInteger(pid) || pid <= 0) {
                fs.unlinkSync(pidPath);
                return { exitCode: 0, stdout: '', stderr: '' };
            }
            const killRes = await (0, command_runner_1.runAllowlistedCommand)('kill', ['-TERM', String(pid)], {
                asRoot: true,
                timeoutMs: 5_000,
            });
            if (killRes.exitCode !== 0)
                return killRes;
            fs.unlinkSync(pidPath);
            return killRes;
        }
        catch {
            return { exitCode: 0, stdout: '', stderr: '' };
        }
    }
    async recordResult(lbId, applied, validated, error) {
        await this.db.run(`UPDATE load_balancers
       SET last_applied_at = CASE WHEN ? = 1 THEN datetime('now') ELSE last_applied_at END,
           last_validated_at = CASE WHEN ? IS NOT NULL AND ? = 1 THEN datetime('now') ELSE last_validated_at END,
           last_error = ?
       WHERE id = ?`, [applied ? 1 : 0, validated, validated, error, lbId]);
    }
    async getLoadBalancerStatus(id) {
        const lb = await this.getLoadBalancer(id);
        if (!lb)
            return null;
        let running = false;
        if (Number(lb.node_id || 1) === 1 || !this.nodeManager) {
            try {
                running = fs.existsSync(this.pidPath(String(lb.name)));
            }
            catch {
                running = false;
            }
        }
        return {
            id: lb.id,
            name: lb.name,
            enabled: Number(lb.enabled) === 1,
            running,
            lastAppliedAt: lb.last_applied_at,
            lastValidatedAt: lb.last_validated_at,
            lastError: lb.last_error,
        };
    }
}
exports.LoadBalancerManager = LoadBalancerManager;
