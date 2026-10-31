"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NodeManager = void 0;
const crypto_1 = __importDefault(require("crypto"));
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const ws_1 = __importDefault(require("ws"));
const crypto_vault_1 = require("../../security/crypto-vault");
const agent_1 = require("../../node-agent/agent");
const health_1 = require("../../node-agent/health");
/**
 * Communicates with remote Node Agents over HTTPS/HTTP using replay-protected HMAC-SHA256 signatures
 * and per-node circuit breakers, while routing `is_local = 1` requests directly to `LocalNodeRuntime`.
 */
class NodeManager {
    db;
    localRuntime;
    circuits = new Map();
    failureThreshold = 3;
    openCooldownMs = 30_000;
    constructor(db, localRuntime) {
        this.db = db;
        this.localRuntime =
            localRuntime ||
                new agent_1.LocalNodeRuntime({
                    onAuditEvent: (evt) => {
                        this.db
                            .logActivity({
                            action: evt.action,
                            resourceType: 'node_shell',
                            resourceId: 'localhost',
                            details: { actor: evt.actor, ...evt.details },
                        })
                            .catch(() => undefined);
                    },
                });
    }
    async listNodes() {
        return this.db.all(`SELECT n.*,
              c.supports_kvm, c.supports_lxc, c.kvm_available, c.lxc_available
       FROM nodes n
       LEFT JOIN node_capabilities c ON c.node_id = n.id
       ORDER BY n.is_local DESC, n.id ASC`);
    }
    async getNodeById(nodeId) {
        return this.db.get(`SELECT n.*,
              c.supports_kvm, c.supports_lxc, c.kvm_available, c.lxc_available
       FROM nodes n
       LEFT JOIN node_capabilities c ON c.node_id = n.id
       WHERE n.id = ?`, [nodeId]);
    }
    async getDefaultNodeForEngine(engine) {
        const capCol = engine === 'kvm' ? 'supports_kvm' : 'supports_lxc';
        const preferred = await this.db.get(`SELECT n.*, c.supports_kvm, c.supports_lxc, c.kvm_available, c.lxc_available
       FROM nodes n
       LEFT JOIN node_capabilities c ON c.node_id = n.id
       WHERE n.maintenance_mode = 0 AND COALESCE(c.${capCol}, 1) = 1
       ORDER BY CASE WHEN n.status = 'online' THEN 0 ELSE 1 END, n.is_local DESC, n.id ASC
       LIMIT 1`);
        if (preferred)
            return preferred;
        const fallback = await this.db.get(`SELECT * FROM nodes ORDER BY is_local DESC, id ASC LIMIT 1`);
        if (!fallback) {
            throw new Error('No nodes registered in HKVM database.');
        }
        return fallback;
    }
    async createNode(input) {
        const keyPair = (0, crypto_vault_1.generateApiKeyPair)('hkvm_node');
        const hmacSecret = crypto_1.default.randomBytes(32).toString('hex');
        let createdId = 0;
        await this.db.transaction(async () => {
            const ins = await this.db.run(`INSERT INTO nodes
         (name, hostname, ip_address, location, url, is_local, verify_ssl, mtls_enabled, status, max_instances, tags, notes)
         VALUES (?, ?, ?, ?, ?, 0, ?, ?, 'provisioning', ?, ?, ?)`, [
                input.name.trim(),
                input.hostname.trim(),
                input.ipAddress.trim(),
                input.location?.trim() || 'Remote Datacenter',
                input.url.trim().replace(/\/+$/, ''),
                input.verifySsl !== false ? 1 : 0,
                input.mtlsEnabled ? 1 : 0,
                Number(input.maxInstances || 100),
                JSON.stringify(input.tags || []),
                input.notes || null,
            ]);
            createdId = ins.lastID;
            await this.db.run(`INSERT INTO node_credentials (node_id, api_key_prefix, api_key_hash, api_key_enc, hmac_secret_enc)
         VALUES (?, ?, ?, ?, ?)`, [
                createdId,
                keyPair.keyPrefix,
                keyPair.keyHash,
                (0, crypto_vault_1.encryptSecret)(keyPair.rawKey),
                (0, crypto_vault_1.encryptSecret)(hmacSecret),
            ]);
            await this.db.run(`INSERT INTO node_capabilities (node_id, supports_kvm, supports_lxc)
         VALUES (?, ?, ?)`, [
                createdId,
                input.supportsKvm !== false ? 1 : 0,
                input.supportsLxc !== false ? 1 : 0,
            ]);
        });
        const node = (await this.getNodeById(createdId));
        return {
            node,
            bootstrapCredentials: {
                apiKey: keyPair.rawKey,
                hmacSecret,
            },
        };
    }
    async updateNode(nodeId, patch) {
        const existing = await this.getNodeById(nodeId);
        if (!existing)
            throw new Error(`Node #${nodeId} not found.`);
        await this.db.run(`UPDATE nodes SET
         name = COALESCE(?, name),
         hostname = COALESCE(?, hostname),
         ip_address = COALESCE(?, ip_address),
         location = COALESCE(?, location),
         url = COALESCE(?, url),
         maintenance_mode = COALESCE(?, maintenance_mode),
         verify_ssl = COALESCE(?, verify_ssl),
         max_instances = COALESCE(?, max_instances),
         notes = COALESCE(?, notes),
         updated_at = datetime('now')
       WHERE id = ?`, [
            patch.name?.trim() ?? null,
            patch.hostname?.trim() ?? null,
            patch.ipAddress?.trim() ?? null,
            patch.location?.trim() ?? null,
            patch.url?.trim().replace(/\/+$/, '') ?? null,
            patch.maintenanceMode !== undefined ? (patch.maintenanceMode ? 1 : 0) : null,
            patch.verifySsl !== undefined ? (patch.verifySsl ? 1 : 0) : null,
            patch.maxInstances !== undefined ? Number(patch.maxInstances) : null,
            patch.notes !== undefined ? patch.notes : null,
            nodeId,
        ]);
        if (patch.supportsKvm !== undefined || patch.supportsLxc !== undefined) {
            await this.db.run(`UPDATE node_capabilities SET
           supports_kvm = COALESCE(?, supports_kvm),
           supports_lxc = COALESCE(?, supports_lxc),
           updated_at = datetime('now')
         WHERE node_id = ?`, [
                patch.supportsKvm !== undefined ? (patch.supportsKvm ? 1 : 0) : null,
                patch.supportsLxc !== undefined ? (patch.supportsLxc ? 1 : 0) : null,
                nodeId,
            ]);
        }
        return (await this.getNodeById(nodeId));
    }
    async deleteNode(nodeId) {
        const node = await this.getNodeById(nodeId);
        if (!node)
            throw new Error(`Node #${nodeId} not found.`);
        if (node.is_local) {
            throw new Error('Cannot delete the built-in localhost controller node.');
        }
        const activeCount = await this.db.get(`SELECT COUNT(*) AS cnt FROM instances WHERE node_id = ?`, [nodeId]);
        if ((activeCount?.cnt || 0) > 0) {
            throw new Error(`Cannot remove node "${node.name}" while ${activeCount?.cnt} instance(s) are still assigned to it.`);
        }
        await this.db.run(`DELETE FROM nodes WHERE id = ?`, [nodeId]);
    }
    async rotateNodeCredentials(nodeId) {
        const node = await this.getNodeById(nodeId);
        if (!node)
            throw new Error(`Node #${nodeId} not found.`);
        const newPair = (0, crypto_vault_1.generateApiKeyPair)('hkvm_node');
        const newHmac = crypto_1.default.randomBytes(32).toString('hex');
        let pushedToAgent = false;
        if (!node.is_local) {
            try {
                await this.requestRemoteNode(nodeId, 'POST', '/api/v1/credentials/rotate', {
                    newApiKey: newPair.rawKey,
                    newHmacSecret: newHmac,
                });
                pushedToAgent = true;
            }
            catch {
                pushedToAgent = false;
            }
        }
        else {
            pushedToAgent = true;
        }
        await this.db.run(`UPDATE node_credentials
       SET api_key_prefix = ?, api_key_hash = ?, api_key_enc = ?, hmac_secret_enc = ?, rotated_at = datetime('now')
       WHERE node_id = ?`, [
            newPair.keyPrefix,
            newPair.keyHash,
            (0, crypto_vault_1.encryptSecret)(newPair.rawKey),
            (0, crypto_vault_1.encryptSecret)(newHmac),
            nodeId,
        ]);
        return { apiKey: newPair.rawKey, hmacSecret: newHmac, pushedToAgent };
    }
    /**
     * Refreshes health, capabilities, and real host stats for a node (local or remote).
     */
    async checkNodeHealthAndStats(nodeId) {
        const node = await this.getNodeById(nodeId);
        if (!node)
            throw new Error(`Node #${nodeId} not found.`);
        try {
            let health;
            let stats;
            if (node.is_local) {
                health = await (0, health_1.getNodeHealthReport)(true);
                stats = await this.localRuntime.statsCollector.collect();
            }
            else {
                health = await this.requestRemoteNode(nodeId, 'GET', '/api/v1/health?refresh=1');
                stats = await this.requestRemoteNode(nodeId, 'GET', '/api/v1/stats');
            }
            await this.db.run(`UPDATE nodes SET
           status = 'online',
           agent_version = ?,
           last_heartbeat = datetime('now'),
           circuit_state = 'closed',
           consecutive_failures = 0,
           cpu_cores = ?,
           cpu_model = ?,
           ram_total_mb = ?,
           disk_total_gb = ?,
           updated_at = datetime('now')
         WHERE id = ?`, [
                health.agentVersion,
                stats.cpuCores,
                stats.cpuModel,
                stats.ramTotalMb,
                stats.diskTotalGb,
                nodeId,
            ]);
            await this.db.run(`INSERT INTO node_capabilities
           (node_id, supports_kvm, supports_lxc, kvm_available, lxc_available, nested_virt, cgroup_version, storage_backends, network_backends, qemu_version, lxc_version, kernel_version, updated_at)
         VALUES (?, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
         ON CONFLICT(node_id) DO UPDATE SET
           kvm_available = excluded.kvm_available,
           lxc_available = excluded.lxc_available,
           nested_virt = excluded.nested_virt,
           cgroup_version = excluded.cgroup_version,
           storage_backends = excluded.storage_backends,
           network_backends = excluded.network_backends,
           qemu_version = excluded.qemu_version,
           lxc_version = excluded.lxc_version,
           kernel_version = excluded.kernel_version,
           updated_at = datetime('now')`, [
                nodeId,
                health.capabilities.kvmAvailable ? 1 : 0,
                health.capabilities.lxcAvailable ? 1 : 0,
                health.capabilities.kvmDevicePresent ? 1 : 0,
                health.capabilities.cgroupVersion,
                JSON.stringify(health.capabilities.storageBackends),
                JSON.stringify(health.capabilities.networkBackends),
                health.capabilities.qemuVersion,
                health.capabilities.lxcVersion,
                health.capabilities.kernelVersion,
            ]);
            this.recordCircuitSuccess(nodeId);
            const updatedNode = (await this.getNodeById(nodeId));
            return { node: updatedNode, health, stats };
        }
        catch (err) {
            await this.recordCircuitFailure(nodeId);
            throw err;
        }
    }
    checkCircuitAllowed(nodeId) {
        const entry = this.circuits.get(nodeId);
        if (!entry || entry.state === 'closed')
            return;
        if (entry.state === 'open') {
            if (Date.now() - entry.openedAt >= this.openCooldownMs) {
                entry.state = 'half-open';
                return;
            }
            throw new Error(`Circuit breaker OPEN for node #${nodeId}: remote node is unreachable. Retrying after cooldown.`);
        }
    }
    recordCircuitSuccess(nodeId) {
        this.circuits.set(nodeId, { state: 'closed', failures: 0, openedAt: 0 });
    }
    async recordCircuitFailure(nodeId) {
        const prev = this.circuits.get(nodeId) || { state: 'closed', failures: 0, openedAt: 0 };
        const failures = prev.failures + 1;
        const state = failures >= this.failureThreshold ? 'open' : 'closed';
        this.circuits.set(nodeId, {
            state,
            failures,
            openedAt: state === 'open' ? Date.now() : prev.openedAt,
        });
        await this.db.run(`UPDATE nodes SET status = 'offline', circuit_state = ?, consecutive_failures = ?, updated_at = datetime('now') WHERE id = ?`, [state, failures, nodeId]);
    }
    async requestRemoteNode(nodeId, method, pathWithQuery, body, timeoutMs = 30_000) {
        this.checkCircuitAllowed(nodeId);
        const node = await this.getNodeById(nodeId);
        if (!node)
            throw new Error(`Node #${nodeId} not found.`);
        if (node.is_local) {
            throw new Error('Use localRuntime directly for localhost node operations.');
        }
        const creds = await this.db.get(`SELECT * FROM node_credentials WHERE node_id = ?`, [nodeId]);
        if (!creds) {
            throw new Error(`Credentials missing for node #${nodeId}.`);
        }
        const rawApiKey = (0, crypto_vault_1.decryptSecret)(creds.api_key_enc);
        const hmacSecret = (0, crypto_vault_1.decryptSecret)(creds.hmac_secret_enc);
        const rawBody = body !== undefined ? JSON.stringify(body) : '';
        const signed = (0, crypto_vault_1.signAgentRequest)({
            nodeId,
            apiKey: rawApiKey,
            hmacSecret,
            method,
            pathWithQuery,
            bodyBuffer: rawBody,
        });
        const targetUrl = new URL(pathWithQuery, node.url);
        const isHttps = targetUrl.protocol === 'https:';
        return new Promise((resolve, reject) => {
            const reqOpts = {
                method,
                hostname: targetUrl.hostname,
                port: targetUrl.port || (isHttps ? 443 : 80),
                path: targetUrl.pathname + targetUrl.search,
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(rawBody),
                    'X-HKVM-Node-Key': rawApiKey,
                    ...signed,
                },
                timeout: timeoutMs,
            };
            if (isHttps) {
                reqOpts.rejectUnauthorized = Boolean(node.verify_ssl);
                if (creds.tls_ca_pem)
                    reqOpts.ca = creds.tls_ca_pem;
                if (creds.tls_client_cert_pem && creds.tls_client_key_enc) {
                    reqOpts.cert = creds.tls_client_cert_pem;
                    reqOpts.key = (0, crypto_vault_1.decryptSecret)(creds.tls_client_key_enc);
                }
            }
            const transport = isHttps ? https_1.default : http_1.default;
            const req = transport.request(reqOpts, (res) => {
                let respData = '';
                res.on('data', (chunk) => {
                    respData += chunk.toString('utf8');
                });
                res.on('end', () => {
                    const code = res.statusCode || 500;
                    if (code >= 200 && code < 300) {
                        this.recordCircuitSuccess(nodeId);
                        try {
                            resolve((respData ? JSON.parse(respData) : {}));
                        }
                        catch {
                            resolve(respData);
                        }
                    }
                    else {
                        let errMsg = `Remote node HTTP ${code}`;
                        try {
                            const parsed = JSON.parse(respData);
                            if (parsed?.error)
                                errMsg = parsed.error;
                        }
                        catch {
                            if (respData)
                                errMsg = respData.slice(0, 300);
                        }
                        reject(new Error(errMsg));
                    }
                });
            });
            req.on('timeout', () => {
                req.destroy(new Error(`Remote node #${nodeId} request timed out after ${timeoutMs}ms`));
            });
            req.on('error', async (err) => {
                await this.recordCircuitFailure(nodeId).catch(() => undefined);
                reject(err);
            });
            if (rawBody) {
                req.write(rawBody);
            }
            req.end();
        });
    }
    async openRemoteAgentWebSocket(nodeId, wsPath, query = {}) {
        const node = await this.getNodeById(nodeId);
        if (!node || node.is_local) {
            throw new Error(`Node #${nodeId} is not a remote node.`);
        }
        const creds = await this.db.get(`SELECT api_key_enc, hmac_secret_enc FROM node_credentials WHERE node_id = ?`, [nodeId]);
        if (!creds)
            throw new Error(`Credentials missing for node #${nodeId}.`);
        const rawApiKey = (0, crypto_vault_1.decryptSecret)(creds.api_key_enc);
        const hmacSecret = (0, crypto_vault_1.decryptSecret)(creds.hmac_secret_enc);
        const signed = (0, crypto_vault_1.signAgentRequest)({
            nodeId,
            apiKey: rawApiKey,
            hmacSecret,
            method: 'GET',
            pathWithQuery: wsPath,
            bodyBuffer: '',
        });
        const baseWsUrl = node.url.replace(/^http:/i, 'ws:').replace(/^https:/i, 'wss:');
        const urlObj = new URL(wsPath, baseWsUrl);
        for (const [k, v] of Object.entries(query)) {
            urlObj.searchParams.set(k, String(v));
        }
        return new ws_1.default(urlObj.toString(), {
            rejectUnauthorized: Boolean(node.verify_ssl),
            headers: {
                'X-HKVM-Node-Key': rawApiKey,
                ...signed,
            },
        });
    }
}
exports.NodeManager = NodeManager;
