"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NodeManager = void 0;
const crypto_1 = __importDefault(require("crypto"));
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const tls_1 = __importDefault(require("tls"));
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
    latencies = new Map();
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
    normalizeTagsJson(raw) {
        if (!raw)
            return '[]';
        const items = Array.isArray(raw)
            ? raw
            : (() => {
                const str = String(raw).trim();
                if (str.startsWith('[')) {
                    try {
                        const parsed = JSON.parse(str);
                        if (Array.isArray(parsed))
                            return parsed;
                    }
                    catch {
                        // treat as comma-separated
                    }
                }
                return str.split(',');
            })();
        const cleaned = Array.from(new Set(items
            .map((t) => String(t || '').trim().toLowerCase().replace(/[^a-z0-9._:-]+/g, '-'))
            .filter((t) => t.length > 0))).slice(0, 16);
        return JSON.stringify(cleaned);
    }
    enrichNodeRow(r) {
        const kvmCount = Number(r.kvm_count || 0);
        const lxcCount = Number(r.lxc_count || 0);
        const kvmRunning = Number(r.kvm_running || 0);
        const lxcRunning = Number(r.lxc_running || 0);
        return {
            ...r,
            kvm_count: kvmCount,
            kvm_running: kvmRunning,
            lxc_count: lxcCount,
            lxc_running: lxcRunning,
            total_instances: kvmCount + lxcCount,
            running_instances: kvmRunning + lxcRunning,
            allocated_vcpus: Number(r.allocated_vcpus || 0),
            allocated_ram_mb: Number(r.allocated_ram_mb || 0),
            allocated_disk_gb: Number(Number(r.allocated_disk_gb || 0).toFixed(1)),
            latency_ms: this.latencies.get(r.id) ?? (r.is_local ? 1 : null),
        };
    }
    nodeSelectSql = `
    SELECT n.*,
           c.supports_kvm, c.supports_lxc, c.kvm_available, c.lxc_available,
           c.nested_virt, c.cgroup_version, c.qemu_version, c.lxc_version,
           c.kernel_version, c.storage_backends, c.network_backends,
           COALESCE(vk.kvm_count, 0) AS kvm_count,
           COALESCE(vk.kvm_running, 0) AS kvm_running,
           COALESCE(lx.lxc_count, 0) AS lxc_count,
           COALESCE(lx.lxc_running, 0) AS lxc_running,
           COALESCE(vk.kvm_cpus, 0) + COALESCE(lx.lxc_cpus, 0) AS allocated_vcpus,
           COALESCE(vk.kvm_ram, 0) + COALESCE(lx.lxc_ram, 0) AS allocated_ram_mb,
           COALESCE(vk.kvm_disk, 0) + COALESCE(lx.lxc_disk, 0) AS allocated_disk_gb,
           mh.cpu_percent AS live_cpu_percent,
           mh.ram_used_mb AS live_ram_used_mb,
           mh.disk_used_gb AS live_disk_used_gb,
           mh.load_avg_1 AS live_load_1
    FROM nodes n
    LEFT JOIN node_capabilities c ON c.node_id = n.id
    LEFT JOIN (
      SELECT COALESCE(node_id, 1) AS nid,
             COUNT(*) AS kvm_count,
             SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS kvm_running,
             SUM(COALESCE(cpus, cpu_cores, 1)) AS kvm_cpus,
             SUM(COALESCE(memory, 0)) AS kvm_ram,
             SUM(CAST(REPLACE(REPLACE(COALESCE(disk_size, '0'), 'G', ''), 'g', '') AS REAL)) AS kvm_disk
      FROM vms
      GROUP BY COALESCE(node_id, 1)
    ) vk ON vk.nid = n.id
    LEFT JOIN (
      SELECT COALESCE(node_id, 1) AS nid,
             COUNT(*) AS lxc_count,
             SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS lxc_running,
             SUM(COALESCE(cpu_cores, 1)) AS lxc_cpus,
             SUM(COALESCE(ram_mb, 0)) AS lxc_ram,
             SUM(COALESCE(disk_gb, 0)) AS lxc_disk
      FROM lxc_instances
      GROUP BY COALESCE(node_id, 1)
    ) lx ON lx.nid = n.id
    LEFT JOIN metrics_history mh ON mh.id = (
      SELECT m2.id FROM metrics_history m2
      WHERE m2.target_type = 'node' AND m2.target_id = n.id
      ORDER BY m2.id DESC LIMIT 1
    )
  `;
    async listNodes() {
        const rows = await this.db.all(`${this.nodeSelectSql} ORDER BY n.is_local DESC, n.id ASC`);
        return rows.map((r) => this.enrichNodeRow(r));
    }
    async getNodeById(nodeId) {
        const row = await this.db.get(`${this.nodeSelectSql} WHERE n.id = ?`, [nodeId]);
        return row ? this.enrichNodeRow(row) : undefined;
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
            throw new Error('No nodes registered in TGVPANEL database.');
        }
        return fallback;
    }
    async createNode(input) {
        const keyPair = (0, crypto_vault_1.generateApiKeyPair)('tgv_node');
        const hmacSecret = crypto_1.default.randomBytes(32).toString('hex');
        const tagsJson = this.normalizeTagsJson(input.tags);
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
                Math.max(1, Number(input.maxInstances || 100)),
                tagsJson,
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
        const tagsVal = patch.tags !== undefined ? this.normalizeTagsJson(patch.tags) : null;
        await this.db.run(`UPDATE nodes SET
         name = COALESCE(?, name),
         hostname = COALESCE(?, hostname),
         ip_address = COALESCE(?, ip_address),
         location = COALESCE(?, location),
         url = COALESCE(?, url),
         maintenance_mode = COALESCE(?, maintenance_mode),
         verify_ssl = COALESCE(?, verify_ssl),
         max_instances = COALESCE(?, max_instances),
         tags = COALESCE(?, tags),
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
            patch.maxInstances !== undefined ? Math.max(1, Number(patch.maxInstances)) : null,
            tagsVal,
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
        const newPair = (0, crypto_vault_1.generateApiKeyPair)('tgv_node');
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
        const t0 = Date.now();
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
            const latencyMs = Math.max(1, Date.now() - t0);
            this.latencies.set(nodeId, latencyMs);
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
            return { node: updatedNode, health, stats, latencyMs };
        }
        catch (err) {
            await this.recordCircuitFailure(nodeId);
            throw err;
        }
    }
    async resetCircuitBreaker(nodeId) {
        const node = await this.getNodeById(nodeId);
        if (!node)
            throw new Error(`Node #${nodeId} not found.`);
        this.circuits.set(nodeId, { state: 'closed', failures: 0, openedAt: 0 });
        await this.db.run(`UPDATE nodes SET circuit_state = 'closed', consecutive_failures = 0, updated_at = datetime('now') WHERE id = ?`, [nodeId]);
        return (await this.getNodeById(nodeId));
    }
    /**
     * Pre-flight HTTP/HTTPS + TLS reachability probe for remote Node Agent URLs.
     */
    async probeEndpointConnection(input) {
        const rawUrl = String(input.url || '').trim();
        if (!rawUrl)
            throw new Error('Endpoint URL is required.');
        let parsed;
        try {
            parsed = new URL(rawUrl);
        }
        catch {
            throw new Error('Invalid URL format. Expected http://host:port or https://host:port');
        }
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            throw new Error('Only http:// and https:// agent endpoints are supported.');
        }
        const isHttps = parsed.protocol === 'https:';
        const verifySsl = input.verifySsl !== false;
        const timeoutMs = Math.min(10_000, Math.max(1000, Number(input.timeoutMs || 4000)));
        const probeUrl = new URL('/api/v1/health', parsed.origin);
        const t0 = Date.now();
        return new Promise((resolve) => {
            const reqOpts = {
                method: 'GET',
                hostname: probeUrl.hostname,
                port: probeUrl.port || (isHttps ? 443 : 80),
                path: probeUrl.pathname,
                timeout: timeoutMs,
                headers: { Accept: 'application/json', 'User-Agent': 'TGVPANEL-Controller-Probe/3.0' },
            };
            if (isHttps) {
                reqOpts.rejectUnauthorized = verifySsl;
            }
            const mod = isHttps ? https_1.default : http_1.default;
            const req = mod.request(reqOpts, (res) => {
                let body = '';
                res.on('data', (c) => {
                    if (body.length < 4096)
                        body += c.toString('utf8');
                });
                res.on('end', () => {
                    const latencyMs = Math.max(1, Date.now() - t0);
                    const status = res.statusCode || 0;
                    let tlsInfo = null;
                    if (isHttps && res.socket instanceof tls_1.default.TLSSocket) {
                        const cert = res.socket.getPeerCertificate();
                        tlsInfo = {
                            authorized: res.socket.authorized,
                            authorizationError: res.socket.authorizationError
                                ? String(res.socket.authorizationError)
                                : null,
                            subjectCN: Array.isArray(cert?.subject?.CN)
                                ? cert.subject.CN[0] || null
                                : cert?.subject?.CN || null,
                            issuerCN: Array.isArray(cert?.issuer?.CN)
                                ? cert.issuer.CN[0] || null
                                : cert?.issuer?.CN || null,
                            validTo: cert?.valid_to || null,
                            protocol: res.socket.getProtocol() || null,
                        };
                    }
                    const lower = body.toLowerCase();
                    const agentDetected = status === 401 ||
                        status === 200 ||
                        lower.includes('hmac') ||
                        lower.includes('node') ||
                        lower.includes('tgvpanel') ||
                        lower.includes('capabilities');
                    resolve({
                        reachable: true,
                        url: parsed.origin,
                        protocol: isHttps ? 'https' : 'http',
                        latencyMs,
                        httpStatus: status,
                        agentDetected,
                        tls: tlsInfo,
                        message: status === 401
                            ? `Reachable in ${latencyMs}ms — TGVPANEL Node Agent listening (HMAC authentication enforced).`
                            : status === 200
                                ? `Reachable in ${latencyMs}ms — Health endpoint responded HTTP 200.`
                                : `Endpoint reachable in ${latencyMs}ms (HTTP ${status}).`,
                    });
                });
            });
            req.on('timeout', () => {
                req.destroy(new Error(`Connection timed out after ${timeoutMs}ms`));
            });
            req.on('error', (err) => {
                const latencyMs = Math.max(1, Date.now() - t0);
                const code = err?.code ? ` (${err.code})` : '';
                const hint = isHttps && verifySsl && /self[- ]signed|unable to verify|cert/i.test(String(err?.message || ''))
                    ? ' Tip: uncheck "Verify TLS Cert" if this node uses a self-signed certificate.'
                    : '';
                resolve({
                    reachable: false,
                    url: parsed.origin,
                    protocol: isHttps ? 'https' : 'http',
                    latencyMs,
                    httpStatus: null,
                    agentDetected: false,
                    tls: null,
                    message: `Unreachable${code}: ${err?.message || 'Connection failed'}.${hint}`,
                });
            });
            req.end();
        });
    }
    /**
     * Computes transparent smart placement scores across cluster nodes for KVM or LXC workloads.
     */
    async rankPlacementCandidates(engine) {
        const nodes = await this.listNodes();
        return nodes
            .map((n) => {
            const reasons = [];
            let eligible = true;
            if (n.status !== 'online') {
                eligible = false;
                reasons.push(`Status is ${n.status}`);
            }
            if (n.maintenance_mode) {
                eligible = false;
                reasons.push('Cordoned (Maintenance Mode)');
            }
            if (n.circuit_state === 'open') {
                eligible = false;
                reasons.push('Circuit breaker open');
            }
            const maxInst = Number(n.max_instances || 100);
            const curInst = Number(n.total_instances || 0);
            if (maxInst > 0 && curInst >= maxInst) {
                eligible = false;
                reasons.push(`Instance quota full (${curInst}/${maxInst})`);
            }
            if (engine === 'kvm' && Number(n.supports_kvm ?? 1) === 0) {
                eligible = false;
                reasons.push('KVM scheduling disabled on node');
            }
            if (engine === 'lxc' && Number(n.supports_lxc ?? 1) === 0) {
                eligible = false;
                reasons.push('LXC scheduling disabled on node');
            }
            const hwReady = engine === 'kvm' ? Boolean(n.kvm_available) : Boolean(n.lxc_available);
            const cpuPct = Number(n.live_cpu_percent ?? 10);
            const ramTot = Math.max(1, Number(n.ram_total_mb || 1024));
            const ramUsed = Number(n.live_ram_used_mb ?? Math.min(ramTot, Number(n.allocated_ram_mb || 0)));
            const freeRamRatio = Math.max(0, 1 - ramUsed / ramTot);
            const slotRatio = maxInst > 0 ? Math.max(0, 1 - curInst / maxInst) : 1;
            const cpuHeadroom = Math.max(0, 1 - cpuPct / 100);
            let score = eligible
                ? Math.round(freeRamRatio * 45 + cpuHeadroom * 35 + slotRatio * 20 + (hwReady ? 10 : -25))
                : 0;
            score = Math.max(0, Math.min(100, score));
            if (eligible) {
                reasons.push(hwReady ? `${engine.toUpperCase()} hypervisor ready` : `${engine.toUpperCase()} binary not detected yet`);
                reasons.push(`${Math.round(freeRamRatio * 100)}% free RAM headroom`);
                reasons.push(`${curInst}/${maxInst} instance slots used`);
            }
            return {
                nodeId: n.id,
                name: n.name,
                location: n.location,
                isLocal: Boolean(n.is_local),
                eligible,
                hardwareReady: hwReady,
                score,
                reasons,
            };
        })
            .sort((a, b) => Number(b.eligible) - Number(a.eligible) || b.score - a.score || a.nodeId - b.nodeId);
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
