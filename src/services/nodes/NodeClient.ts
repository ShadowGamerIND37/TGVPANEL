import crypto from 'crypto';
import http from 'http';
import https from 'https';
import WebSocket from 'ws';
import { UnifiedDatabase } from '../../db/database';
import {
  decryptSecret,
  encryptSecret,
  generateApiKeyPair,
  hashApiKey,
  signAgentRequest,
} from '../../security/crypto-vault';
import { LocalNodeRuntime } from '../../node-agent/agent';
import { getNodeHealthReport, NodeHealthReport } from '../../node-agent/health';
import { HostResourceStats } from '../../node-agent/host-stats';

export interface NodeRecord {
  id: number;
  name: string;
  hostname: string;
  ip_address: string;
  location: string;
  url: string;
  is_local: number;
  maintenance_mode: number;
  verify_ssl: number;
  mtls_enabled: number;
  status: string;
  agent_version: string | null;
  last_heartbeat: string | null;
  circuit_state: 'closed' | 'open' | 'half-open';
  consecutive_failures: number;
  cpu_cores: number;
  cpu_model: string | null;
  ram_total_mb: number;
  disk_total_gb: number;
  max_instances: number;
  tags: string;
  notes: string | null;
  supports_kvm?: number;
  supports_lxc?: number;
  kvm_available?: number;
  lxc_available?: number;
}

interface CircuitBreakerEntry {
  state: 'closed' | 'open' | 'half-open';
  failures: number;
  openedAt: number;
}

/**
 * Communicates with remote Node Agents over HTTPS/HTTP using replay-protected HMAC-SHA256 signatures
 * and per-node circuit breakers, while routing `is_local = 1` requests directly to `LocalNodeRuntime`.
 */
export class NodeManager {
  private db: UnifiedDatabase;
  public readonly localRuntime: LocalNodeRuntime;
  private circuits = new Map<number, CircuitBreakerEntry>();
  private readonly failureThreshold = 3;
  private readonly openCooldownMs = 30_000;

  constructor(db: UnifiedDatabase, localRuntime?: LocalNodeRuntime) {
    this.db = db;
    this.localRuntime =
      localRuntime ||
      new LocalNodeRuntime({
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

  public async listNodes(): Promise<NodeRecord[]> {
    return this.db.all<NodeRecord>(
      `SELECT n.*,
              c.supports_kvm, c.supports_lxc, c.kvm_available, c.lxc_available
       FROM nodes n
       LEFT JOIN node_capabilities c ON c.node_id = n.id
       ORDER BY n.is_local DESC, n.id ASC`
    );
  }

  public async getNodeById(nodeId: number): Promise<NodeRecord | undefined> {
    return this.db.get<NodeRecord>(
      `SELECT n.*,
              c.supports_kvm, c.supports_lxc, c.kvm_available, c.lxc_available
       FROM nodes n
       LEFT JOIN node_capabilities c ON c.node_id = n.id
       WHERE n.id = ?`,
      [nodeId]
    );
  }

  public async getDefaultNodeForEngine(engine: 'kvm' | 'lxc'): Promise<NodeRecord> {
    const capCol = engine === 'kvm' ? 'supports_kvm' : 'supports_lxc';
    const preferred = await this.db.get<NodeRecord>(
      `SELECT n.*, c.supports_kvm, c.supports_lxc, c.kvm_available, c.lxc_available
       FROM nodes n
       LEFT JOIN node_capabilities c ON c.node_id = n.id
       WHERE n.maintenance_mode = 0 AND COALESCE(c.${capCol}, 1) = 1
       ORDER BY CASE WHEN n.status = 'online' THEN 0 ELSE 1 END, n.is_local DESC, n.id ASC
       LIMIT 1`
    );
    if (preferred) return preferred;

    const fallback = await this.db.get<NodeRecord>(`SELECT * FROM nodes ORDER BY is_local DESC, id ASC LIMIT 1`);
    if (!fallback) {
      throw new Error('No nodes registered in TGVPANEL database.');
    }
    return fallback;
  }

  public async createNode(input: {
    name: string;
    hostname: string;
    ipAddress: string;
    location?: string;
    url: string;
    verifySsl?: boolean;
    mtlsEnabled?: boolean;
    supportsKvm?: boolean;
    supportsLxc?: boolean;
    maxInstances?: number;
    tags?: string[];
    notes?: string;
  }): Promise<{
    node: NodeRecord;
    bootstrapCredentials: { apiKey: string; hmacSecret: string };
  }> {
    const keyPair = generateApiKeyPair('hkvm_node');
    const hmacSecret = crypto.randomBytes(32).toString('hex');

    let createdId = 0;
    await this.db.transaction(async () => {
      const ins = await this.db.run(
        `INSERT INTO nodes
         (name, hostname, ip_address, location, url, is_local, verify_ssl, mtls_enabled, status, max_instances, tags, notes)
         VALUES (?, ?, ?, ?, ?, 0, ?, ?, 'provisioning', ?, ?, ?)`,
        [
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
        ]
      );
      createdId = ins.lastID;

      await this.db.run(
        `INSERT INTO node_credentials (node_id, api_key_prefix, api_key_hash, api_key_enc, hmac_secret_enc)
         VALUES (?, ?, ?, ?, ?)`,
        [
          createdId,
          keyPair.keyPrefix,
          keyPair.keyHash,
          encryptSecret(keyPair.rawKey),
          encryptSecret(hmacSecret),
        ]
      );

      await this.db.run(
        `INSERT INTO node_capabilities (node_id, supports_kvm, supports_lxc)
         VALUES (?, ?, ?)`,
        [
          createdId,
          input.supportsKvm !== false ? 1 : 0,
          input.supportsLxc !== false ? 1 : 0,
        ]
      );
    });

    const node = (await this.getNodeById(createdId))!;
    return {
      node,
      bootstrapCredentials: {
        apiKey: keyPair.rawKey,
        hmacSecret,
      },
    };
  }

  public async updateNode(
    nodeId: number,
    patch: {
      name?: string;
      hostname?: string;
      ipAddress?: string;
      location?: string;
      url?: string;
      maintenanceMode?: boolean;
      verifySsl?: boolean;
      maxInstances?: number;
      supportsKvm?: boolean;
      supportsLxc?: boolean;
      notes?: string;
    }
  ): Promise<NodeRecord> {
    const existing = await this.getNodeById(nodeId);
    if (!existing) throw new Error(`Node #${nodeId} not found.`);

    await this.db.run(
      `UPDATE nodes SET
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
       WHERE id = ?`,
      [
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
      ]
    );

    if (patch.supportsKvm !== undefined || patch.supportsLxc !== undefined) {
      await this.db.run(
        `UPDATE node_capabilities SET
           supports_kvm = COALESCE(?, supports_kvm),
           supports_lxc = COALESCE(?, supports_lxc),
           updated_at = datetime('now')
         WHERE node_id = ?`,
        [
          patch.supportsKvm !== undefined ? (patch.supportsKvm ? 1 : 0) : null,
          patch.supportsLxc !== undefined ? (patch.supportsLxc ? 1 : 0) : null,
          nodeId,
        ]
      );
    }

    return (await this.getNodeById(nodeId))!;
  }

  public async deleteNode(nodeId: number): Promise<void> {
    const node = await this.getNodeById(nodeId);
    if (!node) throw new Error(`Node #${nodeId} not found.`);
    if (node.is_local) {
      throw new Error('Cannot delete the built-in localhost controller node.');
    }

    const activeCount = await this.db.get<{ cnt: number }>(
      `SELECT COUNT(*) AS cnt FROM instances WHERE node_id = ?`,
      [nodeId]
    );
    if ((activeCount?.cnt || 0) > 0) {
      throw new Error(
        `Cannot remove node "${node.name}" while ${activeCount?.cnt} instance(s) are still assigned to it.`
      );
    }

    await this.db.run(`DELETE FROM nodes WHERE id = ?`, [nodeId]);
  }

  public async rotateNodeCredentials(
    nodeId: number
  ): Promise<{ apiKey: string; hmacSecret: string; pushedToAgent: boolean }> {
    const node = await this.getNodeById(nodeId);
    if (!node) throw new Error(`Node #${nodeId} not found.`);

    const newPair = generateApiKeyPair('hkvm_node');
    const newHmac = crypto.randomBytes(32).toString('hex');
    let pushedToAgent = false;

    if (!node.is_local) {
      try {
        await this.requestRemoteNode(nodeId, 'POST', '/api/v1/credentials/rotate', {
          newApiKey: newPair.rawKey,
          newHmacSecret: newHmac,
        });
        pushedToAgent = true;
      } catch {
        pushedToAgent = false;
      }
    } else {
      pushedToAgent = true;
    }

    await this.db.run(
      `UPDATE node_credentials
       SET api_key_prefix = ?, api_key_hash = ?, api_key_enc = ?, hmac_secret_enc = ?, rotated_at = datetime('now')
       WHERE node_id = ?`,
      [
        newPair.keyPrefix,
        newPair.keyHash,
        encryptSecret(newPair.rawKey),
        encryptSecret(newHmac),
        nodeId,
      ]
    );

    return { apiKey: newPair.rawKey, hmacSecret: newHmac, pushedToAgent };
  }

  /**
   * Refreshes health, capabilities, and real host stats for a node (local or remote).
   */
  public async checkNodeHealthAndStats(nodeId: number): Promise<{
    node: NodeRecord;
    health: NodeHealthReport;
    stats: HostResourceStats;
  }> {
    const node = await this.getNodeById(nodeId);
    if (!node) throw new Error(`Node #${nodeId} not found.`);

    try {
      let health: NodeHealthReport;
      let stats: HostResourceStats;

      if (node.is_local) {
        health = await getNodeHealthReport(true);
        stats = await this.localRuntime.statsCollector.collect();
      } else {
        health = await this.requestRemoteNode<NodeHealthReport>(
          nodeId,
          'GET',
          '/api/v1/health?refresh=1'
        );
        stats = await this.requestRemoteNode<HostResourceStats>(nodeId, 'GET', '/api/v1/stats');
      }

      await this.db.run(
        `UPDATE nodes SET
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
         WHERE id = ?`,
        [
          health.agentVersion,
          stats.cpuCores,
          stats.cpuModel,
          stats.ramTotalMb,
          stats.diskTotalGb,
          nodeId,
        ]
      );

      await this.db.run(
        `INSERT INTO node_capabilities
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
           updated_at = datetime('now')`,
        [
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
        ]
      );

      this.recordCircuitSuccess(nodeId);
      const updatedNode = (await this.getNodeById(nodeId))!;
      return { node: updatedNode, health, stats };
    } catch (err: any) {
      await this.recordCircuitFailure(nodeId);
      throw err;
    }
  }

  private checkCircuitAllowed(nodeId: number): void {
    const entry = this.circuits.get(nodeId);
    if (!entry || entry.state === 'closed') return;
    if (entry.state === 'open') {
      if (Date.now() - entry.openedAt >= this.openCooldownMs) {
        entry.state = 'half-open';
        return;
      }
      throw new Error(
        `Circuit breaker OPEN for node #${nodeId}: remote node is unreachable. Retrying after cooldown.`
      );
    }
  }

  private recordCircuitSuccess(nodeId: number): void {
    this.circuits.set(nodeId, { state: 'closed', failures: 0, openedAt: 0 });
  }

  private async recordCircuitFailure(nodeId: number): Promise<void> {
    const prev = this.circuits.get(nodeId) || { state: 'closed', failures: 0, openedAt: 0 };
    const failures = prev.failures + 1;
    const state: 'closed' | 'open' =
      failures >= this.failureThreshold ? 'open' : 'closed';
    this.circuits.set(nodeId, {
      state,
      failures,
      openedAt: state === 'open' ? Date.now() : prev.openedAt,
    });
    await this.db.run(
      `UPDATE nodes SET status = 'offline', circuit_state = ?, consecutive_failures = ?, updated_at = datetime('now') WHERE id = ?`,
      [state, failures, nodeId]
    );
  }

  public async requestRemoteNode<T = any>(
    nodeId: number,
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    pathWithQuery: string,
    body?: unknown,
    timeoutMs = 30_000
  ): Promise<T> {
    this.checkCircuitAllowed(nodeId);

    const node = await this.getNodeById(nodeId);
    if (!node) throw new Error(`Node #${nodeId} not found.`);
    if (node.is_local) {
      throw new Error('Use localRuntime directly for localhost node operations.');
    }

    const creds = await this.db.get<{
      api_key_enc: string;
      hmac_secret_enc: string;
      tls_ca_pem: string | null;
      tls_client_cert_pem: string | null;
      tls_client_key_enc: string | null;
    }>(`SELECT * FROM node_credentials WHERE node_id = ?`, [nodeId]);

    if (!creds) {
      throw new Error(`Credentials missing for node #${nodeId}.`);
    }

    const rawApiKey = decryptSecret(creds.api_key_enc);
    const hmacSecret = decryptSecret(creds.hmac_secret_enc);
    const rawBody = body !== undefined ? JSON.stringify(body) : '';

    const signed = signAgentRequest({
      nodeId,
      apiKey: rawApiKey,
      hmacSecret,
      method,
      pathWithQuery,
      bodyBuffer: rawBody,
    });

    const targetUrl = new URL(pathWithQuery, node.url);
    const isHttps = targetUrl.protocol === 'https:';

    return new Promise<T>((resolve, reject) => {
      const reqOpts: https.RequestOptions = {
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
        if (creds.tls_ca_pem) reqOpts.ca = creds.tls_ca_pem;
        if (creds.tls_client_cert_pem && creds.tls_client_key_enc) {
          reqOpts.cert = creds.tls_client_cert_pem;
          reqOpts.key = decryptSecret(creds.tls_client_key_enc);
        }
      }

      const transport = isHttps ? https : http;
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
              resolve((respData ? JSON.parse(respData) : {}) as T);
            } catch {
              resolve(respData as unknown as T);
            }
          } else {
            let errMsg = `Remote node HTTP ${code}`;
            try {
              const parsed = JSON.parse(respData);
              if (parsed?.error) errMsg = parsed.error;
            } catch {
              if (respData) errMsg = respData.slice(0, 300);
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

  public async openRemoteAgentWebSocket(
    nodeId: number,
    wsPath: string,
    query: Record<string, string | number> = {}
  ): Promise<WebSocket> {
    const node = await this.getNodeById(nodeId);
    if (!node || node.is_local) {
      throw new Error(`Node #${nodeId} is not a remote node.`);
    }
    const creds = await this.db.get<{
      api_key_enc: string;
      hmac_secret_enc: string;
    }>(`SELECT api_key_enc, hmac_secret_enc FROM node_credentials WHERE node_id = ?`, [nodeId]);
    if (!creds) throw new Error(`Credentials missing for node #${nodeId}.`);

    const rawApiKey = decryptSecret(creds.api_key_enc);
    const hmacSecret = decryptSecret(creds.hmac_secret_enc);
    const signed = signAgentRequest({
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

    return new WebSocket(urlObj.toString(), {
      rejectUnauthorized: Boolean(node.verify_ssl),
      headers: {
        'X-HKVM-Node-Key': rawApiKey,
        ...signed,
      },
    });
  }
}
