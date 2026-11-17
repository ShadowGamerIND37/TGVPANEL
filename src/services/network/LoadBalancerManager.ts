import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { UnifiedDatabase } from '../../db/database';
import { isBinaryAvailable, runAllowlistedCommand } from '../../node-agent/command-runner';
import { SafeValidators } from '../../security/middleware';
import { NodeManager } from '../nodes/NodeClient';

const ALLOWED_PROTOCOLS = new Set(['tcp', 'http']);
const ALLOWED_ALGORITHMS = new Set(['roundrobin', 'leastconn', 'source']);

export interface LoadBalancerBackendInput {
  name: string;
  target: string;
  port: number;
  weight?: number;
  enabled?: boolean;
}

/**
 * HAProxy load balancer registry and lifecycle manager.
 *
 * The panel renders a complete HAProxy configuration from the registered
 * frontend + backend rows, validates it with `haproxy -c`, and starts/reloads
 * (or stops) the process on the target node via allowlisted host commands.
 * Nodes without the `haproxy` binary fail honestly — nothing is faked.
 */
export class LoadBalancerManager {
  private db: UnifiedDatabase;
  private nodeManager?: NodeManager;

  constructor(db: UnifiedDatabase, nodeManager?: NodeManager) {
    this.db = db;
    this.nodeManager = nodeManager;
  }

  private getConfigDir(): string {
    const dataDir = process.env.TGVPANEL_DATA_DIR || path.join(os.homedir(), 'vms');
    return path.join(dataDir, 'haproxy');
  }

  private configPath(name: string): string {
    return path.join(this.getConfigDir(), `${name}.cfg`);
  }

  private pidPath(name: string): string {
    return path.join(this.getConfigDir(), `${name}.pid`);
  }

  // --- Registry ---
  public async listLoadBalancers() {
    return this.db.all<any>(
      `SELECT lb.*, n.name AS node_name,
              (SELECT COUNT(*) FROM load_balancer_backends b WHERE b.load_balancer_id = lb.id) AS backend_count
       FROM load_balancers lb
       LEFT JOIN nodes n ON n.id = lb.node_id
       ORDER BY lb.id ASC`
    );
  }

  public async getLoadBalancer(id: number) {
    const lb = await this.db.get<any>(
      `SELECT lb.*, n.name AS node_name FROM load_balancers lb
       LEFT JOIN nodes n ON n.id = lb.node_id WHERE lb.id = ?`,
      [id]
    );
    if (!lb) return null;
    lb.backends = await this.db.all<any>(
      `SELECT * FROM load_balancer_backends WHERE load_balancer_id = ? ORDER BY position ASC, id ASC`,
      [id]
    );
    return lb;
  }

  private validateBackends(backends: LoadBalancerBackendInput[]): void {
    if (!Array.isArray(backends)) throw new Error('backends must be an array.');
    backends.forEach((backend, i) => {
      const label = `Backend ${i + 1}`;
      const name = String(backend.name || '').trim();
      if (!name || name.length > 60) throw new Error(`${label}: name is required (max 60 chars).`);
      const target = String(backend.target || '').trim();
      if (!target || target.length > 253) throw new Error(`${label}: target is required.`);
      if (!/^[0-9a-zA-Z._:-]+$/.test(target)) throw new Error(`${label}: invalid target.`);
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

  public async createLoadBalancer(input: {
    name: string;
    nodeId?: number;
    listenIp?: string;
    listenPort: number;
    protocol?: string;
    algorithm?: string;
    backends: LoadBalancerBackendInput[];
  }) {
    const name = SafeValidators.loadBalancerName(String(input.name || ''));
    const protocol = String(input.protocol || 'tcp').toLowerCase();
    if (!ALLOWED_PROTOCOLS.has(protocol)) throw new Error('protocol must be tcp or http.');
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

    const ins = await this.db.run(
      `INSERT INTO load_balancers (name, node_id, listen_ip, listen_port, protocol, algorithm, enabled)
       VALUES (?, ?, ?, ?, ?, ?, 1)`,
      [name, Number(input.nodeId || 1), listenIp, listenPort, protocol, algorithm]
    );
    const id = Number(ins.lastID);
    await this.replaceBackends(id, backends);
    return this.getLoadBalancer(id);
  }

  public async updateLoadBalancer(
    id: number,
    input: {
      name?: string;
      nodeId?: number;
      listenIp?: string;
      listenPort?: number;
      protocol?: string;
      algorithm?: string;
      enabled?: boolean;
      backends?: LoadBalancerBackendInput[];
    }
  ) {
    const existing = await this.getLoadBalancer(id);
    if (!existing) throw new Error('Load balancer does not exist.');
    const name = input.name !== undefined ? SafeValidators.loadBalancerName(String(input.name)) : existing.name;
    const protocol =
      input.protocol !== undefined
        ? String(input.protocol).toLowerCase()
        : String(existing.protocol);
    if (!ALLOWED_PROTOCOLS.has(protocol)) throw new Error('protocol must be tcp or http.');
    const algorithm =
      input.algorithm !== undefined
        ? String(input.algorithm).toLowerCase()
        : String(existing.algorithm);
    if (!ALLOWED_ALGORITHMS.has(algorithm)) {
      throw new Error('algorithm must be roundrobin, leastconn or source.');
    }
    const listenPort =
      input.listenPort !== undefined ? Number(input.listenPort) : Number(existing.listen_port);
    if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) {
      throw new Error('listenPort must be between 1 and 65535.');
    }
    const listenIp =
      input.listenIp !== undefined ? String(input.listenIp).trim() || '0.0.0.0' : existing.listen_ip;
    const nodeId = input.nodeId !== undefined ? Number(input.nodeId) : Number(existing.node_id);

    await this.db.run(
      `UPDATE load_balancers
       SET name = ?, node_id = ?, listen_ip = ?, listen_port = ?, protocol = ?, algorithm = ?, enabled = ?
       WHERE id = ?`,
      [
        name,
        nodeId,
        listenIp,
        listenPort,
        protocol,
        algorithm,
        input.enabled === false ? 0 : 1,
        id,
      ]
    );
    if (input.backends !== undefined) {
      this.validateBackends(input.backends);
      await this.replaceBackends(id, input.backends);
    }
    return this.getLoadBalancer(id);
  }

  private async replaceBackends(lbId: number, backends: LoadBalancerBackendInput[]) {
    await this.db.run(`DELETE FROM load_balancer_backends WHERE load_balancer_id = ?`, [lbId]);
    for (let i = 0; i < backends.length; i++) {
      const backend = backends[i];
      await this.db.run(
        `INSERT INTO load_balancer_backends
           (load_balancer_id, name, target, port, weight, enabled, position)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          lbId,
          String(backend.name).trim(),
          String(backend.target).trim(),
          Number(backend.port),
          Number(backend.weight ?? 1),
          backend.enabled === false ? 0 : 1,
          i,
        ]
      );
    }
  }

  public async deleteLoadBalancer(id: number): Promise<void> {
    const existing = await this.getLoadBalancer(id);
    if (!existing) return;
    // Best-effort stop so the host process does not keep serving stale config.
    await this.applyLoadBalancer(existing, 'stop').catch(() => undefined);
    await this.db.run(`DELETE FROM load_balancer_backends WHERE load_balancer_id = ?`, [id]);
    await this.db.run(`DELETE FROM load_balancers WHERE id = ?`, [id]);
  }

  // --- Config rendering & lifecycle ---
  public renderConfig(lb: any): string {
    const backends = Array.isArray(lb.backends) ? lb.backends : [];
    const enabledBackends = backends.filter((b: any) => Number(b.enabled) === 1);
    const lines: string[] = [
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
    } else {
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

  private async isRemoteNode(nodeId: number): Promise<boolean> {
    if (!this.nodeManager) return false;
    const node = await this.nodeManager.getNodeById(nodeId);
    return Boolean(node && !node.is_local);
  }

  /**
   * Validates the rendered config and starts/reloads/stops the HAProxy
   * process on the target node. Records honest validation/apply results on
   * the load balancer row.
   */
  public async applyLoadBalancer(
    lb: any,
    mode: 'start' | 'reload' | 'stop' = 'start'
  ): Promise<{ applied: boolean; validated: boolean; error?: string | null }> {
    const name = String(lb.name);
    const config = this.renderConfig(lb);
    const nodeId = Number(lb.node_id || 1);

    if (await this.isRemoteNode(nodeId)) {
      const node = await this.nodeManager!.getNodeById(nodeId);
      if (!node || node.status !== 'online') {
        await this.recordResult(lb.id, false, null, 'Target node is not online.');
        return { applied: false, validated: false, error: 'Target node is not online.' };
      }
      const res = await this.nodeManager!.requestRemoteNode<{ applied?: boolean; validated?: boolean; error?: string }>(
        nodeId,
        'POST',
        '/api/v1/load-balancers/apply',
        { name, config, mode },
        15_000
      );
      const validated = Boolean(res?.validated);
      const applied = Boolean(res?.applied);
      await this.recordResult(
        lb.id,
        applied,
        validated,
        res?.error || (!validated ? 'Remote HAProxy config validation failed.' : null)
      );
      return { applied, validated, error: res?.error || null };
    }

    if (!isBinaryAvailable('haproxy')) {
      const error = 'The haproxy binary is not available on this node.';
      await this.recordResult(lb.id, false, null, error);
      return { applied: false, validated: false, error };
    }

    fs.mkdirSync(this.getConfigDir(), { recursive: true });
    const cfgPath = this.configPath(name);
    const pidPath = this.pidPath(name);
    fs.writeFileSync(cfgPath, config, { mode: 0o640 });

    // 1. Validate the rendered configuration before touching a running process.
    const check = await runAllowlistedCommand('haproxy', ['-c', '-f', cfgPath], {
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
    } else if (mode === 'reload') {
      applyRes = await runAllowlistedCommand('haproxy', ['-sf', '-p', pidPath, '-f', cfgPath], {
        asRoot: true,
        timeoutMs: 10_000,
      });
    } else {
      applyRes = await runAllowlistedCommand('haproxy', ['-D', '-f', cfgPath, '-p', pidPath], {
        asRoot: true,
        timeoutMs: 10_000,
      });
    }
    const applied = applyRes.exitCode === 0;
    await this.recordResult(
      lb.id,
      applied,
      true,
      applied ? null : `HAProxy ${mode} failed: ${(applyRes.stderr || applyRes.stdout).trim()}`
    );
    return { applied, validated: true, error: applied ? null : `HAProxy ${mode} failed.` };
  }

  private async stopLocalProcess(pidPath: string): Promise<{ exitCode: number; stdout: string; stderr: string }> {
    try {
      if (!fs.existsSync(pidPath)) return { exitCode: 0, stdout: '', stderr: '' };
      const pid = Number(fs.readFileSync(pidPath, 'utf8').trim());
      if (!Number.isInteger(pid) || pid <= 0) {
        fs.unlinkSync(pidPath);
        return { exitCode: 0, stdout: '', stderr: '' };
      }
      const killRes = await runAllowlistedCommand('kill', ['-TERM', String(pid)], {
        asRoot: true,
        timeoutMs: 5_000,
      });
      if (killRes.exitCode !== 0) return killRes;
      fs.unlinkSync(pidPath);
      return killRes;
    } catch {
      return { exitCode: 0, stdout: '', stderr: '' };
    }
  }

  private async recordResult(
    lbId: number,
    applied: boolean,
    validated: boolean | null,
    error: string | null
  ): Promise<void> {
    await this.db.run(
      `UPDATE load_balancers
       SET last_applied_at = CASE WHEN ? = 1 THEN datetime('now') ELSE last_applied_at END,
           last_validated_at = CASE WHEN ? IS NOT NULL AND ? = 1 THEN datetime('now') ELSE last_validated_at END,
           last_error = ?
       WHERE id = ?`,
      [applied ? 1 : 0, validated, validated, error, lbId]
    );
  }

  public async getLoadBalancerStatus(id: number) {
    const lb = await this.getLoadBalancer(id);
    if (!lb) return null;
    let running = false;
    if (Number(lb.node_id || 1) === 1 || !this.nodeManager) {
      try {
        running = fs.existsSync(this.pidPath(String(lb.name)));
      } catch {
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
