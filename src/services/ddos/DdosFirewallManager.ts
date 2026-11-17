import { execFile } from 'child_process';
import { promisify } from 'util';
import type { UnifiedDatabase } from '../../db/database';

const execFileAsync = promisify(execFile);

const isLinux = process.platform === 'linux';
const RULE_TAG = 'TGVPANEL_DDOS';

export interface FirewallResult {
  success: boolean;
  message: string;
  ruleId?: string;
  error?: string;
}

function isValidIP(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;
  // IPv4
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    for (const p of parts) {
      if (p === '' || !/^\d{1,3}$/.test(p) || parseInt(p, 10) > 255) return false;
    }
    if (ip === '0.0.0.0' || ip === '255.255.255.255') return false;
    return true;
  }
  // IPv6 (basic check)
  if (ip.includes(':')) {
    return /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':');
  }
  return false;
}

function isPrivateIP(ip: string): boolean {
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.') || ip.startsWith('169.254.')) return true;
  if (ip === '127.0.0.1' || ip.startsWith('127.')) return true;
  if (ip.startsWith('224.') || ip.startsWith('240.')) return true;
  return false;
}

function generateRuleId(): string {
  return `${RULE_TAG}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Safe firewall operations manager for DDoS mitigation.
 *
 * Uses nftables when available (preferred), falls back to iptables/ip6tables.
 * Every rule created is tracked with a unique rule ID and stored in the
 * `ddos_firewall_rules` table so it can be precisely rolled back without
 * ever flushing unrelated rules. A process-level lock prevents concurrent
 * firewall mutations. Private/management IPs are never blocked.
 */
export class DdosFirewallManager {
  private db: UnifiedDatabase;
  private lock: Promise<void> = Promise.resolve();
  private nftAvailable: boolean | null = null;

  constructor(db: UnifiedDatabase) {
    this.db = db;
  }

  public isLinux(): boolean {
    return isLinux;
  }

  private async withLock<T>(fn: () => Promise<T>): Promise<T> {
    let release: () => void;
    const prev = this.lock;
    this.lock = new Promise<void>((resolve) => { release = resolve; });
    await prev;
    try {
      return await fn();
    } finally {
      release!();
    }
  }

  private async runCmd(cmd: string, asRoot = true): Promise<string> {
    const args = asRoot && typeof process.getuid === 'function' && process.getuid() !== 0
      ? ['-n', 'bash', '-c', cmd]
      : ['-c', cmd];
    const execCmd = asRoot && typeof process.getuid === 'function' && process.getuid() !== 0
      ? `sudo -n bash -c ${JSON.stringify(cmd)}`
      : cmd;
    const { stdout } = await execFileAsync(execCmd, { shell: '/bin/bash', maxBuffer: 1024 * 1024 });
    return stdout;
  }

  private async isNftAvailable(): Promise<boolean> {
    if (this.nftAvailable !== null) return this.nftAvailable;
    if (!isLinux) { this.nftAvailable = false; return false; }
    try {
      const { stdout } = await execFileAsync('nft -V', { shell: '/bin/bash' });
      this.nftAvailable = stdout.includes('nft') || stdout.length > 0;
    } catch {
      this.nftAvailable = false;
    }
    return this.nftAvailable;
  }

  private async audit(action: string, target: string, success: boolean, detail?: string, user_id?: number): Promise<void> {
    await this.db.run(
      `INSERT INTO ddos_audit_log (action, target, method, success, detail, user_id) VALUES (?, ?, ?, ?, ?, ?)`,
      [action, target, this.nftAvailable ? 'nftables' : 'iptables', success ? 1 : 0, detail || null, user_id || null]
    );
  }

  public async blockIP(ip: string, protocol?: string, port?: string, nodeId?: number, vpsId?: number, userId?: number): Promise<FirewallResult> {
    if (!isLinux) return { success: false, message: 'Firewall operations require Linux.' };
    if (!isValidIP(ip)) return { success: false, message: 'Invalid IP address.' };
    if (isPrivateIP(ip)) return { success: false, message: 'Cannot block private/management IP.' };

    return this.withLock(async () => {
      const ruleId = generateRuleId();
      try {
        const nft = await this.isNftAvailable();
        if (nft) {
          // nftables: create a dedicated chain and add a drop rule
          const chainName = `TGVPANEL_DDOS_BLOCK`;
          const tableName = 'tgvpanel_ddos';
          // Ensure table + chain exist
          await this.runCmd(`nft add table ${tableName} 2>/dev/null || true`);
          await this.runCmd(`nft add chain ${tableName} ${chainName} { type filter hook input priority -100 \; 2>/dev/null || true`);
          // Build match spec
          const match = protocol ? `ip protocol ${protocol} ` : '';
          const portSpec = port ? ` th port ${port} ` : '';
          await this.runCmd(`nft add rule ${tableName} ${chainName} ip saddr ${ip} ${match}${portSpec} drop`);
        } else {
          // iptables fallback
          const iptablesBin = ip.includes(':') ? 'ip6tables' : 'iptables';
          const protocolSpec = protocol && protocol !== 'all' ? `-p ${protocol} ` : '';
          const portSpec = port ? `--dport ${port} ` : '';
          // Check if already blocked
          const check = await this.runCmd(`${iptablesBin} -C INPUT -s ${ip} ${protocolSpec}${portSpec} -j DROP 2>&1`);
          if (check.trim() === '0') {
            await this.runCmd(`${iptablesBin} -I INPUT -s ${ip} ${protocolSpec}${portSpec} -j DROP`);
          }
        }

        await this.db.run(
          `INSERT INTO ddos_firewall_rules (rule_id, ip, protocol, port, action, direction, table_name, chain, node_id, vps_id, created_at, active)
           VALUES (?, ?, ?, ?, 'DROP', 'INPUT', ?, ?, ?, ?, ?, 1)`,
          [ruleId, ip, protocol || null, port || null, this.nftAvailable ? 'nftables' : 'iptables', this.nftAvailable ? 'tgvpanel_ddos/TGVPANEL_DDOS_BLOCK' : 'filter/INPUT', nodeId || null, vpsId || null, Date.now()]
        );
        await this.audit('block', ip, true, `rule_id=${ruleId}`, userId);
        return { success: true, message: 'IP blocked', ruleId };
      } catch (err: any) {
        await this.audit('block', ip, false, err.message, userId);
        return { success: false, message: 'Block failed', error: err.message };
      }
    });
  }

  public async unblockIP(ip: string, userId?: number): Promise<FirewallResult> {
    if (!isLinux) return { success: false, message: 'Firewall operations require Linux.' };
    if (!isValidIP(ip)) return { success: false, message: 'Invalid IP address.' };

    return this.withLock(async () => {
      try {
        // Find and roll back all active rules for this IP
        const rules = await this.db.all<{ rule_id: string; protocol: string | null; port: string | null; table_name: string; chain: string }>(
          `SELECT * FROM ddos_firewall_rules WHERE ip = ? AND active = 1`, [ip]
        );
        let count = 0;
        for (const rule of rules) {
          try {
            if (rule.table_name.includes('nftables') || rule.table_name.includes('tgvpanel_ddos')) {
              const match = rule.protocol ? `ip protocol ${rule.protocol} ` : '';
              const portSpec = rule.port ? ` th port ${rule.port} ` : '';
              await this.runCmd(`nft delete rule tgvpanel_ddos TGVPANEL_DDOS_BLOCK ip saddr ${ip} ${match}${portSpec} drop 2>/dev/null || true`);
            } else {
              const iptablesBin = ip.includes(':') ? 'ip6tables' : 'iptables';
              const protocolSpec = rule.protocol && rule.protocol !== 'all' ? `-p ${rule.protocol} ` : '';
              const portSpec = rule.port ? `--dport ${rule.port} ` : '';
              await this.runCmd(`${iptablesBin} -D INPUT -s ${ip} ${protocolSpec}${portSpec} -j DROP 2>/dev/null || true`);
            }
            await this.db.run(`UPDATE ddos_firewall_rules SET active = 0, rolled_back = 1 WHERE rule_id = ?`, [rule.rule_id]);
            count++;
          } catch (err: any) {
            await this.db.run(`UPDATE ddos_firewall_rules SET active = 0, rolled_back = 0 WHERE rule_id = ?`, [rule.rule_id]);
          }
        }
        await this.audit('unblock', ip, count > 0, `rules_removed=${count}`, userId);
        return { success: count > 0, message: count > 0 ? `IP unblocked (${count} rules)` : 'IP was not actively blocked' };
      } catch (err: any) {
        await this.audit('unblock', ip, false, err.message, userId);
        return { success: false, message: 'Unblock failed', error: err.message };
      }
    });
  }

  public async rollbackAll(userId?: number): Promise<FirewallResult> {
    if (!isLinux) return { success: false, message: 'Firewall operations require Linux.' };
    return this.withLock(async () => {
      try {
        const rules = await this.db.all<{ rule_id: string; ip: string; protocol: string | null; port: string | null; table_name: string }>(
          `SELECT * FROM ddos_firewall_rules WHERE active = 1`
        );
        let count = 0;
        for (const rule of rules) {
          try {
            if (rule.table_name.includes('nftables') || rule.table_name.includes('tgvpanel_ddos')) {
              const match = rule.protocol ? `ip protocol ${rule.protocol} ` : '';
              const portSpec = rule.port ? ` th port ${rule.port} ` : '';
              await this.runCmd(`nft delete rule tgvpanel_ddos TGVPANEL_DDOS_BLOCK ip saddr ${rule.ip} ${match}${portSpec} drop 2>/dev/null || true`);
            } else {
              const iptablesBin = rule.ip.includes(':') ? 'ip6tables' : 'iptables';
              const protocolSpec = rule.protocol && rule.protocol !== 'all' ? `-p ${rule.protocol} ` : '';
              const portSpec = rule.port ? `--dport ${rule.port} ` : '';
              await this.runCmd(`${iptablesBin} -D INPUT -s ${rule.ip} ${protocolSpec}${portSpec} -j DROP 2>/dev/null || true`);
            }
            await this.db.run(`UPDATE ddos_firewall_rules SET active = 0, rolled_back = 1 WHERE rule_id = ?`, [rule.rule_id]);
            count++;
          } catch {
            await this.db.run(`UPDATE ddos_firewall_rules SET active = 0, rolled_back = 0 WHERE rule_id = ?`, [rule.rule_id]);
          }
        }
        await this.audit('rollback_all', 'all', count > 0, `rules_rolled_back=${count}`, userId);
        return { success: count > 0, message: `Rolled back ${count} firewall rules` };
      } catch (err: any) {
        await this.audit('rollback_all', 'all', false, err.message, userId);
        return { success: false, message: 'Rollback failed', error: err.message };
      }
    });
  }

  public async listRules(ip?: string): Promise<unknown[]> {
    let query = `SELECT * FROM ddos_firewall_rules WHERE active = 1`;
    const params: unknown[] = [];
    if (ip) { query += ` AND ip = ?`; params.push(ip); }
    query += ` ORDER BY created_at DESC`;
    return this.db.all(query, params);
  }

  public async applySynCookies(enabled: boolean, userId?: number): Promise<FirewallResult> {
    if (!isLinux) return { success: false, message: 'Firewall operations require Linux.' };
    return this.withLock(async () => {
      try {
        const value = enabled ? '1' : '0';
        await this.runCmd(`sysctl -w net.ipv4.tcp_syncookies=${value} 2>/dev/null || true`);
        await this.audit('syn_cookies', enabled ? 'on' : 'off', true, '', userId);
        return { success: true, message: `SYN cookies ${enabled ? 'enabled' : 'disabled'}` };
      } catch (err: any) {
        await this.audit('syn_cookies', enabled ? 'on' : 'off', false, err.message, userId);
        return { success: false, message: 'SYN cookies failed', error: err.message };
      }
    });
  }

  public async applyConnectionLimit(limit: number, userId?: number): Promise<FirewallResult> {
    if (!isLinux) return { success: false, message: 'Firewall operations require Linux.' };
    if (limit < 1) return { success: false, message: 'Connection limit must be >= 1.' };
    return this.withLock(async () => {
      try {
        await this.runCmd(`sysctl -w net.core.somaxconn=${limit} 2>/dev/null || true`);
        await this.audit('connection_limit', String(limit), true, '', userId);
        return { success: true, message: `Connection limit set to ${limit}` };
      } catch (err: any) {
        await this.audit('connection_limit', String(limit), false, err.message, userId);
        return { success: false, message: 'Connection limit failed', error: err.message };
      }
    });
  }

  public async applyPacketRateLimit(rate: number, userId?: number): Promise<FirewallResult> {
    if (!isLinux) return { success: false, message: 'Firewall operations require Linux.' };
    if (rate <= 0) return { success: false, message: 'Rate must be > 0.' };
    return this.withLock(async () => {
      try {
        // Use iptables hashlimit or tc; here we set an iptables rate limit on INPUT
        const nft = await this.isNftAvailable();
        if (nft) {
          await this.runCmd(`nft add table tgvpanel_ddos 2>/dev/null || true`);
          await this.runCmd(`nft add chain tgvpanel_ddos RATE_LIMIT { type filter hook input priority -90 \; 2>/dev/null || true`);
          await this.runCmd(`nft add rule tgvpanel_ddos RATE_LIMIT limit rate ${rate}/min burst ${Math.ceil(rate / 10)}/min drop`);
        } else {
          await this.runCmd(`iptables -I INPUT -m limit --limit ${rate}/min --limit-burst ${Math.ceil(rate / 10)} -j DROP 2>/dev/null || true`);
        }
        await this.audit('packet_rate_limit', String(rate), true, '', userId);
        return { success: true, message: `Packet rate limit set to ${rate}/min` };
      } catch (err: any) {
        await this.audit('packet_rate_limit', String(rate), false, err.message, userId);
        return { success: false, message: 'Packet rate limit failed', error: err.message };
      }
    });
  }

  public async emergencyMode(enabled: boolean, userId?: number): Promise<FirewallResult> {
    if (!isLinux) return { success: false, message: 'Firewall operations require Linux.' };
    return this.withLock(async () => {
      try {
        if (enabled) {
          // Aggressive mode: enable SYN cookies, tighten connection limits
          await this.runCmd(`sysctl -w net.ipv4.tcp_syncookies=1 2>/dev/null || true`);
          await this.runCmd(`sysctl -w net.ipv4.tcp_max_syn_backlog=2048 2>/dev/null || true`);
        }
        await this.audit('emergency_mode', enabled ? 'on' : 'off', true, '', userId);
        return { success: true, message: `Emergency mode ${enabled ? 'enabled' : 'disabled'}` };
      } catch (err: any) {
        await this.audit('emergency_mode', enabled ? 'on' : 'off', false, err.message, userId);
        return { success: false, message: 'Emergency mode failed', error: err.message };
      }
    });
  }

  public async getStatus(): Promise<{ nftables: boolean; iptables: boolean; active_rules: number; engine: string }> {
    const nft = await this.isNftAvailable();
    const ruleCount = await this.db.get<{ total: number }>(`SELECT COUNT(*) as total FROM ddos_firewall_rules WHERE active = 1`);
    return {
      nftables: nft,
      iptables: !nft,
      active_rules: ruleCount?.total || 0,
      engine: nft ? 'nftables' : 'iptables',
    };
  }
}
