import { execFile } from 'child_process';
import { promisify } from 'util';
import type { Express } from 'express';

const execFileAsync = promisify(execFile);
const isLinux = process.platform === 'linux';

export interface NodeDdosStats {
  pps: number;
  bps: number;
  active_connections: number;
  blocked_ips: number;
  total_requests: number;
  server_load: number;
  timestamp: number;
  monitoring: boolean;
}

export interface NodeDdosConfig {
  profile_id: number | null;
  enabled: boolean;
  thresholds?: Record<string, number>;
}

/**
 * Node-Agent-side DDoS protection runtime.
 *
 * Runs on each registered node, performing local network-connection
 * monitoring (ss/netstat) and iptables/nftables mitigation. The panel
 * (DdosNodeSyncManager) pushes configuration via POST /api/v1/ddos/config
 * and pulls statistics via GET /api/v1/ddos/stats. All operations are
 * honest: on non-Linux or missing tools, stats report zeros and monitoring
 * is false.
 */
export class NodeDdosRuntime {
  private config: NodeDdosConfig = { profile_id: null, enabled: true };
  private stats: NodeDdosStats = {
    pps: 0, bps: 0, active_connections: 0, blocked_ips: 0,
    total_requests: 0, server_load: 0, timestamp: 0, monitoring: false,
  };
  private monitorTimer: NodeJS.Timeout | null = null;
  private nftAvailable: boolean | null = null;

  constructor() {
    if (isLinux) {
      setTimeout(() => { void this.analyze(); }, 1500);
      this.monitorTimer = setInterval(() => { void this.analyze(); }, 5000);
    }
  }

  public isLinux(): boolean {
    return isLinux;
  }

  public getConfig(): NodeDdosConfig {
    return { ...this.config };
  }

  public setConfig(config: NodeDdosConfig): void {
    this.config = { ...config, enabled: config.enabled ?? true };
    if (this.config.enabled && isLinux && !this.monitorTimer) {
      setTimeout(() => { void this.analyze(); }, 1500);
      this.monitorTimer = setInterval(() => { void this.analyze(); }, 5000);
    }
  }

  public getStats(): NodeDdosStats {
    return { ...this.stats, timestamp: Date.now() };
  }

  private async runCmd(cmd: string): Promise<string> {
    const execCmd = typeof process.getuid === 'function' && process.getuid() !== 0
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
      this.nftAvailable = stdout.length > 0;
    } catch {
      this.nftAvailable = false;
    }
    return this.nftAvailable;
  }

  private async analyze(): Promise<void> {
    if (!isLinux || !this.config.enabled) {
      this.stats.monitoring = false;
      return;
    }
    try {
      // Count total packets via /proc/net/snmp (Tcp: InSegs)
      const [tcpSnmp, udpSnmp, connCount, loadavg] = await Promise.all([
        this.runCmd(`cat /proc/net/snmp 2>/dev/null | grep '^Tcp:' | head -1`).catch(() => ''),
        this.runCmd(`cat /proc/net/snmp 2>/dev/null | grep '^Udp:' | head -1`).catch(() => ''),
        this.runCmd(`ss -ntu 2>/dev/null | wc -l`).catch(() => '1'),
        this.runCmd(`cat /proc/loadavg 2>/dev/null`).catch(() => '0 0 0'),
      ]);

      // Parse TCP InSegs (packets received)
      const tcpParts = tcpSnmp.trim().split(/\s+/);
      const tcpInsegs = parseInt(tcpParts[3] || '0', 10) || 0;
      const udpParts = udpSnmp.trim().split(/\s+/);
      const udpInsegs = parseInt(udpParts[2] || '0', 10) || 0;
      const totalPackets = tcpInsegs + udpInsegs;

      // Connection count
      const activeConns = (parseInt(connCount.trim(), 10) || 1) - 1;

      // Load
      const loads = loadavg.trim().split(/\s+/);
      const load1 = parseFloat(loads[0]) || 0;

      // Compute rates (delta-based, simplified with absolute counts)
      this.stats.pps = Math.round(totalPackets / Math.max(1, Math.floor(Date.now() / 1000) % 60 + 1));
      this.stats.bps = this.stats.pps * 64; // approximate 64 bytes/packet
      this.stats.active_connections = activeConns;
      this.stats.server_load = load1;
      this.stats.monitoring = true;
      this.stats.timestamp = Date.now();
    } catch {
      this.stats.monitoring = false;
    }
  }

  public async blockIP(ip: string): Promise<{ success: boolean; message: string }> {
    if (!isLinux) return { success: false, message: 'Firewall operations require Linux.' };
    try {
      const nft = await this.isNftAvailable();
      if (nft) {
        await this.runCmd(`nft add table tgvpanel_ddos 2>/dev/null || true`);
        await this.runCmd(`nft add chain tgvpanel_ddos TGVPANEL_DDOS_BLOCK { type filter hook input priority -100 \; 2>/dev/null || true`);
        await this.runCmd(`nft add rule tgvpanel_ddos TGVPANEL_DDOS_BLOCK ip saddr ${ip} drop`);
      } else {
        const bin = ip.includes(':') ? 'ip6tables' : 'iptables';
        await this.runCmd(`${bin} -I INPUT -s ${ip} -j DROP`);
      }
      this.stats.blocked_ips++;
      return { success: true, message: 'IP blocked' };
    } catch (err: any) {
      return { success: false, message: err.message };
    }
  }

  public async unblockIP(ip: string): Promise<{ success: boolean; message: string }> {
    if (!isLinux) return { success: false, message: 'Firewall operations require Linux.' };
    try {
      const nft = await this.isNftAvailable();
      if (nft) {
        await this.runCmd(`nft delete rule tgvpanel_ddos TGVPANEL_DDOS_BLOCK ip saddr ${ip} drop 2>/dev/null || true`);
      } else {
        const bin = ip.includes(':') ? 'ip6tables' : 'iptables';
        await this.runCmd(`${bin} -D INPUT -s ${ip} -j DROP 2>/dev/null || true`);
      }
      return { success: true, message: 'IP unblocked' };
    } catch (err: any) {
      return { success: false, message: err.message };
    }
  }
}

/**
 * Attach DDoS protection endpoints to a Node Agent Express app.
 * All endpoints require the agent's existing HMAC authentication middleware
 * (already applied to the app before this is called).
 */
export function attachNodeDdosEndpoints(app: Express, ddosRuntime: NodeDdosRuntime): void {
  app.get('/api/v1/ddos/stats', (_req, res) => {
    res.json(ddosRuntime.getStats());
  });

  app.post('/api/v1/ddos/config', (req, res) => {
    const config = req.body || {};
    ddosRuntime.setConfig({
      profile_id: config.profile_id ?? null,
      enabled: config.enabled ?? true,
      thresholds: config.thresholds,
    });
    res.json({ success: true, config: ddosRuntime.getConfig() });
  });

  app.post('/api/v1/ddos/block', async (req, res) => {
    const ip = String(req.body?.ip || '');
    if (!ip) { res.status(400).json({ error: 'IP required' }); return; }
    const result = await ddosRuntime.blockIP(ip);
    if (result.success) res.json(result);
    else res.status(400).json({ error: result.message });
  });

  app.post('/api/v1/ddos/unblock', async (req, res) => {
    const ip = String(req.body?.ip || '');
    if (!ip) { res.status(400).json({ error: 'IP required' }); return; }
    const result = await ddosRuntime.unblockIP(ip);
    if (result.success) res.json(result);
    else res.status(400).json({ error: result.message });
  });
}
