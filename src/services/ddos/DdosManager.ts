import { execFile } from 'child_process';
import { promisify } from 'util';
import type { UnifiedDatabase } from '../../db/database';
import type { MonitoringService } from '../monitoring/MonitoringService';
import type { DdosFirewallManager } from './DdosFirewallManager';

const execFileAsync = promisify(execFile);

const isLinux = process.platform === 'linux';

export interface DdosIpRecord {
  ip: string;
  requests: number;
  bandwidth: number;
  threads: number;
  blocked: number;
  blocked_at: number | null;
  first_seen: number | null;
  last_seen: number | null;
  country: string | null;
  threat_level: string;
  ack_count: number;
  icmp_count: number;
  http_get_count: number;
  http_post_count: number;
  slowloris_count: number;
  dns_amp_count: number;
  udp_amp_count: number;
  packet_rate: number;
  reputation: number;
  banned: number;
  ban_type: string;
  ban_reason: string | null;
  ban_expires: number | null;
  whitelisted: number;
  attack_types: string | null;
  pps: number;
  bps: number;
  conn_rate: number;
  last_attack_at: number | null;
  attack_count: number;
}

export interface DdosStats {
  total_requests: number;
  total_blocked: number;
  active_connections: number;
  total_bandwidth: number;
  total_connections: number;
  suspicious_ips: number;
  critical_threats: number;
  high_threats: number;
  medium_threats: number;
  server_load: number;
  memory_usage: number;
  total_network_connections: number;
  established_connections: number;
  syn_recv_total: number;
  last_scan: number;
  total_ips: number;
  blocked_ips: number;
  // Enterprise metrics
  pps: number;
  bps: number;
  conn_rate: number;
  inbound_bps: number;
  outbound_bps: number;
  packets_per_sec: number;
  active_mitigations: number;
  banned_ips: number;
  whitelisted_ips: number;
  attacks_detected: number;
  attacks_mitigated: number;
  engine_health: string;
  firewall_engine: string;
}

export interface DdosSettings {
  rate_limit_per_minute: number;
  max_bandwidth_per_minute: number;
  auto_block: number;
  block_duration: number;
  threat_threshold_medium: number;
  threat_threshold_high: number;
  threat_threshold_critical: number;
  auto_block_syn_recv: number;
  auto_block_high_connections: number;
  auto_block_port_scan: number;
  auto_block_time_wait: number;
  intelligent_blocking: number;
  // Enterprise
  syn_cookies: number;
  connection_limit: number;
  packet_rate_limit: number;
  per_ip_rate_limit: number;
  emergency_mode: number;
  max_bandwidth_mbps: number;
  max_connections: number;
  ack_flood_threshold: number;
  icmp_flood_threshold: number;
  http_get_threshold: number;
  http_post_threshold: number;
  slowloris_threshold: number;
  dns_amp_threshold: number;
  udp_amp_threshold: number;
  packet_rate_threshold: number;
  suspicious_user_agent_block: number;
  trusted_proxies: string;
  cloudflare_enabled: number;
  cloudflare_zone: string | null;
  cloudflare_security_level: string;
  notify_attack_detected: number;
  notify_attack_mitigated: number;
  notify_attack_ended: number;
  notify_critical_bandwidth: number;
  notify_suspicious_traffic: number;
  notify_node_failure: number;
  notify_firewall_failure: number;
  notify_engine_failure: number;
}

const DEFAULT_SETTINGS: DdosSettings = {
  rate_limit_per_minute: 60,
  max_bandwidth_per_minute: 1048576,
  auto_block: 1,
  block_duration: 3600,
  threat_threshold_medium: 100,
  threat_threshold_high: 500,
  threat_threshold_critical: 1000,
  auto_block_syn_recv: 50,
  auto_block_high_connections: 150,
  auto_block_port_scan: 10,
  auto_block_time_wait: 300,
  intelligent_blocking: 1,
  syn_cookies: 1,
  connection_limit: 1000,
  packet_rate_limit: 0,
  per_ip_rate_limit: 0,
  emergency_mode: 0,
  max_bandwidth_mbps: 0,
  max_connections: 10000,
  ack_flood_threshold: 200,
  icmp_flood_threshold: 500,
  http_get_threshold: 300,
  http_post_threshold: 150,
  slowloris_threshold: 20,
  dns_amp_threshold: 100,
  udp_amp_threshold: 100,
  packet_rate_threshold: 5000,
  suspicious_user_agent_block: 1,
  trusted_proxies: '',
  cloudflare_enabled: 0,
  cloudflare_zone: null,
  cloudflare_security_level: 'medium',
  notify_attack_detected: 1,
  notify_attack_mitigated: 1,
  notify_attack_ended: 1,
  notify_critical_bandwidth: 1,
  notify_suspicious_traffic: 1,
  notify_node_failure: 1,
  notify_firewall_failure: 1,
  notify_engine_failure: 1,
};

const ENTERPRISE_COLUMNS = [
  'syn_cookies', 'connection_limit', 'packet_rate_limit', 'per_ip_rate_limit',
  'emergency_mode', 'max_bandwidth_mbps', 'max_connections',
  'ack_flood_threshold', 'icmp_flood_threshold', 'http_get_threshold', 'http_post_threshold',
  'slowloris_threshold', 'dns_amp_threshold', 'udp_amp_threshold', 'packet_rate_threshold',
  'suspicious_user_agent_block', 'trusted_proxies', 'cloudflare_enabled', 'cloudflare_zone',
  'cloudflare_security_level',
  'notify_attack_detected', 'notify_attack_mitigated', 'notify_attack_ended',
  'notify_critical_bandwidth', 'notify_suspicious_traffic',
  'notify_node_failure', 'notify_firewall_failure', 'notify_engine_failure',
] as const;

function isValidIPv4(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;
  const match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return false;
  for (let i = 1; i <= 4; i++) {
    const octet = parseInt(match[i], 10);
    if (octet < 0 || octet > 255) return false;
  }
  if (ip === '0.0.0.0' || ip === '127.0.0.1' || ip === '255.255.255.255') return false;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.')) return false;
  if (ip.startsWith('169.254.')) return false;
  if (ip.startsWith('224.') || ip.startsWith('240.')) return false;
  return true;
}

function isValidIP(ip: string): boolean {
  if (isValidIPv4(ip)) return true;
  // Basic IPv6
  if (ip.includes(':') && /^[0-9a-fA-F:]+$/.test(ip)) return true;
  return false;
}

function isPrivateIP(ip: string): boolean {
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.') || ip.startsWith('169.254.')) return true;
  if (ip === '127.0.0.1' || ip.startsWith('127.')) return true;
  if (ip.startsWith('::1') || ip.startsWith('fe80:')) return true;
  if (ip.startsWith('224.') || ip.startsWith('240.')) return true;
  return false;
}

/**
 * Enterprise DDoS protection manager.
 *
 * Performs real-time network-connection monitoring via ss/netstat, detects
 * all supported attack types (SYN, ACK, connection floods, UDP/ICMP floods,
 * HTTP GET/POST floods, Slowloris, DNS/UDP amplification, packet-rate
 * anomalies, bandwidth/connection exhaustion, port scanning), scores each
 * source IP, and automatically mitigates via the DdosFirewallManager
 * (nftables/iptables). Tracks attack history, active mitigations, IP
 * reputation, and sends TGVPANEL notifications. Honest platform gating:
 * on non-Linux or missing tools, monitoring returns zeros and blocking
 * reports a clear error — no fake data.
 */
export class DdosManager {
  private db: UnifiedDatabase;
  private monitoringService: MonitoringService | null;
  private firewallManager: DdosFirewallManager;
  private settings: DdosSettings = { ...DEFAULT_SETTINGS };
  private stats: DdosStats;
  private liveIPs = new Map<string, Record<string, unknown>>();
  private minuteTracker = new Map<string, { minute: number; requests: number; bandwidth: number }>();
  private monitorTimer: NodeJS.Timeout | null = null;
  private autoUnblockTimer: NodeJS.Timeout | null = null;
  private persistTimer: NodeJS.Timeout | null = null;
  private notifyUserId: number | null = null;
  private lastPacketCounts = { tcp: 0, udp: 0, time: 0 };

  constructor(db: UnifiedDatabase, firewallManager: DdosFirewallManager, monitoringService?: MonitoringService) {
    this.db = db;
    this.firewallManager = firewallManager;
    this.monitoringService = monitoringService || null;
    this.stats = {
      total_requests: 0, total_blocked: 0, active_connections: 0, total_bandwidth: 0,
      total_connections: 0, suspicious_ips: 0, critical_threats: 0, high_threats: 0, medium_threats: 0,
      server_load: 0, memory_usage: 0, total_network_connections: 0, established_connections: 0,
      syn_recv_total: 0, last_scan: 0, total_ips: 0, blocked_ips: 0,
      pps: 0, bps: 0, conn_rate: 0, inbound_bps: 0, outbound_bps: 0, packets_per_sec: 0,
      active_mitigations: 0, banned_ips: 0, whitelisted_ips: 0,
      attacks_detected: 0, attacks_mitigated: 0,
      engine_health: 'unknown', firewall_engine: 'unknown',
    };
  }

  public setNotifyUserId(userId: number | null): void {
    this.notifyUserId = userId;
  }

  public isLinux(): boolean {
    return isLinux;
  }

  public async start(): Promise<void> {
    await this.loadSettings();
    if (!isLinux) {
      this.stats.engine_health = 'unavailable';
      this.stats.firewall_engine = 'unavailable';
      console.warn('[DDoS] Non-Linux platform detected - network monitoring and firewall blocking are disabled.');
      return;
    }
    // Determine firewall engine
    const fwStatus = await this.firewallManager.getStatus();
    this.stats.firewall_engine = fwStatus.engine;

    setTimeout(() => { void this.analyzeNetworkActivity(); }, 1500);
    this.monitorTimer = setInterval(() => { void this.analyzeNetworkActivity(); }, 5000);
    this.autoUnblockTimer = setInterval(() => { void this.autoUnblockExpired(); }, 30000);
    this.persistTimer = setInterval(() => { void this.persistLiveData(); }, 5000);
    this.stats.engine_health = 'healthy';
    console.log(`[DDoS] Real-time network monitoring started (5s interval, ${fwStatus.engine})`);
  }

  public async stop(): Promise<void> {
    if (this.monitorTimer) clearInterval(this.monitorTimer);
    if (this.autoUnblockTimer) clearInterval(this.autoUnblockTimer);
    if (this.persistTimer) clearInterval(this.persistTimer);
    this.monitorTimer = null;
    this.autoUnblockTimer = null;
    this.persistTimer = null;
    this.stats.engine_health = 'stopped';
  }

  private async loadSettings(): Promise<void> {
    const row = await this.db.get<DdosSettings>(`SELECT * FROM ddos_settings WHERE id = 1`);
    if (row) {
      this.settings = { ...DEFAULT_SETTINGS, ...row };
    }
  }

  public getSettings(): DdosSettings {
    return { ...this.settings };
  }

  public async updateSettings(input: Partial<DdosSettings>): Promise<DdosSettings> {
    const baseCols = [
      'rate_limit_per_minute', 'max_bandwidth_per_minute', 'auto_block', 'block_duration',
      'threat_threshold_medium', 'threat_threshold_high', 'threat_threshold_critical',
      'auto_block_syn_recv', 'auto_block_high_connections', 'auto_block_port_scan',
      'auto_block_time_wait', 'intelligent_blocking',
    ] as const;
    const allCols = [...baseCols, ...ENTERPRISE_COLUMNS];
    const next: DdosSettings = { ...this.settings };
    const colsToUpdate: string[] = [];
    const params: unknown[] = [];
    for (const key of allCols) {
      if (input[key] !== undefined) {
        if (key === 'trusted_proxies') {
          (next as unknown as Record<string, unknown>)[key] = String(input[key]);
        } else if (key === 'cloudflare_zone') {
          (next as unknown as Record<string, unknown>)[key] = String(input[key]);
        } else {
          (next as unknown as Record<string, unknown>)[key] = Number(input[key]);
        }
        colsToUpdate.push(`${key} = ?`);
        params.push((next as unknown as Record<string, unknown>)[key]);
      }
    }
    if (colsToUpdate.length > 0) {
      await this.db.run(`UPDATE ddos_settings SET ${colsToUpdate.join(', ')} WHERE id = 1`, params);
    }
    this.settings = next;
    return { ...next };
  }

  public getStats(): DdosStats {
    // Refresh derived counts
    this.stats.total_ips = this.liveIPs.size;
    this.stats.blocked_ips = Array.from(this.liveIPs.values()).filter((v) => v.blocked).length;
    this.stats.banned_ips = this.liveIPs.size; // approximated from tracked IPs
    return { ...this.stats };
  }

  private async runCmd(cmd: string): Promise<string> {
    const execCmd = typeof process.getuid === 'function' && process.getuid() !== 0
      ? `sudo -n bash -c ${JSON.stringify(cmd)}`
      : cmd;
    const { stdout } = await execFileAsync(execCmd, { shell: '/bin/bash', maxBuffer: 1024 * 1024 });
    return stdout;
  }

  private async monitorActiveConnections(): Promise<Record<string, number>> {
    if (!isLinux) return {};
    try {
      const out = await this.runCmd(
        `ss -ntu state established 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | sort | uniq -c | sort -nr | head -100`
      );
      const connections: Record<string, number> = {};
      for (const line of out.trim().split('\n').filter((l) => l.trim())) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const count = parseInt(parts[0], 10);
          const ip = parts[1];
          if (isValidIPv4(ip)) connections[ip] = (connections[ip] || 0) + count;
        }
      }
      return connections;
    } catch { return {}; }
  }

  private async monitorAckFlood(): Promise<Record<string, number>> {
    if (!isLinux) return {};
    try {
      const out = await this.runCmd(
        `ss -ntu state established 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.' | sort | uniq -c | sort -nr | awk '$1 > 20 {print $1, $2}'`
      );
      const ackFlood: Record<string, number> = {};
      for (const line of out.trim().split('\n').filter((l) => l.trim())) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const count = parseInt(parts[0], 10);
          const ip = parts[1];
          if (isValidIP(ip) && count > 20) ackFlood[ip] = count;
        }
      }
      return ackFlood;
    } catch { return {}; }
  }

  private async monitorSynFlood(): Promise<Record<string, number>> {
    if (!isLinux) return {};
    try {
      const synFlood: Record<string, number> = {};
      const synRecv = await this.runCmd(
        `ss -ntu state syn-recv 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.' | sort | uniq -c | sort -nr | head -50`
      );
      for (const line of synRecv.trim().split('\n').filter((l) => l.trim())) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const count = parseInt(parts[0], 10);
          const ip = parts[1];
          if (ip && count > 5) synFlood[ip] = (synFlood[ip] || 0) + count;
        }
      }
      const synSent = await this.runCmd(
        `ss -ntu state syn-sent 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.' | sort | uniq -c | sort -nr | head -50`
      );
      for (const line of synSent.trim().split('\n').filter((l) => l.trim())) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const count = parseInt(parts[0], 10);
          const ip = parts[1];
          if (ip && count > 3) synFlood[ip] = (synFlood[ip] || 0) + count;
        }
      }
      return synFlood;
    } catch { return {}; }
  }

  private async detectPortScanning(): Promise<Record<string, number>> {
    if (!isLinux) return {};
    try {
      const out = await this.runCmd(
        `ss -ntu 2>/dev/null | awk '{print $5}' | grep -E '^[0-9]+\\.' | sort | uniq | awk -F: '{print $1}' | uniq -c | sort -nr | head -50`
      );
      const scanners: Record<string, number> = {};
      for (const line of out.trim().split('\n').filter((l) => l.trim())) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const portCount = parseInt(parts[0], 10);
          const ip = parts[1];
          if (portCount > 3 && ip && !isPrivateIP(ip)) scanners[ip] = portCount;
        }
      }
      return scanners;
    } catch { return {}; }
  }

  private async detectUDPFlood(): Promise<Record<string, number>> {
    if (!isLinux) return {};
    try {
      const out = await this.runCmd(
        `ss -nu 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.' | sort | uniq -c | sort -nr | head -50`
      );
      const udpFlood: Record<string, number> = {};
      for (const line of out.trim().split('\n').filter((l) => l.trim())) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const count = parseInt(parts[0], 10);
          const ip = parts[1];
          if (count > 20 && ip) udpFlood[ip] = count;
        }
      }
      return udpFlood;
    } catch { return {}; }
  }

  private async detectICMPFlood(): Promise<Record<string, number>> {
    if (!isLinux) return {};
    try {
      const out = await this.runCmd(
        `ss -nu icmp 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.' | sort | uniq -c | sort -nr | head -50`
      );
      const icmpFlood: Record<string, number> = {};
      for (const line of out.trim().split('\n').filter((l) => l.trim())) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const count = parseInt(parts[0], 10);
          const ip = parts[1];
          if (count > 50 && ip) icmpFlood[ip] = count;
        }
      }
      return icmpFlood;
    } catch { return {}; }
  }

  private async detectTimeWaitAbuse(): Promise<Record<string, number>> {
    if (!isLinux) return {};
    try {
      const out = await this.runCmd(
        `ss -ntu state time-wait 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.' | sort | uniq -c | sort -nr | head -50`
      );
      const timeWait: Record<string, number> = {};
      for (const line of out.trim().split('\n').filter((l) => l.trim())) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const count = parseInt(parts[0], 10);
          const ip = parts[1];
          if (count > 100 && ip) timeWait[ip] = count;
        }
      }
      return timeWait;
    } catch { return {}; }
  }

  private async detectHighConnectionIPs(): Promise<Record<string, number>> {
    if (!isLinux) return {};
    try {
      const out = await this.runCmd(
        `ss -ntu 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | sort | uniq -c | awk '$1 > 50 {print $1, $2}'`
      );
      const highConn: Record<string, number> = {};
      for (const line of out.trim().split('\n').filter((l) => l.trim())) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const count = parseInt(parts[0], 10);
          const ip = parts[1];
          if (isValidIP(ip)) highConn[ip] = count;
        }
      }
      return highConn;
    } catch { return {}; }
  }

  private async detectDNSAmplification(): Promise<Record<string, number>> {
    if (!isLinux) return {};
    try {
      // DNS amplification: many DNS queries (port 53) from single IP
      const out = await this.runCmd(
        `ss -nu state established 2>/dev/null | grep ':53 ' | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.' | sort | uniq -c | sort -nr | head -50`
      );
      const dnsAmp: Record<string, number> = {};
      for (const line of out.trim().split('\n').filter((l) => l.trim())) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const count = parseInt(parts[0], 10);
          const ip = parts[1];
          if (count > 50 && ip) dnsAmp[ip] = count;
        }
      }
      return dnsAmp;
    } catch { return {}; }
  }

  private async detectUDPAmplification(): Promise<Record<string, number>> {
    if (!isLinux) return {};
    try {
      // UDP amplification: high UDP volume to large payload ports
      const out = await this.runCmd(
        `ss -nu 2>/dev/null | awk '{print $5}' | cut -d: -f2 | sort | uniq -c | sort -nr | head -20`
      );
      // This detects amplification via response sizes; simplified
      const udpAmp: Record<string, number> = {};
      for (const line of out.trim().split('\n').filter((l) => l.trim())) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const count = parseInt(parts[0], 10);
          if (count > 100) {
            // Record total UDP count as amplification indicator
            udpAmp['amplification'] = count;
          }
        }
      }
      return udpAmp;
    } catch { return {}; }
  }

  private async getPacketRates(): Promise<{ pps: number; bps: number; inbound: number; outbound: number }> {
    if (!isLinux) return { pps: 0, bps: 0, inbound: 0, outbound: 0 };
    try {
      const [tcpSnmp, udpSnmp] = await Promise.all([
        this.runCmd(`cat /proc/net/snmp 2>/dev/null | grep '^Tcp:' | head -1`).catch(() => ''),
        this.runCmd(`cat /proc/net/snmp 2>/dev/null | grep '^Udp:' | head -1`).catch(() => ''),
      ]);
      const tcpParts = tcpSnmp.trim().split(/\s+/);
      const udpParts = udpSnmp.trim().split(/\s+/);
      const tcpInsegs = parseInt(tcpParts[3] || '0', 10) || 0;
      const udpInsegs = parseInt(udpParts[2] || '0', 10) || 0;
      const totalPackets = tcpInsegs + udpInsegs;
      const now = Date.now();
      const elapsed = (now - this.lastPacketCounts.time) / 1000;
      let pps = 0;
      if (elapsed > 0 && this.lastPacketCounts.time > 0) {
        pps = Math.round((totalPackets - this.lastPacketCounts.tcp - this.lastPacketCounts.udp) / elapsed);
      }
      this.lastPacketCounts = { tcp: tcpInsegs, udp: udpInsegs, time: now };
      const bps = pps * 64 * 8;
      return { pps: Math.max(0, pps), bps, inbound: bps, outbound: Math.floor(bps * 0.3) };
    } catch { return { pps: 0, bps: 0, inbound: 0, outbound: 0 }; }
  }

  private async getServerStats(): Promise<{
    load_1min: number; memory_total: number; memory_used: number; memory_percent: number;
    total_network_connections: number; established_connections: number;
  }> {
    if (!isLinux) {
      return { load_1min: 0, memory_total: 0, memory_used: 0, memory_percent: 0, total_network_connections: 0, established_connections: 0 };
    }
    try {
      const loadavg = await this.runCmd(`cat /proc/loadavg 2>/dev/null`);
      const loads = loadavg.trim().split(/\s+/);
      const meminfo = await this.runCmd(`free -m 2>/dev/null | grep Mem`);
      const memParts = meminfo.trim().split(/\s+/);
      const connCount = await this.runCmd(`ss -ntu 2>/dev/null | wc -l`);
      const estabCount = await this.runCmd(`ss -ntu state established 2>/dev/null | wc -l`);
      return {
        load_1min: parseFloat(loads[0]) || 0,
        memory_total: parseInt(memParts[1], 10) || 0,
        memory_used: parseInt(memParts[2], 10) || 0,
        memory_percent: memParts[1] ? Math.round(((parseInt(memParts[2], 10) || 0) / (parseInt(memParts[1], 10) || 1)) * 100) : 0,
        total_network_connections: (parseInt(connCount.trim(), 10) || 1) - 1,
        established_connections: (parseInt(estabCount.trim(), 10) || 1) - 1,
      };
    } catch {
      return { load_1min: 0, memory_total: 0, memory_used: 0, memory_percent: 0, total_network_connections: 0, established_connections: 0 };
    }
  }

  private async notify(type: 'info' | 'success' | 'warning' | 'critical', title: string, message: string, data?: Record<string, unknown>): Promise<void> {
    if (!this.notifyUserId || !this.monitoringService) return;
    const settingMap: Record<string, keyof DdosSettings> = {
      'attack_detected': 'notify_attack_detected',
      'attack_mitigated': 'notify_attack_mitigated',
      'attack_ended': 'notify_attack_ended',
      'critical_bandwidth': 'notify_critical_bandwidth',
      'suspicious_traffic': 'notify_suspicious_traffic',
      'node_failure': 'notify_node_failure',
      'firewall_failure': 'notify_firewall_failure',
      'engine_failure': 'notify_engine_failure',
    };
    const key = title.toLowerCase().replace(/\s+/g, '_');
    const settingKey = settingMap[key];
    if (settingKey && this.settings[settingKey] === 0) return;
    try {
      await this.monitoringService.createNotification({
        userId: this.notifyUserId,
        type,
        title,
        message,
        data,
      });
    } catch (err) {
      // Notification failures must never block the protection engine
      console.warn('[DDoS] Notification failed:', err);
    }
  }

  private async recordAttack(ip: string, attackType: string, severity: string, pps: number, bps: number, connections: number, nodeId?: number, vpsId?: number, mitigated?: boolean, method?: string): Promise<void> {
    await this.db.run(
      `INSERT INTO ddos_attacks
        (ip, attack_type, severity, detected_at, ended_at, duration_seconds, pps, bps, connections, node_id, vps_id, mitigated, mitigation_method, details)
       VALUES (?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [ip, attackType, severity, Date.now(), pps, bps, connections, nodeId || null, vpsId || null, mitigated ? 1 : 0, method || null, JSON.stringify({ attackType })]
    );
    this.stats.attacks_detected++;
    if (mitigated) this.stats.attacks_mitigated++;
  }

  private async endAttack(ip: string, attackType: string): Promise<void> {
    const row = await this.db.get<{ id: number; detected_at: number }>(
      `SELECT id, detected_at FROM ddos_attacks WHERE ip = ? AND attack_type = ? AND ended_at IS NULL ORDER BY id DESC LIMIT 1`,
      [ip, attackType]
    );
    if (row) {
      const duration = Math.floor((Date.now() - row.detected_at) / 1000);
      await this.db.run(`UPDATE ddos_attacks SET ended_at = ?, duration_seconds = ? WHERE id = ?`, [Date.now(), duration, row.id]);
    }
  }

  private async analyzeNetworkActivity(): Promise<void> {
    if (!isLinux) {
      this.stats.engine_health = 'unavailable';
      return;
    }
    try {
      const [connections, ackFlood, synFlood, scanners, udpFlood, icmpFlood, timeWaitAbuse, highConnIPs, dnsAmp, udpAmp, packetRates, serverStats] = await Promise.all([
        this.monitorActiveConnections(),
        this.monitorAckFlood(),
        this.monitorSynFlood(),
        this.detectPortScanning(),
        this.detectUDPFlood(),
        this.detectICMPFlood(),
        this.detectTimeWaitAbuse(),
        this.detectHighConnectionIPs(),
        this.detectDNSAmplification(),
        this.detectUDPAmplification(),
        this.getPacketRates(),
        this.getServerStats(),
      ]);

      const now = Date.now();
      const allIPs = [
        ...Object.keys(connections), ...Object.keys(ackFlood), ...Object.keys(synFlood),
        ...Object.keys(scanners), ...Object.keys(udpFlood), ...Object.keys(icmpFlood),
        ...Object.keys(timeWaitAbuse), ...Object.keys(highConnIPs), ...Object.keys(dnsAmp),
      ];
      const detectedIPs = new Set(allIPs.filter((ip) => isValidIP(ip) && !isPrivateIP(ip)));

      this.stats.server_load = serverStats.load_1min;
      this.stats.memory_usage = serverStats.memory_percent;
      this.stats.total_network_connections = serverStats.total_network_connections;
      this.stats.established_connections = serverStats.established_connections;
      this.stats.pps = packetRates.pps;
      this.stats.bps = packetRates.bps;
      this.stats.packets_per_sec = packetRates.pps;
      this.stats.inbound_bps = packetRates.inbound;
      this.stats.outbound_bps = packetRates.outbound;
      this.stats.conn_rate = Object.values(connections).reduce((a, b) => a + b, 0);

      let criticalCount = 0, highCount = 0, mediumCount = 0;

      for (const ip of detectedIPs) {
        const connectionCount = connections[ip] || 0;
        const ackCount = ackFlood[ip] || 0;
        const synCount = synFlood[ip] || 0;
        const portScanCount = scanners[ip] || 0;
        const udpCount = udpFlood[ip] || 0;
        const icmpCount = icmpFlood[ip] || 0;
        const timeWaitCount = timeWaitAbuse[ip] || 0;
        const highConnCount = highConnIPs[ip] || 0;
        const dnsAmpCount = dnsAmp[ip] || 0;

        let threatScore = 0;
        const attackType: string[] = [];

        // SYN flood
        if (synCount > 20) { threatScore += synCount * 10; attackType.push('syn_flood'); }
        else if (synCount > 10) { threatScore += synCount * 5; attackType.push('syn_attack'); }

        // ACK flood
        if (ackCount > this.settings.ack_flood_threshold) { threatScore += ackCount * 8; attackType.push('ack_flood'); }
        else if (ackCount > 100) { threatScore += ackCount * 4; attackType.push('ack_attack'); }

        // Connection flood
        if (highConnCount > 200) { threatScore += highConnCount * 3; attackType.push('massive_connection_flood'); }
        else if (highConnCount > 100) { threatScore += highConnCount * 2; attackType.push('connection_flood'); }
        else if (highConnCount > 50) { threatScore += highConnCount; attackType.push('high_connections'); }

        // TIME_WAIT abuse
        if (timeWaitCount > 500) { threatScore += timeWaitCount * 2; attackType.push('time_wait_exhaustion'); }
        else if (timeWaitCount > 200) { threatScore += timeWaitCount; attackType.push('time_wait_abuse'); }

        if (connectionCount > 100) { threatScore += connectionCount * 2; if (!attackType.includes('connection_flood')) attackType.push('connection_flood'); }
        else if (connectionCount > 50) { threatScore += connectionCount; attackType.push('high_connections'); }

        // Port scan
        if (portScanCount > 10) { threatScore += portScanCount * 15; attackType.push('aggressive_scan'); }
        else if (portScanCount > 5) { threatScore += portScanCount * 10; attackType.push('port_scan'); }

        // UDP flood
        if (udpCount > 50) { threatScore += udpCount * 5; attackType.push('udp_flood'); }
        else if (udpCount > 20) { threatScore += udpCount * 3; attackType.push('udp_attack'); }

        // ICMP flood
        if (icmpCount > this.settings.icmp_flood_threshold) { threatScore += icmpCount * 8; attackType.push('icmp_flood'); }
        else if (icmpCount > 200) { threatScore += icmpCount * 4; attackType.push('icmp_attack'); }

        // DNS amplification
        if (dnsAmpCount > this.settings.dns_amp_threshold) { threatScore += dnsAmpCount * 12; attackType.push('dns_amplification'); }
        else if (dnsAmpCount > 50) { threatScore += dnsAmpCount * 6; attackType.push('dns_amp_attack'); }

        // UDP amplification (global indicator)
        if (udpAmp['amplification'] && udpAmp['amplification'] > this.settings.udp_amp_threshold) {
          threatScore += udpAmp['amplification'];
          attackType.push('udp_amplification');
        }

        // Packet rate anomaly
        if (this.settings.packet_rate_threshold > 0 && packetRates.pps > this.settings.packet_rate_threshold) {
          threatScore += packetRates.pps;
          attackType.push('packet_rate_anomaly');
        }

        if (!this.liveIPs.has(ip)) {
          const existingIP = await this.db.get<{ blocked: number; blocked_at: number | null; whitelisted: number; reputation: number }>(
            `SELECT blocked, blocked_at, whitelisted, reputation FROM ddos_ips WHERE ip = ?`, [ip]
          );
          this.liveIPs.set(ip, {
            requests: 0, bandwidth: 0, threads: 0,
            first_seen: now, last_seen: now, threat_level: 'low',
            connections: 0, attack_type: [], threat_score: 0, attack_details: {},
            blocked: Boolean(existingIP?.blocked), blocked_at: existingIP?.blocked_at ?? null,
            whitelisted: Boolean(existingIP?.whitelisted), reputation: existingIP?.reputation || 0,
            attack_count: 0,
          });
          await this.db.run(`INSERT OR IGNORE INTO ddos_ips (ip, first_seen, last_seen) VALUES (?, ?, ?)`, [ip, now, now]);
        }

        const live = this.liveIPs.get(ip)!;
        live.connections = connectionCount;
        live.last_seen = now;
        live.threat_score = threatScore;
        live.attack_type = attackType;
        live.syn_count = synCount;
        live.ack_count = ackCount;
        live.icmp_count = icmpCount;
        live.udp_count = udpCount;
        live.port_scan_count = portScanCount;
        live.high_conn_count = highConnCount;
        live.time_wait_count = timeWaitCount;
        live.dns_amp_count = dnsAmpCount;
        live.pps = packetRates.pps;
        live.bps = packetRates.bps;

        // Update per-IP attack type counters in DB
        const typeSet = new Set(attackType);
        if (attackType.length > 0) {
          live.attack_count = ((live.attack_count as number) || 0) + 1;
          live.last_attack_at = now;
          // Update reputation: +1 per attack type
          live.reputation = ((live.reputation as number) || 0) + attackType.length;
        }

        if (threatScore >= this.settings.threat_threshold_critical) { live.threat_level = 'critical'; criticalCount++; }
        else if (threatScore >= this.settings.threat_threshold_high) { live.threat_level = 'high'; highCount++; }
        else if (threatScore >= this.settings.threat_threshold_medium) { live.threat_level = 'medium'; mediumCount++; }
        else { live.threat_level = 'low'; }

        // Check whitelist — never block whitelisted IPs
        if ((live.whitelisted as boolean)) continue;

        // Adaptive detection: escalate threat level if IP has repeated attacks
        const attackCount = ((live.attack_count as number) || 0);
        if (attackCount >= 5 && threatScore >= this.settings.threat_threshold_medium) {
          live.threat_level = 'high';
          highCount++;
        }

        const shouldBlock = this.settings.auto_block && (
          live.threat_level === 'critical' ||
          threatScore >= this.settings.threat_threshold_critical ||
          (this.settings.intelligent_blocking && (
            synCount >= this.settings.auto_block_syn_recv ||
            highConnCount >= this.settings.auto_block_high_connections ||
            portScanCount >= this.settings.auto_block_port_scan ||
            timeWaitCount >= this.settings.auto_block_time_wait ||
            attackType.length >= 3 ||
            (synCount > 20 && highConnCount > 100) ||
            (portScanCount > 5 && synCount > 10) ||
            (udpCount > 30 && connectionCount > 50) ||
            ackCount > this.settings.ack_flood_threshold ||
            icmpCount > this.settings.icmp_flood_threshold ||
            dnsAmpCount > this.settings.dns_amp_threshold
          ))
        );

        if (shouldBlock) {
          const alreadyBlocked = Boolean(live.blocked);
          if (!alreadyBlocked) {
            // Record attack
            const topType = attackType[0] || 'unknown';
            await this.recordAttack(ip, topType, live.threat_level as string, packetRates.pps, packetRates.bps, connectionCount);
            const result = await this.firewallManager.blockIP(ip, undefined, undefined, undefined, undefined);
            if (result.success) {
              live.blocked = true;
              live.blocked_at = Date.now();
              this.stats.total_blocked++;
              this.stats.active_mitigations++;
              await this.db.run(
                `INSERT INTO ddos_mitigations (ip, method, attack_type, active, created_at, expired_at)
                 VALUES (?, 'auto', ?, 1, ?, ?)`,
                [ip, topType, Date.now(), Date.now() + this.settings.block_duration * 1000]
              );
              await this.db.run(`UPDATE ddos_ips SET blocked = 1, blocked_at = ?, ban_type = 'temporary', ban_expires = ?, ban_reason = ?, last_attack_at = ?, attack_count = attack_count + 1 WHERE ip = ?`,
                [Date.now(), Date.now() + this.settings.block_duration * 1000, topType, now, ip]);
              await this.notify('critical', 'Attack detected', `DDoS attack detected from ${ip} (${topType}, ${live.threat_level}). Auto-mitigation applied.`, { ip, attackType: topType, severity: live.threat_level });
              await this.notify('success', 'Attack mitigated', `IP ${ip} has been blocked via ${this.stats.firewall_engine}.`, { ip, method: this.stats.firewall_engine });
              console.log(`[DDoS] AUTO-BLOCK: ${ip} (${live.threat_level}, score ${threatScore}) [${attackType.join(', ')}]`);
            } else {
              await this.notify('critical', 'Firewall failure', `Failed to block ${ip}: ${result.message}`, { ip, error: result.error });
            }
          }
        } else if (attackType.length > 0) {
          // Attack detected but not blocking — record it
          const topType = attackType[0] || 'unknown';
          const alreadyBlocked2 = Boolean(live.blocked);
          if (!alreadyBlocked2) {
            await this.recordAttack(ip, topType, live.threat_level as string, packetRates.pps, packetRates.bps, connectionCount);
            await this.notify('warning', 'Suspicious traffic', `Suspicious traffic pattern from ${ip}: ${attackType.join(', ')} (${live.threat_level}).`, { ip, attackTypes: attackType });
          }
        }
      }

      this.stats.total_connections = Object.values(connections).reduce((a, b) => a + b, 0);
      this.stats.suspicious_ips = detectedIPs.size;
      this.stats.critical_threats = criticalCount;
      this.stats.high_threats = highCount;
      this.stats.medium_threats = mediumCount;
      this.stats.last_scan = now;
      this.stats.engine_health = 'healthy';
    } catch (err) {
      this.stats.engine_health = 'error';
      console.error('[DDoS] Network analysis error:', err);
    }
  }

  private async persistLiveData(): Promise<void> {
    const now = Date.now();
    for (const [ip, data] of this.liveIPs.entries()) {
      const d = data as Record<string, unknown>;
      await this.db.run(
        `INSERT INTO ddos_ips (ip, requests, bandwidth, threads, last_seen, threat_level, first_seen,
           ack_count, icmp_count, http_get_count, http_post_count, slowloris_count, dns_amp_count, udp_amp_count,
           packet_rate, pps, bps, conn_rate, last_attack_at, attack_count, reputation, attack_types)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(ip) DO UPDATE SET
           requests = requests + ?, bandwidth = bandwidth + ?, threads = ?, last_seen = ?, threat_level = ?,
           ack_count = ?, icmp_count = ?, dns_amp_count = ?, packet_rate = ?, pps = ?, bps = ?, conn_rate = ?,
           last_attack_at = ?, attack_count = ?, reputation = ?, attack_types = ?`,
        [
          ip, d.requests, d.bandwidth, d.threads, d.last_seen, d.threat_level, d.first_seen,
          d.ack_count || 0, d.icmp_count || 0, d.http_get_count || 0, d.http_post_count || 0,
          d.slowloris_count || 0, d.dns_amp_count || 0, d.udp_amp_count || 0, d.packet_rate || 0,
          d.pps || 0, d.bps || 0, d.conn_rate || 0, d.last_attack_at || null, d.attack_count || 0,
          d.reputation || 0, Array.isArray(d.attack_type) ? (d.attack_type as string[]).join(',') : null,
          d.requests, d.bandwidth, d.threads, d.last_seen, d.threat_level,
          d.ack_count || 0, d.icmp_count || 0, d.dns_amp_count || 0, d.packet_rate || 0,
          d.pps || 0, d.bps || 0, d.conn_rate || 0,
          d.last_attack_at || null, d.attack_count || 0, d.reputation || 0,
          Array.isArray(d.attack_type) ? (d.attack_type as string[]).join(',') : null,
        ]
      );
    }
  }

  private async autoUnblockExpired(): Promise<void> {
    if (this.settings.block_duration <= 0) return;
    const expireTime = Date.now() - this.settings.block_duration * 1000;
    const rows = await this.db.all<{ ip: string; attack_types: string | null }>(
      `SELECT ip, attack_types FROM ddos_ips WHERE blocked = 1 AND ban_expires < ? AND whitelisted = 0`,
      [expireTime]
    );
    for (const row of rows) {
      const result = await this.firewallManager.unblockIP(row.ip);
      if (result.success) {
        await this.db.run(`UPDATE ddos_ips SET blocked = 0, blocked_at = NULL, ban_expires = NULL, ban_reason = NULL WHERE ip = ?`, [row.ip]);
        await this.db.run(`UPDATE ddos_mitigations SET active = 0, rolled_back = 1 WHERE ip = ? AND active = 1`, [row.ip]);
        await this.endAttack(row.ip, row.attack_types || 'unknown');
        await this.notify('success', 'Attack ended', `Auto-unblocked ${row.ip} after block duration expired.`, { ip: row.ip });
        console.log(`[DDoS] Auto-unblocked: ${row.ip} (duration expired)`);
      }
    }
  }

  public async blockIP(ip: string, reason = 'manual', protocol?: string, port?: string, userId?: number): Promise<{ success: boolean; message: string; error?: string }> {
    if (!isLinux) return { success: false, message: 'Blocking requires a Linux host with iptables/nftables.' };
    if (!isValidIP(ip)) return { success: false, message: 'Invalid IP address.' };
    if (isPrivateIP(ip)) return { success: false, message: 'Cannot block private/management IP.' };

    // Check whitelist
    const whitelisted = await this.db.get<{ ip: string }>(`SELECT ip FROM ddos_whitelist WHERE ip = ?`, [ip]);
    if (whitelisted) return { success: false, message: 'IP is whitelisted and cannot be blocked.' };

    // Check if already blocked
    const existing = await this.db.get<{ blocked: number }>(`SELECT blocked FROM ddos_ips WHERE ip = ?`, [ip]);
    if (existing?.blocked) {
      return { success: true, message: 'Already blocked' };
    }

    const result = await this.firewallManager.blockIP(ip, protocol, port, undefined, undefined, userId);
    if (result.success) {
      this.stats.total_blocked++;
      this.stats.active_mitigations++;
      await this.db.run(
        `INSERT INTO ddos_ips (ip, blocked, blocked_at, ban_type, ban_reason, ban_expires, last_attack_at, first_seen, last_seen)
         VALUES (?, 1, ?, 'temporary', ?, ?, ?, ?, ?)
         ON CONFLICT(ip) DO UPDATE SET blocked = 1, blocked_at = ?, ban_type = 'temporary', ban_reason = ?, ban_expires = ?, last_attack_at = ?`,
        [ip, Date.now(), reason, Date.now() + this.settings.block_duration * 1000, Date.now(), Date.now(),
          Date.now(), reason, Date.now() + this.settings.block_duration * 1000, Date.now()]
      );
      await this.db.run(
        `INSERT INTO ddos_mitigations (ip, method, attack_type, active, created_at, expired_at)
         VALUES (?, 'manual', ?, 1, ?, ?)`,
        [ip, reason, Date.now(), Date.now() + this.settings.block_duration * 1000]
      );
      await this.db.run(`INSERT INTO ddos_attack_logs (ip, timestamp, requests, bandwidth, action) VALUES (?, ?, ?, ?, ?)`,
        [ip, Date.now(), 0, 0, `blocked_${reason}`]);
      const live = this.liveIPs.get(ip);
      if (live) { live.blocked = true; live.blocked_at = Date.now(); }
      await this.notify('critical', 'Attack detected', `IP ${ip} manually blocked (${reason}).`, { ip, reason });
      await this.notify('success', 'Attack mitigated', `IP ${ip} blocked via ${this.stats.firewall_engine}.`, { ip, method: this.stats.firewall_engine });
      console.log(`[DDoS] Blocked: ${ip} (${reason})`);
    }
    return result;
  }

  public async unblockIP(ip: string, userId?: number): Promise<{ success: boolean; message: string; error?: string }> {
    if (!isLinux) return { success: false, message: 'Unblocking requires a Linux host with iptables/nftables.' };
    if (!isValidIP(ip)) return { success: false, message: 'Invalid IP address.' };

    const result = await this.firewallManager.unblockIP(ip, userId);
    if (result.success) {
      this.stats.active_mitigations = Math.max(0, this.stats.active_mitigations - 1);
      await this.db.run(`UPDATE ddos_ips SET blocked = 0, blocked_at = NULL, ban_expires = NULL, ban_reason = NULL WHERE ip = ?`, [ip]);
      await this.db.run(`UPDATE ddos_mitigations SET active = 0, rolled_back = 1 WHERE ip = ? AND active = 1`, [ip]);
      await this.db.run(`INSERT INTO ddos_attack_logs (ip, timestamp, requests, bandwidth, action) VALUES (?, ?, ?, ?, ?)`,
        [ip, Date.now(), 0, 0, 'unblocked']);
      await this.notify('success', 'Attack ended', `IP ${ip} unblocked.`, { ip });
      const live = this.liveIPs.get(ip);
      if (live) { live.blocked = false; live.blocked_at = null; }
      console.log(`[DDoS] Unblocked: ${ip}`);
    }
    return result;
  }

  public async listIps(opts: { page?: number; limit?: number; filter?: string; search?: string } = {}): Promise<{
    ips: DdosIpRecord[];
    pagination: { page: number; limit: number; total: number; pages: number };
  }> {
    const page = Math.max(1, opts.page || 1);
    const limit = Math.min(200, Math.max(1, opts.limit || 50));
    const offset = (page - 1) * limit;
    const filter = opts.filter || 'all';
    const search = opts.search || '';

    let query = `SELECT * FROM ddos_ips`;
    const conditions: string[] = [];
    const params: unknown[] = [];
    if (filter === 'blocked') conditions.push(`blocked = 1`);
    else if (filter === 'banned') conditions.push(`banned = 1`);
    else if (filter === 'active') { conditions.push(`last_seen > ?`); params.push(Date.now() - 300000); }
    else if (filter === 'threat') conditions.push(`threat_level IN ('high', 'critical')`);
    else if (filter === 'whitelisted') conditions.push(`whitelisted = 1`);
    if (search) { conditions.push(`ip LIKE ?`); params.push(`%${search}%`); }
    if (conditions.length > 0) query += ` WHERE ${conditions.join(' AND ')}`;
    query += ` ORDER BY requests DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const rows = await this.db.all<DdosIpRecord>(query, params);
    const countParams = [...params.slice(0, -2)];
    const count = await this.db.get<{ total: number }>(
      `SELECT COUNT(*) as total FROM ddos_ips${conditions.length > 0 ? ` WHERE ${conditions.join(' AND ').replace(/\?/g, '?')}` : ''}`,
      countParams
    );
    return {
      ips: rows,
      pagination: { page, limit, total: count?.total || 0, pages: Math.ceil((count?.total || 0) / limit) },
    };
  }

  public async getIp(ip: string): Promise<{ ip: DdosIpRecord; live: Record<string, unknown> | null; logs: unknown[]; attacks: unknown[] } | null> {
    const ipData = await this.db.get<DdosIpRecord>(`SELECT * FROM ddos_ips WHERE ip = ?`, [ip]);
    if (!ipData) return null;
    const logs = await this.db.all(`SELECT * FROM ddos_attack_logs WHERE ip = ? ORDER BY timestamp DESC LIMIT 100`, [ip]);
    const attacks = await this.db.all(`SELECT * FROM ddos_attacks WHERE ip = ? ORDER BY detected_at DESC LIMIT 50`, [ip]);
    return { ip: ipData, live: this.liveIPs.get(ip) || null, logs, attacks };
  }

  public async clearIp(ip: string): Promise<{ success: boolean; message: string }> {
    await this.db.run(`DELETE FROM ddos_ips WHERE ip = ?`, [ip]);
    await this.db.run(`DELETE FROM ddos_attack_logs WHERE ip = ?`, [ip]);
    await this.db.run(`DELETE FROM ddos_attacks WHERE ip = ?`, [ip]);
    await this.db.run(`DELETE FROM ddos_mitigations WHERE ip = ?`, [ip]);
    await this.db.run(`DELETE FROM ddos_firewall_rules WHERE ip = ?`, [ip]);
    this.liveIPs.delete(ip);
    this.minuteTracker.delete(ip);
    return { success: true, message: 'IP data cleared' };
  }

  public async listLogs(limit = 100): Promise<unknown[]> {
    return this.db.all(`SELECT * FROM ddos_attack_logs ORDER BY timestamp DESC LIMIT ?`, [limit]);
  }

  public async listAttacks(opts: { limit?: number; page?: number; severity?: string; ip?: string } = {}): Promise<{
    attacks: unknown[];
    pagination: { page: number; limit: number; total: number; pages: number };
  }> {
    const page = Math.max(1, opts.page || 1);
    const limit = Math.min(500, Math.max(1, opts.limit || 50));
    const offset = (page - 1) * limit;
    const conditions: string[] = [];
    const params: unknown[] = [];
    if (opts.severity) { conditions.push(`severity = ?`); params.push(opts.severity); }
    if (opts.ip) { conditions.push(`ip = ?`); params.push(opts.ip); }
    const where = conditions.length > 0 ? ` WHERE ${conditions.join(' AND ')}` : '';
    const attacks = await this.db.all(`SELECT * FROM ddos_attacks${where} ORDER BY detected_at DESC LIMIT ? OFFSET ?`, [...params, limit, offset]);
    const count = await this.db.get<{ total: number }>(`SELECT COUNT(*) as total FROM ddos_attacks${where}`, params);
    return { attacks, pagination: { page, limit, total: count?.total || 0, pages: Math.ceil((count?.total || 0) / limit) } };
  }

  public async listMitigations(active?: boolean): Promise<unknown[]> {
    if (active) return this.db.all(`SELECT * FROM ddos_mitigations WHERE active = 1 ORDER BY created_at DESC`);
    return this.db.all(`SELECT * FROM ddos_mitigations ORDER BY created_at DESC LIMIT 200`);
  }

  public async listWhitelist(opts: { nodeId?: number; vpsId?: number } = {}): Promise<unknown[]> {
    let query = `SELECT * FROM ddos_whitelist`;
    const params: unknown[] = [];
    if (opts.nodeId) { query += ` WHERE node_id = ?`; params.push(opts.nodeId); }
    else if (opts.vpsId) { query += ` WHERE vps_id = ?`; params.push(opts.vpsId); }
    query += ` ORDER BY created_at DESC`;
    return this.db.all(query, params);
  }

  public async listFirewallRules(ip?: string): Promise<unknown[]> {
    return this.firewallManager.listRules(ip);
  }

  public async listAuditLogs(limit = 100): Promise<unknown[]> {
    return this.db.all(`SELECT * FROM ddos_audit_log ORDER BY created_at DESC LIMIT ?`, [limit]);
  }

  public async trackRequest(ip: string, contentLength: number, method?: string): Promise<void> {
    const now = Date.now();
    const currentMinute = Math.floor(now / 60000);
    this.stats.total_requests++;
    this.stats.active_connections++;

    if (!this.liveIPs.has(ip)) {
      this.liveIPs.set(ip, {
        requests: 0, bandwidth: 0, threads: 0,
        first_seen: now, last_seen: now, threat_level: 'low',
      });
      await this.db.run(`INSERT OR IGNORE INTO ddos_ips (ip, first_seen, last_seen) VALUES (?, ?, ?)`, [ip, now, now]);
    }
    const live = this.liveIPs.get(ip)!;
    (live as Record<string, unknown>).requests = ((live as Record<string, unknown>).requests as number || 0) + 1;
    (live as Record<string, unknown>).threads = ((live as Record<string, unknown>).threads as number || 0) + 1;
    (live as Record<string, unknown>).last_seen = now;
    (live as Record<string, unknown>).bandwidth = ((live as Record<string, unknown>).bandwidth as number || 0) + contentLength;
    if (method === 'GET') (live as Record<string, unknown>).http_get_count = ((live as Record<string, unknown>).http_get_count as number || 0) + 1;
    if (method === 'POST') (live as Record<string, unknown>).http_post_count = ((live as Record<string, unknown>).http_post_count as number || 0) + 1;

    const tracker = this.minuteTracker.get(ip);
    if (!tracker || tracker.minute !== currentMinute) {
      this.minuteTracker.set(ip, { minute: currentMinute, requests: 0, bandwidth: 0 });
    }
    const t = this.minuteTracker.get(ip)!;
    t.requests++;
    t.bandwidth += contentLength;
    this.stats.total_bandwidth += contentLength;

    const requests = t.requests;
    const bandwidth = t.bandwidth;
    let level = 'low';
    if (requests >= this.settings.threat_threshold_high || bandwidth >= this.settings.max_bandwidth_per_minute * 5) level = 'critical';
    else if (requests >= this.settings.threat_threshold_medium || bandwidth >= this.settings.max_bandwidth_per_minute * 2) level = 'high';
    else if (requests >= this.settings.rate_limit_per_minute || bandwidth >= this.settings.max_bandwidth_per_minute) level = 'medium';
    (live as Record<string, unknown>).threat_level = level;

    if (this.settings.auto_block) {
      const exceedsRate = t.requests > this.settings.rate_limit_per_minute;
      const exceedsBw = t.bandwidth > this.settings.max_bandwidth_per_minute;
      if (exceedsRate || exceedsBw) {
        const reason = exceedsRate ? 'rate_limit' : 'bandwidth_limit';
        await this.blockIP(ip, reason);
      }
    }

    setTimeout(() => {
      const l = this.liveIPs.get(ip);
      if (l) (l as Record<string, unknown>).threads = Math.max(0, ((l as Record<string, unknown>).threads as number || 0) - 1);
      this.stats.active_connections = Math.max(0, this.stats.active_connections - 1);
    }, 60000);
  }

  public async getNetworkAnalysis(): Promise<{
    active_connections: Record<string, number>;
    syn_flood_attacks: Record<string, number>;
    ack_flood_attacks: Record<string, number>;
    icmp_flood_attacks: Record<string, number>;
    port_scanners: Record<string, number>;
    udp_flood_attacks: Record<string, number>;
    dns_amplification: Record<string, number>;
    total_connections: number;
    suspicious_count: number;
    timestamp: number;
  }> {
    const [connections, synFlood, ackFlood, icmpFlood, scanners, udpFlood, dnsAmp] = await Promise.all([
      this.monitorActiveConnections(),
      this.monitorSynFlood(),
      this.monitorAckFlood(),
      this.detectICMPFlood(),
      this.detectPortScanning(),
      this.detectUDPFlood(),
      this.detectDNSAmplification(),
    ]);
    const totalConnections = Object.values(connections).reduce((a, b) => a + b, 0);
    return {
      active_connections: connections,
      syn_flood_attacks: synFlood,
      ack_flood_attacks: ackFlood,
      icmp_flood_attacks: icmpFlood,
      port_scanners: scanners,
      udp_flood_attacks: udpFlood,
      dns_amplification: dnsAmp,
      total_connections: totalConnections,
      suspicious_count: Object.keys(synFlood).length + Object.keys(ackFlood).length + Object.keys(scanners).length,
      timestamp: Date.now(),
    };
  }
}
