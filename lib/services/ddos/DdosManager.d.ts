import type { UnifiedDatabase } from '../../db/database';
import type { MonitoringService } from '../monitoring/MonitoringService';
import type { DdosFirewallManager } from './DdosFirewallManager';
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
export declare class DdosManager {
    private db;
    private monitoringService;
    private firewallManager;
    private settings;
    private stats;
    private liveIPs;
    private minuteTracker;
    private monitorTimer;
    private autoUnblockTimer;
    private persistTimer;
    private notifyUserId;
    private lastPacketCounts;
    constructor(db: UnifiedDatabase, firewallManager: DdosFirewallManager, monitoringService?: MonitoringService);
    setNotifyUserId(userId: number | null): void;
    isLinux(): boolean;
    start(): Promise<void>;
    stop(): Promise<void>;
    private loadSettings;
    getSettings(): DdosSettings;
    updateSettings(input: Partial<DdosSettings>): Promise<DdosSettings>;
    getStats(): DdosStats;
    private runCmd;
    private monitorActiveConnections;
    private monitorAckFlood;
    private monitorSynFlood;
    private detectPortScanning;
    private detectUDPFlood;
    private detectICMPFlood;
    private detectTimeWaitAbuse;
    private detectHighConnectionIPs;
    private detectDNSAmplification;
    private detectUDPAmplification;
    private getPacketRates;
    private getServerStats;
    private notify;
    private recordAttack;
    private endAttack;
    private analyzeNetworkActivity;
    private persistLiveData;
    private autoUnblockExpired;
    blockIP(ip: string, reason?: string, protocol?: string, port?: string, userId?: number): Promise<{
        success: boolean;
        message: string;
        error?: string;
    }>;
    unblockIP(ip: string, userId?: number): Promise<{
        success: boolean;
        message: string;
        error?: string;
    }>;
    listIps(opts?: {
        page?: number;
        limit?: number;
        filter?: string;
        search?: string;
    }): Promise<{
        ips: DdosIpRecord[];
        pagination: {
            page: number;
            limit: number;
            total: number;
            pages: number;
        };
    }>;
    getIp(ip: string): Promise<{
        ip: DdosIpRecord;
        live: Record<string, unknown> | null;
        logs: unknown[];
        attacks: unknown[];
    } | null>;
    clearIp(ip: string): Promise<{
        success: boolean;
        message: string;
    }>;
    listLogs(limit?: number): Promise<unknown[]>;
    listAttacks(opts?: {
        limit?: number;
        page?: number;
        severity?: string;
        ip?: string;
    }): Promise<{
        attacks: unknown[];
        pagination: {
            page: number;
            limit: number;
            total: number;
            pages: number;
        };
    }>;
    listMitigations(active?: boolean): Promise<unknown[]>;
    listWhitelist(opts?: {
        nodeId?: number;
        vpsId?: number;
    }): Promise<unknown[]>;
    listFirewallRules(ip?: string): Promise<unknown[]>;
    listAuditLogs(limit?: number): Promise<unknown[]>;
    trackRequest(ip: string, contentLength: number, method?: string): Promise<void>;
    getNetworkAnalysis(): Promise<{
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
    }>;
}
