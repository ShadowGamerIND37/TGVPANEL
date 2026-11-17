import type { UnifiedDatabase } from '../../db/database';
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
}
/**
 * DDoS protection manager.
 *
 * Monitors live TCP/UDP connection state via `ss`/`netstat`, scores each
 * source IP for threat level, and automatically blocks high-threat IPs with
 * `iptables -A INPUT -s <ip> -j DROP`. Manual block/unblock and settings are
 * exposed through the v1 API. All network/firewall operations require a Linux
 * host with `ss`, `netstat`, and `iptables` available (honest capability
 * gating: on non-Linux or when tools are absent, monitoring returns empty data
 * and blocking reports a clear error rather than faking results).
 */
export declare class DdosManager {
    private db;
    private settings;
    private stats;
    private liveIPs;
    private minuteTracker;
    private monitorTimer;
    private autoUnblockTimer;
    private persistTimer;
    constructor(db: UnifiedDatabase);
    isLinux(): boolean;
    start(): Promise<void>;
    stop(): Promise<void>;
    private loadSettings;
    getSettings(): DdosSettings;
    updateSettings(input: Partial<DdosSettings>): Promise<DdosSettings>;
    getStats(): DdosStats;
    private runCmd;
    private monitorActiveConnections;
    private monitorSynFlood;
    private detectPortScanning;
    private detectUDPFlood;
    private detectTimeWaitAbuse;
    private detectHighConnectionIPs;
    private getServerStats;
    private analyzeNetworkActivity;
    private persistLiveData;
    private autoUnblockExpired;
    blockIP(ip: string, reason?: string): Promise<{
        success: boolean;
        message: string;
        error?: string;
    }>;
    unblockIP(ip: string): Promise<{
        success: boolean;
        message: string;
        error?: string;
    }>;
    listIps(opts?: {
        page?: number;
        limit?: number;
        filter?: string;
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
    } | null>;
    clearIp(ip: string): Promise<{
        success: boolean;
        message: string;
    }>;
    listLogs(limit?: number): Promise<unknown[]>;
    trackRequest(ip: string, contentLength: number): Promise<void>;
    getNetworkAnalysis(): Promise<{
        active_connections: Record<string, number>;
        syn_flood_attacks: Record<string, number>;
        port_scanners: Record<string, number>;
        total_connections: number;
        suspicious_count: number;
        timestamp: number;
    }>;
}
