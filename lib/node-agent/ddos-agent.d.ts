import type { Express } from 'express';
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
export declare class NodeDdosRuntime {
    private config;
    private stats;
    private monitorTimer;
    private nftAvailable;
    constructor();
    isLinux(): boolean;
    getConfig(): NodeDdosConfig;
    setConfig(config: NodeDdosConfig): void;
    getStats(): NodeDdosStats;
    private runCmd;
    private isNftAvailable;
    private analyze;
    blockIP(ip: string): Promise<{
        success: boolean;
        message: string;
    }>;
    unblockIP(ip: string): Promise<{
        success: boolean;
        message: string;
    }>;
}
/**
 * Attach DDoS protection endpoints to a Node Agent Express app.
 * All endpoints require the agent's existing HMAC authentication middleware
 * (already applied to the app before this is called).
 */
export declare function attachNodeDdosEndpoints(app: Express, ddosRuntime: NodeDdosRuntime): void;
