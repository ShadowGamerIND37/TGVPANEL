import type { UnifiedDatabase } from '../../db/database';
export interface FirewallResult {
    success: boolean;
    message: string;
    ruleId?: string;
    error?: string;
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
export declare class DdosFirewallManager {
    private db;
    private lock;
    private nftAvailable;
    constructor(db: UnifiedDatabase);
    isLinux(): boolean;
    private withLock;
    private runCmd;
    private isNftAvailable;
    private audit;
    blockIP(ip: string, protocol?: string, port?: string, nodeId?: number, vpsId?: number, userId?: number): Promise<FirewallResult>;
    unblockIP(ip: string, userId?: number): Promise<FirewallResult>;
    rollbackAll(userId?: number): Promise<FirewallResult>;
    listRules(ip?: string): Promise<unknown[]>;
    applySynCookies(enabled: boolean, userId?: number): Promise<FirewallResult>;
    applyConnectionLimit(limit: number, userId?: number): Promise<FirewallResult>;
    applyPacketRateLimit(rate: number, userId?: number): Promise<FirewallResult>;
    emergencyMode(enabled: boolean, userId?: number): Promise<FirewallResult>;
    getStatus(): Promise<{
        nftables: boolean;
        iptables: boolean;
        active_rules: number;
        engine: string;
    }>;
}
