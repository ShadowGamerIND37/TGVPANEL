import type { UnifiedDatabase } from '../../db/database';
export interface VpsDdosPolicy {
    id: number;
    vps_id: number;
    instance_type: string;
    instance_ref_id: number;
    node_id: number | null;
    enabled: number;
    profile_id: number | null;
    tcp_protection: number;
    udp_protection: number;
    icmp_protection: number;
    connection_limit: number;
    per_ip_rate_limit: number;
    port_whitelist: string | null;
    ip_whitelist: string | null;
    auto_block: number;
    block_duration: number;
    network_isolation: number;
    created_at: string;
    updated_at: string;
}
/**
 * Per-VPS DDoS protection policies for KVM and LXC instances.
 *
 * Each VPS can have an individual protection policy: protocol-level
 * protection (TCP/UDP/ICMP), connection limits, per-IP rate limits,
 * port/IP whitelists, and network isolation. Policies are applied at the
 * host firewall level using tagged rules (owned by DdosFirewallManager)
 * so they can be rolled back precisely without affecting other VPS or
 * host-wide rules. Only traffic the host can actually inspect and filter
 * is protected — the manager does not claim to protect against traffic
 * that never reaches the host.
 */
export declare class DdosVpsPolicyManager {
    private db;
    constructor(db: UnifiedDatabase);
    listPolicies(): Promise<VpsDdosPolicy[]>;
    getPolicy(vpsId: number): Promise<VpsDdosPolicy | null>;
    getPoliciesForNode(nodeId: number): Promise<VpsDdosPolicy[]>;
    setPolicy(input: {
        vps_id: number;
        instance_type: string;
        instance_ref_id: number;
        node_id?: number;
        enabled?: number;
        profile_id?: number | null;
        tcp_protection?: number;
        udp_protection?: number;
        icmp_protection?: number;
        connection_limit?: number;
        per_ip_rate_limit?: number;
        port_whitelist?: string | null;
        ip_whitelist?: string | null;
        auto_block?: number;
        block_duration?: number;
        network_isolation?: number;
    }): Promise<VpsDdosPolicy>;
    deletePolicy(vpsId: number): Promise<boolean>;
    isWhitelisted(ip: string, vpsId?: number, nodeId?: number): Promise<boolean>;
    addWhitelist(ip: string, reason?: string, nodeId?: number, vpsId?: number, userId?: number): Promise<boolean>;
    removeWhitelist(ip: string): Promise<boolean>;
    listWhitelist(nodeId?: number, vpsId?: number): Promise<unknown[]>;
}
