import type { UnifiedDatabase } from '../../db/database';
export interface DdosProfile {
    id: number;
    name: string;
    description: string | null;
    level: string;
    syn_cookies: number;
    connection_limit: number;
    packet_rate_limit: number;
    per_ip_rate_limit: number;
    auto_block: number;
    block_duration: number;
    threat_threshold_medium: number;
    threat_threshold_high: number;
    threat_threshold_critical: number;
    http_get_threshold: number;
    http_post_threshold: number;
    slowloris_threshold: number;
    dns_amp_threshold: number;
    udp_amp_threshold: number;
    packet_rate_threshold: number;
    suspicious_ua_block: number;
    emergency_mode: number;
    protocols: string | null;
    ports: string | null;
    is_active: number;
    created_at: string;
}
export interface DdosProfileAssignment {
    id: number;
    profile_id: number;
    node_id: number | null;
    vps_id: number | null;
    created_at: string;
}
/**
 * Management of DDoS protection profiles.
 * Profiles define reusable threshold sets (Basic, Standard, Advanced,
 * Aggressive, Custom) that can be assigned to nodes and VPS instances.
 */
export declare class DdosProfileManager {
    private db;
    constructor(db: UnifiedDatabase);
    listProfiles(): Promise<DdosProfile[]>;
    getProfile(id: number): Promise<DdosProfile | null>;
    getActiveProfile(): Promise<DdosProfile | null>;
    createProfile(input: Partial<DdosProfile> & {
        name: string;
    }): Promise<DdosProfile>;
    updateProfile(id: number, input: Partial<DdosProfile>): Promise<DdosProfile | null>;
    deleteProfile(id: number): Promise<boolean>;
    setActiveProfile(id: number): Promise<boolean>;
    assignProfile(profileId: number, nodeId?: number, vpsId?: number): Promise<boolean>;
    unassignProfile(profileId: number, nodeId?: number, vpsId?: number): Promise<boolean>;
    getAssignments(profileId?: number): Promise<DdosProfileAssignment[]>;
    getProfileForNode(nodeId: number): Promise<DdosProfile | null>;
    getProfileForVps(vpsId: number): Promise<DdosProfile | null>;
    getLevels(): string[];
}
