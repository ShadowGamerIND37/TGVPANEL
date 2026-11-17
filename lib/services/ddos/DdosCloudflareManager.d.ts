import type { UnifiedDatabase } from '../../db/database';
export interface CloudflareIntegration {
    id: number;
    name: string;
    provider: string;
    api_key_enc: string | null;
    api_email: string | null;
    zone: string | null;
    security_level: string;
    is_active: number;
    last_sync_at: number | null;
    last_error: string | null;
    created_at: string;
}
export interface CloudflareStats {
    zone: string;
    requests: number;
    threats_blocked: number;
    bandwidth: number;
    threats_by_type: Record<string, number>;
    security_level: string;
    last_sync: number | null;
}
/**
 * Optional Cloudflare / upstream provider integration for DDoS protection.
 *
 * Stores API credentials encrypted at rest (via the crypto-vault). When
 * active, the panel can synchronize security settings (WAF mode) and fetch
 * traffic analytics from the Cloudflare API. All network calls are optional
 * and fail gracefully — local firewall protection remains the primary
 * mitigation layer; Cloudflare is an additional edge layer.
 */
export declare class DdosCloudflareManager {
    private db;
    private keyCache;
    constructor(db: UnifiedDatabase);
    listIntegrations(): Promise<(Omit<CloudflareIntegration, 'api_key_enc'> & {
        has_key: boolean;
    })[]>;
    createIntegration(input: {
        name: string;
        provider: string;
        apiKey?: string;
        apiEmail?: string;
        zone?: string;
        securityLevel?: string;
        isActive?: number;
    }): Promise<CloudflareIntegration>;
    getIntegration(id: number): Promise<CloudflareIntegration | null>;
    updateIntegration(id: number, input: Partial<{
        name: string;
        provider: string;
        apiKey: string;
        apiEmail: string;
        zone: string;
        securityLevel: string;
        isActive: number;
    }>): Promise<CloudflareIntegration | null>;
    deleteIntegration(id: number): Promise<boolean>;
    private getApiKey;
    /**
     * Set the Cloudflare zone security level (WAF mode).
     * Requires network access to api.cloudflare.com — fails gracefully if unavailable.
     */
    setSecurityLevel(id: number, level: string): Promise<{
        success: boolean;
        message: string;
    }>;
    /**
     * Fetch traffic analytics from Cloudflare for a zone.
     * Returns zeroed stats if the API is unreachable (honest, no fake data).
     */
    getTrafficStats(id: number): Promise<CloudflareStats>;
    getSecurityLevels(): string[];
}
