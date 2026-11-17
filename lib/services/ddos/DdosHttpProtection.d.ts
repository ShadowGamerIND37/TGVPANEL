import type { UnifiedDatabase } from '../../db/database';
export interface HttpProtectionSettings {
    http_get_threshold: number;
    http_post_threshold: number;
    slowloris_threshold: number;
    suspicious_user_agent_block: number;
    trusted_proxies: string;
    connection_limit: number;
    per_ip_request_limit: number;
    burst_detection: number;
    cloudflare_enabled: number;
}
export interface HttpThreatResult {
    blocked: boolean;
    reason?: string;
    threatLevel?: 'low' | 'medium' | 'high' | 'critical';
    ip?: string;
}
/**
 * HTTP-layer DDoS protection.
 *
 * Detects HTTP GET/POST floods, HTTP connection floods, Slowloris/slow HTTP
 * attacks, suspicious user-agents, bot/abnormal requests, and request bursts.
 * Provides secure client-IP extraction that only trusts proxy headers from
 * configured trusted reverse proxies. Integrates with Cloudflare headers.
 */
export declare class DdosHttpProtection {
    private db;
    private settings;
    private requestTracker;
    private lastCleanup;
    constructor(db: UnifiedDatabase);
    loadSettings(): Promise<void>;
    getSettings(): HttpProtectionSettings;
    updateSettings(input: Partial<HttpProtectionSettings>): Promise<HttpProtectionSettings>;
    private getTrustedProxies;
    extractIP(req: {
        headers: Record<string, string | string[] | undefined>;
        socket?: {
            remoteAddress?: string | null;
        };
        connection?: {
            remoteAddress?: string | null;
        };
    }): string;
    /**
     * Analyze an incoming HTTP request for DDoS indicators.
     * Returns a threat result; if blocked, the caller should reject the request.
     */
    analyzeRequest(req: {
        headers: Record<string, string | string[] | undefined>;
        method: string;
        socket?: {
            remoteAddress?: string | null;
        };
        connection?: {
            remoteAddress?: string | null;
        };
        url?: string;
    }): HttpThreatResult;
    /**
     * Record a completed HTTP request for tracking (called on response finish).
     */
    recordRequest(ip: string, method: string): void;
    getTrackerStats(): {
        tracked_ips: number;
        top_ips: {
            ip: string;
            count: number;
        }[];
    };
    isSuspiciousUserAgent(ua: string): boolean;
    getSuspiciousPatterns(): string[];
}
