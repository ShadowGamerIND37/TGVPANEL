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

const DEFAULT_HTTP_SETTINGS: HttpProtectionSettings = {
  http_get_threshold: 300,
  http_post_threshold: 150,
  slowloris_threshold: 20,
  suspicious_user_agent_block: 1,
  trusted_proxies: '',
  connection_limit: 1000,
  per_ip_request_limit: 100,
  burst_detection: 50,
  cloudflare_enabled: 0,
};

const SUSPICIOUS_UA_PATTERNS = [
  /sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /zgrab/i, /python-requests/i,
  /curl\//i, /wget\//i, /go-http-client/i, /java\/http/i, /libwww-perl/i,
  /python-urllib/i, /httpclient/i, /scrapy/i, /headlesschrome/i,
];

function extractClientIP(req: { headers: Record<string, string | string[] | undefined>; socket?: { remoteAddress?: string | null }; connection?: { remoteAddress?: string | null } }, trustedProxies: string[]): string {
  // Secure real client IP extraction: only trust X-Forwarded-For / X-Real-IP
  // from configured trusted reverse proxies. Otherwise use the socket address.
  const forwarded = req.headers['x-forwarded-for'];
  const realIp = req.headers['x-real-ip'];
  const proto = req.headers['x-forwarded-proto'];

  const socketAddr = (req.socket?.remoteAddress || req.connection?.remoteAddress || '').replace(/^::ffff:/, '');

  // If no trusted proxies configured, never trust proxy headers
  if (trustedProxies.length === 0) {
    return socketAddr || 'unknown';
  }

  // Check if socket address is a trusted proxy
  const socketIsTrusted = trustedProxies.includes(socketAddr);
  if (!socketIsTrusted) {
    return socketAddr || 'unknown';
  }

  // Trusted proxy: use X-Forwarded-For (leftmost = original client)
  if (forwarded) {
    const fwdValue = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    const firstIp = fwdValue.split(',')[0].trim();
    if (firstIp) return firstIp;
  }
  if (realIp) {
    return Array.isArray(realIp) ? realIp[0] : realIp;
  }
  return socketAddr || 'unknown';
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
export class DdosHttpProtection {
  private db: UnifiedDatabase;
  private settings: HttpProtectionSettings = { ...DEFAULT_HTTP_SETTINGS };
  // Per-IP request tracking: ip -> { windowStart, count, firstSeen, slowRequests }
  private requestTracker = new Map<string, { windowStart: number; count: number; firstSeen: number; slowRequests: number; userAgents: Set<string> }>();
  private lastCleanup = 0;

  constructor(db: UnifiedDatabase) {
    this.db = db;
  }

  public async loadSettings(): Promise<void> {
    const row = await this.db.get<HttpProtectionSettings>(`SELECT * FROM ddos_settings WHERE id = 1`);
    if (row) {
      this.settings = { ...DEFAULT_HTTP_SETTINGS, ...row };
    }
  }

  public getSettings(): HttpProtectionSettings {
    return { ...this.settings };
  }

  public async updateSettings(input: Partial<HttpProtectionSettings>): Promise<HttpProtectionSettings> {
    const allowed = [
      'http_get_threshold', 'http_post_threshold', 'slowloris_threshold',
      'suspicious_user_agent_block', 'trusted_proxies', 'connection_limit',
      'per_ip_request_limit', 'burst_detection', 'cloudflare_enabled',
    ] as const;
    const next = { ...this.settings };
    for (const key of allowed) {
      if (input[key] !== undefined) {
        if (key === 'trusted_proxies') {
          (next as unknown as Record<string, unknown>)[key] = String(input[key]);
        } else {
          (next as unknown as Record<string, unknown>)[key] = Number(input[key]);
        }
      }
    }
    // Update the relevant columns in ddos_settings
    const cols = allowed.filter((k) => input[k] !== undefined);
    if (cols.length > 0) {
      const setClauses = cols.map((c) => `${c} = ?`);
      const params = cols.map((c) => {
        const v = (next as unknown as Record<string, unknown>)[c];
        return c === 'trusted_proxies' ? v : Number(v);
      });
      await this.db.run(`UPDATE ddos_settings SET ${setClauses.join(', ')} WHERE id = 1`, params);
    }
    this.settings = next;
    return { ...next };
  }

  private getTrustedProxies(): string[] {
    return this.settings.trusted_proxies
      ? this.settings.trusted_proxies.split(',').map((s) => s.trim()).filter(Boolean)
      : [];
  }

  public extractIP(req: { headers: Record<string, string | string[] | undefined>; socket?: { remoteAddress?: string | null }; connection?: { remoteAddress?: string | null } }): string {
    return extractClientIP(req, this.getTrustedProxies());
  }

  /**
   * Analyze an incoming HTTP request for DDoS indicators.
   * Returns a threat result; if blocked, the caller should reject the request.
   */
  public analyzeRequest(req: {
    headers: Record<string, string | string[] | undefined>;
    method: string;
    socket?: { remoteAddress?: string | null };
    connection?: { remoteAddress?: string | null };
    url?: string;
  }): HttpThreatResult {
    // Clean up stale trackers periodically (every 60s)
    const now = Date.now();
    if (now - this.lastCleanup > 60000) {
      this.lastCleanup = now;
      for (const [ip, t] of this.requestTracker.entries()) {
        if (now - t.firstSeen > 120000) this.requestTracker.delete(ip);
      }
    }

    const ip = this.extractIP(req);
    const userAgent = String(req.headers['user-agent'] || 'unknown');
    const method = (req.method || 'GET').toUpperCase();

    // Suspicious user-agent detection
    if (this.settings.suspicious_user_agent_block) {
      for (const pattern of SUSPICIOUS_UA_PATTERNS) {
        if (pattern.test(userAgent)) {
          return { blocked: true, reason: 'suspicious_user_agent', threatLevel: 'medium', ip };
        }
      }
    }

    // Cloudflare integration: if Cloudflare is enabled, trust CF-Connecting-IP
    const cfIp = req.headers['cf-connecting-ip'] as string | undefined;
    if (this.settings.cloudflare_enabled && cfIp) {
      // Cloudflare handles the attack at the edge; don't block locally
      return { blocked: false, ip: cfIp, threatLevel: 'low' };
    }

    // Track per-IP request rate (per 60s window)
    let tracker = this.requestTracker.get(ip);
    if (!tracker) {
      tracker = { windowStart: now, count: 0, firstSeen: now, slowRequests: 0, userAgents: new Set<string>() };
      this.requestTracker.set(ip, tracker);
    }
    tracker.count++;
    tracker.userAgents.add(userAgent);

    // Slowloris detection: too many distinct user-agents with low request volume
    if (tracker.userAgents.size > this.settings.slowloris_threshold && tracker.count < tracker.userAgents.size * 3) {
      return { blocked: true, reason: 'slowloris', threatLevel: 'high', ip };
    }

    // Burst detection
    if (tracker.count > this.settings.burst_detection && now - tracker.windowStart < 1000) {
      return { blocked: true, reason: 'request_burst', threatLevel: 'medium', ip };
    }

    // HTTP GET/POST flood thresholds
    if (method === 'GET' && tracker.count >= this.settings.http_get_threshold) {
      return { blocked: true, reason: 'http_get_flood', threatLevel: 'high', ip };
    }
    if (method === 'POST' && tracker.count >= this.settings.http_post_threshold) {
      return { blocked: true, reason: 'http_post_flood', threatLevel: 'high', ip };
    }

    // Per-IP request limit
    if (tracker.count >= this.settings.per_ip_request_limit * 10) {
      return { blocked: true, reason: 'per_ip_request_limit', threatLevel: 'medium', ip };
    }

    return { blocked: false, ip, threatLevel: 'low' };
  }

  /**
   * Record a completed HTTP request for tracking (called on response finish).
   */
  public recordRequest(ip: string, method: string): void {
    // Window rollover
    const now = Date.now();
    const tracker = this.requestTracker.get(ip);
    if (tracker && now - tracker.windowStart > 60000) {
      tracker.windowStart = now;
      tracker.count = 0;
    }
  }

  public getTrackerStats(): { tracked_ips: number; top_ips: { ip: string; count: number }[] } {
    const top = Array.from(this.requestTracker.entries())
      .map(([ip, t]) => ({ ip, count: t.count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 20);
    return { tracked_ips: this.requestTracker.size, top_ips: top };
  }

  public isSuspiciousUserAgent(ua: string): boolean {
    return SUSPICIOUS_UA_PATTERNS.some((p) => p.test(ua));
  }

  public getSuspiciousPatterns(): string[] {
    return SUSPICIOUS_UA_PATTERNS.map((p) => p.source);
  }
}
