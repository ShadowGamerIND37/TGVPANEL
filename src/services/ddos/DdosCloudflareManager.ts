import { encryptSecret, decryptSecret } from '../../security/crypto-vault';
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

const CLOUDFLARE_SECURITY_LEVELS = ['off', 'low', 'medium', 'high', 'under_attack'];

/**
 * Optional Cloudflare / upstream provider integration for DDoS protection.
 *
 * Stores API credentials encrypted at rest (via the crypto-vault). When
 * active, the panel can synchronize security settings (WAF mode) and fetch
 * traffic analytics from the Cloudflare API. All network calls are optional
 * and fail gracefully — local firewall protection remains the primary
 * mitigation layer; Cloudflare is an additional edge layer.
 */
export class DdosCloudflareManager {
  private db: UnifiedDatabase;
  // In-memory cache of decrypted API key for API calls (not persisted)
  private keyCache: Map<number, string> = new Map();

  constructor(db: UnifiedDatabase) {
    this.db = db;
  }

  public async listIntegrations(): Promise<(Omit<CloudflareIntegration, 'api_key_enc'> & { has_key: boolean })[]> {
    const rows = await this.db.all<CloudflareIntegration>(`SELECT * FROM ddos_integrations ORDER BY id`);
    return rows.map((r) => ({
      id: r.id, name: r.name, provider: r.provider, api_email: r.api_email,
      zone: r.zone, security_level: r.security_level, is_active: r.is_active,
      last_sync_at: r.last_sync_at, last_error: r.last_error, created_at: r.created_at,
      has_key: Boolean(r.api_key_enc),
    }));
  }

  public async createIntegration(input: {
    name: string;
    provider: string;
    apiKey?: string;
    apiEmail?: string;
    zone?: string;
    securityLevel?: string;
    isActive?: number;
  }): Promise<CloudflareIntegration> {
    const encrypted = input.apiKey ? encryptSecret(input.apiKey) : null;
    const result = await this.db.run(
      `INSERT INTO ddos_integrations (name, provider, api_key_enc, api_email, zone, security_level, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [input.name, input.provider, encrypted, input.apiEmail || null, input.zone || null,
       input.securityLevel && CLOUDFLARE_SECURITY_LEVELS.includes(input.securityLevel) ? input.securityLevel : 'medium',
       input.isActive ?? 0]
    );
    const created = await this.getIntegration(result.lastID);
    return created!;
  }

  public async getIntegration(id: number): Promise<CloudflareIntegration | null> {
    const row = await this.db.get<CloudflareIntegration>(`SELECT * FROM ddos_integrations WHERE id = ?`, [id]);
    return row || null;
  }

  public async updateIntegration(id: number, input: Partial<{
    name: string; provider: string; apiKey: string; apiEmail: string;
    zone: string; securityLevel: string; isActive: number;
  }>): Promise<CloudflareIntegration | null> {
    const existing = await this.getIntegration(id);
    if (!existing) return null;
    const encrypted = input.apiKey ? encryptSecret(input.apiKey) : null;
    await this.db.run(
      `UPDATE ddos_integrations SET
         name=?, provider=?, api_key_enc=COALESCE(?, api_key_enc), api_email=?,
         zone=?, security_level=?, is_active=?, last_error=NULL
       WHERE id = ?`,
      [input.name ?? existing.name, input.provider ?? existing.provider, encrypted,
       input.apiEmail ?? existing.api_email, input.zone ?? existing.zone,
       input.securityLevel && CLOUDFLARE_SECURITY_LEVELS.includes(input.securityLevel) ? input.securityLevel : existing.security_level,
       input.isActive ?? existing.is_active, id]
    );
    if (input.apiKey) {
      const fresh = await this.getIntegration(id);
      if (fresh) this.keyCache.set(id, decryptSecret(fresh.api_key_enc!));
    }
    return await this.getIntegration(id);
  }

  public async deleteIntegration(id: number): Promise<boolean> {
    this.keyCache.delete(id);
    const result = await this.db.run(`DELETE FROM ddos_integrations WHERE id = ?`, [id]);
    return result.changes > 0;
  }

  private async getApiKey(id: number): Promise<string | null> {
    if (this.keyCache.has(id)) return this.keyCache.get(id)!;
    const row = await this.db.get<{ api_key_enc: string | null }>(`SELECT api_key_enc FROM ddos_integrations WHERE id = ?`, [id]);
    if (row?.api_key_enc) {
      const key = decryptSecret(row.api_key_enc);
      if (key) this.keyCache.set(id, key);
      return key;
    }
    return null;
  }

  /**
   * Set the Cloudflare zone security level (WAF mode).
   * Requires network access to api.cloudflare.com — fails gracefully if unavailable.
   */
  public async setSecurityLevel(id: number, level: string): Promise<{ success: boolean; message: string }> {
    if (!CLOUDFLARE_SECURITY_LEVELS.includes(level)) {
      return { success: false, message: `Invalid security level. Must be one of: ${CLOUDFLARE_SECURITY_LEVELS.join(', ')}` };
    }
    const integration = await this.getIntegration(id);
    if (!integration) return { success: false, message: 'Integration not found.' };
    const apiKey = await this.getApiKey(id);
    if (!apiKey) return { success: false, message: 'API key not configured.' };
    if (!integration.zone) return { success: false, message: 'No zone configured.' };

    try {
      // Cloudflare API: PATCH zone security level
      const response = await fetch(
        `https://api.cloudflare.com/client/v4/zones/${integration.zone}/settings/security_level`,
        {
          method: 'PATCH',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ value: level }),
        }
      );
      const data = await response.json() as { success?: boolean; errors?: { message: string }[] };
      if (data.success) {
        await this.db.run(`UPDATE ddos_integrations SET security_level=?, last_sync_at=?, last_error=NULL WHERE id=?`, [level, Date.now(), id]);
        return { success: true, message: `Security level set to ${level}` };
      }
      const errMsg = data.errors?.[0]?.message || 'Cloudflare API returned an error';
      await this.db.run(`UPDATE ddos_integrations SET last_error=? WHERE id=?`, [errMsg, id]);
      return { success: false, message: errMsg };
    } catch (err: any) {
      await this.db.run(`UPDATE ddos_integrations SET last_error=? WHERE id=?`, [err.message, id]);
      return { success: false, message: `Cloudflare API unreachable: ${err.message}` };
    }
  }

  /**
   * Fetch traffic analytics from Cloudflare for a zone.
   * Returns zeroed stats if the API is unreachable (honest, no fake data).
   */
  public async getTrafficStats(id: number): Promise<CloudflareStats> {
    const integration = await this.getIntegration(id);
    if (!integration) {
      return { zone: '', requests: 0, threats_blocked: 0, bandwidth: 0, threats_by_type: {}, security_level: '', last_sync: null };
    }
    const apiKey = await this.getApiKey(id);
    if (!apiKey || !integration.zone) {
      return {
        zone: integration.zone || '', requests: 0, threats_blocked: 0, bandwidth: 0,
        threats_by_type: {}, security_level: integration.security_level, last_sync: integration.last_sync_at,
      };
    }

    try {
      const now = Math.floor(Date.now() / 1000);
      const oneDayAgo = now - 86400;
      const response = await fetch(
        `https://api.cloudflare.com/client/v4/zones/${integration.zone}/analytics/dashboard?from=${oneDayAgo}&to=${now}`,
        { headers: { 'Authorization': `Bearer ${apiKey}` } }
      );
      const data = await response.json() as {
        success?: boolean;
        result?: {
          totals?: Record<string, number>;
          timeseries?: Array<Record<string, number>>;
        };
      };
      if (data.success && data.result) {
        const totals = data.result.totals || {};
        await this.db.run(`UPDATE ddos_integrations SET last_sync_at=?, last_error=NULL WHERE id=?`, [Date.now(), id]);
        return {
          zone: integration.zone,
          requests: totals.requests || 0,
          threats_blocked: totals.threats_blocked || 0,
          bandwidth: totals.bandwidth || 0,
          threats_by_type: {},
          security_level: integration.security_level,
          last_sync: Date.now(),
        };
      }
      await this.db.run(`UPDATE ddos_integrations SET last_error=? WHERE id=?`, ['Cloudflare API returned no data', id]);
      return {
        zone: integration.zone, requests: 0, threats_blocked: 0, bandwidth: 0,
        threats_by_type: {}, security_level: integration.security_level, last_sync: integration.last_sync_at,
      };
    } catch (err: any) {
      await this.db.run(`UPDATE ddos_integrations SET last_error=? WHERE id=?`, [err.message, id]);
      return {
        zone: integration.zone, requests: 0, threats_blocked: 0, bandwidth: 0,
        threats_by_type: {}, security_level: integration.security_level, last_sync: integration.last_sync_at,
      };
    }
  }

  public getSecurityLevels(): string[] {
    return [...CLOUDFLARE_SECURITY_LEVELS];
  }
}
