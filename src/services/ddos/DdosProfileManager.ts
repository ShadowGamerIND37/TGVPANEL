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

const PROFILE_LEVELS = ['basic', 'standard', 'advanced', 'aggressive', 'custom'];

/**
 * Management of DDoS protection profiles.
 * Profiles define reusable threshold sets (Basic, Standard, Advanced,
 * Aggressive, Custom) that can be assigned to nodes and VPS instances.
 */
export class DdosProfileManager {
  private db: UnifiedDatabase;

  constructor(db: UnifiedDatabase) {
    this.db = db;
  }

  public async listProfiles(): Promise<DdosProfile[]> {
    return this.db.all<DdosProfile>(`SELECT * FROM ddos_profiles ORDER BY id`);
  }

  public async getProfile(id: number): Promise<DdosProfile | null> {
    const row = await this.db.get<DdosProfile>(`SELECT * FROM ddos_profiles WHERE id = ?`, [id]);
    return row || null;
  }

  public async getActiveProfile(): Promise<DdosProfile | null> {
    const row = await this.db.get<DdosProfile>(`SELECT * FROM ddos_profiles WHERE is_active = 1 ORDER BY id LIMIT 1`);
    return row || null;
  }

  public async createProfile(input: Partial<DdosProfile> & { name: string }): Promise<DdosProfile> {
    const level = input.level && PROFILE_LEVELS.includes(input.level) ? input.level : 'custom';
    const result = await this.db.run(
      `INSERT INTO ddos_profiles
        (name, description, level, syn_cookies, connection_limit, packet_rate_limit, per_ip_rate_limit,
         auto_block, block_duration, threat_threshold_medium, threat_threshold_high, threat_threshold_critical,
         http_get_threshold, http_post_threshold, slowloris_threshold, dns_amp_threshold, udp_amp_threshold,
         packet_rate_threshold, suspicious_ua_block, emergency_mode, protocols, ports, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        input.name, input.description || null, level,
        input.syn_cookies ?? 1, input.connection_limit ?? 1000, input.packet_rate_limit ?? 0,
        input.per_ip_rate_limit ?? 0, input.auto_block ?? 1, input.block_duration ?? 3600,
        input.threat_threshold_medium ?? 100, input.threat_threshold_high ?? 500, input.threat_threshold_critical ?? 1000,
        input.http_get_threshold ?? 300, input.http_post_threshold ?? 150, input.slowloris_threshold ?? 20,
        input.dns_amp_threshold ?? 100, input.udp_amp_threshold ?? 100, input.packet_rate_threshold ?? 5000,
        input.suspicious_ua_block ?? 1, input.emergency_mode ?? 0,
        input.protocols || null, input.ports || null, input.is_active ?? 0,
      ]
    );
    const created = await this.getProfile(result.lastID);
    return created!;
  }

  public async updateProfile(id: number, input: Partial<DdosProfile>): Promise<DdosProfile | null> {
    const existing = await this.getProfile(id);
    if (!existing) return null;
    const next = { ...existing, ...input, id };
    const level = PROFILE_LEVELS.includes(next.level) ? next.level : existing.level;
    await this.db.run(
      `UPDATE ddos_profiles SET
         name=?, description=?, level=?, syn_cookies=?, connection_limit=?, packet_rate_limit=?, per_ip_rate_limit=?,
         auto_block=?, block_duration=?, threat_threshold_medium=?, threat_threshold_high=?, threat_threshold_critical=?,
         http_get_threshold=?, http_post_threshold=?, slowloris_threshold=?, dns_amp_threshold=?, udp_amp_threshold=?,
         packet_rate_threshold=?, suspicious_ua_block=?, emergency_mode=?, protocols=?, ports=?, is_active=?
       WHERE id = ?`,
      [
        next.name, next.description, level,
        next.syn_cookies, next.connection_limit, next.packet_rate_limit, next.per_ip_rate_limit,
        next.auto_block, next.block_duration, next.threat_threshold_medium, next.threat_threshold_high, next.threat_threshold_critical,
        next.http_get_threshold, next.http_post_threshold, next.slowloris_threshold, next.dns_amp_threshold, next.udp_amp_threshold,
        next.packet_rate_threshold, next.suspicious_ua_block, next.emergency_mode,
        next.protocols, next.ports, next.is_active, id,
      ]
    );
    return this.getProfile(id);
  }

  public async deleteProfile(id: number): Promise<boolean> {
    // Deactivate assignments first
    await this.db.run(`DELETE FROM ddos_profile_assignments WHERE profile_id = ?`, [id]);
    const result = await this.db.run(`DELETE FROM ddos_profiles WHERE id = ?`, [id]);
    return result.changes > 0;
  }

  public async setActiveProfile(id: number): Promise<boolean> {
    // Deactivate all, activate the selected
    await this.db.run(`UPDATE ddos_profiles SET is_active = 0`);
    const result = await this.db.run(`UPDATE ddos_profiles SET is_active = 1 WHERE id = ?`, [id]);
    return result.changes > 0;
  }

  public async assignProfile(profileId: number, nodeId?: number, vpsId?: number): Promise<boolean> {
    await this.db.run(
      `INSERT OR IGNORE INTO ddos_profile_assignments (profile_id, node_id, vps_id) VALUES (?, ?, ?)`,
      [profileId, nodeId || null, vpsId || null]
    );
    return true;
  }

  public async unassignProfile(profileId: number, nodeId?: number, vpsId?: number): Promise<boolean> {
    const result = await this.db.run(
      `DELETE FROM ddos_profile_assignments WHERE profile_id = ? AND node_id IS ? AND vps_id IS ?`,
      [profileId, nodeId || null, vpsId || null]
    );
    return result.changes > 0;
  }

  public async getAssignments(profileId?: number): Promise<DdosProfileAssignment[]> {
    if (profileId) {
      return this.db.all<DdosProfileAssignment>(`SELECT * FROM ddos_profile_assignments WHERE profile_id = ?`, [profileId]);
    }
    return this.db.all<DdosProfileAssignment>(`SELECT * FROM ddos_profile_assignments`);
  }

  public async getProfileForNode(nodeId: number): Promise<DdosProfile | null> {
    const assignment = await this.db.get<{ profile_id: number }>(
      `SELECT profile_id FROM ddos_profile_assignments WHERE node_id = ?`, [nodeId]
    );
    if (!assignment) return this.getActiveProfile();
    return this.getProfile(assignment.profile_id);
  }

  public async getProfileForVps(vpsId: number): Promise<DdosProfile | null> {
    const assignment = await this.db.get<{ profile_id: number }>(
      `SELECT profile_id FROM ddos_profile_assignments WHERE vps_id = ?`, [vpsId]
    );
    if (!assignment) return this.getActiveProfile();
    return this.getProfile(assignment.profile_id);
  }

  public getLevels(): string[] {
    return [...PROFILE_LEVELS];
  }
}
