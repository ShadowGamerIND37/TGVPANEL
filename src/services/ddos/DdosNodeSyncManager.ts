import type { UnifiedDatabase } from '../../db/database';
import type { NodeManager } from '../nodes/NodeClient';

export interface NodeDdosStatus {
  node_id: number;
  enabled: number;
  profile_id: number | null;
  online: number;
  last_sync_at: number | null;
  last_error: string | null;
  pps: number;
  bps: number;
  active_connections: number;
  blocked_ips: number;
}

export interface NodeDdosConfig {
  profile_id: number | null;
  enabled: boolean;
  thresholds?: Record<string, number>;
}

/**
 * Multi-node DDoS protection sync manager.
 *
 * Centralizes protection management across TGVPANEL's registered nodes.
 * Each node runs its own DDoS monitoring/mitigation agent (via the Node
 * Agent). The panel pushes configuration (profile thresholds, enabled state)
 * to nodes and pulls real-time statistics. Node disconnection is handled
 * gracefully — offline nodes report as offline with stale data, never
 * blocking the central panel.
 */
export class DdosNodeSyncManager {
  private db: UnifiedDatabase;
  private nodeManager: NodeManager;
  private syncTimer: NodeJS.Timeout | null = null;
  private syncInterval = 60_000;

  constructor(db: UnifiedDatabase, nodeManager: NodeManager) {
    this.db = db;
    this.nodeManager = nodeManager;
  }

  public async start(): Promise<void> {
    if (this.syncTimer) return;
    this.syncTimer = setInterval(() => { void this.syncAllNodes(); }, this.syncInterval);
    // Initial sync shortly after start
    setTimeout(() => { void this.syncAllNodes(); }, 5000);
  }

  public async stop(): Promise<void> {
    if (this.syncTimer) clearInterval(this.syncTimer);
    this.syncTimer = null;
  }

  public async getAllStatus(): Promise<NodeDdosStatus[]> {
    const nodes = await this.db.all<NodeDdosStatus>(`SELECT * FROM ddos_node_status ORDER BY node_id`);
    // Ensure local node has a status row
    return nodes;
  }

  public async getStatus(nodeId: number): Promise<NodeDdosStatus | null> {
    const row = await this.db.get<NodeDdosStatus>(`SELECT * FROM ddos_node_status WHERE node_id = ?`, [nodeId]);
    return row || null;
  }

  public async enableNode(nodeId: number, profileId?: number): Promise<boolean> {
    await this.db.run(
      `INSERT INTO ddos_node_status (node_id, enabled, profile_id, online, updated_at)
       VALUES (?, 1, ?, 0, ?)
       ON CONFLICT(node_id) DO UPDATE SET enabled = 1, profile_id = COALESCE(?, profile_id), updated_at = ?`,
      [nodeId, profileId || null, Date.now(), profileId || null, Date.now()]
    );
    return true;
  }

  public async disableNode(nodeId: number): Promise<boolean> {
    const result = await this.db.run(`UPDATE ddos_node_status SET enabled = 0, updated_at = ? WHERE node_id = ?`, [Date.now(), nodeId]);
    return result.changes > 0;
  }

  public async setProfile(nodeId: number, profileId: number | null): Promise<boolean> {
    const result = await this.db.run(`UPDATE ddos_node_status SET profile_id = ?, updated_at = ? WHERE node_id = ?`, [profileId, Date.now(), nodeId]);
    return result.changes > 0;
  }

  /**
   * Push configuration to a remote node agent via its HTTP API.
   * Returns success/failure; network errors are recorded, never thrown.
   */
  public async pushConfig(nodeId: number): Promise<{ success: boolean; message: string }> {
    try {
      const node = await this.nodeManager.getNodeById(nodeId);
      if (!node) return { success: false, message: 'Node not found.' };
      const status = await this.getStatus(nodeId);
      if (!status || !status.enabled) return { success: false, message: 'Node DDoS protection is disabled.' };

      const config: NodeDdosConfig = {
        profile_id: status.profile_id,
        enabled: true,
      };

      // The node agent exposes POST /api/v1/ddos/config
      const result = await this.nodeManager.requestRemoteNode(nodeId, 'POST', '/api/v1/ddos/config', config);

      await this.db.run(`UPDATE ddos_node_status SET last_sync_at = ?, last_error = NULL, online = 1 WHERE node_id = ?`, [Date.now(), nodeId]);
      return { success: true, message: 'Config pushed to node.' };
    } catch (err: any) {
      await this.db.run(`UPDATE ddos_node_status SET last_error = ?, online = 0 WHERE node_id = ?`, [err.message, nodeId]);
      return { success: false, message: `Node unreachable: ${err.message}` };
    }
  }

  /**
   * Pull real-time statistics from a node agent.
   */
  public async pullStats(nodeId: number): Promise<{ success: boolean; stats?: Record<string, number>; message: string }> {
    try {
      const result = await this.nodeManager.requestRemoteNode(nodeId, 'GET', '/api/v1/ddos/stats');
      const stats = (result as any).stats || {};
      await this.db.run(
        `UPDATE ddos_node_status SET pps = ?, bps = ?, active_connections = ?, blocked_ips = ?, last_sync_at = ?, last_error = NULL, online = 1 WHERE node_id = ?`,
        [stats.pps || 0, stats.bps || 0, stats.active_connections || 0, stats.blocked_ips || 0, Date.now(), nodeId]
      );
      return { success: true, stats, message: 'Stats pulled from node.' };
    } catch (err: any) {
      await this.db.run(`UPDATE ddos_node_status SET last_error = ?, online = 0 WHERE node_id = ?`, [err.message, nodeId]);
      return { success: false, message: `Node unreachable: ${err.message}` };
    }
  }

  /**
   * Sync all enabled nodes: push config + pull stats.
   */
  public async syncAllNodes(): Promise<void> {
    const enabledNodes = await this.db.all<{ node_id: number }>(`SELECT node_id FROM ddos_node_status WHERE enabled = 1`);
    for (const node of enabledNodes) {
      await this.pushConfig(node.node_id);
      await this.pullStats(node.node_id);
    }
  }

  /**
   * Handle node disconnection: mark as offline, keep last stats.
   */
  public async handleNodeDisconnect(nodeId: number): Promise<void> {
    await this.db.run(`UPDATE ddos_node_status SET online = 0, last_error = 'node_disconnected' WHERE node_id = ?`, [nodeId]);
  }

  /**
   * Initialize node status for all registered nodes (on startup).
   */
  public async initializeNodes(): Promise<void> {
    const nodes = await this.nodeManager.listNodes();
    for (const node of nodes) {
      const existing = await this.getStatus(node.id);
      if (!existing) {
        await this.db.run(
          `INSERT INTO ddos_node_status (node_id, enabled, online, updated_at) VALUES (?, 0, 0, ?)
           ON CONFLICT(node_id) DO NOTHING`,
          [node.id, Date.now()]
        );
      }
    }
  }

  public async getOnlineNodes(): Promise<NodeDdosStatus[]> {
    return this.db.all<NodeDdosStatus>(`SELECT * FROM ddos_node_status WHERE enabled = 1 AND online = 1`);
  }
}
