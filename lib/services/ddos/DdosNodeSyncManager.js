"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DdosNodeSyncManager = void 0;
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
class DdosNodeSyncManager {
    db;
    nodeManager;
    syncTimer = null;
    syncInterval = 60_000;
    constructor(db, nodeManager) {
        this.db = db;
        this.nodeManager = nodeManager;
    }
    async start() {
        if (this.syncTimer)
            return;
        this.syncTimer = setInterval(() => { void this.syncAllNodes(); }, this.syncInterval);
        // Initial sync shortly after start
        setTimeout(() => { void this.syncAllNodes(); }, 5000);
    }
    async stop() {
        if (this.syncTimer)
            clearInterval(this.syncTimer);
        this.syncTimer = null;
    }
    async getAllStatus() {
        const nodes = await this.db.all(`SELECT * FROM ddos_node_status ORDER BY node_id`);
        // Ensure local node has a status row
        return nodes;
    }
    async getStatus(nodeId) {
        const row = await this.db.get(`SELECT * FROM ddos_node_status WHERE node_id = ?`, [nodeId]);
        return row || null;
    }
    async enableNode(nodeId, profileId) {
        await this.db.run(`INSERT INTO ddos_node_status (node_id, enabled, profile_id, online, updated_at)
       VALUES (?, 1, ?, 0, ?)
       ON CONFLICT(node_id) DO UPDATE SET enabled = 1, profile_id = COALESCE(?, profile_id), updated_at = ?`, [nodeId, profileId || null, Date.now(), profileId || null, Date.now()]);
        return true;
    }
    async disableNode(nodeId) {
        const result = await this.db.run(`UPDATE ddos_node_status SET enabled = 0, updated_at = ? WHERE node_id = ?`, [Date.now(), nodeId]);
        return result.changes > 0;
    }
    async setProfile(nodeId, profileId) {
        const result = await this.db.run(`UPDATE ddos_node_status SET profile_id = ?, updated_at = ? WHERE node_id = ?`, [profileId, Date.now(), nodeId]);
        return result.changes > 0;
    }
    /**
     * Push configuration to a remote node agent via its HTTP API.
     * Returns success/failure; network errors are recorded, never thrown.
     */
    async pushConfig(nodeId) {
        try {
            const node = await this.nodeManager.getNodeById(nodeId);
            if (!node)
                return { success: false, message: 'Node not found.' };
            const status = await this.getStatus(nodeId);
            if (!status || !status.enabled)
                return { success: false, message: 'Node DDoS protection is disabled.' };
            const config = {
                profile_id: status.profile_id,
                enabled: true,
            };
            // The node agent exposes POST /api/v1/ddos/config
            const result = await this.nodeManager.requestRemoteNode(nodeId, 'POST', '/api/v1/ddos/config', config);
            await this.db.run(`UPDATE ddos_node_status SET last_sync_at = ?, last_error = NULL, online = 1 WHERE node_id = ?`, [Date.now(), nodeId]);
            return { success: true, message: 'Config pushed to node.' };
        }
        catch (err) {
            await this.db.run(`UPDATE ddos_node_status SET last_error = ?, online = 0 WHERE node_id = ?`, [err.message, nodeId]);
            return { success: false, message: `Node unreachable: ${err.message}` };
        }
    }
    /**
     * Pull real-time statistics from a node agent.
     */
    async pullStats(nodeId) {
        try {
            const result = await this.nodeManager.requestRemoteNode(nodeId, 'GET', '/api/v1/ddos/stats');
            const stats = result.stats || {};
            await this.db.run(`UPDATE ddos_node_status SET pps = ?, bps = ?, active_connections = ?, blocked_ips = ?, last_sync_at = ?, last_error = NULL, online = 1 WHERE node_id = ?`, [stats.pps || 0, stats.bps || 0, stats.active_connections || 0, stats.blocked_ips || 0, Date.now(), nodeId]);
            return { success: true, stats, message: 'Stats pulled from node.' };
        }
        catch (err) {
            await this.db.run(`UPDATE ddos_node_status SET last_error = ?, online = 0 WHERE node_id = ?`, [err.message, nodeId]);
            return { success: false, message: `Node unreachable: ${err.message}` };
        }
    }
    /**
     * Sync all enabled nodes: push config + pull stats.
     */
    async syncAllNodes() {
        const enabledNodes = await this.db.all(`SELECT node_id FROM ddos_node_status WHERE enabled = 1`);
        for (const node of enabledNodes) {
            await this.pushConfig(node.node_id);
            await this.pullStats(node.node_id);
        }
    }
    /**
     * Handle node disconnection: mark as offline, keep last stats.
     */
    async handleNodeDisconnect(nodeId) {
        await this.db.run(`UPDATE ddos_node_status SET online = 0, last_error = 'node_disconnected' WHERE node_id = ?`, [nodeId]);
    }
    /**
     * Initialize node status for all registered nodes (on startup).
     */
    async initializeNodes() {
        const nodes = await this.nodeManager.listNodes();
        for (const node of nodes) {
            const existing = await this.getStatus(node.id);
            if (!existing) {
                await this.db.run(`INSERT INTO ddos_node_status (node_id, enabled, online, updated_at) VALUES (?, 0, 0, ?)
           ON CONFLICT(node_id) DO NOTHING`, [node.id, Date.now()]);
            }
        }
    }
    async getOnlineNodes() {
        return this.db.all(`SELECT * FROM ddos_node_status WHERE enabled = 1 AND online = 1`);
    }
}
exports.DdosNodeSyncManager = DdosNodeSyncManager;
