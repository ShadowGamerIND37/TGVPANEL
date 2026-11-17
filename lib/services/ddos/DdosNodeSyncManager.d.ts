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
export declare class DdosNodeSyncManager {
    private db;
    private nodeManager;
    private syncTimer;
    private syncInterval;
    constructor(db: UnifiedDatabase, nodeManager: NodeManager);
    start(): Promise<void>;
    stop(): Promise<void>;
    getAllStatus(): Promise<NodeDdosStatus[]>;
    getStatus(nodeId: number): Promise<NodeDdosStatus | null>;
    enableNode(nodeId: number, profileId?: number): Promise<boolean>;
    disableNode(nodeId: number): Promise<boolean>;
    setProfile(nodeId: number, profileId: number | null): Promise<boolean>;
    /**
     * Push configuration to a remote node agent via its HTTP API.
     * Returns success/failure; network errors are recorded, never thrown.
     */
    pushConfig(nodeId: number): Promise<{
        success: boolean;
        message: string;
    }>;
    /**
     * Pull real-time statistics from a node agent.
     */
    pullStats(nodeId: number): Promise<{
        success: boolean;
        stats?: Record<string, number>;
        message: string;
    }>;
    /**
     * Sync all enabled nodes: push config + pull stats.
     */
    syncAllNodes(): Promise<void>;
    /**
     * Handle node disconnection: mark as offline, keep last stats.
     */
    handleNodeDisconnect(nodeId: number): Promise<void>;
    /**
     * Initialize node status for all registered nodes (on startup).
     */
    initializeNodes(): Promise<void>;
    getOnlineNodes(): Promise<NodeDdosStatus[]>;
}
