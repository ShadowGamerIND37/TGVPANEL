import http from 'http';
import sqlite3 from 'sqlite3';
import { UnifiedDatabase } from './db/database';
import { NodeManager } from './services/nodes/NodeClient';
import { KVMAdapter, LegacyKvmHooks } from './services/virtualization/KVMAdapter';
import { LXCAdapter } from './services/virtualization/LXCAdapter';
import { VirtualizationManager } from './services/virtualization/VirtualizationManager';
import { InstanceManager } from './services/virtualization/InstanceManager';
import { StorageManager } from './services/storage/StorageManager';
import { NetworkManager } from './services/network/NetworkManager';
import { LoadBalancerManager } from './services/network/LoadBalancerManager';
import { DockerManager } from './services/docker/DockerManager';
import { BillingManager } from './services/billing/BillingManager';
import { PaymentGatewayManager } from './services/billing/PaymentGatewayManager';
import { DdosManager } from './services/ddos/DdosManager';
import { DdosFirewallManager } from './services/ddos/DdosFirewallManager';
import { DdosHttpProtection } from './services/ddos/DdosHttpProtection';
import { DdosProfileManager } from './services/ddos/DdosProfileManager';
import { DdosCloudflareManager } from './services/ddos/DdosCloudflareManager';
import { DdosNodeSyncManager } from './services/ddos/DdosNodeSyncManager';
import { DdosVpsPolicyManager } from './services/ddos/DdosVpsPolicyManager';
import { SqliteSessionStore } from './security/session-store';
import { BackupSnapshotManager } from './services/backup/BackupSnapshotManager';
import { MigrationManager } from './services/migration/MigrationManager';
import { MonitoringService } from './services/monitoring/MonitoringService';
export interface HkvmRuntimeContext {
    db: UnifiedDatabase;
    nodeManager: NodeManager;
    kvmAdapter: KVMAdapter;
    lxcAdapter: LXCAdapter;
    virtManager: VirtualizationManager;
    instanceManager: InstanceManager;
    storageManager: StorageManager;
    networkManager: NetworkManager;
    loadBalancerManager: LoadBalancerManager;
    dockerManager: DockerManager;
    billingManager: BillingManager;
    paymentGatewayManager: PaymentGatewayManager;
    ddosManager: DdosManager;
    ddosFirewallManager: DdosFirewallManager;
    ddosHttpProtection: DdosHttpProtection;
    ddosProfileManager: DdosProfileManager;
    ddosCloudflareManager: DdosCloudflareManager;
    ddosNodeSyncManager: DdosNodeSyncManager;
    ddosVpsPolicyManager: DdosVpsPolicyManager;
    sessionStore: SqliteSessionStore;
    backupManager: BackupSnapshotManager;
    migrationManager: MigrationManager;
    monitoringService: MonitoringService;
}
export declare function initializeUnifiedHkvmRuntime(rawDb: sqlite3.Database, dbPath: string, legacyKvmHooks?: LegacyKvmHooks): Promise<HkvmRuntimeContext>;
export declare function getHkvmRuntimeContext(): HkvmRuntimeContext;
/**
 * Attaches session-authenticated WebSocket endpoints for:
 *  - `/ws/lxc/:id/console` (Real LXC container PTY console via LocalNodeRuntime or remote Node Agent)
 *  - `/ws/nodes/:id/shell` (Restricted, audited Admin Node Console)
 */
export declare function attachUnifiedWebSockets(server: http.Server, sessionMiddleware: any, ctx: HkvmRuntimeContext): void;
