import { UnifiedDatabase } from '../../db/database';
import { AuthenticatedPrincipal } from '../../security/middleware';
import { VirtualizationManager } from './VirtualizationManager';
import { InstanceTask, InstanceTaskManager } from './InstanceTaskManager';
import { InstanceTelemetry, LifecycleAction, UnifiedInstanceRecord, VirtualizationEngine } from './VirtualizationAdapter';
export { VirtualizationManager };
/**
 * High-level Unified Instance Manager handling cross-engine queries, RBAC/ownership/sharing
 * checks, bulk actions, and automated expiration enforcement.
 */
export declare class InstanceManager {
    private db;
    readonly virt: VirtualizationManager;
    readonly tasks: InstanceTaskManager;
    constructor(db: UnifiedDatabase, virt: VirtualizationManager);
    isStaff(principal: AuthenticatedPrincipal): boolean;
    listAccessibleInstances(principal: AuthenticatedPrincipal, filter?: {
        engine?: VirtualizationEngine;
        nodeId?: number;
        status?: string;
        search?: string;
    }): Promise<UnifiedInstanceRecord[]>;
    getAuthorizedInstance(principal: AuthenticatedPrincipal, engine: VirtualizationEngine, refId: number, requireOwnerOrStaff?: boolean): Promise<UnifiedInstanceRecord>;
    resizeKvmDisk(principal: AuthenticatedPrincipal, refId: number, requestedSize: string): Promise<{
        diskSize: string;
        virtualSizeBytes: number;
        guestFilesystemResizeRequired: true;
    }>;
    getKvmVncSettings(principal: AuthenticatedPrincipal, refId: number): Promise<{
        enabled: boolean;
        port: number | null;
    }>;
    setKvmVncEnabled(principal: AuthenticatedPrincipal, refId: number, enabled: boolean): Promise<{
        enabled: boolean;
        port: number | null;
    }>;
    setInstanceServiceLock(principal: AuthenticatedPrincipal, engine: VirtualizationEngine, refId: number, locked: boolean, reason?: string): Promise<UnifiedInstanceRecord>;
    cloneKvmInstance(principal: AuthenticatedPrincipal, refId: number, newName: string): Promise<{
        vmId: number;
        name: string;
        diskSizeBytes: number;
        sshForwardPort: number;
        guestIdentityResetRequired: true;
    }>;
    cloneLxcInstance(principal: AuthenticatedPrincipal, refId: number, newName: string): Promise<{
        instance: UnifiedInstanceRecord;
        sourceName: string;
        networkDetached: true;
        guestIdentityResetRequired: true;
    }>;
    listKvmDevices(principal: AuthenticatedPrincipal, refId: number): Promise<{
        disks: Array<{
            id: string;
            sizeBytes: number;
            format: string;
            attached: boolean;
        }>;
        nics: Array<{
            id: string;
            macAddress: string;
            model: string;
            networkMode: string;
        }>;
    }>;
    attachKvmDisk(principal: AuthenticatedPrincipal, refId: number, size: string): Promise<{
        id: string;
        sizeBytes: number;
        format: 'qcow2';
    }>;
    reattachKvmDisk(principal: AuthenticatedPrincipal, refId: number, deviceId: string): Promise<{
        id: string;
        attached: true;
    }>;
    detachKvmDisk(principal: AuthenticatedPrincipal, refId: number, deviceId: string): Promise<{
        id: string;
        imagePreserved: true;
    }>;
    attachKvmNatNic(principal: AuthenticatedPrincipal, refId: number): Promise<{
        id: string;
        macAddress: string;
        model: 'virtio-net-pci';
        networkMode: 'user';
    }>;
    detachKvmNic(principal: AuthenticatedPrincipal, refId: number, deviceId: string): Promise<{
        id: string;
    }>;
    executeAction(principal: AuthenticatedPrincipal, engine: VirtualizationEngine, refId: number, action: LifecycleAction, reason?: string, force?: boolean): Promise<UnifiedInstanceRecord>;
    executeActionTracked(principal: AuthenticatedPrincipal, engine: VirtualizationEngine, refId: number, action: LifecycleAction, reason?: string, force?: boolean): Promise<UnifiedInstanceRecord>;
    private performLifecycleAction;
    /** Start an asynchronous, persisted lifecycle task while retaining the legacy synchronous action API. */
    startActionTask(principal: AuthenticatedPrincipal, engine: VirtualizationEngine, refId: number, action: LifecycleAction, reason?: string, force?: boolean): Promise<InstanceTask>;
    listInstanceTasks(principal: AuthenticatedPrincipal, engine: VirtualizationEngine, refId: number, limit?: number): Promise<InstanceTask[]>;
    getAuthorizedTask(principal: AuthenticatedPrincipal, taskId: string): Promise<InstanceTask>;
    bulkAction(principal: AuthenticatedPrincipal, targets: Array<{
        engine: VirtualizationEngine;
        refId: number;
    }>, action: 'start' | 'stop' | 'restart'): Promise<Array<{
        uid: string;
        ok: boolean;
        error?: string;
    }>>;
    getTelemetry(principal: AuthenticatedPrincipal, engine: VirtualizationEngine, refId: number): Promise<InstanceTelemetry>;
    /**
     * Internal telemetry collection without a request principal. Used by the
     * background traffic-accounting loop (monitoring service); never exposed
     * through customer-facing routes.
     */
    collectInstanceTelemetry(engine: VirtualizationEngine, refId: number): Promise<InstanceTelemetry>;
    /**
     * Background check that suspends expired LXC instances when `auto_suspend_enabled = 1`
     * and `whitelisted = 0`.
     */
    processExpiredInstances(): Promise<number>;
}
