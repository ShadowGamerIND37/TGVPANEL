import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';
import { VirtualizationManager } from '../virtualization/VirtualizationManager';
export declare class BackupSnapshotManager {
    private db;
    private nodeManager;
    private virt;
    private scheduleTimer;
    private scheduleBootTimer;
    private isRunningSchedules;
    constructor(db: UnifiedDatabase, nodeManager: NodeManager, virt: VirtualizationManager);
    private nextRunAt;
    startScheduleLoop(intervalMs?: number): void;
    stopScheduleLoop(): void;
    listBackupSchedules(filter?: {
        engine?: 'kvm' | 'lxc';
        refId?: number;
    }): Promise<any[]>;
    upsertBackupSchedule(params: {
        engine: 'kvm' | 'lxc';
        refId: number;
        frequency: 'hourly' | 'daily' | 'weekly';
        retentionCount: number;
        actorId: number;
        ownerUserId: number;
    }): Promise<any>;
    deleteBackupSchedule(engine: 'kvm' | 'lxc', refId: number, actorId: number): Promise<void>;
    /** Execute due schedules once; each schedule is claimed transactionally to avoid duplicate runs. */
    runDueBackupSchedules(): Promise<{
        processed: number;
        succeeded: number;
        failed: number;
    }>;
    listSnapshots(engine: 'kvm' | 'lxc', refId: number): Promise<any[]>;
    createSnapshot(params: {
        engine: 'kvm' | 'lxc';
        refId: number;
        name?: string;
        description?: string;
        actorId?: number;
    }): Promise<{
        id: number;
        name: string;
    }>;
    restoreSnapshot(engine: 'kvm' | 'lxc', refId: number, snapshotId: number): Promise<void>;
    deleteSnapshot(engine: 'kvm' | 'lxc', refId: number, snapshotId: number): Promise<void>;
    listBackups(filter?: {
        engine?: 'kvm' | 'lxc';
        refId?: number;
    }): Promise<any[]>;
    createBackup(params: {
        engine: 'kvm' | 'lxc';
        refId: number;
        label?: string;
        actorId?: number;
    }): Promise<{
        backupId: number;
        filePath: string;
        sizeBytes: number;
        checksumSha256: string;
    }>;
    getBackupRecord(backupId: number): Promise<any | undefined>;
    verifyBackupIntegrity(backupId: number): Promise<{
        valid: boolean;
        expectedSha256: string | null;
        actualSha256: string | null;
    }>;
    restoreBackup(backupId: number, actorId?: number): Promise<{
        restored: boolean;
        status: string;
    }>;
    deleteBackup(backupId: number): Promise<void>;
}
