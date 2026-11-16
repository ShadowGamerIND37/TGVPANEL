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
    private isRunningSnapshotSchedules;
    constructor(db: UnifiedDatabase, nodeManager: NodeManager, virt: VirtualizationManager);
    private runAllScheduledJobs;
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
    listSnapshotSchedules(filter?: {
        engine?: 'kvm' | 'lxc';
        refId?: number;
    }): Promise<any[]>;
    upsertSnapshotSchedule(params: {
        engine: 'kvm' | 'lxc';
        refId: number;
        frequency: 'hourly' | 'daily' | 'weekly';
        retentionCount: number;
        actorId: number;
        ownerUserId: number;
    }): Promise<any>;
    deleteSnapshotSchedule(engine: 'kvm' | 'lxc', refId: number, actorId: number): Promise<void>;
    runDueSnapshotSchedules(): Promise<{
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
        scheduled?: boolean;
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
    /**
     * Restore rehearsal (dry-run): confirms a backup is restorable WITHOUT performing
     * the restore. For local archives this verifies the checksum (decrypting encrypted
     * archives first), then structurally inspects the tar.gz (entry count + top-level
     * container dir) so an operator can see whether a restore would succeed before
     * touching the live container. For remote archives it delegates to the node agent's
     * rehearsal endpoint. Returns a structured, human-readable verdict.
     */
    rehearseRestore(backupId: number): Promise<{
        restorable: boolean;
        backupId: number;
        instanceType: string;
        instanceRefId: number;
        encrypted: boolean;
        checksumValid: boolean;
        archiveValid: boolean;
        entryCount: number | null;
        topLevelDir: string | null;
        sizeBytes: number | null;
        reasons: string[];
    }>;
    /**
     * Copies a backup archive to a destination node (backup replication/offload),
     * addressing the "remote destinations" gap. The stored archive is copied as-is
     * (encrypted archives stay encrypted) and the copy is integrity-verified against
     * the source checksum before being recorded in `backup_copies`. For a remote
     * target the archive is streamed to the node agent's receive endpoint; for a
     * local target it is written to the confined backup directory and verified here.
     */
    copyBackupToNode(backupId: number, targetNodeId: number, actorId?: number): Promise<{
        copyId: number;
        backupId: number;
        targetNodeId: number;
        filePath: string;
        checksumSha256: string;
        sizeBytes: number;
        encrypted: boolean;
        status: string;
    }>;
    /** Computes the SHA-256 of a stored archive, decrypting encrypted archives first. */
    private computeStoredChecksum;
    listBackupCopies(backupId: number): Promise<any[]>;
    restoreBackup(backupId: number, actorId?: number): Promise<{
        restored: boolean;
        status: string;
    }>;
    deleteBackup(backupId: number): Promise<void>;
}
