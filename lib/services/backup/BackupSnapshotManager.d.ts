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
        backupName: string;
        filePath: string;
        sizeBytes: number;
        checksumSha256: string;
        encrypted: boolean;
        encryptionAlg: string;
    } | {
        backupName: string;
        filePath: string;
        sizeBytes: number;
        checksumSha256: string;
        backupId: number;
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
     * rehearsal endpoint. KVM disk archives are validated for integrity/structure but
     * are reported as not restorable because live archive restore is an LXC-only path
     * (KVM instances revert via QCOW2 snapshots). Returns a structured verdict.
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
    /**
     * Restores an LXC container from a backup archive. By default the primary
     * archive (`container_backups.file_path`) is used; passing `options.copyId`
     * restores from a specific recorded copy (`backup_copies`) instead — useful
     * when the primary archive is unavailable but a verified copy exists on
     * another node. Encrypted archives (primary or copy) are decrypted and
     * checksum-verified at the panel before the restore, and the copy's own
     * `encrypted`/`checksum_sha256` metadata is honored.
     */
    restoreBackup(backupId: number, actorId?: number, options?: {
        copyId?: number;
    }): Promise<{
        restored: boolean;
        status: string;
        sourceCopyId: number | null;
    }>;
    /** True when the given node id refers to the panel's local host. */
    private isNodeLocal;
    /**
     * Reads a local archive as base64, decrypting encrypted archives to a confined
     * temp file first and verifying the recovered content against the expected
     * (decrypted-content) checksum.
     */
    private readPlaintextArchive;
    /**
     * Decrypts base64-encoded encrypted archive bytes to a confined temp file and
     * verifies the recovered content against the expected checksum.
     */
    private decryptBase64Archive;
    private verifyDecryptedChecksum;
    deleteBackup(backupId: number): Promise<void>;
}
