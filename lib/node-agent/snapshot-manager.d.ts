export interface SnapshotInfo {
    name: string;
    comment: string;
    timestamp: string;
    sizeBytes: number;
}
export interface BackupArtifact {
    backupName: string;
    filePath: string;
    sizeBytes: number;
    checksumSha256: string;
    createdAt: string;
}
export declare class LxcSnapshotAndBackupManager {
    private backupDir;
    private lxcBaseDir;
    constructor(backupDir?: string, lxcBaseDir?: string);
    getBackupDir(): string;
    resolveConfinedBackupPath(filePath: string): string;
    private needsRootForStore;
    private lxcPathArgs;
    listSnapshots(containerName: string): Promise<SnapshotInfo[]>;
    createSnapshot(containerName: string, comment?: string): Promise<SnapshotInfo>;
    restoreSnapshot(containerName: string, snapshotName: string): Promise<void>;
    deleteSnapshot(containerName: string, snapshotName: string): Promise<void>;
    createTarBackup(containerName: string, backupLabel?: string): Promise<BackupArtifact>;
    restoreTarBackup(archivePath: string, expectedChecksumSha256?: string, cleanContainerName?: string): Promise<void>;
    computeFileSha256(filePath: string): Promise<string>;
    /**
     * Structurally inspects a tar.gz archive WITHOUT extracting it, for restore
     * rehearsal. Lists entries via the allowlisted `tar -tzf` and reports the entry
     * count, the top-level directory (the container name captured at backup time),
     * and whether the archive is a valid, readable gzip tar. Does not modify the
     * archive. Throws if the archive is missing or not a valid tar.gz.
     */
    inspectTarArchive(archivePath: string): Promise<{
        valid: boolean;
        entryCount: number;
        topLevelDir: string | null;
        sizeBytes: number;
    }>;
}
