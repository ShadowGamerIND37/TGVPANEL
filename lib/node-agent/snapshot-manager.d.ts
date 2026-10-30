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
    listSnapshots(containerName: string): Promise<SnapshotInfo[]>;
    createSnapshot(containerName: string, comment?: string): Promise<SnapshotInfo>;
    restoreSnapshot(containerName: string, snapshotName: string): Promise<void>;
    deleteSnapshot(containerName: string, snapshotName: string): Promise<void>;
    createTarBackup(containerName: string, backupLabel?: string): Promise<BackupArtifact>;
    restoreTarBackup(archivePath: string, expectedChecksumSha256?: string): Promise<void>;
    computeFileSha256(filePath: string): Promise<string>;
}
