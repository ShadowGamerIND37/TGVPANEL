import { UnifiedDatabase } from './database';
export interface HvmImportReport {
    backupPath: string;
    usersMappedExisting: number;
    usersCreated: number;
    nodesImported: number;
    vpsImported: number;
    portsImported: number;
    snapshotsImported: number;
    backupsImported: number;
    notificationsImported: number;
    apiKeysImported: number;
    warnings: string[];
}
/**
 * Verifies legacy Werkzeug hashes (pbkdf2:sha256 / scrypt) or bcrypt hashes
 * so imported HVM accounts can authenticate safely and upgrade to HKVM bcrypt.
 */
export declare function verifyPasswordWithLegacySupport(plaintext: string, storedHash: string): {
    valid: boolean;
    needsRehash: boolean;
};
export interface HvmImportDryRunReport {
    dryRun: true;
    sourceFile: string;
    sourceTables: string[];
    requiredTablesPresent: boolean;
    counts: {
        users: number;
        nodes: number;
        vps: number;
        portAllocations: number;
        portForwards: number;
        snapshots: number;
        backups: number;
        notifications: number;
        apiKeys: number;
    };
    passwordHashFormats: {
        bcrypt: number;
        pbkdf2: number;
        scrypt: number;
        unrecognized: number;
    };
    existingUserCollisions: number;
    warnings: string[];
    ready: boolean;
}
/**
 * Dry-run / preflight for HVM database import. Opens the source database
 * READ-ONLY and validates what an import would do WITHOUT creating a backup or
 * writing anything: required tables present, per-table row counts, password-hash
 * format coverage, and username/email collisions against the existing HKVM
 * database. Returns a preflight report so an operator can confirm the source is
 * safe to import before committing.
 */
export declare function dryRunHvmImport(hkvmDb: UnifiedDatabase, hvmDbFilePath: string): Promise<HvmImportDryRunReport>;
export declare function importHvmDatabase(hkvmDb: UnifiedDatabase, hvmDbFilePath: string): Promise<HvmImportReport>;
