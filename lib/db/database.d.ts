import sqlite3 from 'sqlite3';
export interface RunResult {
    lastID: number;
    changes: number;
}
export declare class UnifiedDatabase {
    readonly raw: sqlite3.Database;
    readonly dbPath: string;
    constructor(rawDb: sqlite3.Database, dbPath: string);
    get<T = any>(sql: string, params?: any[]): Promise<T | undefined>;
    all<T = any>(sql: string, params?: any[]): Promise<T[]>;
    run(sql: string, params?: any[]): Promise<RunResult>;
    exec(sql: string): Promise<void>;
    /**
     * Executes multiple statements atomically inside a SQLite transaction.
     */
    transaction<T>(fn: () => Promise<T>): Promise<T>;
    /**
     * Creates an automatic timestamped backup of data/hkvm.db before running migrations.
     */
    createBackup(label?: string): Promise<{
        backupPath: string;
        sizeBytes: number;
    }>;
    logActivity(params: {
        userId?: number | null;
        action: string;
        resourceType?: string | null;
        resourceId?: string | number | null;
        details?: Record<string, any> | string | null;
        ipAddress?: string | null;
        userAgent?: string | null;
    }): Promise<void>;
    close(): Promise<void>;
}
export declare function registerUnifiedDatabase(rawDb: sqlite3.Database, dbPath: string): UnifiedDatabase;
export declare function getUnifiedDatabase(): UnifiedDatabase;
