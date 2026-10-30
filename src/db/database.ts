import fs from 'fs';
import path from 'path';
import sqlite3 from 'sqlite3';

export interface RunResult {
  lastID: number;
  changes: number;
}

export class UnifiedDatabase {
  public readonly raw: sqlite3.Database;
  public readonly dbPath: string;

  constructor(rawDb: sqlite3.Database, dbPath: string) {
    this.raw = rawDb;
    this.dbPath = dbPath;
  }

  public get<T = any>(sql: string, params: any[] = []): Promise<T | undefined> {
    return new Promise((resolve, reject) => {
      this.raw.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row as T | undefined);
      });
    });
  }

  public all<T = any>(sql: string, params: any[] = []): Promise<T[]> {
    return new Promise((resolve, reject) => {
      this.raw.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve((rows || []) as T[]);
      });
    });
  }

  public run(sql: string, params: any[] = []): Promise<RunResult> {
    return new Promise((resolve, reject) => {
      this.raw.run(sql, params, function (this: sqlite3.RunResult, err: Error | null) {
        if (err) reject(err);
        else resolve({ lastID: this.lastID || 0, changes: this.changes || 0 });
      });
    });
  }

  public exec(sql: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.raw.exec(sql, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  /**
   * Executes multiple statements atomically inside a SQLite transaction.
   */
  public async transaction<T>(fn: () => Promise<T>): Promise<T> {
    await this.run('BEGIN IMMEDIATE TRANSACTION');
    try {
      const result = await fn();
      await this.run('COMMIT');
      return result;
    } catch (err) {
      try {
        await this.run('ROLLBACK');
      } catch {
        // Ignore rollback secondary error
      }
      throw err;
    }
  }

  /**
   * Creates an automatic timestamped backup of data/hkvm.db before running migrations.
   */
  public async createBackup(label = 'auto'): Promise<{ backupPath: string; sizeBytes: number }> {
    const dir = path.join(path.dirname(this.dbPath), 'backups');
    fs.mkdirSync(dir, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const safeLabel = label.replace(/[^a-zA-Z0-9_-]/g, '_');
    const backupPath = path.join(dir, `hkvm_${safeLabel}_${ts}.db`);

    // Checkpoint WAL first so the copy is self-contained, then use VACUUM INTO if supported
    try {
      await this.run('PRAGMA wal_checkpoint(PASSIVE)');
      const escaped = backupPath.replace(/'/g, "''");
      await this.run(`VACUUM INTO '${escaped}'`);
    } catch {
      fs.copyFileSync(this.dbPath, backupPath);
    }

    const stat = fs.statSync(backupPath);
    return { backupPath, sizeBytes: stat.size };
  }

  public async logActivity(params: {
    userId?: number | null;
    action: string;
    resourceType?: string | null;
    resourceId?: string | number | null;
    details?: Record<string, any> | string | null;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<void> {
    try {
      const detailsStr =
        params.details === null || params.details === undefined
          ? null
          : typeof params.details === 'string'
          ? params.details
          : JSON.stringify(params.details);
      await this.run(
        `INSERT INTO activity_logs (user_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [
          params.userId ?? null,
          params.action,
          params.resourceType ?? null,
          params.resourceId !== undefined && params.resourceId !== null
            ? String(params.resourceId)
            : null,
          detailsStr,
          params.ipAddress ?? null,
          params.userAgent ?? null,
        ]
      );
    } catch {
      // Never crash caller if audit table is mid-initialization
    }
  }

  public close(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.raw.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}

let singletonDb: UnifiedDatabase | null = null;

export function registerUnifiedDatabase(rawDb: sqlite3.Database, dbPath: string): UnifiedDatabase {
  singletonDb = new UnifiedDatabase(rawDb, dbPath);
  return singletonDb;
}

export function getUnifiedDatabase(): UnifiedDatabase {
  if (!singletonDb) {
    throw new Error('UnifiedDatabase has not been initialized yet');
  }
  return singletonDb;
}
