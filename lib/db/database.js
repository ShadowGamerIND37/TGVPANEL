"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UnifiedDatabase = void 0;
exports.registerUnifiedDatabase = registerUnifiedDatabase;
exports.getUnifiedDatabase = getUnifiedDatabase;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
class UnifiedDatabase {
    raw;
    dbPath;
    constructor(rawDb, dbPath) {
        this.raw = rawDb;
        this.dbPath = dbPath;
    }
    get(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.raw.get(sql, params, (err, row) => {
                if (err)
                    reject(err);
                else
                    resolve(row);
            });
        });
    }
    all(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.raw.all(sql, params, (err, rows) => {
                if (err)
                    reject(err);
                else
                    resolve((rows || []));
            });
        });
    }
    run(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.raw.run(sql, params, function (err) {
                if (err)
                    reject(err);
                else
                    resolve({ lastID: this.lastID || 0, changes: this.changes || 0 });
            });
        });
    }
    exec(sql) {
        return new Promise((resolve, reject) => {
            this.raw.exec(sql, (err) => {
                if (err)
                    reject(err);
                else
                    resolve();
            });
        });
    }
    /**
     * Executes multiple statements atomically inside a SQLite transaction.
     */
    async transaction(fn) {
        await this.run('BEGIN IMMEDIATE TRANSACTION');
        try {
            const result = await fn();
            await this.run('COMMIT');
            return result;
        }
        catch (err) {
            try {
                await this.run('ROLLBACK');
            }
            catch {
                // Ignore rollback secondary error
            }
            throw err;
        }
    }
    /**
     * Creates an automatic timestamped backup of data/hkvm.db before running migrations.
     */
    async createBackup(label = 'auto') {
        const dir = path_1.default.join(path_1.default.dirname(this.dbPath), 'backups');
        fs_1.default.mkdirSync(dir, { recursive: true });
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const safeLabel = label.replace(/[^a-zA-Z0-9_-]/g, '_');
        const backupPath = path_1.default.join(dir, `hkvm_${safeLabel}_${ts}.db`);
        // Checkpoint WAL first so the copy is self-contained, then use VACUUM INTO if supported
        try {
            await this.run('PRAGMA wal_checkpoint(PASSIVE)');
            const escaped = backupPath.replace(/'/g, "''");
            await this.run(`VACUUM INTO '${escaped}'`);
        }
        catch {
            fs_1.default.copyFileSync(this.dbPath, backupPath);
        }
        const stat = fs_1.default.statSync(backupPath);
        return { backupPath, sizeBytes: stat.size };
    }
    async logActivity(params) {
        try {
            const detailsStr = params.details === null || params.details === undefined
                ? null
                : typeof params.details === 'string'
                    ? params.details
                    : JSON.stringify(params.details);
            await this.run(`INSERT INTO activity_logs (user_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`, [
                params.userId ?? null,
                params.action,
                params.resourceType ?? null,
                params.resourceId !== undefined && params.resourceId !== null
                    ? String(params.resourceId)
                    : null,
                detailsStr,
                params.ipAddress ?? null,
                params.userAgent ?? null,
            ]);
        }
        catch {
            // Never crash caller if audit table is mid-initialization
        }
    }
    close() {
        return new Promise((resolve, reject) => {
            this.raw.close((err) => {
                if (err)
                    reject(err);
                else
                    resolve();
            });
        });
    }
}
exports.UnifiedDatabase = UnifiedDatabase;
let singletonDb = null;
function registerUnifiedDatabase(rawDb, dbPath) {
    singletonDb = new UnifiedDatabase(rawDb, dbPath);
    return singletonDb;
}
function getUnifiedDatabase() {
    if (!singletonDb) {
        throw new Error('UnifiedDatabase has not been initialized yet');
    }
    return singletonDb;
}
