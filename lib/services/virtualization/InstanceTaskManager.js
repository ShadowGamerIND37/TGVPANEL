"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.InstanceTaskManager = exports.InstanceTaskConflictError = void 0;
const crypto_1 = __importDefault(require("crypto"));
class InstanceTaskConflictError extends Error {
    statusCode = 409;
    constructor() {
        super('Another operation is already queued or running for this VPS.');
        this.name = 'InstanceTaskConflictError';
    }
}
exports.InstanceTaskConflictError = InstanceTaskConflictError;
/**
 * Persistent task history and per-instance operation exclusion for VPS lifecycle work.
 * Work executes in this controller process; this is not a distributed job queue and does
 * not claim automatic recovery of an interrupted hypervisor operation.
 */
class InstanceTaskManager {
    db;
    constructor(db) {
        this.db = db;
    }
    mapRow(row) {
        let result = null;
        if (row.result_json) {
            try {
                result = JSON.parse(row.result_json);
            }
            catch {
                result = null;
            }
        }
        return {
            id: row.id,
            engine: row.engine,
            instanceRefId: Number(row.instance_ref_id),
            actorId: row.actor_id === null ? null : Number(row.actor_id),
            action: row.action,
            status: row.status,
            progress: row.progress === null || row.progress === undefined ? null : Number(row.progress),
            currentStep: row.current_step,
            result,
            error: row.error_message,
            createdAt: row.created_at,
            startedAt: row.started_at,
            updatedAt: row.updated_at,
            completedAt: row.completed_at,
        };
    }
    async createQueuedTask(params) {
        if (!['kvm', 'lxc'].includes(params.engine))
            throw new Error('Unsupported instance engine.');
        if (!Number.isInteger(params.instanceRefId) || params.instanceRefId < 1) {
            throw new Error('Invalid VPS identifier.');
        }
        const action = String(params.action || '').trim().toLowerCase();
        if (!/^[a-z][a-z0-9_-]{0,47}$/.test(action))
            throw new Error('Invalid task action.');
        const id = crypto_1.default.randomUUID();
        try {
            await this.db.run(`INSERT INTO instance_tasks (id, engine, instance_ref_id, actor_id, action, status, current_step)
         VALUES (?, ?, ?, ?, ?, 'queued', 'Queued')`, [id, params.engine, params.instanceRefId, params.actorId, action]);
        }
        catch (err) {
            if (/UNIQUE constraint failed: instance_tasks\.(engine|instance_ref_id)/i.test(String(err?.message || err))) {
                throw new InstanceTaskConflictError();
            }
            throw err;
        }
        return id;
    }
    async start(params) {
        const id = await this.createQueuedTask(params);
        // Defer the worker so callers receive the durable task identifier before work begins.
        setImmediate(() => {
            // Worker failures are recorded on the task row; do not leak instance details into logs.
            this.execute(id, params.worker).catch(() => undefined);
        });
        const row = await this.db.get(`SELECT * FROM instance_tasks WHERE id = ?`, [id]);
        if (!row)
            throw new Error('Could not read the newly created VPS task.');
        return this.mapRow(row);
    }
    async runSync(params) {
        const id = await this.createQueuedTask(params);
        const result = await this.execute(id, params.worker);
        const row = await this.db.get(`SELECT * FROM instance_tasks WHERE id = ?`, [id]);
        if (!row)
            throw new Error('Could not read the completed VPS task.');
        return { task: this.mapRow(row), result };
    }
    async execute(id, worker) {
        const claimed = await this.db.run(`UPDATE instance_tasks SET status = 'running', current_step = 'Starting',
         started_at = datetime('now'), updated_at = datetime('now')
       WHERE id = ? AND status = 'queued'`, [id]);
        if (!claimed.changes)
            throw new Error('VPS task was not queued when execution began.');
        const heartbeat = setInterval(() => {
            this.db.run(`UPDATE instance_tasks SET updated_at = datetime('now') WHERE id = ? AND status = 'running'`, [id]).catch(() => undefined);
        }, 15_000);
        heartbeat.unref?.();
        const reportProgress = async (progress, step) => {
            const bounded = progress === null
                ? null
                : Math.max(1, Math.min(99, Math.floor(Number(progress) || 1)));
            const cleanStep = String(step || '').trim().slice(0, 200) || 'Working';
            await this.db.run(`UPDATE instance_tasks
         SET progress = CASE WHEN ? IS NULL THEN progress ELSE MAX(COALESCE(progress, 0), ?) END,
             current_step = ?, updated_at = datetime('now')
         WHERE id = ? AND status = 'running'`, [bounded, bounded, cleanStep, id]);
        };
        try {
            const result = await worker(reportProgress);
            let resultJson = null;
            try {
                const encoded = JSON.stringify(result);
                resultJson = encoded && encoded.length <= 64 * 1024 ? encoded : null;
            }
            catch {
                resultJson = null;
            }
            await this.db.run(`UPDATE instance_tasks SET status = 'succeeded', progress = 100, current_step = 'Completed',
           result_json = ?, error_message = NULL, completed_at = datetime('now'), updated_at = datetime('now')
         WHERE id = ? AND status = 'running'`, [resultJson, id]);
            return result;
        }
        catch (err) {
            const error = String(err?.message || 'VPS operation failed.').slice(0, 2000);
            await this.db.run(`UPDATE instance_tasks SET status = 'failed', current_step = 'Failed', error_message = ?,
           completed_at = datetime('now'), updated_at = datetime('now')
         WHERE id = ? AND status IN ('queued', 'running')`, [error, id]);
            throw err;
        }
        finally {
            clearInterval(heartbeat);
        }
    }
    async get(id) {
        const row = await this.db.get(`SELECT * FROM instance_tasks WHERE id = ?`, [id]);
        return row ? this.mapRow(row) : undefined;
    }
    async list(engine, instanceRefId, limit = 50) {
        const safeLimit = Math.max(1, Math.min(100, Math.floor(Number(limit) || 50)));
        const rows = await this.db.all(`SELECT * FROM instance_tasks WHERE engine = ? AND instance_ref_id = ?
       ORDER BY created_at DESC, rowid DESC LIMIT ?`, [engine, instanceRefId, safeLimit]);
        return rows.map((row) => this.mapRow(row));
    }
    /** Mark all work left active by the previous controller process as interrupted; never replay blindly. */
    async recoverInterruptedTasks() {
        const result = await this.db.run(`UPDATE instance_tasks SET status = 'failed', current_step = 'Interrupted',
         error_message = 'Controller stopped before the task completed; verify VPS state before retrying.',
         completed_at = datetime('now'), updated_at = datetime('now')
       WHERE status IN ('queued', 'running')`);
        return result.changes;
    }
    /** Mark old abandoned work failed; never retry dangerous operations blindly. */
    async failStaleTasks(staleMinutes = 5) {
        const minutes = Math.max(1, Math.min(60, Math.floor(staleMinutes)));
        const result = await this.db.run(`UPDATE instance_tasks SET status = 'failed', current_step = 'Interrupted',
         error_message = 'Controller stopped before the task completed; verify VPS state before retrying.',
         completed_at = datetime('now'), updated_at = datetime('now')
       WHERE status IN ('queued', 'running')
         AND datetime(updated_at) <= datetime('now', ?)`, [`-${minutes} minutes`]);
        return result.changes;
    }
}
exports.InstanceTaskManager = InstanceTaskManager;
