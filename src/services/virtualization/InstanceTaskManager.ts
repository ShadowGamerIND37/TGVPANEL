import crypto from 'crypto';
import { UnifiedDatabase } from '../../db/database';
import { VirtualizationEngine } from './VirtualizationAdapter';

export type InstanceTaskStatus = 'queued' | 'running' | 'succeeded' | 'failed';

export interface InstanceTask {
  id: string;
  engine: VirtualizationEngine;
  instanceRefId: number;
  actorId: number | null;
  action: string;
  status: InstanceTaskStatus;
  progress: number | null;
  currentStep: string | null;
  result: unknown;
  error: string | null;
  createdAt: string;
  startedAt: string | null;
  updatedAt: string;
  completedAt: string | null;
}

interface InstanceTaskRow {
  id: string;
  engine: VirtualizationEngine;
  instance_ref_id: number;
  actor_id: number | null;
  action: string;
  status: InstanceTaskStatus;
  progress: number | null;
  current_step: string | null;
  result_json: string | null;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  updated_at: string;
  completed_at: string | null;
}

export class InstanceTaskConflictError extends Error {
  public readonly statusCode = 409;
  constructor() {
    super('Another operation is already queued or running for this VPS.');
    this.name = 'InstanceTaskConflictError';
  }
}

/**
 * Persistent task history and per-instance operation exclusion for VPS lifecycle work.
 * Work executes in this controller process; this is not a distributed job queue and does
 * not claim automatic recovery of an interrupted hypervisor operation.
 */
export class InstanceTaskManager {
  constructor(private readonly db: UnifiedDatabase) {}

  private mapRow(row: InstanceTaskRow): InstanceTask {
    let result: unknown = null;
    if (row.result_json) {
      try {
        result = JSON.parse(row.result_json);
      } catch {
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

  private async createQueuedTask(params: {
    engine: VirtualizationEngine;
    instanceRefId: number;
    actorId: number;
    action: string;
  }): Promise<string> {
    if (!['kvm', 'lxc'].includes(params.engine)) throw new Error('Unsupported instance engine.');
    if (!Number.isInteger(params.instanceRefId) || params.instanceRefId < 1) {
      throw new Error('Invalid VPS identifier.');
    }
    const action = String(params.action || '').trim().toLowerCase();
    if (!/^[a-z][a-z0-9_-]{0,47}$/.test(action)) throw new Error('Invalid task action.');
    const id = crypto.randomUUID();
    try {
      await this.db.run(
        `INSERT INTO instance_tasks (id, engine, instance_ref_id, actor_id, action, status, current_step)
         VALUES (?, ?, ?, ?, ?, 'queued', 'Queued')`,
        [id, params.engine, params.instanceRefId, params.actorId, action]
      );
    } catch (err: any) {
      if (/UNIQUE constraint failed: instance_tasks\.(engine|instance_ref_id)/i.test(String(err?.message || err))) {
        throw new InstanceTaskConflictError();
      }
      throw err;
    }
    return id;
  }

  public async start<T>(params: {
    engine: VirtualizationEngine;
    instanceRefId: number;
    actorId: number;
    action: string;
    worker: (reportProgress: (progress: number | null, step: string) => Promise<void>) => Promise<T>;
  }): Promise<InstanceTask> {
    const id = await this.createQueuedTask(params);
    // Defer the worker so callers receive the durable task identifier before work begins.
    setImmediate(() => {
      // Worker failures are recorded on the task row; do not leak instance details into logs.
      this.execute(id, params.worker).catch(() => undefined);
    });
    const row = await this.db.get<InstanceTaskRow>(`SELECT * FROM instance_tasks WHERE id = ?`, [id]);
    if (!row) throw new Error('Could not read the newly created VPS task.');
    return this.mapRow(row);
  }

  public async runSync<T>(params: {
    engine: VirtualizationEngine;
    instanceRefId: number;
    actorId: number;
    action: string;
    worker: (reportProgress: (progress: number | null, step: string) => Promise<void>) => Promise<T>;
  }): Promise<{ task: InstanceTask; result: T }> {
    const id = await this.createQueuedTask(params);
    const result = await this.execute(id, params.worker);
    const row = await this.db.get<InstanceTaskRow>(`SELECT * FROM instance_tasks WHERE id = ?`, [id]);
    if (!row) throw new Error('Could not read the completed VPS task.');
    return { task: this.mapRow(row), result };
  }

  private async execute<T>(
    id: string,
    worker: (reportProgress: (progress: number | null, step: string) => Promise<void>) => Promise<T>
  ): Promise<T> {
    const claimed = await this.db.run(
      `UPDATE instance_tasks SET status = 'running', current_step = 'Starting',
         started_at = datetime('now'), updated_at = datetime('now')
       WHERE id = ? AND status = 'queued'`,
      [id]
    );
    if (!claimed.changes) throw new Error('VPS task was not queued when execution began.');

    const heartbeat = setInterval(() => {
      this.db.run(
        `UPDATE instance_tasks SET updated_at = datetime('now') WHERE id = ? AND status = 'running'`,
        [id]
      ).catch(() => undefined);
    }, 15_000);
    heartbeat.unref?.();

    const reportProgress = async (progress: number | null, step: string): Promise<void> => {
      const bounded = progress === null
        ? null
        : Math.max(1, Math.min(99, Math.floor(Number(progress) || 1)));
      const cleanStep = String(step || '').trim().slice(0, 200) || 'Working';
      await this.db.run(
        `UPDATE instance_tasks
         SET progress = CASE WHEN ? IS NULL THEN progress ELSE MAX(COALESCE(progress, 0), ?) END,
             current_step = ?, updated_at = datetime('now')
         WHERE id = ? AND status = 'running'`,
        [bounded, bounded, cleanStep, id]
      );
    };

    try {
      const result = await worker(reportProgress);
      let resultJson: string | null = null;
      try {
        const encoded = JSON.stringify(result);
        resultJson = encoded && encoded.length <= 64 * 1024 ? encoded : null;
      } catch {
        resultJson = null;
      }
      await this.db.run(
        `UPDATE instance_tasks SET status = 'succeeded', progress = 100, current_step = 'Completed',
           result_json = ?, error_message = NULL, completed_at = datetime('now'), updated_at = datetime('now')
         WHERE id = ? AND status = 'running'`,
        [resultJson, id]
      );
      return result;
    } catch (err: any) {
      const error = String(err?.message || 'VPS operation failed.').slice(0, 2000);
      await this.db.run(
        `UPDATE instance_tasks SET status = 'failed', current_step = 'Failed', error_message = ?,
           completed_at = datetime('now'), updated_at = datetime('now')
         WHERE id = ? AND status IN ('queued', 'running')`,
        [error, id]
      );
      throw err;
    } finally {
      clearInterval(heartbeat);
    }
  }

  public async get(id: string): Promise<InstanceTask | undefined> {
    const row = await this.db.get<InstanceTaskRow>(`SELECT * FROM instance_tasks WHERE id = ?`, [id]);
    return row ? this.mapRow(row) : undefined;
  }

  public async list(engine: VirtualizationEngine, instanceRefId: number, limit = 50): Promise<InstanceTask[]> {
    const safeLimit = Math.max(1, Math.min(100, Math.floor(Number(limit) || 50)));
    const rows = await this.db.all<InstanceTaskRow>(
      `SELECT * FROM instance_tasks WHERE engine = ? AND instance_ref_id = ?
       ORDER BY created_at DESC, rowid DESC LIMIT ?`,
      [engine, instanceRefId, safeLimit]
    );
    return rows.map((row) => this.mapRow(row));
  }

  /** Mark all work left active by the previous controller process as interrupted; never replay blindly. */
  public async recoverInterruptedTasks(): Promise<number> {
    const result = await this.db.run(
      `UPDATE instance_tasks SET status = 'failed', current_step = 'Interrupted',
         error_message = 'Controller stopped before the task completed; verify VPS state before retrying.',
         completed_at = datetime('now'), updated_at = datetime('now')
       WHERE status IN ('queued', 'running')`
    );
    return result.changes;
  }

  /** Mark old abandoned work failed; never retry dangerous operations blindly. */
  public async failStaleTasks(staleMinutes = 5): Promise<number> {
    const minutes = Math.max(1, Math.min(60, Math.floor(staleMinutes)));
    const result = await this.db.run(
      `UPDATE instance_tasks SET status = 'failed', current_step = 'Interrupted',
         error_message = 'Controller stopped before the task completed; verify VPS state before retrying.',
         completed_at = datetime('now'), updated_at = datetime('now')
       WHERE status IN ('queued', 'running')
         AND datetime(updated_at) <= datetime('now', ?)`,
      [`-${minutes} minutes`]
    );
    return result.changes;
  }
}
