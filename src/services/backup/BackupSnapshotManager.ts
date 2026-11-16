import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';
import { VirtualizationManager } from '../virtualization/VirtualizationManager';
import { SafeValidators } from '../../security/middleware';

export class BackupSnapshotManager {
  private db: UnifiedDatabase;
  private nodeManager: NodeManager;
  private virt: VirtualizationManager;
  private scheduleTimer: NodeJS.Timeout | null = null;
  private scheduleBootTimer: NodeJS.Timeout | null = null;
  private isRunningSchedules = false;
  private isRunningSnapshotSchedules = false;

  constructor(
    db: UnifiedDatabase,
    nodeManager: NodeManager,
    virt: VirtualizationManager
  ) {
    this.db = db;
    this.nodeManager = nodeManager;
    this.virt = virt;
  }

  private async runAllScheduledJobs(): Promise<void> {
    await this.runDueBackupSchedules();
    await this.runDueSnapshotSchedules();
  }

  private nextRunAt(frequency: string, from = new Date()): string {
    const next = new Date(from);
    if (frequency === 'hourly') next.setUTCHours(next.getUTCHours() + 1);
    else if (frequency === 'daily') next.setUTCDate(next.getUTCDate() + 1);
    else if (frequency === 'weekly') next.setUTCDate(next.getUTCDate() + 7);
    else throw new Error('Frequency must be hourly, daily, or weekly.');
    return next.toISOString().slice(0, 19).replace('T', ' ');
  }

  public startScheduleLoop(intervalMs = 60_000): void {
    if (this.scheduleTimer) return;
    this.scheduleBootTimer = setTimeout(() => {
      this.scheduleBootTimer = null;
      this.runAllScheduledJobs().catch((err) => {
        console.error('[Scheduled Jobs] Initial cycle failed:', err?.message || err);
      });
    }, 5000);
    this.scheduleBootTimer.unref?.();
    this.scheduleTimer = setInterval(() => {
      this.runAllScheduledJobs().catch((err) => {
        console.error('[Scheduled Jobs] Cycle failed:', err?.message || err);
      });
    }, intervalMs);
    this.scheduleTimer.unref?.();
  }

  public stopScheduleLoop(): void {
    if (this.scheduleTimer) clearInterval(this.scheduleTimer);
    if (this.scheduleBootTimer) clearTimeout(this.scheduleBootTimer);
    this.scheduleTimer = null;
    this.scheduleBootTimer = null;
  }

  public async listBackupSchedules(filter?: { engine?: 'kvm' | 'lxc'; refId?: number }) {
    if (filter?.engine && filter.refId !== undefined) {
      return this.db.all<any>(
        `SELECT s.*, COALESCE(v.vm_name, l.container_name) AS instance_name
         FROM backup_schedules s
         LEFT JOIN vms v ON s.instance_type = 'kvm' AND v.vm_id = s.instance_ref_id
         LEFT JOIN lxc_instances l ON s.instance_type = 'lxc' AND l.id = s.instance_ref_id
         WHERE s.instance_type = ? AND s.instance_ref_id = ?`,
        [filter.engine, filter.refId]
      );
    }
    return this.db.all<any>(
      `SELECT s.*, COALESCE(v.vm_name, l.container_name) AS instance_name
       FROM backup_schedules s
       LEFT JOIN vms v ON s.instance_type = 'kvm' AND v.vm_id = s.instance_ref_id
       LEFT JOIN lxc_instances l ON s.instance_type = 'lxc' AND l.id = s.instance_ref_id
       ORDER BY s.next_run ASC, s.id ASC`
    );
  }

  public async upsertBackupSchedule(params: {
    engine: 'kvm' | 'lxc';
    refId: number;
    frequency: 'hourly' | 'daily' | 'weekly';
    retentionCount: number;
    actorId: number;
    ownerUserId: number;
  }) {
    if (!['kvm', 'lxc'].includes(params.engine)) throw new Error('Unsupported backup schedule instance type.');
    if (!Number.isInteger(params.refId) || params.refId < 1) throw new Error('Invalid instance ID.');
    if (!['hourly', 'daily', 'weekly'].includes(params.frequency)) throw new Error('Frequency must be hourly, daily, or weekly.');
    if (!Number.isInteger(params.retentionCount) || params.retentionCount < 1 || params.retentionCount > 365) {
      throw new Error('Retention must be an integer between 1 and 365 scheduled backups.');
    }
    const nextRun = this.nextRunAt(params.frequency);
    await this.db.run(
      `INSERT INTO backup_schedules
         (instance_type, instance_ref_id, enabled, frequency, retention_count, next_run,
          created_by, owner_user_id, last_status, last_error, updated_at)
       VALUES (?, ?, 1, ?, ?, ?, ?, ?, 'scheduled', NULL, datetime('now'))
       ON CONFLICT(instance_type, instance_ref_id) DO UPDATE SET
         enabled = 1, frequency = excluded.frequency, retention_count = excluded.retention_count,
         next_run = excluded.next_run, created_by = excluded.created_by,
         owner_user_id = excluded.owner_user_id, last_status = 'scheduled', last_error = NULL,
         updated_at = datetime('now')`,
      [params.engine, params.refId, params.frequency, params.retentionCount, nextRun, params.actorId, params.ownerUserId]
    );
    const schedule = await this.db.get<any>(
      `SELECT * FROM backup_schedules WHERE instance_type = ? AND instance_ref_id = ?`,
      [params.engine, params.refId]
    );
    await this.db.logActivity({
      userId: params.actorId,
      action: 'backup_schedule_saved',
      resourceType: params.engine,
      resourceId: String(params.refId),
      details: { frequency: params.frequency, retentionCount: params.retentionCount, nextRun },
    });
    return schedule;
  }

  public async deleteBackupSchedule(engine: 'kvm' | 'lxc', refId: number, actorId: number): Promise<void> {
    await this.db.run(
      `DELETE FROM backup_schedules WHERE instance_type = ? AND instance_ref_id = ?`,
      [engine, refId]
    );
    await this.db.logActivity({
      userId: actorId,
      action: 'backup_schedule_deleted',
      resourceType: engine,
      resourceId: String(refId),
    });
  }

  /** Execute due schedules once; each schedule is claimed transactionally to avoid duplicate runs. */
  public async runDueBackupSchedules(): Promise<{ processed: number; succeeded: number; failed: number }> {
    if (this.isRunningSchedules) return { processed: 0, succeeded: 0, failed: 0 };
    this.isRunningSchedules = true;
    let processed = 0;
    let succeeded = 0;
    let failed = 0;
    try {
      const due = await this.db.all<any>(
        `SELECT * FROM backup_schedules
         WHERE enabled = 1 AND (
           next_run IS NULL OR datetime(next_run) <= datetime('now') OR
           (last_status = 'running' AND datetime(last_run) <= datetime('now', '-2 hours'))
         )
         ORDER BY COALESCE(next_run, created_at), id LIMIT 10`
      );
      for (const candidate of due) {
        let claimed = false;
        await this.db.transaction(async () => {
          const current = await this.db.get<any>(
            `SELECT * FROM backup_schedules
             WHERE id = ? AND enabled = 1 AND (
               next_run IS NULL OR datetime(next_run) <= datetime('now') OR
               (last_status = 'running' AND datetime(last_run) <= datetime('now', '-2 hours'))
             )`,
            [candidate.id]
          );
          if (!current) return;
          const frequency = ['hourly', 'daily', 'weekly'].includes(current.frequency) ? current.frequency : 'daily';
          const nextRun = this.nextRunAt(frequency);
          await this.db.run(
            `UPDATE backup_schedules
             SET frequency = ?, last_run = datetime('now'), next_run = ?, last_status = 'running', last_error = NULL,
                 updated_at = datetime('now') WHERE id = ?`,
            [frequency, nextRun, current.id]
          );
          Object.assign(candidate, current, { frequency, next_run: nextRun });
          claimed = true;
        });
        if (!claimed) continue;

        processed += 1;
        const instanceExists = candidate.instance_type === 'kvm'
          ? await this.db.get(`SELECT vm_id FROM vms WHERE vm_id = ?`, [candidate.instance_ref_id])
          : await this.db.get(`SELECT id FROM lxc_instances WHERE id = ?`, [candidate.instance_ref_id]);
        if (!instanceExists) {
          await this.db.run(
            `UPDATE backup_schedules SET enabled = 0, last_status = 'orphaned',
             last_error = 'Instance no longer exists; schedule disabled.', updated_at = datetime('now') WHERE id = ?`,
            [candidate.id]
          );
          failed += 1;
          continue;
        }

        try {
          const backup = await this.createBackup({
            engine: candidate.instance_type,
            refId: Number(candidate.instance_ref_id),
            label: `auto_s${candidate.id}_${Date.now()}`,
            actorId: candidate.owner_user_id || candidate.created_by || undefined,
          });
          const integrity = await this.verifyBackupIntegrity(Number(backup.backupId));
          if (
            !/^[a-f0-9]{64}$/i.test(String(integrity.expectedSha256 || '')) ||
            !integrity.actualSha256 ||
            !integrity.valid
          ) {
            await this.deleteBackup(Number(backup.backupId)).catch(async () => {
              await this.db.run(`UPDATE container_backups SET status = 'verification_failed' WHERE id = ?`, [backup.backupId]);
            });
            throw new Error('Scheduled backup is missing a valid SHA-256 checksum or failed integrity verification.');
          }

          await this.db.run(
            `UPDATE container_backups SET is_scheduled = 1, schedule_id = ?, created_by = COALESCE(created_by, ?) WHERE id = ?`,
            [candidate.id, candidate.owner_user_id || candidate.created_by || null, backup.backupId]
          );
          const requestedRetention = Number(candidate.retention_count);
          const retentionCount = Number.isInteger(requestedRetention) && requestedRetention >= 1 && requestedRetention <= 365
            ? requestedRetention
            : 7;
          const excess = await this.db.all<{ id: number }>(
            `SELECT id FROM container_backups
             WHERE schedule_id = ? AND is_scheduled = 1
             ORDER BY id DESC LIMIT -1 OFFSET ?`,
            [candidate.id, retentionCount]
          );
          for (const old of excess) await this.deleteBackup(old.id);

          await this.db.run(
            `UPDATE backup_schedules SET last_status = 'success', last_error = NULL,
             last_backup_id = ?, updated_at = datetime('now') WHERE id = ?`,
            [backup.backupId, candidate.id]
          );
          await this.db.logActivity({
            userId: candidate.created_by || candidate.owner_user_id || null,
            action: 'scheduled_backup_completed',
            resourceType: candidate.instance_type,
            resourceId: String(candidate.instance_ref_id),
            details: { scheduleId: candidate.id, backupId: backup.backupId, checksumSha256: backup.checksumSha256 },
          }).catch(() => undefined);
          if (candidate.owner_user_id) {
            await this.db.run(
              `INSERT INTO notifications (user_id, type, title, message)
               SELECT ?, 'success', 'Scheduled backup completed', ?
               WHERE EXISTS (SELECT 1 FROM users WHERE id = ?)`,
              [candidate.owner_user_id, `Verified backup #${backup.backupId} completed; retention keeps the latest ${retentionCount}.`, candidate.owner_user_id]
            ).catch(() => undefined);
          }
          succeeded += 1;
        } catch (err: any) {
          const message = String(err?.message || err || 'Backup failed').slice(0, 1000);
          await this.db.run(
            `UPDATE backup_schedules SET last_status = 'failed', last_error = ?, updated_at = datetime('now') WHERE id = ?`,
            [message, candidate.id]
          );
          await this.db.logActivity({
            userId: candidate.created_by || candidate.owner_user_id || null,
            action: 'scheduled_backup_failed',
            resourceType: candidate.instance_type,
            resourceId: String(candidate.instance_ref_id),
            details: { scheduleId: candidate.id, error: message },
          }).catch(() => undefined);
          if (candidate.owner_user_id) {
            await this.db.run(
              `INSERT INTO notifications (user_id, type, title, message)
               SELECT ?, 'error', 'Scheduled backup failed', ?
               WHERE EXISTS (SELECT 1 FROM users WHERE id = ?)`,
              [candidate.owner_user_id, `Scheduled backup failed: ${message}`, candidate.owner_user_id]
            ).catch(() => undefined);
          }
          failed += 1;
        }
      }
      return { processed, succeeded, failed };
    } finally {
      this.isRunningSchedules = false;
    }
  }

  public async listSnapshotSchedules(filter?: { engine?: 'kvm' | 'lxc'; refId?: number }) {
    if (filter?.engine && filter.refId !== undefined) {
      return this.db.all<any>(
        `SELECT s.*, COALESCE(v.vm_name, l.container_name) AS instance_name
         FROM snapshot_schedules s
         LEFT JOIN vms v ON s.instance_type = 'kvm' AND v.vm_id = s.instance_ref_id
         LEFT JOIN lxc_instances l ON s.instance_type = 'lxc' AND l.id = s.instance_ref_id
         WHERE s.instance_type = ? AND s.instance_ref_id = ?`,
        [filter.engine, filter.refId]
      );
    }
    return this.db.all<any>(
      `SELECT s.*, COALESCE(v.vm_name, l.container_name) AS instance_name
       FROM snapshot_schedules s
       LEFT JOIN vms v ON s.instance_type = 'kvm' AND v.vm_id = s.instance_ref_id
       LEFT JOIN lxc_instances l ON s.instance_type = 'lxc' AND l.id = s.instance_ref_id
       ORDER BY s.next_run ASC, s.id ASC`
    );
  }

  public async upsertSnapshotSchedule(params: {
    engine: 'kvm' | 'lxc';
    refId: number;
    frequency: 'hourly' | 'daily' | 'weekly';
    retentionCount: number;
    actorId: number;
    ownerUserId: number;
  }) {
    if (!['kvm', 'lxc'].includes(params.engine)) throw new Error('Unsupported snapshot schedule instance type.');
    if (!Number.isInteger(params.refId) || params.refId < 1) throw new Error('Invalid instance ID.');
    if (!['hourly', 'daily', 'weekly'].includes(params.frequency)) throw new Error('Frequency must be hourly, daily, or weekly.');
    if (!Number.isInteger(params.retentionCount) || params.retentionCount < 1 || params.retentionCount > 365) {
      throw new Error('Retention must be an integer between 1 and 365 scheduled snapshots.');
    }
    const nextRun = this.nextRunAt(params.frequency);
    await this.db.run(
      `INSERT INTO snapshot_schedules
         (instance_type, instance_ref_id, enabled, frequency, retention_count, next_run,
          created_by, owner_user_id, last_status, last_error, updated_at)
       VALUES (?, ?, 1, ?, ?, ?, ?, ?, 'scheduled', NULL, datetime('now'))
       ON CONFLICT(instance_type, instance_ref_id) DO UPDATE SET
         enabled = 1, frequency = excluded.frequency, retention_count = excluded.retention_count,
         next_run = excluded.next_run, created_by = excluded.created_by,
         owner_user_id = excluded.owner_user_id, last_status = 'scheduled', last_error = NULL,
         updated_at = datetime('now')`,
      [params.engine, params.refId, params.frequency, params.retentionCount, nextRun, params.actorId, params.ownerUserId]
    );
    const schedule = await this.db.get<any>(
      `SELECT * FROM snapshot_schedules WHERE instance_type = ? AND instance_ref_id = ?`,
      [params.engine, params.refId]
    );
    await this.db.logActivity({
      userId: params.actorId,
      action: 'snapshot_schedule_saved',
      resourceType: params.engine,
      resourceId: String(params.refId),
      details: { frequency: params.frequency, retentionCount: params.retentionCount, nextRun },
    });
    return schedule;
  }

  public async deleteSnapshotSchedule(engine: 'kvm' | 'lxc', refId: number, actorId: number): Promise<void> {
    await this.db.run(
      `DELETE FROM snapshot_schedules WHERE instance_type = ? AND instance_ref_id = ?`,
      [engine, refId]
    );
    await this.db.logActivity({
      userId: actorId,
      action: 'snapshot_schedule_deleted',
      resourceType: engine,
      resourceId: String(refId),
    });
  }

  public async runDueSnapshotSchedules(): Promise<{ processed: number; succeeded: number; failed: number }> {
    if (this.isRunningSnapshotSchedules) return { processed: 0, succeeded: 0, failed: 0 };
    this.isRunningSnapshotSchedules = true;
    let processed = 0;
    let succeeded = 0;
    let failed = 0;
    try {
      const due = await this.db.all<any>(
        `SELECT * FROM snapshot_schedules
         WHERE enabled = 1 AND (
           next_run IS NULL OR datetime(next_run) <= datetime('now') OR
           (last_status = 'running' AND datetime(last_run) <= datetime('now', '-2 hours'))
         )
         ORDER BY COALESCE(next_run, created_at), id LIMIT 10`
      );
      for (const candidate of due) {
        let claimed = false;
        await this.db.transaction(async () => {
          const current = await this.db.get<any>(
            `SELECT * FROM snapshot_schedules
             WHERE id = ? AND enabled = 1 AND (
               next_run IS NULL OR datetime(next_run) <= datetime('now') OR
               (last_status = 'running' AND datetime(last_run) <= datetime('now', '-2 hours'))
             )`,
            [candidate.id]
          );
          if (!current) return;
          const frequency = ['hourly', 'daily', 'weekly'].includes(current.frequency) ? current.frequency : 'daily';
          const nextRun = this.nextRunAt(frequency);
          await this.db.run(
            `UPDATE snapshot_schedules SET frequency = ?, last_run = datetime('now'), next_run = ?,
             last_status = 'running', last_error = NULL, updated_at = datetime('now') WHERE id = ?`,
            [frequency, nextRun, current.id]
          );
          Object.assign(candidate, current, { frequency, next_run: nextRun });
          claimed = true;
        });
        if (!claimed) continue;
        processed += 1;
        const exists = candidate.instance_type === 'kvm'
          ? await this.db.get(`SELECT vm_id FROM vms WHERE vm_id = ?`, [candidate.instance_ref_id])
          : await this.db.get(`SELECT id FROM lxc_instances WHERE id = ?`, [candidate.instance_ref_id]);
        if (!exists) {
          await this.db.run(
            `UPDATE snapshot_schedules SET enabled = 0, last_status = 'orphaned',
             last_error = 'Instance no longer exists; schedule disabled.', updated_at = datetime('now') WHERE id = ?`,
            [candidate.id]
          );
          failed += 1;
          continue;
        }

        try {
          if (candidate.instance_type === 'kvm') {
            const vm = await this.db.get<{ status: string }>(`SELECT status FROM vms WHERE vm_id = ?`, [candidate.instance_ref_id]);
            const dbStatus = String(vm?.status || '').trim().toLowerCase();
            if (dbStatus !== 'stopped') {
              throw new Error('Scheduled KVM snapshots require the VM to be stopped; this run was skipped.');
            }
            // Also inspect the recorded QEMU PID to avoid snapshotting a process that was
            // started outside the panel while the database still says "stopped".
            const liveStatus = await this.virt.kvm.getTelemetry(Number(candidate.instance_ref_id));
            if (String(liveStatus.status || '').trim().toLowerCase() !== 'stopped') {
              throw new Error('Scheduled KVM snapshots require the VM to be stopped; this run was skipped.');
            }
          }
          const snapshot = await this.createSnapshot({
            engine: candidate.instance_type,
            refId: Number(candidate.instance_ref_id),
            name: `auto_s${candidate.id}_${Date.now()}`,
            description: `Scheduled ${candidate.frequency} snapshot`,
            actorId: candidate.owner_user_id || candidate.created_by || undefined,
            scheduled: true,
          });
          const table = candidate.instance_type === 'kvm' ? 'vm_snapshots' : 'container_snapshots';
          const idColumn = candidate.instance_type === 'kvm' ? 'snapshot_id' : 'id';
          await this.db.run(
            `UPDATE ${table} SET is_scheduled = 1, schedule_id = ? WHERE ${idColumn} = ?`,
            [candidate.id, snapshot.id]
          );
          const requestedRetention = Number(candidate.retention_count);
          const retentionCount = Number.isInteger(requestedRetention) && requestedRetention >= 1 && requestedRetention <= 365
            ? requestedRetention
            : 7;
          const excess = await this.db.all<{ id: number }>(
            `SELECT ${idColumn} AS id FROM ${table}
             WHERE schedule_id = ? AND is_scheduled = 1
             ORDER BY ${idColumn} DESC LIMIT -1 OFFSET ?`,
            [candidate.id, retentionCount]
          );
          for (const old of excess) await this.deleteSnapshot(candidate.instance_type, Number(candidate.instance_ref_id), old.id);

          await this.db.run(
            `UPDATE snapshot_schedules SET last_status = 'success', last_error = NULL,
             last_snapshot_id = ?, updated_at = datetime('now') WHERE id = ?`,
            [snapshot.id, candidate.id]
          );
          await this.db.logActivity({
            userId: candidate.created_by || candidate.owner_user_id || null,
            action: 'scheduled_snapshot_completed',
            resourceType: candidate.instance_type,
            resourceId: String(candidate.instance_ref_id),
            details: { scheduleId: candidate.id, snapshotId: snapshot.id, snapshotName: snapshot.name },
          }).catch(() => undefined);
          if (candidate.owner_user_id) {
            await this.db.run(
              `INSERT INTO notifications (user_id, type, title, message)
               SELECT ?, 'success', 'Scheduled snapshot completed', ?
               WHERE EXISTS (SELECT 1 FROM users WHERE id = ?)`,
              [candidate.owner_user_id, `Snapshot #${snapshot.id} completed; retention keeps the latest ${retentionCount}.`, candidate.owner_user_id]
            ).catch(() => undefined);
          }
          succeeded += 1;
        } catch (err: any) {
          const message = String(err?.message || err || 'Snapshot failed').slice(0, 1000);
          await this.db.run(
            `UPDATE snapshot_schedules SET last_status = 'failed', last_error = ?, updated_at = datetime('now') WHERE id = ?`,
            [message, candidate.id]
          );
          await this.db.logActivity({
            userId: candidate.created_by || candidate.owner_user_id || null,
            action: 'scheduled_snapshot_failed',
            resourceType: candidate.instance_type,
            resourceId: String(candidate.instance_ref_id),
            details: { scheduleId: candidate.id, error: message },
          }).catch(() => undefined);
          if (candidate.owner_user_id) {
            await this.db.run(
              `INSERT INTO notifications (user_id, type, title, message)
               SELECT ?, 'error', 'Scheduled snapshot failed', ?
               WHERE EXISTS (SELECT 1 FROM users WHERE id = ?)`,
              [candidate.owner_user_id, `Scheduled snapshot failed: ${message}`, candidate.owner_user_id]
            ).catch(() => undefined);
          }
          failed += 1;
        }
      }
      return { processed, succeeded, failed };
    } finally {
      this.isRunningSnapshotSchedules = false;
    }
  }

  // --- Unified Snapshots (KVM QCOW2 + LXC) ---
  public async listSnapshots(engine: 'kvm' | 'lxc', refId: number) {
    if (engine === 'kvm') {
      return this.db.all<any>(
        `SELECT snapshot_id AS id, vm_id AS ref_id, 'kvm' AS engine, snapshot_name, description, created_at
         FROM vm_snapshots WHERE vm_id = ? ORDER BY snapshot_id DESC`,
        [refId]
      );
    }
    return this.db.all<any>(
      `SELECT id, lxc_id AS ref_id, 'lxc' AS engine, snapshot_name, description, size_bytes, snapshot_type, status, created_at
       FROM container_snapshots WHERE lxc_id = ? ORDER BY id DESC`,
      [refId]
    );
  }

  public async createSnapshot(params: {
    engine: 'kvm' | 'lxc';
    refId: number;
    name?: string;
    description?: string;
    actorId?: number;
    scheduled?: boolean;
  }) {
    if (params.engine === 'kvm') {
      const snapName = params.name
        ? SafeValidators.snapshotName(params.name)
        : `snap_${Date.now()}`;
      return this.virt.kvm.createQcow2Snapshot(
        params.refId,
        snapName,
        params.description || ''
      );
    }

    const row = await this.virt.lxc.getRawLxcRow(params.refId);
    if (!row) throw new Error(`LXC container #${params.refId} not found.`);

    const countRow = await this.db.get<{ cnt: number }>(
      `SELECT COUNT(*) AS cnt FROM container_snapshots WHERE lxc_id = ?`,
      [params.refId]
    );
    const limit = Number(row.snapshot_limit || 5);
    if (!params.scheduled && (countRow?.cnt || 0) >= limit) {
      throw new Error(`Snapshot limit reached (${countRow?.cnt}/${limit}). Delete an older snapshot first.`);
    }

    let snapInfo: { name: string };
    if (row.is_local) {
      snapInfo = await this.nodeManager.localRuntime.snapshotManager.createSnapshot(
        row.container_name,
        params.description || ''
      );
    } else {
      const resp = await this.nodeManager.requestRemoteNode<{ snapshot: { name: string } }>(
        row.node_id,
        'POST',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}/snapshots`,
        { comment: params.description || '' }
      );
      snapInfo = resp.snapshot;
    }

    const ins = await this.db.run(
      `INSERT INTO container_snapshots
         (lxc_id, snapshot_name, description, snapshot_type, status, created_by)
       VALUES (?, ?, ?, 'manual', 'completed', ?)`,
      [params.refId, snapInfo.name, params.description || null, params.actorId || null]
    );

    return { id: ins.lastID, name: snapInfo.name };
  }

  public async restoreSnapshot(
    engine: 'kvm' | 'lxc',
    refId: number,
    snapshotId: number
  ): Promise<void> {
    if (engine === 'kvm') {
      await this.virt.kvm.restoreQcow2Snapshot(refId, snapshotId);
      return;
    }

    const row = await this.virt.lxc.getRawLxcRow(refId);
    const snap = await this.db.get<any>(
      `SELECT * FROM container_snapshots WHERE id = ? AND lxc_id = ?`,
      [snapshotId, refId]
    );
    if (!row || !snap) throw new Error('Container or snapshot not found.');

    if (row.is_local) {
      await this.nodeManager.localRuntime.snapshotManager.restoreSnapshot(
        row.container_name,
        snap.snapshot_name
      );
    } else {
      await this.nodeManager.requestRemoteNode(
        row.node_id,
        'POST',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}/snapshots/${encodeURIComponent(snap.snapshot_name)}/restore`
      );
    }
  }

  public async deleteSnapshot(
    engine: 'kvm' | 'lxc',
    refId: number,
    snapshotId: number
  ): Promise<void> {
    if (engine === 'kvm') {
      await this.virt.kvm.deleteQcow2Snapshot(refId, snapshotId);
      return;
    }

    const row = await this.virt.lxc.getRawLxcRow(refId);
    const snap = await this.db.get<any>(
      `SELECT * FROM container_snapshots WHERE id = ? AND lxc_id = ?`,
      [snapshotId, refId]
    );
    if (!row || !snap) throw new Error('Container or snapshot not found.');

    if (row.is_local) {
      await this.nodeManager.localRuntime.snapshotManager
        .deleteSnapshot(row.container_name, snap.snapshot_name)
        .catch(() => undefined);
    } else {
      await this.nodeManager
        .requestRemoteNode(
          row.node_id,
          'DELETE',
          `/api/v1/containers/${encodeURIComponent(row.container_name)}/snapshots/${encodeURIComponent(snap.snapshot_name)}`
        )
        .catch(() => undefined);
    }
    await this.db.run(`DELETE FROM container_snapshots WHERE id = ?`, [snapshotId]);
  }

  // --- Unified Archive Backups with SHA-256 Integrity ---
  public async listBackups(filter?: { engine?: 'kvm' | 'lxc'; refId?: number }) {
    if (filter?.engine && filter?.refId !== undefined) {
      return this.db.all<any>(
        `SELECT b.*, n.name AS node_name
         FROM container_backups b
         LEFT JOIN nodes n ON n.id = b.node_id
         WHERE b.instance_type = ? AND b.instance_ref_id = ?
         ORDER BY b.id DESC`,
        [filter.engine, filter.refId]
      );
    }
    return this.db.all<any>(
      `SELECT b.*, n.name AS node_name
       FROM container_backups b
       LEFT JOIN nodes n ON n.id = b.node_id
       ORDER BY b.id DESC`
    );
  }

  public async createBackup(params: {
    engine: 'kvm' | 'lxc';
    refId: number;
    label?: string;
    actorId?: number;
  }) {
    if (params.engine === 'kvm') {
      return this.virt.kvm.createDiskBackup(params.refId);
    }

    const row = await this.virt.lxc.getRawLxcRow(params.refId);
    if (!row) throw new Error(`LXC container #${params.refId} not found.`);

    let artifact: {
      backupName: string;
      filePath: string;
      sizeBytes: number;
      checksumSha256: string;
    };

    if (row.is_local) {
      artifact = await this.nodeManager.localRuntime.snapshotManager.createTarBackup(
        row.container_name,
        params.label
      );
    } else {
      const resp = await this.nodeManager.requestRemoteNode<{ backup: typeof artifact }>(
        row.node_id,
        'POST',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}/backups`,
        { label: params.label },
        900_000
      );
      artifact = resp.backup;
    }

    const ins = await this.db.run(
      `INSERT INTO container_backups
         (instance_type, instance_ref_id, node_id, backup_name, file_path, size_bytes, checksum_sha256, status, created_by)
       VALUES ('lxc', ?, ?, ?, ?, ?, ?, 'completed', ?)`,
      [
        params.refId,
        row.node_id,
        artifact.backupName,
        artifact.filePath,
        artifact.sizeBytes,
        artifact.checksumSha256,
        params.actorId || null,
      ]
    );

    return {
      backupId: ins.lastID,
      ...artifact,
    };
  }

  public async getBackupRecord(backupId: number): Promise<any | undefined> {
    return this.db.get<any>(
      `SELECT b.*, n.is_local
       FROM container_backups b
       LEFT JOIN nodes n ON n.id = b.node_id
       WHERE b.id = ?`,
      [backupId]
    );
  }

  public async verifyBackupIntegrity(backupId: number): Promise<{
    valid: boolean;
    expectedSha256: string | null;
    actualSha256: string | null;
  }> {
    const bkp = await this.getBackupRecord(backupId);
    if (!bkp) throw new Error('Backup record not found.');

    if (bkp.node_id && bkp.is_local === 0) {
      return this.nodeManager.requestRemoteNode<{
        valid: boolean;
        expectedSha256: string | null;
        actualSha256: string | null;
      }>(bkp.node_id, 'POST', '/api/v1/backups/verify', {
        filePath: bkp.file_path,
        expectedSha256: bkp.checksum_sha256,
      });
    }

    if (!fs.existsSync(bkp.file_path)) {
      return { valid: false, expectedSha256: bkp.checksum_sha256, actualSha256: null };
    }
    const actual = await this.nodeManager.localRuntime.snapshotManager.computeFileSha256(
      bkp.file_path
    );
    const valid = !bkp.checksum_sha256 || bkp.checksum_sha256.toLowerCase() === actual.toLowerCase();
    return { valid, expectedSha256: bkp.checksum_sha256, actualSha256: actual };
  }

  public async restoreBackup(
    backupId: number,
    actorId?: number
  ): Promise<{ restored: boolean; status: string }> {
    const bkp = await this.getBackupRecord(backupId);
    if (!bkp) throw new Error('Backup record not found.');

    if (bkp.instance_type !== 'lxc') {
      throw new Error('Archive live restore is currently supported for LXC container backups (use QCOW2 Snapshots for KVM instant revert).');
    }

    const row = await this.virt.lxc.getRawLxcRow(Number(bkp.instance_ref_id));
    if (!row) throw new Error(`LXC container #${bkp.instance_ref_id} not found.`);

    const backupOnDifferentNode =
      Boolean(bkp.node_id) && Number(bkp.node_id) !== Number(row.node_id);

    let crossNodeBase64: string | null = null;
    if (backupOnDifferentNode) {
      if (Number(bkp.is_local || 0) === 1 || Number(bkp.node_id) === 1) {
        if (!fs.existsSync(bkp.file_path)) {
          throw new Error('Backup archive file no longer exists on source node.');
        }
        crossNodeBase64 = fs.readFileSync(bkp.file_path).toString('base64');
      } else {
        const dl = await this.nodeManager.requestRemoteNode<{
          archiveBase64: string;
          checksumSha256: string;
        }>(
          Number(bkp.node_id),
          'POST',
          '/api/v1/backups/download',
          {
            filePath: bkp.file_path,
            expectedSha256: bkp.checksum_sha256 || undefined,
          },
          600_000
        );
        crossNodeBase64 = dl.archiveBase64;
      }
    }

    let postState = 'stopped';
    if (row.is_local) {
      let localTargetFile = String(bkp.file_path);
      let tempLocalFile: string | null = null;
      if (crossNodeBase64) {
        tempLocalFile = this.nodeManager.localRuntime.snapshotManager.resolveConfinedBackupPath(
          path.join(
            this.nodeManager.localRuntime.snapshotManager.getBackupDir(),
            `crossnode_restore_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.tar.gz`
          )
        );
        fs.mkdirSync(path.dirname(tempLocalFile), { recursive: true });
        fs.writeFileSync(tempLocalFile, Buffer.from(crossNodeBase64, 'base64'), { mode: 0o600 });
        localTargetFile = tempLocalFile;
      }
      try {
        const before = await this.nodeManager.localRuntime.containerManager.inspectContainer(
          row.container_name
        );
        const wasRunning = before.state === 'running' || before.state === 'frozen';
        if (wasRunning) {
          await this.nodeManager.localRuntime.containerManager.stopContainer(
            row.container_name,
            false
          );
        }
        await this.nodeManager.localRuntime.snapshotManager.restoreTarBackup(
          localTargetFile,
          bkp.checksum_sha256 || undefined,
          row.container_name
        );
        if (wasRunning) {
          await this.nodeManager.localRuntime.containerManager.startContainer(row.container_name);
        }
        const after = await this.nodeManager.localRuntime.containerManager.inspectContainer(
          row.container_name
        );
        postState = after.state === 'running' ? 'running' : 'stopped';
      } finally {
        if (tempLocalFile && fs.existsSync(tempLocalFile)) {
          try {
            fs.unlinkSync(tempLocalFile);
          } catch {
            // ignore
          }
        }
      }
    } else {
      const resp = await this.nodeManager.requestRemoteNode<{
        success: boolean;
        container?: { state?: string };
      }>(
        row.node_id,
        'POST',
        `/api/v1/containers/${encodeURIComponent(row.container_name)}/backups/restore`,
        crossNodeBase64
          ? {
              archiveBase64: crossNodeBase64,
              expectedSha256: bkp.checksum_sha256 || undefined,
            }
          : {
              filePath: bkp.file_path,
              expectedSha256: bkp.checksum_sha256 || undefined,
            },
        900_000
      );
      postState = resp.container?.state === 'running' ? 'running' : 'stopped';
    }

    await this.db.run(
      `UPDATE lxc_instances SET status = ?, updated_at = datetime('now') WHERE id = ?`,
      [postState, row.id]
    );
    await this.virt.lxc.syncRegistryRow(row.id);
    await this.db.logActivity({
      userId: actorId,
      action: 'lxc_backup_restored',
      resourceType: 'lxc',
      resourceId: String(row.id),
      details: {
        backupId,
        backupName: bkp.backup_name,
        checksumSha256: bkp.checksum_sha256,
      },
    });

    return { restored: true, status: postState };
  }

  public async deleteBackup(backupId: number): Promise<void> {
    const bkp = await this.getBackupRecord(backupId);
    if (!bkp) throw new Error('Backup record not found.');
    if (bkp.node_id && bkp.is_local === 0) {
      await this.nodeManager.requestRemoteNode(bkp.node_id, 'DELETE', '/api/v1/backups/file', {
        filePath: bkp.file_path,
      });
    } else if (bkp.file_path && fs.existsSync(bkp.file_path)) {
      fs.unlinkSync(bkp.file_path);
    }
    await this.db.run(`DELETE FROM container_backups WHERE id = ?`, [backupId]);
  }
}
