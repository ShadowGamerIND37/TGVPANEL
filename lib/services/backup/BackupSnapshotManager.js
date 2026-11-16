"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BackupSnapshotManager = void 0;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const middleware_1 = require("../../security/middleware");
const backup_crypto_1 = require("./backup-crypto");
class BackupSnapshotManager {
    db;
    nodeManager;
    virt;
    scheduleTimer = null;
    scheduleBootTimer = null;
    isRunningSchedules = false;
    isRunningSnapshotSchedules = false;
    constructor(db, nodeManager, virt) {
        this.db = db;
        this.nodeManager = nodeManager;
        this.virt = virt;
    }
    async runAllScheduledJobs() {
        await this.runDueBackupSchedules();
        await this.runDueSnapshotSchedules();
    }
    nextRunAt(frequency, from = new Date()) {
        const next = new Date(from);
        if (frequency === 'hourly')
            next.setUTCHours(next.getUTCHours() + 1);
        else if (frequency === 'daily')
            next.setUTCDate(next.getUTCDate() + 1);
        else if (frequency === 'weekly')
            next.setUTCDate(next.getUTCDate() + 7);
        else
            throw new Error('Frequency must be hourly, daily, or weekly.');
        return next.toISOString().slice(0, 19).replace('T', ' ');
    }
    startScheduleLoop(intervalMs = 60_000) {
        if (this.scheduleTimer)
            return;
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
    stopScheduleLoop() {
        if (this.scheduleTimer)
            clearInterval(this.scheduleTimer);
        if (this.scheduleBootTimer)
            clearTimeout(this.scheduleBootTimer);
        this.scheduleTimer = null;
        this.scheduleBootTimer = null;
    }
    async listBackupSchedules(filter) {
        if (filter?.engine && filter.refId !== undefined) {
            return this.db.all(`SELECT s.*, COALESCE(v.vm_name, l.container_name) AS instance_name
         FROM backup_schedules s
         LEFT JOIN vms v ON s.instance_type = 'kvm' AND v.vm_id = s.instance_ref_id
         LEFT JOIN lxc_instances l ON s.instance_type = 'lxc' AND l.id = s.instance_ref_id
         WHERE s.instance_type = ? AND s.instance_ref_id = ?`, [filter.engine, filter.refId]);
        }
        return this.db.all(`SELECT s.*, COALESCE(v.vm_name, l.container_name) AS instance_name
       FROM backup_schedules s
       LEFT JOIN vms v ON s.instance_type = 'kvm' AND v.vm_id = s.instance_ref_id
       LEFT JOIN lxc_instances l ON s.instance_type = 'lxc' AND l.id = s.instance_ref_id
       ORDER BY s.next_run ASC, s.id ASC`);
    }
    async upsertBackupSchedule(params) {
        if (!['kvm', 'lxc'].includes(params.engine))
            throw new Error('Unsupported backup schedule instance type.');
        if (!Number.isInteger(params.refId) || params.refId < 1)
            throw new Error('Invalid instance ID.');
        if (!['hourly', 'daily', 'weekly'].includes(params.frequency))
            throw new Error('Frequency must be hourly, daily, or weekly.');
        if (!Number.isInteger(params.retentionCount) || params.retentionCount < 1 || params.retentionCount > 365) {
            throw new Error('Retention must be an integer between 1 and 365 scheduled backups.');
        }
        const nextRun = this.nextRunAt(params.frequency);
        await this.db.run(`INSERT INTO backup_schedules
         (instance_type, instance_ref_id, enabled, frequency, retention_count, next_run,
          created_by, owner_user_id, last_status, last_error, updated_at)
       VALUES (?, ?, 1, ?, ?, ?, ?, ?, 'scheduled', NULL, datetime('now'))
       ON CONFLICT(instance_type, instance_ref_id) DO UPDATE SET
         enabled = 1, frequency = excluded.frequency, retention_count = excluded.retention_count,
         next_run = excluded.next_run, created_by = excluded.created_by,
         owner_user_id = excluded.owner_user_id, last_status = 'scheduled', last_error = NULL,
         updated_at = datetime('now')`, [params.engine, params.refId, params.frequency, params.retentionCount, nextRun, params.actorId, params.ownerUserId]);
        const schedule = await this.db.get(`SELECT * FROM backup_schedules WHERE instance_type = ? AND instance_ref_id = ?`, [params.engine, params.refId]);
        await this.db.logActivity({
            userId: params.actorId,
            action: 'backup_schedule_saved',
            resourceType: params.engine,
            resourceId: String(params.refId),
            details: { frequency: params.frequency, retentionCount: params.retentionCount, nextRun },
        });
        return schedule;
    }
    async deleteBackupSchedule(engine, refId, actorId) {
        await this.db.run(`DELETE FROM backup_schedules WHERE instance_type = ? AND instance_ref_id = ?`, [engine, refId]);
        await this.db.logActivity({
            userId: actorId,
            action: 'backup_schedule_deleted',
            resourceType: engine,
            resourceId: String(refId),
        });
    }
    /** Execute due schedules once; each schedule is claimed transactionally to avoid duplicate runs. */
    async runDueBackupSchedules() {
        if (this.isRunningSchedules)
            return { processed: 0, succeeded: 0, failed: 0 };
        this.isRunningSchedules = true;
        let processed = 0;
        let succeeded = 0;
        let failed = 0;
        try {
            const due = await this.db.all(`SELECT * FROM backup_schedules
         WHERE enabled = 1 AND (
           next_run IS NULL OR datetime(next_run) <= datetime('now') OR
           (last_status = 'running' AND datetime(last_run) <= datetime('now', '-2 hours'))
         )
         ORDER BY COALESCE(next_run, created_at), id LIMIT 10`);
            for (const candidate of due) {
                let claimed = false;
                await this.db.transaction(async () => {
                    const current = await this.db.get(`SELECT * FROM backup_schedules
             WHERE id = ? AND enabled = 1 AND (
               next_run IS NULL OR datetime(next_run) <= datetime('now') OR
               (last_status = 'running' AND datetime(last_run) <= datetime('now', '-2 hours'))
             )`, [candidate.id]);
                    if (!current)
                        return;
                    const frequency = ['hourly', 'daily', 'weekly'].includes(current.frequency) ? current.frequency : 'daily';
                    const nextRun = this.nextRunAt(frequency);
                    await this.db.run(`UPDATE backup_schedules
             SET frequency = ?, last_run = datetime('now'), next_run = ?, last_status = 'running', last_error = NULL,
                 updated_at = datetime('now') WHERE id = ?`, [frequency, nextRun, current.id]);
                    Object.assign(candidate, current, { frequency, next_run: nextRun });
                    claimed = true;
                });
                if (!claimed)
                    continue;
                processed += 1;
                const instanceExists = candidate.instance_type === 'kvm'
                    ? await this.db.get(`SELECT vm_id FROM vms WHERE vm_id = ?`, [candidate.instance_ref_id])
                    : await this.db.get(`SELECT id FROM lxc_instances WHERE id = ?`, [candidate.instance_ref_id]);
                if (!instanceExists) {
                    await this.db.run(`UPDATE backup_schedules SET enabled = 0, last_status = 'orphaned',
             last_error = 'Instance no longer exists; schedule disabled.', updated_at = datetime('now') WHERE id = ?`, [candidate.id]);
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
                    if (!/^[a-f0-9]{64}$/i.test(String(integrity.expectedSha256 || '')) ||
                        !integrity.actualSha256 ||
                        !integrity.valid) {
                        await this.deleteBackup(Number(backup.backupId)).catch(async () => {
                            await this.db.run(`UPDATE container_backups SET status = 'verification_failed' WHERE id = ?`, [backup.backupId]);
                        });
                        throw new Error('Scheduled backup is missing a valid SHA-256 checksum or failed integrity verification.');
                    }
                    await this.db.run(`UPDATE container_backups SET is_scheduled = 1, schedule_id = ?, created_by = COALESCE(created_by, ?) WHERE id = ?`, [candidate.id, candidate.owner_user_id || candidate.created_by || null, backup.backupId]);
                    const requestedRetention = Number(candidate.retention_count);
                    const retentionCount = Number.isInteger(requestedRetention) && requestedRetention >= 1 && requestedRetention <= 365
                        ? requestedRetention
                        : 7;
                    const excess = await this.db.all(`SELECT id FROM container_backups
             WHERE schedule_id = ? AND is_scheduled = 1
             ORDER BY id DESC LIMIT -1 OFFSET ?`, [candidate.id, retentionCount]);
                    for (const old of excess)
                        await this.deleteBackup(old.id);
                    await this.db.run(`UPDATE backup_schedules SET last_status = 'success', last_error = NULL,
             last_backup_id = ?, updated_at = datetime('now') WHERE id = ?`, [backup.backupId, candidate.id]);
                    await this.db.logActivity({
                        userId: candidate.created_by || candidate.owner_user_id || null,
                        action: 'scheduled_backup_completed',
                        resourceType: candidate.instance_type,
                        resourceId: String(candidate.instance_ref_id),
                        details: { scheduleId: candidate.id, backupId: backup.backupId, checksumSha256: backup.checksumSha256 },
                    }).catch(() => undefined);
                    if (candidate.owner_user_id) {
                        await this.db.run(`INSERT INTO notifications (user_id, type, title, message)
               SELECT ?, 'success', 'Scheduled backup completed', ?
               WHERE EXISTS (SELECT 1 FROM users WHERE id = ?)`, [candidate.owner_user_id, `Verified backup #${backup.backupId} completed; retention keeps the latest ${retentionCount}.`, candidate.owner_user_id]).catch(() => undefined);
                    }
                    succeeded += 1;
                }
                catch (err) {
                    const message = String(err?.message || err || 'Backup failed').slice(0, 1000);
                    await this.db.run(`UPDATE backup_schedules SET last_status = 'failed', last_error = ?, updated_at = datetime('now') WHERE id = ?`, [message, candidate.id]);
                    await this.db.logActivity({
                        userId: candidate.created_by || candidate.owner_user_id || null,
                        action: 'scheduled_backup_failed',
                        resourceType: candidate.instance_type,
                        resourceId: String(candidate.instance_ref_id),
                        details: { scheduleId: candidate.id, error: message },
                    }).catch(() => undefined);
                    if (candidate.owner_user_id) {
                        await this.db.run(`INSERT INTO notifications (user_id, type, title, message)
               SELECT ?, 'error', 'Scheduled backup failed', ?
               WHERE EXISTS (SELECT 1 FROM users WHERE id = ?)`, [candidate.owner_user_id, `Scheduled backup failed: ${message}`, candidate.owner_user_id]).catch(() => undefined);
                    }
                    failed += 1;
                }
            }
            return { processed, succeeded, failed };
        }
        finally {
            this.isRunningSchedules = false;
        }
    }
    async listSnapshotSchedules(filter) {
        if (filter?.engine && filter.refId !== undefined) {
            return this.db.all(`SELECT s.*, COALESCE(v.vm_name, l.container_name) AS instance_name
         FROM snapshot_schedules s
         LEFT JOIN vms v ON s.instance_type = 'kvm' AND v.vm_id = s.instance_ref_id
         LEFT JOIN lxc_instances l ON s.instance_type = 'lxc' AND l.id = s.instance_ref_id
         WHERE s.instance_type = ? AND s.instance_ref_id = ?`, [filter.engine, filter.refId]);
        }
        return this.db.all(`SELECT s.*, COALESCE(v.vm_name, l.container_name) AS instance_name
       FROM snapshot_schedules s
       LEFT JOIN vms v ON s.instance_type = 'kvm' AND v.vm_id = s.instance_ref_id
       LEFT JOIN lxc_instances l ON s.instance_type = 'lxc' AND l.id = s.instance_ref_id
       ORDER BY s.next_run ASC, s.id ASC`);
    }
    async upsertSnapshotSchedule(params) {
        if (!['kvm', 'lxc'].includes(params.engine))
            throw new Error('Unsupported snapshot schedule instance type.');
        if (!Number.isInteger(params.refId) || params.refId < 1)
            throw new Error('Invalid instance ID.');
        if (!['hourly', 'daily', 'weekly'].includes(params.frequency))
            throw new Error('Frequency must be hourly, daily, or weekly.');
        if (!Number.isInteger(params.retentionCount) || params.retentionCount < 1 || params.retentionCount > 365) {
            throw new Error('Retention must be an integer between 1 and 365 scheduled snapshots.');
        }
        const nextRun = this.nextRunAt(params.frequency);
        await this.db.run(`INSERT INTO snapshot_schedules
         (instance_type, instance_ref_id, enabled, frequency, retention_count, next_run,
          created_by, owner_user_id, last_status, last_error, updated_at)
       VALUES (?, ?, 1, ?, ?, ?, ?, ?, 'scheduled', NULL, datetime('now'))
       ON CONFLICT(instance_type, instance_ref_id) DO UPDATE SET
         enabled = 1, frequency = excluded.frequency, retention_count = excluded.retention_count,
         next_run = excluded.next_run, created_by = excluded.created_by,
         owner_user_id = excluded.owner_user_id, last_status = 'scheduled', last_error = NULL,
         updated_at = datetime('now')`, [params.engine, params.refId, params.frequency, params.retentionCount, nextRun, params.actorId, params.ownerUserId]);
        const schedule = await this.db.get(`SELECT * FROM snapshot_schedules WHERE instance_type = ? AND instance_ref_id = ?`, [params.engine, params.refId]);
        await this.db.logActivity({
            userId: params.actorId,
            action: 'snapshot_schedule_saved',
            resourceType: params.engine,
            resourceId: String(params.refId),
            details: { frequency: params.frequency, retentionCount: params.retentionCount, nextRun },
        });
        return schedule;
    }
    async deleteSnapshotSchedule(engine, refId, actorId) {
        await this.db.run(`DELETE FROM snapshot_schedules WHERE instance_type = ? AND instance_ref_id = ?`, [engine, refId]);
        await this.db.logActivity({
            userId: actorId,
            action: 'snapshot_schedule_deleted',
            resourceType: engine,
            resourceId: String(refId),
        });
    }
    async runDueSnapshotSchedules() {
        if (this.isRunningSnapshotSchedules)
            return { processed: 0, succeeded: 0, failed: 0 };
        this.isRunningSnapshotSchedules = true;
        let processed = 0;
        let succeeded = 0;
        let failed = 0;
        try {
            const due = await this.db.all(`SELECT * FROM snapshot_schedules
         WHERE enabled = 1 AND (
           next_run IS NULL OR datetime(next_run) <= datetime('now') OR
           (last_status = 'running' AND datetime(last_run) <= datetime('now', '-2 hours'))
         )
         ORDER BY COALESCE(next_run, created_at), id LIMIT 10`);
            for (const candidate of due) {
                let claimed = false;
                await this.db.transaction(async () => {
                    const current = await this.db.get(`SELECT * FROM snapshot_schedules
             WHERE id = ? AND enabled = 1 AND (
               next_run IS NULL OR datetime(next_run) <= datetime('now') OR
               (last_status = 'running' AND datetime(last_run) <= datetime('now', '-2 hours'))
             )`, [candidate.id]);
                    if (!current)
                        return;
                    const frequency = ['hourly', 'daily', 'weekly'].includes(current.frequency) ? current.frequency : 'daily';
                    const nextRun = this.nextRunAt(frequency);
                    await this.db.run(`UPDATE snapshot_schedules SET frequency = ?, last_run = datetime('now'), next_run = ?,
             last_status = 'running', last_error = NULL, updated_at = datetime('now') WHERE id = ?`, [frequency, nextRun, current.id]);
                    Object.assign(candidate, current, { frequency, next_run: nextRun });
                    claimed = true;
                });
                if (!claimed)
                    continue;
                processed += 1;
                const exists = candidate.instance_type === 'kvm'
                    ? await this.db.get(`SELECT vm_id FROM vms WHERE vm_id = ?`, [candidate.instance_ref_id])
                    : await this.db.get(`SELECT id FROM lxc_instances WHERE id = ?`, [candidate.instance_ref_id]);
                if (!exists) {
                    await this.db.run(`UPDATE snapshot_schedules SET enabled = 0, last_status = 'orphaned',
             last_error = 'Instance no longer exists; schedule disabled.', updated_at = datetime('now') WHERE id = ?`, [candidate.id]);
                    failed += 1;
                    continue;
                }
                try {
                    if (candidate.instance_type === 'kvm') {
                        const vm = await this.db.get(`SELECT status FROM vms WHERE vm_id = ?`, [candidate.instance_ref_id]);
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
                    await this.db.run(`UPDATE ${table} SET is_scheduled = 1, schedule_id = ? WHERE ${idColumn} = ?`, [candidate.id, snapshot.id]);
                    const requestedRetention = Number(candidate.retention_count);
                    const retentionCount = Number.isInteger(requestedRetention) && requestedRetention >= 1 && requestedRetention <= 365
                        ? requestedRetention
                        : 7;
                    const excess = await this.db.all(`SELECT ${idColumn} AS id FROM ${table}
             WHERE schedule_id = ? AND is_scheduled = 1
             ORDER BY ${idColumn} DESC LIMIT -1 OFFSET ?`, [candidate.id, retentionCount]);
                    for (const old of excess)
                        await this.deleteSnapshot(candidate.instance_type, Number(candidate.instance_ref_id), old.id);
                    await this.db.run(`UPDATE snapshot_schedules SET last_status = 'success', last_error = NULL,
             last_snapshot_id = ?, updated_at = datetime('now') WHERE id = ?`, [snapshot.id, candidate.id]);
                    await this.db.logActivity({
                        userId: candidate.created_by || candidate.owner_user_id || null,
                        action: 'scheduled_snapshot_completed',
                        resourceType: candidate.instance_type,
                        resourceId: String(candidate.instance_ref_id),
                        details: { scheduleId: candidate.id, snapshotId: snapshot.id, snapshotName: snapshot.name },
                    }).catch(() => undefined);
                    if (candidate.owner_user_id) {
                        await this.db.run(`INSERT INTO notifications (user_id, type, title, message)
               SELECT ?, 'success', 'Scheduled snapshot completed', ?
               WHERE EXISTS (SELECT 1 FROM users WHERE id = ?)`, [candidate.owner_user_id, `Snapshot #${snapshot.id} completed; retention keeps the latest ${retentionCount}.`, candidate.owner_user_id]).catch(() => undefined);
                    }
                    succeeded += 1;
                }
                catch (err) {
                    const message = String(err?.message || err || 'Snapshot failed').slice(0, 1000);
                    await this.db.run(`UPDATE snapshot_schedules SET last_status = 'failed', last_error = ?, updated_at = datetime('now') WHERE id = ?`, [message, candidate.id]);
                    await this.db.logActivity({
                        userId: candidate.created_by || candidate.owner_user_id || null,
                        action: 'scheduled_snapshot_failed',
                        resourceType: candidate.instance_type,
                        resourceId: String(candidate.instance_ref_id),
                        details: { scheduleId: candidate.id, error: message },
                    }).catch(() => undefined);
                    if (candidate.owner_user_id) {
                        await this.db.run(`INSERT INTO notifications (user_id, type, title, message)
               SELECT ?, 'error', 'Scheduled snapshot failed', ?
               WHERE EXISTS (SELECT 1 FROM users WHERE id = ?)`, [candidate.owner_user_id, `Scheduled snapshot failed: ${message}`, candidate.owner_user_id]).catch(() => undefined);
                    }
                    failed += 1;
                }
            }
            return { processed, succeeded, failed };
        }
        finally {
            this.isRunningSnapshotSchedules = false;
        }
    }
    // --- Unified Snapshots (KVM QCOW2 + LXC) ---
    async listSnapshots(engine, refId) {
        if (engine === 'kvm') {
            return this.db.all(`SELECT snapshot_id AS id, vm_id AS ref_id, 'kvm' AS engine, snapshot_name, description, created_at
         FROM vm_snapshots WHERE vm_id = ? ORDER BY snapshot_id DESC`, [refId]);
        }
        return this.db.all(`SELECT id, lxc_id AS ref_id, 'lxc' AS engine, snapshot_name, description, size_bytes, snapshot_type, status, created_at
       FROM container_snapshots WHERE lxc_id = ? ORDER BY id DESC`, [refId]);
    }
    async createSnapshot(params) {
        if (params.engine === 'kvm') {
            const snapName = params.name
                ? middleware_1.SafeValidators.snapshotName(params.name)
                : `snap_${Date.now()}`;
            return this.virt.kvm.createQcow2Snapshot(params.refId, snapName, params.description || '');
        }
        const row = await this.virt.lxc.getRawLxcRow(params.refId);
        if (!row)
            throw new Error(`LXC container #${params.refId} not found.`);
        const countRow = await this.db.get(`SELECT COUNT(*) AS cnt FROM container_snapshots WHERE lxc_id = ?`, [params.refId]);
        const limit = Number(row.snapshot_limit || 5);
        if (!params.scheduled && (countRow?.cnt || 0) >= limit) {
            throw new Error(`Snapshot limit reached (${countRow?.cnt}/${limit}). Delete an older snapshot first.`);
        }
        let snapInfo;
        if (row.is_local) {
            snapInfo = await this.nodeManager.localRuntime.snapshotManager.createSnapshot(row.container_name, params.description || '');
        }
        else {
            const resp = await this.nodeManager.requestRemoteNode(row.node_id, 'POST', `/api/v1/containers/${encodeURIComponent(row.container_name)}/snapshots`, { comment: params.description || '' });
            snapInfo = resp.snapshot;
        }
        const ins = await this.db.run(`INSERT INTO container_snapshots
         (lxc_id, snapshot_name, description, snapshot_type, status, created_by)
       VALUES (?, ?, ?, 'manual', 'completed', ?)`, [params.refId, snapInfo.name, params.description || null, params.actorId || null]);
        return { id: ins.lastID, name: snapInfo.name };
    }
    async restoreSnapshot(engine, refId, snapshotId) {
        if (engine === 'kvm') {
            await this.virt.kvm.restoreQcow2Snapshot(refId, snapshotId);
            return;
        }
        const row = await this.virt.lxc.getRawLxcRow(refId);
        const snap = await this.db.get(`SELECT * FROM container_snapshots WHERE id = ? AND lxc_id = ?`, [snapshotId, refId]);
        if (!row || !snap)
            throw new Error('Container or snapshot not found.');
        if (row.is_local) {
            await this.nodeManager.localRuntime.snapshotManager.restoreSnapshot(row.container_name, snap.snapshot_name);
        }
        else {
            await this.nodeManager.requestRemoteNode(row.node_id, 'POST', `/api/v1/containers/${encodeURIComponent(row.container_name)}/snapshots/${encodeURIComponent(snap.snapshot_name)}/restore`);
        }
    }
    async deleteSnapshot(engine, refId, snapshotId) {
        if (engine === 'kvm') {
            await this.virt.kvm.deleteQcow2Snapshot(refId, snapshotId);
            return;
        }
        const row = await this.virt.lxc.getRawLxcRow(refId);
        const snap = await this.db.get(`SELECT * FROM container_snapshots WHERE id = ? AND lxc_id = ?`, [snapshotId, refId]);
        if (!row || !snap)
            throw new Error('Container or snapshot not found.');
        if (row.is_local) {
            await this.nodeManager.localRuntime.snapshotManager
                .deleteSnapshot(row.container_name, snap.snapshot_name)
                .catch(() => undefined);
        }
        else {
            await this.nodeManager
                .requestRemoteNode(row.node_id, 'DELETE', `/api/v1/containers/${encodeURIComponent(row.container_name)}/snapshots/${encodeURIComponent(snap.snapshot_name)}`)
                .catch(() => undefined);
        }
        await this.db.run(`DELETE FROM container_snapshots WHERE id = ?`, [snapshotId]);
    }
    // --- Unified Archive Backups with SHA-256 Integrity ---
    async listBackups(filter) {
        if (filter?.engine && filter?.refId !== undefined) {
            return this.db.all(`SELECT b.*, n.name AS node_name
         FROM container_backups b
         LEFT JOIN nodes n ON n.id = b.node_id
         WHERE b.instance_type = ? AND b.instance_ref_id = ?
         ORDER BY b.id DESC`, [filter.engine, filter.refId]);
        }
        return this.db.all(`SELECT b.*, n.name AS node_name
       FROM container_backups b
       LEFT JOIN nodes n ON n.id = b.node_id
       ORDER BY b.id DESC`);
    }
    async createBackup(params) {
        if (params.engine === 'kvm') {
            return this.virt.kvm.createDiskBackup(params.refId);
        }
        const row = await this.virt.lxc.getRawLxcRow(params.refId);
        if (!row)
            throw new Error(`LXC container #${params.refId} not found.`);
        let artifact;
        let encrypted = 0;
        let encryptionAlg = null;
        if (row.is_local) {
            artifact = await this.nodeManager.localRuntime.snapshotManager.createTarBackup(row.container_name, params.label);
            // Encrypt the archive at rest. AES-GCM's tag also guards the stored file; the
            // recorded checksum remains the decrypted-content SHA-256 for restore verification.
            const enc = (0, backup_crypto_1.encryptArchive)(artifact.filePath);
            artifact.filePath = enc.encryptedPath;
            artifact.sizeBytes = enc.plaintextSizeBytes;
            encrypted = 1;
            encryptionAlg = 'aes-256-gcm';
        }
        else {
            const resp = await this.nodeManager.requestRemoteNode(row.node_id, 'POST', `/api/v1/containers/${encodeURIComponent(row.container_name)}/backups`, { label: params.label }, 900_000);
            artifact = resp.backup;
        }
        const ins = await this.db.run(`INSERT INTO container_backups
         (instance_type, instance_ref_id, node_id, backup_name, file_path, size_bytes, checksum_sha256, encrypted, encryption_alg, status, created_by)
       VALUES ('lxc', ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?)`, [
            params.refId,
            row.node_id,
            artifact.backupName,
            artifact.filePath,
            artifact.sizeBytes,
            artifact.checksumSha256,
            encrypted,
            encryptionAlg,
            params.actorId || null,
        ]);
        return {
            backupId: ins.lastID,
            ...artifact,
        };
    }
    async getBackupRecord(backupId) {
        return this.db.get(`SELECT b.*, n.is_local
       FROM container_backups b
       LEFT JOIN nodes n ON n.id = b.node_id
       WHERE b.id = ?`, [backupId]);
    }
    async verifyBackupIntegrity(backupId) {
        const bkp = await this.getBackupRecord(backupId);
        if (!bkp)
            throw new Error('Backup record not found.');
        if (bkp.node_id && bkp.is_local === 0) {
            return this.nodeManager.requestRemoteNode(bkp.node_id, 'POST', '/api/v1/backups/verify', {
                filePath: bkp.file_path,
                expectedSha256: bkp.checksum_sha256,
            });
        }
        if (!fs_1.default.existsSync(bkp.file_path)) {
            return { valid: false, expectedSha256: bkp.checksum_sha256, actualSha256: null };
        }
        // Encrypted archives are verified by decrypting to a temp file and checksumming the
        // recovered content. AES-GCM authentication also fails here if the stored file was
        // tampered with, so corruption is surfaced as an invalid/failed verification.
        let verifyPath = bkp.file_path;
        let tempVerifyPath = null;
        if (Number(bkp.encrypted || 0) === 1) {
            tempVerifyPath = path_1.default.join(this.nodeManager.localRuntime.snapshotManager.getBackupDir(), `verify_${Date.now()}_${crypto_1.default.randomBytes(4).toString('hex')}.tar.gz`);
            this.nodeManager.localRuntime.snapshotManager.resolveConfinedBackupPath(tempVerifyPath);
            (0, backup_crypto_1.decryptArchive)(bkp.file_path, tempVerifyPath);
            verifyPath = tempVerifyPath;
        }
        try {
            const actual = await this.nodeManager.localRuntime.snapshotManager.computeFileSha256(verifyPath);
            const valid = !bkp.checksum_sha256 || bkp.checksum_sha256.toLowerCase() === actual.toLowerCase();
            return { valid, expectedSha256: bkp.checksum_sha256, actualSha256: actual };
        }
        finally {
            if (tempVerifyPath && fs_1.default.existsSync(tempVerifyPath)) {
                try {
                    fs_1.default.unlinkSync(tempVerifyPath);
                }
                catch { /* best effort */ }
            }
        }
    }
    async restoreBackup(backupId, actorId) {
        const bkp = await this.getBackupRecord(backupId);
        if (!bkp)
            throw new Error('Backup record not found.');
        if (bkp.instance_type !== 'lxc') {
            throw new Error('Archive live restore is currently supported for LXC container backups (use QCOW2 Snapshots for KVM instant revert).');
        }
        const row = await this.virt.lxc.getRawLxcRow(Number(bkp.instance_ref_id));
        if (!row)
            throw new Error(`LXC container #${bkp.instance_ref_id} not found.`);
        const backupOnDifferentNode = Boolean(bkp.node_id) && Number(bkp.node_id) !== Number(row.node_id);
        let crossNodeBase64 = null;
        if (backupOnDifferentNode) {
            if (Number(bkp.is_local || 0) === 1 || Number(bkp.node_id) === 1) {
                if (!fs_1.default.existsSync(bkp.file_path)) {
                    throw new Error('Backup archive file no longer exists on source node.');
                }
                crossNodeBase64 = fs_1.default.readFileSync(bkp.file_path).toString('base64');
            }
            else {
                const dl = await this.nodeManager.requestRemoteNode(Number(bkp.node_id), 'POST', '/api/v1/backups/download', {
                    filePath: bkp.file_path,
                    expectedSha256: bkp.checksum_sha256 || undefined,
                }, 600_000);
                crossNodeBase64 = dl.archiveBase64;
            }
        }
        let postState = 'stopped';
        if (row.is_local) {
            let localTargetFile = String(bkp.file_path);
            let tempLocalFile = null;
            if (crossNodeBase64) {
                tempLocalFile = this.nodeManager.localRuntime.snapshotManager.resolveConfinedBackupPath(path_1.default.join(this.nodeManager.localRuntime.snapshotManager.getBackupDir(), `crossnode_restore_${Date.now()}_${crypto_1.default.randomBytes(4).toString('hex')}.tar.gz`));
                fs_1.default.mkdirSync(path_1.default.dirname(tempLocalFile), { recursive: true });
                fs_1.default.writeFileSync(tempLocalFile, Buffer.from(crossNodeBase64, 'base64'), { mode: 0o600 });
                localTargetFile = tempLocalFile;
            }
            else if (Number(bkp.encrypted || 0) === 1) {
                // Encrypted local archive: decrypt to a confined temp file, then restore from it.
                // The stored checksum verifies the recovered (decrypted) content.
                tempLocalFile = this.nodeManager.localRuntime.snapshotManager.resolveConfinedBackupPath(path_1.default.join(this.nodeManager.localRuntime.snapshotManager.getBackupDir(), `restore_${Date.now()}_${crypto_1.default.randomBytes(4).toString('hex')}.tar.gz`));
                (0, backup_crypto_1.decryptArchive)(bkp.file_path, tempLocalFile);
                localTargetFile = tempLocalFile;
            }
            try {
                const before = await this.nodeManager.localRuntime.containerManager.inspectContainer(row.container_name);
                const wasRunning = before.state === 'running' || before.state === 'frozen';
                if (wasRunning) {
                    await this.nodeManager.localRuntime.containerManager.stopContainer(row.container_name, false);
                }
                await this.nodeManager.localRuntime.snapshotManager.restoreTarBackup(localTargetFile, bkp.checksum_sha256 || undefined, row.container_name);
                if (wasRunning) {
                    await this.nodeManager.localRuntime.containerManager.startContainer(row.container_name);
                }
                const after = await this.nodeManager.localRuntime.containerManager.inspectContainer(row.container_name);
                postState = after.state === 'running' ? 'running' : 'stopped';
            }
            finally {
                if (tempLocalFile && fs_1.default.existsSync(tempLocalFile)) {
                    try {
                        fs_1.default.unlinkSync(tempLocalFile);
                    }
                    catch {
                        // ignore
                    }
                }
            }
        }
        else {
            const resp = await this.nodeManager.requestRemoteNode(row.node_id, 'POST', `/api/v1/containers/${encodeURIComponent(row.container_name)}/backups/restore`, crossNodeBase64
                ? {
                    archiveBase64: crossNodeBase64,
                    expectedSha256: bkp.checksum_sha256 || undefined,
                }
                : {
                    filePath: bkp.file_path,
                    expectedSha256: bkp.checksum_sha256 || undefined,
                }, 900_000);
            postState = resp.container?.state === 'running' ? 'running' : 'stopped';
        }
        await this.db.run(`UPDATE lxc_instances SET status = ?, updated_at = datetime('now') WHERE id = ?`, [postState, row.id]);
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
    async deleteBackup(backupId) {
        const bkp = await this.getBackupRecord(backupId);
        if (!bkp)
            throw new Error('Backup record not found.');
        if (bkp.node_id && bkp.is_local === 0) {
            await this.nodeManager.requestRemoteNode(bkp.node_id, 'DELETE', '/api/v1/backups/file', {
                filePath: bkp.file_path,
            });
        }
        else if (bkp.file_path && fs_1.default.existsSync(bkp.file_path)) {
            fs_1.default.unlinkSync(bkp.file_path);
        }
        await this.db.run(`DELETE FROM container_backups WHERE id = ?`, [backupId]);
    }
}
exports.BackupSnapshotManager = BackupSnapshotManager;
