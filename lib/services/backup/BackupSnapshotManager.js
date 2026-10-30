"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BackupSnapshotManager = void 0;
const fs_1 = __importDefault(require("fs"));
const middleware_1 = require("../../security/middleware");
class BackupSnapshotManager {
    db;
    nodeManager;
    virt;
    constructor(db, nodeManager, virt) {
        this.db = db;
        this.nodeManager = nodeManager;
        this.virt = virt;
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
        if ((countRow?.cnt || 0) >= limit) {
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
        if (row.is_local) {
            artifact = await this.nodeManager.localRuntime.snapshotManager.createTarBackup(row.container_name, params.label);
        }
        else {
            const resp = await this.nodeManager.requestRemoteNode(row.node_id, 'POST', `/api/v1/containers/${encodeURIComponent(row.container_name)}/backups`, { label: params.label }, 900_000);
            artifact = resp.backup;
        }
        const ins = await this.db.run(`INSERT INTO container_backups
         (instance_type, instance_ref_id, node_id, backup_name, file_path, size_bytes, checksum_sha256, status, created_by)
       VALUES ('lxc', ?, ?, ?, ?, ?, ?, 'completed', ?)`, [
            params.refId,
            row.node_id,
            artifact.backupName,
            artifact.filePath,
            artifact.sizeBytes,
            artifact.checksumSha256,
            params.actorId || null,
        ]);
        return {
            backupId: ins.lastID,
            ...artifact,
        };
    }
    async verifyBackupIntegrity(backupId) {
        const bkp = await this.db.get(`SELECT * FROM container_backups WHERE id = ?`, [backupId]);
        if (!bkp)
            throw new Error('Backup record not found.');
        if (!fs_1.default.existsSync(bkp.file_path)) {
            return { valid: false, expectedSha256: bkp.checksum_sha256, actualSha256: null };
        }
        const actual = await this.nodeManager.localRuntime.snapshotManager.computeFileSha256(bkp.file_path);
        const valid = !bkp.checksum_sha256 || bkp.checksum_sha256.toLowerCase() === actual.toLowerCase();
        return { valid, expectedSha256: bkp.checksum_sha256, actualSha256: actual };
    }
    async deleteBackup(backupId) {
        const bkp = await this.db.get(`SELECT * FROM container_backups WHERE id = ?`, [backupId]);
        if (!bkp)
            throw new Error('Backup record not found.');
        if (bkp.file_path && fs_1.default.existsSync(bkp.file_path)) {
            fs_1.default.unlinkSync(bkp.file_path);
        }
        await this.db.run(`DELETE FROM container_backups WHERE id = ?`, [backupId]);
    }
}
exports.BackupSnapshotManager = BackupSnapshotManager;
