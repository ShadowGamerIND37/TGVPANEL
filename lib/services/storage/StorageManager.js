"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.StorageManager = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
/**
 * Unified Storage Pool & LXC OS Template Manager for HKVM V3.
 * Supports directory, RAW, QCOW2, LVM, ZFS, and Btrfs storage pools plus
 * centralized LXC OS template catalog management.
 */
class StorageManager {
    db;
    constructor(db) {
        this.db = db;
    }
    async listPools() {
        return this.db.all(`SELECT sp.*, n.name AS node_name
       FROM storage_pools sp
       LEFT JOIN nodes n ON n.id = sp.node_id
       ORDER BY sp.id ASC`);
    }
    async syncPoolCapacities() {
        const pools = await this.listPools();
        for (const p of pools) {
            if (p.path && fs_1.default.existsSync(p.path)) {
                try {
                    const st = fs_1.default.statfsSync(p.path);
                    const totalBytes = Number(st.blocks) * Number(st.bsize);
                    const availBytes = Number(st.bavail) * Number(st.bsize);
                    const usedBytes = Math.max(0, totalBytes - availBytes);
                    await this.db.run(`UPDATE storage_pools
             SET total_bytes = ?, used_bytes = ?, available_bytes = ?, status = 'online', updated_at = datetime('now')
             WHERE id = ?`, [totalBytes, usedBytes, availBytes, p.id]);
                }
                catch {
                    // Retain cached values when filesystem statfs is restricted
                }
            }
        }
        return this.listPools();
    }
    async createPool(input) {
        const nodeId = Number(input.nodeId || 1);
        const name = String(input.name || '').trim();
        const rawPath = String(input.path || '').trim();
        if (!name || !rawPath) {
            throw new Error('Storage pool name and path are required.');
        }
        const cleanPath = path_1.default.resolve(rawPath);
        const poolType = String(input.poolType || 'dir').trim();
        const engineScope = String(input.engineScope || 'both').trim();
        const ins = await this.db.run(`INSERT INTO storage_pools (node_id, name, engine, pool_type, engine_scope, path, overcommit_ratio, enabled, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1)`, [
            nodeId,
            name,
            engineScope,
            poolType,
            engineScope,
            cleanPath,
            Number(input.overcommitRatio || 1.5),
        ]);
        return this.db.get(`SELECT * FROM storage_pools WHERE id = ?`, [ins.lastID]);
    }
    async deletePool(poolId) {
        const inUse = await this.db.get(`SELECT COUNT(*) AS cnt FROM storage_volumes WHERE pool_id = ?`, [poolId]);
        if ((inUse?.cnt || 0) > 0) {
            throw new Error('Cannot delete a storage pool that still contains active volumes.');
        }
        await this.db.run(`DELETE FROM storage_pools WHERE id = ?`, [poolId]);
    }
    async verifyCapacityAvailable(nodeId, engine, requestedGb) {
        const pools = await this.db.all(`SELECT * FROM storage_pools
       WHERE node_id = ? AND COALESCE(enabled, 1) = 1
         AND (COALESCE(engine_scope, engine, 'both') IN ('both', ?))`, [nodeId, engine]);
        if (pools.length === 0)
            return { ok: true };
        const reqBytes = Math.max(1, requestedGb) * 1024 ** 3;
        for (const p of pools) {
            const avail = Number(p.available_bytes || 0);
            if (avail === 0 || avail * Number(p.overcommit_ratio || 1.5) >= reqBytes) {
                return { ok: true };
            }
        }
        return {
            ok: false,
            reason: `Insufficient available storage capacity on node #${nodeId}.`,
        };
    }
    async listLxcTemplates(includeDisabled = false) {
        const where = includeDisabled ? '' : 'WHERE COALESCE(enabled, is_active, 1) = 1';
        return this.db.all(`SELECT * FROM lxc_templates ${where} ORDER BY distro ASC, release DESC, id ASC`);
    }
    async upsertLxcTemplate(input) {
        const cleanSlug = String(input.slug || `${input.distro}-${input.release}`)
            .trim()
            .toLowerCase()
            .replace(/[^a-z0-9._-]+/g, '-');
        if (!cleanSlug || !input.name?.trim()) {
            throw new Error('Template slug and display name are required.');
        }
        const distro = input.distro.trim().toLowerCase();
        const release = input.release.trim();
        const alias = `${distro}:${release}`;
        await this.db.run(`INSERT INTO lxc_templates
         (template_key, label, image_alias, slug, name, distro, release, arch, variant, family, min_disk_gb, min_ram_mb, is_custom, local_path, file_path, sha256, checksum_sha256, is_active, enabled)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(slug) DO UPDATE SET
         label = excluded.label,
         name = excluded.name,
         distro = excluded.distro,
         release = excluded.release,
         arch = excluded.arch,
         variant = excluded.variant,
         family = excluded.family,
         min_disk_gb = excluded.min_disk_gb,
         min_ram_mb = excluded.min_ram_mb,
         file_path = COALESCE(excluded.file_path, lxc_templates.file_path),
         checksum_sha256 = COALESCE(excluded.checksum_sha256, lxc_templates.checksum_sha256),
         is_active = excluded.is_active,
         enabled = excluded.enabled`, [
            cleanSlug,
            input.name.trim(),
            alias,
            cleanSlug,
            input.name.trim(),
            distro,
            release,
            input.arch?.trim() || 'amd64',
            input.variant?.trim() || 'default',
            input.family?.trim() || 'debian',
            Number(input.minDiskGb || 5),
            Number(input.minRamMb || 256),
            input.isCustom ? 1 : 0,
            input.filePath || null,
            input.filePath || null,
            input.checksumSha256 || null,
            input.checksumSha256 || null,
            input.enabled !== false ? 1 : 0,
            input.enabled !== false ? 1 : 0,
        ]);
        return this.db.get(`SELECT * FROM lxc_templates WHERE slug = ?`, [cleanSlug]);
    }
    async toggleLxcTemplate(id, enabled) {
        const v = enabled ? 1 : 0;
        await this.db.run(`UPDATE lxc_templates SET enabled = ?, is_active = ? WHERE id = ?`, [
            v,
            v,
            id,
        ]);
    }
    async deleteLxcTemplate(id) {
        const row = await this.db.get(`SELECT * FROM lxc_templates WHERE id = ?`, [id]);
        if (row?.is_custom && row?.file_path && fs_1.default.existsSync(row.file_path)) {
            try {
                fs_1.default.unlinkSync(row.file_path);
            }
            catch {
                // ignore
            }
        }
        await this.db.run(`DELETE FROM lxc_templates WHERE id = ?`, [id]);
    }
}
exports.StorageManager = StorageManager;
