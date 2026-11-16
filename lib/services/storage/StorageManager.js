"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.StorageManager = void 0;
const fs_1 = __importDefault(require("fs"));
const os_1 = __importDefault(require("os"));
const path_1 = __importDefault(require("path"));
/**
 * Unified Storage Pool & LXC OS Template Manager for TGVPANEL V4.
 * Supports directory, RAW, QCOW2, LVM, ZFS, and Btrfs storage pools across both
 * local and remote Node Agents, plus centralized LXC OS template catalog management.
 */
class StorageManager {
    db;
    nodeManager;
    constructor(db, nodeManager) {
        this.db = db;
        this.nodeManager = nodeManager;
    }
    async listPools() {
        return this.db.all(`SELECT sp.*,
              n.name AS node_name,
              COALESCE(n.is_local, 0) AS node_is_local,
              (SELECT COUNT(*) FROM storage_volumes sv WHERE sv.pool_id = sp.id) AS volume_count
       FROM storage_pools sp
       LEFT JOIN nodes n ON n.id = sp.node_id
       ORDER BY sp.id ASC`);
    }
    resolveNearestExistingAncestor(targetPath) {
        let cur = path_1.default.resolve(targetPath);
        while (true) {
            if (fs_1.default.existsSync(cur))
                return cur;
            const parent = path_1.default.dirname(cur);
            if (!parent || parent === cur)
                break;
            cur = parent;
        }
        return null;
    }
    async syncPoolCapacities() {
        const pools = await this.listPools();
        for (const p of pools) {
            if (!p.path)
                continue;
            const isLocal = Number(p.node_is_local || 0) === 1 || Number(p.node_id) === 1;
            let effectivePath = String(p.path);
            // Heal legacy seeded sandbox path (/home/user/vms) on local-kvm when running elsewhere
            if (isLocal &&
                p.name === 'local-kvm' &&
                effectivePath === '/home/user/vms' &&
                !fs_1.default.existsSync(effectivePath)) {
                const appVmsDir = path_1.default.resolve(process.cwd(), 'vms');
                try {
                    fs_1.default.mkdirSync(appVmsDir, { recursive: true });
                }
                catch {
                    // ignore if read-only
                }
                if (fs_1.default.existsSync(appVmsDir)) {
                    effectivePath = appVmsDir;
                    await this.db.run(`UPDATE storage_pools SET path = ? WHERE id = ?`, [
                        effectivePath,
                        p.id,
                    ]);
                }
            }
            if (isLocal) {
                const statTarget = this.resolveNearestExistingAncestor(effectivePath);
                if (statTarget) {
                    try {
                        const st = fs_1.default.statfsSync(statTarget);
                        const totalBytes = Number(st.blocks) * Number(st.bsize);
                        const availBytes = Number(st.bavail) * Number(st.bsize);
                        const usedBytes = Math.max(0, totalBytes - availBytes);
                        const poolState = fs_1.default.existsSync(effectivePath) ? 'online' : 'ready';
                        await this.db.run(`UPDATE storage_pools
               SET total_bytes = ?, used_bytes = ?, available_bytes = ?, status = ?, updated_at = datetime('now')
               WHERE id = ?`, [totalBytes, usedBytes, availBytes, poolState, p.id]);
                    }
                    catch {
                        // Retain cached values when filesystem statfs is restricted
                    }
                }
            }
            else if (this.nodeManager) {
                try {
                    const remote = await this.nodeManager.requestRemoteNode(Number(p.node_id), 'POST', '/api/v1/storage/statfs', { path: effectivePath }, 12_000);
                    const poolState = remote.exists ? 'online' : 'ready';
                    await this.db.run(`UPDATE storage_pools
             SET total_bytes = ?, used_bytes = ?, available_bytes = ?, status = ?, updated_at = datetime('now')
             WHERE id = ?`, [
                        Number(remote.totalBytes || 0),
                        Number(remote.usedBytes || 0),
                        Number(remote.availableBytes || 0),
                        poolState,
                        p.id,
                    ]);
                }
                catch {
                    await this.db
                        .run(`UPDATE storage_pools SET status = 'offline', updated_at = datetime('now') WHERE id = ?`, [
                        p.id,
                    ])
                        .catch(() => undefined);
                }
            }
        }
        return this.listPools();
    }
    async createPool(input) {
        const nodeId = Number(input.nodeId || 1);
        const name = String(input.name || '').trim();
        const rawPath = String(input.path || input.poolPath || '').trim();
        if (!name || !rawPath) {
            throw new Error('Storage pool name and path are required.');
        }
        const cleanPath = path_1.default.resolve(rawPath);
        const poolType = String(input.poolType || 'dir').trim();
        const engineScope = String(input.engineScope || 'both').trim();
        const overcommit = Math.max(0.5, Math.min(10, Number(input.overcommitRatio || 1.5)));
        const nodeRow = await this.db.get(`SELECT is_local FROM nodes WHERE id = ?`, [nodeId]);
        const isLocal = nodeId === 1 || Number(nodeRow?.is_local || 0) === 1;
        if (isLocal) {
            try {
                fs_1.default.mkdirSync(cleanPath, { recursive: true });
            }
            catch {
                // Directory may require root or manual mount; statfs will probe nearest ancestor
            }
        }
        else if (this.nodeManager) {
            await this.nodeManager
                .requestRemoteNode(nodeId, 'POST', '/api/v1/storage/statfs', {
                path: cleanPath,
                ensureDir: true,
            })
                .catch(() => undefined);
        }
        const ins = await this.db.run(`INSERT INTO storage_pools (node_id, name, engine, pool_type, engine_scope, path, overcommit_ratio, enabled, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1)`, [
            nodeId,
            name,
            engineScope,
            poolType,
            engineScope,
            cleanPath,
            overcommit,
        ]);
        await this.syncPoolCapacities().catch(() => undefined);
        return this.db.get(`SELECT * FROM storage_pools WHERE id = ?`, [ins.lastID]);
    }
    async deletePool(poolId) {
        const inUse = await this.db.get(`SELECT COUNT(*) AS cnt FROM storage_volumes WHERE pool_id = ?`, [poolId]);
        if ((inUse?.cnt || 0) > 0) {
            throw new Error('Cannot delete a storage pool that still contains active volumes.');
        }
        await this.db.run(`DELETE FROM storage_pools WHERE id = ?`, [poolId]);
    }
    /**
     * Lists the ISO images available in the managed ISO directory with honest
     * file size and SHA-256 checksum. The checksum is computed from the real file
     * contents (reusing the node-agent checksum helper) so operators can verify
     * ISO integrity; it is null only when the checksum cannot be computed.
     */
    /**
     * Report-only orphan image detection: scans **local** storage pool directories for
     * disk image files (qcow2/raw/img/vmdk) that are not referenced by any live record —
     * KVM VMs (`vms.disk_file` or `extra_disks_json` disk paths), LXC container rootfs
     * directories (`lxc_instances.rootfs_path`, so files inside them are not flagged) or
     * LXC OS templates (`lxc_templates.file_path`). This NEVER deletes or modifies
     * anything; it only reports candidates so an operator can reconcile them
     * deliberately. Remote pools are skipped (no agent-side directory listing is
     * implemented), and pools whose path does not exist yield no entries.
     */
    async listOrphanImages() {
        const IMAGE_EXTENSIONS = new Set(['.qcow2', '.qcow', '.qcow3', '.raw', '.img', '.vmdk']);
        // Collect referenced files and referenced directories from live instance records.
        const referencedFiles = new Set();
        const referencedDirs = [];
        const vms = await this.db.all(`SELECT disk_file, extra_disks_json FROM vms`);
        for (const vm of vms) {
            if (vm.disk_file) {
                referencedFiles.add(path_1.default.resolve(String(vm.disk_file)));
            }
            if (vm.extra_disks_json) {
                try {
                    const parsed = JSON.parse(String(vm.extra_disks_json));
                    if (Array.isArray(parsed)) {
                        for (const dev of parsed) {
                            const devPath = dev && typeof dev === 'object' && typeof dev.path === 'string'
                                ? dev.path
                                : typeof dev === 'string'
                                    ? dev
                                    : null;
                            if (devPath)
                                referencedFiles.add(path_1.default.resolve(devPath));
                        }
                    }
                }
                catch {
                    // Skip malformed device JSON; it must not crash the scan.
                }
            }
        }
        const lxcRows = await this.db.all(`SELECT rootfs_path FROM lxc_instances WHERE rootfs_path IS NOT NULL AND rootfs_path != ''`);
        for (const row of lxcRows) {
            try {
                referencedDirs.push(fs_1.default.realpathSync(String(row.rootfs_path)));
            }
            catch {
                // Missing rootfs directory: ignore rather than flag its contents.
            }
        }
        const templateRows = await this.db.all(`SELECT file_path FROM lxc_templates WHERE file_path IS NOT NULL AND file_path != ''`);
        for (const row of templateRows) {
            if (row.file_path)
                referencedFiles.add(path_1.default.resolve(String(row.file_path)));
        }
        const orphans = [];
        const pools = await this.listPools();
        for (const pool of pools) {
            const isLocal = Number(pool.node_is_local || 0) === 1 || Number(pool.node_id) === 1;
            if (!isLocal || !pool.path)
                continue;
            const poolPath = path_1.default.resolve(String(pool.path));
            if (!fs_1.default.existsSync(poolPath))
                continue;
            for (const file of this.walkImageFiles(poolPath, IMAGE_EXTENSIONS)) {
                if (referencedFiles.has(file))
                    continue;
                if (referencedDirs.some((dir) => file === dir || file.startsWith(`${dir}${path_1.default.sep}`)))
                    continue;
                let sizeBytes = 0;
                try {
                    sizeBytes = fs_1.default.statSync(file).size;
                }
                catch {
                    continue;
                }
                orphans.push({
                    poolId: Number(pool.id),
                    poolName: String(pool.name),
                    poolPath,
                    filePath: file,
                    sizeBytes,
                    reason: 'Disk image is not referenced by any KVM VM, LXC container, or OS template.',
                });
            }
        }
        orphans.sort((a, b) => a.poolId - b.poolId || a.filePath.localeCompare(b.filePath));
        return orphans;
    }
    /** Recursively collects image files under `rootDir`, skipping hidden entries. */
    walkImageFiles(rootDir, extensions) {
        const out = [];
        const stack = [rootDir];
        while (stack.length > 0) {
            const dir = stack.pop();
            let entries;
            try {
                entries = fs_1.default.readdirSync(dir, { withFileTypes: true });
            }
            catch {
                continue;
            }
            for (const entry of entries) {
                if (entry.name.startsWith('.'))
                    continue;
                const full = path_1.default.join(dir, entry.name);
                if (entry.isDirectory()) {
                    stack.push(full);
                }
                else if (entry.isFile() && extensions.has(path_1.default.extname(entry.name).toLowerCase())) {
                    out.push(path_1.default.resolve(full));
                }
            }
        }
        return out;
    }
    async listIsoFiles() {
        const isoDir = path_1.default.join(os_1.default.homedir(), 'vms', 'iso');
        let files;
        try {
            files = fs_1.default.readdirSync(isoDir).filter((f) => f.toLowerCase().endsWith('.iso'));
        }
        catch {
            return [];
        }
        const out = [];
        for (const file of files.sort()) {
            const full = path_1.default.join(isoDir, file);
            try {
                const stat = fs_1.default.statSync(full);
                if (!stat.isFile())
                    continue;
                const sha256 = this.nodeManager?.localRuntime?.snapshotManager
                    ? await this.nodeManager.localRuntime.snapshotManager.computeFileSha256(full).catch(() => null)
                    : null;
                out.push({ filename: file, sizeBytes: stat.size, sha256 });
            }
            catch {
                // Skip files that disappear or cannot be stat'ed between listing and inspection.
            }
        }
        return out;
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
    static resolveLxcTemplateIcon(tpl) {
        const raw = String(tpl.icon_path || tpl.icon || '').trim();
        if (raw && raw.startsWith('/images/os/') && raw.endsWith('.svg'))
            return raw;
        if (raw && (raw.startsWith('http://') || raw.startsWith('https://') || raw.startsWith('data:image/'))) {
            return raw;
        }
        const hint = `${tpl.slug || ''} ${tpl.template_key || ''} ${tpl.distro || ''} ${tpl.category || ''} ${tpl.name || ''} ${tpl.label || ''} ${raw}`.toLowerCase();
        if (hint.includes('proxmox') || hint.includes('pve'))
            return '/images/os/proxmox.svg';
        if (hint.includes('ubuntu'))
            return '/images/os/ubuntu.svg';
        if (hint.includes('debian'))
            return '/images/os/debian.svg';
        if (hint.includes('fedora'))
            return '/images/os/fedora.svg';
        if (hint.includes('centos'))
            return '/images/os/centos.svg';
        if (hint.includes('alma'))
            return '/images/os/almalinux.svg';
        if (hint.includes('rocky'))
            return '/images/os/rocky.svg';
        if (hint.includes('kali'))
            return '/images/os/kali.svg';
        if (hint.includes('alpine'))
            return '/images/os/alpine.svg';
        return '/images/os/linux.svg';
    }
    async listLxcTemplates(includeDisabled = false) {
        const where = includeDisabled ? '' : 'WHERE COALESCE(enabled, is_active, 1) = 1';
        const rows = await this.db.all(`SELECT * FROM lxc_templates ${where} ORDER BY distro ASC, release DESC, id ASC`);
        return rows.map((r) => {
            const iconPath = StorageManager.resolveLxcTemplateIcon(r);
            return { ...r, icon: iconPath, icon_path: iconPath };
        });
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
        const iconPath = StorageManager.resolveLxcTemplateIcon({
            icon: input.icon || null,
            distro,
            slug: cleanSlug,
            category: input.category || null,
            name: input.name,
        });
        const proxmoxCodename = input.proxmoxCodename ||
            (cleanSlug.startsWith('proxmox') || distro === 'proxmox'
                ? release === '13' || release === 'trixie' || cleanSlug.includes('ve-9')
                    ? 'trixie'
                    : 'bookworm'
                : null);
        await this.db.run(`INSERT INTO lxc_templates
         (template_key, label, image_alias, slug, name, distro, release, arch, variant, family, category, icon, icon_path, proxmox_codename, min_disk_gb, min_ram_mb, is_custom, local_path, file_path, sha256, checksum_sha256, is_active, enabled)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(slug) DO UPDATE SET
         label = excluded.label,
         name = excluded.name,
         distro = excluded.distro,
         release = excluded.release,
         arch = excluded.arch,
         variant = excluded.variant,
         family = excluded.family,
         category = COALESCE(excluded.category, lxc_templates.category),
         icon = excluded.icon,
         icon_path = excluded.icon_path,
         proxmox_codename = COALESCE(excluded.proxmox_codename, lxc_templates.proxmox_codename),
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
            input.category?.trim() || null,
            iconPath,
            iconPath,
            proxmoxCodename,
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
        const row = await this.db.get(`SELECT * FROM lxc_templates WHERE slug = ?`, [cleanSlug]);
        if (row) {
            const resolved = StorageManager.resolveLxcTemplateIcon(row);
            return { ...row, icon: resolved, icon_path: resolved };
        }
        return row;
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
