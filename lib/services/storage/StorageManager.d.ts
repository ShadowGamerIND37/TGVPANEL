import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';
/**
 * Unified Storage Pool & LXC OS Template Manager for TGVPANEL V4.
 * Supports directory, RAW, QCOW2, LVM, ZFS, and Btrfs storage pools across both
 * local and remote Node Agents, plus centralized LXC OS template catalog management.
 */
export declare class StorageManager {
    private readonly db;
    private readonly nodeManager?;
    constructor(db: UnifiedDatabase, nodeManager?: NodeManager | undefined);
    listPools(): Promise<any[]>;
    private resolveNearestExistingAncestor;
    syncPoolCapacities(): Promise<any[]>;
    createPool(input: {
        nodeId?: number;
        name: string;
        poolType?: string;
        engineScope?: string;
        path?: string;
        poolPath?: string;
        overcommitRatio?: number;
    }): Promise<any>;
    deletePool(poolId: number): Promise<void>;
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
    listOrphanImages(): Promise<Array<{
        poolId: number;
        poolName: string;
        poolPath: string;
        filePath: string;
        sizeBytes: number;
        reason: string;
    }>>;
    /** Recursively collects image files under `rootDir`, skipping hidden entries. */
    private walkImageFiles;
    listIsoFiles(): Promise<Array<{
        filename: string;
        sizeBytes: number;
        sha256: string | null;
    }>>;
    verifyCapacityAvailable(nodeId: number, engine: 'kvm' | 'lxc', requestedGb: number): Promise<{
        ok: boolean;
        reason?: string;
    }>;
    static resolveLxcTemplateIcon(tpl: {
        icon?: string | null;
        icon_path?: string | null;
        distro?: string | null;
        slug?: string | null;
        template_key?: string | null;
        category?: string | null;
        name?: string | null;
        label?: string | null;
    }): string;
    listLxcTemplates(includeDisabled?: boolean): Promise<any[]>;
    upsertLxcTemplate(input: {
        slug: string;
        name: string;
        distro: string;
        release: string;
        arch?: string;
        variant?: string;
        family?: string;
        category?: string;
        icon?: string | null;
        proxmoxCodename?: string | null;
        minDiskGb?: number;
        minRamMb?: number;
        isCustom?: boolean;
        filePath?: string | null;
        checksumSha256?: string | null;
        enabled?: boolean;
    }): Promise<any>;
    toggleLxcTemplate(id: number, enabled: boolean): Promise<void>;
    deleteLxcTemplate(id: number): Promise<void>;
}
