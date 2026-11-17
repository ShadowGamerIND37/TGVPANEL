import { UnifiedDatabase } from '../../db/database';
import { runAllowlistedCommand } from '../../node-agent/command-runner';
import { InstanceCapabilityProfile, InstanceTelemetry, LifecycleAction, UnifiedInstanceRecord, VirtualizationAdapter } from './VirtualizationAdapter';
export interface LegacyKvmHooks {
    startVmById?: (vmId: number) => Promise<void>;
    stopVmById?: (vmId: number, force?: boolean) => Promise<void>;
    restartVmById?: (vmId: number) => Promise<void>;
    deleteVmById?: (vmId: number) => Promise<void>;
}
/**
 * Real QEMU/KVM hypervisor adapter wrapping HKVM's `vms` (`vm_id`, `vm_name`, `owner_id`, `disk_file`)
 * records, Linux `/proc/<pid>` telemetry, and real `qemu-img` snapshot/backup operations.
 */
export declare class KVMAdapter implements VirtualizationAdapter {
    private readonly commandRunner;
    readonly engine: 'kvm';
    private db;
    private hooks;
    private prevPidTicks;
    private pendingClonePorts;
    constructor(db: UnifiedDatabase, hooks?: LegacyKvmHooks, commandRunner?: typeof runAllowlistedCommand);
    setLegacyHooks(hooks: LegacyKvmHooks): void;
    getCapabilityProfile(): InstanceCapabilityProfile;
    private resolveVmDiskPath;
    private parseDiskGb;
    /**
     * Reads honest disk-image statistics via `qemu-img info --output=json`:
     * `virtual-size` (the image's virtual capacity) and `disk-size` (the actual
     * bytes allocated on disk). This replaces a bare `statSync` image-file-size
     * reading, which does not distinguish virtual capacity from allocated usage or
     * disclose the image format. Returns null when qemu-img is unavailable or fails
     * (callers fall back to the previous behavior).
     */
    private getDiskImageStats;
    private parseDiskSizeBytes;
    private mapRowToUnified;
    listInstances(filter?: {
        ownerId?: number;
        nodeId?: number;
    }): Promise<UnifiedInstanceRecord[]>;
    getInstance(refId: number): Promise<UnifiedInstanceRecord | undefined>;
    private isProcessAlive;
    private assertCanStopWithoutHook;
    private assertHookedVmProcessState;
    private stopVmProcess;
    private isTcpPortAvailable;
    private allocateClonePort;
    /** Clone a stopped NAT-mode KVM with a flattened standalone system disk and fresh host network metadata. */
    cloneStoppedVm(refId: number, requestedName: string): Promise<{
        vmId: number;
        name: string;
        diskSizeBytes: number;
        sshForwardPort: number;
        guestIdentityResetRequired: true;
    }>;
    getVncSettings(refId: number): Promise<{
        enabled: boolean;
        port: number | null;
    }>;
    setVncEnabled(refId: number, enabled: boolean): Promise<{
        enabled: boolean;
        port: number | null;
    }>;
    getAttachedDevices(refId: number): Promise<{
        disks: Array<{
            id: string;
            sizeBytes: number;
            format: string;
            attached: boolean;
        }>;
        nics: Array<{
            id: string;
            macAddress: string;
            model: string;
            networkMode: string;
        }>;
    }>;
    private getStoppedVmForDeviceChange;
    private parseDeviceList;
    /** Create and attach a secondary QCOW2 disk to a stopped KVM VM. Detaching never deletes data. */
    attachDiskImage(refId: number, requestedSize: string): Promise<{
        id: string;
        sizeBytes: number;
        format: 'qcow2';
    }>;
    /** Detach a secondary disk configuration while preserving and cataloguing its image. */
    detachDiskImage(refId: number, deviceId: string): Promise<{
        id: string;
        imagePreserved: true;
    }>;
    /** Reattach a previously detached secondary image without changing its contents. */
    reattachDiskImage(refId: number, deviceId: string): Promise<{
        id: string;
        attached: true;
    }>;
    /** Attach a secondary user-mode NAT network interface to a stopped KVM VM. */
    attachNatNic(refId: number): Promise<{
        id: string;
        macAddress: string;
        model: 'virtio-net-pci';
        networkMode: 'user';
    }>;
    /** Detach a secondary network-interface configuration from a stopped KVM VM. */
    detachNic(refId: number, deviceId: string): Promise<{
        id: string;
    }>;
    /** Expand an offline standalone KVM disk image. Guest partitions/filesystems are not resized here. */
    resizeDiskImage(refId: number, requestedSize: string): Promise<{
        diskSize: string;
        virtualSizeBytes: number;
        guestFilesystemResizeRequired: true;
    }>;
    syncRegistryRow(vmId: number): Promise<void>;
    performLifecycleAction(refId: number, action: LifecycleAction, options?: {
        reason?: string;
        actorId?: number;
        force?: boolean;
    }): Promise<UnifiedInstanceRecord>;
    getTelemetry(refId: number): Promise<InstanceTelemetry>;
    createQcow2Snapshot(vmId: number, snapshotName: string, description?: string): Promise<{
        id: number;
        name: string;
    }>;
    restoreQcow2Snapshot(vmId: number, snapshotId: number): Promise<void>;
    deleteQcow2Snapshot(vmId: number, snapshotId: number): Promise<void>;
    createDiskBackup(vmId: number, backupDir?: string): Promise<{
        backupId: number;
        backupName: string;
        filePath: string;
        sizeBytes: number;
        checksumSha256: string;
        encrypted: boolean;
        encryptionAlg: string;
    }>;
}
