export interface LxcCreateSpec {
    containerName: string;
    hostname?: string;
    distro: string;
    release: string;
    fallbackRelease?: string | null;
    arch?: string;
    templateArchivePath?: string | null;
    cpuCores: number;
    cpuShares?: number;
    cpuLimitPercent?: number;
    cpuPinning?: string | null;
    ramMb: number;
    swapMb?: number;
    diskGb: number;
    backingStore?: 'dir' | 'lvm' | 'zfs' | 'btrfs';
    privileged?: boolean;
    nesting?: boolean;
    apparmorProfile?: string;
    bridge?: string;
    ipv4Address?: string | null;
    ipv4Gateway?: string | null;
    ipv6Address?: string | null;
    macAddress?: string | null;
    vlanId?: number | null;
    rootPassword?: string;
    sshPublicKeys?: string[];
    autostart?: boolean;
    mounts?: Array<{
        hostSource: string;
        guestTarget: string;
        readOnly?: boolean;
    }>;
    /**
     * When true (set by LXCAdapter when the panel database has no record for this container),
     * any stale/orphaned `/var/lib/lxc/<name>` directory from an earlier interrupted run is
     * cleanly destroyed and replaced instead of failing with "already exists on host".
     */
    replaceOrphanOnHost?: boolean;
}
export interface LxcResourceUpdateSpec {
    cpuCores?: number;
    cpuShares?: number;
    cpuLimitPercent?: number;
    cpuPinning?: string | null;
    ramMb?: number;
    swapMb?: number;
    diskGb?: number;
    nesting?: boolean;
    privileged?: boolean;
    apparmorProfile?: string;
    autostart?: boolean;
    bridge?: string;
    ipv4Address?: string | null;
    ipv4Gateway?: string | null;
    ipv6Address?: string | null;
}
export interface LxcContainerRuntimeInfo {
    name: string;
    state: 'running' | 'stopped' | 'frozen' | 'missing';
    pid: number | null;
    ips: string[];
    cpuUseSeconds: number;
    memoryBytes: number;
    swapBytes: number;
    rxBytes: number;
    txBytes: number;
    diskUsedBytes: number;
    startupWarning?: string;
}
/**
 * Translates human/LXD version identifiers (e.g. `ubuntu` + `24.04` or `debian` + `12`)
 * into canonical `images.linuxcontainers.org` release names expected by `lxc-create -t download`
 * (`noble`, `bookworm`, `current`, etc.), while retaining fallbacks.
 */
export declare function resolveDownloadReleaseCandidates(rawDistro: string, rawRelease: string, fallbackRelease?: string | null): {
    distro: string;
    releases: string[];
    archMapper: (arch: string) => string;
};
export declare function isAppArmorProfileLoadable(): boolean;
export declare class LxcContainerManager {
    private lxcBaseDir;
    private inFlightCreations;
    constructor(lxcBaseDir?: string);
    isCreationInFlight(containerName: string): boolean;
    getBaseDir(): string;
    getContainerDir(containerName: string): string;
    getRootfsDir(containerName: string): string;
    /**
     * Determines whether operations against `this.lxcBaseDir` require root (`sudo -n`).
     * System `/var/lib/lxc` requires root, whereas unprivileged temporary directories in tests do not.
     */
    needsRootForStore(): boolean;
    private lxcPathArgs;
    private assertLxcInstalled;
    private ensureHostLxcDirectories;
    private ensureBridgeAvailable;
    listContainers(): Promise<LxcContainerRuntimeInfo[]>;
    inspectContainer(containerName: string): Promise<LxcContainerRuntimeInfo>;
    private parseHumanSizeToBytes;
    private measureDirBytesFast;
    private getRootfsUsedBytes;
    private createFromLocalArchive;
    private applyOfflineRootPasswordHash;
    createContainer(spec: LxcCreateSpec): Promise<LxcContainerRuntimeInfo>;
    writeManagedConfigSection(containerName: string, cfg: {
        hostname?: string;
        cpuCores?: number;
        cpuShares?: number;
        cpuLimitPercent?: number;
        cpuPinning?: string | null;
        ramMb?: number;
        swapMb?: number;
        nesting?: boolean;
        privileged?: boolean;
        apparmorProfile?: string;
        autostart?: boolean;
        bridge?: string;
        ipv4Address?: string | null;
        ipv4Gateway?: string | null;
        ipv6Address?: string | null;
        macAddress?: string | null;
        mounts?: Array<{
            hostSource: string;
            guestTarget: string;
            readOnly?: boolean;
        }>;
    }): Promise<void>;
    startContainer(containerName: string): Promise<void>;
    stopContainer(containerName: string, force?: boolean): Promise<void>;
    restartContainer(containerName: string): Promise<void>;
    freezeContainer(containerName: string): Promise<void>;
    unfreezeContainer(containerName: string): Promise<void>;
    destroyContainer(containerName: string): Promise<void>;
    reinstallContainer(spec: LxcCreateSpec): Promise<LxcContainerRuntimeInfo>;
    updateContainerResources(containerName: string, update: LxcResourceUpdateSpec): Promise<void>;
    /**
     * Resets root password inside container using `chpasswd` over stdin (`shell: false`),
     * with offline `/etc/shadow` SHA-512 hash fallback when container is stopped.
     * Zero shell interpolation of password characters.
     */
    setRootPassword(containerName: string, newPassword: string): Promise<void>;
    injectSshPublicKey(containerName: string, publicKey: string): Promise<void>;
    getContainerProcesses(containerName: string): Promise<Array<{
        pid: string;
        user: string;
        cpu: string;
        mem: string;
        command: string;
    }>>;
    getContainerLogs(containerName: string, maxLines?: number): Promise<string>;
    /**
     * Resolves a user-supplied path strictly within `<lxcBaseDir>/<container>/rootfs`,
     * blocking both `..` traversal and symlink escapes outside `rootfs`.
     */
    resolveConfinedRootfsPath(containerName: string, subPath: string): string;
    listRootfsDirectory(containerName: string, subPath?: string): Array<{
        name: string;
        path: string;
        isDirectory: boolean;
        size: number;
        modifiedAt: string;
    }>;
    readRootfsFile(containerName: string, subPath: string, maxBytes?: number): Buffer;
    writeRootfsFile(containerName: string, subPath: string, data: Buffer | string): void;
    deleteRootfsEntry(containerName: string, subPath: string): void;
}
