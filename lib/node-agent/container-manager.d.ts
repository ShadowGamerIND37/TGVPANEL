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
    kvmNesting?: boolean;
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
    kvmNesting?: boolean;
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
    configuredIpv4?: string | null;
    configuredGateway?: string | null;
    startupWarning?: string;
}
export interface LxcBridgeNetworkInfo {
    ready: boolean;
    bridgeIp: string | null;
    prefixLen: number;
    subnetCidr: string | null;
    hasDhcpServer: boolean;
    natConfigured: boolean;
    dnsRelayPort: number;
}
export interface LxcNetworkRepairResult {
    containerName: string;
    state: LxcContainerRuntimeInfo['state'];
    bridge: string;
    ipv4Address: string | null;
    gateway: string | null;
    dnsServers: string[];
    dnsRelayPort?: number;
    natConfigured: boolean;
    liveApplied: boolean;
    restartedForVeth?: boolean;
}
export declare function ipv4ToUint32(ip: string): number;
export declare function uint32ToIpv4(num: number): string;
export declare function prefixLenToNetmask(prefixLen: number): string;
export declare function computeIpv4SubnetCidr(ip: string, prefixLen?: number): string | null;
/**
 * Resolves up to 3 reliable upstream IPv4 DNS servers suitable for inside an LXC container
 * (respecting glibc MAXNS=3 while filtering out host loopback 127.0.0.53 and WSL2's
 * non-bridge-routable 10.255.255.254 tunnel listener).
 */
export declare function resolveGuestDnsServers(hostResolvConfContent?: string): string[];
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
    private isSystemLxcStore;
    private bridgeHasPhysicalSlave;
    private detectBridgeDhcpServer;
    private ensureIptablesRule;
    /**
     * Ensures the Linux bridge exists, is UP, has an IPv4 gateway address (when operating as
     * a virtual NAT bridge such as `lxcbr0`), starts HKVM's host-side `BridgeDnsRelay`, enables
     * kernel forwarding/rp_filter sysctls, and installs idempotent MASQUERADE, FORWARD ACCEPT,
     * INPUT ACCEPT, TCPMSS clamping, and PREROUTING DNS REDIRECT rules across BOTH `iptables`
     * and `iptables-legacy` (preventing WSL2 / Docker Desktop / UFW split-brain packet drops).
     */
    ensureBridgeNetworkReady(bridgeName: string): Promise<LxcBridgeNetworkInfo>;
    /**
     * Allocates a deterministic, collision-free IPv4 address from the bridge subnet when
     * no DHCP daemon (e.g. `dnsmasq`) is running on the bridge.
     */
    allocateAutoBridgeIpv4(containerName: string, bridgeName: string, bridgeIp: string, prefixLen?: number): Promise<string | null>;
    private resolveConfinedRootfsDir;
    /**
     * Configures guest DNS (`/etc/resolv.conf` + `systemd-resolved` drop-in) and guest
     * network manager config (`netplan`, `systemd-networkd`, `ifupdown`) strictly inside
     * the confined container rootfs so guest boot daemons never wipe liblxc's assigned IPv4
     * or point `/etc/resolv.conf` at a dead `127.0.0.53` stub.
     */
    configureGuestNetworkingAndDns(containerName: string, opts?: {
        ipv4Cidr?: string | null;
        gateway?: string | null;
        useDhcp?: boolean;
        dnsServers?: string[];
    }): string[];
    listContainers(): Promise<LxcContainerRuntimeInfo[]>;
    private readContainerNetFromConfig;
    inspectContainer(containerName: string): Promise<LxcContainerRuntimeInfo>;
    /**
     * Fallback live memory (VmRSS) & CPU time aggregator across `<initPid>` and all its
     * descendant processes in `/proc` for hosts (e.g. WSL2 / un-delegated cgroup v2) where
     * `lxc-info` does not emit `Memory use:` / `CPU use:`.
     */
    private measureContainerProcTree;
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
        kvmNesting?: boolean;
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
    private buildEffectiveGuestDnsList;
    private prepareContainerNetworkPreStart;
    /**
     * Ensures a running container's host-side `veth` peer is enslaved to `bridge` and `UP`
     * (recovers containers whose bridge was recreated or bounced while the container stayed running).
     */
    private ensureRunningVethAttachedToBridge;
    private applyLiveGuestNetworkIfNeeded;
    /**
     * Repairs host bridge/NAT/FORWARD/DNS-relay rules, upgrades `lxc.net.0.type = none` if needed,
     * auto-assigns a collision-free IPv4 if the container lacks one, re-enslaves orphaned host
     * `veth` peers (or restarts the container if `eth0` was never created), and applies IP/route/DNS
     * live inside the guest.
     */
    repairContainerNetworking(containerName: string, fallbackBridge?: string): Promise<LxcNetworkRepairResult>;
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
