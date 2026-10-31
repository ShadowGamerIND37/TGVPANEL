import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  canPasswordlessSudo,
  ensureLxcfsDaemonMounted,
  findActiveMountSource,
  isBinaryAvailable,
  isRunningAsRoot,
  privilegedFs,
  runAllowlistedCommand,
} from './command-runner';
import { getSharedBridgeDnsRelay } from './dns-relay';
import { SafeValidators } from '../security/middleware';

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
  backingStore?: 'dir' | 'loop' | 'lvm' | 'zfs' | 'btrfs';
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
  mounts?: Array<{ hostSource: string; guestTarget: string; readOnly?: boolean }>;
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
  backingStore?: string;
  diskQuotaEnforced?: boolean;
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

export function ipv4ToUint32(ip: string): number {
  const parts = ip.trim().split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return 0;
  }
  return (((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0);
}

export function uint32ToIpv4(num: number): string {
  const u = num >>> 0;
  return `${(u >>> 24) & 255}.${(u >>> 16) & 255}.${(u >>> 8) & 255}.${u & 255}`;
}

export function prefixLenToNetmask(prefixLen: number): string {
  const p = Math.min(32, Math.max(0, Math.floor(prefixLen)));
  const mask = p === 0 ? 0 : ((0xffffffff << (32 - p)) >>> 0);
  return uint32ToIpv4(mask);
}

export function computeIpv4SubnetCidr(ip: string, prefixLen = 24): string | null {
  const u = ipv4ToUint32(ip);
  if (!u) return null;
  const p = Math.min(32, Math.max(8, Math.floor(prefixLen)));
  const mask = (0xffffffff << (32 - p)) >>> 0;
  const net = (u & mask) >>> 0;
  return `${uint32ToIpv4(net)}/${p}`;
}

function isPrivateRfc1918Ipv4(ip: string): boolean {
  const parts = ip.trim().split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  return false;
}

/**
 * Resolves up to 3 reliable upstream IPv4 DNS servers suitable for inside an LXC container
 * (respecting glibc MAXNS=3 while filtering out host loopback 127.0.0.53 and WSL2's
 * non-bridge-routable 10.255.255.254 tunnel listener).
 */
export function resolveGuestDnsServers(hostResolvConfContent?: string): string[] {
  const envDns = (process.env.HKVM_LXC_DNS || '').trim();
  if (envDns) {
    const custom = envDns
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter((s) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s));
    if (custom.length > 0) return custom.slice(0, 3);
  }

  const hostCandidates: string[] = [];
  try {
    const raw =
      hostResolvConfContent !== undefined
        ? hostResolvConfContent
        : fs.existsSync('/etc/resolv.conf')
        ? fs.readFileSync('/etc/resolv.conf', 'utf8')
        : '';
    for (const line of raw.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const m = trimmed.match(/^nameserver\s+(\d{1,3}(?:\.\d{1,3}){3})\b/i);
      if (!m) continue;
      const ns = m[1];
      if (
        ns.startsWith('127.') ||
        ns.startsWith('0.') ||
        ns.startsWith('169.254.') ||
        ns === '10.255.255.254'
      ) {
        continue;
      }
      if (!hostCandidates.includes(ns)) hostCandidates.push(ns);
    }
  } catch {
    // ignore host /etc/resolv.conf read errors
  }

  const ordered: string[] = ['1.1.1.1', '8.8.8.8'];
  for (const h of hostCandidates) {
    if (!ordered.includes(h)) ordered.push(h);
  }
  if (ordered.length < 3 && !ordered.includes('1.0.0.1')) {
    ordered.push('1.0.0.1');
  }
  return ordered.slice(0, 3);
}

const DEFAULT_LXC_BASE = process.env.HKVM_LXC_PATH || '/var/lib/lxc';

const UBUNTU_RELEASE_MAP: Record<string, string> = {
  '18.04': 'bionic',
  '20.04': 'focal',
  '22.04': 'jammy',
  '24.04': 'noble',
  '24.10': 'oracular',
  '25.04': 'plucky',
  '25.10': 'questing',
  '26.04': 'resolute',
};

const DEBIAN_RELEASE_MAP: Record<string, string> = {
  '10': 'buster',
  '11': 'bullseye',
  '12': 'bookworm',
  '13': 'trixie',
  '14': 'forky',
};

const DEVUAN_RELEASE_MAP: Record<string, string> = {
  '4': 'chimaera',
  '5': 'daedalus',
};

/**
 * Translates human/LXD version identifiers (e.g. `ubuntu` + `24.04` or `debian` + `12`)
 * into canonical `images.linuxcontainers.org` release names expected by `lxc-create -t download`
 * (`noble`, `bookworm`, `current`, etc.), while retaining fallbacks.
 */
export function resolveDownloadReleaseCandidates(
  rawDistro: string,
  rawRelease: string,
  fallbackRelease?: string | null
): { distro: string; releases: string[]; archMapper: (arch: string) => string } {
  const distro = rawDistro.toLowerCase().replace(/[^a-z0-9_.-]/g, '') || 'ubuntu';
  const cleanRel = rawRelease.replace(/[^a-zA-Z0-9_.-]/g, '');
  const candidates: string[] = [];

  const pushUnique = (val?: string | null) => {
    if (!val) return;
    const cleaned = val.replace(/[^a-zA-Z0-9_.-]/g, '');
    if (cleaned && !candidates.includes(cleaned)) {
      candidates.push(cleaned);
    }
  };

  if (distro === 'ubuntu') {
    if (UBUNTU_RELEASE_MAP[cleanRel]) {
      pushUnique(UBUNTU_RELEASE_MAP[cleanRel]);
    }
    pushUnique(cleanRel);
    for (const [ver, codename] of Object.entries(UBUNTU_RELEASE_MAP)) {
      if (codename === cleanRel.toLowerCase()) pushUnique(ver);
    }
  } else if (distro === 'debian') {
    if (DEBIAN_RELEASE_MAP[cleanRel]) {
      pushUnique(DEBIAN_RELEASE_MAP[cleanRel]);
    }
    pushUnique(cleanRel);
    for (const [ver, codename] of Object.entries(DEBIAN_RELEASE_MAP)) {
      if (codename === cleanRel.toLowerCase()) pushUnique(ver);
    }
  } else if (distro === 'devuan') {
    if (DEVUAN_RELEASE_MAP[cleanRel]) {
      pushUnique(DEVUAN_RELEASE_MAP[cleanRel]);
    }
    pushUnique(cleanRel);
  } else if (
    distro === 'kali' ||
    distro === 'archlinux' ||
    distro === 'voidlinux' ||
    distro === 'gentoo'
  ) {
    if (!cleanRel || cleanRel.toLowerCase() === 'rolling' || cleanRel.toLowerCase() === 'latest') {
      pushUnique('current');
    }
    pushUnique(cleanRel);
    pushUnique('current');
  } else if (distro === 'centos') {
    if (/^\d+$/.test(cleanRel)) {
      pushUnique(`${cleanRel}-Stream`);
    }
    pushUnique(cleanRel);
  } else {
    pushUnique(cleanRel);
  }

  if (fallbackRelease) {
    const fb = fallbackRelease.replace(/^images:[^/:]+[:/]/i, '');
    if (distro === 'ubuntu' && UBUNTU_RELEASE_MAP[fb]) pushUnique(UBUNTU_RELEASE_MAP[fb]);
    if (distro === 'debian' && DEBIAN_RELEASE_MAP[fb]) pushUnique(DEBIAN_RELEASE_MAP[fb]);
    pushUnique(fb);
  }

  if (candidates.length === 0) {
    candidates.push(distro === 'ubuntu' ? 'noble' : distro === 'debian' ? 'bookworm' : 'current');
  }

  return {
    distro,
    releases: candidates,
    archMapper: (rawArch: string) => {
      const a = (rawArch || 'amd64').toLowerCase().replace(/[^a-z0-9_.-]/g, '');
      if (a === 'x86_64' || a === 'x64') return 'amd64';
      if (a === 'aarch64') return 'arm64';
      return a || 'amd64';
    },
  };
}

export function isAppArmorProfileLoadable(): boolean {
  try {
    if (!fs.existsSync('/sys/module/apparmor/parameters/enabled')) {
      return false;
    }
    const enabled = fs.readFileSync('/sys/module/apparmor/parameters/enabled', 'utf8').trim();
    if (enabled !== 'Y' && enabled !== '1') {
      return false;
    }
    return privilegedFs.existsSync('/sys/kernel/security/apparmor/.load');
  } catch {
    return false;
  }
}

/**
 * Parses Linux CPU list syntax (e.g. `"0-3"`, `"0,2-3,6"`) into sorted unique CPU IDs.
 */
export function parseCpuListSpec(spec: string): number[] {
  const cpus = new Set<number>();
  for (const part of String(spec || '').trim().split(',')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const rangeMatch = trimmed.match(/^(\d+)-(\d+)$/);
    if (rangeMatch) {
      const start = parseInt(rangeMatch[1], 10);
      const end = parseInt(rangeMatch[2], 10);
      if (end >= start && end - start <= 1024) {
        for (let i = start; i <= end; i++) cpus.add(i);
      }
    } else if (/^\d+$/.test(trimmed)) {
      cpus.add(parseInt(trimmed, 10));
    }
  }
  return Array.from(cpus).sort((a, b) => a - b);
}

export function readEffectiveHostCpuIds(): number[] {
  try {
    for (const p of ['/sys/fs/cgroup/cpuset.cpus.effective', '/sys/fs/cgroup/cpuset/cpuset.cpus']) {
      if (fs.existsSync(p)) {
        const parsed = parseCpuListSpec(fs.readFileSync(p, 'utf8'));
        if (parsed.length > 0) return parsed;
      }
    }
  } catch {
    // fallback to os.cpus()
  }
  const n = Math.max(1, os.cpus().length || 1);
  return Array.from({ length: n }, (_, idx) => idx);
}

/**
 * Deterministically assigns `requestedCores` distinct online host CPUs to `containerName`
 * (or honors `explicitPinning`), ensuring `nproc`, `lscpu`, and `neofetch` inside the guest
 * report the container's assigned vCPU count while spreading load across host cores.
 */
export function selectContainerCpuset(
  containerName: string,
  requestedCores: number,
  availableCpus: number[] = readEffectiveHostCpuIds(),
  explicitPinning?: string | null
): string | null {
  if (explicitPinning && /^[0-9,-]+$/.test(explicitPinning.trim())) {
    return explicitPinning.trim();
  }
  if (!availableCpus || availableCpus.length === 0) return null;
  const count = Math.max(1, Math.min(availableCpus.length, Math.floor(requestedCores || 1)));
  let hash = 2166136261;
  for (let i = 0; i < containerName.length; i++) {
    hash ^= containerName.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  const start = (hash >>> 0) % availableCpus.length;
  const picked: number[] = [];
  for (let i = 0; i < count; i++) {
    picked.push(availableCpus[(start + i) % availableCpus.length]);
  }
  picked.sort((a, b) => a - b);
  return picked.join(',');
}

/**
 * Ensures cgroup v2 `cpu`, `cpuset`, `memory`, and `pids` controllers are delegated in
 * `/sys/fs/cgroup/cgroup.subtree_control`. On Docker / GitHub Codespace cgroup roots where
 * PID 1 sits directly in `/sys/fs/cgroup/cgroup.procs` ("no internal processes" rule -> EBUSY),
 * safely evacuates root processes into `/sys/fs/cgroup/hkvm.host` first.
 */
function ensureCgroupV2SubtreeDelegation(): void {
  try {
    if (
      !fs.existsSync('/sys/fs/cgroup/cgroup.controllers') ||
      !fs.existsSync('/sys/fs/cgroup/cgroup.subtree_control')
    ) {
      return;
    }
    if (!isRunningAsRoot() && !canPasswordlessSudo()) return;

    const rootControllers = new Set(
      fs.readFileSync('/sys/fs/cgroup/cgroup.controllers', 'utf8').trim().split(/\s+/).filter(Boolean)
    );
    const readDelegated = () =>
      new Set(
        fs
          .readFileSync('/sys/fs/cgroup/cgroup.subtree_control', 'utf8')
          .trim()
          .split(/\s+/)
          .filter(Boolean)
      );

    const desired = ['cpu', 'cpuset', 'memory', 'pids'].filter((c) => rootControllers.has(c));
    let delegated = readDelegated();
    let missing = desired.filter((c) => !delegated.has(c));
    if (missing.length === 0) return;

    const enableControllers = (ctrls: string[]) => {
      for (const c of ctrls) {
        try {
          privilegedFs.writeFileSync('/sys/fs/cgroup/cgroup.subtree_control', `+${c}`);
        } catch {
          // ignore individual controller failure
        }
      }
    };

    enableControllers(missing);
    delegated = readDelegated();
    missing = desired.filter((c) => !delegated.has(c));
    if (missing.length === 0) return;

    // EBUSY inside container cgroup root: evacuate internal processes into /sys/fs/cgroup/hkvm.host
    const leafCgroup = '/sys/fs/cgroup/hkvm.host';
    privilegedFs.mkdirpSync(leafCgroup);
    const procsRaw = fs.readFileSync('/sys/fs/cgroup/cgroup.procs', 'utf8');
    for (const pidLine of procsRaw.split('\n')) {
      const pid = pidLine.trim();
      if (!/^\d+$/.test(pid) || pid === '0') continue;
      try {
        privilegedFs.writeFileSync(path.join(leafCgroup, 'cgroup.procs'), `${pid}\n`);
      } catch {
        // kernel thread or exited process
      }
    }
    enableControllers(missing);
  } catch {
    // non-fatal on read-only cgroupfs
  }
}

function readActiveCgroupV2Controllers(enableIfSystem = false): Set<string> | null {
  try {
    if (!fs.existsSync('/sys/fs/cgroup/cgroup.controllers')) {
      return null;
    }
    if (enableIfSystem) {
      ensureCgroupV2SubtreeDelegation();
    }
    const raw = fs.readFileSync('/sys/fs/cgroup/cgroup.controllers', 'utf8').trim();
    const rootControllers = new Set(raw.split(/\s+/).filter(Boolean));
    if (fs.existsSync('/sys/fs/cgroup/cgroup.subtree_control')) {
      const subRaw = fs.readFileSync('/sys/fs/cgroup/cgroup.subtree_control', 'utf8').trim();
      const delegated = new Set(subRaw.split(/\s+/).filter(Boolean));
      // On WSL2 / nested container hosts where root subtree_control has not delegated controllers,
      // writing lxc.cgroup2.<ctrl>.* causes lxc-start to fail with ENOENT on child cgroup files.
      return new Set([...rootControllers].filter((c) => delegated.has(c)));
    }
    return rootControllers;
  } catch {
    return null;
  }
}

function isCgroupV2SwapSupported(): boolean {
  if (
    fs.existsSync('/sys/fs/cgroup/memory.swap.max') ||
    fs.existsSync('/sys/fs/cgroup/init.scope/memory.swap.max') ||
    fs.existsSync('/sys/fs/cgroup/system.slice/memory.swap.max') ||
    fs.existsSync('/sys/fs/cgroup/hkvm.host/memory.swap.max')
  ) {
    return true;
  }
  try {
    for (const entry of fs.readdirSync('/sys/fs/cgroup')) {
      if (fs.existsSync(path.join('/sys/fs/cgroup', entry, 'memory.swap.max'))) {
        return true;
      }
    }
  } catch {
    // ignore
  }
  return false;
}

export class LxcContainerManager {
  private lxcBaseDir: string;
  private inFlightCreations = new Set<string>();

  constructor(lxcBaseDir = DEFAULT_LXC_BASE) {
    this.lxcBaseDir = path.resolve(lxcBaseDir);
  }

  public isCreationInFlight(containerName: string): boolean {
    const safeName = SafeValidators.containerName(containerName);
    return this.inFlightCreations.has(safeName.toLowerCase());
  }

  public getBaseDir(): string {
    return this.lxcBaseDir;
  }

  public getContainerDir(containerName: string): string {
    const safeName = SafeValidators.containerName(containerName);
    return path.join(this.lxcBaseDir, safeName);
  }

  public getRootfsDir(containerName: string): string {
    return path.join(this.getContainerDir(containerName), 'rootfs');
  }

  /**
   * Determines whether operations against `this.lxcBaseDir` require root (`sudo -n`).
   * System `/var/lib/lxc` requires root, whereas unprivileged temporary directories in tests do not.
   */
  public needsRootForStore(): boolean {
    if (isRunningAsRoot()) return false;
    if (this.lxcBaseDir === '/var/lib/lxc' || this.lxcBaseDir.startsWith('/var/lib/lxc/')) {
      return true;
    }
    try {
      if (fs.existsSync(this.lxcBaseDir)) {
        fs.accessSync(this.lxcBaseDir, fs.constants.R_OK | fs.constants.W_OK | fs.constants.X_OK);
        return false;
      }
      const parent = path.dirname(this.lxcBaseDir);
      fs.accessSync(parent, fs.constants.R_OK | fs.constants.W_OK | fs.constants.X_OK);
      return false;
    } catch {
      return true;
    }
  }

  private lxcPathArgs(): string[] {
    return ['-P', this.lxcBaseDir];
  }

  private assertLxcInstalled(): void {
    if (!isBinaryAvailable('lxc-info') || !isBinaryAvailable('lxc-create')) {
      throw new Error(
        'LXC userland utilities (lxc-create / lxc-start / lxc-info) are not installed on this host.'
      );
    }
  }

  private ensureHostLxcDirectories(): void {
    privilegedFs.mkdirpSync(this.lxcBaseDir, 0o755);
    if (this.lxcBaseDir === '/var/lib/lxc') {
      try {
        privilegedFs.mkdirpSync('/var/cache/lxc', 0o755);
        privilegedFs.mkdirpSync('/var/log/lxc', 0o755);
      } catch {
        // non-fatal if /var/log/lxc cannot be created
      }
    }
  }

  private isSystemLxcStore(): boolean {
    return this.lxcBaseDir === '/var/lib/lxc' || this.lxcBaseDir.startsWith('/var/lib/lxc/');
  }

  private bridgeHasPhysicalSlave(safeBridge: string): boolean {
    try {
      const brifDir = `/sys/class/net/${safeBridge}/brif`;
      if (!fs.existsSync(brifDir)) return false;
      for (const iface of fs.readdirSync(brifDir)) {
        if (fs.existsSync(`/sys/class/net/${iface}/device`)) {
          return true;
        }
      }
      return false;
    } catch {
      return false;
    }
  }

  private detectBridgeDhcpServer(safeBridge: string): boolean {
    try {
      for (const pidFile of ['/run/lxc/dnsmasq.pid', '/var/run/lxc/dnsmasq.pid']) {
        if (safeBridge === 'lxcbr0' && fs.existsSync(pidFile)) {
          const p = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
          if (p > 0 && fs.existsSync(`/proc/${p}`)) return true;
        }
      }
      if (!fs.existsSync('/proc')) return false;
      for (const ent of fs.readdirSync('/proc')) {
        if (!/^\d+$/.test(ent)) continue;
        try {
          const cmd = fs.readFileSync(`/proc/${ent}/cmdline`, 'utf8').replace(/\0/g, ' ');
          if (
            /(dnsmasq|dhcpd|kea-dhcp4|udhcpd)/i.test(cmd) &&
            (cmd.includes(safeBridge) || (safeBridge === 'lxcbr0' && cmd.includes('lxc')))
          ) {
            return true;
          }
        } catch {
          // ignore exited proc
        }
      }
      return false;
    } catch {
      return false;
    }
  }

  private async ensureIptablesRule(
    bin: 'iptables' | 'iptables-legacy',
    table: 'filter' | 'nat' | 'mangle',
    chain: string,
    ruleArgs: string[],
    insertTop = true
  ): Promise<boolean> {
    const tblArgs = table === 'filter' ? [] : ['-t', table];
    const check = await runAllowlistedCommand(
      bin,
      [...tblArgs, '-C', chain, ...ruleArgs],
      { timeoutMs: 4000, asRoot: true }
    );
    if (check.exitCode === 0) return true;
    const addArgs = insertTop
      ? [...tblArgs, '-I', chain, '1', ...ruleArgs]
      : [...tblArgs, '-A', chain, ...ruleArgs];
    const add = await runAllowlistedCommand(bin, addArgs, { timeoutMs: 4000, asRoot: true });
    return add.exitCode === 0;
  }

  /**
   * Ensures the Linux bridge exists, is UP, has an IPv4 gateway address (when operating as
   * a virtual NAT bridge such as `lxcbr0`), starts HKVM's host-side `BridgeDnsRelay`, enables
   * kernel forwarding/rp_filter sysctls, and installs idempotent MASQUERADE, FORWARD ACCEPT,
   * INPUT ACCEPT, TCPMSS clamping, and PREROUTING DNS REDIRECT rules across BOTH `iptables`
   * and `iptables-legacy` (preventing WSL2 / Docker Desktop / UFW split-brain packet drops).
   */
  public async ensureBridgeNetworkReady(bridgeName: string): Promise<LxcBridgeNetworkInfo> {
    const safeBridge = SafeValidators.bridgeOrIface(bridgeName);
    if (!isBinaryAvailable('ip')) {
      return {
        ready: fs.existsSync(`/sys/class/net/${safeBridge}`),
        bridgeIp: null,
        prefixLen: 24,
        subnetCidr: null,
        hasDhcpServer: this.detectBridgeDhcpServer(safeBridge),
        natConfigured: false,
        dnsRelayPort: 0,
      };
    }

    if (!fs.existsSync(`/sys/class/net/${safeBridge}`)) {
      await runAllowlistedCommand('ip', ['link', 'add', 'name', safeBridge, 'type', 'bridge'], {
        timeoutMs: 5000,
        asRoot: true,
      });
    }

    if (!fs.existsSync(`/sys/class/net/${safeBridge}`)) {
      return {
        ready: false,
        bridgeIp: null,
        prefixLen: 24,
        subnetCidr: null,
        hasDhcpServer: false,
        natConfigured: false,
        dnsRelayPort: 0,
      };
    }

    await runAllowlistedCommand('ip', ['link', 'set', safeBridge, 'up'], {
      timeoutMs: 5000,
      asRoot: true,
    });

    let bridgeIp: string | null = null;
    let prefixLen = 24;
    const addrRes = await runAllowlistedCommand(
      'ip',
      ['-4', '-o', 'addr', 'show', 'dev', safeBridge],
      { timeoutMs: 5000, asRoot: true }
    );
    const addrMatch = addrRes.stdout.match(/\binet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)\b/);
    if (addrMatch) {
      bridgeIp = addrMatch[1];
      prefixLen = parseInt(addrMatch[2], 10) || 24;
    }

    const isVirtualNatBridge = !this.bridgeHasPhysicalSlave(safeBridge);

    if (!bridgeIp && isVirtualNatBridge) {
      const routeRes = await runAllowlistedCommand('ip', ['-4', 'route', 'show'], {
        timeoutMs: 5000,
      });
      const routesText = routeRes.stdout || '';
      const gatewayCandidates = ['10.0.3.1', '10.88.3.1', '10.99.3.1', '172.29.3.1'];
      let chosenGw = '10.0.3.1';
      for (const cand of gatewayCandidates) {
        const prefix3 = cand.split('.').slice(0, 3).join('.') + '.';
        if (!routesText.includes(prefix3)) {
          chosenGw = cand;
          break;
        }
      }
      const assignRes = await runAllowlistedCommand(
        'ip',
        ['addr', 'add', `${chosenGw}/24`, 'dev', safeBridge],
        { timeoutMs: 5000, asRoot: true }
      );
      if (assignRes.exitCode === 0 || /File exists/i.test(assignRes.stderr)) {
        bridgeIp = chosenGw;
        prefixLen = 24;
      }
    }

    const subnetCidr = bridgeIp ? computeIpv4SubnetCidr(bridgeIp, prefixLen) : null;
    let natConfigured = false;
    let dnsRelayPort = 0;

    if (bridgeIp && subnetCidr && isVirtualNatBridge && isPrivateRfc1918Ipv4(bridgeIp)) {
      const dnsRelay = getSharedBridgeDnsRelay();
      dnsRelay.addExcludedLoopIp(bridgeIp);
      dnsRelayPort = await dnsRelay.ensureStarted().catch(() => 0);

      if (isBinaryAvailable('modprobe')) {
        for (const mod of ['iptable_nat', 'nf_nat', 'xt_MASQUERADE', 'xt_REDIRECT', 'xt_TCPMSS']) {
          await runAllowlistedCommand('modprobe', [mod], {
            timeoutMs: 3000,
            asRoot: true,
          }).catch(() => undefined);
        }
      }

      if (isBinaryAvailable('sysctl')) {
        const sysctlKeys = [
          'net.ipv4.ip_forward=1',
          'net.ipv4.conf.all.forwarding=1',
          'net.ipv4.conf.default.forwarding=1',
          `net.ipv4.conf.${safeBridge}.forwarding=1`,
          `net.ipv4.conf.${safeBridge}.rp_filter=0`,
          'net.ipv4.conf.all.rp_filter=0',
        ];
        for (const kv of sysctlKeys) {
          await runAllowlistedCommand('sysctl', ['-w', kv], {
            timeoutMs: 3000,
            asRoot: true,
          }).catch(() => undefined);
        }
      }

      // Program BOTH iptables (often iptables-nft) AND iptables-legacy if present on host:
      // on WSL2 + Docker Desktop / Ubuntu, Docker frequently sets `FORWARD DROP` in
      // iptables-legacy while `/usr/sbin/iptables` points to iptables-nft!
      const iptBins: Array<'iptables' | 'iptables-legacy'> = [];
      if (isBinaryAvailable('iptables')) iptBins.push('iptables');
      if (isBinaryAvailable('iptables-legacy')) iptBins.push('iptables-legacy');

      for (const bin of iptBins) {
        const masqOk = await this.ensureIptablesRule(
          bin,
          'nat',
          'POSTROUTING',
          ['-s', subnetCidr, '!', '-d', subnetCidr, '-j', 'MASQUERADE'],
          true
        );
        if (masqOk) natConfigured = true;

        // Top-of-chain FORWARD ACCEPT by both bridge device AND container CIDR (handles br_netfilter)
        await this.ensureIptablesRule(bin, 'filter', 'FORWARD', ['-i', safeBridge, '-j', 'ACCEPT'], true);
        await this.ensureIptablesRule(bin, 'filter', 'FORWARD', ['-o', safeBridge, '-j', 'ACCEPT'], true);
        await this.ensureIptablesRule(bin, 'filter', 'FORWARD', ['-s', subnetCidr, '-j', 'ACCEPT'], true);
        await this.ensureIptablesRule(bin, 'filter', 'FORWARD', ['-d', subnetCidr, '-j', 'ACCEPT'], true);

        // Clamp TCP MSS to path MTU (prevents `apt update` hanging at 0% [Working] on WSL2/PPPoE/Hotspot!)
        await this.ensureIptablesRule(
          bin,
          'mangle',
          'FORWARD',
          ['-i', safeBridge, '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--clamp-mss-to-pmtu'],
          true
        );
        await this.ensureIptablesRule(
          bin,
          'mangle',
          'FORWARD',
          ['-o', safeBridge, '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--clamp-mss-to-pmtu'],
          true
        );

        // Allow DHCP (67/68) and DNS (53 + dnsRelayPort) through host INPUT chain (UFW / INPUT DROP hosts)
        await this.ensureIptablesRule(bin, 'filter', 'INPUT', ['-i', safeBridge, '-p', 'udp', '--dport', '67', '-j', 'ACCEPT'], true);
        await this.ensureIptablesRule(bin, 'filter', 'INPUT', ['-s', subnetCidr, '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'], true);
        await this.ensureIptablesRule(bin, 'filter', 'INPUT', ['-s', subnetCidr, '-p', 'tcp', '--dport', '53', '-j', 'ACCEPT'], true);

        if (dnsRelayPort > 0) {
          await this.ensureIptablesRule(
            bin,
            'filter',
            'INPUT',
            ['-s', subnetCidr, '-p', 'udp', '--dport', String(dnsRelayPort), '-j', 'ACCEPT'],
            true
          );
          await this.ensureIptablesRule(
            bin,
            'filter',
            'INPUT',
            ['-s', subnetCidr, '-p', 'tcp', '--dport', String(dnsRelayPort), '-j', 'ACCEPT'],
            true
          );
          await this.ensureIptablesRule(
            bin,
            'nat',
            'PREROUTING',
            ['-s', subnetCidr, '-d', bridgeIp, '-p', 'udp', '--dport', '53', '-j', 'REDIRECT', '--to-ports', String(dnsRelayPort)],
            true
          );
          await this.ensureIptablesRule(
            bin,
            'nat',
            'PREROUTING',
            ['-s', subnetCidr, '-d', bridgeIp, '-p', 'tcp', '--dport', '53', '-j', 'REDIRECT', '--to-ports', String(dnsRelayPort)],
            true
          );
        }
      }

      if (!natConfigured && isBinaryAvailable('nft')) {
        await runAllowlistedCommand('nft', ['add', 'table', 'ip', 'hkvm_lxc_nat'], {
          timeoutMs: 5000,
          asRoot: true,
        });
        await runAllowlistedCommand(
          'nft',
          [
            'add',
            'chain',
            'ip',
            'hkvm_lxc_nat',
            'postrouting',
            '{ type nat hook postrouting priority 100 ; }',
          ],
          { timeoutMs: 5000, asRoot: true }
        );
        await runAllowlistedCommand('nft', ['flush', 'chain', 'ip', 'hkvm_lxc_nat', 'postrouting'], {
          timeoutMs: 5000,
          asRoot: true,
        });
        const nftMasq = await runAllowlistedCommand(
          'nft',
          [
            'add',
            'rule',
            'ip',
            'hkvm_lxc_nat',
            'postrouting',
            'ip',
            'saddr',
            subnetCidr,
            'ip',
            'daddr',
            '!=',
            subnetCidr,
            'masquerade',
          ],
          { timeoutMs: 5000, asRoot: true }
        );
        await runAllowlistedCommand(
          'nft',
          [
            'add',
            'chain',
            'ip',
            'hkvm_lxc_nat',
            'forward',
            '{ type filter hook forward priority -10 ; policy accept ; }',
          ],
          { timeoutMs: 5000, asRoot: true }
        );
        if (dnsRelayPort > 0) {
          await runAllowlistedCommand(
            'nft',
            [
              'add',
              'chain',
              'ip',
              'hkvm_lxc_nat',
              'prerouting',
              '{ type nat hook prerouting priority -100 ; }',
            ],
            { timeoutMs: 5000, asRoot: true }
          );
          await runAllowlistedCommand('nft', ['flush', 'chain', 'ip', 'hkvm_lxc_nat', 'prerouting'], {
            timeoutMs: 5000,
            asRoot: true,
          });
          await runAllowlistedCommand(
            'nft',
            [
              'add',
              'rule',
              'ip',
              'hkvm_lxc_nat',
              'prerouting',
              'ip',
              'saddr',
              subnetCidr,
              'ip',
              'daddr',
              bridgeIp,
              'udp',
              'dport',
              '53',
              'redirect',
              'to',
              `:${dnsRelayPort}`,
            ],
            { timeoutMs: 5000, asRoot: true }
          );
          await runAllowlistedCommand(
            'nft',
            [
              'add',
              'rule',
              'ip',
              'hkvm_lxc_nat',
              'prerouting',
              'ip',
              'saddr',
              subnetCidr,
              'ip',
              'daddr',
              bridgeIp,
              'tcp',
              'dport',
              '53',
              'redirect',
              'to',
              `:${dnsRelayPort}`,
            ],
            { timeoutMs: 5000, asRoot: true }
          );
        }
        natConfigured = nftMasq.exitCode === 0;
      }
    }

    return {
      ready: true,
      bridgeIp,
      prefixLen,
      subnetCidr,
      hasDhcpServer: this.detectBridgeDhcpServer(safeBridge),
      natConfigured,
      dnsRelayPort,
    };
  }

  /**
   * Allocates a deterministic, collision-free IPv4 address from the bridge subnet when
   * no DHCP daemon (e.g. `dnsmasq`) is running on the bridge.
   */
  public async allocateAutoBridgeIpv4(
    containerName: string,
    bridgeName: string,
    bridgeIp: string,
    prefixLen = 24
  ): Promise<string | null> {
    const safeName = SafeValidators.containerName(containerName);
    const gwUint = ipv4ToUint32(bridgeIp);
    if (!gwUint || prefixLen < 16 || prefixLen > 29) return null;

    const mask = (0xffffffff << (32 - prefixLen)) >>> 0;
    const netBase = (gwUint & mask) >>> 0;
    const hostCount = (1 << (32 - prefixLen)) - 2;
    if (hostCount < 4) return null;

    const usedIps = new Set<string>([bridgeIp]);

    // Scan existing container configs in lxcBaseDir
    try {
      if (privilegedFs.existsSync(this.lxcBaseDir)) {
        for (const dirName of privilegedFs.readdirNamesSync(this.lxcBaseDir)) {
          const cfgPath = path.join(this.lxcBaseDir, dirName, 'config');
          if (!privilegedFs.existsSync(cfgPath)) continue;
          try {
            const txt = privilegedFs.readTextSync(cfgPath);
            const m = txt.match(/^\s*lxc\.net\.0\.ipv4\.address\s*=\s*(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?/m);
            if (!m) continue;
            const ipOnly = m[1];
            if (dirName === safeName) {
              const candNet = (ipv4ToUint32(ipOnly) & mask) >>> 0;
              if (candNet === netBase && ipOnly !== bridgeIp) {
                return `${ipOnly}/${prefixLen}`;
              }
            } else {
              usedIps.add(ipOnly);
            }
          } catch {
            // ignore unreadable config
          }
        }
      }
    } catch {
      // ignore scan failure
    }

    // Also avoid any active ARP neighbors on the bridge
    if (isBinaryAvailable('ip') && this.isSystemLxcStore()) {
      const neighRes = await runAllowlistedCommand(
        'ip',
        ['-4', 'neigh', 'show', 'dev', SafeValidators.bridgeOrIface(bridgeName)],
        { timeoutMs: 4000 }
      ).catch(() => null);
      if (neighRes && neighRes.stdout) {
        for (const line of neighRes.stdout.split('\n')) {
          const m = line.trim().match(/^(\d+\.\d+\.\d+\.\d+)\b/);
          if (m) usedIps.add(m[1]);
        }
      }
    }

    const minHost = Math.min(100, Math.max(2, Math.floor(hostCount / 4)));
    const maxHost = Math.min(hostCount, 250);
    const poolSize = Math.max(1, maxHost - minHost + 1);

    let hash = 0;
    for (let i = 0; i < safeName.length; i++) {
      hash = (hash * 31 + safeName.charCodeAt(i)) >>> 0;
    }

    for (let i = 0; i < poolSize; i++) {
      const hostOffset = minHost + ((hash + i) % poolSize);
      const candidateIp = uint32ToIpv4((netBase + hostOffset) >>> 0);
      if (!usedIps.has(candidateIp)) {
        return `${candidateIp}/${prefixLen}`;
      }
    }

    for (let hostOffset = 2; hostOffset <= hostCount; hostOffset++) {
      const candidateIp = uint32ToIpv4((netBase + hostOffset) >>> 0);
      if (!usedIps.has(candidateIp)) {
        return `${candidateIp}/${prefixLen}`;
      }
    }

    return null;
  }

  private resolveConfinedRootfsDir(containerName: string, relDir: string, createIfMissing = false): string | null {
    const rootfs = path.resolve(this.getRootfsDir(containerName));
    if (!privilegedFs.existsSync(rootfs)) return null;
    const segments = relDir.split('/').filter(Boolean);
    let cur = rootfs;
    for (const seg of segments) {
      const next = path.join(cur, seg);
      if (!next.startsWith(rootfs + path.sep)) return null;
      if (privilegedFs.existsSync(next)) {
        const meta = privilegedFs.lstatMetaSync(next);
        if (meta.isSymbolicLink || !meta.isDirectory) {
          return null;
        }
      } else if (createIfMissing) {
        privilegedFs.mkdirpSync(next, 0o755);
      } else {
        return null;
      }
      cur = next;
    }
    return cur;
  }

  /**
   * Configures guest DNS (`/etc/resolv.conf` + `systemd-resolved` drop-in) and guest
   * network manager config (`netplan`, `systemd-networkd`, `ifupdown`) strictly inside
   * the confined container rootfs so guest boot daemons never wipe liblxc's assigned IPv4
   * or point `/etc/resolv.conf` at a dead `127.0.0.53` stub.
   */
  public configureGuestNetworkingAndDns(
    containerName: string,
    opts: {
      ipv4Cidr?: string | null;
      gateway?: string | null;
      useDhcp?: boolean;
      dnsServers?: string[];
    } = {}
  ): string[] {
    const safeName = SafeValidators.containerName(containerName);
    const dnsList = (opts.dnsServers && opts.dnsServers.length > 0
      ? opts.dnsServers
      : resolveGuestDnsServers()
    ).slice(0, 3);

    const etcDir = this.resolveConfinedRootfsDir(safeName, 'etc', false);
    if (!etcDir) return dnsList;

    // 1. Replace broken/dangling symlink /etc/resolv.conf with real regular file
    try {
      const resolvPath = path.join(etcDir, 'resolv.conf');
      privilegedFs.unlinkSync(resolvPath);
      const resolvBody =
        ['# Managed by HKVM Panel', ...dnsList.map((ns) => `nameserver ${ns}`), 'options timeout:2 attempts:2', ''].join(
          '\n'
        );
      privilegedFs.writeFileSync(resolvPath, resolvBody, 0o644);
    } catch {
      // non-fatal on read-only rootfs
    }

    // 2. Configure systemd-resolved upstream drop-in AND normalize /etc/nsswitch.conf
    // (`hosts: files resolve [!UNAVAIL=return] dns` on Ubuntu 22.04/24.04 blocks glibc from
    // falling back to /etc/resolv.conf when systemd-resolved in memory has stale/empty state!)
    try {
      const nssPath = path.join(etcDir, 'nsswitch.conf');
      if (privilegedFs.existsSync(nssPath) && !privilegedFs.lstatMetaSync(nssPath).isSymbolicLink) {
        const nssRaw = privilegedFs.readTextSync(nssPath);
        if (/^hosts:.*\[!UNAVAIL=return\]/m.test(nssRaw)) {
          const nssFixed = nssRaw.replace(
            /^hosts:.*$/m,
            'hosts:          files dns'
          );
          privilegedFs.writeFileSync(nssPath, nssFixed, 0o644);
        }
      }
    } catch {
      // ignore
    }

    try {
      const systemdDir = this.resolveConfinedRootfsDir(safeName, 'etc/systemd', false);
      if (systemdDir) {
        const dropinDir = this.resolveConfinedRootfsDir(
          safeName,
          'etc/systemd/resolved.conf.d',
          true
        );
        if (dropinDir) {
          const dropinContent = `[Resolve]\nDNS=${dnsList.join(' ')}\nFallbackDNS=1.0.0.1 8.8.4.4\n`;
          privilegedFs.writeFileSync(
            path.join(dropinDir, '99-hkvm-dns.conf'),
            dropinContent,
            0o644
          );
        }
      }
    } catch {
      // ignore
    }

    const ipv4Cidr = opts.ipv4Cidr ? opts.ipv4Cidr.trim() : null;
    const gateway =
      opts.gateway && opts.gateway !== 'auto' ? opts.gateway.trim() : null;

    // 3. Synchronize Ubuntu Netplan (/etc/netplan/10-lxc.yaml) so systemd-networkd does not flush eth0!
    try {
      const netplanDir = this.resolveConfinedRootfsDir(safeName, 'etc/netplan', false);
      if (netplanDir) {
        const netplanFile = path.join(netplanDir, '10-lxc.yaml');
        if (ipv4Cidr) {
          const cidrFormatted = ipv4Cidr.includes('/') ? ipv4Cidr : `${ipv4Cidr}/24`;
          const routeBlock = gateway
            ? `      routes:\n        - to: default\n          via: ${gateway}\n`
            : '';
          const yaml = [
            '# Managed by HKVM Panel',
            'network:',
            '  version: 2',
            '  ethernets:',
            '    eth0:',
            '      dhcp4: false',
            '      addresses:',
            `        - ${cidrFormatted}`,
            routeBlock ? routeBlock.trimEnd() : '',
            '      nameservers:',
            `        addresses: [${dnsList.join(', ')}]`,
            '',
          ]
            .filter((l) => l !== '')
            .join('\n') + '\n';
          privilegedFs.unlinkSync(netplanFile);
          privilegedFs.writeFileSync(netplanFile, yaml, 0o600);
        } else if (opts.useDhcp) {
          const yaml = [
            '# Managed by HKVM Panel',
            'network:',
            '  version: 2',
            '  ethernets:',
            '    eth0:',
            '      dhcp4: true',
            '      nameservers:',
            `        addresses: [${dnsList.join(', ')}]`,
            '',
          ].join('\n');
          if (privilegedFs.existsSync(netplanFile)) {
            const existingYaml = privilegedFs.readTextSync(netplanFile);
            if (existingYaml.includes('Managed by HKVM Panel')) {
              privilegedFs.writeFileSync(netplanFile, yaml, 0o600);
            }
          }
        }
      }
    } catch {
      // ignore
    }

    // 4. Synchronize systemd-networkd (/etc/systemd/network/05-hkvm-eth0.network) when netplan is absent
    try {
      const netplanDir = this.resolveConfinedRootfsDir(safeName, 'etc/netplan', false);
      const networkdDir = this.resolveConfinedRootfsDir(safeName, 'etc/systemd/network', false);
      if (!netplanDir && networkdDir) {
        const unitPath = path.join(networkdDir, '05-hkvm-eth0.network');
        if (ipv4Cidr) {
          const cidrFormatted = ipv4Cidr.includes('/') ? ipv4Cidr : `${ipv4Cidr}/24`;
          const lines = [
            '# Managed by HKVM Panel',
            '[Match]',
            'Name=eth0',
            '',
            '[Network]',
            'DHCP=no',
            'KeepConfiguration=yes',
            `Address=${cidrFormatted}`,
          ];
          if (gateway) lines.push(`Gateway=${gateway}`);
          for (const ns of dnsList) lines.push(`DNS=${ns}`);
          lines.push('');
          privilegedFs.unlinkSync(unitPath);
          privilegedFs.writeFileSync(unitPath, lines.join('\n'), 0o644);
        } else if (opts.useDhcp && privilegedFs.existsSync(unitPath)) {
          privilegedFs.unlinkSync(unitPath);
        }
      }
    } catch {
      // ignore
    }

    // 5. Synchronize Debian / Alpine /etc/network/interfaces if present
    try {
      const netIfDir = this.resolveConfinedRootfsDir(safeName, 'etc/network', false);
      if (netIfDir && ipv4Cidr) {
        const ifacesPath = path.join(netIfDir, 'interfaces');
        if (privilegedFs.existsSync(ifacesPath) && !privilegedFs.lstatMetaSync(ifacesPath).isSymbolicLink) {
          const curTxt = privilegedFs.readTextSync(ifacesPath);
          if (/iface\s+eth0\s+inet\s+dhcp/i.test(curTxt) || curTxt.includes('# HKVM-ETH0')) {
            const [ipOnly, pfxRaw] = (ipv4Cidr.includes('/') ? ipv4Cidr : `${ipv4Cidr}/24`).split('/');
            const mask = prefixLenToNetmask(parseInt(pfxRaw || '24', 10) || 24);
            const staticStanza = [
              '# HKVM-ETH0',
              'auto eth0',
              'iface eth0 inet static',
              `    address ${ipOnly}`,
              `    netmask ${mask}`,
              ...(gateway ? [`    gateway ${gateway}`] : []),
            ].join('\n');
            const stripped = curTxt
              .replace(/# HKVM-ETH0[\s\S]*?(?=\n(?:auto|allow-|iface|source)\b|$)/g, '')
              .replace(/^\s*auto\s+eth0\s*$/gm, '')
              .replace(/^\s*iface\s+eth0\s+inet\s+dhcp\s*$/gim, '');
            privilegedFs.writeFileSync(
              ifacesPath,
              `${stripped.trimEnd()}\n\n${staticStanza}\n`,
              0o644
            );
          }
        }
      }
    } catch {
      // ignore
    }

    return dnsList;
  }

  public async listContainers(): Promise<LxcContainerRuntimeInfo[]> {
    if (!isBinaryAvailable('lxc-ls')) {
      return [];
    }
    if (!privilegedFs.existsSync(this.lxcBaseDir)) {
      return [];
    }
    const lsRes = await runAllowlistedCommand('lxc-ls', [...this.lxcPathArgs(), '-1'], {
      timeoutMs: 10_000,
      asRoot: this.needsRootForStore() || undefined,
    });
    if (lsRes.exitCode !== 0) return [];
    const names = lsRes.stdout
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);

    const results: LxcContainerRuntimeInfo[] = [];
    for (const name of names) {
      try {
        results.push(await this.inspectContainer(name));
      } catch {
        // skip invalid entries
      }
    }
    return results;
  }

  private readContainerNetFromConfig(containerName: string): {
    bridge: string | null;
    ipv4Cidr: string | null;
    gateway: string | null;
  } {
    const safeName = SafeValidators.containerName(containerName);
    const configPath = path.join(this.lxcBaseDir, safeName, 'config');
    if (!privilegedFs.existsSync(configPath)) {
      return { bridge: null, ipv4Cidr: null, gateway: null };
    }
    try {
      const txt = privilegedFs.readTextSync(configPath);
      const brMatches = [...txt.matchAll(/^\s*lxc\.net\.0\.link\s*=\s*(\S+)/gm)];
      const ipMatches = [...txt.matchAll(/^\s*lxc\.net\.0\.ipv4\.address\s*=\s*(\S+)/gm)];
      const gwMatches = [...txt.matchAll(/^\s*lxc\.net\.0\.ipv4\.gateway\s*=\s*(\S+)/gm)];
      return {
        bridge: brMatches.length > 0 ? brMatches[brMatches.length - 1][1].trim() : null,
        ipv4Cidr: ipMatches.length > 0 ? ipMatches[ipMatches.length - 1][1].trim() : null,
        gateway: gwMatches.length > 0 ? gwMatches[gwMatches.length - 1][1].trim() : null,
      };
    } catch {
      return { bridge: null, ipv4Cidr: null, gateway: null };
    }
  }

  public async inspectContainer(containerName: string): Promise<LxcContainerRuntimeInfo> {
    const safeName = SafeValidators.containerName(containerName);
    const configPath = path.join(this.lxcBaseDir, safeName, 'config');
    const cfgNet = this.readContainerNetFromConfig(safeName);
    const configuredIpv4 = cfgNet.ipv4Cidr ? cfgNet.ipv4Cidr.split('/')[0] : null;
    const configuredGateway = cfgNet.gateway || null;

    if (!isBinaryAvailable('lxc-info')) {
      const existsOnDisk = privilegedFs.existsSync(configPath);
      return {
        name: safeName,
        state: existsOnDisk ? 'stopped' : 'missing',
        pid: null,
        ips: configuredIpv4 ? [configuredIpv4] : [],
        cpuUseSeconds: 0,
        memoryBytes: 0,
        swapBytes: 0,
        rxBytes: 0,
        txBytes: 0,
        diskUsedBytes: this.measureDirBytesFast(path.join(this.lxcBaseDir, safeName, 'rootfs')),
        configuredIpv4,
        configuredGateway,
      };
    }

    const res = await runAllowlistedCommand('lxc-info', [...this.lxcPathArgs(), '-n', safeName], {
      timeoutMs: 10_000,
      asRoot: this.needsRootForStore() || undefined,
    });
    if (res.exitCode !== 0) {
      const existsOnDisk = privilegedFs.existsSync(configPath);
      return {
        name: safeName,
        state: existsOnDisk ? 'stopped' : 'missing',
        pid: null,
        ips: [],
        cpuUseSeconds: 0,
        memoryBytes: 0,
        swapBytes: 0,
        rxBytes: 0,
        txBytes: 0,
        diskUsedBytes: 0,
        configuredIpv4,
        configuredGateway,
      };
    }

    let state: LxcContainerRuntimeInfo['state'] = 'stopped';
    let pid: number | null = null;
    const ips: string[] = [];
    let cpuUseSeconds = 0;
    let memoryBytes = 0;
    let rxBytes = 0;
    let txBytes = 0;

    for (const line of res.stdout.split('\n')) {
      const [rawKey, ...rest] = line.split(':');
      if (!rawKey || rest.length === 0) continue;
      const key = rawKey.trim().toLowerCase();
      const val = rest.join(':').trim();

      if (key === 'state') {
        const s = val.toLowerCase();
        if (s.includes('running')) state = 'running';
        else if (s.includes('frozen')) state = 'frozen';
        else state = 'stopped';
      } else if (key === 'pid') {
        const n = parseInt(val, 10);
        if (!Number.isNaN(n) && n > 0) pid = n;
      } else if (key === 'ip') {
        ips.push(val);
      } else if (key === 'cpu use') {
        cpuUseSeconds = parseFloat(val.replace(/[^0-9.]/g, '')) || 0;
      } else if (key === 'memory use') {
        memoryBytes = this.parseHumanSizeToBytes(val);
      } else if (key === 'rx bytes') {
        rxBytes += this.parseHumanSizeToBytes(val);
      } else if (key === 'tx bytes') {
        txBytes += this.parseHumanSizeToBytes(val);
      }
    }

    const diskUsedBytes = await this.getRootfsUsedBytes(safeName);
    const hasLoopDisk =
      privilegedFs.existsSync(this.getQuotaDiskImagePath(safeName)) ||
      Boolean(findActiveMountSource(this.getRootfsDir(safeName)));

    if ((state === 'running' || state === 'frozen') && pid && pid > 0 && memoryBytes === 0) {
      const procStats = this.measureContainerProcTree(pid);
      if (procStats.memoryBytes > 0) {
        memoryBytes = procStats.memoryBytes;
      }
      if (cpuUseSeconds === 0 && procStats.cpuUseSeconds > 0) {
        cpuUseSeconds = procStats.cpuUseSeconds;
      }
    }

    return {
      name: safeName,
      state,
      pid,
      ips,
      cpuUseSeconds,
      memoryBytes,
      swapBytes: 0,
      rxBytes,
      txBytes,
      diskUsedBytes,
      backingStore: hasLoopDisk ? 'loop' : 'dir',
      diskQuotaEnforced: hasLoopDisk,
      configuredIpv4,
      configuredGateway,
    };
  }

  /**
   * Fallback live memory (VmRSS) & CPU time aggregator across `<initPid>` and all its
   * descendant processes in `/proc` for hosts (e.g. WSL2 / un-delegated cgroup v2) where
   * `lxc-info` does not emit `Memory use:` / `CPU use:`.
   */
  private measureContainerProcTree(rootPid: number): {
    memoryBytes: number;
    cpuUseSeconds: number;
  } {
    try {
      if (!fs.existsSync('/proc')) return { memoryBytes: 0, cpuUseSeconds: 0 };
      const entries = fs.readdirSync('/proc');
      const childrenByPpid = new Map<number, number[]>();
      const ticksByPid = new Map<number, number>();

      for (const ent of entries) {
        if (!/^\d+$/.test(ent)) continue;
        const p = parseInt(ent, 10);
        try {
          const statRaw = fs.readFileSync(`/proc/${p}/stat`, 'utf8');
          const closeParen = statRaw.lastIndexOf(')');
          if (closeParen === -1) continue;
          const rest = statRaw.slice(closeParen + 2).trim().split(/\s+/);
          const ppid = parseInt(rest[1] || '0', 10);
          const utime = parseInt(rest[11] || '0', 10) || 0;
          const stime = parseInt(rest[12] || '0', 10) || 0;
          ticksByPid.set(p, utime + stime);
          if (ppid > 0) {
            const arr = childrenByPpid.get(ppid) || [];
            arr.push(p);
            childrenByPpid.set(ppid, arr);
          }
        } catch {
          // process exited between readdir and readFile
        }
      }

      const treePids: number[] = [];
      const visited = new Set<number>();
      const queue = [rootPid];
      while (queue.length > 0) {
        const cur = queue.shift()!;
        if (visited.has(cur)) continue;
        visited.add(cur);
        treePids.push(cur);
        const kids = childrenByPpid.get(cur);
        if (kids) {
          for (const k of kids) {
            if (!visited.has(k)) queue.push(k);
          }
        }
      }

      let totalRssBytes = 0;
      let totalTicks = 0;
      for (const tp of treePids) {
        totalTicks += ticksByPid.get(tp) || 0;
        try {
          const statusTxt = fs.readFileSync(`/proc/${tp}/status`, 'utf8');
          const m = statusTxt.match(/^VmRSS:\s*(\d+)\s*kB/m);
          if (m) {
            totalRssBytes += (parseInt(m[1], 10) || 0) * 1024;
          }
        } catch {
          // ignore exited child
        }
      }

      return {
        memoryBytes: totalRssBytes,
        cpuUseSeconds: Number((totalTicks / 100).toFixed(2)),
      };
    } catch {
      return { memoryBytes: 0, cpuUseSeconds: 0 };
    }
  }

  private parseHumanSizeToBytes(text: string): number {
    const m = text.trim().match(/^([0-9.]+)\s*([KMGTPE]?i?B?)/i);
    if (!m) return 0;
    const num = parseFloat(m[1]) || 0;
    const unit = (m[2] || '').toUpperCase();
    if (unit.startsWith('K')) return Math.round(num * 1024);
    if (unit.startsWith('M')) return Math.round(num * 1024 * 1024);
    if (unit.startsWith('G')) return Math.round(num * 1024 * 1024 * 1024);
    if (unit.startsWith('T')) return Math.round(num * 1024 * 1024 * 1024 * 1024);
    return Math.round(num);
  }

  private measureDirBytesFast(dirPath: string): number {
    try {
      return privilegedFs.lstatMetaSync(dirPath).size;
    } catch {
      return 0;
    }
  }

  private async getRootfsUsedBytes(containerName: string): Promise<number> {
    const rootfs = this.getRootfsDir(containerName);
    if (!privilegedFs.existsSync(rootfs)) return 0;

    // Fast kernel statfs path when rootfs is a dedicated loop-mounted ext4 quota volume
    if (findActiveMountSource(rootfs) && isBinaryAvailable('df')) {
      const dfRes = await runAllowlistedCommand('df', ['-B1', '--output=used', rootfs], {
        timeoutMs: 4000,
        asRoot: true,
      });
      if (dfRes.exitCode === 0) {
        const lines = dfRes.stdout.trim().split('\n');
        const val = parseInt((lines[lines.length - 1] || '').trim(), 10);
        if (!Number.isNaN(val) && val >= 0) return val;
      }
    }

    if (isBinaryAvailable('du')) {
      const res = await runAllowlistedCommand('du', ['-sb', rootfs], {
        timeoutMs: 8000,
        asRoot: true,
      });
      if (res.exitCode === 0) {
        const bytes = parseInt(res.stdout.trim().split(/\s+/)[0] || '0', 10);
        if (!Number.isNaN(bytes)) return bytes;
      }
    }
    return 0;
  }

  public getQuotaDiskDir(): string {
    if (this.isSystemLxcStore()) {
      return '/var/lib/hkvm-lxc-disks';
    }
    return path.join(path.dirname(path.resolve(this.lxcBaseDir)), 'hkvm-lxc-disks');
  }

  public getQuotaDiskImagePath(containerName: string): string {
    const safeName = SafeValidators.containerName(containerName);
    return path.join(this.getQuotaDiskDir(), `${safeName}.ext4`);
  }

  /**
   * Ensures an existing sparse `.ext4` quota volume is loop-mounted onto `<ctDir>/rootfs`
   * (for example after a host reboot before `lxc-start`).
   */
  public async ensureExistingQuotaDiskMounted(containerName: string): Promise<boolean> {
    const safeName = SafeValidators.containerName(containerName);
    const imgPath = this.getQuotaDiskImagePath(safeName);
    if (!privilegedFs.existsSync(imgPath)) return false;

    const rootfsDir = this.getRootfsDir(safeName);
    privilegedFs.mkdirpSync(rootfsDir, 0o755);
    if (findActiveMountSource(rootfsDir)) return true;

    if (!isBinaryAvailable('mount') || (!isRunningAsRoot() && !canPasswordlessSudo())) {
      return false;
    }

    let mntRes = await runAllowlistedCommand('mount', ['-o', 'loop', imgPath, rootfsDir], {
      timeoutMs: 15_000,
      asRoot: true,
    });
    if (mntRes.exitCode !== 0 && isBinaryAvailable('e2fsck')) {
      await runAllowlistedCommand('e2fsck', ['-fy', imgPath], {
        timeoutMs: 60_000,
        asRoot: true,
      }).catch(() => undefined);
      mntRes = await runAllowlistedCommand('mount', ['-o', 'loop', imgPath, rootfsDir], {
        timeoutMs: 15_000,
        asRoot: true,
      });
    }
    return mntRes.exitCode === 0 && Boolean(findActiveMountSource(rootfsDir));
  }

  /**
   * Unmounts `<ctDir>/rootfs` if backed by a loop mount, and optionally deletes the `.ext4` image.
   */
  public async unmountQuotaDiskIfMounted(
    containerName: string,
    removeImage = false
  ): Promise<void> {
    const safeName = SafeValidators.containerName(containerName);
    const rootfsDir = this.getRootfsDir(safeName);
    if (findActiveMountSource(rootfsDir) && isBinaryAvailable('umount')) {
      const uRes = await runAllowlistedCommand('umount', [rootfsDir], {
        timeoutMs: 10_000,
        asRoot: true,
      });
      if (uRes.exitCode !== 0) {
        await runAllowlistedCommand('umount', ['-l', rootfsDir], {
          timeoutMs: 10_000,
          asRoot: true,
        }).catch(() => undefined);
      }
    }
    if (removeImage) {
      const imgPath = this.getQuotaDiskImagePath(safeName);
      if (privilegedFs.existsSync(imgPath)) {
        privilegedFs.unlinkSync(imgPath);
      }
    }
  }

  /**
   * Provisions or resizes a thin-provisioned sparse `ext4` loop quota volume mounted on `<ctDir>/rootfs`
   * so `df -h` inside the container reports the exact assigned `diskGb` (e.g. `20G`) and the kernel
   * enforces the hard block limit instead of exposing the entire host partition (`overlay 32G`).
   *
   * - Initial conversion is atomic: builds `.ext4.tmp` via `mkfs.ext4 -d <rootfs>`, probe-mounts on
   *   a temporary directory first to verify kernel loop-mount permission, and rolls back cleanly if
   *   loop mounting is unavailable.
   * - Online growth (`diskGb` increased while running) runs `truncate` + `losetup -c` + `resize2fs`
   *   with zero container downtime.
   */
  public async ensureContainerQuotaDisk(
    containerName: string,
    diskGb: number,
    options: { allowNonSystemStore?: boolean } = {}
  ): Promise<boolean> {
    if (
      !options.allowNonSystemStore &&
      !this.isSystemLxcStore() &&
      process.env.HKVM_FORCE_LOOP_QUOTA !== 'true'
    ) {
      return false;
    }

    const requiredBins = ['truncate', 'mkfs.ext4', 'mount', 'umount', 'losetup', 'resize2fs'];
    if (requiredBins.some((b) => !isBinaryAvailable(b))) {
      return false;
    }
    if (!isRunningAsRoot() && !canPasswordlessSudo()) {
      return false;
    }

    const safeName = SafeValidators.containerName(containerName);
    const rootfsDir = this.getRootfsDir(safeName);
    if (!privilegedFs.existsSync(rootfsDir)) return false;

    const diskDir = this.getQuotaDiskDir();
    privilegedFs.mkdirpSync(diskDir, 0o700);
    const imgPath = this.getQuotaDiskImagePath(safeName);
    const targetBytes = Math.max(1, Math.round(Number(diskGb || 20))) * 1024 * 1024 * 1024;

    // 1. Existing `.ext4` quota volume: ensure mounted & grow online/offline if diskGb increased
    if (privilegedFs.existsSync(imgPath)) {
      const mountedOk = await this.ensureExistingQuotaDiskMounted(safeName);
      if (!mountedOk) return false;

      const meta = privilegedFs.lstatMetaSync(imgPath);
      if (targetBytes > meta.size + 64 * 1024 * 1024) {
        const truncRes = await runAllowlistedCommand(
          'truncate',
          ['-s', String(targetBytes), imgPath],
          { timeoutMs: 15_000, asRoot: true }
        );
        if (truncRes.exitCode === 0) {
          const loopSrc = findActiveMountSource(rootfsDir);
          if (loopSrc && loopSrc.startsWith('/dev/loop')) {
            await runAllowlistedCommand('losetup', ['-c', loopSrc], {
              timeoutMs: 10_000,
              asRoot: true,
            });
            await runAllowlistedCommand('resize2fs', [loopSrc], {
              timeoutMs: 60_000,
              asRoot: true,
            });
          } else {
            if (isBinaryAvailable('e2fsck')) {
              await runAllowlistedCommand('e2fsck', ['-fy', imgPath], {
                timeoutMs: 60_000,
                asRoot: true,
              }).catch(() => undefined);
            }
            await runAllowlistedCommand('resize2fs', [imgPath], {
              timeoutMs: 60_000,
              asRoot: true,
            });
          }
        }
      }
      return true;
    }

    // 2. Convert plain `dir` rootfs into a sparse loop-mounted `ext4` quota volume (container must be stopped)
    const curState = await this.inspectContainer(safeName);
    if (curState.state === 'running' || curState.state === 'frozen') {
      return false;
    }
    if (findActiveMountSource(rootfsDir)) {
      return true;
    }

    const usedBytes = await this.getRootfsUsedBytes(safeName);
    const effectiveBytes = Math.max(targetBytes, usedBytes + 512 * 1024 * 1024);
    const tmpImgPath = `${imgPath}.tmp`;
    const probeDir = path.join(this.getContainerDir(safeName), '.rootfs-loop-probe');

    if (privilegedFs.existsSync(tmpImgPath)) privilegedFs.unlinkSync(tmpImgPath);
    if (privilegedFs.existsSync(probeDir)) privilegedFs.rmRecursiveSync(probeDir);

    const truncRes = await runAllowlistedCommand(
      'truncate',
      ['-s', String(effectiveBytes), tmpImgPath],
      { timeoutMs: 15_000, asRoot: true }
    );
    if (truncRes.exitCode !== 0) {
      if (privilegedFs.existsSync(tmpImgPath)) privilegedFs.unlinkSync(tmpImgPath);
      return false;
    }

    const mkfsRes = await runAllowlistedCommand(
      'mkfs.ext4',
      [
        '-q',
        '-F',
        '-m',
        '0',
        '-d',
        rootfsDir,
        '-E',
        'lazy_itable_init=1,lazy_journal_init=1',
        tmpImgPath,
      ],
      { timeoutMs: 300_000, asRoot: true }
    );
    if (mkfsRes.exitCode !== 0) {
      if (privilegedFs.existsSync(tmpImgPath)) privilegedFs.unlinkSync(tmpImgPath);
      return false;
    }

    // Probe-mount BEFORE touching `rootfsDir` so restricted kernels never affect guest files
    privilegedFs.mkdirpSync(probeDir, 0o700);
    const probeMnt = await runAllowlistedCommand('mount', ['-o', 'loop', tmpImgPath, probeDir], {
      timeoutMs: 15_000,
      asRoot: true,
    });
    if (probeMnt.exitCode !== 0) {
      privilegedFs.rmRecursiveSync(probeDir);
      privilegedFs.unlinkSync(tmpImgPath);
      return false;
    }
    await runAllowlistedCommand('umount', [probeDir], {
      timeoutMs: 10_000,
      asRoot: true,
    }).catch(() =>
      runAllowlistedCommand('umount', ['-l', probeDir], { timeoutMs: 10_000, asRoot: true })
    );
    privilegedFs.rmRecursiveSync(probeDir);

    // Atomic directory swap -> mount `.ext4` onto `rootfsDir`
    const bakDir = `${rootfsDir}.preloop-bak`;
    if (privilegedFs.existsSync(bakDir)) privilegedFs.rmRecursiveSync(bakDir);

    privilegedFs.renameSync(rootfsDir, bakDir);
    privilegedFs.mkdirpSync(rootfsDir, 0o755);
    privilegedFs.renameSync(tmpImgPath, imgPath);

    const finalMnt = await runAllowlistedCommand('mount', ['-o', 'loop', imgPath, rootfsDir], {
      timeoutMs: 15_000,
      asRoot: true,
    });
    if (finalMnt.exitCode === 0 && findActiveMountSource(rootfsDir)) {
      privilegedFs.rmRecursiveSync(bakDir);
      return true;
    }

    // Rollback on unexpected mount failure
    await runAllowlistedCommand('umount', ['-l', rootfsDir], {
      timeoutMs: 10_000,
      asRoot: true,
    }).catch(() => undefined);
    privilegedFs.rmRecursiveSync(rootfsDir);
    privilegedFs.renameSync(bakDir, rootfsDir);
    if (privilegedFs.existsSync(imgPath)) privilegedFs.unlinkSync(imgPath);
    return false;
  }

  private async createFromLocalArchive(safeName: string, archivePath: string): Promise<void> {
    const resolvedArchive = path.resolve(archivePath);
    if (!fs.existsSync(resolvedArchive)) {
      throw new Error(`Custom LXC template archive not found at ${resolvedArchive}`);
    }
    const ctDir = this.getContainerDir(safeName);
    const rootfsDir = this.getRootfsDir(safeName);
    privilegedFs.mkdirpSync(rootfsDir, 0o755);

    const tarRes = await runAllowlistedCommand(
      'tar',
      ['--numeric-owner', '-xpf', resolvedArchive, '-C', rootfsDir],
      {
        timeoutMs: 600_000,
        asRoot: true,
      }
    );
    if (tarRes.exitCode !== 0) {
      privilegedFs.rmRecursiveSync(ctDir);
      throw new Error(
        `Failed to unpack custom LXC rootfs archive: ${tarRes.stderr || tarRes.stdout}`
      );
    }

    const baseConfigLines = [
      '# Distribution configuration',
      ...(fs.existsSync('/usr/share/lxc/config/common.conf')
        ? ['lxc.include = /usr/share/lxc/config/common.conf']
        : []),
      `lxc.arch = ${process.arch === 'arm64' ? 'aarch64' : 'x86_64'}`,
      '',
      '# Container specific configuration',
      `lxc.rootfs.path = dir:${rootfsDir}`,
      `lxc.uts.name = ${safeName}`,
      '',
    ];
    privilegedFs.writeFileSync(path.join(ctDir, 'config'), baseConfigLines.join('\n'), 0o640);
  }

  private async applyOfflineRootPasswordHash(
    safeName: string,
    plainPassword: string
  ): Promise<boolean> {
    if (!plainPassword || plainPassword.includes('\n') || plainPassword.includes('\0')) {
      return false;
    }
    if (!isBinaryAvailable('openssl')) return false;

    const shadowPath = path.join(this.getRootfsDir(safeName), 'etc', 'shadow');
    if (!privilegedFs.existsSync(shadowPath)) return false;

    const hashRes = await runAllowlistedCommand('openssl', ['passwd', '-6', '-stdin'], {
      stdinData: `${plainPassword}\n`,
      timeoutMs: 5000,
      asRoot: false,
    });
    const passwordHash = hashRes.stdout.trim();
    if (hashRes.exitCode !== 0 || !passwordHash.startsWith('$6$')) {
      return false;
    }

    try {
      const shadowContent = privilegedFs.readTextSync(shadowPath);
      const lines = shadowContent.split('\n');
      let replaced = false;
      const updated = lines.map((line) => {
        if (line.startsWith('root:')) {
          const parts = line.split(':');
          parts[1] = passwordHash;
          replaced = true;
          return parts.join(':');
        }
        return line;
      });
      if (!replaced) return false;
      privilegedFs.writeFileSync(shadowPath, updated.join('\n'), 0o640);
      return true;
    } catch {
      return false;
    }
  }

  public async createContainer(spec: LxcCreateSpec): Promise<LxcContainerRuntimeInfo> {
    this.assertLxcInstalled();
    const safeName = SafeValidators.containerName(spec.containerName);
    const lockKey = safeName.toLowerCase();
    if (this.inFlightCreations.has(lockKey)) {
      throw new Error(
        `LXC container "${safeName}" is currently being provisioned (downloading OS template). Please wait for it to finish.`
      );
    }

    this.inFlightCreations.add(lockKey);
    try {
      const requestedBacking = spec.backingStore === 'loop' ? 'dir' : (spec.backingStore || 'dir');
      const backing = requestedBacking;
      this.ensureHostLxcDirectories();

      // Clean up any leftover empty/corrupt/orphan directory if not registered in panel DB
      const existingInfo = await this.inspectContainer(safeName);
      const ctDir = this.getContainerDir(safeName);
      if (existingInfo.state !== 'missing') {
        if (spec.replaceOrphanOnHost) {
          await this.destroyContainer(safeName).catch(() => undefined);
          if (privilegedFs.existsSync(ctDir)) {
            privilegedFs.rmRecursiveSync(ctDir);
          }
        } else {
          throw new Error(
            `LXC container "${safeName}" already exists on host (${existingInfo.state}).`
          );
        }
      } else if (privilegedFs.existsSync(ctDir)) {
        privilegedFs.rmRecursiveSync(ctDir);
      }

      if (spec.templateArchivePath && fs.existsSync(path.resolve(spec.templateArchivePath))) {
        await this.createFromLocalArchive(safeName, spec.templateArchivePath);
      } else {
        const { distro, releases, archMapper } = resolveDownloadReleaseCandidates(
          spec.distro,
          spec.release,
          spec.fallbackRelease
        );
        const arch = archMapper(spec.arch || 'amd64');
        const downloadEnv = {
          DOWNLOAD_KEYSERVER:
            process.env.LXC_DOWNLOAD_KEYSERVER || 'hkp://keyserver.ubuntu.com:80',
        };

        let created = false;
        let lastFailure = '';

        for (const relCandidate of releases) {
          const baseArgs = [
            ...this.lxcPathArgs(),
            '-n',
            safeName,
            '-B',
            backing,
            '-t',
            'download',
            '--',
            '-d',
            distro,
            '-r',
            relCandidate,
            '-a',
            arch,
          ];

          let createRes = await runAllowlistedCommand('lxc-create', baseArgs, {
            timeoutMs: 600_000,
            env: downloadEnv,
            asRoot: this.needsRootForStore() || undefined,
          });

          const combinedOut = `${createRes.stderr}\n${createRes.stdout}`;
          if (
            createRes.exitCode !== 0 &&
            process.env.HKVM_LXC_STRICT_GPG !== 'true' &&
            /unable to fetch gpg key|gpg.*keyserver|gnupg/i.test(combinedOut)
          ) {
            if (privilegedFs.existsSync(ctDir)) {
              privilegedFs.rmRecursiveSync(ctDir);
            }
            createRes = await runAllowlistedCommand(
              'lxc-create',
              [...baseArgs, '--no-validate'],
              {
                timeoutMs: 600_000,
                env: downloadEnv,
                asRoot: this.needsRootForStore() || undefined,
              }
            );
          }

          if (createRes.exitCode === 0) {
            created = true;
            break;
          }

          lastFailure = `lxc-create failed (${createRes.exitCode}): ${(
            createRes.stderr || createRes.stdout
          ).trim()}`;
          if (privilegedFs.existsSync(ctDir)) {
            privilegedFs.rmRecursiveSync(ctDir);
          }

          const retryNextRelease = /couldn't find a matching image|no matching image/i.test(
            `${createRes.stderr}\n${createRes.stdout}`
          );
          if (!retryNextRelease) {
            break;
          }
        }

        if (!created) {
          throw new Error(lastFailure || `lxc-create failed for ${distro}:${spec.release} (${arch})`);
        }
      }

      try {
        await this.writeManagedConfigSection(safeName, {
          hostname: spec.hostname || safeName,
          cpuCores: spec.cpuCores,
          cpuShares: spec.cpuShares ?? 1024,
          cpuLimitPercent: spec.cpuLimitPercent ?? 100,
          cpuPinning: spec.cpuPinning || null,
          ramMb: spec.ramMb,
          swapMb: spec.swapMb ?? 512,
          nesting: spec.nesting !== false,
          kvmNesting: Boolean(spec.kvmNesting),
          privileged: spec.privileged !== false,
          apparmorProfile: spec.apparmorProfile || 'generated',
          autostart: Boolean(spec.autostart),
          bridge: spec.bridge || 'lxcbr0',
          ipv4Address: spec.ipv4Address || null,
          ipv4Gateway: spec.ipv4Gateway || null,
          ipv6Address: spec.ipv6Address || null,
          macAddress: spec.macAddress || null,
          mounts: spec.mounts || [],
        });

        if (spec.rootPassword) {
          await this.applyOfflineRootPasswordHash(safeName, spec.rootPassword);
        }

        if (spec.sshPublicKeys && spec.sshPublicKeys.length > 0) {
          for (const pubKey of spec.sshPublicKeys) {
            await this.injectSshPublicKey(safeName, pubKey);
          }
        }

        // Convert plain `dir` rootfs into a dedicated sparse `ext4` loop quota volume so
        // `df -h` inside the container reports exact `spec.diskGb` (e.g. 20G) instead of host disk
        if ((!spec.backingStore || spec.backingStore === 'dir' || spec.backingStore === 'loop') && spec.diskGb >= 1) {
          await this.ensureContainerQuotaDisk(safeName, spec.diskGb).catch(() => false);
        }
      } catch (cfgErr) {
        await this.destroyContainer(safeName).catch(() => {
          if (privilegedFs.existsSync(ctDir)) privilegedFs.rmRecursiveSync(ctDir);
        });
        throw cfgErr;
      }

      let startupWarning: string | undefined;
      try {
        await this.startContainer(safeName);
        if (spec.rootPassword) {
          await this.setRootPassword(safeName, spec.rootPassword).catch(() => undefined);
        }
      } catch (startErr: any) {
        const msg = String(startErr?.message || startErr);
        // Never discard a validly provisioned container if only initial auto-start failed:
        // keep it registered in 'stopped' state so the admin can inspect logs/config and start it.
        startupWarning = `Container rootfs and configuration were created on disk (status: stopped), but automatic startup encountered a host issue: ${msg}`;
      }

      const info = await this.inspectContainer(safeName);
      if (startupWarning) {
        info.startupWarning = startupWarning;
      }
      return info;
    } finally {
      this.inFlightCreations.delete(lockKey);
    }
  }

  public async writeManagedConfigSection(
    containerName: string,
    cfg: {
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
      mounts?: Array<{ hostSource: string; guestTarget: string; readOnly?: boolean }>;
    }
  ): Promise<void> {
    const safeName = SafeValidators.containerName(containerName);
    const configFile = path.join(this.getContainerDir(safeName), 'config');
    if (!privilegedFs.existsSync(configFile)) {
      throw new Error(`Container config not found at ${configFile}`);
    }

    const existing = privilegedFs.readTextSync(configFile);
    const markerStart = '# --- BEGIN HKVM MANAGED CONFIG ---';
    const markerEnd = '# --- END HKVM MANAGED CONFIG ---';

    let stripped = existing.replace(
      new RegExp(`${markerStart}[\\s\\S]*?${markerEnd}\\n?`, 'g'),
      ''
    );

    // Strip template-copied default lxc.net.0.* and lxc.apparmor.* directives so HKVM's managed block is authoritative
    if (cfg.bridge !== undefined) {
      stripped = stripped.replace(/^\s*lxc\.net\.0(?:\.[a-zA-Z0-9_.-]+)?\s*=.*$/gm, '');
    }
    stripped = stripped.replace(/^\s*lxc\.apparmor\.(?:profile|allow_nesting)\s*=.*$/gm, '');
    stripped = stripped.replace(/\n{3,}/g, '\n\n');

    const isSystemStore = this.isSystemLxcStore();
    if (isSystemStore) {
      await ensureLxcfsDaemonMounted().catch(() => false);
    }

    const cgroupV2Controllers = readActiveCgroupV2Controllers(isSystemStore);
    const isCgroupV2 = cgroupV2Controllers !== null;
    const apparmorAvailable = isAppArmorProfileLoadable();
    const lines: string[] = [markerStart];

    if (cfg.hostname) {
      const cleanHost = cfg.hostname.replace(/[^a-zA-Z0-9.-]/g, '').slice(0, 63);
      if (cleanHost) lines.push(`lxc.uts.name = ${cleanHost}`);
    }

    if (cfg.autostart !== undefined) {
      lines.push(`lxc.start.auto = ${cfg.autostart ? 1 : 0}`);
    }

    if (cfg.nesting) {
      if (apparmorAvailable && fs.existsSync('/usr/share/lxc/config/nesting.conf')) {
        lines.push('lxc.include = /usr/share/lxc/config/nesting.conf');
      } else {
        lines.push('lxc.mount.auto =');
        lines.push('lxc.mount.auto = proc:mixed sys:rw cgroup:mixed');
      }
    }

    // Bind-mount cgroup-virtualized lxcfs /proc entries so `free -h`, `neofetch`, `top`, and `htop`
    // inside the container display the container's assigned RAM/Swap/CPU instead of host /proc!
    if (isSystemStore && fs.existsSync('/var/lib/lxcfs/proc/meminfo')) {
      const hasCommonLxcfsHook =
        stripped.includes('/usr/share/lxc/config/common.conf') &&
        fs.existsSync('/usr/share/lxc/config/common.conf.d/00-lxcfs.conf');
      if (!hasCommonLxcfsHook) {
        for (const procEntry of ['cpuinfo', 'diskstats', 'loadavg', 'meminfo', 'stat', 'swaps', 'uptime']) {
          if (fs.existsSync(`/var/lib/lxcfs/proc/${procEntry}`)) {
            lines.push(
              `lxc.mount.entry = /var/lib/lxcfs/proc/${procEntry} proc/${procEntry} none bind,rw,optional 0 0`
            );
          }
        }
      }
    }

    const requestedProfile = (cfg.apparmorProfile || 'generated').replace(/[^a-zA-Z0-9_.-]/g, '');
    const effectiveAppArmor =
      apparmorAvailable && !cfg.kvmNesting ? requestedProfile || 'generated' : 'unconfined';
    lines.push(`lxc.apparmor.profile = ${effectiveAppArmor}`);

    if (cfg.kvmNesting) {
      if (isCgroupV2) {
        lines.push('lxc.cgroup2.devices.allow = c 10:232 rwm');
        lines.push('lxc.cgroup2.devices.allow = c 10:200 rwm');
      } else {
        lines.push('lxc.cgroup.devices.allow = c 10:232 rwm');
        lines.push('lxc.cgroup.devices.allow = c 10:200 rwm');
      }
      lines.push('lxc.mount.entry = /dev/kvm dev/kvm none bind,optional,create=file 0 0');
      lines.push('lxc.mount.entry = /dev/net/tun dev/net/tun none bind,optional,create=file 0 0');
    }

    const cores = Math.max(1, Number(cfg.cpuCores || 1));
    const pct = Math.min(100, Math.max(5, Number(cfg.cpuLimitPercent || 100)));
    const quotaUs = Math.round(cores * 100_000 * (pct / 100));
    const effectiveCpuset = selectContainerCpuset(
      safeName,
      cores,
      readEffectiveHostCpuIds(),
      cfg.cpuPinning
    );

    if (isCgroupV2 && cgroupV2Controllers) {
      if (cgroupV2Controllers.has('cpu')) {
        lines.push(`lxc.cgroup2.cpu.max = ${quotaUs} 100000`);
        if (cfg.cpuShares) {
          const weight = Math.min(10000, Math.max(1, Math.round((cfg.cpuShares / 1024) * 100)));
          lines.push(`lxc.cgroup2.cpu.weight = ${weight}`);
        }
      }
      if (cgroupV2Controllers.has('cpuset') && effectiveCpuset) {
        lines.push(`lxc.cgroup2.cpuset.cpus = ${effectiveCpuset}`);
      }
      if (cgroupV2Controllers.has('memory')) {
        if (cfg.ramMb) {
          lines.push(`lxc.cgroup2.memory.max = ${Math.max(64, cfg.ramMb)}M`);
        }
        if (cfg.swapMb !== undefined && isCgroupV2SwapSupported()) {
          lines.push(`lxc.cgroup2.memory.swap.max = ${Math.max(0, cfg.swapMb)}M`);
        }
      }
    } else if (!isCgroupV2) {
      lines.push(`lxc.cgroup.cpu.cfs_period_us = 100000`);
      lines.push(`lxc.cgroup.cpu.cfs_quota_us = ${quotaUs}`);
      if (cfg.cpuShares) {
        lines.push(`lxc.cgroup.cpu.shares = ${Math.max(64, cfg.cpuShares)}`);
      }
      if (effectiveCpuset) {
        lines.push(`lxc.cgroup.cpuset.cpus = ${effectiveCpuset}`);
      }
      if (cfg.ramMb) {
        lines.push(`lxc.cgroup.memory.limit_in_bytes = ${Math.max(64, cfg.ramMb)}M`);
      }
    }

    let configuredGuestIpv4: string | null = null;
    let configuredGuestGateway: string | null = null;
    let activeBridgeInfo: LxcBridgeNetworkInfo | null = null;

    if (cfg.bridge) {
      const safeBridge = SafeValidators.bridgeOrIface(cfg.bridge);
      const isSystemStore = this.isSystemLxcStore();
      const bridgeInfo: LxcBridgeNetworkInfo = isSystemStore
        ? await this.ensureBridgeNetworkReady(safeBridge)
        : {
            ready: true,
            bridgeIp: null,
            prefixLen: 24,
            subnetCidr: null,
            hasDhcpServer: true,
            natConfigured: false,
            dnsRelayPort: 0,
          };
      activeBridgeInfo = bridgeInfo;

      if (bridgeInfo.ready) {
        lines.push(`lxc.net.0.type = veth`);
        lines.push(`lxc.net.0.link = ${safeBridge}`);
        lines.push(`lxc.net.0.flags = up`);
        lines.push(`lxc.net.0.name = eth0`);
        if (cfg.macAddress && /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(cfg.macAddress)) {
          lines.push(`lxc.net.0.hwaddr = ${cfg.macAddress}`);
        }

        if (cfg.ipv4Address) {
          configuredGuestIpv4 = cfg.ipv4Address.includes('/')
            ? cfg.ipv4Address
            : `${SafeValidators.ipv4(cfg.ipv4Address)}/24`;
        } else if (isSystemStore && !bridgeInfo.hasDhcpServer && bridgeInfo.bridgeIp) {
          configuredGuestIpv4 = await this.allocateAutoBridgeIpv4(
            safeName,
            safeBridge,
            bridgeInfo.bridgeIp,
            bridgeInfo.prefixLen
          );
        }

        if (configuredGuestIpv4) {
          lines.push(`lxc.net.0.ipv4.address = ${configuredGuestIpv4}`);
        }

        if (cfg.ipv4Gateway) {
          configuredGuestGateway =
            cfg.ipv4Gateway === 'auto' ? 'auto' : SafeValidators.ipv4(cfg.ipv4Gateway);
        } else if (configuredGuestIpv4) {
          if (bridgeInfo.bridgeIp) {
            configuredGuestGateway = bridgeInfo.bridgeIp;
          } else {
            const [ipOnly, pfxRaw] = configuredGuestIpv4.split('/');
            const pfx = parseInt(pfxRaw || '24', 10) || 24;
            const sub = computeIpv4SubnetCidr(ipOnly, pfx);
            if (sub) {
              const netUint = ipv4ToUint32(sub.split('/')[0]);
              const gwCandidate = uint32ToIpv4((netUint + 1) >>> 0);
              configuredGuestGateway = gwCandidate !== ipOnly ? gwCandidate : 'auto';
            } else {
              configuredGuestGateway = 'auto';
            }
          }
        }

        if (configuredGuestGateway) {
          lines.push(`lxc.net.0.ipv4.gateway = ${configuredGuestGateway}`);
        }
        if (cfg.ipv6Address) {
          lines.push(`lxc.net.0.ipv6.address = ${SafeValidators.ipv6OrCidr(cfg.ipv6Address)}`);
        }
      } else {
        // Host does not have bridge interface and kernel denied creating one (e.g. nested container host)
        lines.push(`lxc.net.0.type = none`);
      }
    }

    if (Array.isArray(cfg.mounts)) {
      for (const m of cfg.mounts) {
        const guestRel = SafeValidators.safeContainerSubpath(m.guestTarget).replace(/^\//, '');
        if (!guestRel) continue;
        const hostReal = path.resolve(m.hostSource);
        const roOpt = m.readOnly ? ',ro' : '';
        lines.push(`lxc.mount.entry = ${hostReal} ${guestRel} none bind,create=dir${roOpt} 0 0`);
      }
    }

    lines.push(markerEnd);
    privilegedFs.writeFileSync(
      configFile,
      `${stripped.trimEnd()}\n\n${lines.join('\n')}\n`,
      0o640
    );

    const dnsServers = this.buildEffectiveGuestDnsList(activeBridgeInfo);
    // Ensure guest /etc/resolv.conf + netplan/networkd/interfaces match so DNS & routing work immediately
    this.configureGuestNetworkingAndDns(safeName, {
      ipv4Cidr: configuredGuestIpv4,
      gateway: configuredGuestGateway && configuredGuestGateway !== 'auto' ? configuredGuestGateway : null,
      useDhcp: !configuredGuestIpv4,
      dnsServers,
    });
  }

  private buildEffectiveGuestDnsList(bridgeInfo?: LxcBridgeNetworkInfo | null): string[] {
    const base = resolveGuestDnsServers();
    if (bridgeInfo && bridgeInfo.bridgeIp && bridgeInfo.dnsRelayPort > 0) {
      return [
        bridgeInfo.bridgeIp,
        ...base.filter((ip) => ip !== bridgeInfo.bridgeIp),
      ].slice(0, 3);
    }
    return base.slice(0, 3);
  }

  private async prepareContainerNetworkPreStart(
    containerName: string,
    opts: { forceAutoIpIfRunningWithoutIp?: boolean; fallbackBridge?: string } = {}
  ): Promise<{
    bridge: string;
    ipv4Cidr: string | null;
    gateway: string | null;
    dnsServers: string[];
    dnsRelayPort: number;
    natConfigured: boolean;
  }> {
    const safeName = SafeValidators.containerName(containerName);
    const netCfg = this.readContainerNetFromConfig(safeName);
    const bridge = SafeValidators.bridgeOrIface(netCfg.bridge || opts.fallbackBridge || 'lxcbr0');
    let ipv4Cidr = netCfg.ipv4Cidr;
    let gateway = netCfg.gateway;
    let natConfigured = false;
    let activeBridgeInfo: LxcBridgeNetworkInfo | null = null;

    if (this.isSystemLxcStore()) {
      const bridgeInfo = await this.ensureBridgeNetworkReady(bridge);
      activeBridgeInfo = bridgeInfo;
      natConfigured = bridgeInfo.natConfigured;

      const configFile = path.join(this.getContainerDir(safeName), 'config');
      const curCfgText = privilegedFs.existsSync(configFile)
        ? privilegedFs.readTextSync(configFile)
        : '';
      const hadNetTypeNone = /^\s*lxc\.net\.0\.type\s*=\s*none\b/m.test(curCfgText);

      let runningWithoutIp = false;
      if (opts.forceAutoIpIfRunningWithoutIp && !ipv4Cidr) {
        const curInfo = await this.inspectContainer(safeName);
        if (curInfo.state === 'running' && curInfo.ips.length === 0) {
          runningWithoutIp = true;
        }
      }

      const needsAutoIp =
        !ipv4Cidr &&
        Boolean(bridgeInfo.bridgeIp) &&
        (!bridgeInfo.hasDhcpServer || runningWithoutIp);

      if (needsAutoIp && bridgeInfo.bridgeIp) {
        const autoIp = await this.allocateAutoBridgeIpv4(
          safeName,
          bridge,
          bridgeInfo.bridgeIp,
          bridgeInfo.prefixLen
        );
        if (autoIp) {
          ipv4Cidr = autoIp;
          gateway = bridgeInfo.bridgeIp;
        }
      }
      if (!gateway && bridgeInfo.bridgeIp) {
        gateway = bridgeInfo.bridgeIp;
      }

      if (bridgeInfo.ready && curCfgText && (hadNetTypeNone || !netCfg.bridge || needsAutoIp)) {
        const markerEnd = '# --- END HKVM MANAGED CONFIG ---';
        const netLines = [
          `lxc.net.0.type = veth`,
          `lxc.net.0.link = ${bridge}`,
          `lxc.net.0.flags = up`,
          `lxc.net.0.name = eth0`,
          ...(ipv4Cidr ? [`lxc.net.0.ipv4.address = ${ipv4Cidr}`] : []),
          ...(gateway ? [`lxc.net.0.ipv4.gateway = ${gateway}`] : []),
        ].join('\n');
        const cleaned = curCfgText
          .replace(/^\s*lxc\.net\.0(?:\.(?:type|link|flags|name|ipv4\.address|ipv4\.gateway))?\s*=.*$/gm, '')
          .replace(/\n{3,}/g, '\n\n');
        const updated = cleaned.includes(markerEnd)
          ? cleaned.replace(markerEnd, `${netLines}\n${markerEnd}`)
          : `${cleaned.trimEnd()}\n${netLines}\n`;
        privilegedFs.writeFileSync(configFile, updated, 0o640);
      }
    }

    const effectiveDns = this.buildEffectiveGuestDnsList(activeBridgeInfo);
    const dnsServers = this.configureGuestNetworkingAndDns(safeName, {
      ipv4Cidr,
      gateway: gateway && gateway !== 'auto' ? gateway : null,
      useDhcp: !ipv4Cidr,
      dnsServers: effectiveDns,
    });

    return {
      bridge,
      ipv4Cidr,
      gateway,
      dnsServers,
      dnsRelayPort: activeBridgeInfo?.dnsRelayPort || 0,
      natConfigured,
    };
  }

  /**
   * Ensures a running container's host-side `veth` peer is enslaved to `bridge` and `UP`
   * (recovers containers whose bridge was recreated or bounced while the container stayed running).
   */
  private async ensureRunningVethAttachedToBridge(
    containerName: string,
    bridge: string
  ): Promise<{ eth0Exists: boolean }> {
    if (!this.isSystemLxcStore() || !isBinaryAvailable('lxc-attach') || !isBinaryAvailable('ip')) {
      return { eth0Exists: true };
    }
    const safeName = SafeValidators.containerName(containerName);
    const safeBridge = SafeValidators.bridgeOrIface(bridge);
    const linkRes = await runAllowlistedCommand(
      'lxc-attach',
      [...this.lxcPathArgs(), '-n', safeName, '--', 'ip', '-o', 'link', 'show', 'dev', 'eth0'],
      { timeoutMs: 5000, asRoot: true }
    ).catch(() => null);

    if (!linkRes || linkRes.exitCode !== 0) {
      return { eth0Exists: false };
    }

    const peerMatch = linkRes.stdout.match(/\beth0@if(\d+):/);
    if (peerMatch) {
      const hostIfIndex = parseInt(peerMatch[1], 10);
      if (hostIfIndex > 0) {
        const hostLinks = await runAllowlistedCommand('ip', ['-o', 'link', 'show'], {
          timeoutMs: 4000,
        }).catch(() => null);
        if (hostLinks && hostLinks.stdout) {
          for (const line of hostLinks.stdout.split('\n')) {
            const m = line.match(new RegExp(`^${hostIfIndex}:\\s+([^:@\\s]+)`));
            if (m) {
              const hostVeth = SafeValidators.bridgeOrIface(m[1]);
              await runAllowlistedCommand(
                'ip',
                ['link', 'set', 'dev', hostVeth, 'master', safeBridge],
                { timeoutMs: 4000, asRoot: true }
              ).catch(() => undefined);
              await runAllowlistedCommand('ip', ['link', 'set', 'dev', hostVeth, 'up'], {
                timeoutMs: 4000,
                asRoot: true,
              }).catch(() => undefined);
              break;
            }
          }
        }
      }
    }
    return { eth0Exists: true };
  }

  private async applyLiveGuestNetworkIfNeeded(
    containerName: string,
    ipv4Cidr: string | null,
    gateway: string | null,
    dnsServers: string[],
    force = false
  ): Promise<boolean> {
    if (!isBinaryAvailable('lxc-attach')) return false;
    const safeName = SafeValidators.containerName(containerName);
    const info = await this.inspectContainer(safeName);
    if (info.state !== 'running') return false;

    const rootOpt = { timeoutMs: 8000, asRoot: this.needsRootForStore() || undefined };
    let applied = false;

    await runAllowlistedCommand(
      'lxc-attach',
      [...this.lxcPathArgs(), '-n', safeName, '--', 'ip', 'link', 'set', 'eth0', 'up'],
      rootOpt
    ).catch(() => undefined);

    if (ipv4Cidr) {
      const ipOnly = ipv4Cidr.split('/')[0];
      const cidrFull = ipv4Cidr.includes('/') ? ipv4Cidr : `${ipv4Cidr}/24`;
      if (force || !info.ips.includes(ipOnly)) {
        const addrRes = await runAllowlistedCommand(
          'lxc-attach',
          [...this.lxcPathArgs(), '-n', safeName, '--', 'ip', 'addr', 'replace', cidrFull, 'dev', 'eth0'],
          rootOpt
        ).catch(() => null);
        if (addrRes && addrRes.exitCode === 0) applied = true;
      }
      if (gateway && gateway !== 'auto') {
        const routeRes = await runAllowlistedCommand(
          'lxc-attach',
          [
            ...this.lxcPathArgs(),
            '-n',
            safeName,
            '--',
            'ip',
            'route',
            'replace',
            'default',
            'via',
            gateway,
            'dev',
            'eth0',
          ],
          rootOpt
        ).catch(() => null);
        if (routeRes && routeRes.exitCode === 0) applied = true;
      }
    } else if (gateway && gateway !== 'auto') {
      // Even when IP came via DHCP, ensure a default route exists on eth0
      const defCheck = await runAllowlistedCommand(
        'lxc-attach',
        [...this.lxcPathArgs(), '-n', safeName, '--', 'ip', '-4', 'route', 'show', 'default'],
        rootOpt
      ).catch(() => null);
      if (defCheck && defCheck.exitCode === 0 && !defCheck.stdout.trim()) {
        await runAllowlistedCommand(
          'lxc-attach',
          [
            ...this.lxcPathArgs(),
            '-n',
            safeName,
            '--',
            'ip',
            'route',
            'replace',
            'default',
            'via',
            gateway,
            'dev',
            'eth0',
          ],
          rootOpt
        ).catch(() => undefined);
      }
    }

    if (dnsServers.length > 0 && (force || this.isSystemLxcStore())) {
      const resolvBody = [
        '# Managed by HKVM Panel',
        ...dnsServers.map((ns) => `nameserver ${ns}`),
        'options timeout:2 attempts:2',
        '',
      ].join('\n');
      await runAllowlistedCommand(
        'lxc-attach',
        [...this.lxcPathArgs(), '-n', safeName, '--', 'rm', '-f', '/etc/resolv.conf'],
        rootOpt
      ).catch(() => undefined);
      const teeRes = await runAllowlistedCommand(
        'lxc-attach',
        [...this.lxcPathArgs(), '-n', safeName, '--', 'tee', '/etc/resolv.conf'],
        { ...rootOpt, stdinData: resolvBody }
      ).catch(() => null);
      if (teeRes && teeRes.exitCode === 0) applied = true;

      // Also push DNS servers into live systemd-resolved (if running inside Ubuntu/Debian guest)
      await runAllowlistedCommand(
        'lxc-attach',
        [...this.lxcPathArgs(), '-n', safeName, '--', 'resolvectl', 'dns', 'eth0', ...dnsServers],
        { ...rootOpt, timeoutMs: 4000 }
      ).catch(() => undefined);
      await runAllowlistedCommand(
        'lxc-attach',
        [...this.lxcPathArgs(), '-n', safeName, '--', 'resolvectl', 'flush-caches'],
        { ...rootOpt, timeoutMs: 4000 }
      ).catch(() => undefined);
    }

    return applied;
  }

  /**
   * Repairs host bridge/NAT/FORWARD/DNS-relay rules, upgrades `lxc.net.0.type = none` if needed,
   * auto-assigns a collision-free IPv4 if the container lacks one, re-enslaves orphaned host
   * `veth` peers (or restarts the container if `eth0` was never created), and applies IP/route/DNS
   * live inside the guest.
   */
  public async repairContainerNetworking(
    containerName: string,
    fallbackBridge = 'lxcbr0'
  ): Promise<LxcNetworkRepairResult> {
    const safeName = SafeValidators.containerName(containerName);
    let pre = await this.prepareContainerNetworkPreStart(safeName, {
      forceAutoIpIfRunningWithoutIp: true,
      fallbackBridge,
    });

    let restartedForVeth = false;
    const beforeInfo = await this.inspectContainer(safeName);
    if (beforeInfo.state === 'running' && this.isSystemLxcStore()) {
      const vethCheck = await this.ensureRunningVethAttachedToBridge(safeName, pre.bridge);
      if (!vethCheck.eth0Exists) {
        // Container booted previously without an eth0 veth device (e.g. lxc.net.0.type = none):
        // restart it once so liblxc attaches the newly configured veth pair to the bridge.
        await this.stopContainer(safeName).catch(() => undefined);
        await this.startContainer(safeName);
        restartedForVeth = true;
        pre = await this.prepareContainerNetworkPreStart(safeName, {
          forceAutoIpIfRunningWithoutIp: true,
          fallbackBridge,
        });
      }
    }

    const liveApplied = await this.applyLiveGuestNetworkIfNeeded(
      safeName,
      pre.ipv4Cidr,
      pre.gateway,
      pre.dnsServers,
      true
    );
    const info = await this.inspectContainer(safeName);
    const resolvedIp =
      info.ips[0] || (pre.ipv4Cidr ? pre.ipv4Cidr.split('/')[0] : null) || info.configuredIpv4 || null;
    return {
      containerName: safeName,
      state: info.state,
      bridge: pre.bridge,
      ipv4Address: resolvedIp,
      gateway: pre.gateway && pre.gateway !== 'auto' ? pre.gateway : null,
      dnsServers: pre.dnsServers,
      dnsRelayPort: pre.dnsRelayPort || undefined,
      natConfigured: pre.natConfigured,
      liveApplied: liveApplied || restartedForVeth,
      restartedForVeth,
    };
  }

  public async startContainer(containerName: string): Promise<void> {
    this.assertLxcInstalled();
    const safeName = SafeValidators.containerName(containerName);
    const info = await this.inspectContainer(safeName);
    if (info.state === 'running') return;
    if (info.state === 'frozen') {
      await this.unfreezeContainer(safeName);
      return;
    }

    if (this.isSystemLxcStore()) {
      await ensureLxcfsDaemonMounted().catch(() => false);
      ensureCgroupV2SubtreeDelegation();
    }
    await this.ensureExistingQuotaDiskMounted(safeName).catch(() => false);
    const preNet = await this.prepareContainerNetworkPreStart(safeName).catch(() => null);

    const logFile = privilegedFs.existsSync('/var/log/lxc')
      ? `/var/log/lxc/${safeName}.log`
      : path.join(this.getContainerDir(safeName), `${safeName}.log`);

    const runStart = () =>
      runAllowlistedCommand(
        'lxc-start',
        [...this.lxcPathArgs(), '-n', safeName, '-d', '-l', 'ERROR', '-o', logFile],
        {
          timeoutMs: 30_000,
          asRoot: this.needsRootForStore() || undefined,
        }
      );

    let res = await runStart();
    if (res.exitCode !== 0) {
      let logTail = '';
      if (privilegedFs.existsSync(logFile)) {
        try {
          logTail = privilegedFs.readTextSync(logFile).trim().split('\n').slice(-15).join('\n');
        } catch {
          // ignore
        }
      }

      const combinedDiag = `${res.stderr}\n${res.stdout}\n${logTail}`;
      const configFile = path.join(this.getContainerDir(safeName), 'config');
      if (/cgroup|limits|devices/i.test(combinedDiag) && privilegedFs.existsSync(configFile)) {
        try {
          let curCfg = privilegedFs.readTextSync(configFile);
          // Stage 1: Strip ONLY `devices.allow` / `devices.deny` first (eBPF device rules often fail in
          // nested Docker/Codespace cgroups, and must NEVER wipe out `memory.max` or `cpu.max`!)
          const withoutDevices = curCfg.replace(
            /^\s*lxc\.cgroup2?\.devices\.[a-zA-Z0-9_.-]+\s*=.*$/gm,
            ''
          );
          if (withoutDevices !== curCfg) {
            privilegedFs.writeFileSync(configFile, withoutDevices, 0o640);
            curCfg = withoutDevices;
            res = await runStart();
          }

          // Stage 2: If still failing, strip `cpuset.cpus` next while keeping `memory.max` and `cpu.max`
          if (res.exitCode !== 0) {
            const withoutCpuset = curCfg.replace(
              /^\s*lxc\.cgroup2?\.cpuset\.[a-zA-Z0-9_.-]+\s*=.*$/gm,
              ''
            );
            if (withoutCpuset !== curCfg) {
              privilegedFs.writeFileSync(configFile, withoutCpuset, 0o640);
              curCfg = withoutCpuset;
              res = await runStart();
            }
          }

          // Stage 3: Last-resort fallback on unprivileged kernels without any cgroup delegation
          if (res.exitCode !== 0) {
            const nextCfg = curCfg.replace(/^\s*lxc\.cgroup2?\.[a-zA-Z0-9_.-]+\s*=.*$/gm, '');
            if (nextCfg !== curCfg) {
              privilegedFs.writeFileSync(configFile, nextCfg, 0o640);
              res = await runStart();
            }
          }
        } catch {
          // ignore config rewrite error and surface original failure
        }
      }

      if (res.exitCode !== 0) {
        let logDetails = '';
        if (privilegedFs.existsSync(logFile)) {
          try {
            const tail = privilegedFs.readTextSync(logFile).trim().split('\n').slice(-12).join('\n');
            if (tail) logDetails = ` | Log: ${tail}`;
          } catch {
            // ignore
          }
        }
        throw new Error(`lxc-start failed: ${(res.stderr || res.stdout).trim()}${logDetails}`);
      }
    }

    if (preNet && this.isSystemLxcStore()) {
      await this.applyLiveGuestNetworkIfNeeded(
        safeName,
        preNet.ipv4Cidr,
        preNet.gateway,
        preNet.dnsServers,
        false
      ).catch(() => undefined);
    }
  }

  public async stopContainer(containerName: string, force = false): Promise<void> {
    this.assertLxcInstalled();
    const safeName = SafeValidators.containerName(containerName);
    const info = await this.inspectContainer(safeName);
    if (info.state === 'stopped' || info.state === 'missing') return;
    const args = force
      ? [...this.lxcPathArgs(), '-n', safeName, '-k']
      : [...this.lxcPathArgs(), '-n', safeName, '-t', '15'];
    const res = await runAllowlistedCommand('lxc-stop', args, {
      timeoutMs: 25_000,
      asRoot: this.needsRootForStore() || undefined,
    });
    if (res.exitCode !== 0) {
      const killRes = await runAllowlistedCommand(
        'lxc-stop',
        [...this.lxcPathArgs(), '-n', safeName, '-k'],
        {
          timeoutMs: 10_000,
          asRoot: this.needsRootForStore() || undefined,
        }
      );
      if (killRes.exitCode !== 0) {
        throw new Error(`lxc-stop failed: ${killRes.stderr || res.stderr}`);
      }
    }
  }

  public async restartContainer(containerName: string): Promise<void> {
    const safeName = SafeValidators.containerName(containerName);
    await this.stopContainer(safeName, false);
    await this.startContainer(safeName);
  }

  public async freezeContainer(containerName: string): Promise<void> {
    this.assertLxcInstalled();
    const safeName = SafeValidators.containerName(containerName);
    const res = await runAllowlistedCommand(
      'lxc-freeze',
      [...this.lxcPathArgs(), '-n', safeName],
      {
        timeoutMs: 15_000,
        asRoot: this.needsRootForStore() || undefined,
      }
    );
    if (res.exitCode !== 0) {
      throw new Error(`lxc-freeze failed: ${res.stderr || res.stdout}`);
    }
  }

  public async unfreezeContainer(containerName: string): Promise<void> {
    this.assertLxcInstalled();
    const safeName = SafeValidators.containerName(containerName);
    const res = await runAllowlistedCommand(
      'lxc-unfreeze',
      [...this.lxcPathArgs(), '-n', safeName],
      {
        timeoutMs: 15_000,
        asRoot: this.needsRootForStore() || undefined,
      }
    );
    if (res.exitCode !== 0) {
      throw new Error(`lxc-unfreeze failed: ${res.stderr || res.stdout}`);
    }
  }

  public async destroyContainer(containerName: string): Promise<void> {
    this.assertLxcInstalled();
    const safeName = SafeValidators.containerName(containerName);
    await this.stopContainer(safeName, true).catch(() => undefined);
    await this.unmountQuotaDiskIfMounted(safeName, true).catch(() => undefined);
    const res = await runAllowlistedCommand(
      'lxc-destroy',
      [...this.lxcPathArgs(), '-n', safeName, '-f'],
      {
        timeoutMs: 60_000,
        asRoot: this.needsRootForStore() || undefined,
      }
    );
    if (res.exitCode !== 0) {
      const ctDir = this.getContainerDir(safeName);
      if (!privilegedFs.existsSync(ctDir)) return;
      throw new Error(`lxc-destroy failed: ${res.stderr || res.stdout}`);
    }
  }

  public async reinstallContainer(spec: LxcCreateSpec): Promise<LxcContainerRuntimeInfo> {
    const safeName = SafeValidators.containerName(spec.containerName);
    const info = await this.inspectContainer(safeName);
    if (info.state !== 'missing') {
      await this.destroyContainer(safeName);
    } else {
      await this.unmountQuotaDiskIfMounted(safeName, true).catch(() => undefined);
    }
    return this.createContainer(spec);
  }

  public async updateContainerResources(
    containerName: string,
    update: LxcResourceUpdateSpec
  ): Promise<void> {
    const safeName = SafeValidators.containerName(containerName);
    await this.writeManagedConfigSection(safeName, update);

    // Apply live cgroup limits immediately if container is running
    const info = await this.inspectContainer(safeName);
    if (info.state === 'running' && isBinaryAvailable('lxc-cgroup')) {
      const isV2 = fs.existsSync('/sys/fs/cgroup/cgroup.controllers');
      const rootOpt = { timeoutMs: 5000, asRoot: this.needsRootForStore() || undefined };
      if (update.ramMb) {
        const key = isV2 ? 'memory.max' : 'memory.limit_in_bytes';
        await runAllowlistedCommand(
          'lxc-cgroup',
          [...this.lxcPathArgs(), '-n', safeName, key, `${Math.max(64, update.ramMb)}M`],
          rootOpt
        ).catch(() => undefined);
      }
      if (update.swapMb !== undefined && isV2 && isCgroupV2SwapSupported()) {
        await runAllowlistedCommand(
          'lxc-cgroup',
          [...this.lxcPathArgs(), '-n', safeName, 'memory.swap.max', `${Math.max(0, update.swapMb)}M`],
          rootOpt
        ).catch(() => undefined);
      }
      if (update.cpuCores) {
        const pct = Math.min(100, Math.max(5, Number(update.cpuLimitPercent || 100)));
        const quotaUs = Math.round(Math.max(1, update.cpuCores) * 100_000 * (pct / 100));
        if (isV2) {
          await runAllowlistedCommand(
            'lxc-cgroup',
            [...this.lxcPathArgs(), '-n', safeName, 'cpu.max', `${quotaUs} 100000`],
            rootOpt
          ).catch(() => undefined);
        } else {
          await runAllowlistedCommand(
            'lxc-cgroup',
            [...this.lxcPathArgs(), '-n', safeName, 'cpu.cfs_quota_us', `${quotaUs}`],
            rootOpt
          ).catch(() => undefined);
        }

        const cpuset = selectContainerCpuset(
          safeName,
          update.cpuCores,
          readEffectiveHostCpuIds(),
          update.cpuPinning
        );
        if (cpuset) {
          await runAllowlistedCommand(
            'lxc-cgroup',
            [...this.lxcPathArgs(), '-n', safeName, 'cpuset.cpus', cpuset],
            rootOpt
          ).catch(() => undefined);
        }
      }
    }

    // Apply disk quota volume provisioning or live online resize (`truncate` + `losetup -c` + `resize2fs`)
    if (update.diskGb && update.diskGb >= 1 && this.isSystemLxcStore()) {
      const hasLoopAlready = privilegedFs.existsSync(this.getQuotaDiskImagePath(safeName));
      if (hasLoopAlready) {
        await this.ensureContainerQuotaDisk(safeName, update.diskGb).catch(() => false);
      } else {
        // Existing plain `dir` container without a quota volume yet: convert cleanly (brief stop/start if running)
        const wasRunning = info.state === 'running';
        if (wasRunning) {
          await this.stopContainer(safeName).catch(() => undefined);
        }
        await this.ensureContainerQuotaDisk(safeName, update.diskGb).catch(() => false);
        if (wasRunning) {
          await this.startContainer(safeName).catch(() => undefined);
        }
      }
    }
  }

  /**
   * Resets root password inside container using `chpasswd` over stdin (`shell: false`),
   * with offline `/etc/shadow` SHA-512 hash fallback when container is stopped.
   * Zero shell interpolation of password characters.
   */
  public async setRootPassword(containerName: string, newPassword: string): Promise<void> {
    const safeName = SafeValidators.containerName(containerName);
    if (!newPassword || newPassword.includes('\n') || newPassword.includes('\0')) {
      throw new Error('Password contains invalid control characters.');
    }

    const info = await this.inspectContainer(safeName);
    if (info.state !== 'running') {
      const updatedOffline = await this.applyOfflineRootPasswordHash(safeName, newPassword);
      if (updatedOffline) return;
      throw new Error(`Container "${safeName}" is not running and /etc/shadow could not be updated.`);
    }

    this.assertLxcInstalled();
    const res = await runAllowlistedCommand(
      'lxc-attach',
      [...this.lxcPathArgs(), '-n', safeName, '--', 'chpasswd'],
      {
        stdinData: `root:${newPassword}\n`,
        timeoutMs: 10_000,
        asRoot: this.needsRootForStore() || undefined,
      }
    );
    if (res.exitCode !== 0) {
      const fallback = await this.applyOfflineRootPasswordHash(safeName, newPassword);
      if (!fallback) {
        throw new Error(`Failed to update container root password: ${res.stderr || res.stdout}`);
      }
    }
  }

  public async injectSshPublicKey(containerName: string, publicKey: string): Promise<void> {
    const safeName = SafeValidators.containerName(containerName);
    const trimmed = publicKey.trim();
    if (!/^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521))\s+[A-Za-z0-9+/=]+/.test(trimmed)) {
      throw new Error('Invalid OpenSSH public key format.');
    }
    const rootfs = this.getRootfsDir(safeName);
    if (!privilegedFs.existsSync(rootfs)) {
      throw new Error(`Container rootfs does not exist at ${rootfs}`);
    }
    const sshDir = this.resolveConfinedRootfsPath(safeName, '/root/.ssh');
    privilegedFs.mkdirpSync(sshDir, 0o700);
    const authKeysPath = path.join(sshDir, 'authorized_keys');
    const existing = privilegedFs.existsSync(authKeysPath)
      ? privilegedFs.readTextSync(authKeysPath)
      : '';
    if (!existing.includes(trimmed)) {
      const nextContent = existing
        ? `${existing.replace(/\n*$/, '\n')}${trimmed}\n`
        : `${trimmed}\n`;
      privilegedFs.writeFileSync(authKeysPath, nextContent, 0o600);
    }
  }

  public async getContainerProcesses(
    containerName: string
  ): Promise<Array<{ pid: string; user: string; cpu: string; mem: string; command: string }>> {
    this.assertLxcInstalled();
    const safeName = SafeValidators.containerName(containerName);
    const res = await runAllowlistedCommand(
      'lxc-attach',
      [
        ...this.lxcPathArgs(),
        '-n',
        safeName,
        '--',
        'ps',
        '-eo',
        'pid,user,pcpu,pmem,comm',
        '--no-headers',
      ],
      {
        timeoutMs: 8000,
        asRoot: this.needsRootForStore() || undefined,
      }
    );
    if (res.exitCode !== 0) return [];
    return res.stdout
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        const cols = line.trim().split(/\s+/);
        return {
          pid: cols[0] || '',
          user: cols[1] || '',
          cpu: cols[2] || '0.0',
          mem: cols[3] || '0.0',
          command: cols.slice(4).join(' '),
        };
      });
  }

  public async getContainerLogs(containerName: string, maxLines = 200): Promise<string> {
    const safeName = SafeValidators.containerName(containerName);
    const candidates = [
      `/var/log/lxc/${safeName}.log`,
      path.join(this.getContainerDir(safeName), `${safeName}.log`),
    ];
    for (const file of candidates) {
      if (privilegedFs.existsSync(file)) {
        try {
          const content = privilegedFs.readTextSync(file);
          return content.split('\n').slice(-maxLines).join('\n');
        } catch {
          // ignore unreadable log candidate
        }
      }
    }
    return '';
  }

  /**
   * Resolves a user-supplied path strictly within `<lxcBaseDir>/<container>/rootfs`,
   * blocking both `..` traversal and symlink escapes outside `rootfs`.
   */
  public resolveConfinedRootfsPath(containerName: string, subPath: string): string {
    const safeName = SafeValidators.containerName(containerName);
    const rootfs = path.resolve(this.getRootfsDir(safeName));
    if (!privilegedFs.existsSync(rootfs)) {
      throw new Error(`Container rootfs does not exist for "${safeName}".`);
    }
    const realRootfs = privilegedFs.realpathSync(rootfs);
    const safeRel = SafeValidators.safeContainerSubpath(subPath).replace(/^\//, '');
    const joined = path.resolve(realRootfs, safeRel);

    if (joined !== realRootfs && !joined.startsWith(realRootfs + path.sep)) {
      throw new Error('Path traversal outside container rootfs denied.');
    }

    // Walk every existing path segment from rootfs downward to block intermediate or broken symlink escapes
    const segments = safeRel.split('/').filter(Boolean);
    let cursor = realRootfs;
    for (const seg of segments) {
      cursor = path.join(cursor, seg);
      let meta: ReturnType<typeof privilegedFs.lstatMetaSync>;
      try {
        meta = privilegedFs.lstatMetaSync(cursor);
      } catch {
        break;
      }
      if (meta.isSymbolicLink) {
        let realTarget: string;
        try {
          realTarget = privilegedFs.realpathSync(cursor);
        } catch {
          throw new Error('Symlink escape outside container rootfs denied.');
        }
        if (realTarget !== realRootfs && !realTarget.startsWith(realRootfs + path.sep)) {
          throw new Error('Symlink escape outside container rootfs denied.');
        }
      }
    }

    return joined;
  }

  public listRootfsDirectory(
    containerName: string,
    subPath = '/'
  ): Array<{ name: string; path: string; isDirectory: boolean; size: number; modifiedAt: string }> {
    const targetDir = this.resolveConfinedRootfsPath(containerName, subPath);
    const cleanRel = SafeValidators.safeContainerSubpath(subPath);
    const names = privilegedFs.readdirNamesSync(targetDir);
    return names.map((name) => {
      const childPath = path.join(targetDir, name);
      let size = 0;
      let modifiedAt = new Date(0).toISOString();
      let isDirectory = false;
      try {
        const st = privilegedFs.lstatMetaSync(childPath);
        size = st.size;
        modifiedAt = st.mtimeIso;
        isDirectory = st.isDirectory;
      } catch {
        // ignore broken symlink stat
      }
      return {
        name,
        path: cleanRel === '/' ? `/${name}` : `${cleanRel}/${name}`,
        isDirectory,
        size,
        modifiedAt,
      };
    });
  }

  public readRootfsFile(
    containerName: string,
    subPath: string,
    maxBytes = 2 * 1024 * 1024
  ): Buffer {
    const target = this.resolveConfinedRootfsPath(containerName, subPath);
    const st = privilegedFs.lstatMetaSync(target);
    if (st.isSymbolicLink || !st.isFile) {
      throw new Error('Target is not a regular file.');
    }
    if (st.size > maxBytes) {
      throw new Error(`File exceeds maximum inline read size (${maxBytes} bytes).`);
    }
    return privilegedFs.readFileSync(target, maxBytes);
  }

  public writeRootfsFile(containerName: string, subPath: string, data: Buffer | string): void {
    const target = this.resolveConfinedRootfsPath(containerName, subPath);
    if (privilegedFs.existsSync(target) && privilegedFs.lstatMetaSync(target).isSymbolicLink) {
      throw new Error('Refusing to overwrite symlink inside container rootfs.');
    }
    privilegedFs.mkdirpSync(path.dirname(target));
    privilegedFs.writeFileSync(target, data);
  }

  public deleteRootfsEntry(containerName: string, subPath: string): void {
    const cleanRel = SafeValidators.safeContainerSubpath(subPath);
    if (cleanRel === '/') {
      throw new Error('Refusing to delete container root directory.');
    }
    const target = this.resolveConfinedRootfsPath(containerName, cleanRel);
    privilegedFs.rmRecursiveSync(target);
  }
}
