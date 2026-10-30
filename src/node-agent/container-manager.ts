import fs from 'fs';
import path from 'path';
import { isBinaryAvailable, runAllowlistedCommand } from './command-runner';
import { SafeValidators } from '../security/middleware';

export interface LxcCreateSpec {
  containerName: string;
  hostname?: string;
  distro: string;
  release: string;
  arch?: string;
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
  mounts?: Array<{ hostSource: string; guestTarget: string; readOnly?: boolean }>;
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
}

const DEFAULT_LXC_BASE = process.env.HKVM_LXC_PATH || '/var/lib/lxc';

export class LxcContainerManager {
  private lxcBaseDir: string;

  constructor(lxcBaseDir = DEFAULT_LXC_BASE) {
    this.lxcBaseDir = lxcBaseDir;
  }

  public getContainerDir(containerName: string): string {
    const safeName = SafeValidators.containerName(containerName);
    return path.join(this.lxcBaseDir, safeName);
  }

  public getRootfsDir(containerName: string): string {
    return path.join(this.getContainerDir(containerName), 'rootfs');
  }

  private assertLxcInstalled(): void {
    if (!isBinaryAvailable('lxc-info') || !isBinaryAvailable('lxc-create')) {
      throw new Error(
        'LXC userland utilities (lxc-create / lxc-start / lxc-info) are not installed on this host.'
      );
    }
  }

  public async listContainers(): Promise<LxcContainerRuntimeInfo[]> {
    if (!isBinaryAvailable('lxc-ls')) {
      return [];
    }
    const lsRes = await runAllowlistedCommand('lxc-ls', ['-1'], { timeoutMs: 10_000 });
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

  public async inspectContainer(containerName: string): Promise<LxcContainerRuntimeInfo> {
    const safeName = SafeValidators.containerName(containerName);
    if (!isBinaryAvailable('lxc-info')) {
      const existsOnDisk = fs.existsSync(path.join(this.lxcBaseDir, safeName, 'config'));
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
        diskUsedBytes: this.measureDirBytesFast(path.join(this.lxcBaseDir, safeName, 'rootfs')),
      };
    }

    const res = await runAllowlistedCommand('lxc-info', ['-n', safeName], { timeoutMs: 10_000 });
    if (res.exitCode !== 0) {
      return {
        name: safeName,
        state: 'missing',
        pid: null,
        ips: [],
        cpuUseSeconds: 0,
        memoryBytes: 0,
        swapBytes: 0,
        rxBytes: 0,
        txBytes: 0,
        diskUsedBytes: 0,
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
    };
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
      const st = fs.statSync(dirPath);
      return st.size;
    } catch {
      return 0;
    }
  }

  private async getRootfsUsedBytes(containerName: string): Promise<number> {
    const rootfs = this.getRootfsDir(containerName);
    if (!fs.existsSync(rootfs)) return 0;
    if (isBinaryAvailable('du')) {
      const res = await runAllowlistedCommand('du', ['-sb', rootfs], { timeoutMs: 8000 });
      if (res.exitCode === 0) {
        const bytes = parseInt(res.stdout.trim().split(/\s+/)[0] || '0', 10);
        if (!Number.isNaN(bytes)) return bytes;
      }
    }
    return 0;
  }

  public async createContainer(spec: LxcCreateSpec): Promise<LxcContainerRuntimeInfo> {
    this.assertLxcInstalled();
    const safeName = SafeValidators.containerName(spec.containerName);
    const distro = spec.distro.replace(/[^a-zA-Z0-9_.-]/g, '');
    const release = spec.release.replace(/[^a-zA-Z0-9_.-]/g, '');
    const arch = (spec.arch || 'amd64').replace(/[^a-zA-Z0-9_.-]/g, '');
    const backing = spec.backingStore || 'dir';

    const args = ['-n', safeName, '-B', backing, '-t', 'download', '--', '-d', distro, '-r', release, '-a', arch];
    const createRes = await runAllowlistedCommand('lxc-create', args, { timeoutMs: 600_000 });
    if (createRes.exitCode !== 0) {
      throw new Error(`lxc-create failed (${createRes.exitCode}): ${createRes.stderr || createRes.stdout}`);
    }

    await this.writeManagedConfigSection(safeName, {
      hostname: spec.hostname || safeName,
      cpuCores: spec.cpuCores,
      cpuShares: spec.cpuShares ?? 1024,
      cpuLimitPercent: spec.cpuLimitPercent ?? 100,
      cpuPinning: spec.cpuPinning || null,
      ramMb: spec.ramMb,
      swapMb: spec.swapMb ?? 512,
      nesting: spec.nesting !== false,
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

    await this.startContainer(safeName);

    if (spec.rootPassword) {
      await this.setRootPassword(safeName, spec.rootPassword);
    }

    if (spec.sshPublicKeys && spec.sshPublicKeys.length > 0) {
      for (const pubKey of spec.sshPublicKeys) {
        await this.injectSshPublicKey(safeName, pubKey);
      }
    }

    return this.inspectContainer(safeName);
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
    if (!fs.existsSync(configFile)) {
      throw new Error(`Container config not found at ${configFile}`);
    }

    const existing = fs.readFileSync(configFile, 'utf8');
    const markerStart = '# --- BEGIN HKVM MANAGED CONFIG ---';
    const markerEnd = '# --- END HKVM MANAGED CONFIG ---';

    const stripped = existing.replace(
      new RegExp(`${markerStart}[\\s\\S]*?${markerEnd}\\n?`, 'g'),
      ''
    );

    const isCgroupV2 = fs.existsSync('/sys/fs/cgroup/cgroup.controllers');
    const lines: string[] = [markerStart];

    if (cfg.hostname) {
      const cleanHost = cfg.hostname.replace(/[^a-zA-Z0-9.-]/g, '').slice(0, 63);
      if (cleanHost) lines.push(`lxc.uts.name = ${cleanHost}`);
    }

    if (cfg.autostart !== undefined) {
      lines.push(`lxc.start.auto = ${cfg.autostart ? 1 : 0}`);
    }

    if (cfg.nesting) {
      lines.push('lxc.include = /usr/share/lxc/config/nesting.conf');
    }

    if (cfg.apparmorProfile) {
      const cleanProfile = cfg.apparmorProfile.replace(/[^a-zA-Z0-9_.-]/g, '');
      if (cleanProfile) lines.push(`lxc.apparmor.profile = ${cleanProfile}`);
    }

    const cores = Math.max(1, Number(cfg.cpuCores || 1));
    const pct = Math.min(100, Math.max(5, Number(cfg.cpuLimitPercent || 100)));
    const quotaUs = Math.round(cores * 100_000 * (pct / 100));

    if (isCgroupV2) {
      lines.push(`lxc.cgroup2.cpu.max = ${quotaUs} 100000`);
      if (cfg.cpuShares) {
        const weight = Math.min(10000, Math.max(1, Math.round((cfg.cpuShares / 1024) * 100)));
        lines.push(`lxc.cgroup2.cpu.weight = ${weight}`);
      }
      if (cfg.cpuPinning && /^[0-9,-]+$/.test(cfg.cpuPinning)) {
        lines.push(`lxc.cgroup2.cpuset.cpus = ${cfg.cpuPinning}`);
      }
      if (cfg.ramMb) {
        lines.push(`lxc.cgroup2.memory.max = ${Math.max(64, cfg.ramMb)}M`);
      }
      if (cfg.swapMb !== undefined) {
        lines.push(`lxc.cgroup2.memory.swap.max = ${Math.max(0, cfg.swapMb)}M`);
      }
    } else {
      lines.push(`lxc.cgroup.cpu.cfs_period_us = 100000`);
      lines.push(`lxc.cgroup.cpu.cfs_quota_us = ${quotaUs}`);
      if (cfg.cpuShares) {
        lines.push(`lxc.cgroup.cpu.shares = ${Math.max(64, cfg.cpuShares)}`);
      }
      if (cfg.cpuPinning && /^[0-9,-]+$/.test(cfg.cpuPinning)) {
        lines.push(`lxc.cgroup.cpuset.cpus = ${cfg.cpuPinning}`);
      }
      if (cfg.ramMb) {
        lines.push(`lxc.cgroup.memory.limit_in_bytes = ${Math.max(64, cfg.ramMb)}M`);
      }
    }

    if (cfg.bridge) {
      const safeBridge = SafeValidators.bridgeOrIface(cfg.bridge);
      lines.push(`lxc.net.0.type = veth`);
      lines.push(`lxc.net.0.link = ${safeBridge}`);
      lines.push(`lxc.net.0.flags = up`);
      if (cfg.macAddress && /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(cfg.macAddress)) {
        lines.push(`lxc.net.0.hwaddr = ${cfg.macAddress}`);
      }
      if (cfg.ipv4Address) {
        const addrPart = cfg.ipv4Address.includes('/') ? cfg.ipv4Address : `${SafeValidators.ipv4(cfg.ipv4Address)}/24`;
        lines.push(`lxc.net.0.ipv4.address = ${addrPart}`);
      }
      if (cfg.ipv4Gateway) {
        lines.push(`lxc.net.0.ipv4.gateway = ${cfg.ipv4Gateway === 'auto' ? 'auto' : SafeValidators.ipv4(cfg.ipv4Gateway)}`);
      }
      if (cfg.ipv6Address) {
        lines.push(`lxc.net.0.ipv6.address = ${SafeValidators.ipv6OrCidr(cfg.ipv6Address)}`);
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
    fs.writeFileSync(configFile, `${stripped.trimEnd()}\n\n${lines.join('\n')}\n`, 'utf8');
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
    const res = await runAllowlistedCommand('lxc-start', ['-n', safeName, '-d'], { timeoutMs: 30_000 });
    if (res.exitCode !== 0) {
      throw new Error(`lxc-start failed: ${res.stderr || res.stdout}`);
    }
  }

  public async stopContainer(containerName: string, force = false): Promise<void> {
    this.assertLxcInstalled();
    const safeName = SafeValidators.containerName(containerName);
    const info = await this.inspectContainer(safeName);
    if (info.state === 'stopped' || info.state === 'missing') return;
    const args = force ? ['-n', safeName, '-k'] : ['-n', safeName, '-t', '15'];
    const res = await runAllowlistedCommand('lxc-stop', args, { timeoutMs: 25_000 });
    if (res.exitCode !== 0) {
      const killRes = await runAllowlistedCommand('lxc-stop', ['-n', safeName, '-k'], { timeoutMs: 10_000 });
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
    const res = await runAllowlistedCommand('lxc-freeze', ['-n', safeName], { timeoutMs: 15_000 });
    if (res.exitCode !== 0) {
      throw new Error(`lxc-freeze failed: ${res.stderr || res.stdout}`);
    }
  }

  public async unfreezeContainer(containerName: string): Promise<void> {
    this.assertLxcInstalled();
    const safeName = SafeValidators.containerName(containerName);
    const res = await runAllowlistedCommand('lxc-unfreeze', ['-n', safeName], { timeoutMs: 15_000 });
    if (res.exitCode !== 0) {
      throw new Error(`lxc-unfreeze failed: ${res.stderr || res.stdout}`);
    }
  }

  public async destroyContainer(containerName: string): Promise<void> {
    this.assertLxcInstalled();
    const safeName = SafeValidators.containerName(containerName);
    await this.stopContainer(safeName, true).catch(() => undefined);
    const res = await runAllowlistedCommand('lxc-destroy', ['-n', safeName, '-f'], { timeoutMs: 60_000 });
    if (res.exitCode !== 0) {
      throw new Error(`lxc-destroy failed: ${res.stderr || res.stdout}`);
    }
  }

  public async reinstallContainer(spec: LxcCreateSpec): Promise<LxcContainerRuntimeInfo> {
    const safeName = SafeValidators.containerName(spec.containerName);
    const info = await this.inspectContainer(safeName);
    if (info.state !== 'missing') {
      await this.destroyContainer(safeName);
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
      if (update.ramMb) {
        const key = isV2 ? 'memory.max' : 'memory.limit_in_bytes';
        await runAllowlistedCommand('lxc-cgroup', ['-n', safeName, key, `${Math.max(64, update.ramMb)}M`], {
          timeoutMs: 5000,
        });
      }
      if (update.cpuCores) {
        const pct = Math.min(100, Math.max(5, Number(update.cpuLimitPercent || 100)));
        const quotaUs = Math.round(Math.max(1, update.cpuCores) * 100_000 * (pct / 100));
        if (isV2) {
          await runAllowlistedCommand('lxc-cgroup', ['-n', safeName, 'cpu.max', `${quotaUs} 100000`], {
            timeoutMs: 5000,
          });
        } else {
          await runAllowlistedCommand('lxc-cgroup', ['-n', safeName, 'cpu.cfs_quota_us', `${quotaUs}`], {
            timeoutMs: 5000,
          });
        }
      }
    }
  }

  /**
   * Resets root password inside container using `chpasswd` over stdin (`shell: false`).
   * Zero shell interpolation of password characters.
   */
  public async setRootPassword(containerName: string, newPassword: string): Promise<void> {
    this.assertLxcInstalled();
    const safeName = SafeValidators.containerName(containerName);
    if (!newPassword || newPassword.includes('\n') || newPassword.includes('\0')) {
      throw new Error('Password contains invalid control characters.');
    }
    const res = await runAllowlistedCommand(
      'lxc-attach',
      ['-n', safeName, '--', '/usr/sbin/chpasswd'],
      {
        stdinData: `root:${newPassword}\n`,
        timeoutMs: 10_000,
      }
    );
    if (res.exitCode !== 0) {
      throw new Error(`Failed to update container root password: ${res.stderr || res.stdout}`);
    }
  }

  public async injectSshPublicKey(containerName: string, publicKey: string): Promise<void> {
    const safeName = SafeValidators.containerName(containerName);
    const trimmed = publicKey.trim();
    if (!/^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521))\s+[A-Za-z0-9+/=]+/.test(trimmed)) {
      throw new Error('Invalid OpenSSH public key format.');
    }
    const rootfs = this.getRootfsDir(safeName);
    if (!fs.existsSync(rootfs)) {
      throw new Error(`Container rootfs does not exist at ${rootfs}`);
    }
    const sshDir = this.resolveConfinedRootfsPath(safeName, '/root/.ssh');
    fs.mkdirSync(sshDir, { recursive: true, mode: 0o700 });
    const authKeysPath = path.join(sshDir, 'authorized_keys');
    const existing = fs.existsSync(authKeysPath) ? fs.readFileSync(authKeysPath, 'utf8') : '';
    if (!existing.includes(trimmed)) {
      fs.appendFileSync(authKeysPath, `${trimmed}\n`, { mode: 0o600 });
    }
  }

  public async getContainerProcesses(
    containerName: string
  ): Promise<Array<{ pid: string; user: string; cpu: string; mem: string; command: string }>> {
    this.assertLxcInstalled();
    const safeName = SafeValidators.containerName(containerName);
    const res = await runAllowlistedCommand(
      'lxc-attach',
      ['-n', safeName, '--', 'ps', '-eo', 'pid,user,pcpu,pmem,comm', '--no-headers'],
      { timeoutMs: 8000 }
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
      if (fs.existsSync(file)) {
        const content = fs.readFileSync(file, 'utf8');
        return content.split('\n').slice(-maxLines).join('\n');
      }
    }
    return '';
  }

  /**
   * Resolves a user-supplied path strictly within `/var/lib/lxc/<container>/rootfs`,
   * blocking both `..` traversal and symlink escapes outside `rootfs`.
   */
  public resolveConfinedRootfsPath(containerName: string, subPath: string): string {
    const safeName = SafeValidators.containerName(containerName);
    const rootfs = path.resolve(this.getRootfsDir(safeName));
    if (!fs.existsSync(rootfs)) {
      throw new Error(`Container rootfs does not exist for "${safeName}".`);
    }
    const realRootfs = fs.realpathSync(rootfs);
    const safeRel = SafeValidators.safeContainerSubpath(subPath).replace(/^\//, '');
    const joined = path.resolve(realRootfs, safeRel);

    if (joined !== realRootfs && !joined.startsWith(realRootfs + path.sep)) {
      throw new Error('Path traversal outside container rootfs denied.');
    }

    // Check existing parent/target realpath to prevent symlink escape
    const checkTarget = fs.existsSync(joined) ? joined : path.dirname(joined);
    if (fs.existsSync(checkTarget)) {
      const realTarget = fs.realpathSync(checkTarget);
      if (realTarget !== realRootfs && !realTarget.startsWith(realRootfs + path.sep)) {
        throw new Error('Symlink escape outside container rootfs denied.');
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
    const entries = fs.readdirSync(targetDir, { withFileTypes: true });
    return entries.map((ent) => {
      const childPath = path.join(targetDir, ent.name);
      let size = 0;
      let modifiedAt = new Date(0).toISOString();
      try {
        const st = fs.lstatSync(childPath);
        size = st.size;
        modifiedAt = st.mtime.toISOString();
      } catch {
        // ignore broken symlink stat
      }
      return {
        name: ent.name,
        path: cleanRel === '/' ? `/${ent.name}` : `${cleanRel}/${ent.name}`,
        isDirectory: ent.isDirectory(),
        size,
        modifiedAt,
      };
    });
  }

  public readRootfsFile(containerName: string, subPath: string, maxBytes = 2 * 1024 * 1024): Buffer {
    const target = this.resolveConfinedRootfsPath(containerName, subPath);
    const st = fs.lstatSync(target);
    if (st.isSymbolicLink() || !st.isFile()) {
      throw new Error('Target is not a regular file.');
    }
    if (st.size > maxBytes) {
      throw new Error(`File exceeds maximum inline read size (${maxBytes} bytes).`);
    }
    return fs.readFileSync(target);
  }

  public writeRootfsFile(containerName: string, subPath: string, data: Buffer | string): void {
    const target = this.resolveConfinedRootfsPath(containerName, subPath);
    if (fs.existsSync(target) && fs.lstatSync(target).isSymbolicLink()) {
      throw new Error('Refusing to overwrite symlink inside container rootfs.');
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, data);
  }

  public deleteRootfsEntry(containerName: string, subPath: string): void {
    const cleanRel = SafeValidators.safeContainerSubpath(subPath);
    if (cleanRel === '/') {
      throw new Error('Refusing to delete container root directory.');
    }
    const target = this.resolveConfinedRootfsPath(containerName, cleanRel);
    fs.rmSync(target, { recursive: true, force: false });
  }
}
