import { execFile, spawn } from 'child_process';
import fs from 'fs';
import path from 'path';

export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  durationMs: number;
}

export interface CommandOptions {
  timeoutMs?: number;
  maxOutputBytes?: number;
  stdinData?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}

/**
 * Explicit allowlist of system binaries the HKVM Node Agent and Virtualization Adapters may invoke.
 * Commands are ALWAYS executed via `spawn` / `execFile` with argument arrays (`shell: false`).
 */
const ALLOWED_BINARIES = new Set([
  // LXC native tools
  'lxc-create',
  'lxc-start',
  'lxc-stop',
  'lxc-destroy',
  'lxc-info',
  'lxc-ls',
  'lxc-freeze',
  'lxc-unfreeze',
  'lxc-attach',
  'lxc-snapshot',
  'lxc-cgroup',
  'lxc-checkconfig',
  'lxc-config',
  'lxc-autostart',
  // QEMU / KVM tools
  'qemu-system-x86_64',
  'qemu-system-aarch64',
  'qemu-img',
  'cloud-localds',
  'genisoimage',
  'mkisofs',
  // Storage & archive tools
  'df',
  'du',
  'tar',
  'gzip',
  'sha256sum',
  'lvcreate',
  'lvremove',
  'lvextend',
  'lvs',
  'vgs',
  'zfs',
  'zpool',
  'btrfs',
  'truncate',
  'mkfs.ext4',
  'resize2fs',
  // Linux networking & firewall tools
  'ip',
  'bridge',
  'iptables',
  'iptables-save',
  'iptables-restore',
  'ip6tables',
  'nft',
  'tc',
  'sysctl',
  // System inspection tools
  'uname',
  'uptime',
  'hostname',
  'ps',
  'free',
  'which',
  'openssl',
]);

const SEARCH_DIRS = [
  '/usr/local/sbin',
  '/usr/local/bin',
  '/usr/sbin',
  '/usr/bin',
  '/sbin',
  '/bin',
];

export function resolveBinaryPath(binaryName: string): string | null {
  const clean = path.basename(binaryName);
  if (!ALLOWED_BINARIES.has(clean)) {
    throw new Error(`Security policy violation: binary "${binaryName}" is not in the allowlist.`);
  }
  for (const dir of SEARCH_DIRS) {
    const candidate = path.join(dir, clean);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      // continue searching
    }
  }
  return null;
}

export function isBinaryAvailable(binaryName: string): boolean {
  try {
    return resolveBinaryPath(binaryName) !== null;
  } catch {
    return false;
  }
}

/**
 * Safely executes an allowlisted binary with `shell: false`, optional stdin pipe,
 * hard timeout, and bounded stdout/stderr buffers.
 */
export async function runAllowlistedCommand(
  binaryName: string,
  args: string[] = [],
  options: CommandOptions = {}
): Promise<CommandResult> {
  const cleanName = path.basename(binaryName);
  if (!ALLOWED_BINARIES.has(cleanName)) {
    throw new Error(`Security policy violation: binary "${binaryName}" is not in the allowlist.`);
  }

  for (const arg of args) {
    if (typeof arg !== 'string' || arg.includes('\0')) {
      throw new Error('Invalid command argument (null byte or non-string detected).');
    }
  }

  const resolved = resolveBinaryPath(cleanName);
  if (!resolved) {
    return {
      exitCode: 127,
      stdout: '',
      stderr: `Required host binary "${cleanName}" is not installed on this node.`,
      timedOut: false,
      durationMs: 0,
    };
  }

  const timeoutMs = options.timeoutMs ?? 60_000;
  const maxBytes = options.maxOutputBytes ?? 4 * 1024 * 1024;
  const startedAt = Date.now();

  return new Promise<CommandResult>((resolve) => {
    const child = spawn(resolved, args, {
      cwd: options.cwd || '/',
      env: {
        PATH: SEARCH_DIRS.join(':'),
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8',
        ...(options.env || {}),
      },
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdoutBuf = '';
    let stderrBuf = '';
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill('SIGKILL');
      } catch {
        // ignore
      }
    }, timeoutMs);

    child.stdout.on('data', (chunk: Buffer) => {
      if (stdoutBuf.length < maxBytes) {
        stdoutBuf += chunk.toString('utf8').slice(0, maxBytes - stdoutBuf.length);
      }
    });

    child.stderr.on('data', (chunk: Buffer) => {
      if (stderrBuf.length < maxBytes) {
        stderrBuf += chunk.toString('utf8').slice(0, maxBytes - stderrBuf.length);
      }
    });

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        exitCode: 126,
        stdout: stdoutBuf,
        stderr: err.message,
        timedOut,
        durationMs: Date.now() - startedAt,
      });
    });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        exitCode: code ?? (timedOut ? 124 : 1),
        stdout: stdoutBuf,
        stderr: stderrBuf,
        timedOut,
        durationMs: Date.now() - startedAt,
      });
    });

    if (options.stdinData !== undefined) {
      child.stdin.write(options.stdinData);
    }
    child.stdin.end();
  });
}

export interface HostCapabilities {
  kvmDevicePresent: boolean;
  qemuSystemAvailable: boolean;
  qemuImgAvailable: boolean;
  kvmAvailable: boolean;
  lxcCreateAvailable: boolean;
  lxcStartAvailable: boolean;
  lxcInfoAvailable: boolean;
  lxcAvailable: boolean;
  cgroupVersion: 1 | 2 | 0;
  storageBackends: string[];
  networkBackends: string[];
  qemuVersion: string | null;
  lxcVersion: string | null;
  kernelVersion: string;
  architecture: string;
}

export async function detectHostCapabilities(): Promise<HostCapabilities> {
  const kvmDevicePresent = fs.existsSync('/dev/kvm');
  const qemuSystemAvailable =
    isBinaryAvailable('qemu-system-x86_64') || isBinaryAvailable('qemu-system-aarch64');
  const qemuImgAvailable = isBinaryAvailable('qemu-img');
  const lxcCreateAvailable = isBinaryAvailable('lxc-create');
  const lxcStartAvailable = isBinaryAvailable('lxc-start');
  const lxcInfoAvailable = isBinaryAvailable('lxc-info');

  let cgroupVersion: 1 | 2 | 0 = 0;
  if (fs.existsSync('/sys/fs/cgroup/cgroup.controllers')) {
    cgroupVersion = 2;
  } else if (fs.existsSync('/sys/fs/cgroup/memory') || fs.existsSync('/sys/fs/cgroup/cpu')) {
    cgroupVersion = 1;
  }

  const storageBackends: string[] = ['dir', 'raw'];
  if (qemuImgAvailable) storageBackends.push('qcow2');
  if (isBinaryAvailable('lvs')) storageBackends.push('lvm', 'lvm-thin');
  if (isBinaryAvailable('zfs')) storageBackends.push('zfs');
  if (isBinaryAvailable('btrfs')) storageBackends.push('btrfs');

  const networkBackends: string[] = [];
  if (isBinaryAvailable('ip')) networkBackends.push('iproute2', 'bridge', 'vlan');
  if (isBinaryAvailable('iptables')) networkBackends.push('iptables', 'nat');
  if (isBinaryAvailable('nft')) networkBackends.push('nftables');
  if (isBinaryAvailable('tc')) networkBackends.push('tc-qos');

  let qemuVersion: string | null = null;
  if (isBinaryAvailable('qemu-system-x86_64')) {
    const res = await runAllowlistedCommand('qemu-system-x86_64', ['--version'], { timeoutMs: 5000 });
    if (res.exitCode === 0) {
      qemuVersion = res.stdout.split('\n')[0]?.trim() || null;
    }
  }

  let lxcVersion: string | null = null;
  if (lxcInfoAvailable) {
    const res = await runAllowlistedCommand('lxc-info', ['--version'], { timeoutMs: 5000 });
    if (res.exitCode === 0) {
      lxcVersion = res.stdout.trim() || null;
    }
  }

  const unameRes = await runAllowlistedCommand('uname', ['-r'], { timeoutMs: 3000 });
  const archRes = await runAllowlistedCommand('uname', ['-m'], { timeoutMs: 3000 });

  return {
    kvmDevicePresent,
    qemuSystemAvailable,
    qemuImgAvailable,
    kvmAvailable: qemuSystemAvailable && qemuImgAvailable,
    lxcCreateAvailable,
    lxcStartAvailable,
    lxcInfoAvailable,
    lxcAvailable: lxcCreateAvailable && lxcStartAvailable && lxcInfoAvailable,
    cgroupVersion,
    storageBackends,
    networkBackends,
    qemuVersion,
    lxcVersion,
    kernelVersion: unameRes.stdout.trim() || process.platform,
    architecture: archRes.stdout.trim() || process.arch,
  };
}

// Keep unused execFile imported cleanly if needed by callers
export { execFile };
