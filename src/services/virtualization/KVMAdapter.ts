import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import net from 'net';
import { UnifiedDatabase } from '../../db/database';
import { isBinaryAvailable, runAllowlistedCommand } from '../../node-agent/command-runner';
import { SafeValidators } from '../../security/middleware';
import {
  InstanceCapabilityProfile,
  InstanceTelemetry,
  LifecycleAction,
  UnifiedInstanceRecord,
  VirtualizationAdapter,
} from './VirtualizationAdapter';

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
export class KVMAdapter implements VirtualizationAdapter {
  public readonly engine = 'kvm' as const;
  private db: UnifiedDatabase;
  private hooks: LegacyKvmHooks;
  private prevPidTicks = new Map<number, { procJiffies: number; tsMs: number }>();
  private pendingClonePorts = new Set<number>();

  constructor(
    db: UnifiedDatabase,
    hooks: LegacyKvmHooks = {},
    private readonly commandRunner: typeof runAllowlistedCommand = runAllowlistedCommand
  ) {
    this.db = db;
    this.hooks = hooks;
  }

  public setLegacyHooks(hooks: LegacyKvmHooks): void {
    this.hooks = { ...this.hooks, ...hooks };
  }

  public getCapabilityProfile(): InstanceCapabilityProfile {
    return {
      engine: 'kvm',
      supportsFreeze: false,
      supportsSuspend: true,
      supportsSnapshots: true,
      supportsBackups: true,
      supportsOfflineMigration: false,
      supportsIsoMount: true,
      supportsBootOrder: true,
      supportsSmbios: true,
      supportsCloudInit: true,
      supportsSerialConsole: true,
      supportsPtyConsole: false,
      supportsSshBridge: true,
      supportsRootfsFileBrowser: false,
      supportsContainerProcessList: false,
    };
  }

  private resolveVmDiskPath(row: any): string | null {
    const candidate = row.disk_file || row.img_file || null;
    if (!candidate) return null;
    if (path.isAbsolute(candidate)) return candidate;
    return path.join(os.homedir(), 'vms', candidate);
  }

  private parseDiskGb(diskSizeVal: unknown): number {
    return parseFloat(String(diskSizeVal || '20').replace(/[^0-9.]/g, '')) || 20;
  }

  private parseDiskSizeBytes(value: string): number | null {
    const match = String(value || '').trim().match(/^(\d+(?:\.\d+)?)\s*(B|K|KB|KIB|M|MB|MIB|G|GB|GIB|T|TB|TIB)?$/i);
    if (!match) return null;
    const unit = String(match[2] || 'B').toUpperCase();
    const power = unit.startsWith('T') ? 4 : unit.startsWith('G') ? 3 : unit.startsWith('M') ? 2 : unit.startsWith('K') ? 1 : 0;
    const bytes = Number(match[1]) * 1024 ** power;
    return Number.isSafeInteger(Math.floor(bytes)) && bytes > 0 ? Math.floor(bytes) : null;
  }

  private mapRowToUnified(row: any): UnifiedInstanceRecord {
    let shared: number[] = [];
    try {
      const parsed = JSON.parse(row.shared_with || '[]');
      if (Array.isArray(parsed)) shared = parsed.map(Number).filter(Boolean);
    } catch {
      shared = [];
    }

    const refId = Number(row.vm_id ?? row.id);
    const vmName = row.vm_name || row.name || `vm-${refId}`;

    return {
      uid: `kvm:${refId}`,
      engine: 'kvm',
      refId,
      name: vmName,
      hostname: row.hostname || vmName,
      ownerId: Number(row.owner_id || 1),
      ownerUsername: row.owner_username || undefined,
      nodeId: Number(row.node_id || 1),
      nodeName: row.resolved_node_name || row.node_name || 'localhost',
      status: row.suspended ? 'suspended' : row.status || 'stopped',
      suspended: Boolean(row.suspended),
      suspendedReason: row.suspended_reason || null,
      serviceLocked: Boolean(row.service_locked),
      serviceLockReason: row.service_lock_reason || null,
      osLabel: row.os_type || 'KVM Guest',
      cpuCores: Number(row.cpus || row.cpu_cores || 1),
      ramMb: Number(row.memory || 1024),
      swapMb: 0,
      diskGb: this.parseDiskGb(row.disk_size),
      primaryIp: row.ipv4_address || null,
      sshPort: row.ssh_port || null,
      sharedWith: shared,
      expiresAt: row.expires_at || null,
      createdAt: row.created_at,
      capabilities: this.getCapabilityProfile(),
    };
  }

  public async listInstances(filter?: {
    ownerId?: number;
    nodeId?: number;
  }): Promise<UnifiedInstanceRecord[]> {
    const clauses: string[] = [];
    const params: unknown[] = [];

    if (filter?.ownerId !== undefined) {
      clauses.push(`(v.owner_id = ? OR COALESCE(v.shared_with, '[]') LIKE ?)`);
      params.push(filter.ownerId, `%${filter.ownerId}%`);
    }
    if (filter?.nodeId !== undefined) {
      clauses.push(`COALESCE(v.node_id, 1) = ?`);
      params.push(filter.nodeId);
    }

    const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = await this.db.all<any>(
      `SELECT v.*, u.username AS owner_username, n.name AS resolved_node_name
       FROM vms v
       LEFT JOIN users u ON u.id = v.owner_id
       LEFT JOIN nodes n ON n.id = COALESCE(v.node_id, 1)
       ${whereSql}
       ORDER BY v.vm_id DESC`,
      params
    );

    const mapped = rows.map((r) => this.mapRowToUnified(r));
    if (filter?.ownerId !== undefined) {
      return mapped.filter(
        (m) => m.ownerId === filter.ownerId || m.sharedWith.includes(filter.ownerId!)
      );
    }
    return mapped;
  }

  public async getInstance(refId: number): Promise<UnifiedInstanceRecord | undefined> {
    const row = await this.db.get<any>(
      `SELECT v.*, u.username AS owner_username, n.name AS resolved_node_name
       FROM vms v
       LEFT JOIN users u ON u.id = v.owner_id
       LEFT JOIN nodes n ON n.id = COALESCE(v.node_id, 1)
       WHERE v.vm_id = ?`,
      [refId]
    );
    return row ? this.mapRowToUnified(row) : undefined;
  }

  private isProcessAlive(pid: number): boolean {
    try {
      process.kill(pid, 0);
      return true;
    } catch (error) {
      // EPERM means the process exists but belongs to another user; ESRCH means it is gone.
      return (error as NodeJS.ErrnoException)?.code === 'EPERM';
    }
  }

  private assertCanStopWithoutHook(vm: any, action: string): void {
    const hasHook = Boolean(this.hooks.stopVmById);
    const hasPid = Boolean(vm.pid && this.isProcessAlive(Number(vm.pid)));
    if (String(vm.status || '').toLowerCase() === 'running' && !hasHook && !hasPid) {
      throw new Error(
        `Cannot ${action} KVM VM #${vm.vm_id}: status is running but no stop hook or live PID is available.`
      );
    }
  }

  private async assertHookedVmProcessState(
    refId: number,
    expected: 'running' | 'stopped'
  ): Promise<void> {
    const current = await this.db.get<any>(`SELECT * FROM vms WHERE vm_id = ?`, [refId]);
    if (!current) {
      throw new Error(`KVM VM #${refId} disappeared after a lifecycle hook.`);
    }

    if (expected === 'running') {
      if (!current.pid || !this.isProcessAlive(Number(current.pid))) {
        throw new Error(
          `KVM VM #${refId} did not reach the running state after the lifecycle hook.`
        );
      }
      return;
    }

    if (current.pid && this.isProcessAlive(Number(current.pid))) {
      throw new Error(
        `KVM VM #${refId} still has a live process after the lifecycle hook; refusing to record stopped state.`
      );
    }
  }

  private async stopVmProcess(
    pid: number | null | undefined,
    force?: boolean,
    gracefulWaitMs?: number
  ): Promise<void> {
    const processPid = Number(pid) || 0;
    if (!processPid || !this.isProcessAlive(processPid)) {
      return;
    }

    try {
      process.kill(processPid, force ? 'SIGKILL' : 'SIGTERM');
    } catch (error) {
      if (!this.isProcessAlive(processPid)) return;
      throw error;
    }

    const deadlineMs = Date.now() + (force ? 3000 : gracefulWaitMs ?? 5000);
    while (Date.now() < deadlineMs) {
      if (!this.isProcessAlive(processPid)) return;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }

    throw new Error(
      `KVM VM process ${processPid} did not stop before the ${force ? 3000 : (gracefulWaitMs ?? 5000)}ms deadline.`
    );
  }

  private async isTcpPortAvailable(port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const server = net.createServer();
      server.once('error', () => resolve(false));
      server.listen(port, '0.0.0.0', () => server.close(() => resolve(true)));
    });
  }

  private async allocateClonePort(start: number, excluded: Set<number>): Promise<number> {
    const rows = await this.db.all<any>(`SELECT ssh_port, ssh_port_static, http_port FROM vms`);
    for (const row of rows) {
      for (const key of ['ssh_port', 'ssh_port_static', 'http_port']) {
        const value = Number(row[key]);
        if (value > 0) excluded.add(value);
      }
    }
    for (let candidate = start; candidate < 65000; candidate += 1) {
      if (!excluded.has(candidate) && !this.pendingClonePorts.has(candidate) && await this.isTcpPortAvailable(candidate)) {
        excluded.add(candidate);
        this.pendingClonePorts.add(candidate);
        const reservation = setTimeout(() => this.pendingClonePorts.delete(candidate), 120_000);
        reservation.unref?.();
        return candidate;
      }
    }
    throw Object.assign(new Error('No free TCP forwarding port is available for the clone.'), { statusCode: 503 });
  }

  /** Clone a stopped NAT-mode KVM with a flattened standalone system disk and fresh host network metadata. */
  public async cloneStoppedVm(refId: number, requestedName: string): Promise<{
    vmId: number; name: string; diskSizeBytes: number; sshForwardPort: number; guestIdentityResetRequired: true;
  }> {
    const source = await this.db.get<any>(`SELECT * FROM vms WHERE vm_id = ?`, [refId]);
    if (!source) throw Object.assign(new Error(`KVM VM #${refId} not found.`), { statusCode: 404 });
    if (String(source.status || '').toLowerCase() !== 'stopped') {
      throw Object.assign(new Error('Stop the source VM before cloning it.'), { statusCode: 409 });
    }
    if (Number(source.pid || 0) > 1 && fs.existsSync(`/proc/${Number(source.pid)}`)) {
      throw Object.assign(new Error('A QEMU process is still active; cloning is blocked.'), { statusCode: 409 });
    }
    if (String(source.network_type || 'nat').toLowerCase() !== 'nat') {
      throw Object.assign(new Error('Only user-mode NAT VMs can be cloned safely; reconfigure a bridged guest first.'), { statusCode: 400 });
    }
    if (this.parseDeviceList(source.extra_disks_json, 'disk').some((disk) => disk?.attached !== false) || this.parseDeviceList(source.extra_nics_json, 'network').length) {
      throw Object.assign(new Error('Detach all secondary disks and NICs before cloning; only the primary disk is cloned.'), { statusCode: 400 });
    }
    const name = String(requestedName || '').trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$/.test(name)) {
      throw Object.assign(new Error('Clone name must be 2–63 characters using letters, numbers, dot, underscore, or hyphen.'), { statusCode: 400 });
    }
    if (await this.db.get(`SELECT vm_id FROM vms WHERE vm_name = ?`, [name])) {
      throw Object.assign(new Error('A VM with that name already exists.'), { statusCode: 409 });
    }
    const candidate = this.resolveVmDiskPath(source);
    if (!candidate || !fs.existsSync(candidate)) throw Object.assign(new Error('Source VM disk image was not found.'), { statusCode: 404 });
    let sourcePath: string;
    try { sourcePath = fs.realpathSync(candidate); } catch {
      throw Object.assign(new Error('Could not resolve the source VM disk path.'), { statusCode: 400 });
    }
    const managedRoot = fs.realpathSync(path.join(os.homedir(), 'vms'));
    const relativeSource = path.relative(managedRoot, sourcePath);
    if (!relativeSource || relativeSource === '..' || relativeSource.startsWith(`..${path.sep}`) || path.isAbsolute(relativeSource)) {
      throw Object.assign(new Error('Source disk must be inside the managed VM directory.'), { statusCode: 400 });
    }

    const inspect = await this.commandRunner('qemu-img', ['info', '--output=json', sourcePath], { timeoutMs: 30_000 });
    if (inspect.exitCode !== 0 || inspect.timedOut) throw new Error('Could not inspect source disk image for cloning.');
    let sourceInfo: any;
    try { sourceInfo = JSON.parse(inspect.stdout); } catch {
      throw new Error('qemu-img returned invalid source disk metadata.');
    }
    const sourceFormat = String(sourceInfo.format || '').toLowerCase();
    const sizeBytes = Number(sourceInfo['virtual-size']);
    if (!['qcow2', 'raw'].includes(sourceFormat) || sourceInfo['backing-filename']) {
      throw Object.assign(new Error('Clone requires a standalone QCOW2 or raw source image without a backing chain.'), { statusCode: 400 });
    }
    if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 1) throw new Error('Could not determine source virtual disk size.');

    const sourceWebPort = Number(source.http_port || 0);
    const isProxmox = /proxmox/i.test(`${source.os_type || ''} ${source.template_type || ''}`);
    const excludedPorts = new Set<number>();
    const sshPort = await this.allocateClonePort(22000, excludedPorts);
    const webPort = isProxmox ? await this.allocateClonePort(Math.max(8007, sourceWebPort + 1), excludedPorts) : Number(source.http_port || 80);
    const id = crypto.randomUUID();
    const cloneDir = path.join(managedRoot, 'clones');
    fs.mkdirSync(cloneDir, { recursive: true, mode: 0o700 });
    const cloneRoot = fs.realpathSync(cloneDir);
    const relativeCloneDir = path.relative(managedRoot, cloneRoot);
    if (!relativeCloneDir || relativeCloneDir === '..' || relativeCloneDir.startsWith(`..${path.sep}`) || path.isAbsolute(relativeCloneDir)) {
      throw Object.assign(new Error('Clone storage must be inside the managed VM directory.'), { statusCode: 400 });
    }
    try { fs.chmodSync(cloneRoot, 0o700); } catch { /* checked below */ }
    if ((fs.statSync(cloneRoot).mode & 0o077) !== 0) throw new Error('Clone storage directory permissions are too broad.');
    const targetPath = path.join(cloneRoot, `${id}.qcow2`);
    const converted = await this.commandRunner('qemu-img', ['convert', '-O', 'qcow2', sourcePath, targetPath], { timeoutMs: 900_000 });
    if (converted.exitCode !== 0 || converted.timedOut || !fs.existsSync(targetPath)) {
      try { fs.unlinkSync(targetPath); } catch { /* no image to clean */ }
      throw new Error('Could not create a flattened clone disk image.');
    }
    fs.chmodSync(targetPath, 0o600);
    if ((fs.statSync(targetPath).mode & 0o077) !== 0) {
      try { fs.unlinkSync(targetPath); } catch { /* permission failure remains primary */ }
      throw new Error('Clone disk permissions are too broad; no VM record was created.');
    }
    const cloneInfoResult = await this.commandRunner('qemu-img', ['info', '--output=json', targetPath], { timeoutMs: 30_000 });
    let cloneInfo: any;
    try { cloneInfo = JSON.parse(cloneInfoResult.stdout); } catch { cloneInfo = null; }
    if (cloneInfoResult.exitCode !== 0 || cloneInfoResult.timedOut || !cloneInfo || cloneInfo.format !== 'qcow2' || Number(cloneInfo['virtual-size']) !== sizeBytes) {
      try { fs.unlinkSync(targetPath); } catch { /* verification failure remains primary */ }
      throw new Error('Clone disk verification failed; no VM record was created.');
    }
    let insertedVmId = 0;
    try {
      const columns = await this.db.all<{ name: string }>(`PRAGMA table_info(vms)`);
      const names = columns.map((column) => column.name).filter((column) => column !== 'vm_id');
      const overrides: Record<string, any> = {
        vm_name: name,
        hostname: name.toLowerCase().replace(/[^a-z0-9.-]/g, '-').slice(0, 63),
        disk_file: targetPath,
        img_file: null,
        seed_file: null,
        iso_attached: null,
        boot_from_iso: 0,
        boot_order: 'disk',
        status: 'stopped',
        pid: null,
        uptime: 0,
        created_at: new Date().toISOString(),
        clone_of: refId,
        smbios_serial: `tgv-clone-${crypto.randomUUID()}`,
        mac_address: `52:54:00:${crypto.randomBytes(3).toString('hex').match(/../g)!.join(':')}`,
        network_type: 'nat',
        ipv4_address: null,
        ipv4_gateway: null,
        gateway: null,
        ipv6_address: null,
        ipv6_gateway: null,
        ssh_port: sshPort,
        ssh_port_static: sshPort,
        http_port: webPort,
        vnc_port: null,
        extra_disks_json: '[]',
        extra_nics_json: '[]',
      };
      const selected = names.filter((column) => column in source || column in overrides);
      const selectValues = selected.map((column) => column in overrides ? '?' : `?`);
      const params = selected.map((column) => column in overrides ? overrides[column] : source[column]);
      const inserted = await this.db.run(
        `INSERT INTO vms (${selected.map((column) => `"${column}"`).join(', ')})
         VALUES (${selectValues.join(', ')})`,
        params
      );
      insertedVmId = inserted.lastID;
      await this.syncRegistryRow(insertedVmId);
    } catch (err) {
      if (insertedVmId) {
        await this.db.run(`DELETE FROM instances WHERE engine = 'kvm' AND ref_id = ?`, [insertedVmId]).catch(() => undefined);
        await this.db.run(`DELETE FROM vms WHERE vm_id = ?`, [insertedVmId]).catch(() => undefined);
      }
      try { fs.unlinkSync(targetPath); } catch { /* keep original error */ }
      throw err;
    }
    return { vmId: insertedVmId, name, diskSizeBytes: sizeBytes, sshForwardPort: sshPort, guestIdentityResetRequired: true };
  }

  public async getVncSettings(refId: number): Promise<{ enabled: boolean; port: number | null }> {
    const row = await this.db.get<any>(`SELECT vnc_port FROM vms WHERE vm_id = ?`, [refId]);
    if (!row) throw Object.assign(new Error(`KVM VM #${refId} not found.`), { statusCode: 404 });
    const port = Number(row.vnc_port || 0);
    return { enabled: port >= 5900 && port < 65000, port: port >= 5900 && port < 65000 ? port : null };
  }

  public async setVncEnabled(refId: number, enabled: boolean): Promise<{ enabled: boolean; port: number | null }> {
    const row = await this.getStoppedVmForDeviceChange(refId);
    if (!enabled) {
      await this.db.run(`UPDATE vms SET vnc_port = NULL WHERE vm_id = ?`, [refId]);
      return { enabled: false, port: null };
    }
    const current = Number(row.vnc_port || 0);
    if (current >= 5900 && current < 65000) return { enabled: true, port: current };
    const usedRows = await this.db.all<any>(`SELECT vnc_port FROM vms WHERE vnc_port IS NOT NULL`);
    const used = new Set<number>(usedRows.map((item) => Number(item.vnc_port)).filter((port) => Number.isInteger(port)));
    for (let port = 5900; port < 65000; port += 1) {
      if (used.has(port) || !await this.isTcpPortAvailable(port)) continue;
      const updated = await this.db.run(`UPDATE vms SET vnc_port = ? WHERE vm_id = ? AND (vnc_port IS NULL OR vnc_port = 0)`, [port, refId]);
      if (updated.changes) return { enabled: true, port };
      const refreshed = await this.db.get<any>(`SELECT vnc_port FROM vms WHERE vm_id = ?`, [refId]);
      const raced = Number(refreshed?.vnc_port || 0);
      if (raced >= 5900 && raced < 65000) return { enabled: true, port: raced };
      throw Object.assign(new Error('Could not persist VNC port configuration.'), { statusCode: 409 });
    }
    throw Object.assign(new Error('No local VNC port is available on this host.'), { statusCode: 503 });
  }

  public async getAttachedDevices(refId: number): Promise<{ disks: Array<{ id: string; sizeBytes: number; format: string; attached: boolean }>; nics: Array<{ id: string; macAddress: string; model: string; networkMode: string }> }> {
    const row = await this.db.get<any>(`SELECT extra_disks_json, extra_nics_json FROM vms WHERE vm_id = ?`, [refId]);
    if (!row) throw Object.assign(new Error(`KVM VM #${refId} not found.`), { statusCode: 404 });
    const disks = this.parseDeviceList(row.extra_disks_json, 'disk').map((disk) => ({
      id: String(disk.id || ''), sizeBytes: Number(disk.sizeBytes || 0), format: String(disk.format || 'unknown'),
      attached: disk.attached !== false,
    }));
    const nics = this.parseDeviceList(row.extra_nics_json, 'network').map((nic) => ({
      id: String(nic.id || ''), macAddress: String(nic.macAddress || ''),
      model: String(nic.model || ''), networkMode: String(nic.networkMode || ''),
    }));
    return { disks, nics };
  }

  private async getStoppedVmForDeviceChange(refId: number): Promise<any> {
    const row = await this.db.get<any>(`SELECT * FROM vms WHERE vm_id = ?`, [refId]);
    if (!row) throw Object.assign(new Error(`KVM VM #${refId} not found.`), { statusCode: 404 });
    if (String(row.status || '').toLowerCase() !== 'stopped') {
      throw Object.assign(new Error('Stop the VM before changing attached devices.'), { statusCode: 409 });
    }
    const pid = Number(row.pid || 0);
    if (pid > 1 && fs.existsSync(`/proc/${pid}`)) {
      throw Object.assign(new Error('A QEMU process is still active; device changes are blocked.'), { statusCode: 409 });
    }
    return row;
  }

  private parseDeviceList(value: unknown, label: string): any[] {
    if (!value) return [];
    try {
      const parsed = JSON.parse(String(value));
      if (!Array.isArray(parsed)) throw new Error('not an array');
      return parsed;
    } catch {
      throw Object.assign(new Error(`Stored KVM ${label} configuration is invalid; contact an administrator.`), { statusCode: 500 });
    }
  }

  /** Create and attach a secondary QCOW2 disk to a stopped KVM VM. Detaching never deletes data. */
  public async attachDiskImage(refId: number, requestedSize: string): Promise<{ id: string; sizeBytes: number; format: 'qcow2' }> {
    const row = await this.getStoppedVmForDeviceChange(refId);
    const sizeBytes = this.parseDiskSizeBytes(requestedSize);
    if (!sizeBytes || sizeBytes < 1024 ** 3) {
      throw Object.assign(new Error('Additional disks must be at least 1 GiB and use a valid B/K/M/G/T unit.'), { statusCode: 400 });
    }
    const disks = this.parseDeviceList(row.extra_disks_json, 'disk');
    if (disks.filter((disk) => disk?.attached !== false).length >= 8) throw Object.assign(new Error('A KVM VM may have at most 8 additional attached disks.'), { statusCode: 400 });
    const id = crypto.randomUUID();
    const vmRoot = path.resolve(os.homedir(), 'vms');
    const diskDir = path.join(vmRoot, `vm-${refId}-devices`);
    fs.mkdirSync(diskDir, { recursive: true, mode: 0o700 });
    const realRoot = fs.realpathSync(vmRoot);
    const realDir = fs.realpathSync(diskDir);
    const relativeDir = path.relative(realRoot, realDir);
    if (!relativeDir || relativeDir === '..' || relativeDir.startsWith(`..${path.sep}`) || path.isAbsolute(relativeDir)) {
      throw Object.assign(new Error('Additional disk storage must be inside the managed VM directory.'), { statusCode: 400 });
    }
    try { fs.chmodSync(realDir, 0o700); } catch { /* fail closed on permissions below */ }
    const dirStat = fs.statSync(realDir);
    if ((dirStat.mode & 0o077) !== 0) {
      throw Object.assign(new Error('Additional disk storage directory permissions are too broad.'), { statusCode: 500 });
    }
    const imagePath = path.join(realDir, `${id}.qcow2`);
    const created = await this.commandRunner('qemu-img', ['create', '-f', 'qcow2', imagePath, String(sizeBytes)], { timeoutMs: 120_000 });
    if (created.exitCode !== 0 || created.timedOut || !fs.existsSync(imagePath)) {
      try { fs.unlinkSync(imagePath); } catch { /* no artifact to clean */ }
      throw new Error('Could not create the additional QCOW2 disk image.');
    }
    fs.chmodSync(imagePath, 0o600);
    if ((fs.statSync(imagePath).mode & 0o077) !== 0) {
      try { fs.unlinkSync(imagePath); } catch { /* permission failure remains primary */ }
      throw new Error('Additional disk image permissions are too broad.');
    }
    const device = { id, path: imagePath, format: 'qcow2', sizeBytes };
    const originalDeviceJson = String(row.extra_disks_json || '[]');
    let configurationWritten = false;
    try {
      await this.db.run(`UPDATE vms SET extra_disks_json = ? WHERE vm_id = ?`, [JSON.stringify([...disks, device]), refId]);
      configurationWritten = true;
    } catch (err) {
      let rolledBack = !configurationWritten;
      if (configurationWritten) {
        try {
          await this.db.run(`UPDATE vms SET extra_disks_json = ? WHERE vm_id = ?`, [originalDeviceJson, refId]);
          rolledBack = true;
        } catch { /* retain the image if config rollback cannot be confirmed */ }
      }
      if (rolledBack) {
        try { fs.unlinkSync(imagePath); } catch { /* preserve the primary failure */ }
      }
      throw err;
    }
    return { id, sizeBytes, format: 'qcow2' };
  }

  /** Detach a secondary disk configuration while preserving and cataloguing its image. */
  public async detachDiskImage(refId: number, deviceId: string): Promise<{ id: string; imagePreserved: true }> {
    const row = await this.getStoppedVmForDeviceChange(refId);
    const disks = this.parseDeviceList(row.extra_disks_json, 'disk');
    const target = disks.find((disk) => disk?.id === deviceId && disk?.attached !== false);
    if (!target) throw Object.assign(new Error('Attached disk not found.'), { statusCode: 404 });
    target.attached = false;
    await this.db.run(`UPDATE vms SET extra_disks_json = ? WHERE vm_id = ?`, [JSON.stringify(disks), refId]);
    return { id: deviceId, imagePreserved: true };
  }

  /** Reattach a previously detached secondary image without changing its contents. */
  public async reattachDiskImage(refId: number, deviceId: string): Promise<{ id: string; attached: true }> {
    const row = await this.getStoppedVmForDeviceChange(refId);
    const disks = this.parseDeviceList(row.extra_disks_json, 'disk');
    if (disks.filter((disk) => disk?.attached !== false).length >= 8) {
      throw Object.assign(new Error('A KVM VM may have at most 8 additional attached disks.'), { statusCode: 400 });
    }
    const target = disks.find((disk) => disk?.id === deviceId);
    if (!target || target.attached !== false) throw Object.assign(new Error('Detached disk image not found.'), { statusCode: 404 });
    try {
      const managedDir = fs.realpathSync(path.join(os.homedir(), 'vms', `vm-${refId}-devices`));
      const image = fs.realpathSync(String(target.path || ''));
      const relative = path.relative(managedDir, image);
      if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative) || path.basename(image) !== `${deviceId}.qcow2`) {
        throw new Error('invalid disk path');
      }
    } catch {
      throw Object.assign(new Error('Detached disk image is missing or outside its managed directory.'), { statusCode: 400 });
    }
    target.attached = true;
    await this.db.run(`UPDATE vms SET extra_disks_json = ? WHERE vm_id = ?`, [JSON.stringify(disks), refId]);
    return { id: deviceId, attached: true };
  }

  /** Attach a secondary user-mode NAT network interface to a stopped KVM VM. */
  public async attachNatNic(refId: number): Promise<{ id: string; macAddress: string; model: 'virtio-net-pci'; networkMode: 'user' }> {
    const row = await this.getStoppedVmForDeviceChange(refId);
    const nics = this.parseDeviceList(row.extra_nics_json, 'network');
    if (nics.length >= 7) throw Object.assign(new Error('A KVM VM may have at most 7 additional network interfaces.'), { statusCode: 400 });
    const configuredMacs = new Set<string>();
    const vmRows = await this.db.all<any>(`SELECT mac_address, extra_nics_json FROM vms`);
    for (const vmRow of vmRows) {
      if (vmRow.mac_address) configuredMacs.add(String(vmRow.mac_address).toLowerCase());
      for (const nic of this.parseDeviceList(vmRow.extra_nics_json, 'network')) {
        if (nic?.macAddress) configuredMacs.add(String(nic.macAddress).toLowerCase());
      }
    }
    let macAddress = '';
    for (let tries = 0; tries < 8; tries += 1) {
      macAddress = `52:54:00:${crypto.randomBytes(3).toString('hex').match(/../g)!.join(':')}`;
      if (!configuredMacs.has(macAddress)) break;
      macAddress = '';
    }
    if (!macAddress) throw new Error('Could not allocate a unique MAC address for the network interface.');
    const id = crypto.randomUUID();
    const nic = { id, macAddress, model: 'virtio-net-pci', networkMode: 'user' };
    await this.db.run(`UPDATE vms SET extra_nics_json = ? WHERE vm_id = ?`, [JSON.stringify([...nics, nic]), refId]);
    return { id, macAddress, model: 'virtio-net-pci', networkMode: 'user' };
  }

  /** Detach a secondary network-interface configuration from a stopped KVM VM. */
  public async detachNic(refId: number, deviceId: string): Promise<{ id: string }> {
    const row = await this.getStoppedVmForDeviceChange(refId);
    const nics = this.parseDeviceList(row.extra_nics_json, 'network');
    const next = nics.filter((nic) => nic?.id !== deviceId);
    if (next.length === nics.length) throw Object.assign(new Error('Attached network interface not found.'), { statusCode: 404 });
    await this.db.run(`UPDATE vms SET extra_nics_json = ? WHERE vm_id = ?`, [JSON.stringify(next), refId]);
    return { id: deviceId };
  }

  /** Expand an offline standalone KVM disk image. Guest partitions/filesystems are not resized here. */
  public async resizeDiskImage(
    refId: number,
    requestedSize: string
  ): Promise<{ diskSize: string; virtualSizeBytes: number; guestFilesystemResizeRequired: true }> {
    const row = await this.db.get<any>(`SELECT * FROM vms WHERE vm_id = ?`, [refId]);
    if (!row) throw Object.assign(new Error(`KVM VM #${refId} not found.`), { statusCode: 404 });
    if (String(row.status || '').toLowerCase() === 'running') {
      throw Object.assign(new Error('Stop the VM before resizing its virtual disk.'), { statusCode: 409 });
    }
    const pid = Number(row.pid || 0);
    if (pid > 1 && fs.existsSync(`/proc/${pid}`)) {
      throw Object.assign(new Error('A QEMU process is still active; disk resize is blocked.'), { statusCode: 409 });
    }

    const targetBytes = this.parseDiskSizeBytes(requestedSize);
    if (!targetBytes || targetBytes < 1024 ** 3) {
      throw Object.assign(new Error('Disk size must be at least 1 GiB and use a valid B/K/M/G/T unit.'), { statusCode: 400 });
    }
    const candidate = this.resolveVmDiskPath(row);
    if (!candidate || !fs.existsSync(candidate)) {
      throw Object.assign(new Error('The VM disk image was not found; no disk was changed.'), { statusCode: 404 });
    }

    let diskPath: string;
    try {
      diskPath = fs.realpathSync(candidate);
    } catch {
      throw Object.assign(new Error('Could not resolve the VM disk image path.'), { statusCode: 400 });
    }
    const vmRoot = path.resolve(os.homedir(), 'vms');
    const relativePath = path.relative(vmRoot, diskPath);
    if (!relativePath || relativePath === '..' || relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath)) {
      throw Object.assign(new Error('VM disk image must be stored inside the managed VM directory.'), { statusCode: 400 });
    }

    const inspect = async (): Promise<any> => {
      const info = await this.commandRunner('qemu-img', ['info', '--output=json', diskPath], { timeoutMs: 30_000 });
      if (info.exitCode !== 0 || info.timedOut) {
        throw new Error('Could not inspect the VM disk image with qemu-img.');
      }
      let parsed: any;
      try {
        parsed = JSON.parse(info.stdout);
      } catch {
        throw new Error('qemu-img returned invalid disk metadata.');
      }
      if (!['qcow2', 'raw'].includes(String(parsed.format || '').toLowerCase())) {
        throw new Error(`Disk format "${parsed.format || 'unknown'}" is not supported for resize.`);
      }
      if (parsed['backing-filename']) {
        throw new Error('Backing-chain disks cannot be resized by this workflow. Flatten or migrate the disk first.');
      }
      return parsed;
    };

    const before = await inspect();
    const currentBytes = Number(before['virtual-size']);
    if (!Number.isSafeInteger(currentBytes) || currentBytes < 1) throw new Error('Could not determine the VM disk virtual size.');
    if (targetBytes < currentBytes) {
      throw Object.assign(new Error('Disk shrinking is disabled because it can destroy guest data. Choose a size equal to or larger than the current virtual size.'), { statusCode: 400 });
    }
    if (targetBytes > currentBytes) {
      const resized = await this.commandRunner('qemu-img', ['resize', diskPath, String(targetBytes)], { timeoutMs: 120_000 });
      if (resized.exitCode !== 0 || resized.timedOut) {
        throw new Error('qemu-img could not expand the VM disk image.');
      }
    }

    const after = await inspect();
    const actualBytes = Number(after['virtual-size']);
    if (!Number.isSafeInteger(actualBytes) || actualBytes < targetBytes) {
      throw new Error('Disk expansion did not reach the requested virtual size; verify the disk before retrying.');
    }
    const diskSize = String(requestedSize).trim().toUpperCase();
    await this.db.run(`UPDATE vms SET disk_size = ? WHERE vm_id = ?`, [diskSize, refId]);
    await this.syncRegistryRow(refId);
    return { diskSize, virtualSizeBytes: actualBytes, guestFilesystemResizeRequired: true };
  }

  public async syncRegistryRow(vmId: number): Promise<void> {
    const vm = await this.db.get<any>(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
    if (!vm) {
      await this.db.run(`DELETE FROM instances WHERE engine = 'kvm' AND ref_id = ?`, [vmId]);
      return;
    }
    await this.db.run(
      `INSERT INTO instances
         (engine, ref_id, name, hostname, owner_id, node_id, status, suspended, os_label, cpu_cores, ram_mb, disk_gb, primary_ip, shared_with, updated_at)
       VALUES ('kvm', ?, ?, ?, ?, COALESCE(?, 1), ?, COALESCE(?, 0), ?, ?, ?, ?, ?, COALESCE(?, '[]'), datetime('now'))
       ON CONFLICT(engine, ref_id) DO UPDATE SET
         name = excluded.name,
         hostname = excluded.hostname,
         owner_id = excluded.owner_id,
         node_id = excluded.node_id,
         status = excluded.status,
         suspended = excluded.suspended,
         os_label = excluded.os_label,
         cpu_cores = excluded.cpu_cores,
         ram_mb = excluded.ram_mb,
         disk_gb = excluded.disk_gb,
         primary_ip = excluded.primary_ip,
         shared_with = excluded.shared_with,
         updated_at = datetime('now')`,
      [
        vm.vm_id,
        vm.vm_name,
        vm.hostname || vm.vm_name,
        vm.owner_id || 1,
        vm.node_id,
        vm.status || 'stopped',
        vm.suspended,
        vm.os_type || 'KVM Guest',
        vm.cpus || 1,
        vm.memory || 1024,
        this.parseDiskGb(vm.disk_size),
        vm.ipv4_address || null,
        vm.shared_with || '[]',
      ]
    );
  }

  public async performLifecycleAction(
    refId: number,
    action: LifecycleAction,
    options?: { reason?: string; actorId?: number; force?: boolean }
  ): Promise<UnifiedInstanceRecord> {
    const vm = await this.db.get<any>(`SELECT * FROM vms WHERE vm_id = ?`, [refId]);
    if (!vm) throw new Error(`KVM VM #${refId} not found.`);

    if (action === 'freeze' || action === 'unfreeze') {
      throw new Error(`Action "${action}" is only supported for LXC containers, not KVM VMs.`);
    }

    if (action === 'start') {
      if (vm.suspended) {
        throw new Error('Cannot start a suspended VM. Unsuspend it first.');
      }
      if (!this.hooks.startVmById) {
        throw new Error('KVM start hook is not registered.');
      }
      await this.hooks.startVmById(refId);
      await this.assertHookedVmProcessState(refId, 'running');
    } else if (action === 'shutdown') {
      // Graceful guest shutdown: SIGTERM with a longer grace period and no forced kill.
      // Distinct from `stop`, which may escalate to SIGKILL when force is requested.
      if (this.hooks.stopVmById) {
        await this.hooks.stopVmById(refId, false);
        await this.assertHookedVmProcessState(refId, 'stopped');
      } else {
        this.assertCanStopWithoutHook(vm, 'shutdown');
        await this.stopVmProcess(vm.pid, false, 15_000);
        await this.db.run(`UPDATE vms SET status = 'stopped', pid = NULL WHERE vm_id = ?`, [refId]);
      }
    } else if (action === 'stop') {
      if (this.hooks.stopVmById) {
        await this.hooks.stopVmById(refId, options?.force);
        await this.assertHookedVmProcessState(refId, 'stopped');
      } else {
        this.assertCanStopWithoutHook(vm, 'stop');
        await this.stopVmProcess(vm.pid, options?.force);
        await this.db.run(`UPDATE vms SET status = 'stopped', pid = NULL WHERE vm_id = ?`, [refId]);
      }
    } else if (action === 'restart') {
      if (this.hooks.restartVmById) {
        await this.hooks.restartVmById(refId);
        await this.assertHookedVmProcessState(refId, 'running');
      } else {
        if (!this.hooks.stopVmById || !this.hooks.startVmById) {
          throw new Error(
            'KVM restart requires a registered restart hook or both stop and start hooks.'
          );
        }
        await this.hooks.stopVmById(refId, false);
        await this.assertHookedVmProcessState(refId, 'stopped');
        await this.hooks.startVmById(refId);
        await this.assertHookedVmProcessState(refId, 'running');
      }
    } else if (action === 'suspend') {
      if (vm.status === 'running' || (vm.pid && this.isProcessAlive(Number(vm.pid)))) {
        if (this.hooks.stopVmById) {
          await this.hooks.stopVmById(refId, false);
          await this.assertHookedVmProcessState(refId, 'stopped');
        } else {
          this.assertCanStopWithoutHook(vm, 'suspend');
          await this.stopVmProcess(vm.pid, false);
        }
      }
      await this.db.run(
        `UPDATE vms SET suspended = 1, suspended_reason = ?, status = 'stopped', pid = NULL WHERE vm_id = ?`,
        [options?.reason || 'Suspended by administrator', refId]
      );
    } else if (action === 'unsuspend') {
      await this.db.run(
        `UPDATE vms SET suspended = 0, suspended_reason = NULL WHERE vm_id = ?`,
        [refId]
      );
    } else if (action === 'delete') {
      if (this.hooks.deleteVmById) {
        await this.hooks.deleteVmById(refId);
        if (vm.pid && this.isProcessAlive(Number(vm.pid))) {
          throw new Error(
            `KVM VM #${refId} still has a live process (PID ${vm.pid}) after the delete hook; refusing to report deletion.`
          );
        }
        const remaining = await this.db.get<any>(`SELECT vm_id FROM vms WHERE vm_id = ?`, [refId]);
        if (remaining) {
          throw new Error(
            `KVM VM #${refId} was not removed by the delete hook; refusing to report deletion.`
          );
        }
      } else {
        throw new Error(
          `KVM delete hook is not registered for VM #${refId}; refusing to remove panel records without host disk cleanup.`
        );
      }
      await this.db.run(`DELETE FROM instances WHERE engine = 'kvm' AND ref_id = ?`, [refId]);
      return this.mapRowToUnified({ ...vm, status: 'deleted' });
    }

    await this.syncRegistryRow(refId);
    return (await this.getInstance(refId))!;
  }

  public async getTelemetry(refId: number): Promise<InstanceTelemetry> {
    const vm = await this.db.get<any>(`SELECT * FROM vms WHERE vm_id = ?`, [refId]);
    if (!vm) throw new Error(`KVM VM #${refId} not found.`);

    const pid = vm.pid ? Number(vm.pid) : null;
    let isAlive = false;
    let cpuPercent = 0;
    let ramUsedMb = 0;

    if (pid && pid > 0 && fs.existsSync(`/proc/${pid}/stat`)) {
      isAlive = true;
      try {
        const statContent = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
        const afterComm = statContent.slice(statContent.lastIndexOf(')') + 2).trim().split(/\s+/);
        const utime = parseInt(afterComm[11] || '0', 10) || 0;
        const stime = parseInt(afterComm[12] || '0', 10) || 0;
        const procJiffies = utime + stime;
        const nowMs = Date.now();
        const clkTck = 100;

        const prev = this.prevPidTicks.get(pid);
        if (prev && nowMs > prev.tsMs) {
          const deltaSec = (nowMs - prev.tsMs) / 1000;
          const cpuSec = (procJiffies - prev.procJiffies) / clkTck;
          const vcpus = Math.max(1, Number(vm.cpus || 1));
          cpuPercent = Number(
            Math.min(100, Math.max(0, ((cpuSec / deltaSec) / vcpus) * 100)).toFixed(2)
          );
        }
        this.prevPidTicks.set(pid, { procJiffies, tsMs: nowMs });

        const statusContent = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
        const rssMatch = statusContent.match(/^VmRSS:\s+(\d+)\s+kB/m);
        if (rssMatch) {
          ramUsedMb = Math.round(parseInt(rssMatch[1], 10) / 1024);
        }
      } catch {
        isAlive = false;
      }
    }

    const diskPath = this.resolveVmDiskPath(vm);
    let diskUsedGb = 0;
    if (diskPath && fs.existsSync(diskPath)) {
      try {
        diskUsedGb = Number((fs.statSync(diskPath).size / 1024 ** 3).toFixed(2));
      } catch {
        diskUsedGb = 0;
      }
    }

    const ramTotalMb = Math.max(1, Number(vm.memory || 1024));
    const status = isAlive ? 'running' : vm.status === 'running' ? 'stopped' : vm.status || 'stopped';

    return {
      engine: 'kvm',
      refId,
      status,
      pid: isAlive ? pid : null,
      cpuPercent,
      ramUsedMb,
      ramTotalMb,
      ramPercent: Number(Math.min(100, (ramUsedMb / ramTotalMb) * 100).toFixed(2)),
      diskUsedGb,
      diskTotalGb: this.parseDiskGb(vm.disk_size),
      netRxBytes: null,
      netTxBytes: null,
      measuredAt: new Date().toISOString(),
    };
  }

  public async createQcow2Snapshot(
    vmId: number,
    snapshotName: string,
    description = ''
  ): Promise<{ id: number; name: string }> {
    const safeSnap = SafeValidators.snapshotName(snapshotName);
    const vm = await this.db.get<any>(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
    if (!vm) throw new Error(`KVM VM #${vmId} not found.`);
    if ((vm.disk_format || 'qcow2').toLowerCase() !== 'qcow2') {
      throw new Error('Internal QEMU snapshots require QCOW2 disk format (current disk is RAW).');
    }
    if (!isBinaryAvailable('qemu-img')) {
      throw new Error('qemu-img binary is not installed on this host.');
    }
    const diskPath = this.resolveVmDiskPath(vm);
    if (!diskPath || !fs.existsSync(diskPath)) {
      throw new Error(`VM disk image does not exist on disk: ${diskPath}`);
    }

    const res = await runAllowlistedCommand('qemu-img', ['snapshot', '-c', safeSnap, diskPath], {
      timeoutMs: 120_000,
    });
    if (res.exitCode !== 0) {
      throw new Error(`qemu-img snapshot failed: ${res.stderr || res.stdout}`);
    }

    const sizeGb = Number((fs.statSync(diskPath).size / 1024 ** 3).toFixed(2));
    const ins = await this.db.run(
      `INSERT INTO vm_snapshots (vm_id, snapshot_name, tag_name, file_path, size_gb, description, status)
       VALUES (?, ?, ?, ?, ?, ?, 'completed')`,
      [vmId, safeSnap, safeSnap, diskPath, sizeGb, description]
    );
    return { id: ins.lastID, name: safeSnap };
  }

  public async restoreQcow2Snapshot(vmId: number, snapshotId: number): Promise<void> {
    const vm = await this.db.get<any>(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
    const snap = await this.db.get<any>(
      `SELECT * FROM vm_snapshots WHERE snapshot_id = ? AND vm_id = ?`,
      [snapshotId, vmId]
    );
    if (!vm || !snap) throw new Error('VM or snapshot not found.');
    if (vm.status === 'running') {
      throw new Error('Stop the KVM VM before reverting to a disk snapshot.');
    }
    if (!isBinaryAvailable('qemu-img')) {
      throw new Error('qemu-img binary is not installed on this host.');
    }
    const diskPath = this.resolveVmDiskPath(vm);
    if (!diskPath || !fs.existsSync(diskPath)) {
      throw new Error(`VM disk image not found: ${diskPath}`);
    }
    const res = await runAllowlistedCommand(
      'qemu-img',
      ['snapshot', '-a', snap.snapshot_name, diskPath],
      { timeoutMs: 120_000 }
    );
    if (res.exitCode !== 0) {
      throw new Error(`qemu-img snapshot revert failed: ${res.stderr || res.stdout}`);
    }
  }

  public async deleteQcow2Snapshot(vmId: number, snapshotId: number): Promise<void> {
    const vm = await this.db.get<any>(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
    const snap = await this.db.get<any>(
      `SELECT * FROM vm_snapshots WHERE snapshot_id = ? AND vm_id = ?`,
      [snapshotId, vmId]
    );
    if (!vm || !snap) throw new Error('VM or snapshot not found.');

    const diskPath = this.resolveVmDiskPath(vm);
    if (isBinaryAvailable('qemu-img') && diskPath && fs.existsSync(diskPath)) {
      await runAllowlistedCommand('qemu-img', ['snapshot', '-d', snap.snapshot_name, diskPath], {
        timeoutMs: 60_000,
      });
    }
    await this.db.run(`DELETE FROM vm_snapshots WHERE snapshot_id = ?`, [snapshotId]);
  }

  public async createDiskBackup(
    vmId: number,
    backupDir = path.resolve(process.cwd(), 'data', 'instance-backups')
  ): Promise<{ backupId: number; filePath: string; sizeBytes: number; checksumSha256: string }> {
    const vm = await this.db.get<any>(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
    if (!vm) throw new Error(`KVM VM #${vmId} not found.`);
    const diskPath = this.resolveVmDiskPath(vm);
    if (!diskPath || !fs.existsSync(diskPath)) {
      throw new Error(`VM disk image not found at ${diskPath}`);
    }

    fs.mkdirSync(backupDir, { recursive: true });
    const backupName = `kvm_${vm.vm_id}_${Date.now()}`;
    const outFile = path.join(backupDir, `${backupName}.tar.gz`);

    const diskDir = path.dirname(diskPath);
    const diskBase = path.basename(diskPath);
    const tarRes = await runAllowlistedCommand('tar', ['-czpf', outFile, '-C', diskDir, diskBase], {
      timeoutMs: 900_000,
    });
    if (tarRes.exitCode !== 0) {
      throw new Error(`KVM disk backup failed: ${tarRes.stderr || tarRes.stdout}`);
    }

    const hash = crypto.createHash('sha256');
    await new Promise<void>((resolve, reject) => {
      const s = fs.createReadStream(outFile);
      s.on('data', (c) => hash.update(c));
      s.on('error', reject);
      s.on('end', () => resolve());
    });
    const checksumSha256 = hash.digest('hex');
    const sizeBytes = fs.statSync(outFile).size;

    const ins = await this.db.run(
      `INSERT INTO container_backups
         (instance_type, instance_ref_id, node_id, backup_name, file_path, size_bytes, sha256, checksum_sha256, verified, status)
       VALUES ('kvm', ?, COALESCE(?, 1), ?, ?, ?, ?, ?, 1, 'completed')`,
      [vm.vm_id, vm.node_id, backupName, outFile, sizeBytes, checksumSha256, checksumSha256]
    );

    return { backupId: ins.lastID, filePath: outFile, sizeBytes, checksumSha256 };
  }
}
