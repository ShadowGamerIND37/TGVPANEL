import { UnifiedDatabase } from '../../db/database';
import { AuthenticatedPrincipal } from '../../security/middleware';
import { VirtualizationManager } from './VirtualizationManager';
import { InstanceTask, InstanceTaskManager } from './InstanceTaskManager';
import {
  InstanceTelemetry,
  LifecycleAction,
  UnifiedInstanceRecord,
  VirtualizationEngine,
} from './VirtualizationAdapter';

export { VirtualizationManager };

/**
 * High-level Unified Instance Manager handling cross-engine queries, RBAC/ownership/sharing
 * checks, bulk actions, and automated expiration enforcement.
 */
export class InstanceManager {
  private db: UnifiedDatabase;
  public readonly virt: VirtualizationManager;
  public readonly tasks: InstanceTaskManager;

  constructor(db: UnifiedDatabase, virt: VirtualizationManager) {
    this.db = db;
    this.virt = virt;
    this.tasks = new InstanceTaskManager(db);
  }

  public isStaff(principal: AuthenticatedPrincipal): boolean {
    return (
      principal.role === 'admin' ||
      principal.role === 'subadmin' ||
      principal.role === 'operator'
    );
  }

  public async listAccessibleInstances(
    principal: AuthenticatedPrincipal,
    filter?: { engine?: VirtualizationEngine; nodeId?: number; status?: string; search?: string }
  ): Promise<UnifiedInstanceRecord[]> {
    const ownerFilter = this.isStaff(principal) ? undefined : principal.userId;

    const lists: UnifiedInstanceRecord[] = [];
    if (!filter?.engine || filter.engine === 'kvm') {
      lists.push(
        ...(await this.virt.kvm.listInstances({
          ownerId: ownerFilter,
          nodeId: filter?.nodeId,
        }))
      );
    }
    if (!filter?.engine || filter.engine === 'lxc') {
      lists.push(
        ...(await this.virt.lxc.listInstances({
          ownerId: ownerFilter,
          nodeId: filter?.nodeId,
        }))
      );
    }

    let combined = lists.sort(
      (a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime()
    );

    if (filter?.status) {
      const s = filter.status.toLowerCase();
      combined = combined.filter((i) => i.status.toLowerCase() === s);
    }

    if (filter?.search) {
      const q = filter.search.toLowerCase();
      combined = combined.filter(
        (i) =>
          i.name.toLowerCase().includes(q) ||
          i.hostname.toLowerCase().includes(q) ||
          (i.primaryIp || '').toLowerCase().includes(q) ||
          (i.ownerUsername || '').toLowerCase().includes(q)
      );
    }

    return combined;
  }

  public async getAuthorizedInstance(
    principal: AuthenticatedPrincipal,
    engine: VirtualizationEngine,
    refId: number,
    requireOwnerOrStaff = false
  ): Promise<UnifiedInstanceRecord> {
    const inst = await this.virt.getAdapter(engine).getInstance(refId);
    if (!inst) {
      throw Object.assign(new Error(`${engine.toUpperCase()} instance #${refId} not found.`), {
        statusCode: 404,
      });
    }

    if (this.isStaff(principal)) {
      return inst;
    }

    const isOwner = inst.ownerId === principal.userId;
    const isShared = inst.sharedWith.includes(principal.userId);

    if (requireOwnerOrStaff && !isOwner) {
      throw Object.assign(new Error('Only the instance owner or an administrator may perform this action.'), {
        statusCode: 403,
      });
    }

    if (!isOwner && !isShared) {
      throw Object.assign(new Error('Access denied to this instance.'), {
        statusCode: 403,
      });
    }

    return inst;
  }

  public async resizeKvmDisk(
    principal: AuthenticatedPrincipal,
    refId: number,
    requestedSize: string
  ): Promise<{ diskSize: string; virtualSizeBytes: number; guestFilesystemResizeRequired: true }> {
    await this.getAuthorizedInstance(principal, 'kvm', refId, true);
    const outcome = await this.tasks.runSync({
      engine: 'kvm',
      instanceRefId: refId,
      actorId: principal.userId,
      action: 'disk_resize',
      worker: async (reportProgress) => {
        await reportProgress(null, 'Validating stopped VM and disk image');
        const result = await this.virt.kvm.resizeDiskImage(refId, requestedSize);
        await reportProgress(null, 'Virtual disk expanded; guest filesystem may need in-guest growth');
        return result;
      },
    });
    await this.db.logActivity({
      userId: principal.userId,
      action: 'kvm_disk_resize',
      resourceType: 'kvm',
      resourceId: String(refId),
      details: { diskSize: outcome.result.diskSize },
    });
    return outcome.result;
  }

  public async getKvmVncSettings(principal: AuthenticatedPrincipal, refId: number) {
    await this.getAuthorizedInstance(principal, 'kvm', refId);
    return this.virt.kvm.getVncSettings(refId);
  }

  public async setKvmVncEnabled(principal: AuthenticatedPrincipal, refId: number, enabled: boolean) {
    await this.getAuthorizedInstance(principal, 'kvm', refId, true);
    const out = await this.tasks.runSync({
      engine: 'kvm', instanceRefId: refId, actorId: principal.userId, action: enabled ? 'vnc_enable' : 'vnc_disable',
      worker: async (report) => {
        await report(null, enabled ? 'Enabling loopback-only VNC for next start' : 'Disabling VNC for next start');
        return this.virt.kvm.setVncEnabled(refId, enabled);
      },
    });
    return out.result;
  }

  public async setInstanceServiceLock(
    principal: AuthenticatedPrincipal,
    engine: VirtualizationEngine,
    refId: number,
    locked: boolean,
    reason?: string
  ): Promise<UnifiedInstanceRecord> {
    if (!this.isStaff(principal)) {
      throw Object.assign(new Error('Only staff may set or clear a VPS service lock.'), { statusCode: 403 });
    }
    const current = await this.getAuthorizedInstance(principal, engine, refId);
    const cleanReason = String(reason || '').trim().slice(0, 500);
    const table = engine === 'kvm' ? 'vms' : 'lxc_instances';
    const idColumn = engine === 'kvm' ? 'vm_id' : 'id';
    const out = await this.tasks.runSync({
      engine, instanceRefId: refId, actorId: principal.userId,
      action: locked ? 'service_lock' : 'service_unlock',
      worker: async (report) => {
        await report(null, locked ? 'Applying administrative service lock (without stopping the guest)' : 'Clearing administrative service lock');
        await this.db.run(
          `UPDATE ${table} SET service_locked = ?, service_lock_reason = ?,
             service_locked_at = CASE WHEN ? = 1 THEN datetime('now') ELSE NULL END,
             service_locked_by = CASE WHEN ? = 1 THEN ? ELSE NULL END
           WHERE ${idColumn} = ?`,
          [locked ? 1 : 0, locked && cleanReason ? cleanReason : null, locked ? 1 : 0, locked ? 1 : 0, locked ? principal.userId : null, refId]
        );
        if (engine === 'kvm') await this.virt.kvm.syncRegistryRow(refId);
        else await this.virt.lxc.syncRegistryRow(refId);
        await report(null, locked ? 'Lock persisted; running guest was not stopped' : 'Service lock cleared');
        return this.virt.getAdapter(engine).getInstance(refId);
      },
    });
    await this.db.logActivity({
      userId: principal.userId,
      action: locked ? 'instance_service_lock' : 'instance_service_unlock',
      resourceType: engine,
      resourceId: String(refId),
      details: { previousLock: Boolean(current.serviceLocked), reason: locked ? cleanReason || null : null },
    });
    return out.result as UnifiedInstanceRecord;
  }

  public async cloneKvmInstance(
    principal: AuthenticatedPrincipal,
    refId: number,
    newName: string
  ): Promise<{ vmId: number; name: string; diskSizeBytes: number; sshForwardPort: number; guestIdentityResetRequired: true }> {
    await this.getAuthorizedInstance(principal, 'kvm', refId, true);
    const out = await this.tasks.runSync({
      engine: 'kvm', instanceRefId: refId, actorId: principal.userId, action: 'clone',
      worker: async (report) => {
        await report(null, 'Validating stopped NAT VM and managed primary disk');
        const result = await this.virt.kvm.cloneStoppedVm(refId, newName);
        await report(null, 'Clone disk verified; new VM remains stopped');
        return result;
      },
    });
    return out.result;
  }

  public async cloneLxcInstance(principal: AuthenticatedPrincipal, refId: number, newName: string) {
    await this.getAuthorizedInstance(principal, 'lxc', refId, true);
    const out = await this.tasks.runSync({
      engine: 'lxc', instanceRefId: refId, actorId: principal.userId, action: 'clone',
      worker: async (report) => {
        await report(null, 'Validating stopped directory-backed LXC and preparing disconnected clone');
        const result = await this.virt.lxc.cloneStoppedLxcInstance(refId, newName);
        await report(null, 'LXC copy verified; clone remains stopped with networking detached');
        return result;
      },
    });
    await this.db.logActivity({
      userId: principal.userId,
      action: 'lxc_clone',
      resourceType: 'lxc',
      resourceId: String(out.result.instance.refId),
      details: { sourceRefId: refId, name: out.result.instance.name, networkDetached: true },
    });
    return out.result;
  }

  public async listKvmDevices(principal: AuthenticatedPrincipal, refId: number) {
    await this.getAuthorizedInstance(principal, 'kvm', refId);
    return this.virt.kvm.getAttachedDevices(refId);
  }

  public async attachKvmDisk(
    principal: AuthenticatedPrincipal,
    refId: number,
    size: string
  ): Promise<{ id: string; sizeBytes: number; format: 'qcow2' }> {
    await this.getAuthorizedInstance(principal, 'kvm', refId, true);
    const out = await this.tasks.runSync({
      engine: 'kvm', instanceRefId: refId, actorId: principal.userId, action: 'disk_attach',
      worker: async (report) => {
        await report(null, 'Creating an offline secondary QCOW2 disk');
        return this.virt.kvm.attachDiskImage(refId, size);
      },
    });
    return out.result;
  }

  public async reattachKvmDisk(principal: AuthenticatedPrincipal, refId: number, deviceId: string): Promise<{ id: string; attached: true }> {
    await this.getAuthorizedInstance(principal, 'kvm', refId, true);
    const out = await this.tasks.runSync({
      engine: 'kvm', instanceRefId: refId, actorId: principal.userId, action: 'disk_reattach',
      worker: async (report) => {
        await report(null, 'Reattaching the preserved secondary disk image');
        return this.virt.kvm.reattachDiskImage(refId, deviceId);
      },
    });
    return out.result;
  }

  public async detachKvmDisk(principal: AuthenticatedPrincipal, refId: number, deviceId: string): Promise<{ id: string; imagePreserved: true }> {
    await this.getAuthorizedInstance(principal, 'kvm', refId, true);
    const out = await this.tasks.runSync({
      engine: 'kvm', instanceRefId: refId, actorId: principal.userId, action: 'disk_detach',
      worker: async (report) => {
        await report(null, 'Detaching the secondary disk configuration; preserving its image');
        return this.virt.kvm.detachDiskImage(refId, deviceId);
      },
    });
    return out.result;
  }

  public async attachKvmNatNic(principal: AuthenticatedPrincipal, refId: number): Promise<{ id: string; macAddress: string; model: 'virtio-net-pci'; networkMode: 'user' }> {
    await this.getAuthorizedInstance(principal, 'kvm', refId, true);
    const out = await this.tasks.runSync({
      engine: 'kvm', instanceRefId: refId, actorId: principal.userId, action: 'nic_attach',
      worker: async (report) => {
        await report(null, 'Attaching an offline user-mode NAT network interface');
        return this.virt.kvm.attachNatNic(refId);
      },
    });
    return out.result;
  }

  public async detachKvmNic(principal: AuthenticatedPrincipal, refId: number, deviceId: string): Promise<{ id: string }> {
    await this.getAuthorizedInstance(principal, 'kvm', refId, true);
    const out = await this.tasks.runSync({
      engine: 'kvm', instanceRefId: refId, actorId: principal.userId, action: 'nic_detach',
      worker: async (report) => {
        await report(null, 'Detaching the secondary network-interface configuration');
        return this.virt.kvm.detachNic(refId, deviceId);
      },
    });
    return out.result;
  }

  public async executeAction(
    principal: AuthenticatedPrincipal,
    engine: VirtualizationEngine,
    refId: number,
    action: LifecycleAction,
    reason?: string,
    force = false
  ): Promise<UnifiedInstanceRecord> {
    // Keep the existing synchronous result/response contract (including reseller callers),
    // while sharing per-instance exclusion and persisted history with other VPS mutations.
    const authorizedInstance = await this.getAuthorizedInstance(principal, engine, refId);
    if ((action === 'start' || action === 'restart') && authorizedInstance.serviceLocked) {
      throw Object.assign(new Error('This VPS has an administrative service lock; unlock it before starting or restarting.'), { statusCode: 423 });
    }
    const outcome = await this.tasks.runSync({
      engine,
      instanceRefId: refId,
      actorId: principal.userId,
      action,
      worker: async (reportProgress) => {
        await reportProgress(null, 'Applying lifecycle action');
        const updated = await this.performLifecycleAction(principal, engine, refId, action, reason, force);
        await reportProgress(null, 'Operation succeeded; refreshing VPS record');
        return updated;
      },
    });
    return outcome.result;
  }

  public async executeActionTracked(
    principal: AuthenticatedPrincipal,
    engine: VirtualizationEngine,
    refId: number,
    action: LifecycleAction,
    reason?: string,
    force = false
  ): Promise<UnifiedInstanceRecord> {
    if (['suspend', 'unsuspend', 'delete'].includes(action) && !this.isStaff(principal)) {
      throw Object.assign(new Error(`Action "${action}" requires administrator privileges.`), {
        statusCode: 403,
      });
    }
    await this.getAuthorizedInstance(principal, engine, refId);
    const outcome = await this.tasks.runSync({
      engine,
      instanceRefId: refId,
      actorId: principal.userId,
      action,
      worker: async (reportProgress) => {
        await reportProgress(null, 'Applying lifecycle action');
        const updated = await this.performLifecycleAction(principal, engine, refId, action, reason, force);
        await reportProgress(null, 'Operation succeeded; refreshing VPS record');
        return updated;
      },
    });
    return outcome.result;
  }

  private async performLifecycleAction(
    principal: AuthenticatedPrincipal,
    engine: VirtualizationEngine,
    refId: number,
    action: LifecycleAction,
    reason?: string,
    force = false
  ): Promise<UnifiedInstanceRecord> {
    const adminOnlyActions: LifecycleAction[] = ['suspend', 'unsuspend', 'delete'];
    if (adminOnlyActions.includes(action) && !this.isStaff(principal)) {
      throw Object.assign(new Error(`Action "${action}" requires administrator privileges.`), {
        statusCode: 403,
      });
    }

    const authorizedInstance = await this.getAuthorizedInstance(principal, engine, refId);
    if ((action === 'start' || action === 'restart') && authorizedInstance.serviceLocked) {
      throw Object.assign(new Error('This VPS has an administrative service lock; unlock it before starting or restarting.'), { statusCode: 423 });
    }
    const updated = await this.virt
      .getAdapter(engine)
      .performLifecycleAction(refId, action, {
        reason,
        actorId: principal.userId,
        force,
      });

    await this.db.logActivity({
      userId: principal.userId,
      action: `instance_${action}`,
      resourceType: engine,
      resourceId: String(refId),
      details: { name: updated.name, actorRole: principal.role, reason: reason || null },
    });

    return updated;
  }

  /** Start an asynchronous, persisted lifecycle task while retaining the legacy synchronous action API. */
  public async startActionTask(
    principal: AuthenticatedPrincipal,
    engine: VirtualizationEngine,
    refId: number,
    action: LifecycleAction,
    reason?: string,
    force = false
  ): Promise<InstanceTask> {
    const allowed: LifecycleAction[] = [
      'start', 'shutdown', 'stop', 'restart', 'freeze', 'unfreeze', 'suspend', 'unsuspend', 'delete',
    ];
    if (!allowed.includes(action)) {
      throw Object.assign(new Error(`Invalid lifecycle action: ${action}`), { statusCode: 400 });
    }
    if (['suspend', 'unsuspend', 'delete'].includes(action) && !this.isStaff(principal)) {
      throw Object.assign(new Error(`Action "${action}" requires administrator privileges.`), {
        statusCode: 403,
      });
    }

    // Authorize before creating a task or revealing its progress to the caller.
    const authorizedInstance = await this.getAuthorizedInstance(principal, engine, refId);
    if ((action === 'start' || action === 'restart') && authorizedInstance.serviceLocked) {
      throw Object.assign(new Error('This VPS has an administrative service lock; unlock it before starting or restarting.'), { statusCode: 423 });
    }
    return this.tasks.start({
      engine,
      instanceRefId: refId,
      actorId: principal.userId,
      action,
      worker: async (reportProgress) => {
        await reportProgress(null, 'Applying lifecycle action');
        const instance = await this.performLifecycleAction(principal, engine, refId, action, reason, force);
        await reportProgress(null, 'Operation succeeded; refreshing VPS record');
        return instance;
      },
    });
  }

  public async listInstanceTasks(
    principal: AuthenticatedPrincipal,
    engine: VirtualizationEngine,
    refId: number,
    limit = 50
  ): Promise<InstanceTask[]> {
    await this.getAuthorizedInstance(principal, engine, refId);
    return this.tasks.list(engine, refId, limit);
  }

  public async getAuthorizedTask(
    principal: AuthenticatedPrincipal,
    taskId: string
  ): Promise<InstanceTask> {
    const task = await this.tasks.get(taskId);
    if (!task) throw Object.assign(new Error('VPS task not found.'), { statusCode: 404 });
    try {
      await this.getAuthorizedInstance(principal, task.engine, task.instanceRefId);
    } catch (err: any) {
      // A completed delete removes the VPS row; retain history access for its actor and staff.
      if (!(err?.statusCode === 404 && (task.actorId === principal.userId || this.isStaff(principal)))) {
        throw err;
      }
    }
    return task;
  }

  public async bulkAction(
    principal: AuthenticatedPrincipal,
    targets: Array<{ engine: VirtualizationEngine; refId: number }>,
    action: 'start' | 'stop' | 'restart'
  ): Promise<Array<{ uid: string; ok: boolean; error?: string }>> {
    const results: Array<{ uid: string; ok: boolean; error?: string }> = [];
    for (const t of targets) {
      const uid = `${t.engine}:${t.refId}`;
      try {
        await this.executeActionTracked(principal, t.engine, t.refId, action);
        results.push({ uid, ok: true });
      } catch (err: any) {
        results.push({ uid, ok: false, error: err.message });
      }
    }
    return results;
  }

  public async getTelemetry(
    principal: AuthenticatedPrincipal,
    engine: VirtualizationEngine,
    refId: number
  ): Promise<InstanceTelemetry> {
    await this.getAuthorizedInstance(principal, engine, refId);
    return this.virt.getAdapter(engine).getTelemetry(refId);
  }

  /**
   * Internal telemetry collection without a request principal. Used by the
   * background traffic-accounting loop (monitoring service); never exposed
   * through customer-facing routes.
   */
  public async collectInstanceTelemetry(
    engine: VirtualizationEngine,
    refId: number
  ): Promise<InstanceTelemetry> {
    return this.virt.getAdapter(engine).getTelemetry(refId);
  }

  /**
   * Background check that suspends expired LXC instances when `auto_suspend_enabled = 1`
   * and `whitelisted = 0`.
   */
  public async processExpiredInstances(): Promise<number> {
    const expired = await this.db.all<{ id: number; container_name: string; user_id: number }>(
      `SELECT id, container_name, user_id
       FROM lxc_instances
       WHERE suspended = 0
         AND whitelisted = 0
         AND auto_suspend_enabled = 1
         AND expires_at IS NOT NULL
         AND datetime(expires_at) <= datetime('now')`
    );

    let count = 0;
    for (const item of expired) {
      try {
        await this.virt.lxc.performLifecycleAction(item.id, 'suspend', {
          reason: 'Instance billing/expiration period reached',
        });
        await this.db.run(
          `INSERT INTO notifications (user_id, type, title, message)
           VALUES (?, 'warning', 'VPS Auto-Suspended (Expired)', ?)`,
          [
            item.user_id,
            `Your LXC VPS "${item.container_name}" reached its expiration date and was automatically suspended.`,
          ]
        );
        count++;
      } catch {
        // continue processing remaining instances
      }
    }
    return count;
  }
}
