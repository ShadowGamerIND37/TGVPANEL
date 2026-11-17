import crypto from 'crypto';
import http from 'http';
import https from 'https';
import { UnifiedDatabase } from '../../db/database';
import { decryptSecret } from '../../security/crypto-vault';
import { NodeManager } from '../nodes/NodeClient';
import { InstanceManager } from '../virtualization/InstanceManager';

/**
 * Non-blocking Live & Historical Telemetry Collector, Threshold Alert Engine,
 * In-Panel Notification Manager, and Signed Webhook Dispatcher (Part 13 & Part 16).
 */
export class MonitoringService {
  private db: UnifiedDatabase;
  private nodeManager: NodeManager;
  private instanceManager: InstanceManager;
  private pollTimer: NodeJS.Timeout | null = null;
  private isPolling = false;
  private trafficTimer: NodeJS.Timeout | null = null;

  constructor(
    db: UnifiedDatabase,
    nodeManager: NodeManager,
    instanceManager: InstanceManager
  ) {
    this.db = db;
    this.nodeManager = nodeManager;
    this.instanceManager = instanceManager;
  }

  public startBackgroundLoop(intervalMs = 60_000): void {
    if (this.pollTimer) return;
    // Kick off initial sample shortly after boot without blocking startup
    const bootTimer = setTimeout(() => {
      this.collectCycle().catch(() => undefined);
    }, 3000);
    if (typeof bootTimer.unref === 'function') bootTimer.unref();

    this.pollTimer = setInterval(() => {
      this.collectCycle().catch(() => undefined);
    }, intervalMs);
    if (typeof this.pollTimer.unref === 'function') this.pollTimer.unref();
  }

  public stopBackgroundLoop(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  public async collectCycle(): Promise<void> {
    if (this.isPolling) return;
    this.isPolling = true;
    try {
      const nodes = await this.nodeManager.listNodes();
      for (const n of nodes) {
        try {
          const { stats } = await this.nodeManager.checkNodeHealthAndStats(n.id);
          await this.db.run(
            `INSERT INTO metrics_history
               (target_type, target_id, cpu_percent, ram_used_mb, ram_total_mb, disk_used_gb, disk_total_gb, net_rx_bytes, net_tx_bytes, load_avg_1)
             VALUES ('node', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              n.id,
              stats.cpuPercent,
              stats.ramUsedMb,
              stats.ramTotalMb,
              stats.diskUsedGb,
              stats.diskTotalGb,
              stats.netRxBytes,
              stats.netTxBytes,
              stats.loadAvg1,
            ]
          );

          await this.evaluateAlertRules('node', {
            targetId: n.id,
            targetName: n.name,
            cpu_percent: stats.cpuPercent,
            ram_percent: stats.ramPercent,
            disk_percent: stats.diskPercent,
            load_avg: stats.loadAvg1,
          });
        } catch {
          // Node offline — circuit breaker already updated node status
          await this.dispatchWebhookEvent('node.offline', {
            nodeId: n.id,
            nodeName: n.name,
            timestamp: new Date().toISOString(),
          });
        }
      }

      // Check expired LXC instances
      await this.instanceManager.processExpiredInstances().catch(() => undefined);

      // Prune metrics older than 14 days to keep SQLite compact
      await this.db.run(
        `DELETE FROM metrics_history WHERE datetime(recorded_at) < datetime('now', '-14 days')`
      );
    } finally {
      this.isPolling = false;
    }
  }

  public async getMetricsHistory(
    targetType: 'node' | 'kvm' | 'lxc',
    targetId: number,
    hours = 24
  ) {
    const safeHours = Math.min(336, Math.max(1, Number(hours || 24)));
    return this.db.all<any>(
      `SELECT cpu_percent, ram_used_mb, ram_total_mb, disk_used_gb, disk_total_gb,
              net_rx_bytes, net_tx_bytes, load_avg_1, recorded_at
       FROM metrics_history
       WHERE target_type = ? AND target_id = ?
         AND datetime(recorded_at) >= datetime('now', ?)
       ORDER BY id ASC
       LIMIT 500`,
      [targetType, targetId, `-${safeHours} hours`]
    );
  }

  /**
   * Persists an instance telemetry sample to metrics_history (record-on-read).
   * This builds honest instance (kvm/lxc) metrics history from real measured
   * samples without a heavy background sweep of every instance. Failures are
   * swallowed so a telemetry read never fails because history recording failed.
   */
  public async recordInstanceMetrics(
    engine: 'kvm' | 'lxc',
    targetId: number,
    sample: {
      cpuPercent: number;
      ramUsedMb: number;
      ramTotalMb: number;
      diskUsedGb: number;
      diskTotalGb: number;
      netRxBytes: number | null;
      netTxBytes: number | null;
    }
  ): Promise<void> {
    await this.db.run(
      `INSERT INTO metrics_history
         (target_type, target_id, cpu_percent, ram_used_mb, ram_total_mb, disk_used_gb, disk_total_gb, net_rx_bytes, net_tx_bytes, load_avg_1)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
      [
        engine,
        targetId,
        sample.cpuPercent,
        sample.ramUsedMb,
        sample.ramTotalMb,
        sample.diskUsedGb,
        sample.diskTotalGb,
        sample.netRxBytes,
        sample.netTxBytes,
      ]
    );
  }

  /**
   * Reads every instance's real network counters and accumulates the delta
   * since the last sample into the instance_traffic ledger. Instances whose
   * telemetry cannot be read are skipped (their ledger keeps its last value)
   * so accounting never fabricates traffic.
   */
  public async accumulateInstanceTraffic(): Promise<{ sampled: number; skipped: number }> {
    const instances = await this.db.all<any>(
      `SELECT engine, ref_id FROM instances WHERE status IN ('running', 'frozen')`
    );
    let sampled = 0;
    let skipped = 0;
    for (const inst of instances) {
      try {
        const telemetry = await this.instanceManager.collectInstanceTelemetry(
          inst.engine as 'kvm' | 'lxc',
          Number(inst.ref_id)
        );
        const rx = telemetry.netRxBytes;
        const tx = telemetry.netTxBytes;
        if (typeof rx !== 'number' || typeof tx !== 'number') {
          skipped++;
          continue;
        }
        const existing = await this.db.get<any>(
          `SELECT rx_bytes, tx_bytes, last_rx_bytes, last_tx_bytes
           FROM instance_traffic WHERE instance_type = ? AND instance_id = ?`,
          [inst.engine, Number(inst.ref_id)]
        );
        // First sample establishes the baseline (pre-accounting counter
        // readings are not counted as usage); later samples accumulate only
        // the positive delta, so a counter reset (reboot/rollover) never
        // inflates or deflates the ledger.
        const hasBaseline = existing && existing.last_rx_bytes !== null && existing.last_rx_bytes !== undefined;
        const deltaRx = hasBaseline ? Math.max(0, rx - Number(existing.last_rx_bytes)) : 0;
        const deltaTx = hasBaseline ? Math.max(0, tx - Number(existing.last_tx_bytes)) : 0;
        const totalRx = Number(existing?.rx_bytes || 0) + deltaRx;
        const totalTx = Number(existing?.tx_bytes || 0) + deltaTx;
        await this.db.run(
          `INSERT INTO instance_traffic
             (instance_type, instance_id, rx_bytes, tx_bytes, last_rx_bytes, last_tx_bytes, last_sampled_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
           ON CONFLICT(instance_type, instance_id) DO UPDATE SET
             rx_bytes = excluded.rx_bytes,
             tx_bytes = excluded.tx_bytes,
             last_rx_bytes = excluded.last_rx_bytes,
             last_tx_bytes = excluded.last_tx_bytes,
             last_sampled_at = excluded.last_sampled_at,
             updated_at = excluded.updated_at`,
          [inst.engine, Number(inst.ref_id), totalRx, totalTx, rx, tx]
        );
        sampled++;
      } catch {
        skipped++;
      }
    }
    return { sampled, skipped };
  }

  /**
   * Cumulative bandwidth totals from the ledger plus measured period usage
   * computed from real metrics_history samples (delta between consecutive
   * samples; honest nulls where no samples exist).
   */
  public async getInstanceTraffic(
    engine: 'kvm' | 'lxc',
    refId: number,
    hours = 24
  ) {
    const safeHours = Math.min(168, Math.max(1, Number(hours || 24)));
    const ledger = await this.db.get<any>(
      `SELECT rx_bytes, tx_bytes, last_sampled_at, updated_at
       FROM instance_traffic WHERE instance_type = ? AND instance_id = ?`,
      [engine, refId]
    );
    const samples = await this.db.all<any>(
      `SELECT net_rx_bytes, net_tx_bytes, recorded_at
       FROM metrics_history
       WHERE target_type = ? AND target_id = ?
         AND datetime(recorded_at) >= datetime('now', ?)
       ORDER BY id ASC`,
      [engine, refId, `-${safeHours} hours`]
    );
    let periodRx = 0;
    let periodTx = 0;
    let prevRx: number | null = null;
    let prevTx: number | null = null;
    for (const sample of samples) {
      const rx = sample.net_rx_bytes === null || sample.net_rx_bytes === undefined ? null : Number(sample.net_rx_bytes);
      const tx = sample.net_tx_bytes === null || sample.net_tx_bytes === undefined ? null : Number(sample.net_tx_bytes);
      if (rx !== null && prevRx !== null) periodRx += Math.max(0, rx - prevRx);
      if (tx !== null && prevTx !== null) periodTx += Math.max(0, tx - prevTx);
      if (rx !== null) prevRx = rx;
      if (tx !== null) prevTx = tx;
    }
    return {
      rxBytes: Number(ledger?.rx_bytes || 0),
      txBytes: Number(ledger?.tx_bytes || 0),
      lastSampledAt: ledger?.last_sampled_at || null,
      updatedAt: ledger?.updated_at || null,
      periodHours: safeHours,
      periodRxBytes: periodRx,
      periodTxBytes: periodTx,
      sampleCount: samples.length,
    };
  }

  public startTrafficLoop(intervalMs = 300_000): void {
    if (this.trafficTimer) return;
    const tick = async () => {
      try {
        await this.accumulateInstanceTraffic().catch(() => undefined);
      } finally {
        this.trafficTimer = setTimeout(tick, intervalMs);
      }
    };
    // Small boot delay so the panel finishes starting before the first sweep.
    this.trafficTimer = setTimeout(tick, 5_000);
    if (typeof this.trafficTimer === 'object' && this.trafficTimer && 'unref' in this.trafficTimer) {
      (this.trafficTimer as any).unref?.();
    }
  }

  public stopTrafficLoop(): void {
    if (this.trafficTimer) {
      clearTimeout(this.trafficTimer);
      this.trafficTimer = null;
    }
  }

  private async evaluateAlertRules(
    scope: 'node' | 'instance',
    metrics: {
      targetId: number;
      targetName: string;
      cpu_percent: number;
      ram_percent: number;
      disk_percent: number;
      load_avg: number;
    }
  ): Promise<void> {
    const rules = await this.db.all<any>(
      `SELECT * FROM alert_rules WHERE enabled = 1 AND target_scope = ?`,
      [scope]
    );

    for (const rule of rules) {
      const val = Number((metrics as any)[rule.metric] ?? 0);
      const threshold = Number(rule.threshold || 90);
      let breached = false;
      if (rule.operator === '>=' && val >= threshold) breached = true;
      else if (rule.operator === '>' && val > threshold) breached = true;
      else if (rule.operator === '<=' && val <= threshold) breached = true;

      if (!breached) continue;

      // Respect 15-minute cooldown between identical alerts
      if (
        rule.last_triggered_at &&
        Date.now() - new Date(rule.last_triggered_at).getTime() < 15 * 60_000
      ) {
        continue;
      }

      await this.db.run(
        `UPDATE alert_rules SET last_triggered_at = datetime('now') WHERE id = ?`,
        [rule.id]
      );

      const admins = await this.db.all<{ id: number }>(
        `SELECT id FROM users WHERE role = 'admin'`
      );
      for (const adm of admins) {
        await this.createNotification({
          userId: adm.id,
          type: rule.severity || 'warning',
          title: `Alert: ${rule.name} (${metrics.targetName})`,
          message: `${rule.metric} reached ${val}% (threshold ${rule.operator} ${threshold}%) on ${scope} "${metrics.targetName}".`,
        });
      }

      await this.dispatchWebhookEvent('alert.triggered', {
        ruleName: rule.name,
        scope,
        targetName: metrics.targetName,
        metric: rule.metric,
        value: val,
        threshold,
      });
    }
  }

  // --- Notifications ---
  public async createNotification(input: {
    userId: number;
    type?: 'info' | 'success' | 'warning' | 'critical';
    title: string;
    message: string;
    data?: Record<string, unknown>;
  }) {
    const ins = await this.db.run(
      `INSERT INTO notifications (user_id, type, title, message, data)
       VALUES (?, ?, ?, ?, ?)`,
      [
        input.userId,
        input.type || 'info',
        input.title,
        input.message,
        input.data ? JSON.stringify(input.data) : null,
      ]
    );
    return ins.lastID;
  }

  public async listUserNotifications(userId: number, unreadOnly = false) {
    const sql = unreadOnly
      ? `SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY id DESC LIMIT 100`
      : `SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 100`;
    return this.db.all<any>(sql, [userId]);
  }

  public async markNotificationsRead(userId: number, notificationId?: number): Promise<void> {
    if (notificationId) {
      await this.db.run(
        `UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?`,
        [notificationId, userId]
      );
    } else {
      await this.db.run(`UPDATE notifications SET is_read = 1 WHERE user_id = ?`, [userId]);
    }
  }

  // --- Outbound HMAC Webhooks ---
  public async dispatchWebhookEvent(
    eventType: string,
    payload: Record<string, unknown>
  ): Promise<void> {
    const hooks = await this.db.all<any>(`SELECT * FROM webhooks WHERE is_active = 1`);
    for (const h of hooks) {
      let subscribed: string[] = [];
      try {
        subscribed = JSON.parse(h.events || '[]');
      } catch {
        subscribed = [];
      }
      if (!subscribed.includes('*') && !subscribed.includes(eventType)) continue;

      const bodyStr = JSON.stringify({
        event: eventType,
        timestamp: new Date().toISOString(),
        data: payload,
      });
      const secret = h.secret_enc ? decryptSecret(h.secret_enc) : '';
      const signature = secret
        ? crypto.createHmac('sha256', secret).update(bodyStr).digest('hex')
        : '';

      this.postWebhookNonBlocking(h.id, h.url, bodyStr, signature).catch(() => undefined);
    }
  }

  /** Maximum delivery attempts (1 initial + 2 retries) for a webhook event. */
  private static readonly WEBHOOK_MAX_ATTEMPTS = 3;

  /** Base backoff between attempts (ms); grows linearly with the failed attempt number. */
  private static readonly WEBHOOK_RETRY_BASE_MS = 2000;

  /**
   * Delivers a webhook POST with bounded retries. A delivery that receives a
   * non-2xx response or fails at the network level is retried with linear
   * backoff (2s, 4s) up to WEBHOOK_MAX_ATTEMPTS total attempts. Each attempt
   * updates last_triggered_at/last_status_code/failure_count; last_error
   * records the failure reason and is cleared on success. Delivery is
   * non-blocking: the returned promise settles after the attempt decision,
   * and retries continue in the background.
   */
  private postWebhookNonBlocking(
    hookId: number,
    urlStr: string,
    bodyStr: string,
    signatureHex: string,
    attempt = 1
  ): Promise<void> {
    return new Promise((resolve) => {
      const recordFailure = (errorText: string) => {
        void this.db
          .run(
            `UPDATE webhooks
                SET last_triggered_at = datetime('now'),
                    last_status_code = 0,
                    last_error = ?,
                    failure_count = failure_count + 1
              WHERE id = ?`,
            [errorText, hookId]
          )
          .then(() => {
            if (attempt >= MonitoringService.WEBHOOK_MAX_ATTEMPTS) {
              resolve();
              return;
            }
            const delay = MonitoringService.WEBHOOK_RETRY_BASE_MS * attempt;
            setTimeout(() => {
              this.postWebhookNonBlocking(hookId, urlStr, bodyStr, signatureHex, attempt + 1)
                .catch(() => undefined);
            }, delay);
            resolve();
          });
      };

      try {
        const u = new URL(urlStr);
        const isHttps = u.protocol === 'https:';
        const mod = isHttps ? https : http;
        const req = mod.request(
          {
            method: 'POST',
            hostname: u.hostname,
            port: u.port || (isHttps ? 443 : 80),
            path: u.pathname + u.search,
            timeout: 8000,
            headers: {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(bodyStr),
              'User-Agent': 'TGVPANEL-Webhook/3.0',
              ...(signatureHex ? { 'X-HKVM-Signature-256': `sha256=${signatureHex}` } : {}),
            },
          },
          (res) => {
            res.resume();
            const code = res.statusCode || 0;
            if (code >= 200 && code < 300) {
              void this.db
                .run(
                  `UPDATE webhooks
                      SET last_triggered_at = datetime('now'),
                          last_status_code = ?,
                          last_error = NULL,
                          failure_count = 0
                    WHERE id = ?`,
                  [code, hookId]
                )
                .finally(() => resolve());
            } else {
              recordFailure(`HTTP ${code}`);
            }
          }
        );
        req.on('error', (err: any) => recordFailure(String(err?.message || err)));
        req.on('timeout', () => {
          req.destroy();
          recordFailure('Request timed out');
        });
        req.write(bodyStr);
        req.end();
      } catch (err: any) {
        recordFailure(String(err?.message || err));
      }
    });
  }
}
