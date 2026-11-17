import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';
import { InstanceManager } from '../virtualization/InstanceManager';
/**
 * Non-blocking Live & Historical Telemetry Collector, Threshold Alert Engine,
 * In-Panel Notification Manager, and Signed Webhook Dispatcher (Part 13 & Part 16).
 */
export declare class MonitoringService {
    private db;
    private nodeManager;
    private instanceManager;
    private pollTimer;
    private isPolling;
    private trafficTimer;
    constructor(db: UnifiedDatabase, nodeManager: NodeManager, instanceManager: InstanceManager);
    startBackgroundLoop(intervalMs?: number): void;
    stopBackgroundLoop(): void;
    collectCycle(): Promise<void>;
    getMetricsHistory(targetType: 'node' | 'kvm' | 'lxc', targetId: number, hours?: number): Promise<any[]>;
    /**
     * Persists an instance telemetry sample to metrics_history (record-on-read).
     * This builds honest instance (kvm/lxc) metrics history from real measured
     * samples without a heavy background sweep of every instance. Failures are
     * swallowed so a telemetry read never fails because history recording failed.
     */
    recordInstanceMetrics(engine: 'kvm' | 'lxc', targetId: number, sample: {
        cpuPercent: number;
        ramUsedMb: number;
        ramTotalMb: number;
        diskUsedGb: number;
        diskTotalGb: number;
        netRxBytes: number | null;
        netTxBytes: number | null;
    }): Promise<void>;
    /**
     * Reads every instance's real network counters and accumulates the delta
     * since the last sample into the instance_traffic ledger. Instances whose
     * telemetry cannot be read are skipped (their ledger keeps its last value)
     * so accounting never fabricates traffic.
     */
    accumulateInstanceTraffic(): Promise<{
        sampled: number;
        skipped: number;
    }>;
    /**
     * Cumulative bandwidth totals from the ledger plus measured period usage
     * computed from real metrics_history samples (delta between consecutive
     * samples; honest nulls where no samples exist).
     */
    getInstanceTraffic(engine: 'kvm' | 'lxc', refId: number, hours?: number): Promise<{
        rxBytes: number;
        txBytes: number;
        lastSampledAt: any;
        updatedAt: any;
        periodHours: number;
        periodRxBytes: number;
        periodTxBytes: number;
        sampleCount: number;
    }>;
    startTrafficLoop(intervalMs?: number): void;
    stopTrafficLoop(): void;
    private evaluateAlertRules;
    createNotification(input: {
        userId: number;
        type?: 'info' | 'success' | 'warning' | 'critical';
        title: string;
        message: string;
        data?: Record<string, unknown>;
    }): Promise<number>;
    listUserNotifications(userId: number, unreadOnly?: boolean): Promise<any[]>;
    markNotificationsRead(userId: number, notificationId?: number): Promise<void>;
    dispatchWebhookEvent(eventType: string, payload: Record<string, unknown>): Promise<void>;
    /** Maximum delivery attempts (1 initial + 2 retries) for a webhook event. */
    private static readonly WEBHOOK_MAX_ATTEMPTS;
    /** Base backoff between attempts (ms); grows linearly with the failed attempt number. */
    private static readonly WEBHOOK_RETRY_BASE_MS;
    /**
     * Delivers a webhook POST with bounded retries. A delivery that receives a
     * non-2xx response or fails at the network level is retried with linear
     * backoff (2s, 4s) up to WEBHOOK_MAX_ATTEMPTS total attempts. Each attempt
     * updates last_triggered_at/last_status_code/failure_count; last_error
     * records the failure reason and is cleared on success. Delivery is
     * non-blocking: the returned promise settles after the attempt decision,
     * and retries continue in the background.
     */
    private postWebhookNonBlocking;
}
