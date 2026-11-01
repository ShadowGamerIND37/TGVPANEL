import WebSocket from 'ws';
import { UnifiedDatabase } from '../../db/database';
import { LocalNodeRuntime } from '../../node-agent/agent';
import { NodeHealthReport } from '../../node-agent/health';
import { HostResourceStats } from '../../node-agent/host-stats';
export interface NodeRecord {
    id: number;
    name: string;
    hostname: string;
    ip_address: string;
    location: string;
    url: string;
    is_local: number;
    maintenance_mode: number;
    verify_ssl: number;
    mtls_enabled: number;
    status: string;
    agent_version: string | null;
    last_heartbeat: string | null;
    circuit_state: 'closed' | 'open' | 'half-open';
    consecutive_failures: number;
    cpu_cores: number;
    cpu_model: string | null;
    ram_total_mb: number;
    disk_total_gb: number;
    max_instances: number;
    tags: string;
    notes: string | null;
    supports_kvm?: number;
    supports_lxc?: number;
    kvm_available?: number;
    lxc_available?: number;
    nested_virt?: number;
    cgroup_version?: string | null;
    qemu_version?: string | null;
    lxc_version?: string | null;
    kernel_version?: string | null;
    storage_backends?: string | null;
    network_backends?: string | null;
    kvm_count?: number;
    kvm_running?: number;
    lxc_count?: number;
    lxc_running?: number;
    total_instances?: number;
    running_instances?: number;
    allocated_vcpus?: number;
    allocated_ram_mb?: number;
    allocated_disk_gb?: number;
    live_cpu_percent?: number | null;
    live_ram_used_mb?: number | null;
    live_disk_used_gb?: number | null;
    live_load_1?: number | null;
    latency_ms?: number | null;
}
export interface EndpointProbeResult {
    reachable: boolean;
    url: string;
    protocol: 'http' | 'https';
    latencyMs: number;
    httpStatus: number | null;
    agentDetected: boolean;
    tls?: {
        authorized: boolean;
        authorizationError?: string | null;
        subjectCN?: string | null;
        issuerCN?: string | null;
        validTo?: string | null;
        protocol?: string | null;
    } | null;
    message: string;
}
/**
 * Communicates with remote Node Agents over HTTPS/HTTP using replay-protected HMAC-SHA256 signatures
 * and per-node circuit breakers, while routing `is_local = 1` requests directly to `LocalNodeRuntime`.
 */
export declare class NodeManager {
    private db;
    readonly localRuntime: LocalNodeRuntime;
    private circuits;
    private latencies;
    private readonly failureThreshold;
    private readonly openCooldownMs;
    constructor(db: UnifiedDatabase, localRuntime?: LocalNodeRuntime);
    private normalizeTagsJson;
    private enrichNodeRow;
    private readonly nodeSelectSql;
    listNodes(): Promise<NodeRecord[]>;
    getNodeById(nodeId: number): Promise<NodeRecord | undefined>;
    getDefaultNodeForEngine(engine: 'kvm' | 'lxc'): Promise<NodeRecord>;
    createNode(input: {
        name: string;
        hostname: string;
        ipAddress: string;
        location?: string;
        url: string;
        verifySsl?: boolean;
        mtlsEnabled?: boolean;
        supportsKvm?: boolean;
        supportsLxc?: boolean;
        maxInstances?: number;
        tags?: string[] | string;
        notes?: string;
    }): Promise<{
        node: NodeRecord;
        bootstrapCredentials: {
            apiKey: string;
            hmacSecret: string;
        };
    }>;
    updateNode(nodeId: number, patch: {
        name?: string;
        hostname?: string;
        ipAddress?: string;
        location?: string;
        url?: string;
        maintenanceMode?: boolean;
        verifySsl?: boolean;
        maxInstances?: number;
        supportsKvm?: boolean;
        supportsLxc?: boolean;
        tags?: string[] | string;
        notes?: string;
    }): Promise<NodeRecord>;
    deleteNode(nodeId: number): Promise<void>;
    rotateNodeCredentials(nodeId: number): Promise<{
        apiKey: string;
        hmacSecret: string;
        pushedToAgent: boolean;
    }>;
    /**
     * Refreshes health, capabilities, and real host stats for a node (local or remote).
     */
    checkNodeHealthAndStats(nodeId: number): Promise<{
        node: NodeRecord;
        health: NodeHealthReport;
        stats: HostResourceStats;
        latencyMs: number;
    }>;
    resetCircuitBreaker(nodeId: number): Promise<NodeRecord>;
    /**
     * Pre-flight HTTP/HTTPS + TLS reachability probe for remote Node Agent URLs.
     */
    probeEndpointConnection(input: {
        url: string;
        verifySsl?: boolean;
        timeoutMs?: number;
    }): Promise<EndpointProbeResult>;
    /**
     * Computes transparent smart placement scores across cluster nodes for KVM or LXC workloads.
     */
    rankPlacementCandidates(engine: 'kvm' | 'lxc'): Promise<{
        nodeId: number;
        name: string;
        location: string;
        isLocal: boolean;
        eligible: boolean;
        hardwareReady: boolean;
        score: number;
        reasons: string[];
    }[]>;
    private checkCircuitAllowed;
    private recordCircuitSuccess;
    private recordCircuitFailure;
    requestRemoteNode<T = any>(nodeId: number, method: 'GET' | 'POST' | 'PATCH' | 'DELETE', pathWithQuery: string, body?: unknown, timeoutMs?: number): Promise<T>;
    openRemoteAgentWebSocket(nodeId: number, wsPath: string, query?: Record<string, string | number>): Promise<WebSocket>;
}
