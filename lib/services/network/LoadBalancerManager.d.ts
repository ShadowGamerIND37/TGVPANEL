import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';
export interface LoadBalancerBackendInput {
    name: string;
    target: string;
    port: number;
    weight?: number;
    enabled?: boolean;
}
/**
 * HAProxy load balancer registry and lifecycle manager.
 *
 * The panel renders a complete HAProxy configuration from the registered
 * frontend + backend rows, validates it with `haproxy -c`, and starts/reloads
 * (or stops) the process on the target node via allowlisted host commands.
 * Nodes without the `haproxy` binary fail honestly — nothing is faked.
 */
export declare class LoadBalancerManager {
    private db;
    private nodeManager?;
    constructor(db: UnifiedDatabase, nodeManager?: NodeManager);
    private getConfigDir;
    private configPath;
    private pidPath;
    listLoadBalancers(): Promise<any[]>;
    getLoadBalancer(id: number): Promise<any>;
    private validateBackends;
    createLoadBalancer(input: {
        name: string;
        nodeId?: number;
        listenIp?: string;
        listenPort: number;
        protocol?: string;
        algorithm?: string;
        backends: LoadBalancerBackendInput[];
    }): Promise<any>;
    updateLoadBalancer(id: number, input: {
        name?: string;
        nodeId?: number;
        listenIp?: string;
        listenPort?: number;
        protocol?: string;
        algorithm?: string;
        enabled?: boolean;
        backends?: LoadBalancerBackendInput[];
    }): Promise<any>;
    private replaceBackends;
    deleteLoadBalancer(id: number): Promise<void>;
    renderConfig(lb: any): string;
    private isRemoteNode;
    /**
     * Validates the rendered config and starts/reloads/stops the HAProxy
     * process on the target node. Records honest validation/apply results on
     * the load balancer row.
     */
    applyLoadBalancer(lb: any, mode?: 'start' | 'reload' | 'stop'): Promise<{
        applied: boolean;
        validated: boolean;
        error?: string | null;
    }>;
    private stopLocalProcess;
    private recordResult;
    getLoadBalancerStatus(id: number): Promise<{
        id: any;
        name: any;
        enabled: boolean;
        running: boolean;
        lastAppliedAt: any;
        lastValidatedAt: any;
        lastError: any;
    } | null>;
}
