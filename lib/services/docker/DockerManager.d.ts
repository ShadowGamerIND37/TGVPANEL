import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';
export interface DockerPortMapping {
    hostPort: number;
    containerPort: number;
    protocol?: 'tcp' | 'udp';
}
export interface DockerContainerInput {
    name?: string;
    nodeId?: number;
    image?: string;
    ports?: Array<Partial<DockerPortMapping>> | string;
    env?: Record<string, string> | string;
    restartPolicy?: string;
    network?: string;
}
/**
 * Docker container manager (Area I).
 *
 * Panel-managed containers are stored in a registry and rendered as
 * `docker run` / lifecycle commands that are executed on the target node via
 * the allowlisted command runner — locally or through the node agent. The
 * `docker` binary is capability-gated: when it is not installed on the host,
 * apply operations fail honestly and the failure is recorded on the row.
 */
export declare class DockerManager {
    private db;
    private nodeManager?;
    constructor(db: UnifiedDatabase, nodeManager?: NodeManager);
    listContainers(): Promise<any[]>;
    getContainer(id: number): Promise<any>;
    getContainerByName(name: string): Promise<any>;
    private parsePorts;
    private parseEnv;
    private validateContainerInput;
    createContainer(input: DockerContainerInput): Promise<any>;
    updateContainer(id: number, input: DockerContainerInput): Promise<any>;
    deleteContainer(id: number): Promise<boolean>;
    /**
     * Renders the `docker run` argument list for a container spec. The rendered
     * command is what gets executed (locally or on the target node) and is also
     * exposed for display/validation.
     */
    renderRunArgs(container: any): string[];
    renderRunCommand(container: any): string;
    private lifecycleArgs;
    renderLifecycleCommand(container: any, mode: 'start' | 'stop' | 'restart' | 'remove'): string;
    private isRemoteNode;
    /**
     * Executes a container lifecycle action on the target node. Records honest
     * apply results on the container row.
     */
    applyContainer(container: any, mode?: 'create' | 'start' | 'stop' | 'restart' | 'remove'): Promise<{
        applied: boolean;
        error?: string | null;
    }>;
    private recordResult;
    getContainerStatus(id: number): Promise<{
        id: any;
        name: any;
        node_id: any;
        state: string | null;
        dockerAvailable: boolean | null;
        status: any;
        last_applied_at: any;
        last_error: any;
    } | null>;
}
