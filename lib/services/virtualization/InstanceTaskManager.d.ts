import { UnifiedDatabase } from '../../db/database';
import { VirtualizationEngine } from './VirtualizationAdapter';
export type InstanceTaskStatus = 'queued' | 'running' | 'succeeded' | 'failed';
export interface InstanceTask {
    id: string;
    engine: VirtualizationEngine;
    instanceRefId: number;
    actorId: number | null;
    action: string;
    status: InstanceTaskStatus;
    progress: number | null;
    currentStep: string | null;
    result: unknown;
    error: string | null;
    createdAt: string;
    startedAt: string | null;
    updatedAt: string;
    completedAt: string | null;
}
export declare class InstanceTaskConflictError extends Error {
    readonly statusCode = 409;
    constructor();
}
/**
 * Persistent task history and per-instance operation exclusion for VPS lifecycle work.
 * Work executes in this controller process; this is not a distributed job queue and does
 * not claim automatic recovery of an interrupted hypervisor operation.
 */
export declare class InstanceTaskManager {
    private readonly db;
    constructor(db: UnifiedDatabase);
    private mapRow;
    private createQueuedTask;
    start<T>(params: {
        engine: VirtualizationEngine;
        instanceRefId: number;
        actorId: number;
        action: string;
        worker: (reportProgress: (progress: number | null, step: string) => Promise<void>) => Promise<T>;
    }): Promise<InstanceTask>;
    runSync<T>(params: {
        engine: VirtualizationEngine;
        instanceRefId: number;
        actorId: number;
        action: string;
        worker: (reportProgress: (progress: number | null, step: string) => Promise<void>) => Promise<T>;
    }): Promise<{
        task: InstanceTask;
        result: T;
    }>;
    private execute;
    get(id: string): Promise<InstanceTask | undefined>;
    list(engine: VirtualizationEngine, instanceRefId: number, limit?: number): Promise<InstanceTask[]>;
    /** Mark all work left active by the previous controller process as interrupted; never replay blindly. */
    recoverInterruptedTasks(): Promise<number>;
    /** Mark old abandoned work failed; never retry dangerous operations blindly. */
    failStaleTasks(staleMinutes?: number): Promise<number>;
}
