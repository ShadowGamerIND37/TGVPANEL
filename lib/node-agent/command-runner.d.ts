import { execFile } from 'child_process';
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
export declare function resolveBinaryPath(binaryName: string): string | null;
export declare function isBinaryAvailable(binaryName: string): boolean;
/**
 * Safely executes an allowlisted binary with `shell: false`, optional stdin pipe,
 * hard timeout, and bounded stdout/stderr buffers.
 */
export declare function runAllowlistedCommand(binaryName: string, args?: string[], options?: CommandOptions): Promise<CommandResult>;
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
export declare function detectHostCapabilities(): Promise<HostCapabilities>;
export { execFile };
