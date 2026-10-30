import WebSocket from 'ws';
export interface ActiveConsoleSession {
    sessionId: string;
    containerName: string;
    startedAt: number;
    cols: number;
    rows: number;
    close: () => void;
}
/**
 * Spawns a real interactive PTY attached to an LXC container (`lxc-attach -n <name> -- /bin/sh -l` or `/bin/bash`)
 * and bridges stdin/stdout/resize frames over WebSocket. Never fabricates terminal output.
 */
export declare class LxcContainerConsoleManager {
    private sessions;
    private idleTimeoutMs;
    constructor(idleTimeoutMs?: number);
    attachWebSocket(ws: WebSocket, containerName: string, options?: {
        cols?: number;
        rows?: number;
        sessionId?: string;
    }): ActiveConsoleSession;
    listActiveSessions(): Array<Omit<ActiveConsoleSession, 'close'>>;
}
