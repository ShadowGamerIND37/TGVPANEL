import session from 'express-session';
/**
 * SQLite-backed express-session store.
 *
 * Replaces the default in-memory store so panel sessions are persisted,
 * enumerable (inventory) and revocable (single or per-user). Every get/set
 * also records lightweight metadata (user id, IP, user agent, last seen)
 * so administrators can audit and revoke active sessions.
 */
export declare class SqliteSessionStore extends session.Store {
    private db;
    constructor(dbPath: string);
    private expiry;
    get(sid: string, callback: (err: any, session?: any) => void): void;
    set(sid: string, sessionData: any, callback?: (err?: any) => void): void;
    destroy(sid: string, callback?: (err?: any) => void): void;
    touch(sid: string, sessionData: any, callback?: (err?: any) => void): void;
    length(callback: (err: any, length?: number) => void): void;
    clear(callback?: (err?: any) => void): void;
    all(callback: (err: any, sessions?: any[]) => void): void;
    /** Records request metadata for inventory/audit (called by a thin middleware). */
    recordActivity(sid: string, userId: number | null, ip: string, userAgent: string): void;
    /** Session inventory for administrators (joins the users table for names). */
    listSessions(): Promise<any[]>;
    revokeSession(sid: string): Promise<number>;
    revokeUserSessions(userId: number): Promise<number>;
}
