import * as fs from 'fs';
import * as path from 'path';
import sqlite3 from 'sqlite3';
import session from 'express-session';

interface SessionRow {
  sid: string;
  data: string;
  expires_at: number;
  created_at: number;
  last_seen_at: number | null;
  user_id: number | null;
  ip: string | null;
  user_agent: string | null;
}

/**
 * SQLite-backed express-session store.
 *
 * Replaces the default in-memory store so panel sessions are persisted,
 * enumerable (inventory) and revocable (single or per-user). Every get/set
 * also records lightweight metadata (user id, IP, user agent, last seen)
 * so administrators can audit and revoke active sessions.
 */
export class SqliteSessionStore extends session.Store {
  private db: sqlite3.Database;

  constructor(dbPath: string) {
    super();
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.db = new sqlite3.Database(dbPath);
    // Match the panel database's WAL mode and wait through transient locks so
    // concurrent writes from the app connection and this store never collide.
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA busy_timeout = 5000');
    // Never let a background statement error crash the process.
    this.db.on('error', (err) => {
      console.error('[SessionStore] database error:', err.message);
    });
    // NOTE: sqlite3 `run()` without a callback never executes; use `exec()`
    // so the schema is guaranteed to exist before the first get/set.
    this.db.exec(
      `CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER,
        user_id INTEGER,
        ip TEXT,
        user_agent TEXT
      )`
    );
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`);
  }

  private expiry(session: any): number {
    const cookieExpires = session?.cookie?.expires;
    if (cookieExpires) {
      const ms = new Date(cookieExpires).getTime();
      if (Number.isFinite(ms)) return ms;
    }
    return Date.now() + 24 * 60 * 60 * 1000;
  }

  get(sid: string, callback: (err: any, session?: any) => void): void {
    this.db.get<SessionRow>(`SELECT * FROM sessions WHERE sid = ?`, [sid], (err, row) => {
      if (err) return callback(err);
      if (!row) return callback(null, null);
      if (Number(row.expires_at) <= Date.now()) {
        this.destroy(sid, () => undefined);
        return callback(null, null);
      }
      try {
        const parsed = JSON.parse(row.data);
        this.db.run(`UPDATE sessions SET last_seen_at = ? WHERE sid = ?`, [Date.now(), sid], () => undefined);
        return callback(null, parsed);
      } catch (parseErr) {
        return callback(parseErr);
      }
    });
  }

  set(sid: string, sessionData: any, callback?: (err?: any) => void): void {
    const expires = this.expiry(sessionData);
    const userId = sessionData?.userId ?? null;
    this.db.run(
      `INSERT INTO sessions (sid, data, expires_at, created_at, last_seen_at, user_id)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(sid) DO UPDATE SET
         data = excluded.data,
         expires_at = excluded.expires_at,
         user_id = excluded.user_id,
         last_seen_at = excluded.last_seen_at`,
      [sid, JSON.stringify(sessionData), expires, Date.now(), Date.now(), userId],
      (err) => {
        if (callback) callback(err || undefined);
      }
    );
  }

  destroy(sid: string, callback?: (err?: any) => void): void {
    this.db.run(`DELETE FROM sessions WHERE sid = ?`, [sid], (err) => {
      if (callback) callback(err || undefined);
    });
  }

  touch(sid: string, sessionData: any, callback?: (err?: any) => void): void {
    this.set(sid, sessionData, callback);
  }

  length(callback: (err: any, length?: number) => void): void {
    this.db.get<{ count: number }>(`SELECT COUNT(*) AS count FROM sessions WHERE expires_at > ?`, [Date.now()], (err, row) => {
      callback(err, row ? Number(row.count) : 0);
    });
  }

  clear(callback?: (err?: any) => void): void {
    this.db.run(`DELETE FROM sessions`, (err) => {
      if (callback) callback(err || undefined);
    });
  }

  all(callback: (err: any, sessions?: any[]) => void): void {
    this.db.all<SessionRow>(`SELECT * FROM sessions WHERE expires_at > ? ORDER BY last_seen_at DESC`, [Date.now()], (err, rows) => {
      if (err) return callback(err);
      const sessions = (rows || []).map((row) => {
        try {
          return JSON.parse(row.data);
        } catch {
          return null;
        }
      }).filter(Boolean);
      callback(null, sessions);
    });
  }

  /** Records request metadata for inventory/audit (called by a thin middleware). */
  recordActivity(sid: string, userId: number | null, ip: string, userAgent: string): void {
    this.db.run(
      `UPDATE sessions SET last_seen_at = ?, user_id = COALESCE(?, user_id), ip = ?, user_agent = ? WHERE sid = ?`,
      [Date.now(), userId, ip, userAgent, sid],
      () => undefined
    );
  }

  /** Session inventory for administrators (joins the users table for names). */
  listSessions(): Promise<any[]> {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT s.sid, s.user_id, u.username, s.created_at, s.last_seen_at, s.expires_at, s.ip, s.user_agent
         FROM sessions s
         LEFT JOIN users u ON u.id = s.user_id
         WHERE s.expires_at > ?
         ORDER BY s.last_seen_at DESC`,
        [Date.now()],
        (err, rows) => {
          if (err) return reject(err);
          resolve(rows || []);
        }
      );
    });
  }

  revokeSession(sid: string): Promise<number> {
    return new Promise((resolve, reject) => {
      this.db.run(`DELETE FROM sessions WHERE sid = ?`, [sid], function (err) {
        if (err) return reject(err);
        resolve(this.changes);
      });
    });
  }

  revokeUserSessions(userId: number): Promise<number> {
    return new Promise((resolve, reject) => {
      this.db.run(`DELETE FROM sessions WHERE user_id = ?`, [userId], function (err) {
        if (err) return reject(err);
        resolve(this.changes);
      });
    });
  }
}
