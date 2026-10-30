import path from 'path';
import sqlite3 from 'sqlite3';
import { UnifiedDatabase } from './database';
import { runMigrations } from './migrations';

async function main() {
  const dbDir = process.env.HKVM_DATA_DIR || path.resolve(process.cwd(), 'data');
  const dbPath = path.join(dbDir, 'hkvm.db');
  const raw = new sqlite3.Database(dbPath);
  const db = new UnifiedDatabase(raw, dbPath);

  try {
    const res = await runMigrations(db);
    console.log(
      JSON.stringify(
        {
          success: true,
          dbPath,
          appliedMigrations: res.applied,
          backupPath: res.backupPath || null,
        },
        null,
        2
      )
    );
  } finally {
    raw.close();
  }
}

main().catch((err) => {
  console.error('[HKVM Migrate Error]', err);
  process.exit(1);
});
