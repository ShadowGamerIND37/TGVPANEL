import path from 'path';
import sqlite3 from 'sqlite3';
import { UnifiedDatabase } from './database';
import { runMigrations } from './migrations';
import { importHvmDatabase } from './hvm-importer';

async function main() {
  const sourcePath = process.argv[2];
  if (!sourcePath) {
    console.error('Usage: npm run import:hvm -- <path-to-hvm.db>');
    process.exit(1);
  }
  const dbDir = process.env.HKVM_DATA_DIR || path.resolve(process.cwd(), 'data');
  const dbPath = path.join(dbDir, 'hkvm.db');
  const raw = new sqlite3.Database(dbPath);
  const db = new UnifiedDatabase(raw, dbPath);

  try {
    await runMigrations(db);
    const report = await importHvmDatabase(db, path.resolve(sourcePath));
    console.log(JSON.stringify({ success: true, report }, null, 2));
  } finally {
    raw.close();
  }
}

main().catch((err) => {
  console.error('[HKVM HVM-Import Error]', err);
  process.exit(1);
});
