#!/usr/bin/env node
/**
 * TGVPANEL — End-to-End Integration, Security & Acceptance Test Suite
 *
 * Runs against an isolated temporary clone of data/tgvpanel.db so live database state
 * is never polluted. Exercises real SQLite, real Express + WebSocket server,
 * real standalone Node Agent HTTP/HMAC server, real AES-256-GCM/TOTP/CSRF/RBAC,
 * real Werkzeug pbkdf2/scrypt legacy HVM importer, and real node-pty restricted shell.
 */
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const sqlite3 = require('sqlite3');
const WebSocket = require('ws');
const { isEncryptedArchive } = require('../lib/services/backup/backup-crypto');

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'tgvpanel-acceptance-'));
const testDbPath = path.join(tmpRoot, 'tgvpanel.db');
const primaryRepoDb = path.resolve(__dirname, '../data/tgvpanel.db');
fs.copyFileSync(primaryRepoDb, testDbPath);

const TEST_PORT = 18940 + Math.floor(Math.random() * 500);
const AGENT_PORT = 19540 + Math.floor(Math.random() * 500);

const seededLegacySessionSecret = crypto.randomBytes(32).toString('hex');
fs.writeFileSync(
  path.join(tmpRoot, '.hkvm-secret'),
  JSON.stringify(
    {
      sessionSecret: seededLegacySessionSecret,
      credentialKeyHex: crypto.randomBytes(32).toString('hex'),
      csrfSecret: crypto.randomBytes(32).toString('hex'),
    },
    null,
    2
  ),
  { mode: 0o600 }
);

process.env.TGVPANEL_DATA_DIR = tmpRoot;
process.env.TGVPANEL_DB_PATH = testDbPath;
process.env.TGVPANEL_SECRET_FILE = path.join(tmpRoot, '.tgvpanel-secret');
process.env.TGVPANEL_LXC_PATH = path.join(tmpRoot, 'local-lxc');
process.env.TGVPANEL_BACKUP_DIR = path.join(tmpRoot, 'local-backups');
process.env.PORT = String(TEST_PORT);
process.env.TGVPANEL_DISABLE_BACKGROUND_POLLER = 'true';
process.env.TGVPANEL_ENABLE_NODE_SHELL = 'true';
// Test-only: treat the loopback peer as a trusted proxy so the per-step
// X-Forwarded-For headers used throughout this suite key rate limits
// per test instead of sharing one 127.0.0.1 bucket across the whole run.
process.env.TRUSTED_PROXIES = '127.0.0.1';

const {
  getSecretBundle,
  getSecretVaultPath,
  encryptSecret,
  decryptSecret,
  isEncryptedSecret,
  generateApiKeyPair,
  hashApiKey,
  signAgentRequest,
  computeTotpCode,
  verifyTotpCode,
} = require('../lib/security/crypto-vault');
const { signResellerRequest } = require('../lib/security/reseller-api-auth');
const { UnifiedDatabase, resolveAndMigrateDatabasePath } = require('../lib/db/database');
const { runMigrations } = require('../lib/db/migrations');
const { KVMAdapter } = require('../lib/services/virtualization/KVMAdapter');
const { LXCAdapter } = require('../lib/services/virtualization/LXCAdapter');
const { importHvmDatabase, dryRunHvmImport } = require('../lib/db/hvm-importer');
const { createNodeAgentServer } = require('../lib/node-agent/agent');
const { runAllowlistedCommand, buildSafeSpawnEnv } = require('../lib/node-agent/command-runner');
const {
  LxcContainerManager,
  resolveDownloadReleaseCandidates,
  computeIpv4SubnetCidr,
  resolveGuestDnsServers,
} = require('../lib/node-agent/container-manager');

const results = [];
// The harness acts as a trusted reverse proxy (TRUSTED_PROXIES=127.0.0.1), so the
// rate limiter honors X-Forwarded-For. Give each test step a unique XFF so every step
// gets a fresh limiter bucket instead of sharing one 120/min window across the whole
// suite. T09 still exercises the real limiter within its own step via a shared XFF.
let currentTestXff = null;
let testStepCounter = 0;
async function runStep(name, fn) {
  currentTestXff = `10.${(testStepCounter++) % 250}.0.1`;
  const start = Date.now();
  try {
    await fn();
    const ms = Date.now() - start;
    results.push({ name, status: 'PASS', ms });
    console.log(`  \x1b[32m✓ PASS\x1b[0m  ${name} (${ms}ms)`);
  } catch (err) {
    const ms = Date.now() - start;
    results.push({ name, status: 'FAIL', ms, error: err.stack || err.message });
    console.error(`  \x1b[31m✗ FAIL\x1b[0m  ${name} (${ms}ms)\n    ${err.stack || err.message}`);
  }
}

class SessionClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.cookie = '';
    this.csrfToken = '';
  }

  async request(method, urlPath, body = undefined, extraHeaders = {}) {
    const headers = { ...extraHeaders };
    if (currentTestXff && !headers['X-Forwarded-For']) headers['X-Forwarded-For'] = currentTestXff;
    if (this.cookie) headers['Cookie'] = this.cookie;
    if (this.csrfToken && !headers['X-CSRF-Token'] && !headers['Authorization']) {
      headers['X-CSRF-Token'] = this.csrfToken;
    }
    let payload;
    if (body !== undefined) {
      if (Buffer.isBuffer(body)) {
        payload = body;
        headers['Content-Length'] = payload.length;
      } else {
        payload = typeof body === 'string' ? body : JSON.stringify(body);
        headers['Content-Type'] = headers['Content-Type'] || 'application/json';
        headers['Content-Length'] = Buffer.byteLength(payload);
      }
    }

    return new Promise((resolve, reject) => {
      const u = new URL(urlPath, this.baseUrl);
      const req = http.request(
        {
          hostname: u.hostname,
          port: u.port,
          path: u.pathname + u.search,
          method,
          headers,
        },
        (res) => {
          const setCookie = res.headers['set-cookie'];
          if (setCookie && setCookie.length > 0) {
            this.cookie = setCookie.map((c) => c.split(';')[0]).join('; ');
          }
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            const csrfMatch = text.match(/meta name="csrf-token" content="([^"]+)"/);
            if (csrfMatch) this.csrfToken = csrfMatch[1];
            let json = null;
            try {
              json = JSON.parse(text);
            } catch (_) {}
            resolve({ status: res.statusCode, headers: res.headers, text, json });
          });
        }
      );
      req.on('error', reject);
      if (payload !== undefined) req.write(payload);
      req.end();
    });
  }
}

function makeWerkzeugPbkdf2Hash(password, salt = 'testsalt1234', iterations = 600000) {
  const dk = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256').toString('hex');
  return `pbkdf2:sha256:${iterations}$${salt}$${dk}`;
}

(async () => {
  console.log('\n====================================================================');
  console.log('  TGVPANEL — Unified Virtualization Panel Acceptance Test Suite');
  console.log('====================================================================\n');

  let agentServer = null;
  let httpsAgentServer = null;
  let app = null;
  let remoteNodeId = null;
  let agentApiKey = null;
  let agentHmacSecret = null;
  const installedLxcShims = [];
  const rootOwnedCleanupDirs = [];

  try {
    // 1. Pre-boot migration & schema preservation test on a clean HKVM V2 baseline DB
    await runStep('T01: Transactional SQLite backup & migrations v001..v022 preserve legacy data, task locks, KVM device/VNC/service-lock settings & cascade VM FKs', async () => {
      const v2ScratchPath = path.join(tmpRoot, 'v2_scratch.db');
      const v2Raw = new sqlite3.Database(v2ScratchPath);
      const v2Db = new UnifiedDatabase(v2Raw, v2ScratchPath);
      await v2Db.exec(`
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, email TEXT, full_name TEXT, role TEXT DEFAULT 'user', is_active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        INSERT INTO users (username, password, email, role) VALUES ('admin', '$2a$10$legacyhashplaceholder123456789012345678901234567', 'admin@hopingboyz.local', 'admin');
        CREATE TABLE vms (vm_id INTEGER PRIMARY KEY AUTOINCREMENT, vm_name TEXT, hostname TEXT, owner_id INTEGER, memory INTEGER DEFAULT 1024, cpus INTEGER DEFAULT 1, disk_size TEXT DEFAULT '20G', status TEXT DEFAULT 'stopped', password TEXT);
        INSERT INTO vms (vm_name, hostname, owner_id) VALUES ('legacy-fk-vm', 'legacy-fk', 1);
        CREATE TABLE vm_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, vm_id INTEGER, action TEXT, status TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(vm_id) REFERENCES vms(vm_id));
        INSERT INTO vm_logs (vm_id, action, status, message) VALUES (1, 'create', 'pending', 'Legacy VM created');
        CREATE TABLE vm_snapshots (snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT, vm_id INTEGER, snapshot_name TEXT, size_gb REAL, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(vm_id) REFERENCES vms(vm_id));
        INSERT INTO vm_snapshots (vm_id, snapshot_name, size_gb, description) VALUES (1, 'snap-legacy', 1.2, 'Before upgrade');
        CREATE TABLE os_templates (template_id INTEGER PRIMARY KEY AUTOINCREMENT, template_key TEXT UNIQUE, template_name TEXT, password TEXT);
        CREATE TABLE settings (setting_key TEXT PRIMARY KEY, setting_value TEXT, updated_at DATETIME);
        INSERT INTO settings (setting_key, setting_value, updated_at) VALUES ('site_name', 'HKVM', datetime('now'));
        INSERT INTO settings (setting_key, setting_value, updated_at) VALUES ('panel_title', 'HKVM Panel V2.0', datetime('now'));
        INSERT INTO settings (setting_key, setting_value, updated_at) VALUES ('panel_version', 'V3.0', datetime('now'));
        CREATE TABLE discord_settings (id INTEGER PRIMARY KEY, enabled INTEGER DEFAULT 0);
        CREATE TABLE user_discord_accounts (id INTEGER PRIMARY KEY, user_id INTEGER, discord_id TEXT);
      `);

      const migRes = await runMigrations(v2Db);
      assert.ok(migRes.applied.length >= 22, 'Expected all v001..v022 migrations to apply');
      assert.ok(migRes.backupPath && fs.existsSync(migRes.backupPath), 'Expected pre-migration backup');

      // Verify v009 upgraded vm_logs & vm_snapshots to ON DELETE CASCADE while preserving rows,
      // and deleting from vms with PRAGMA foreign_keys = ON succeeds cleanly!
      assert.strictEqual((await v2Db.all(`SELECT * FROM vm_logs WHERE vm_id = 1`)).length, 1);
      assert.strictEqual((await v2Db.all(`SELECT * FROM vm_snapshots WHERE vm_id = 1`)).length, 1);
      await v2Db.run(`DELETE FROM vms WHERE vm_id = 1`);
      assert.strictEqual((await v2Db.all(`SELECT * FROM vms WHERE vm_id = 1`)).length, 0);
      assert.strictEqual((await v2Db.all(`SELECT * FROM vm_logs WHERE vm_id = 1`)).length, 0);
      assert.strictEqual((await v2Db.all(`SELECT * FROM vm_snapshots WHERE vm_id = 1`)).length, 0);

      const lxcCols = await v2Db.all(`PRAGMA table_info(lxc_instances)`);
      assert.ok(lxcCols.some((c) => c.name === 'kvm_nesting'), 'Expected kvm_nesting column on lxc_instances');

      const kvmDeviceColumns = await v2Db.all(`PRAGMA table_info(vms)`);
      assert.ok(kvmDeviceColumns.some((column) => column.name === 'extra_disks_json'), 'Expected v020 secondary-disk configuration');
      assert.ok(kvmDeviceColumns.some((column) => column.name === 'extra_nics_json'), 'Expected v020 secondary-NIC configuration');
      assert.ok(kvmDeviceColumns.some((column) => column.name === 'vnc_port'), 'Expected v021 local VNC configuration');
      assert.ok(kvmDeviceColumns.some((column) => column.name === 'service_locked'), 'Expected v022 KVM service lock');
      assert.ok(lxcCols.some((column) => column.name === 'service_locked'), 'Expected v022 LXC service lock');

      const instanceTaskColumns = await v2Db.all(`PRAGMA table_info(instance_tasks)`);
      assert.ok(instanceTaskColumns.some((column) => column.name === 'progress'), 'Expected durable task progress from v019');
      const taskIndexes = await v2Db.all(`PRAGMA index_list(instance_tasks)`);
      assert.ok(taskIndexes.some((index) => index.name === 'idx_instance_tasks_active_lock' && index.unique === 1), 'Expected one-active-task-per-VPS uniqueness lock');

      const resellerCustomerColumns = await v2Db.all(`PRAGMA table_info(reseller_customers)`);
      assert.ok(resellerCustomerColumns.some((column) => column.name === 'reseller_user_id'), 'Expected reseller customer ownership column from v018');
      assert.ok(!resellerCustomerColumns.some((column) => column.name === 'deleted_at'), 'Customer records should not be retained after a requested deletion.');
      await v2Db.run(`INSERT INTO reseller_customers (reseller_user_id, display_name, email) VALUES (1, 'Legacy Contact', 'contact@example.org')`);
      await assert.rejects(() => v2Db.run(`INSERT INTO reseller_customers (reseller_user_id, display_name, email) VALUES (1, 'Duplicate Contact', 'CONTACT@example.org')`), /UNIQUE constraint failed/i);

      const adminUser = await v2Db.get(`SELECT * FROM users WHERE username = 'admin'`);
      assert.ok(adminUser, 'Legacy admin user preserved');
      assert.strictEqual(adminUser.email, 'admin@shadowgamerind.local', 'Expected default email rebranded to ShadowGamerIND');
      const siteNameSetting = await v2Db.get(`SELECT setting_value FROM settings WHERE setting_key = 'site_name'`);
      assert.strictEqual(siteNameSetting.setting_value, 'TGVPANEL', 'Expected legacy site_name HKVM migrated to TGVPANEL');
      const panelTitleSetting = await v2Db.get(`SELECT setting_value FROM settings WHERE setting_key = 'panel_title'`);
      assert.strictEqual(panelTitleSetting.setting_value, 'TGVPANEL V4.0', 'Expected legacy panel_title migrated to TGVPANEL V4.0');
      const panelVersionSetting = await v2Db.get(`SELECT setting_value FROM settings WHERE setting_key = 'panel_version'`);
      assert.strictEqual(panelVersionSetting.setting_value, 'V4.0', 'Expected legacy V3 panel_version migrated to V4.0');
      const maintMsgSetting = await v2Db.get(`SELECT setting_value FROM settings WHERE setting_key = 'maintenance_message'`);
      assert.ok(maintMsgSetting.setting_value.startsWith('TGVPANEL'), 'Expected maintenance_message branded as TGVPANEL');
      const templates = await v2Db.all(`SELECT * FROM lxc_templates`);
      assert.ok(templates.length >= 15, 'Seeded LXC OS template catalog');
      await v2Db.close();

      // A V3 database with operator-customized branding/settings must retain those values on V4 upgrade.
      const customSettingsPath = path.join(tmpRoot, 'custom-settings.db');
      const customSettingsRaw = new sqlite3.Database(customSettingsPath);
      const customSettingsDb = new UnifiedDatabase(customSettingsRaw, customSettingsPath);
      await customSettingsDb.exec(`
        CREATE TABLE settings (setting_key TEXT PRIMARY KEY, setting_value TEXT, updated_at DATETIME);
        INSERT INTO settings (setting_key, setting_value) VALUES ('panel_title', 'Acme Compute');
        INSERT INTO settings (setting_key, setting_value) VALUES ('panel_version', 'Canary');
        CREATE TABLE backup_schedules (id INTEGER PRIMARY KEY, enabled INTEGER, frequency TEXT, retention_count INTEGER, next_run TEXT);
        CREATE TABLE container_backups (id INTEGER PRIMARY KEY, schedule_id INTEGER, is_scheduled INTEGER);
        CREATE TABLE snapshot_schedules (id INTEGER PRIMARY KEY, enabled INTEGER, frequency TEXT, retention_count INTEGER, next_run TEXT);
        CREATE TABLE vm_snapshots (snapshot_id INTEGER PRIMARY KEY, vm_id INTEGER);
        CREATE TABLE container_snapshots (id INTEGER PRIMARY KEY, lxc_id INTEGER);
        CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP);
      `);
      for (let version = 1; version <= 14; version += 1) {
        await customSettingsDb.run(`INSERT INTO schema_migrations (version, name, checksum) VALUES (?, ?, ?)`, [version, `fixture_${version}`, 'fixture']);
      }
      const v4SettingsMigration = await runMigrations(customSettingsDb);
      assert.ok(v4SettingsMigration.applied.includes('v015_scheduled_backup_status_and_retention_metadata'));
      assert.ok(v4SettingsMigration.applied.includes('v016_scheduled_snapshot_status_and_retention_metadata'));
      assert.strictEqual((await customSettingsDb.get(`SELECT setting_value FROM settings WHERE setting_key = 'panel_title'`)).setting_value, 'Acme Compute');
      assert.strictEqual((await customSettingsDb.get(`SELECT setting_value FROM settings WHERE setting_key = 'panel_version'`)).setting_value, 'Canary');
      await customSettingsDb.close();

      // Verify automatic zero-data-loss file migration: hkvm.db (+ -wal/-shm) -> tgvpanel.db (+ -wal/-shm)
      const legacyDbDir = path.join(tmpRoot, 'legacy-db-migration-check');
      fs.mkdirSync(legacyDbDir, { recursive: true });
      fs.writeFileSync(path.join(legacyDbDir, 'hkvm.db'), 'sqlite-main-bytes');
      fs.writeFileSync(path.join(legacyDbDir, 'hkvm.db-wal'), 'sqlite-wal-bytes');
      fs.writeFileSync(path.join(legacyDbDir, 'hkvm.db-shm'), 'sqlite-shm-bytes');
      const resolvedMigratedDb = resolveAndMigrateDatabasePath(legacyDbDir);
      assert.strictEqual(resolvedMigratedDb, path.join(legacyDbDir, 'tgvpanel.db'));
      assert.strictEqual(fs.readFileSync(path.join(legacyDbDir, 'tgvpanel.db'), 'utf8'), 'sqlite-main-bytes');
      assert.strictEqual(fs.readFileSync(path.join(legacyDbDir, 'tgvpanel.db-wal'), 'utf8'), 'sqlite-wal-bytes');
      assert.strictEqual(fs.readFileSync(path.join(legacyDbDir, 'tgvpanel.db-shm'), 'utf8'), 'sqlite-shm-bytes');
      assert.strictEqual(fs.existsSync(path.join(legacyDbDir, 'hkvm.db')), false, 'Expected legacy hkvm.db renamed');
      assert.strictEqual(fs.existsSync(path.join(legacyDbDir, 'hkvm.db-wal')), false, 'Expected legacy hkvm.db-wal renamed');
      assert.strictEqual(fs.existsSync(path.join(legacyDbDir, 'hkvm.db-shm')), false, 'Expected legacy hkvm.db-shm renamed');

      // Ensure testDbPath also has all migrations applied cleanly
      const rawSqlite = new sqlite3.Database(testDbPath);
      const udb = new UnifiedDatabase(rawSqlite, testDbPath);
      await runMigrations(udb);
      await udb.close();
    });

    // 2. Cryptographic Vault & API Key Hashing
    await runStep('T02: Secret vault (.tgvpanel-secret + legacy .hkvm-secret migration), AES-256-GCM & tamper rejection', async () => {
      const legacyVaultFile = path.join(tmpRoot, '.hkvm-secret');
      const bundle = getSecretBundle();
      assert.strictEqual(bundle.sessionSecret, seededLegacySessionSecret, 'Expected legacy .hkvm-secret secrets preserved');
      assert.ok(getSecretVaultPath().endsWith('.tgvpanel-secret'), 'Expected .tgvpanel-secret vault path');
      assert.strictEqual(fs.existsSync(getSecretVaultPath()), true, 'Expected .tgvpanel-secret to exist');
      assert.strictEqual(fs.existsSync(legacyVaultFile), false, 'Expected legacy .hkvm-secret renamed to .tgvpanel-secret');
      const ct = encryptSecret('super-secret-kvm-pass-99!');
      assert.ok(isEncryptedSecret(ct));
      assert.strictEqual(decryptSecret(ct), 'super-secret-kvm-pass-99!');
      const tampered = ct.slice(0, -4) + 'ffff';
      assert.strictEqual(decryptSecret(tampered), '', 'Tampered GCM ciphertext must never return plaintext');

      const apiKey = generateApiKeyPair('hkvm');
      assert.ok(apiKey.rawKey.startsWith('hkvm_'));
      assert.strictEqual(hashApiKey(apiKey.rawKey), apiKey.keyHash);
    });

    // 3. Boot full HKVM V3 Express + WebSocket Server
    // The test harness acts as a trusted reverse proxy on localhost, so X-Forwarded-For is
    // honored here (matching a real proxy deployment). The limiter ignores XFF by default.
    process.env.TRUSTED_PROXIES = '127.0.0.1';
    app = require('../app');
    await app.hkvmReadyPromise;
    await new Promise((r) => setTimeout(r, 250));
    const baseUrl = `http://127.0.0.1:${TEST_PORT}`;
    const ctx = app.getHkvmV3Context();
    assert.ok(ctx, 'HKVM V3 context initialized');

    const bcrypt = require('bcryptjs');
    await ctx.db.run(`UPDATE users SET password = ? WHERE username = 'admin'`, [
      bcrypt.hashSync('AdminTestPass!2026', 10),
    ]);

    // 4. Legacy HVM V9 Importer + Transparent Werkzeug Password Upgrade
    await runStep('T03: Legacy HVM V9 importer (Werkzeug pbkdf2:sha256 + nodes + LXC + port forwards) & login rehash', async () => {
      const legacyDbFile = path.join(tmpRoot, 'legacy_hvm_v9.db');
      const ldb = new sqlite3.Database(legacyDbFile);
      const execSql = (sql, params = []) =>
        new Promise((res, rej) => ldb.run(sql, params, (e) => (e ? rej(e) : res())));

      await execSql(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password_hash TEXT, is_admin INTEGER)`);
      await execSql(`CREATE TABLE nodes (id INTEGER PRIMARY KEY, name TEXT, url TEXT, api_key TEXT, location TEXT, status TEXT)`);
      await execSql(`CREATE TABLE vps (id INTEGER PRIMARY KEY, container_name TEXT, hostname TEXT, user_id INTEGER, node_id INTEGER, cpu INTEGER, ram INTEGER, disk INTEGER, ip_address TEXT, os_image TEXT, status TEXT, suspended INTEGER)`);
      await execSql(`CREATE TABLE port_forwards (id INTEGER PRIMARY KEY, vps_id INTEGER, protocol TEXT, host_port INTEGER, container_port INTEGER)`);

      const wkHash = makeWerkzeugPbkdf2Hash('LegacyHvmPass#42');
      await execSql(`INSERT INTO users VALUES (10, 'hvm_alice', 'alice@example.org', ?, 0)`, [wkHash]);
      await execSql(`INSERT INTO nodes VALUES (2, 'eu-fra-lxc-1', 'https://10.99.0.10:8443', 'old-plaintext-node-key', 'Frankfurt', 'online')`);
      await execSql(`INSERT INTO vps VALUES (5, 'ct-alice-01', 'alice-web', 10, 2, 2, 2048, 25, '10.0.3.55', 'ubuntu:24.04', 'stopped', 0)`);
      await execSql(`INSERT INTO port_forwards VALUES (1, 5, 'tcp', 22055, 22)`);
      await new Promise((res) => ldb.close(() => res()));

      // Phase 11: dry-run / preflight must validate the source WITHOUT importing.
      const dryRun = await dryRunHvmImport(ctx.db, legacyDbFile);
      assert.strictEqual(dryRun.dryRun, true);
      assert.strictEqual(dryRun.requiredTablesPresent, true);
      assert.strictEqual(dryRun.ready, true);
      assert.deepStrictEqual(dryRun.sourceTables.sort(), ['nodes', 'port_forwards', 'users', 'vps']);
      assert.strictEqual(dryRun.counts.users, 1);
      assert.strictEqual(dryRun.counts.nodes, 1);
      assert.strictEqual(dryRun.counts.vps, 1);
      assert.strictEqual(dryRun.counts.portForwards, 1);
      assert.strictEqual(dryRun.passwordHashFormats.pbkdf2, 1);
      assert.strictEqual(dryRun.passwordHashFormats.unrecognized, 0);
      assert.strictEqual(dryRun.existingUserCollisions, 0, 'No collisions before import');
      assert.deepStrictEqual(dryRun.warnings, []);

      const report = await importHvmDatabase(ctx.db, legacyDbFile);
      assert.strictEqual(report.usersCreated, 1);
      assert.strictEqual(report.nodesImported, 1);
      assert.strictEqual(report.vpsImported, 1);

      const nodeCred = await ctx.db.get(
        `SELECT nc.api_key_enc FROM node_credentials nc JOIN nodes n ON n.id = nc.node_id WHERE n.name = 'eu-fra-lxc-1'`
      );
      assert.ok(nodeCred && isEncryptedSecret(nodeCred.api_key_enc));

      const aliceClient = new SessionClient(baseUrl);
      const loginRes = await aliceClient.request('POST', '/api/login', {
        username: 'hvm_alice',
        password: 'LegacyHvmPass#42',
      });
      assert.strictEqual(loginRes.status, 200);
      assert.strictEqual(loginRes.json.success, true);

      const aliceRow = await ctx.db.get(`SELECT password FROM users WHERE username = 'hvm_alice'`);
      assert.ok(aliceRow.password.startsWith('$2'), 'Expected upgraded bcrypt hash');
    });

    // 5. Session Auth, CSRF Enforcement & Scoped API Keys
    const adminClient = new SessionClient(baseUrl);
    let scopedApiKeyRaw = '';
    await runStep('T04: Admin login, CSRF token protection on mutations & scoped Bearer API keys', async () => {
      const login = await adminClient.request('POST', '/api/login', {
        username: 'admin',
        password: 'AdminTestPass!2026',
      });
      assert.strictEqual(login.status, 200);

      const dash = await adminClient.request('GET', '/admin/instances');
      assert.strictEqual(dash.status, 200);
      assert.ok(adminClient.csrfToken.length > 20, 'Extracted CSRF token from EJS header');

      // Attempt POST /api/v1/api-keys WITHOUT CSRF token -> must reject 403!
      const savedCsrf = adminClient.csrfToken;
      adminClient.csrfToken = '';
      const blocked = await adminClient.request('POST', '/api/v1/api-keys', { name: 'should-fail' });
      assert.strictEqual(blocked.status, 403, 'Expected 403 CSRF rejection without token');

      // Restore CSRF token -> succeeds!
      adminClient.csrfToken = savedCsrf;
      const createdKey = await adminClient.request('POST', '/api/v1/api-keys', {
        name: 'ci-automation-key',
        permissions: ['read', 'write', 'admin'],
      });
      assert.strictEqual(createdKey.status, 201, `API key create failed: ${createdKey.text}`);
      assert.ok(createdKey.json.rawApiKey.startsWith('hkvm_pat_'));
      scopedApiKeyRaw = createdKey.json.rawApiKey;

      // Stateless API key call without cookies or CSRF succeeds!
      const apiClient = new SessionClient(baseUrl);
      const apiInstances = await apiClient.request('GET', '/api/v1/instances', undefined, {
        Authorization: `Bearer ${scopedApiKeyRaw}`,
      });
      assert.strictEqual(apiInstances.status, 200);
      assert.ok(Array.isArray(apiInstances.json.instances));
    });

    await runStep('T30: Password changes verify current credentials, require browser session, and audit', async () => {
      const health = await new SessionClient(baseUrl).request('GET', '/api/v1/health');
      assert.strictEqual(health.status, 200);
      assert.strictEqual(health.json.version, '4.0.0', 'Health endpoint must report V4');
      const passwordClient = new SessionClient(baseUrl);
      const login = await passwordClient.request('POST', '/api/login', {
        username: 'admin',
        password: 'AdminTestPass!2026',
      });
      assert.strictEqual(login.status, 200, `Admin login failed: ${login.text}`);
      const settingsPage = await passwordClient.request('GET', '/admin/settings');
      assert.strictEqual(settingsPage.status, 200, 'Settings page should issue the browser CSRF token');
      assert.ok(settingsPage.text.includes('Current Password'), 'Password modal must ask for the current password');
      assert.ok(settingsPage.text.includes('/api/v1/auth/password/change'), 'Settings UI must call the authenticated V4 password endpoint');
      const legacyWeakPassword = await passwordClient.request('PUT', '/api/user/password', {
        current_password: 'AdminTestPass!2026',
        new_password: 'weak123',
      });
      assert.strictEqual(legacyWeakPassword.status, 400, 'Legacy compatibility endpoint must enforce the V4 minimum length');

      const rejected = await passwordClient.request('POST', '/api/v1/auth/password/change', {
        currentPassword: 'not-the-current-password',
        newPassword: 'AdminNewPassword!2027',
      });
      assert.strictEqual(rejected.status, 400, 'Incorrect current password must be rejected');

      const samePassword = await passwordClient.request('POST', '/api/v1/auth/password/change', {
        currentPassword: 'AdminTestPass!2026',
        newPassword: 'AdminTestPass!2026',
      });
      assert.strictEqual(samePassword.status, 400, 'Reusing the current password must be rejected');

      const bearerClient = new SessionClient(baseUrl);
      const bearerAttempt = await bearerClient.request('POST', '/api/v1/auth/password/change', {
        currentPassword: 'AdminTestPass!2026',
        newPassword: 'AdminNewPassword!2027',
      }, { Authorization: `Bearer ${scopedApiKeyRaw}` });
      assert.strictEqual(bearerAttempt.status, 403, 'API keys must not change account passwords');

      const changed = await passwordClient.request('POST', '/api/v1/auth/password/change', {
        currentPassword: 'AdminTestPass!2026',
        newPassword: 'AdminNewPassword!2027',
      });
      assert.strictEqual(changed.status, 200, `Password update failed: ${changed.text}`);
      assert.strictEqual(changed.json.success, true);
      const audit = await ctx.db.get(`SELECT action FROM activity_logs WHERE user_id = 1 AND action = 'password_changed' ORDER BY id DESC LIMIT 1`);
      assert.ok(audit, 'Successful password change must be audited');

      const oldPasswordLogin = await new SessionClient(baseUrl).request('POST', '/api/login', {
        username: 'admin',
        password: 'AdminTestPass!2026',
      });
      assert.notStrictEqual(oldPasswordLogin.status, 200, 'Old password must no longer authenticate');
      const newPasswordLogin = await new SessionClient(baseUrl).request('POST', '/api/login', {
        username: 'admin',
        password: 'AdminNewPassword!2027',
      });
      assert.strictEqual(newPasswordLogin.status, 200, 'New password must authenticate');

      // Restore the fixture credential so the remainder of the acceptance suite stays isolated.
      const restored = await passwordClient.request('POST', '/api/v1/auth/password/change', {
        currentPassword: 'AdminNewPassword!2027',
        newPassword: 'AdminTestPass!2026',
      });
      assert.strictEqual(restored.status, 200, `Could not restore test credential: ${restored.text}`);
      const restoredLogin = await new SessionClient(baseUrl).request('POST', '/api/login', {
        username: 'admin',
        password: 'AdminTestPass!2026',
      });
      assert.strictEqual(restoredLogin.status, 200, 'Fixture credential should be restored');
    });
    // 6. TOTP 2FA End-to-End Flow
    await runStep('T05: RFC 6238 TOTP 2FA setup, QR provisioning & 2-step login verification', async () => {
      const userClient = new SessionClient(baseUrl);
      await userClient.request('POST', '/api/login', {
        username: 'hvm_alice',
        password: 'LegacyHvmPass#42',
      });
      const secPage = await userClient.request('GET', '/security');
      assert.strictEqual(secPage.status, 200);

      const setup = await userClient.request('POST', '/api/v1/auth/2fa/setup', {});
      assert.strictEqual(setup.status, 200, `2FA setup failed: ${setup.text}`);
      assert.ok(setup.json.qrDataUrl.startsWith('data:image/png;base64,'));
      assert.ok(setup.json.otpauthUrl.includes('issuer=TGVPANEL'), 'Expected TOTP issuer=TGVPANEL');
      const secret = setup.json.secret;
      const validCode = computeTotpCode(secret);
      assert.strictEqual(verifyTotpCode(secret, validCode), true);

      const verify = await userClient.request('POST', '/api/v1/auth/2fa/enable', { code: validCode });
      assert.strictEqual(verify.status, 200, `2FA enable failed: ${verify.text}`);

      const freshAlice = new SessionClient(baseUrl);
      const step1 = await freshAlice.request('POST', '/api/login', {
        username: 'hvm_alice',
        password: 'LegacyHvmPass#42',
      });
      assert.strictEqual(step1.status, 200);
      assert.strictEqual(step1.json.requires2FA, true);
      assert.strictEqual(step1.json.redirectTo, '/login/2fa');

      const premature = await freshAlice.request('GET', '/api/v1/instances');
      assert.strictEqual(premature.status, 401);

      const step2 = await freshAlice.request('POST', '/api/login/2fa', {
        code: computeTotpCode(secret),
      });
      assert.strictEqual(step2.status, 200);
      assert.strictEqual(step2.json.success, true);

      const postAuth = await freshAlice.request('GET', '/api/v1/instances');
      assert.strictEqual(postAuth.status, 200);
    });

    // 7. RBAC, Non-Admin Ownership Fixes & VPS Sharing
    await runStep('T06: RBAC enforcement, KVM V2 ownership bugfixes & VPS sharing permissions', async () => {
      const insVm = await ctx.db.run(
        `INSERT INTO vms (vm_name, hostname, owner_id, memory, cpus, disk_size, status, password)
         VALUES ('admin-core-vm', 'admin-core', 1, 2048, 2, '20G', 'stopped', ?)`,
        [encryptSecret('KvmSecretPass!')]
      );
      const adminVmId = insVm.lastID;
      await ctx.kvmAdapter.syncRegistryRow(adminVmId);

      await ctx.db.run(
        `INSERT INTO users (username, password, email, role, is_active) VALUES ('bob_user', ?, 'bob@example.org', 'user', 1)`,
        [bcrypt.hashSync('BobPass!123', 10)]
      );
      const bobRow = await ctx.db.get(`SELECT id FROM users WHERE username = 'bob_user'`);

      const bobClient = new SessionClient(baseUrl);
      await bobClient.request('POST', '/api/login', { username: 'bob_user', password: 'BobPass!123' });
      await bobClient.request('GET', '/instances');

      assert.strictEqual((await bobClient.request('GET', '/api/v1/nodes')).status, 403);
      assert.strictEqual((await bobClient.request('GET', `/api/vms/${adminVmId}/edit`)).status, 403);
      assert.strictEqual((await bobClient.request('GET', `/api/vms/${adminVmId}/logs`)).status, 403);
      assert.strictEqual((await bobClient.request('GET', `/api/vms/${adminVmId}/stats`)).status, 403);
      assert.strictEqual((await bobClient.request('DELETE', `/api/vms/${adminVmId}`)).status, 403);

      const aliceLxc = await ctx.db.get(`SELECT id FROM lxc_instances WHERE container_name = 'ct-alice-01'`);
      const shareRes = await adminClient.request('PUT', `/api/v1/lxc/${aliceLxc.id}/sharing`, {
        userIds: [bobRow.id],
      });
      assert.strictEqual(shareRes.status, 200, `Share failed: ${shareRes.text}`);

      const bobList = await bobClient.request('GET', '/api/v1/instances');
      assert.ok(
        bobList.json.instances.some((i) => i.engine === 'lxc' && i.refId === aliceLxc.id),
        'Shared LXC visible to Bob'
      );
    });

    // 8. Standalone Node Agent + HMAC Auth + Replay Defense
    await runStep('T07: Standalone Node Agent HTTP/HMAC server, capability sync & replay rejection', async () => {
      const regRes = await adminClient.request('POST', '/api/v1/nodes', {
        name: 'local-loopback-agent',
        hostname: '127.0.0.1',
        ipAddress: '127.0.0.1',
        url: `http://127.0.0.1:${AGENT_PORT}`,
        location: 'Loopback DC',
        verifySsl: false,
      });
      assert.strictEqual(regRes.status, 201, `Node register failed: ${regRes.text}`);
      remoteNodeId = regRes.json.node.id;
      const { apiKey, hmacSecret } = regRes.json.bootstrapCredentials;
      agentApiKey = apiKey;
      agentHmacSecret = hmacSecret;

      const agentInst = createNodeAgentServer({
        host: '127.0.0.1',
        port: AGENT_PORT,
        nodeId: 'local-loopback-agent',
        apiKey,
        hmacSecret,
        lxcBaseDir: path.join(tmpRoot, 'agent-lxc'),
        backupDir: path.join(tmpRoot, 'agent-backups'),
      });
      agentServer = agentInst.server;
      await new Promise((resolve) => agentServer.listen(AGENT_PORT, '127.0.0.1', resolve));

      const syncRes = await adminClient.request('POST', `/api/v1/nodes/${remoteNodeId}/check`, {});
      assert.strictEqual(syncRes.status, 200, `Node check failed: ${syncRes.text}`);

      // Test replay attack rejection directly against standalone Node Agent!
      const signedHeaders = signAgentRequest({
        nodeId: 'local-loopback-agent',
        apiKey,
        hmacSecret,
        method: 'GET',
        pathWithQuery: '/api/v1/health',
      });
      const callAgent = () =>
        new Promise((resolve, reject) => {
          const r = http.request(
            {
              hostname: '127.0.0.1',
              port: AGENT_PORT,
              path: '/api/v1/health',
              method: 'GET',
              headers: signedHeaders,
            },
            (res) => resolve(res.statusCode)
          );
          r.on('error', reject);
          r.end();
        });
      assert.strictEqual(await callAgent(), 200, 'First signed request accepted');
      assert.strictEqual(await callAgent(), 409, 'Replayed nonce rejected with 409 Conflict');
    });

    // 9. Unified Virtualization Capabilities, Telemetry & Honest Binary Checks
    await runStep('T08: Unified Virtualization Manager, Linux /proc telemetry & honest hypervisor checks', async () => {
      const kvmCap = ctx.kvmAdapter.getCapabilityProfile();
      const lxcCap = ctx.lxcAdapter.getCapabilityProfile();
      assert.strictEqual(kvmCap.supportsFreeze, false);
      assert.strictEqual(lxcCap.supportsFreeze, true);
      const { selectQemuSystemBinary, qemuBinaryMatchesArchitecture } = require('../lib/node-agent/command-runner');
      assert.strictEqual(
        selectQemuSystemBinary((name) => name === 'qemu-system-aarch64'),
        'qemu-system-aarch64',
        'ARM-only QEMU nodes should still report a QEMU binary for version probing'
      );
      assert.strictEqual(
        selectQemuSystemBinary((name) => name === 'qemu-system-x86_64' || name === 'qemu-system-aarch64'),
        'qemu-system-x86_64',
        'Prefer x86_64 QEMU when both system binaries are installed'
      );
      assert.strictEqual(
        selectQemuSystemBinary((name) => name === 'qemu-system-x86_64' || name === 'qemu-system-aarch64', 'aarch64'),
        'qemu-system-aarch64',
        'Prefer the ARM QEMU binary on ARM hosts even when x86_64 QEMU is installed'
      );
      assert.strictEqual(selectQemuSystemBinary(() => false), null);
      assert.strictEqual(qemuBinaryMatchesArchitecture('qemu-system-aarch64', 'aarch64'), true);
      assert.strictEqual(qemuBinaryMatchesArchitecture('qemu-system-x86_64', 'aarch64'), false);
      assert.strictEqual(qemuBinaryMatchesArchitecture('qemu-system-x86_64', 'x86_64'), true);
      assert.strictEqual(qemuBinaryMatchesArchitecture('qemu-system-aarch64', 'x86_64'), false);

      const { buildCapabilityWarnings } = require('../lib/node-agent/health');
      const makeCaps = (overrides = {}) => ({
        kvmDevicePresent: true,
        qemuSystemAvailable: true,
        qemuImgAvailable: true,
        kvmAvailable: true,
        lxcCreateAvailable: true,
        lxcStartAvailable: true,
        lxcInfoAvailable: true,
        lxcAvailable: true,
        lxcfsAvailable: true,
        lxcfsMounted: true,
        cgroupVersion: 2,
        storageBackends: ['dir'],
        networkBackends: [],
        qemuVersion: 'QEMU 8.2.0',
        lxcVersion: '5.0.3',
        kernelVersion: '6.8',
        architecture: 'x86_64',
        qemuArchitectureMismatch: false,
        ...overrides,
      });
      assert.deepStrictEqual(buildCapabilityWarnings(makeCaps()), [], 'Healthy host should produce no capability warnings');
      assert.ok(
        buildCapabilityWarnings(makeCaps({ lxcfsAvailable: true, lxcfsMounted: false })).some(
          (w) => w.includes('lxcfs is installed but not mounted')
        ),
        'LXC host with lxcfs installed but unmounted must warn about inaccurate guest telemetry'
      );
      assert.ok(
        buildCapabilityWarnings(makeCaps({ lxcfsAvailable: false, lxcfsMounted: true })).some(
          (w) => w.includes('lxcfs binary is not installed')
        ),
        'LXC host with an lxcfs mount but missing binary must warn about inaccurate telemetry'
      );
      assert.ok(
        buildCapabilityWarnings(makeCaps({ cgroupVersion: 1 })).some(
          (w) => w.includes('cgroup v1')
        ),
        'LXC host on cgroup v1 must warn that v2 delegation may be unavailable'
      );
      assert.ok(
        buildCapabilityWarnings(makeCaps({ kvmDevicePresent: false })).some(
          (w) => w.includes('/dev/kvm is unavailable')
        ),
        'QEMU host without /dev/kvm must warn about TCG fallback'
      );
      assert.deepStrictEqual(
        buildCapabilityWarnings(makeCaps({ kvmAvailable: false, lxcAvailable: false })),
        ['Neither QEMU/KVM nor LXC userland utilities are installed on this host. Management plane is online in controller-only mode until hypervisor packages are installed.'],
        'Controller-only host must produce a single clear warning'
      );

      const vm = await ctx.db.get(`SELECT vm_id, ipv4_address FROM vms LIMIT 1`);
      const noHookKvm = new KVMAdapter(ctx.db);
      await assert.rejects(
        noHookKvm.performLifecycleAction(vm.vm_id, 'restart'),
        /KVM restart requires a registered restart hook or both stop and start hooks/
      );
      const restartCalls = [];
      const hookedKvm = new KVMAdapter(ctx.db, {
        stopVmById: async (id) => {
          restartCalls.push(`stop:${id}`);
          await ctx.db.run(`UPDATE vms SET status = 'stopped', pid = NULL WHERE vm_id = ?`, [id]);
        },
        startVmById: async (id) => {
          restartCalls.push(`start:${id}`);
          await ctx.db.run(`UPDATE vms SET status = 'running', pid = ? WHERE vm_id = ?`, [process.pid, id]);
        },
      });
      await hookedKvm.performLifecycleAction(vm.vm_id, 'restart');
      assert.deepStrictEqual(restartCalls, [`stop:${vm.vm_id}`, `start:${vm.vm_id}`]);

      // Graceful KVM shutdown is distinct from stop: it must never force-kill and uses the
      // longer grace period, and must refuse when no hook and no live PID are available.
      const shutdownCalls = [];
      const hookedShutdownKvm = new KVMAdapter(ctx.db, {
        stopVmById: async (id, force) => {
          shutdownCalls.push(`stop:${id}:${force}`);
          await ctx.db.run(`UPDATE vms SET status = 'stopped', pid = NULL WHERE vm_id = ?`, [id]);
        },
      });
      await hookedShutdownKvm.performLifecycleAction(vm.vm_id, 'shutdown');
      assert.deepStrictEqual(shutdownCalls, [`stop:${vm.vm_id}:false`], 'Shutdown must use the hook without force');

      const staleShutdownStatements = [];
      const staleShutdownRow = {
        vm_id: 900004,
        status: 'running',
        pid: null,
        suspended: 0,
      };
      const staleShutdownKvm = new KVMAdapter(
        {
          get: async () => staleShutdownRow,
          run: async (sql) => {
            staleShutdownStatements.push(String(sql));
            return { changes: 1, lastID: 0 };
          },
        },
        {}
      );
      await assert.rejects(
        staleShutdownKvm.performLifecycleAction(staleShutdownRow.vm_id, 'shutdown'),
        /Cannot shutdown KVM VM #900004: status is running but no stop hook or live PID is available\./,
        'KVM shutdown must refuse on a stale running VM with no hook and no live PID'
      );
      assert.strictEqual(
        staleShutdownStatements.length,
        0,
        'Rejected stale-state KVM shutdown must not mutate the record'
      );

      // LXC has no graceful guest shutdown; it must reject rather than pretend to succeed.
      const lxcShutdownRow = {
        id: 900002,
        node_id: 1,
        container_name: 'shutdown-guard-lxc',
        is_local: true,
        suspended: 0,
        suspension_history: '[]',
      };
      const lxcShutdownAdapter = new LXCAdapter(
        {
          get: async () => lxcShutdownRow,
          run: async () => ({ changes: 1, lastID: 0 }),
        },
        {}
      );
      await assert.rejects(
        lxcShutdownAdapter.performLifecycleAction(lxcShutdownRow.id, 'shutdown'),
        (err) => err.statusCode === 501 && /not supported for LXC/.test(err.message),
        'LXC must reject graceful shutdown instead of silently no-op'
      );

      // Clone rollback: when a clone fails after the host artifact is created, the panel must
      // remove the inserted records AND destroy the host container so neither is left behind.
      const lxcCloneSourceRow = {
        id: 900006,
        user_id: 1,
        node_id: 1,
        container_name: 'clone-rollback-source',
        hostname: 'clone-rollback-source',
        os_template: 'ubuntu',
        os_family: 'ubuntu',
        arch: 'amd64',
        cpu_cores: 1,
        cpu_shares: 1024,
        cpu_limit_pct: 100,
        cpu_pinning: null,
        ram_mb: 1024,
        swap_mb: 0,
        disk_gb: 20,
        rootfs_storage_type: 'dir',
        privileged: 0,
        nesting: 0,
        kvm_nesting: 0,
        autostart: 0,
        root_password_enc: null,
        bridge: null,
        ip_address: null,
        gateway: null,
        ipv6_address: null,
        mac_address: null,
        vlan_id: null,
        status: 'stopped',
        bandwidth_quota_gb: 0,
        notes: '',
        expires_at: null,
        expiration_days: 30,
        auto_suspend_enabled: 0,
        last_renewed_at: null,
        is_local: true,
        suspended: 0,
        suspension_history: '[]',
      };
      const lxcCloneRollbackStatements = [];
      let lxcCloneDestroyed = false;
      const lxcCloneRollbackDb = {
        get: async (sql, params) => {
          if (/FROM lxc_instances l/i.test(sql)) return lxcCloneSourceRow;
          if (/SELECT id FROM lxc_instances WHERE LOWER\(container_name\)/i.test(sql)) return undefined;
          return undefined;
        },
        run: async (sql, params) => {
          lxcCloneRollbackStatements.push({ sql: String(sql), params });
          if (/INSERT INTO lxc_instances/i.test(sql)) return { lastID: 900007, changes: 1 };
          if (/INSERT OR REPLACE INTO vps_expiration/i.test(sql)) throw new Error('simulated expiration insert failure');
          return { changes: 1, lastID: 0 };
        },
        all: async () => [],
      };
      const lxcCloneRollbackAdapter = new LXCAdapter(
        lxcCloneRollbackDb,
        {
          localRuntime: {
            containerManager: {
              cloneContainer: async () => ({ name: 'clone-rollback-clone', state: 'stopped', pid: null, ips: [] }),
              destroyContainer: async () => { lxcCloneDestroyed = true; },
            },
          },
        }
      );
      await assert.rejects(
        lxcCloneRollbackAdapter.cloneStoppedLxcInstance(lxcCloneSourceRow.id, 'clone-rollback-clone'),
        /simulated expiration insert failure/,
        'LXC clone must surface the failure instead of reporting success'
      );
      assert.ok(lxcCloneDestroyed, 'LXC clone rollback must destroy the created host container');
      assert.ok(
        lxcCloneRollbackStatements.some((s) => /DELETE FROM lxc_instances WHERE id = \?/i.test(s.sql) && Number(s.params[0]) === 900007),
        'LXC clone rollback must remove the inserted lxc_instances row'
      );
      assert.ok(
        lxcCloneRollbackStatements.some((s) => /DELETE FROM instances WHERE engine = 'lxc' AND ref_id = \?/i.test(s.sql) && Number(s.params[0]) === 900007),
        'LXC clone rollback must remove the inserted unified registry row'
      );

      // KVM clone rollback: when the registry sync fails after the disk image is created, the
      // adapter must remove the inserted VM/registry rows AND delete the created disk image.
      const kvmCloneSizeBytes = 10737418240;
      const kvmCloneSourceDisk = path.join(os.homedir(), 'vms', `tgv-clone-rollback-src-${Date.now()}.qcow2`);
      fs.writeFileSync(kvmCloneSourceDisk, 'source-disk');
      try {
        const kvmCloneSourceRow = {
          vm_id: 900010,
          vm_name: 'clone-rollback-source-kvm',
          hostname: 'clone-rollback-source-kvm',
          owner_id: 1,
          node_id: 1,
          status: 'stopped',
          pid: null,
          suspended: 0,
          network_type: 'nat',
          extra_disks_json: '[]',
          extra_nics_json: '[]',
          disk_file: kvmCloneSourceDisk,
          img_file: null,
          http_port: 80,
          os_type: 'ubuntu',
          template_type: '',
          clone_of: null,
        };
        const kvmCloneRollbackStatements = [];
        let kvmCloneTargetPathValue = '';
        const kvmCloneRollbackDb = {
          get: async (sql, params) => {
            if (/FROM vms WHERE vm_name = ?/i.test(sql)) return undefined;
            if (params && params[0] === 900011 && /SELECT \* FROM vms WHERE vm_id = \?/i.test(sql)) {
              return { vm_id: 900011, vm_name: 'clone-rollback-kvm', hostname: 'clone-rollback-kvm', owner_id: 1, node_id: 1, status: 'stopped', suspended: 0, os_type: 'KVM Guest', cpus: 1, memory: 1024, disk_size: '10G', ipv4_address: null, shared_with: '[]' };
            }
            return kvmCloneSourceRow;
          },
          run: async (sql, params) => {
            kvmCloneRollbackStatements.push({ sql: String(sql), params });
            if (/INSERT INTO vms/i.test(sql)) return { lastID: 900011, changes: 1 };
            if (/INSERT INTO instances/i.test(sql)) throw new Error('simulated registry sync failure');
            return { changes: 1, lastID: 0 };
          },
          all: async () => [],
        };
        const kvmCloneRollbackAdapter = new KVMAdapter(
          kvmCloneRollbackDb,
          {},
          async (cmd, args) => {
            if (cmd === 'qemu-img' && args[0] === 'info') {
              const target = JSON.stringify({ format: 'qcow2', 'virtual-size': kvmCloneSizeBytes });
              return { exitCode: 0, timedOut: false, stdout: target, stderr: '' };
            }
            if (cmd === 'qemu-img' && args[0] === 'convert') {
              const targetPath = args[args.length - 1];
              kvmCloneTargetPathValue = targetPath;
              fs.writeFileSync(targetPath, 'clone-disk');
              return { exitCode: 0, timedOut: false, stdout: '', stderr: '' };
            }
            return { exitCode: 1, timedOut: false, stdout: '', stderr: 'unexpected command' };
          }
        );
        await assert.rejects(
          kvmCloneRollbackAdapter.cloneStoppedVm(kvmCloneSourceRow.vm_id, 'clone-rollback-kvm'),
          /simulated registry sync failure/,
          'KVM clone must surface the registry sync failure instead of reporting success'
        );
        assert.ok(
          kvmCloneRollbackStatements.some((s) => /DELETE FROM vms WHERE vm_id = \?/i.test(s.sql) && Number(s.params[0]) === 900011),
          'KVM clone rollback must remove the inserted vms row'
        );
        assert.ok(
          kvmCloneRollbackStatements.some((s) => /DELETE FROM instances WHERE engine = 'kvm' AND ref_id = \?/i.test(s.sql) && Number(s.params[0]) === 900011),
          'KVM clone rollback must remove the inserted unified registry row'
        );
        assert.ok(kvmCloneTargetPathValue, 'KVM clone should have created a target disk image');
        assert.ok(
          !fs.existsSync(kvmCloneTargetPathValue),
          'KVM clone rollback must delete the created disk image'
        );
      } finally {
        try { fs.unlinkSync(kvmCloneSourceDisk); } catch { /* cleanup best effort */ }
      }

      const hookedGuardRow = {
        vm_id: 900003,
        vm_name: 'hook-guard-vm',
        hostname: 'hook-guard-vm',
        owner_id: 1,
        node_id: 1,
        status: 'stopped',
        suspended: 0,
        pid: null,
        disk_size: '10G',
        memory: 1024,
        cpus: 1,
        shared_with: '[]',
        created_at: new Date().toISOString(),
      };
      const hookedGuardStatements = [];
      const startHookMissKvm = new KVMAdapter(
        {
          get: async () => hookedGuardRow,
          run: async (sql) => {
            hookedGuardStatements.push(String(sql));
            return { changes: 1, lastID: 0 };
          },
        },
        {
          startVmById: async () => {},
        }
      );
      await assert.rejects(
        startHookMissKvm.performLifecycleAction(hookedGuardRow.vm_id, 'start'),
        /KVM VM #900003 did not reach the running state after the lifecycle hook\./,
        'KVM start must refuse when the hook leaves the VM without a live process'
      );
      assert.ok(
        !hookedGuardStatements.some((sql) => sql.includes(`status = 'running'`)),
        'Failed hooked KVM start must not persist running panel state'
      );

      hookedGuardRow.status = 'running';
      hookedGuardRow.pid = process.pid;
      const stopHookMissKvm = new KVMAdapter(
        {
          get: async () => hookedGuardRow,
          run: async (sql) => {
            hookedGuardStatements.push(String(sql));
            return { changes: 1, lastID: 0 };
          },
        },
        {
          stopVmById: async () => {},
        }
      );
      await assert.rejects(
        stopHookMissKvm.performLifecycleAction(hookedGuardRow.vm_id, 'stop'),
        /KVM VM #900003 still has a live process after the lifecycle hook; refusing to record stopped state\./,
        'KVM stop must refuse when the hook leaves a live process behind'
      );
      assert.ok(
        !hookedGuardStatements.some((sql) => sql.includes(`status = 'stopped'`)),
        'Failed hooked KVM stop must not persist stopped panel state'
      );

      hookedGuardRow.status = 'stopped';
      hookedGuardRow.pid = null;
      const deleteHookMissKvm = new KVMAdapter(
        {
          get: async () => hookedGuardRow,
          run: async (sql) => {
            hookedGuardStatements.push(String(sql));
            return { changes: 1, lastID: 0 };
          },
        },
        {
          deleteVmById: async () => {},
        }
      );
      await assert.rejects(
        deleteHookMissKvm.performLifecycleAction(hookedGuardRow.vm_id, 'delete'),
        /KVM VM #900003 was not removed by the delete hook; refusing to report deletion\./,
        'KVM deletion must refuse when the hook leaves the VM record behind'
      );
      assert.ok(
        !hookedGuardStatements.some((sql) => sql.trim().startsWith('DELETE FROM instances')),
        'Failed hooked KVM deletion must not remove the unified registry row'
      );

      const lxcRow = {
        id: 900001,
        node_id: 1,
        container_name: 'host-failure-guard',
        is_local: true,
        suspended: 0,
        suspension_history: '[]',
      };
      const lxcDbStatements = [];
      const failingHostLxc = new LXCAdapter(
        {
          get: async () => lxcRow,
          run: async (sql) => {
            lxcDbStatements.push(String(sql));
            return { changes: 0, lastID: 0 };
          },
        },
        {
          localRuntime: {
            containerManager: {
              inspectContainer: async () => ({ state: 'running' }),
              stopContainer: async () => {
                throw new Error('host stop failed');
              },
              destroyContainer: async () => {
                throw new Error('host destroy failed');
              },
            },
          },
        }
      );
      await assert.rejects(
        failingHostLxc.performLifecycleAction(lxcRow.id, 'suspend', { reason: 'guard' }),
        /host stop failed/,
        'LXC suspension must not persist panel state when the host stop fails'
      );
      assert.ok(!lxcDbStatements.some((sql) => sql.includes('UPDATE lxc_instances')), 'Failed LXC suspension must not mark the record suspended');
      await assert.rejects(
        failingHostLxc.performLifecycleAction(lxcRow.id, 'delete'),
        /host destroy failed/,
        'LXC deletion must not delete panel records when the host destroy fails'
      );
      assert.ok(
        !lxcDbStatements.some((sql) => sql.trim().startsWith('DELETE FROM lxc_instances')),
        'Failed LXC deletion must retain the instance record'
      );

      const stateMismatchStatements = [];
      const stateMismatchLxc = new LXCAdapter(
        {
          get: async () => lxcRow,
          run: async (sql) => {
            stateMismatchStatements.push(String(sql));
            return { changes: 0, lastID: 0 };
          },
        },
        {
          localRuntime: {
            containerManager: {
              startContainer: async () => {},
              inspectContainer: async () => ({ state: 'stopped' }),
              stopContainer: async () => {},
              destroyContainer: async () => {},
            },
          },
        }
      );
      await assert.rejects(
        stateMismatchLxc.performLifecycleAction(lxcRow.id, 'start'),
        /LXC start did not reach expected "running" state on host; host reports "stopped"\./,
        'LXC start must not persist running status when the host inspection reports stopped'
      );
      assert.ok(
        !stateMismatchStatements.some((sql) => sql.includes(`status = 'running'`)),
        'Failed LXC start must not record running panel state'
      );

      const deleteMismatchStatements = [];
      const deleteMismatchLxc = new LXCAdapter(
        {
          get: async () => lxcRow,
          run: async (sql) => {
            deleteMismatchStatements.push(String(sql));
            return { changes: 0, lastID: 0 };
          },
        },
        {
          localRuntime: {
            containerManager: {
              destroyContainer: async () => {},
              inspectContainer: async () => ({ state: 'stopped' }),
            },
          },
        }
      );
      await assert.rejects(
        deleteMismatchLxc.performLifecycleAction(lxcRow.id, 'delete'),
        /LXC delete did not remove the container on host; host reports "stopped"\. Refusing to remove panel records\./,
        'LXC deletion must not remove panel records when the host leaves the container behind'
      );
      assert.ok(
        !deleteMismatchStatements.some((sql) => sql.trim().startsWith('DELETE FROM lxc_instances')),
        'Failed LXC deletion must retain the instance record when the container remains'
      );

      const missingDeleteStatements = [];
      const missingDeleteLxc = new LXCAdapter(
        {
          get: async () => lxcRow,
          run: async (sql) => {
            missingDeleteStatements.push(String(sql));
            return { changes: 1, lastID: 0 };
          },
        },
        {
          localRuntime: {
            containerManager: {
              inspectContainer: async () => ({ state: 'missing' }),
              destroyContainer: async () => {
                throw new Error('destroy should not be called for a missing container');
              },
            },
          },
        }
      );
      await missingDeleteLxc.performLifecycleAction(lxcRow.id, 'delete');
      assert.ok(
        missingDeleteStatements.some((sql) => sql.trim().startsWith('DELETE FROM lxc_instances')),
        'LXC deletion of a missing container should remove panel records without host destroy tooling'
      );

      // Native KVM lifecycle guards: fallback stop must wait for the guest process to exit,
      // suspension must stop a running guest without a hook, and deletion must not remove
      // records while a live guest process remains.
      const kvmGuardStatements = [];
      const kvmGuardRow = {
        vm_id: 900002,
        vm_name: 'lifecycle-guard-vm',
        hostname: 'lifecycle-guard-vm',
        owner_id: 1,
        node_id: 1,
        status: 'running',
        suspended: 0,
        pid: null,
        disk_size: '10G',
        memory: 1024,
        cpus: 1,
        shared_with: '[]',
        created_at: new Date().toISOString(),
      };
      const noHookGuardKvm = new KVMAdapter(
        {
          get: async () => kvmGuardRow,
          run: async (sql) => {
            kvmGuardStatements.push(String(sql));
            if (String(sql).includes('UPDATE vms SET status = \'stopped\'')) {
              kvmGuardRow.status = 'stopped';
              kvmGuardRow.pid = null;
            }
            if (String(sql).includes('UPDATE vms SET suspended = 1')) {
              kvmGuardRow.suspended = 1;
              kvmGuardRow.status = 'stopped';
              kvmGuardRow.pid = null;
            }
            return { changes: 1, lastID: 0 };
          },
        },
        {}
      );
      const startGuestProcess = async () => {
        const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], {
          stdio: 'ignore',
        });
        await new Promise((resolve, reject) => {
          child.once('spawn', resolve);
          child.once('error', reject);
        });
        kvmGuardRow.pid = child.pid;
        kvmGuardRow.status = 'running';
        kvmGuardRow.suspended = 0;
        return child;
      };
      const stopGuestProcess = async (child) => {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        await new Promise((resolve) => {
          if (child.exitCode !== null || child.signalCode !== null) {
            resolve();
          } else {
            child.once('exit', resolve);
          }
        });
      };
      const waitForGuestExit = async (child) => {
        if (child.exitCode !== null || child.signalCode !== null) return;
        await new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('Guest process did not exit')), 2000);
          child.once('exit', () => {
            clearTimeout(timer);
            resolve();
          });
        });
      };

      const stopGuardChild = await startGuestProcess();
      try {
        await noHookGuardKvm.performLifecycleAction(kvmGuardRow.vm_id, 'stop');
        await waitForGuestExit(stopGuardChild);
        assert.ok(
          kvmGuardStatements.some((sql) => sql.includes(`UPDATE vms SET status = 'stopped', pid = NULL`)),
          'KVM fallback stop must persist the stopped state only after the guest exits'
        );
      } finally {
        await stopGuestProcess(stopGuardChild);
      }

      const suspendGuardChild = await startGuestProcess();
      try {
        await noHookGuardKvm.performLifecycleAction(kvmGuardRow.vm_id, 'suspend', { reason: 'guard' });
        await waitForGuestExit(suspendGuardChild);
        assert.ok(
          kvmGuardStatements.some((sql) => sql.includes('UPDATE vms SET suspended = 1')),
          'KVM suspend must persist suspension after stopping a running guest'
        );
      } finally {
        await stopGuestProcess(suspendGuardChild);
      }

      const deleteGuardChild = await startGuestProcess();
      try {
        await assert.rejects(
          noHookGuardKvm.performLifecycleAction(kvmGuardRow.vm_id, 'delete'),
          /KVM delete hook is not registered/,
          'KVM deletion must refuse without a registered host delete hook'
        );
        assert.ok(
          !kvmGuardStatements.some((sql) => sql.trim().startsWith('DELETE FROM vms')),
          'Refused KVM deletion must retain the VM record'
        );
      } finally {
        await stopGuestProcess(deleteGuardChild);
      }

      kvmGuardRow.status = 'running';
      kvmGuardRow.pid = null;
      kvmGuardRow.suspended = 0;
      const staleGuardStatements = kvmGuardStatements.length;
      await assert.rejects(
        noHookGuardKvm.performLifecycleAction(kvmGuardRow.vm_id, 'stop'),
        /no stop hook or live PID is available/,
        'KVM fallback stop must reject stale running state without a stop hook or PID'
      );
      await assert.rejects(
        noHookGuardKvm.performLifecycleAction(kvmGuardRow.vm_id, 'suspend', { reason: 'guard' }),
        /no stop hook or live PID is available/,
        'KVM suspend must reject stale running state without a stop hook or PID'
      );
      assert.strictEqual(
        kvmGuardStatements.length,
        staleGuardStatements,
        'Rejected stale-state KVM lifecycle actions must not mutate the record'
      );

      await ctx.db.run(`UPDATE vms SET pid = ?, status = 'running', ipv4_address = NULL WHERE vm_id = ?`, [
        process.pid,
        vm.vm_id,
      ]);
      const mapped = await ctx.kvmAdapter.getInstance(vm.vm_id);
      assert.strictEqual(mapped.primaryIp, null, 'Unknown KVM addresses must not become a localhost placeholder');
      const tel = await ctx.kvmAdapter.getTelemetry(vm.vm_id);
      assert.strictEqual(tel.pid, process.pid);
      assert.ok(tel.ramUsedMb > 10, `Expected real RSS > 10MB from /proc/${process.pid}/status`);
      assert.strictEqual(tel.netRxBytes, null, 'Unmeasured KVM RX must be null, not a fabricated zero');
      assert.strictEqual(tel.netTxBytes, null, 'Unmeasured KVM TX must be null, not a fabricated zero');
      await ctx.db.run(`UPDATE vms SET pid = NULL, status = 'stopped', ipv4_address = ? WHERE vm_id = ?`, [
        vm.ipv4_address || null,
        vm.vm_id,
      ]);
      await ctx.kvmAdapter.syncRegistryRow(vm.vm_id);

      const freezeKvm = await adminClient.request('POST', `/api/v1/instances/kvm/${vm.vm_id}/action`, {
        action: 'freeze',
      });
      assert.strictEqual(freezeKvm.status, 400);
      assert.match(freezeKvm.json.error, /only supported for LXC/i);
    });

    await runStep('T34: VPS tasks recover safely and verify KVM/LXC cloning, rescue ISO, disk/device workflows, VNC proxy, locks and access', async () => {
      const vm = await ctx.db.get(`SELECT vm_id FROM vms ORDER BY vm_id LIMIT 1`);
      assert.ok(vm?.vm_id, 'Need an existing test KVM VM');
      const rejectedAction = await adminClient.request(
        'POST',
        `/api/v1/instances/kvm/${vm.vm_id}/action`,
        { action: 'freeze', async: true },
        { 'X-Forwarded-For': '198.51.100.34' }
      );
      assert.strictEqual(rejectedAction.status, 202, `Task enqueue should return 202: ${rejectedAction.text}`);
      assert.ok(rejectedAction.json.task?.id, 'Expected durable task id');
      await assert.rejects(
        () => ctx.instanceManager.getAuthorizedTask(
          { userId: 999999, username: 'not-the-owner', role: 'user' },
          rejectedAction.json.task.id
        ),
        (err) => err.statusCode === 403
      );

      let asyncTask;
      for (let i = 0; i < 30; i += 1) {
        const poll = await adminClient.request('GET', `/api/v1/tasks/${rejectedAction.json.task.id}`);
        assert.strictEqual(poll.status, 200, `Authorized task status request failed: ${poll.text}`);
        asyncTask = poll.json.task;
        if (['succeeded', 'failed'].includes(asyncTask.status)) break;
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert.strictEqual(asyncTask.status, 'failed', 'Unsupported KVM freeze must be honestly reported as a failed task');
      assert.match(asyncTask.error, /only supported for LXC/i);
      const taskHistory = await adminClient.request('GET', `/api/v1/instances/kvm/${vm.vm_id}/tasks`);
      assert.strictEqual(taskHistory.status, 200);
      assert.ok(taskHistory.json.tasks.some((task) => task.id === asyncTask.id));

      const taskManager = ctx.instanceManager.tasks;
      let activeTaskId = '';
      const activeTask = await taskManager.start({
        engine: 'lxc', instanceRefId: 987654, actorId: 1, action: 'lock-test',
        worker: async (report) => {
          activeTaskId = 'running';
          await report(25, 'Testing persisted progress');
          await new Promise((resolve) => setTimeout(resolve, 350));
          await report(60, 'Finishing test operation');
          return { verified: true };
        },
      });
      assert.ok(['queued', 'running'].includes(activeTask.status), 'New task should be queued or already running');
      await assert.rejects(
        () => taskManager.start({
          engine: 'lxc', instanceRefId: 987654, actorId: 1, action: 'duplicate',
          worker: async () => true,
        }),
        (err) => err.statusCode === 409 && /already queued or running/i.test(err.message)
      );
      await assert.rejects(
        () => taskManager.runSync({
          engine: 'lxc', instanceRefId: 987654, actorId: 1, action: 'sync-duplicate',
          worker: async () => true,
        }),
        (err) => err.statusCode === 409 && /already queued or running/i.test(err.message)
      );
      let inProgress = await taskManager.get(activeTask.id);
      for (let i = 0; i < 10 && Number(inProgress?.progress || 0) < 25; i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 20));
        inProgress = await taskManager.get(activeTask.id);
      }
      assert.ok(inProgress.progress >= 25 && inProgress.progress < 100, 'Progress endpoint data must reflect an in-flight operation');
      assert.strictEqual(inProgress.currentStep, 'Testing persisted progress');

      let finished = await taskManager.get(activeTask.id);
      for (let i = 0; i < 30 && finished?.status !== 'succeeded'; i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 20));
        finished = await taskManager.get(activeTask.id);
      }
      assert.strictEqual(finished.status, 'succeeded');
      assert.strictEqual(finished.progress, 100);
      assert.deepStrictEqual(finished.result, { verified: true });
      assert.strictEqual(activeTaskId, 'running');

      const legacyConflictTask = await taskManager.start({
        engine: 'kvm', instanceRefId: Number(vm.vm_id), actorId: 1, action: 'lock-test',
        worker: async () => {
          await new Promise((resolve) => setTimeout(resolve, 350));
          return { verified: true };
        },
      });
      const legacyConflict = await adminClient.request(
        'POST',
        `/api/vms/${vm.vm_id}/start`,
        {},
        { 'X-Forwarded-For': '198.51.100.35' }
      );
      assert.strictEqual(legacyConflict.status, 409, `Legacy KVM lifecycle route should honor the active task lock: ${legacyConflict.text}`);
      const legacyConsoleConflict = await adminClient.request(
        'POST', `/api/vms/${vm.vm_id}/console/command`, { command: 'echo must-not-run' },
        { 'X-Forwarded-For': '198.51.100.51' }
      );
      assert.strictEqual(legacyConsoleConflict.status, 409, `Legacy serial-console commands must share the per-instance task lock: ${legacyConsoleConflict.text}`);
      let legacyFinished = await taskManager.get(legacyConflictTask.id);
      for (let i = 0; i < 30 && legacyFinished?.status !== 'succeeded'; i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 20));
        legacyFinished = await taskManager.get(legacyConflictTask.id);
      }
      assert.strictEqual(legacyFinished.status, 'succeeded');

      const lxc = await ctx.db.get(`SELECT id FROM lxc_instances ORDER BY id LIMIT 1`);
      assert.ok(lxc?.id, 'Need an existing test LXC instance');
      const directLxcTask = await taskManager.start({
        engine: 'lxc', instanceRefId: Number(lxc.id), actorId: 1, action: 'lock-test',
        worker: async () => {
          await new Promise((resolve) => setTimeout(resolve, 350));
          return { verified: true };
        },
      });
      const lxcMutationConflict = await adminClient.request(
        'POST',
        `/api/v1/lxc/${lxc.id}/password`,
        { password: 'should-not-be-applied' },
        { 'X-Forwarded-For': '198.51.100.36' }
      );
      assert.strictEqual(lxcMutationConflict.status, 409, `Direct LXC password mutation should honor the active task lock: ${lxcMutationConflict.text}`);
      const lxcFileConflict = await adminClient.request(
        'POST',
        `/api/v1/lxc/${lxc.id}/files/content`,
        { path: '/tmp/tgvpanel-task-lock-test', content: 'must-not-write' },
        { 'X-Forwarded-For': '198.51.100.39' }
      );
      assert.strictEqual(lxcFileConflict.status, 409, `Direct LXC file writes should honor the active task lock: ${lxcFileConflict.text}`);
      let directLxcFinished = await taskManager.get(directLxcTask.id);
      for (let i = 0; i < 30 && directLxcFinished?.status !== 'succeeded'; i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 20));
        directLxcFinished = await taskManager.get(directLxcTask.id);
      }
      assert.strictEqual(directLxcFinished.status, 'succeeded');

      const lxcCloneSource = await ctx.db.get(`SELECT * FROM lxc_instances WHERE id = ?`, [lxc.id]);
      const cloneContainerManager = ctx.nodeManager.localRuntime.containerManager;
      const originalCloneContainer = cloneContainerManager.cloneContainer;
      const originalDestroyContainer = cloneContainerManager.destroyContainer;
      const originalRemoteNodeRequest = ctx.nodeManager.requestRemoteNode;
      const cloneTestName = `t34-clone-${Date.now()}`;
      let clonedLxcId = null;
      try {
        await ctx.db.run(`UPDATE lxc_instances SET status = 'stopped', rootfs_storage_type = 'dir' WHERE id = ?`, [lxc.id]);
        cloneContainerManager.cloneContainer = async (sourceName, targetName, resources) => {
          assert.strictEqual(sourceName, lxcCloneSource.container_name);
          assert.strictEqual(targetName, cloneTestName);
          assert.ok(resources.cpuCores >= 1);
          return { name: targetName, state: 'stopped', pid: null, ips: [] };
        };
        cloneContainerManager.destroyContainer = async () => {};
        ctx.nodeManager.requestRemoteNode = async (_nodeId, method, route, body) => {
          assert.strictEqual(method, 'POST');
          assert.match(route, /\/clone$/);
          assert.strictEqual(body.targetName, cloneTestName);
          return { success: true, networkDetached: true };
        };
        const missingCloneAck = await adminClient.request(
          'POST', `/api/v1/instances/lxc/${lxc.id}/clone`, { name: cloneTestName },
          { 'X-Forwarded-For': '198.51.100.40' }
        );
        assert.strictEqual(missingCloneAck.status, 400, 'LXC clone must require explicit guest identity/network risk acknowledgement');
        const lxcCloneResponse = await adminClient.request(
          'POST', `/api/v1/instances/lxc/${lxc.id}/clone`,
          { name: cloneTestName, acknowledgeGuestIdentityRisk: true },
          { 'X-Forwarded-For': '198.51.100.41' }
        );
        assert.strictEqual(lxcCloneResponse.status, 201, `Stopped directory-backed LXC should clone through its task-tracked API: ${lxcCloneResponse.text}`);
        assert.strictEqual(lxcCloneResponse.json.clone.networkDetached, true);
        assert.strictEqual(lxcCloneResponse.json.clone.guestIdentityResetRequired, true);
        assert.match(lxcCloneResponse.json.warning, /network detached/i);
        clonedLxcId = lxcCloneResponse.json.clone.instance.refId;
        const disconnectedClone = await ctx.db.get(`SELECT status, bridge, ip_address, rootfs_storage_type FROM lxc_instances WHERE id = ?`, [clonedLxcId]);
        assert.deepStrictEqual(disconnectedClone, { status: 'stopped', bridge: null, ip_address: null, rootfs_storage_type: 'dir' });
      } finally {
        cloneContainerManager.cloneContainer = originalCloneContainer;
        cloneContainerManager.destroyContainer = originalDestroyContainer;
        ctx.nodeManager.requestRemoteNode = originalRemoteNodeRequest;
        if (clonedLxcId) {
          await ctx.db.run(`DELETE FROM vps_expiration WHERE lxc_id = ?`, [clonedLxcId]);
          await ctx.db.run(`DELETE FROM instances WHERE engine = 'lxc' AND ref_id = ?`, [clonedLxcId]);
          await ctx.db.run(`DELETE FROM lxc_instances WHERE id = ?`, [clonedLxcId]);
        }
        await ctx.db.run(`UPDATE lxc_instances SET status = ?, rootfs_storage_type = ? WHERE id = ?`, [lxcCloneSource.status, lxcCloneSource.rootfs_storage_type, lxc.id]);
      }

      const staleId = crypto.randomUUID();
      await ctx.db.run(
        `INSERT INTO instance_tasks (id, engine, instance_ref_id, actor_id, action, status, progress, updated_at)
         VALUES (?, 'lxc', 987655, 1, 'interrupted-test', 'running', 40, datetime('now', '-10 minutes'))`,
        [staleId]
      );
      assert.strictEqual(await taskManager.failStaleTasks(5), 1, 'Stale in-flight tasks should be failed instead of retried blindly');
      assert.strictEqual((await taskManager.get(staleId)).status, 'failed');
      const interruptedId = crypto.randomUUID();
      await ctx.db.run(
        `INSERT INTO instance_tasks (id, engine, instance_ref_id, actor_id, action, status, updated_at)
         VALUES (?, 'lxc', 987656, 1, 'startup-recovery-test', 'queued', datetime('now'))`,
        [interruptedId]
      );
      assert.strictEqual(await taskManager.recoverInterruptedTasks(), 1, 'Even recently queued work must be interrupted after a controller restart');
      assert.strictEqual((await taskManager.get(interruptedId)).status, 'failed');

      const resizeRoot = fs.mkdtempSync(path.join(os.homedir(), 'vms', '.tgvpanel-resize-test-'));
      const fakeDisk = path.join(resizeRoot, 'disk.qcow2');
      fs.writeFileSync(fakeDisk, 'test image fixture');
      let virtualSizeBytes = 20 * 1024 ** 3;
      // Honest allocated (on-disk) size reported by qemu-img; intentionally different
      // from the tiny fixture file so telemetry tests prove diskUsedGb comes from
      // qemu-img disk-size rather than a statSync of the image file.
      let diskSizeBytes = 5 * 1024 ** 3;
      const fakeQemuRunner = async (_binary, args) => {
        if (args[0] === 'info') {
          return { exitCode: 0, stdout: JSON.stringify({ format: 'qcow2', 'virtual-size': virtualSizeBytes, 'disk-size': diskSizeBytes }), stderr: '', timedOut: false, durationMs: 0 };
        }
        if (args[0] === 'resize') {
          virtualSizeBytes = Number(args[2]);
          return { exitCode: 0, stdout: '', stderr: '', timedOut: false, durationMs: 0 };
        }
        if (args[0] === 'create') {
          fs.mkdirSync(path.dirname(args[3]), { recursive: true });
          fs.writeFileSync(args[3], 'fake qcow2 image');
          return { exitCode: 0, stdout: '', stderr: '', timedOut: false, durationMs: 0 };
        }
        if (args[0] === 'convert') {
          fs.mkdirSync(path.dirname(args[4]), { recursive: true });
          fs.copyFileSync(args[3], args[4]);
          return { exitCode: 0, stdout: '', stderr: '', timedOut: false, durationMs: 0 };
        }
        if (args[0] === 'snapshot') {
          // qemu-img snapshot -c/-a/-d: succeed without touching the fixture image.
          return { exitCode: 0, stdout: '', stderr: '', timedOut: false, durationMs: 0 };
        }
        return { exitCode: 2, stdout: '', stderr: 'unexpected qemu-img command', timedOut: false, durationMs: 0 };
      };
      const testKvmAdapter = new KVMAdapter(ctx.db, {}, fakeQemuRunner);
      const productionKvmAdapter = ctx.instanceManager.virt.kvm;
      let testExtraDiskPath = null;
      let testCloneVmId = 0;
      let testCloneDiskPath = null;
      let fakeVncServer = null;
      let testVncPort = null;
      const savedVmDisk = await ctx.db.get(`SELECT disk_file, disk_size, status, pid, ssh_port, mac_address, extra_disks_json, extra_nics_json, vnc_port, service_locked, service_lock_reason, service_locked_at, service_locked_by FROM vms WHERE vm_id = ?`, [vm.vm_id]);
      try {
        await ctx.db.run(`UPDATE vms SET disk_file = ?, disk_size = '20G', status = 'stopped', pid = NULL WHERE vm_id = ?`, [fakeDisk, vm.vm_id]);
        ctx.instanceManager.virt.kvm = testKvmAdapter;
        const vncEnable = await adminClient.request(
          'POST',
          `/api/v1/instances/kvm/${vm.vm_id}/vnc`,
          { enabled: true },
          { 'X-Forwarded-For': '198.51.100.48' }
        );
        assert.strictEqual(vncEnable.status, 200, `Stopped KVM should enable loopback VNC: ${vncEnable.text}`);
        testVncPort = vncEnable.json.vnc.port;
        assert.ok(testVncPort >= 5900 && testVncPort < 65000);
        const vncPage = await adminClient.request('GET', `/vm/${vm.vm_id}/vnc`);
        assert.strictEqual(vncPage.status, 200, `Authorized VNC page should render: ${vncPage.text}`);
        assert.match(vncPage.text, /core\/rfb\.js/);
        const vncAsset = await adminClient.request('GET', '/vendor/novnc/core/rfb.js');
        assert.strictEqual(vncAsset.status, 200, 'Vendored noVNC RFB module should be served locally');
        fakeVncServer = net.createServer((socket) => socket.on('data', (chunk) => socket.write(chunk)));
        await new Promise((resolve, reject) => {
          fakeVncServer.once('error', reject);
          fakeVncServer.listen(testVncPort, '127.0.0.1', resolve);
        });
        const rejectedVncOrigin = await new Promise((resolve, reject) => {
          const ws = new WebSocket(`ws://127.0.0.1:${TEST_PORT}/vnc/${vm.vm_id}`, {
            headers: { Cookie: adminClient.cookie, Origin: 'https://attacker.example' },
          });
          const timer = setTimeout(() => { ws.terminate(); reject(new Error('Timed out waiting for hostile VNC origin rejection')); }, 3000);
          ws.once('unexpected-response', (_request, response) => {
            clearTimeout(timer);
            response.resume();
            resolve(response.statusCode);
          });
          ws.once('error', (err) => { clearTimeout(timer); reject(err); });
        });
        assert.strictEqual(rejectedVncOrigin, 403, 'VNC WebSocket must reject cross-origin browser sessions');
        const vncFrame = Buffer.from('tgvpanel-vnc-proxy-frame');
        const proxiedFrame = await new Promise((resolve, reject) => {
          const ws = new WebSocket(`ws://127.0.0.1:${TEST_PORT}/vnc/${vm.vm_id}`, {
            headers: { Cookie: adminClient.cookie },
          });
          const timer = setTimeout(() => { ws.terminate(); reject(new Error('Timed out waiting for VNC TCP/WebSocket proxy echo')); }, 3000);
          ws.once('open', () => ws.send(vncFrame, { binary: true }));
          ws.once('message', (data, isBinary) => {
            clearTimeout(timer);
            ws.close();
            if (!isBinary) return reject(new Error('VNC proxy must preserve binary framing'));
            resolve(Buffer.from(data));
          });
          ws.once('error', (err) => { clearTimeout(timer); reject(err); });
        });
        assert.deepStrictEqual(proxiedFrame, vncFrame, 'Authenticated noVNC WebSocket should proxy raw binary VNC bytes');
        await new Promise((resolve) => fakeVncServer.close(resolve));
        fakeVncServer = null;
        const vncDisable = await adminClient.request(
          'POST',
          `/api/v1/instances/kvm/${vm.vm_id}/vnc`,
          { enabled: false },
          { 'X-Forwarded-For': '198.51.100.49' }
        );
        assert.strictEqual(vncDisable.status, 200, `Stopped KVM should disable VNC: ${vncDisable.text}`);
        testVncPort = null;
        const rescueIsoFilename = `.tgvpanel-rescue-${Date.now()}.iso`;
        const rescueIsoPath = path.join(os.homedir(), 'vms', 'iso', rescueIsoFilename);
        fs.mkdirSync(path.dirname(rescueIsoPath), { recursive: true });
        fs.writeFileSync(rescueIsoPath, 'test rescue media fixture');
        try {
          const badRescueIso = await adminClient.request(
            'POST', `/api/v1/instances/kvm/${vm.vm_id}/rescue`,
            { enabled: true, isoFilename: '../outside.iso' },
            { 'X-Forwarded-For': '198.51.100.42' }
          );
          assert.strictEqual(badRescueIso.status, 400, 'Rescue ISO endpoint must reject paths and accept only managed filenames');
          const rescueEnabled = await adminClient.request(
            'POST', `/api/v1/instances/kvm/${vm.vm_id}/rescue`,
            { enabled: true, isoFilename: rescueIsoFilename },
            { 'X-Forwarded-For': '198.51.100.43' }
          );
          assert.strictEqual(rescueEnabled.status, 200, `Stopped KVM should configure managed rescue media: ${rescueEnabled.text}`);
          const rescueRow = await ctx.db.get(`SELECT iso_attached, boot_from_iso FROM vms WHERE vm_id = ?`, [vm.vm_id]);
          assert.deepStrictEqual(rescueRow, { iso_attached: rescueIsoFilename, boot_from_iso: 1 });
          const rescueDisabled = await adminClient.request(
            'POST', `/api/v1/instances/kvm/${vm.vm_id}/rescue`,
            { enabled: false },
            { 'X-Forwarded-For': '198.51.100.44' }
          );
          assert.strictEqual(rescueDisabled.status, 200, `Stopped KVM should restore disk-first boot after rescue: ${rescueDisabled.text}`);
          const restoredBoot = await ctx.db.get(`SELECT iso_attached, boot_from_iso FROM vms WHERE vm_id = ?`, [vm.vm_id]);
          assert.deepStrictEqual(restoredBoot, { iso_attached: null, boot_from_iso: 0 });
        } finally {
          try { fs.unlinkSync(rescueIsoPath); } catch { /* test cleanup */ }
        }
        const lockedService = await adminClient.request(
          'POST', `/api/v1/instances/kvm/${vm.vm_id}/service-lock`,
          { locked: true, reason: 'T34 service-lock regression' },
          { 'X-Forwarded-For': '198.51.100.45' }
        );
        assert.strictEqual(lockedService.status, 200, `Staff should set a non-suspending service lock: ${lockedService.text}`);
        const lockRow = await ctx.db.get(`SELECT service_locked, service_lock_reason FROM vms WHERE vm_id = ?`, [vm.vm_id]);
        assert.deepStrictEqual(lockRow, { service_locked: 1, service_lock_reason: 'T34 service-lock regression' });
        const blockedV1Start = await adminClient.request(
          'POST', `/api/v1/instances/kvm/${vm.vm_id}/action`, { action: 'start' },
          { 'X-Forwarded-For': '198.51.100.46' }
        );
        assert.strictEqual(blockedV1Start.status, 423, `Unified start must honor service lock: ${blockedV1Start.text}`);
        const blockedLegacyStart = await adminClient.request(
          'POST', `/api/vms/${vm.vm_id}/start`, {},
          { 'X-Forwarded-For': '198.51.100.47' }
        );
        assert.strictEqual(blockedLegacyStart.status, 423, `Legacy start must honor service lock: ${blockedLegacyStart.text}`);
        const unlockedService = await adminClient.request(
          'POST', `/api/v1/instances/kvm/${vm.vm_id}/service-lock`, { locked: false },
          { 'X-Forwarded-For': '198.51.100.48' }
        );
        assert.strictEqual(unlockedService.status, 200, `Staff should clear service lock: ${unlockedService.text}`);
        assert.strictEqual(unlockedService.json.instance.serviceLocked, false);
        const resizeResponse = await adminClient.request(
          'POST',
          `/api/v1/instances/kvm/${vm.vm_id}/disk/resize`,
          { diskSize: '30G' },
          { 'X-Forwarded-For': '198.51.100.37' }
        );
        assert.strictEqual(resizeResponse.status, 200, `KVM disk expansion should succeed: ${resizeResponse.text}`);
        assert.strictEqual(resizeResponse.json.diskSize, '30G');
        assert.strictEqual(resizeResponse.json.virtualSizeBytes, 30 * 1024 ** 3);
        assert.strictEqual(resizeResponse.json.guestFilesystemResizeRequired, true, 'Guest partition/filesystem expansion must be explicitly left to the guest');

        // Phase 12: KVM telemetry must report honest qemu-img disk-image stats rather than the
        // raw image-file size. After the resize to 30G, diskTotalGb must reflect the virtual
        // size (30), diskUsedGb the qemu-img allocated disk-size (5), and diskFormat the format.
        const kvmDiskTel = await ctx.instanceManager.virt.kvm.getTelemetry(vm.vm_id);
        assert.strictEqual(kvmDiskTel.diskFormat, 'qcow2', 'KVM telemetry must report the qemu-img image format');
        assert.strictEqual(kvmDiskTel.diskTotalGb, 30, `KVM diskTotalGb must reflect qemu-img virtual-size (expected 30), got ${kvmDiskTel.diskTotalGb}`);
        assert.strictEqual(kvmDiskTel.diskUsedGb, Number((diskSizeBytes / 1024 ** 3).toFixed(2)), `KVM diskUsedGb must reflect qemu-img allocated disk-size (expected ${Number((diskSizeBytes / 1024 ** 3).toFixed(2))}), got ${kvmDiskTel.diskUsedGb}`);

        // Phase 17: fetching instance telemetry must persist the real measured
        // sample to metrics_history so the metrics history endpoint returns honest data.
        const httpTel = await adminClient.request('GET', `/api/v1/instances/kvm/${vm.vm_id}/telemetry`);
        assert.strictEqual(httpTel.status, 200, `KVM telemetry HTTP failed: ${httpTel.text}`);
        const metricsHist = await adminClient.request('GET', `/api/v1/instances/kvm/${vm.vm_id}/metrics`);
        assert.strictEqual(metricsHist.status, 200, `KVM metrics history failed: ${metricsHist.text}`);
        assert.ok(metricsHist.json.history.length >= 1, 'Fetching telemetry must record a metrics_history sample');
        const rec = metricsHist.json.history[metricsHist.json.history.length - 1];
        assert.strictEqual(rec.disk_total_gb, httpTel.json.telemetry.diskTotalGb, `Recorded history disk_total_gb must match the telemetry sample (expected ${httpTel.json.telemetry.diskTotalGb}, got ${rec.disk_total_gb})`);
        assert.strictEqual(rec.disk_used_gb, httpTel.json.telemetry.diskUsedGb, `Recorded history disk_used_gb must match the telemetry sample (expected ${httpTel.json.telemetry.diskUsedGb}, got ${rec.disk_used_gb})`);

        // Phase 13: KVM QCOW2 snapshot sizing must be honest (qemu-img virtual-size for
        // capacity and allocated disk-size for consumption) rather than the raw image-file
        // size, and the snapshot listing must expose both figures.
        const snapName = `phase13-snap-${Date.now()}`;
        const snapCreate = await ctx.instanceManager.virt.kvm.createQcow2Snapshot(vm.vm_id, snapName, 'Phase 13 honest sizing');
        assert.strictEqual(snapCreate.name, snapName, 'Snapshot should be created with the requested name');
        const snapRow = await ctx.db.get(`SELECT size_gb, allocated_gb FROM vm_snapshots WHERE snapshot_id = ?`, [snapCreate.id]);
        assert.strictEqual(snapRow.size_gb, 30, `KVM snapshot size_gb must reflect qemu-img virtual-size (expected 30), got ${snapRow.size_gb}`);
        assert.strictEqual(snapRow.allocated_gb, Number((diskSizeBytes / 1024 ** 3).toFixed(2)), `KVM snapshot allocated_gb must reflect qemu-img allocated disk-size (expected ${Number((diskSizeBytes / 1024 ** 3).toFixed(2))}), got ${snapRow.allocated_gb}`);
        const snapList = await ctx.backupManager.listSnapshots('kvm', vm.vm_id);
        const snapListed = snapList.find((sn) => sn.id === snapCreate.id);
        assert.ok(snapListed, 'Created snapshot must appear in the KVM snapshot listing');
        assert.strictEqual(snapListed.sizeGb, 30, `Listed snapshot sizeGb must be honest (expected 30), got ${snapListed.sizeGb}`);
        assert.strictEqual(snapListed.allocatedGb, Number((diskSizeBytes / 1024 ** 3).toFixed(2)), `Listed snapshot allocatedGb must be honest (expected ${Number((diskSizeBytes / 1024 ** 3).toFixed(2))}), got ${snapListed.allocatedGb}`);
        await ctx.instanceManager.virt.kvm.deleteQcow2Snapshot(vm.vm_id, snapCreate.id);

        const shrinkResponse = await adminClient.request(
          'POST',
          `/api/v1/instances/kvm/${vm.vm_id}/disk/resize`,
          { diskSize: '10G' },
          { 'X-Forwarded-For': '198.51.100.38' }
        );
        assert.strictEqual(shrinkResponse.status, 400, `Unsafe KVM disk shrink must be refused: ${shrinkResponse.text}`);
        assert.match(shrinkResponse.json.error, /shrinking is disabled/i);
        assert.strictEqual(virtualSizeBytes, 30 * 1024 ** 3, 'Rejected shrink must not alter the image');

        const attachDisk = await adminClient.request(
          'POST',
          `/api/v1/instances/kvm/${vm.vm_id}/devices/disks`,
          { size: '2G' },
          { 'X-Forwarded-For': '198.51.100.40' }
        );
        assert.strictEqual(attachDisk.status, 201, `Stopped KVM should attach a secondary disk: ${attachDisk.text}`);
        assert.strictEqual(attachDisk.json.disk.sizeBytes, 2 * 1024 ** 3);
        const extraImagePath = path.join(os.homedir(), 'vms', `vm-${vm.vm_id}-devices`, `${attachDisk.json.disk.id}.qcow2`);
        testExtraDiskPath = extraImagePath;
        assert.ok(fs.existsSync(extraImagePath), 'Secondary disk image should be created in managed storage');
        const detachDisk = await adminClient.request(
          'DELETE',
          `/api/v1/instances/kvm/${vm.vm_id}/devices/disks/${attachDisk.json.disk.id}`,
          {},
          { 'X-Forwarded-For': '198.51.100.41' }
        );
        assert.strictEqual(detachDisk.status, 200, `Secondary disk should detach safely: ${detachDisk.text}`);
        assert.strictEqual(detachDisk.json.disk.imagePreserved, true);
        assert.ok(fs.existsSync(extraImagePath), 'Detaching a disk must preserve its image data');
        let deviceList = await adminClient.request('GET', `/api/v1/instances/kvm/${vm.vm_id}/devices`);
        assert.strictEqual(deviceList.status, 200);
        assert.strictEqual(deviceList.json.devices.disks[0].attached, false, 'Detached images remain catalogued');
        const reattachDisk = await adminClient.request(
          'POST',
          `/api/v1/instances/kvm/${vm.vm_id}/devices/disks/${attachDisk.json.disk.id}/attach`,
          {},
          { 'X-Forwarded-For': '198.51.100.44' }
        );
        assert.strictEqual(reattachDisk.status, 200, `Preserved disk should be reattachable: ${reattachDisk.text}`);
        deviceList = await adminClient.request('GET', `/api/v1/instances/kvm/${vm.vm_id}/devices`);
        assert.strictEqual(deviceList.json.devices.disks[0].attached, true);
        const detachAgain = await adminClient.request(
          'DELETE',
          `/api/v1/instances/kvm/${vm.vm_id}/devices/disks/${attachDisk.json.disk.id}`,
          {},
          { 'X-Forwarded-For': '198.51.100.47' }
        );
        assert.strictEqual(detachAgain.status, 200, `Disk should detach before primary-disk-only clone: ${detachAgain.text}`);

        const attachNic = await adminClient.request(
          'POST',
          `/api/v1/instances/kvm/${vm.vm_id}/devices/nics`,
          {},
          { 'X-Forwarded-For': '198.51.100.42' }
        );
        assert.strictEqual(attachNic.status, 201, `Stopped KVM should attach a NAT NIC: ${attachNic.text}`);
        assert.strictEqual(attachNic.json.nic.networkMode, 'user');
        assert.match(attachNic.json.nic.macAddress, /^52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i);
        const detachNic = await adminClient.request(
          'DELETE',
          `/api/v1/instances/kvm/${vm.vm_id}/devices/nics/${attachNic.json.nic.id}`,
          {},
          { 'X-Forwarded-For': '198.51.100.43' }
        );
        assert.strictEqual(detachNic.status, 200, `Secondary NIC should detach: ${detachNic.text}`);
        try { fs.unlinkSync(extraImagePath); } catch { /* cleanup after retention assertion */ }

        const refusedClone = await adminClient.request(
          'POST',
          `/api/v1/instances/kvm/${vm.vm_id}/clone`,
          { name: `tgv-clone-${Date.now()}` },
          { 'X-Forwarded-For': '198.51.100.45' }
        );
        assert.strictEqual(refusedClone.status, 400, 'Clone must require explicit acknowledgement of guest identity reuse');
        const cloneName = `tgv-clone-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        const cloneResponse = await adminClient.request(
          'POST',
          `/api/v1/instances/kvm/${vm.vm_id}/clone`,
          { name: cloneName, acknowledgeGuestIdentityRisk: true },
          { 'X-Forwarded-For': '198.51.100.46' }
        );
        assert.strictEqual(cloneResponse.status, 201, `Stopped NAT VM should clone safely: ${cloneResponse.text}`);
        assert.strictEqual(cloneResponse.json.clone.name, cloneName);
        assert.strictEqual(cloneResponse.json.clone.guestIdentityResetRequired, true);
        assert.match(cloneResponse.json.warning, /SSH host keys/i);
        testCloneVmId = cloneResponse.json.clone.vmId;
        const clonedRow = await ctx.db.get(`SELECT vm_id, status, clone_of, network_type, ssh_port, mac_address, disk_file FROM vms WHERE vm_id = ?`, [testCloneVmId]);
        assert.strictEqual(clonedRow.status, 'stopped');
        assert.strictEqual(Number(clonedRow.clone_of), Number(vm.vm_id));
        assert.strictEqual(clonedRow.network_type, 'nat');
        assert.notStrictEqual(Number(clonedRow.ssh_port), Number(savedVmDisk.ssh_port));
        assert.notStrictEqual(clonedRow.mac_address, (await ctx.db.get(`SELECT mac_address FROM vms WHERE vm_id = ?`, [vm.vm_id])).mac_address);
        testCloneDiskPath = clonedRow.disk_file;
        assert.ok(fs.existsSync(testCloneDiskPath), 'Clone should own a separate verified disk image');
      } finally {
        ctx.instanceManager.virt.kvm = productionKvmAdapter;
        if (testCloneVmId) {
          await ctx.db.run(`DELETE FROM instances WHERE engine = 'kvm' AND ref_id = ?`, [testCloneVmId]).catch(() => undefined);
          await ctx.db.run(`DELETE FROM vm_logs WHERE vm_id = ?`, [testCloneVmId]).catch(() => undefined);
          await ctx.db.run(`DELETE FROM vm_snapshots WHERE vm_id = ?`, [testCloneVmId]).catch(() => undefined);
          await ctx.db.run(`DELETE FROM vms WHERE vm_id = ?`, [testCloneVmId]).catch(() => undefined);
        }
        if (testCloneDiskPath) {
          try { fs.unlinkSync(testCloneDiskPath); } catch { /* cleanup best effort */ }
        }
        if (fakeVncServer) await new Promise((resolve) => fakeVncServer.close(resolve));
        if (testExtraDiskPath) {
          try { fs.unlinkSync(testExtraDiskPath); } catch { /* cleanup best effort */ }
          try { fs.rmdirSync(path.dirname(testExtraDiskPath)); } catch { /* preserve non-empty device storage */ }
        }
        await ctx.db.run(`UPDATE vms SET disk_file = ?, disk_size = ?, status = ?, pid = ?, extra_disks_json = ?, extra_nics_json = ?, vnc_port = ?, service_locked = ?, service_lock_reason = ?, service_locked_at = ?, service_locked_by = ? WHERE vm_id = ?`, [
          savedVmDisk.disk_file, savedVmDisk.disk_size, savedVmDisk.status, savedVmDisk.pid,
          savedVmDisk.extra_disks_json, savedVmDisk.extra_nics_json, savedVmDisk.vnc_port,
          savedVmDisk.service_locked, savedVmDisk.service_lock_reason, savedVmDisk.service_locked_at, savedVmDisk.service_locked_by, vm.vm_id,
        ]);
        await ctx.kvmAdapter.syncRegistryRow(vm.vm_id);
        fs.rmSync(resizeRoot, { recursive: true, force: true });
      }
    });

    // Phase 19: storage orphan image detection — report-only scan of local pool
    // directories for unreferenced disk images. It must report the orphan, skip
    // referenced VM disks and images inside referenced LXC rootfs dirs, and never
    // delete anything.
    await runStep('T35: Storage orphan image detection reports unreferenced pool images without deleting them', async () => {
      const poolDir = path.join(tmpRoot, 'orphan-pool');
      fs.mkdirSync(poolDir, { recursive: true });
      const orphanImage = path.join(poolDir, 'orphan.qcow2');
      const usedImage = path.join(poolDir, 'used.qcow2');
      fs.writeFileSync(orphanImage, crypto.randomBytes(4096));
      fs.writeFileSync(usedImage, crypto.randomBytes(4096));
      // An image inside a referenced LXC rootfs directory must not be reported.
      const rootfsDir = path.join(poolDir, 'ctr-rootfs');
      fs.mkdirSync(rootfsDir, { recursive: true });
      const rootfsImage = path.join(rootfsDir, 'inside.qcow2');
      fs.writeFileSync(rootfsImage, crypto.randomBytes(1024));

      await ctx.db.run(
        `INSERT INTO storage_pools (name, node_id, engine, pool_type, path) VALUES (?, 1, 'kvm', 'dir', ?)`,
        ['orphan-test-pool', poolDir]
      );
      const poolRow = await ctx.db.get(`SELECT id FROM storage_pools WHERE name = 'orphan-test-pool'`);
      assert.ok(poolRow, 'Test pool row must be created');

      const vm = await ctx.db.get(`SELECT vm_id, disk_file FROM vms LIMIT 1`);
      const savedDiskFile = vm.disk_file;
      await ctx.db.run(`UPDATE vms SET disk_file = ? WHERE vm_id = ?`, [usedImage, vm.vm_id]);
      await ctx.db.run(
        `INSERT INTO lxc_instances (user_id, node_id, container_name, hostname, os_template, rootfs_path)
         VALUES (1, 1, 'orphan-test-ctr', 'orphan-test-ctr', 'ubuntu:22.04', ?)`,
        [rootfsDir]
      );

      try {
        const orphansRes = await adminClient.request(
          'GET',
          '/api/v1/storage/orphans',
          {},
          { 'X-Forwarded-For': '198.51.100.52' }
        );
        assert.strictEqual(orphansRes.status, 200, `Orphan scan failed: ${orphansRes.text}`);
        const orphans = orphansRes.json.orphans;

        const orphanEntry = orphans.find((o) => o.filePath === orphanImage);
        assert.ok(orphanEntry, 'Unreferenced pool image must be reported as an orphan');
        assert.strictEqual(orphanEntry.poolId, Number(poolRow.id));
        assert.strictEqual(orphanEntry.poolName, 'orphan-test-pool');
        assert.strictEqual(orphanEntry.sizeBytes, 4096);
        assert.ok(orphanEntry.reason, 'Orphan entry must carry an explanatory reason');

        assert.ok(!orphans.some((o) => o.filePath === usedImage), 'A VM-referenced disk image must not be reported');
        assert.ok(!orphans.some((o) => o.filePath === rootfsImage), 'An image inside a referenced LXC rootfs must not be reported');

        // Report-only contract: detection must never delete or modify files.
        assert.ok(fs.existsSync(orphanImage), 'Orphan detection must not delete the reported file');
        assert.ok(fs.existsSync(usedImage), 'Orphan detection must not touch referenced files');
      } finally {
        await ctx.db.run(`DELETE FROM lxc_instances WHERE container_name = 'orphan-test-ctr'`);
        await ctx.db.run(`UPDATE vms SET disk_file = ? WHERE vm_id = ?`, [savedDiskFile, vm.vm_id]);
        await ctx.db.run(`DELETE FROM storage_pools WHERE id = ?`, [poolRow.id]);
      }
    });

    // 10. Rootfs Path Traversal Defense & Command Runner Allowlist
    await runStep('T09: Container rootfs traversal confinement & command-runner allowlist enforcement', async () => {
      await assert.rejects(
        () => runAllowlistedCommand('bash', ['-c', 'id']),
        /not in the allowlist/i
      );
      await assert.rejects(
        () => runAllowlistedCommand('sudo', ['-n', 'id']),
        /not in the allowlist/i
      );
      await assert.rejects(
        () => runAllowlistedCommand('rm', ['-rf', '/tmp/x']),
        /not in the allowlist/i
      );
      await assert.rejects(
        () => runAllowlistedCommand('uname', ['-a\0evil']),
        /Null byte|invalid/i
      );

      // Regression guard for liblxc "//.local/" permission denied bug when HOME was missing or "/"
      const rootEnv = buildSafeSpawnEnv(true, { HOME: '/' });
      assert.strictEqual(rootEnv.HOME, '/root');
      assert.strictEqual(rootEnv.USER, 'root');
      const userEnv = buildSafeSpawnEnv(false, { HOME: '/' });
      assert.notStrictEqual(userEnv.HOME, '/');
      assert.ok(userEnv.HOME && userEnv.HOME.startsWith('/'));

      // Verify images.linuxcontainers.org release codename normalization
      assert.strictEqual(resolveDownloadReleaseCandidates('ubuntu', '24.04').releases[0], 'noble');
      assert.strictEqual(resolveDownloadReleaseCandidates('ubuntu', '22.04').releases[0], 'jammy');
      assert.strictEqual(resolveDownloadReleaseCandidates('debian', '12').releases[0], 'bookworm');
      assert.strictEqual(resolveDownloadReleaseCandidates('kali', 'rolling').releases[0], 'current');
      assert.strictEqual(resolveDownloadReleaseCandidates('centos', '9').releases[0], '9-Stream');

      const fakeLxcBase = path.join(tmpRoot, 'lxc-jail');
      const ctDir = path.join(fakeLxcBase, 'ct-jail-test');
      const ctRoot = path.join(ctDir, 'rootfs');
      fs.mkdirSync(path.join(ctRoot, 'etc'), { recursive: true });
      fs.writeFileSync(path.join(ctRoot, 'etc', 'hostname'), 'ct-jail-test\n');
      fs.writeFileSync(
        path.join(ctDir, 'config'),
        'lxc.rootfs.path = dir:' + ctRoot + '\nlxc.net.0.type = veth\nlxc.net.0.link = oldbr0\nlxc.apparmor.profile = generated\n'
      );

      const cm = new LxcContainerManager(fakeLxcBase);
      await cm.writeManagedConfigSection('ct-jail-test', {
        hostname: 'ct-jail-test',
        cpuCores: 2,
        ramMb: 1024,
        swapMb: 512,
        nesting: true,
        bridge: 'lxcbr0',
      });
      const updatedCfg = fs.readFileSync(path.join(ctDir, 'config'), 'utf8');
      assert.ok(!updatedCfg.includes('oldbr0'), 'Stale template lxc.net.0.link should be stripped');
      assert.ok(updatedCfg.includes('lxc.net.0.link = lxcbr0'));
      assert.strictEqual(
        (updatedCfg.match(/lxc\.apparmor\.profile\s*=/g) || []).length,
        1,
        'Should contain exactly one authoritative lxc.apparmor.profile directive'
      );

      const listing = cm.listRootfsDirectory('ct-jail-test', '/etc');
      assert.ok(listing.some((e) => e.name === 'hostname'));

      assert.throws(
        () => cm.readRootfsFile('ct-jail-test', '/../../../etc/passwd'),
        /traversal|escapes|outside|ENOENT/i
      );

      // Rate-limiter proxy trust: X-Forwarded-For must only be honored from configured
      // reverse proxies so a directly-exposed client cannot spoof the header to bypass limits.
      const { parseTrustedProxies, isIpTrustedByProxies, createRateLimiter } = require('../lib/security/middleware');
      assert.deepStrictEqual(parseTrustedProxies(undefined), [], 'No trusted proxies configured by default');
      assert.deepStrictEqual(parseTrustedProxies('10.0.0.1, 10.0.0.0/8 ,'), ['10.0.0.1', '10.0.0.0/8'], 'Trusted proxies are trimmed and empty entries dropped');
      assert.strictEqual(isIpTrustedByProxies('203.0.113.9', []), false, 'No trusted proxies means no peer is trusted');
      assert.strictEqual(isIpTrustedByProxies('203.0.113.9', ['203.0.113.9']), true, 'Exact IP match is trusted');
      assert.strictEqual(isIpTrustedByProxies('10.1.2.3', ['10.0.0.0/8']), true, 'IPv4 CIDR match is trusted');
      assert.strictEqual(isIpTrustedByProxies('192.168.1.1', ['10.0.0.0/8']), false, 'Out-of-range IP is not trusted');
      assert.strictEqual(isIpTrustedByProxies('2001:db8::1', ['2001:db8::1']), true, 'IPv6 exact match is trusted');
      assert.strictEqual(isIpTrustedByProxies('2001:db8::1', ['2001:db8::/32']), false, 'IPv6 CIDR is not required for this guard');

      const makeLimiterRequest = (remoteAddress, xff) => {
        const headers = {};
        if (xff) headers['x-forwarded-for'] = xff;
        return { headers, socket: { remoteAddress } };
      };
      const runLimiter = async (limiter, req, max) => {
        const seen = [];
        let status = 200;
        for (let i = 0; i < max + 1; i += 1) {
          limiter(req, { setHeader: () => {}, status: (code) => { status = code; return { json: () => ({}) }; } }, () => { seen.push(i); });
          if (status === 429) break;
        }
        return status;
      };
      // Without trusted proxies, spoofing XFF must not bypass the limit (keyed on socket IP).
      const noProxyLimiter = createRateLimiter({ windowMs: 60_000, max: 2, keyPrefix: 'test-noproxy' });
      const spoofedReq = makeLimiterRequest('198.51.100.10', '1.2.3.4');
      assert.strictEqual(await runLimiter(noProxyLimiter, spoofedReq, 2), 429, 'Spoofed XFF must not bypass the limit without a trusted proxy');
      // With a trusted proxy, the forwarded IP is honored and the limit is per forwarded client.
      const proxyLimiter = createRateLimiter({ windowMs: 60_000, max: 2, keyPrefix: 'test-proxy', trustedProxies: ['10.0.0.5'] });
      const proxiedReq = makeLimiterRequest('10.0.0.5', '203.0.113.77');
      assert.strictEqual(await runLimiter(proxyLimiter, proxiedReq, 2), 429, 'Trusted proxy XFF is honored for rate limiting');
    });

    // 11. Storage, Templates, Networking, IPv4/IPv6 Pools, Ports & Firewall
    await runStep('T10: Storage pools, LXC template catalog, Network IP pools, Port forwards & Firewall', async () => {
      const pools = await adminClient.request('GET', '/api/v1/storage/pools');
      assert.strictEqual(pools.status, 200);
      assert.ok(pools.json.pools.length >= 2);

      const tplRes = await adminClient.request('POST', '/api/v1/lxc/templates', {
        slug: 'alpine-3-20-custom',
        name: 'Alpine 3.20 Minimal Custom',
        distro: 'alpine',
        release: '3.20',
      });
      assert.ok(tplRes.status === 200 || tplRes.status === 201, `Template create failed: ${tplRes.text}`);

      const netPool = await adminClient.request('POST', '/api/v1/network/pools', {
        nodeId: 1,
        name: 'hkvm-nat-net',
        networkType: 'nat',
        bridgeName: 'lxcbr0',
        cidr: '10.88.10.0/29',
        gateway: '10.88.10.1',
      });
      assert.strictEqual(netPool.status, 201, `Net pool failed: ${netPool.text}`);

      const addIps = await adminClient.request(
        'POST',
        `/api/v1/network/pools/${netPool.json.pool.id}/ips`,
        { ips: ['10.88.10.2', '10.88.10.3'] }
      );
      assert.strictEqual(addIps.status, 200);

      const listPools = await adminClient.request('GET', '/api/v1/network/pools');
      assert.strictEqual(listPools.status, 200);
      assert.ok(listPools.json.ips.some((i) => i.ip_address === '10.88.10.2'));

      // Phase 16: each network pool must report honest IP capacity computed from
      // real ip_allocations counts (total/available/used), not a stale recorded value.
      const poolWithCap = listPools.json.pools.find((pl) => pl.id === netPool.json.pool.id);
      assert.ok(poolWithCap, 'Expected the created pool in the listing');
      assert.strictEqual(poolWithCap.ipTotal, 2, `Pool ipTotal must reflect real ip_allocations count (expected 2), got ${poolWithCap.ipTotal}`);
      assert.strictEqual(poolWithCap.ipAvailable, 2, `Pool ipAvailable must reflect available IPs (expected 2), got ${poolWithCap.ipAvailable}`);
      assert.strictEqual(poolWithCap.ipUsed, 0, `Pool ipUsed must be total minus available (expected 0), got ${poolWithCap.ipUsed}`);

      const aliceLxc = await ctx.db.get(`SELECT id FROM lxc_instances WHERE container_name = 'ct-alice-01'`);
      const portAlloc = await adminClient.request('POST', '/api/v1/network/ports', {
        instanceType: 'lxc',
        instanceRefId: aliceLxc.id,
        hostPort: 30443,
        guestPort: 443,
        protocol: 'tcp',
        description: 'HTTPS Ingress',
      });
      assert.strictEqual(portAlloc.status, 201, `Port alloc failed: ${portAlloc.text}`);

      const fwRes = await adminClient.request('POST', '/api/v1/network/firewall', {
        nodeId: 1,
        direction: 'in',
        action: 'ACCEPT',
        protocol: 'tcp',
        sourceCidr: '0.0.0.0/0',
        destPort: '8080',
        comment: 'Allow Panel HTTP',
      });
      assert.strictEqual(fwRes.status, 201, `Firewall rule failed: ${fwRes.text}`);

      // Phase 14: ISO library inventory must report honest file size and SHA-256 checksum.
      const isoDir = path.join(os.homedir(), 'vms', 'iso');
      fs.mkdirSync(isoDir, { recursive: true });
      const testIsoName = `tgvpanel-phase14-test-${Date.now()}.iso`;
      const testIsoPath = path.join(isoDir, testIsoName);
      const isoContent = 'TGVPANEL-ISO-TEST-CONTENT-1234567890';
      fs.writeFileSync(testIsoPath, isoContent);
      const expectedSha = crypto.createHash('sha256').update(isoContent).digest('hex');
      const isoInv = await adminClient.request('GET', '/api/v1/iso/inventory');
      assert.strictEqual(isoInv.status, 200, `ISO inventory failed: ${isoInv.text}`);
      const isoEntry = isoInv.json.isoFiles.find((f) => f.filename === testIsoName);
      assert.ok(isoEntry, `Expected ${testIsoName} in ISO inventory`);
      assert.strictEqual(isoEntry.sizeBytes, Buffer.byteLength(isoContent), `ISO sizeBytes must reflect the real file size, got ${isoEntry.sizeBytes}`);
      assert.strictEqual(isoEntry.sha256, expectedSha, 'ISO sha256 must reflect the real file checksum');
      try { fs.unlinkSync(testIsoPath); } catch { /* cleanup best effort */ }
    });

    // 12. Backups SHA-256, Monitoring, Alerts, Audit Logs & Impersonation
    await runStep('T11: KVM QCOW2 disk backup + SHA-256 verify, Monitoring poll, Audit & Impersonation', async () => {
      const vm = await ctx.db.get(`SELECT vm_id FROM vms LIMIT 1`);
      const dummyDisk = path.join(tmpRoot, `vm-${vm.vm_id}-disk.qcow2`);
      fs.writeFileSync(dummyDisk, crypto.randomBytes(65536));
      await ctx.db.run(`UPDATE vms SET disk_file = ? WHERE vm_id = ?`, [dummyDisk, vm.vm_id]);

      const bkRes = await adminClient.request('POST', '/api/v1/backups', {
        engine: 'kvm',
        refId: vm.vm_id,
      });
      assert.strictEqual(bkRes.status, 201, `Backup failed: ${bkRes.text}`);
      const bkId = bkRes.json.backup.backupId || bkRes.json.backup.id;
      assert.strictEqual(bkRes.json.backup.checksumSha256.length, 64);

      const verRes = await adminClient.request('POST', `/api/v1/backups/${bkId}/verify`, {});
      assert.strictEqual(verRes.status, 200, `Verify failed: ${verRes.text}`);
      assert.strictEqual(verRes.json.valid, true);

      // Phase 18: KVM disk backups are encrypted at rest (AES-256-GCM, TGVENC1).
      assert.strictEqual(bkRes.json.backup.encrypted, true, 'KVM backup response must report encryption');
      assert.strictEqual(bkRes.json.backup.encryptionAlg, 'aes-256-gcm');
      const kvmBkpRow = await ctx.db.get(
        `SELECT encrypted, encryption_alg, file_path FROM container_backups WHERE id = ?`,
        [bkId]
      );
      assert.strictEqual(Number(kvmBkpRow.encrypted), 1, 'KVM backup must be marked encrypted');
      assert.strictEqual(kvmBkpRow.encryption_alg, 'aes-256-gcm');
      assert.ok(
        isEncryptedArchive(kvmBkpRow.file_path),
        'Stored KVM backup archive must be encrypted on disk'
      );
      // Rehearsal validates the encrypted archive but honestly refuses KVM live restore.
      const kvmRehearse = await adminClient.request('POST', `/api/v1/backups/${bkId}/rehearse`, {});
      assert.strictEqual(kvmRehearse.status, 200, `KVM rehearsal failed: ${kvmRehearse.text}`);
      assert.strictEqual(kvmRehearse.json.encrypted, true);
      assert.strictEqual(kvmRehearse.json.checksumValid, true);
      assert.strictEqual(kvmRehearse.json.restorable, false, 'KVM archive live restore must be refused');

      await ctx.monitoringService.collectCycle();
      const monRes = await adminClient.request('GET', '/api/v1/monitoring/overview');
      assert.strictEqual(monRes.status, 200);
      assert.ok(monRes.json.nodeMetrics.length >= 1);

      const bobRow = await ctx.db.get(`SELECT id FROM users WHERE username = 'bob_user'`);
      const impStart = await adminClient.request(
        'POST',
        `/api/v1/auth/impersonate/${bobRow.id}`,
        {}
      );
      assert.strictEqual(impStart.status, 200, `Impersonate failed: ${impStart.text}`);

      await adminClient.request('GET', '/instances');
      const impStop = await adminClient.request('POST', '/api/v1/auth/stop-impersonation', {});
      assert.strictEqual(impStop.status, 200, `Stop impersonate failed: ${impStop.text}`);

      const logs = await adminClient.request('GET', '/api/v1/audit-logs');
      assert.strictEqual(logs.status, 200);
      assert.ok(logs.json.logs.length > 0);
    });

    // 13. All 23 Admin Pages + User Pages + Authenticated WebSocket Node PTY Shell
    await runStep('T12: All 23 Admin Sidebar EJS views, User EJS views & real node-pty WebSocket Admin Shell', async () => {
      await adminClient.request('GET', '/admin/instances');
      const adminPages = [
        '/admin/dashboard',
        '/admin/instances',
        '/admin/vms',
        '/admin/lxc',
        '/admin/instances/create',
        '/admin/nodes',
        '/admin/storage',
        '/admin/isos',
        '/admin/templates',
        '/admin/lxc-templates',
        '/admin/networking',
        '/admin/ports',
        '/admin/firewall',
        '/admin/snapshots',
        '/admin/backups',
        '/admin/migrations',
        '/admin/monitoring',
        '/admin/users',
        '/admin/api-keys',
        '/admin/audit-logs',
        '/admin/node-console',
        '/admin/license',
        '/admin/settings',
      ];
      for (const p of adminPages) {
        const r = await adminClient.request('GET', p);
        assert.strictEqual(r.status, 200, `Expected 200 OK on admin route ${p}, got ${r.status}`);
        assert.ok(r.text.includes('TGVPANEL'), `Expected TGVPANEL branding on admin route ${p}`);
        assert.ok(!/HKVM\s*PANEL/i.test(r.text), `Unexpected visible HKVM Panel branding on admin route ${p}`);
      }

      const healthRes = await adminClient.request('GET', '/api/v1/health');
      assert.strictEqual(healthRes.status, 200);
      assert.strictEqual(healthRes.json.panel, 'TGVPANEL', 'Expected /api/v1/health panel === TGVPANEL');

      const unauthLogin = await new SessionClient(baseUrl).request('GET', '/login');
      assert.strictEqual(unauthLogin.status, 200);
      assert.ok(unauthLogin.text.includes('TGVPANEL'), 'Expected TGVPANEL branding on /login');
      assert.ok(!/HKVM\s*PANEL/i.test(unauthLogin.text), 'Unexpected HKVM Panel branding on /login');

      const aliceLxc = await ctx.db.get(`SELECT id FROM lxc_instances WHERE container_name = 'ct-alice-01'`);
      const userPages = ['/dashboard', '/instances', '/lxc', `/lxc/${aliceLxc.id}`, `/lxc/${aliceLxc.id}/console`, '/ports', '/security', '/profile'];
      for (const p of userPages) {
        const r = await adminClient.request('GET', p);
        assert.strictEqual(r.status, 200, `Expected 200 OK on user route ${p}, got ${r.status}`);
        assert.ok(r.text.includes('TGVPANEL'), `Expected TGVPANEL branding on user route ${p}`);
        assert.ok(!/HKVM\s*PANEL/i.test(r.text), `Unexpected visible HKVM Panel branding on user route ${p}`);
      }
      const adminInstancesHtml = await adminClient.request('GET', '/admin/instances');
      const userInstancesHtml = await adminClient.request('GET', '/instances');
      const sharedUiSource = fs.readFileSync(path.resolve(__dirname, '../public/js/tgvpanel-v3.js'), 'utf8');
      assert.ok(adminInstancesHtml.text.includes('hkvmShowInstanceTaskHistory'), 'Admin instance table should link to task history');
      assert.ok(userInstancesHtml.text.includes('hkvmShowInstanceTaskHistory'), 'User instance cards should link to task history');
      const adminLicenseHtml = await adminClient.request('GET', '/admin/license');
      assert.strictEqual(adminLicenseHtml.status, 200, `Admin license page failed: ${adminLicenseHtml.text}`);
      assert.ok(adminLicenseHtml.text.includes('browser loopback-proxied VNC/noVNC and SSH/serial consoles'), 'Admin feature copy should describe the implemented console types');
      assert.ok(adminLicenseHtml.text.includes('loopback-only'), 'Admin feature copy must disclose VNC is proxied locally');
      assert.ok(sharedUiSource.includes('window.hkvmRunInstanceAction'), 'Shared UI should poll task status for lifecycle actions');
      assert.ok(sharedUiSource.includes("progress.removeAttribute('value')"), 'Unknown hypervisor progress must stay indeterminate, not fabricated');

      await new Promise((resolve, reject) => {
        const unauthWs = new WebSocket(`ws://127.0.0.1:${TEST_PORT}/ws/nodes/1/shell`);
        unauthWs.on('unexpected-response', (_req, res) => {
          assert.strictEqual(res.statusCode, 401);
          resolve();
        });
        unauthWs.on('open', () => reject(new Error('Unauthenticated WS should not open')));
        unauthWs.on('error', () => resolve());
      });

      const ptyOutput = await new Promise((resolve, reject) => {
        let buf = '';
        const ws = new WebSocket(`ws://127.0.0.1:${TEST_PORT}/ws/nodes/1/shell`, {
          headers: { Cookie: adminClient.cookie },
        });
        const timer = setTimeout(() => {
          ws.close();
          reject(new Error(`Timed out waiting for PTY output. Got so far: ${buf}`));
        }, 6000);
        ws.on('open', () => {
          setTimeout(() => {
            ws.send(JSON.stringify({ type: 'input', data: 'uname\n' }));
          }, 250);
        });
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'output') {
              buf += msg.data;
              if (buf.includes('Linux')) {
                clearTimeout(timer);
                ws.close();
                resolve(buf);
              }
            }
          } catch (_) {}
        });
        ws.on('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });
      assert.ok(ptyOutput.includes('Linux'), `Expected Linux in PTY output, got: ${ptyOutput}`);

      // Also verify Safe Diagnostic Preset API + redesigned Node Console Studio UI
      const ncHtmlRes = await adminClient.request('GET', '/admin/node-console');
      assert.strictEqual(ncHtmlRes.status, 200);
      assert.ok(ncHtmlRes.text.includes('nc-workbench'), 'Expected redesigned Node Console Workbench');
      assert.ok(ncHtmlRes.text.includes('nc-telemetry-grid'), 'Expected live 4-card Node Telemetry Strip');
      assert.ok(ncHtmlRes.text.includes('runNodeHealthSuite'), 'Expected 7-point Full Health Check button');

      const diagRes = await adminClient.request('POST', '/api/v1/nodes/1/diagnostics/uname', {});
      assert.strictEqual(diagRes.status, 200, `Diag preset failed: ${diagRes.text}`);
      assert.strictEqual(diagRes.json.command, 'uname -a');
      assert.strictEqual(typeof diagRes.json.durationMs, 'number');

      const sysctlDiag = await adminClient.request('POST', '/api/v1/nodes/1/diagnostics/sysctl_net', {});
      assert.strictEqual(sysctlDiag.status, 200, `sysctl_net diag failed: ${sysctlDiag.text}`);
      assert.strictEqual(sysctlDiag.json.command, 'sysctl net.ipv4.ip_forward');

      // Verify upgraded Nodes, Storage, Monitoring & License Studio views + live statfs/sample behavior
      const [nodesHtml, storageHtml, monHtml, licHtml] = await Promise.all([
        adminClient.request('GET', '/admin/nodes'),
        adminClient.request('GET', '/admin/storage'),
        adminClient.request('GET', '/admin/monitoring'),
        adminClient.request('GET', '/admin/license'),
      ]);
      assert.strictEqual(nodesHtml.status, 200);
      assert.ok(nodesHtml.text.includes('nodesKpiGrid'), 'Expected Nodes KPI Strip');
      assert.strictEqual(storageHtml.status, 200);
      assert.ok(storageHtml.text.includes('storageKpiGrid'), 'Expected Storage KPI Strip');
      assert.strictEqual(monHtml.status, 200);
      assert.ok(monHtml.text.includes('monChartCompute'), 'Expected Monitoring SVG Telemetry Charts');
      assert.strictEqual(licHtml.status, 200);
      assert.ok(licHtml.text.includes('lic-hero-banner'), 'Expected License Edition Hero Banner');

      const syncPoolsRes = await adminClient.request('GET', '/api/v1/storage/pools?sync=1');
      assert.strictEqual(syncPoolsRes.status, 200);
      const localKvmPool = (syncPoolsRes.json.pools || []).find((p) => p.name === 'local-kvm');
      assert.ok(localKvmPool && Number(localKvmPool.total_bytes) > 0, 'Expected non-zero statfs capacity on local-kvm pool');

      const beforeSamples = await adminClient.request('GET', '/api/v1/nodes/1/metrics?hours=1');
      await adminClient.request('POST', '/api/v1/nodes/1/check', {});
      const afterSamples = await adminClient.request('GET', '/api/v1/nodes/1/metrics?hours=1');
      assert.ok(
        (afterSamples.json.history || []).length >= (beforeSamples.json.history || []).length + 1,
        'Expected POST /api/v1/nodes/1/check to record an immediate telemetry sample'
      );
    });

    // 14. End-to-End LXC VPS Provisioning, Root-Owned Confinement, Lifecycle, Resize, Credentials & Host Sync
    let e2eUbuntuId = null;
    let e2eCustomId = null;
    let e2eOrphanId = null;
    await runStep('T13: End-to-end LXC VPS creation (template + custom archive + orphan/cgroup/GPG + sync-host), 0700 rootfs & full operations', async () => {
      const { execFileSync } = require('child_process');
      const { canPasswordlessSudo, privilegedFs } = require('../lib/node-agent/command-runner');

      // 13a. Honest host guard BEFORE LXC binaries exist on host: must fail cleanly AND roll back DB row
      const nativeLxcPresent =
        fs.existsSync('/usr/bin/lxc-create') || fs.existsSync('/usr/local/bin/lxc-create');
      if (!nativeLxcPresent) {
        const failProv = await adminClient.request('POST', '/api/v1/lxc', {
          containerName: 'unshimmed-guard-ct',
          templateSlug: 'ubuntu:24.04',
          cpuCores: 1,
          ramMb: 512,
          diskGb: 10,
          provisionOnHost: true,
        });
        assert.strictEqual(failProv.status, 500, 'Expected honest 500 when lxc-* is absent');
        assert.match(failProv.json.error, /not installed/i);
        const zombieRow = await ctx.db.get(
          `SELECT id FROM lxc_instances WHERE container_name = 'unshimmed-guard-ct'`
        );
        assert.strictEqual(zombieRow, undefined, 'Failed host provisioning must roll back DB row');

        const metaOnly = await adminClient.request('POST', '/api/v1/lxc', {
          containerName: 'meta-only-ct',
          templateSlug: 'ubuntu:24.04',
          cpuCores: 1,
          ramMb: 512,
          diskGb: 10,
          provisionOnHost: false,
        });
        assert.strictEqual(metaOnly.status, 201, `Meta-only LXC failed: ${metaOnly.text}`);
        assert.strictEqual(metaOnly.json.instance.status, 'stopped');
        const delMeta = await adminClient.request(
          'POST',
          `/api/v1/instances/lxc/${metaOnly.json.instance.refId}/action`,
          { action: 'delete' }
        );
        assert.strictEqual(delMeta.status, 200);
      }

      // 13b. Real 0700 root:root container directory confinement + multi-level & broken symlink escape blocking
      if (canPasswordlessSudo() && process.getuid && process.getuid() !== 0) {
        const rootJail = path.join(tmpRoot, 'root-owned-lxc-0700');
        rootOwnedCleanupDirs.push(rootJail);
        const ctRootfs = path.join(rootJail, 'ct-root-jail', 'rootfs');
        execFileSync('sudo', ['-n', 'mkdir', '-p', `${ctRootfs}/etc`, `${ctRootfs}/root`, `${ctRootfs}/tmp`]);
        execFileSync('sudo', ['-n', 'tee', `${ctRootfs}/etc/hostname`], { input: 'ct-root-jail\n' });
        execFileSync('sudo', ['-n', 'tee', `${ctRootfs}/etc/shadow`], {
          input: 'root:*:19000:0:99999:7:::\n',
        });
        execFileSync('sudo', ['-n', 'tee', `${rootJail}/ct-root-jail/config`], {
          input: `lxc.rootfs.path = dir:${ctRootfs}\nlxc.uts.name = ct-root-jail\n`,
        });
        execFileSync('sudo', ['-n', 'ln', '-s', '/etc', `${ctRootfs}/tmp/escape_dir`]);
        execFileSync('sudo', ['-n', 'ln', '-s', '/etc/nonexistent_host_secret_xyz', `${ctRootfs}/tmp/broken_sym`]);
        execFileSync('sudo', ['-n', 'chmod', '0700', rootJail]);

        assert.throws(() => fs.readdirSync(rootJail), /EACCES|EPERM/);

        const rootCm = new LxcContainerManager(rootJail);
        const etcList = rootCm.listRootfsDirectory('ct-root-jail', '/etc');
        assert.ok(etcList.some((e) => e.name === 'hostname'), 'privilegedFs listed 0700 root:root /etc');
        assert.strictEqual(
          rootCm.readRootfsFile('ct-root-jail', '/etc/hostname').toString('utf8').trim(),
          'ct-root-jail'
        );

        await rootCm.setRootPassword('ct-root-jail', 'RootOfflinePass!88');
        const shadowAfter = rootCm.readRootfsFile('ct-root-jail', '/etc/shadow').toString('utf8');
        assert.match(shadowAfter, /^root:\$6\$/m, 'Offline SHA-512 password written into 0700 /etc/shadow');

        await rootCm.injectSshPublicKey(
          'ct-root-jail',
          'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRootJailKeyTest00001 root@hkvm'
        );
        const authKeys = rootCm
          .readRootfsFile('ct-root-jail', '/root/.ssh/authorized_keys')
          .toString('utf8');
        assert.ok(authKeys.includes('IRootJailKeyTest00001'));

        // Multi-level intermediate symlink escape (<rootfs>/tmp/escape_dir -> /etc + nested new subdir) MUST fail!
        assert.throws(
          () => rootCm.writeRootfsFile('ct-root-jail', '/tmp/escape_dir/hkvm_never_create/pwn', 'x'),
          /Symlink escape/i
        );
        // Broken symlink escape MUST fail!
        assert.throws(
          () => rootCm.readRootfsFile('ct-root-jail', '/tmp/broken_sym'),
          /Symlink escape|not a regular file/i
        );
      }

      // 13c. Install stateful POSIX LXC test harness for any missing lxc-* binaries on sandbox host
      const shims = {
        'lxc-create': `#!/bin/sh
set -e
BASE="/var/lib/lxc"; NAME=""; DISTRO="ubuntu"; REL="noble"; NOVAL="0"
while [ $# -gt 0 ]; do
  case "$1" in
    -P) BASE="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
while [ $# -gt 0 ]; do
  case "$1" in
    -d) DISTRO="$2"; shift 2 ;;
    -r) REL="$2"; shift 2 ;;
    --no-validate) NOVAL="1"; shift ;;
    *) shift ;;
  esac
done
if [ "$DISTRO" = "gpgtest" ] && [ "$NOVAL" = "0" ]; then
  echo "ERROR: Unable to fetch GPG key from keyserver" >&2
  exit 1
fi
CT="$BASE/$NAME"
mkdir -p "$CT/rootfs/etc/netplan" "$CT/rootfs/etc/systemd" "$CT/rootfs/root" "$CT/rootfs/var/log" "$CT/rootfs/tmp"
printf '%s\\n' "$NAME" > "$CT/rootfs/etc/hostname"
printf 'ID=%s\\nVERSION_ID="%s"\\n' "$DISTRO" "$REL" > "$CT/rootfs/etc/os-release"
printf 'root:*:19000:0:99999:7:::\\n' > "$CT/rootfs/etc/shadow"
chmod 0640 "$CT/rootfs/etc/shadow"
ln -sf ../run/systemd/resolve/stub-resolv.conf "$CT/rootfs/etc/resolv.conf"
cat > "$CT/rootfs/etc/nsswitch.conf" <<EOF
passwd:         files systemd
group:          files systemd
hosts:          files resolve [!UNAVAIL=return] dns
networks:       files
EOF
cat > "$CT/rootfs/etc/netplan/10-lxc.yaml" <<EOF
network:
  version: 2
  ethernets:
    eth0: {dhcp4: true}
EOF
cat > "$CT/config" <<EOF
lxc.rootfs.path = dir:$CT/rootfs
lxc.uts.name = $NAME
lxc.net.0.type = veth
lxc.net.0.link = lxcbr0
lxc.apparmor.profile = generated
EOF
printf 'STOPPED\\n' > "$CT/.state"
`,
        'lxc-start': `#!/bin/sh
set -e
BASE="/var/lib/lxc"; NAME=""; LOG=""
while [ $# -gt 0 ]; do
  case "$1" in
    -P) BASE="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    -o) LOG="$2"; shift 2 ;;
    *) shift ;;
  esac
done
CT="$BASE/$NAME"
[ -f "$CT/config" ] || { echo "Container $NAME config missing" >&2; exit 1; }
if [ -f "$CT/.fail_cgroup_once" ] && grep -q "lxc.cgroup" "$CT/config"; then
  rm -f "$CT/.fail_cgroup_once"
  [ -n "$LOG" ] && printf 'lxc-start %s ERROR cgfsng - Failed to setup cgroup limits\\n' "$NAME" >> "$LOG"
  echo "lxc-start: $NAME: Failed to setup cgroup limits" >&2
  exit 1
fi
nohup sleep 300 >/dev/null 2>&1 </dev/null &
echo $! > "$CT/.pid"
printf 'RUNNING\\n' > "$CT/.state"
[ -n "$LOG" ] && printf 'lxc-start %s NOTICE start - Container started (pid=%s)\\n' "$NAME" "$(cat "$CT/.pid")" >> "$LOG"
exit 0
`,
        'lxc-stop': `#!/bin/sh
BASE="/var/lib/lxc"; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    -P) BASE="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    *) shift ;;
  esac
done
CT="$BASE/$NAME"
if [ -f "$CT/.pid" ]; then
  PID="$(cat "$CT/.pid" 2>/dev/null || true)"
  [ -n "$PID" ] && kill -TERM "$PID" 2>/dev/null || true
  rm -f "$CT/.pid"
fi
[ -d "$CT" ] && printf 'STOPPED\\n' > "$CT/.state"
exit 0
`,
        'lxc-freeze': `#!/bin/sh
BASE="/var/lib/lxc"; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in -P) BASE="$2"; shift 2 ;; -n) NAME="$2"; shift 2 ;; *) shift ;; esac
done
[ -f "$BASE/$NAME/config" ] || exit 1
printf 'FROZEN\\n' > "$BASE/$NAME/.state"
`,
        'lxc-unfreeze': `#!/bin/sh
BASE="/var/lib/lxc"; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in -P) BASE="$2"; shift 2 ;; -n) NAME="$2"; shift 2 ;; *) shift ;; esac
done
[ -f "$BASE/$NAME/config" ] || exit 1
printf 'RUNNING\\n' > "$BASE/$NAME/.state"
`,
        'lxc-destroy': `#!/bin/sh
BASE="/var/lib/lxc"; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in -P) BASE="$2"; shift 2 ;; -n) NAME="$2"; shift 2 ;; *) shift ;; esac
done
CT="$BASE/$NAME"
if [ -f "$CT/.pid" ]; then
  PID="$(cat "$CT/.pid" 2>/dev/null || true)"
  [ -n "$PID" ] && kill -KILL "$PID" 2>/dev/null || true
fi
[ -n "$NAME" ] && rm -rf "$CT"
exit 0
`,
        'lxc-ls': `#!/bin/sh
BASE="/var/lib/lxc"
while [ $# -gt 0 ]; do
  case "$1" in -P) BASE="$2"; shift 2 ;; *) shift ;; esac
done
[ -d "$BASE" ] || exit 0
for d in "$BASE"/*; do
  [ -f "$d/config" ] && basename "$d"
done
exit 0
`,
        'lxc-info': `#!/bin/sh
if [ "$1" = "--version" ]; then echo "5.0.3"; exit 0; fi
BASE="/var/lib/lxc"; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in -P) BASE="$2"; shift 2 ;; -n) NAME="$2"; shift 2 ;; *) shift ;; esac
done
CT="$BASE/$NAME"
[ -f "$CT/config" ] || exit 1
STATE="STOPPED"
[ -f "$CT/.state" ] && STATE="$(cat "$CT/.state" | tr -d '\\r\\n')"
PID=""
[ -f "$CT/.pid" ] && PID="$(cat "$CT/.pid" | tr -d '\\r\\n')"
if [ "$STATE" = "RUNNING" ] || [ "$STATE" = "FROZEN" ]; then
  if [ -z "$PID" ] || ! kill -0 "$PID" 2>/dev/null; then
    STATE="STOPPED"
    PID=""
  fi
fi
echo "Name:           $NAME"
echo "State:          $STATE"
if [ "$STATE" = "RUNNING" ] || [ "$STATE" = "FROZEN" ]; then
  echo "PID:            $PID"
  CFG_IP="$(grep -E '^[[:space:]]*lxc\\.net\\.0\\.ipv4\\.address' "$CT/config" 2>/dev/null | tail -n 1 | awk -F= '{print $2}' | tr -d ' ' | cut -d/ -f1)"
  echo "IP:             \${CFG_IP:-10.88.10.200}"
  if [ ! -f "$CT/.omit_mem_use" ]; then
    if [ ! -f "$CT/.omit_cpu_use" ]; then
      echo "CPU use:        1.35 seconds"
    fi
    echo "Memory use:     64.25 MiB"
  fi
  echo "TX bytes:       18.00 KiB"
  echo "RX bytes:       42.00 KiB"
fi
exit 0
`,
        'lxc-cgroup': `#!/bin/sh
BASE="/var/lib/lxc"; NAME=""; KEY=""; VAL=""
while [ $# -gt 0 ]; do
  case "$1" in
    -P) BASE="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    *) if [ -z "$KEY" ]; then KEY="$1"; else VAL="$1"; fi; shift ;;
  esac
done
printf '%s=%s\\n' "$KEY" "$VAL" >> "$BASE/$NAME/.live_cgroup"
exit 0
`,
        'lxc-snapshot': `#!/bin/sh
set -e
BASE="/var/lib/lxc"; NAME=""; MODE="create"; TARGET=""; CFILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    -P) BASE="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    -L) MODE="list"; shift ;;
    -C) shift ;;
    -c) CFILE="$2"; shift 2 ;;
    -r) MODE="restore"; TARGET="$2"; shift 2 ;;
    -d) MODE="delete"; TARGET="$2"; shift 2 ;;
    *) shift ;;
  esac
done
CT="$BASE/$NAME"
mkdir -p "$CT/.snaps"
META="$CT/.snaps/meta.txt"
touch "$META"
if [ "$MODE" = "list" ]; then
  cat "$META"
  exit 0
elif [ "$MODE" = "create" ]; then
  IDX="$(wc -l < "$META" | tr -d ' ')"
  SNAME="snap$IDX"
  COMMENT=""
  [ -n "$CFILE" ] && [ -f "$CFILE" ] && COMMENT="$(tr '\\n' ' ' < "$CFILE")"
  tar --numeric-owner -czpf "$CT/.snaps/$SNAME.tar.gz" -C "$CT" rootfs
  printf '%s - 2026:10:31 12:00:00 %s\\n' "$SNAME" "$COMMENT" >> "$META"
  exit 0
elif [ "$MODE" = "restore" ]; then
  [ -f "$CT/.snaps/$TARGET.tar.gz" ] || exit 1
  rm -rf "$CT/rootfs"
  tar --numeric-owner -xzpf "$CT/.snaps/$TARGET.tar.gz" -C "$CT"
  exit 0
elif [ "$MODE" = "delete" ]; then
  rm -f "$CT/.snaps/$TARGET.tar.gz"
  grep -v "^$TARGET " "$META" > "$META.tmp" || true
  mv "$META.tmp" "$META"
  exit 0
fi
`,
        'lxc-attach': `#!/bin/sh
set -e
BASE="/var/lib/lxc"; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    -P) BASE="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    --clear-env) shift ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
CT="$BASE/$NAME"
[ -f "$CT/config" ] || { echo "Container $NAME does not exist" >&2; exit 1; }
if [ "$1" = "chpasswd" ]; then
  IFS=: read -r USR PW
  HASH="$(printf '%s\\n' "$PW" | openssl passwd -6 -stdin)"
  awk -F: -v OFS=: -v h="$HASH" '$1=="root"{$2=h}{print}' "$CT/rootfs/etc/shadow" > "$CT/rootfs/etc/shadow.new"
  mv "$CT/rootfs/etc/shadow.new" "$CT/rootfs/etc/shadow"
  chmod 0640 "$CT/rootfs/etc/shadow"
  exit 0
fi
if [ "$1" = "ps" ]; then
  printf '1 root 0.1 0.5 /sbin/init\\n48 www-data 0.4 1.8 nginx\\n'
  exit 0
fi
if [ "$1" = "ip" ] || [ "$1" = "resolvectl" ]; then
  printf '%s\\n' "$*" >> "$CT/.live_net"
  exit 0
fi
if [ "$1" = "rm" ] && [ "$3" = "/etc/resolv.conf" ]; then
  rm -f "$CT/rootfs/etc/resolv.conf"
  exit 0
fi
if [ "$1" = "tee" ] && [ "$2" = "/etc/resolv.conf" ]; then
  cat > "$CT/rootfs/etc/resolv.conf"
  exit 0
fi
export CONTAINER_NAME="$NAME"
exec "$@"
`,
      };

      for (const [bin, script] of Object.entries(shims)) {
        const usrBin = `/usr/bin/${bin}`;
        const localBin = `/usr/local/bin/${bin}`;
        if (!fs.existsSync(usrBin) && !fs.existsSync(localBin)) {
          execFileSync('sudo', ['-n', 'tee', localBin], { input: script, stdio: ['pipe', 'ignore', 'pipe'] });
          execFileSync('sudo', ['-n', 'chmod', '0755', localBin]);
          installedLxcShims.push(localBin);
        }
      }

      // Re-sync node #1 (localhost) and remoteNodeId capabilities now that LXC runtime is active
      const checkLocal = await adminClient.request('POST', '/api/v1/nodes/1/check', {});
      assert.strictEqual(checkLocal.status, 200);
      assert.strictEqual(checkLocal.json.health.capabilities.lxcAvailable, true);
      const checkRemote = await adminClient.request('POST', `/api/v1/nodes/${remoteNodeId}/check`, {});
      assert.strictEqual(checkRemote.status, 200);
      assert.strictEqual(checkRemote.json.health.capabilities.lxcAvailable, true);

      // 13d. Provision LXC VPS #1 from Ubuntu 24.04 template (codename 'noble', SSH key, static IP, encrypted password)
      const createRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'e2e-ubuntu-01',
        hostname: 'e2e-ubuntu-01.hkvm.local',
        templateSlug: 'ubuntu:24.04',
        nodeId: 1,
        cpuCores: 2,
        cpuShares: 1024,
        cpuLimitPercent: 90,
        ramMb: 2048,
        swapMb: 512,
        diskGb: 25,
        bridge: 'lxcbr0',
        ipv4Address: '10.88.10.25/24',
        ipv4Gateway: '10.88.10.1',
        sshPublicKeys: ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkvmE2ePubKey00001 admin@hkvm'],
        autostart: true,
        nesting: true,
        provisionOnHost: true,
      });
      assert.strictEqual(createRes.status, 201, `LXC create #1 failed: ${createRes.text}`);
      assert.strictEqual(createRes.json.instance.status, 'running');
      assert.ok(createRes.json.generatedRootPassword.length >= 16);
      e2eUbuntuId = createRes.json.instance.refId;

      const dbRow1 = await ctx.db.get(`SELECT * FROM lxc_instances WHERE id = ?`, [e2eUbuntuId]);
      assert.ok(isEncryptedSecret(dbRow1.root_password_enc), 'Root password encrypted with AES-256-GCM');
      assert.strictEqual(decryptSecret(dbRow1.root_password_enc), createRes.json.generatedRootPassword);
      const regRow1 = await ctx.db.get(
        `SELECT * FROM instances WHERE engine = 'lxc' AND ref_id = ?`,
        [e2eUbuntuId]
      );
      assert.ok(regRow1 && regRow1.status === 'running', 'Unified instances registry synced');

      const ct1Shadow = privilegedFs.readTextSync(
        path.join(process.env.TGVPANEL_LXC_PATH, 'e2e-ubuntu-01', 'rootfs', 'etc', 'shadow')
      );
      assert.match(ct1Shadow, /^root:\$6\$/m, 'Container /etc/shadow updated with SHA-512 hash');

      // Duplicate name rejection
      const dupRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'e2e-ubuntu-01',
        templateSlug: 'ubuntu:24.04',
        provisionOnHost: true,
      });
      assert.ok(dupRes.status >= 400, 'Duplicate container name must be rejected');

      // 13e. Upload a real custom .tar.gz LXC rootfs archive via multipart/form-data & provision LXC VPS #2
      const customBuildDir = path.join(tmpRoot, 'custom-rootfs-src');
      fs.mkdirSync(path.join(customBuildDir, 'etc'), { recursive: true });
      fs.mkdirSync(path.join(customBuildDir, 'root'), { recursive: true });
      fs.writeFileSync(path.join(customBuildDir, 'etc', 'custom-release'), 'HKVM-Custom-OS-3.0\n');
      fs.writeFileSync(path.join(customBuildDir, 'etc', 'shadow'), 'root:*:19000:0:99999:7:::\n');
      const customTarPath = path.join(tmpRoot, 'hkvm-custom-os.tar.gz');
      execFileSync('tar', ['-czf', customTarPath, '-C', customBuildDir, '.']);
      const tarBytes = fs.readFileSync(customTarPath);

      const boundary = '----HkvmMultipartBoundary' + Date.now();
      const mpParts = [];
      const addField = (k, v) => {
        mpParts.push(
          Buffer.from(
            `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`
          )
        );
      };
      addField('slug', 'custom:hkvm-os-3');
      addField('name', 'HKVM Custom OS 3.0');
      addField('distro', 'debian');
      addField('release', 'bookworm');
      mpParts.push(
        Buffer.from(
          `--${boundary}\r\nContent-Disposition: form-data; name="archive"; filename="hkvm-custom-os.tar.gz"\r\nContent-Type: application/gzip\r\n\r\n`
        )
      );
      mpParts.push(tarBytes);
      mpParts.push(Buffer.from(`\r\n--${boundary}--\r\n`));
      const mpBody = Buffer.concat(mpParts);

      const uploadTpl = await adminClient.request('POST', '/api/v1/lxc/templates', mpBody, {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
      });
      assert.strictEqual(uploadTpl.status, 201, `Custom archive upload failed: ${uploadTpl.text}`);
      assert.strictEqual(uploadTpl.json.template.checksum_sha256.length, 64);

      const createCustom = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'e2e-custom-02',
        templateSlug: 'custom:hkvm-os-3',
        nodeId: 1,
        cpuCores: 1,
        ramMb: 512,
        diskGb: 10,
        provisionOnHost: true,
      });
      assert.strictEqual(createCustom.status, 201, `Custom archive LXC failed: ${createCustom.text}`);
      e2eCustomId = createCustom.json.instance.refId;

      const customStamp = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eCustomId}/files/content?path=${encodeURIComponent('/etc/custom-release')}`
      );
      assert.strictEqual(customStamp.status, 200);
      assert.strictEqual(customStamp.json.content.trim(), 'HKVM-Custom-OS-3.0');

      // 13f. Orphan host directory auto-recovery + GPG --no-validate fallback + WSL2 cgroup retry + sync-host
      const orphanDir = path.join(process.env.TGVPANEL_LXC_PATH, 'e2e-orphan-03');
      fs.mkdirSync(path.join(orphanDir, 'rootfs'), { recursive: true });
      fs.writeFileSync(path.join(orphanDir, 'config'), 'lxc.uts.name = e2e-orphan-03\n');

      const gpgTpl = await adminClient.request('POST', '/api/v1/lxc/templates', {
        slug: 'gpgtest:1.0',
        name: 'GPG Fallback Test Template',
        distro: 'gpgtest',
        release: 'current',
      });
      assert.strictEqual(gpgTpl.status, 201);

      const createOrphanAndGpg = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'e2e-orphan-03',
        templateSlug: 'gpgtest:1.0',
        nodeId: 1,
        cpuCores: 1,
        ramMb: 512,
        diskGb: 8,
        provisionOnHost: true,
      });
      assert.strictEqual(
        createOrphanAndGpg.status,
        201,
        `Orphan replacement + GPG fallback failed: ${createOrphanAndGpg.text}`
      );
      e2eOrphanId = createOrphanAndGpg.json.instance.refId;

      // Test automatic WSL2 cgroup failure strip-and-retry during startContainer
      await adminClient.request('POST', `/api/v1/instances/lxc/${e2eOrphanId}/action`, {
        action: 'stop',
      });
      privilegedFs.writeFileSync(
        path.join(process.env.TGVPANEL_LXC_PATH, 'e2e-orphan-03', '.fail_cgroup_once'),
        '1'
      );
      const retryStart = await adminClient.request(
        'POST',
        `/api/v1/instances/lxc/${e2eOrphanId}/action`,
        { action: 'start' }
      );
      assert.strictEqual(retryStart.status, 200, `WSL2 cgroup retry failed: ${retryStart.text}`);
      assert.strictEqual(retryStart.json.instance.status, 'running');

      // Create an unmanaged container directly via lxc-create and import via POST /api/v1/lxc/sync-host
      execFileSync('sudo', [
        '-n',
        '/usr/local/bin/lxc-create',
        '-P',
        process.env.TGVPANEL_LXC_PATH,
        '-n',
        'ext-host-ct-04',
        '--',
        '-d',
        'debian',
        '-r',
        'bookworm',
      ]);
      const syncHostRes = await adminClient.request('POST', '/api/v1/lxc/sync-host', {});
      assert.strictEqual(syncHostRes.status, 200, `sync-host failed: ${syncHostRes.text}`);
      assert.ok(
        syncHostRes.json.imported.includes('ext-host-ct-04'),
        `Expected ext-host-ct-04 in imported: ${JSON.stringify(syncHostRes.json)}`
      );

      // 13g. Full Lifecycle + Suspension Bypass Protection + Live Resize + Password + SSH + File Manager + Logs/Processes/Telemetry/Renew + UI Contrast Check
      for (const [act, expectedStatus] of [
        ['freeze', 'frozen'],
        ['unfreeze', 'running'],
        ['stop', 'stopped'],
        ['start', 'running'],
        ['restart', 'running'],
        ['suspend', 'suspended'],
      ]) {
        const r = await adminClient.request(
          'POST',
          `/api/v1/instances/lxc/${e2eUbuntuId}/action`,
          { action: act, reason: 'E2E test' }
        );
        assert.strictEqual(r.status, 200, `Action ${act} failed: ${r.text}`);
        assert.strictEqual(r.json.instance.status, expectedStatus);
      }

      // Starting OR reinstalling while suspended MUST be blocked with HTTP 400!
      const startWhileSusp = await adminClient.request(
        'POST',
        `/api/v1/instances/lxc/${e2eUbuntuId}/action`,
        { action: 'start' }
      );
      assert.strictEqual(startWhileSusp.status, 400, 'Cannot start suspended LXC');
      const reinstallWhileSusp = await adminClient.request(
        'POST',
        `/api/v1/lxc/${e2eUbuntuId}/reinstall`,
        { templateSlug: 'ubuntu:24.04' }
      );
      assert.strictEqual(reinstallWhileSusp.status, 400, 'Cannot bypass suspension via reinstall');

      // Unsuspend & start back up
      await adminClient.request('POST', `/api/v1/instances/lxc/${e2eUbuntuId}/action`, {
        action: 'unsuspend',
      });
      const afterUnsusp = await adminClient.request(
        'POST',
        `/api/v1/instances/lxc/${e2eUbuntuId}/action`,
        { action: 'start' }
      );
      assert.strictEqual(afterUnsusp.status, 200);
      assert.strictEqual(afterUnsusp.json.instance.status, 'running');

      // Live resize & network update via PATCH /api/v1/lxc/:id
      const patchRes = await adminClient.request('PATCH', `/api/v1/lxc/${e2eUbuntuId}`, {
        cpuCores: 4,
        cpuLimitPercent: 80,
        cpuShares: 2048,
        ramMb: 4096,
        swapMb: 1024,
        diskGb: 40,
        bridge: 'lxcbr0',
        ipAddress: '10.88.10.26/24',
        gateway: '10.88.10.1',
        nesting: true,
        autostart: true,
      });
      assert.strictEqual(patchRes.status, 200, `Resize PATCH failed: ${patchRes.text}`);
      assert.strictEqual(patchRes.json.instance.cpuCores, 4);
      assert.strictEqual(patchRes.json.instance.ramMb, 4096);
      const liveCg = privilegedFs.readTextSync(
        path.join(process.env.TGVPANEL_LXC_PATH, 'e2e-ubuntu-01', '.live_cgroup')
      );
      assert.ok(liveCg.includes('4096M'), 'Live lxc-cgroup memory limit applied while running');

      // Root password reset (online via lxc-attach chpasswd) & SSH key injection
      const pwRes = await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/password`, {
        password: 'UpdatedLivePass!2026',
      });
      assert.strictEqual(pwRes.status, 200, `Password reset failed: ${pwRes.text}`);
      assert.strictEqual(pwRes.json.rootPassword, 'UpdatedLivePass!2026');

      const sshRes = await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/ssh-key`, {
        publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISecondKeyInjected99999 ops@hkvm',
      });
      assert.strictEqual(sshRes.status, 200, `SSH key inject failed: ${sshRes.text}`);

      // Confined Rootfs File Manager CRUD + traversal block
      const writeF = await adminClient.request(
        'POST',
        `/api/v1/lxc/${e2eUbuntuId}/files/content`,
        { path: '/var/www/index.html', content: '<h1>HKVM LXC OK</h1>' }
      );
      assert.strictEqual(writeF.status, 200);
      const listF = await adminClient.request('GET', `/api/v1/lxc/${e2eUbuntuId}/files?path=/var/www`);
      assert.strictEqual(listF.status, 200);
      assert.ok(listF.json.entries.some((e) => e.name === 'index.html'));
      const readF = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eUbuntuId}/files/content?path=/var/www/index.html`
      );
      assert.strictEqual(readF.json.content, '<h1>HKVM LXC OK</h1>');
      const delF = await adminClient.request(
        'DELETE',
        `/api/v1/lxc/${e2eUbuntuId}/files?path=/var/www/index.html`
      );
      assert.strictEqual(delF.status, 200);
      const travF = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eUbuntuId}/files/content?path=${encodeURIComponent('/../../etc/passwd')}`
      );
      assert.strictEqual(travF.status, 400);

      // Processes, Logs, Telemetry, Expiration Renewal & Detail EJS Regression Check
      const procRes = await adminClient.request('GET', `/api/v1/lxc/${e2eUbuntuId}/processes`);
      assert.strictEqual(procRes.status, 200);
      assert.ok(procRes.json.processes.some((p) => p.command.includes('nginx')));

      const logRes = await adminClient.request('GET', `/api/v1/lxc/${e2eUbuntuId}/logs`);
      assert.strictEqual(logRes.status, 200);
      assert.match(logRes.json.logs, /Container started/);

      const telRes = await adminClient.request(
        'GET',
        `/api/v1/instances/lxc/${e2eUbuntuId}/telemetry`
      );
      assert.strictEqual(telRes.status, 200);
      assert.strictEqual(telRes.json.telemetry.status, 'running');
      assert.ok(telRes.json.telemetry.ramUsedMb >= 60);

      const renewRes = await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/renew`, {
        days: 30,
      });
      assert.strictEqual(renewRes.status, 200);
      assert.ok(renewRes.json.instance.expiresAt);

      const detailPage = await adminClient.request('GET', `/lxc/${e2eUbuntuId}`);
      assert.strictEqual(detailPage.status, 200);
      assert.ok(
        !detailPage.text.includes('background: var(--accent-primary'),
        'Regression guard: .lxc-tab.active must not use white --accent-primary background'
      );
      assert.ok(detailPage.text.includes('id="pane-resources"'), 'Staff resize pane rendered');
    });

    await runStep('T31: Scheduled LXC backups run on due time, verify SHA-256, retain latest N, notify owner, and preserve manual backups', async () => {
      const manualBefore = await ctx.db.get(`SELECT COUNT(*) AS count FROM container_backups WHERE instance_type = 'lxc' AND instance_ref_id = ? AND COALESCE(is_scheduled, 0) = 0`, [e2eUbuntuId]);
      const invalid = await adminClient.request('PUT', `/api/v1/backup-schedules/lxc/${e2eUbuntuId}`, {
        frequency: 'daily', retentionCount: 366,
      });
      assert.strictEqual(invalid.status, 400, 'Out-of-range retention should be rejected');

      const configured = await adminClient.request('PUT', `/api/v1/backup-schedules/lxc/${e2eUbuntuId}`, {
        frequency: 'daily', retentionCount: 1,
      });
      assert.strictEqual(configured.status, 200, `Schedule setup failed: ${configured.text}`);
      assert.strictEqual(configured.json.schedule.last_status, 'scheduled');
      const scheduleList = await adminClient.request('GET', `/api/v1/backup-schedules?engine=lxc&refId=${e2eUbuntuId}`);
      assert.strictEqual(scheduleList.status, 200);
      assert.strictEqual(scheduleList.json.schedules.length, 1);
      const nonOwner = new SessionClient(baseUrl);
      const nonOwnerLogin = await nonOwner.request('POST', '/api/login', { username: 'bob_user', password: 'BobPass!123' });
      assert.strictEqual(nonOwnerLogin.status, 200);
      const nonOwnerSchedule = await nonOwner.request('GET', `/api/v1/backup-schedules?engine=lxc&refId=${e2eUbuntuId}`);
      assert.strictEqual(nonOwnerSchedule.status, 403, 'Non-owners cannot view/manage a backup schedule');
      const backupAdminPage = await adminClient.request('GET', '/admin/backups');
      assert.strictEqual(backupAdminPage.status, 200);
      assert.ok(backupAdminPage.text.includes('Automated Backup Schedule'), 'Admin backups page should render schedule controls');

      for (let run = 0; run < 3; run += 1) {
        await ctx.db.run(`UPDATE backup_schedules SET next_run = datetime('now', '-1 minute') WHERE id = ?`, [configured.json.schedule.id]);
        const result = await ctx.backupManager.runDueBackupSchedules();
        assert.deepStrictEqual(result, { processed: 1, succeeded: 1, failed: 0 }, `Scheduled backup run ${run + 1} did not succeed`);
      }
      const completedSchedule = await ctx.db.get(`SELECT * FROM backup_schedules WHERE id = ?`, [configured.json.schedule.id]);
      assert.strictEqual(completedSchedule.last_status, 'success');
      assert.ok(completedSchedule.last_backup_id > 0);
      assert.ok(completedSchedule.next_run > completedSchedule.last_run, 'Next scheduled run must advance');

      const retained = await ctx.db.all(`SELECT * FROM container_backups WHERE schedule_id = ? AND is_scheduled = 1`, [configured.json.schedule.id]);
      assert.strictEqual(retained.length, 1, 'Retention should keep exactly one scheduled backup');
      const integrity = await ctx.backupManager.verifyBackupIntegrity(retained[0].id);
      assert.strictEqual(integrity.valid, true, 'Retained scheduled archive must verify by SHA-256');
      const manualAfter = await ctx.db.get(`SELECT COUNT(*) AS count FROM container_backups WHERE instance_type = 'lxc' AND instance_ref_id = ? AND COALESCE(is_scheduled, 0) = 0`, [e2eUbuntuId]);
      assert.strictEqual(manualAfter.count, manualBefore.count, 'Scheduled retention must never prune manual backups');
      const ownerNotices = await ctx.db.get(`SELECT COUNT(*) AS count FROM notifications WHERE user_id = 1 AND title = 'Scheduled backup completed'`);
      assert.ok(ownerNotices.count >= 3, 'Each verified schedule run should notify the owner');

      const removed = await adminClient.request('DELETE', `/api/v1/backup-schedules/lxc/${e2eUbuntuId}`);
      assert.strictEqual(removed.status, 200);
      await ctx.backupManager.deleteBackup(retained[0].id);

      const orphan = await ctx.db.run(
        `INSERT INTO backup_schedules (instance_type, instance_ref_id, enabled, frequency, retention_count, next_run, created_by, owner_user_id)
         VALUES ('lxc', 999999, 1, 'daily', 1, datetime('now', '-1 minute'), 1, 1)`
      );
      const orphanRun = await ctx.backupManager.runDueBackupSchedules();
      assert.deepStrictEqual(orphanRun, { processed: 1, succeeded: 0, failed: 1 });
      const orphanStatus = await ctx.db.get(`SELECT enabled, last_status FROM backup_schedules WHERE id = ?`, [orphan.lastID]);
      assert.strictEqual(orphanStatus.enabled, 0, 'Deleted/missing instance schedules should be disabled');
      assert.strictEqual(orphanStatus.last_status, 'orphaned');
    });

    await runStep('T32: Scheduled LXC snapshots execute, retain only scheduled points, notify owners, and skip running KVMs', async () => {
      const manualBefore = await ctx.db.get(
        `SELECT COUNT(*) AS count FROM container_snapshots WHERE lxc_id = ? AND COALESCE(is_scheduled, 0) = 0`,
        [e2eUbuntuId]
      );
      const invalid = await adminClient.request('PUT', `/api/v1/snapshot-schedules/lxc/${e2eUbuntuId}`, {
        frequency: 'daily', retentionCount: 0,
      });
      assert.strictEqual(invalid.status, 400, 'Invalid snapshot retention must be rejected');

      const configured = await adminClient.request('PUT', `/api/v1/snapshot-schedules/lxc/${e2eUbuntuId}`, {
        frequency: 'daily', retentionCount: 1,
      });
      assert.strictEqual(configured.status, 200, `Snapshot schedule setup failed: ${configured.text}`);
      assert.strictEqual(configured.json.schedule.last_status, 'scheduled');
      const listed = await adminClient.request('GET', `/api/v1/snapshot-schedules?engine=lxc&refId=${e2eUbuntuId}`);
      assert.strictEqual(listed.status, 200);
      assert.strictEqual(listed.json.schedules.length, 1);
      const snapshotPage = await adminClient.request('GET', '/admin/snapshots');
      assert.strictEqual(snapshotPage.status, 200);
      assert.ok(snapshotPage.text.includes('Automated Snapshot Schedule'));
      assert.ok(snapshotPage.text.includes('not guest-consistent'));

      const nonOwner = new SessionClient(baseUrl);
      await nonOwner.request('POST', '/api/login', { username: 'bob_user', password: 'BobPass!123' });
      const denied = await nonOwner.request('GET', `/api/v1/snapshot-schedules?engine=lxc&refId=${e2eUbuntuId}`);
      assert.strictEqual(denied.status, 403, 'Non-owners cannot view snapshot schedules');

      for (let run = 0; run < 3; run += 1) {
        await ctx.db.run(`UPDATE snapshot_schedules SET next_run = datetime('now', '-1 minute') WHERE id = ?`, [configured.json.schedule.id]);
        const result = await ctx.backupManager.runDueSnapshotSchedules();
        assert.deepStrictEqual(result, { processed: 1, succeeded: 1, failed: 0 }, `Scheduled LXC snapshot run ${run + 1} failed`);
      }
      const completed = await ctx.db.get(`SELECT * FROM snapshot_schedules WHERE id = ?`, [configured.json.schedule.id]);
      assert.strictEqual(completed.last_status, 'success');
      assert.ok(completed.last_snapshot_id > 0);
      const retained = await ctx.db.all(`SELECT * FROM container_snapshots WHERE schedule_id = ? AND is_scheduled = 1`, [configured.json.schedule.id]);
      assert.strictEqual(retained.length, 1, 'Snapshot retention must keep exactly one scheduled snapshot');
      const manualAfter = await ctx.db.get(
        `SELECT COUNT(*) AS count FROM container_snapshots WHERE lxc_id = ? AND COALESCE(is_scheduled, 0) = 0`,
        [e2eUbuntuId]
      );
      assert.strictEqual(manualAfter.count, manualBefore.count, 'Scheduled retention must preserve manual snapshots');
      const notices = await ctx.db.get(`SELECT COUNT(*) AS count FROM notifications WHERE user_id = 1 AND title = 'Scheduled snapshot completed'`);
      assert.ok(notices.count >= 3, 'Each scheduled snapshot should notify the owner');
      const deleted = await adminClient.request('DELETE', `/api/v1/snapshot-schedules/lxc/${e2eUbuntuId}`);
      assert.strictEqual(deleted.status, 200);
      await ctx.backupManager.deleteSnapshot('lxc', e2eUbuntuId, retained[0].id);

      const vm = await ctx.db.get(`SELECT vm_id FROM vms WHERE owner_id = 1 ORDER BY vm_id LIMIT 1`);
      assert.ok(vm, 'A test KVM VM should exist for the stopped-VM safety check');
      const oldStatus = await ctx.db.get(`SELECT status, pid FROM vms WHERE vm_id = ?`, [vm.vm_id]);
      await ctx.db.run(`UPDATE vms SET status = 'running' WHERE vm_id = ?`, [vm.vm_id]);
      try {
        const kvmSchedule = await adminClient.request('PUT', `/api/v1/snapshot-schedules/kvm/${vm.vm_id}`, {
          frequency: 'hourly', retentionCount: 1,
        });
        assert.strictEqual(kvmSchedule.status, 200, `KVM schedule setup failed: ${kvmSchedule.text}`);
        await ctx.db.run(`UPDATE snapshot_schedules SET next_run = datetime('now', '-1 minute') WHERE id = ?`, [kvmSchedule.json.schedule.id]);
        const skipped = await ctx.backupManager.runDueSnapshotSchedules();
        assert.deepStrictEqual(skipped, { processed: 1, succeeded: 0, failed: 1 });
        const status = await ctx.db.get(`SELECT last_status, last_error FROM snapshot_schedules WHERE id = ?`, [kvmSchedule.json.schedule.id]);
        assert.strictEqual(status.last_status, 'failed');
        assert.match(status.last_error, /require the VM to be stopped/);
        await adminClient.request('DELETE', `/api/v1/snapshot-schedules/kvm/${vm.vm_id}`);

        // Even if the database says stopped, a live QEMU PID must block disk snapshotting.
        await ctx.db.run(`UPDATE vms SET status = 'stopped', pid = ? WHERE vm_id = ?`, [process.pid, vm.vm_id]);
        const livePidSchedule = await adminClient.request('PUT', `/api/v1/snapshot-schedules/kvm/${vm.vm_id}`, {
          frequency: 'hourly', retentionCount: 1,
        });
        assert.strictEqual(livePidSchedule.status, 200);
        await ctx.db.run(`UPDATE snapshot_schedules SET next_run = datetime('now', '-1 minute') WHERE id = ?`, [livePidSchedule.json.schedule.id]);
        const livePidSkipped = await ctx.backupManager.runDueSnapshotSchedules();
        assert.deepStrictEqual(livePidSkipped, { processed: 1, succeeded: 0, failed: 1 });
        const livePidError = await ctx.db.get(`SELECT last_error FROM snapshot_schedules WHERE id = ?`, [livePidSchedule.json.schedule.id]);
        assert.match(livePidError.last_error, /require the VM to be stopped/);
        await adminClient.request('DELETE', `/api/v1/snapshot-schedules/kvm/${vm.vm_id}`);
      } finally {
        await ctx.db.run(`UPDATE vms SET status = ?, pid = ? WHERE vm_id = ?`, [oldStatus.status, oldStatus.pid, vm.vm_id]);
      }
    });

    await runStep('T33: Reseller HMAC API keys enforce scopes, replay protection, rotation, rate/IP limits and admin revocation', async () => {
      const bcrypt = require('bcryptjs');
      const inserted = await ctx.db.run(
        `INSERT INTO users (username, password, email, role, is_active) VALUES ('api_reseller', ?, 'api-reseller@example.org', 'reseller', 1)`,
        [bcrypt.hashSync('ResellerPass!234', 10)]
      );
      const resellerId = inserted.lastID;
      const reseller = new SessionClient(baseUrl);
      const login = await reseller.request('POST', '/api/login', { username: 'api_reseller', password: 'ResellerPass!234' });
      assert.strictEqual(login.status, 200, `Reseller login failed: ${login.text}`);
      const portal = await reseller.request('GET', '/reseller/api-keys');
      assert.strictEqual(portal.status, 200);
      assert.ok(portal.text.includes('Reseller API Keys'));
      const customerPortal = await reseller.request('GET', '/reseller/customers');
      assert.strictEqual(customerPortal.status, 200);
      assert.ok(customerPortal.text.includes('Reseller Customer Directory'));
      assert.ok(customerPortal.text.includes('do not grant access to any VPS or resources'));
      const roleSetup = await adminClient.request('GET', '/admin/users/create');
      assert.strictEqual(roleSetup.status, 200);
      assert.ok(roleSetup.text.includes('value="reseller"'), 'Admin user creation should offer the reseller role');
      const adminUsersPage = await adminClient.request('GET', '/admin/users');
      assert.strictEqual(adminUsersPage.status, 200);
      assert.ok(adminUsersPage.text.includes('toggleResellerAccount'), 'Admin user list should expose reseller suspend controls');
      assert.ok(adminUsersPage.text.includes('Reseller resources'), 'Admin user list should include resource summary columns');

      const created = await reseller.request('POST', '/api/v1/reseller/api-keys', {
        name: 'read-only automation',
        description: 'Acceptance-test credentials',
        permissions: ['vps.read', 'stats.read', 'resources.read', 'customers.read', 'customers.create', 'customers.update', 'customers.delete'],
        rateLimitPerMinute: 100,
        ipAllowlist: [],
      });
      assert.strictEqual(created.status, 201, `Reseller key creation failed: ${created.text}`);
      assert.ok(created.json.apiKey.startsWith('tgvpk_'));
      assert.strictEqual(created.json.secretShownOnce, true);
      assert.ok(created.json.apiSecret);
      const keyRow = await ctx.db.get(`SELECT * FROM reseller_api_keys WHERE id = ?`, [created.json.id]);
      assert.ok(keyRow.secret_enc.startsWith('enc:v1:'), 'HMAC secret must be encrypted at rest');
      assert.notStrictEqual(keyRow.secret_enc, created.json.apiSecret);
      assert.strictEqual(keyRow.secret_hash, hashApiKey(created.json.apiSecret));
      assert.strictEqual(keyRow.key_hash, hashApiKey(created.json.apiKey));

      const list = await reseller.request('GET', '/api/v1/reseller/api-keys');
      assert.strictEqual(list.status, 200);
      assert.strictEqual(list.json.apiKeys.length, 1);
      assert.ok(!JSON.stringify(list.json).includes(created.json.apiSecret), 'Key listing must never reveal the secret');
      assert.ok(!JSON.stringify(list.json).includes(created.json.apiKey), 'Key listing must never reveal the raw key');

      async function signedRequest(method, pathWithQuery, apiKey, apiSecret, body, options = {}) {
        const rawBody = body === undefined ? undefined : JSON.stringify(body);
        const headers = signResellerRequest({
          apiKey,
          apiSecret,
          method,
          pathWithQuery,
          body: rawBody,
          timestamp: options.timestamp,
          nonce: options.nonce,
        });
        if (options.bodyOverride !== undefined) {
          const client = new SessionClient(baseUrl);
          return client.request(method, pathWithQuery, options.bodyOverride, headers);
        }
        return new SessionClient(baseUrl).request(method, pathWithQuery, rawBody, headers);
      }

      const statsPath = '/api/v1/reseller/stats';
      const stats = await signedRequest('GET', statsPath, created.json.apiKey, created.json.apiSecret);
      assert.strictEqual(stats.status, 200, `Signed stats request failed: ${stats.text}`);
      assert.ok(Number.isInteger(stats.json.stats.totalVps));
      const resourceSummary = await signedRequest('GET', '/api/v1/reseller/resources', created.json.apiKey, created.json.apiSecret);
      assert.strictEqual(resourceSummary.status, 200, `Signed resource summary failed: ${resourceSummary.text}`);
      assert.strictEqual(resourceSummary.json.resources.allocated.vps, 0);
      assert.strictEqual(resourceSummary.json.resources.limitsAvailable, false, 'Do not invent reseller quotas before allocation models exist');
      assert.strictEqual(resourceSummary.json.resources.telemetry.cpuPercent, null, 'Unavailable telemetry must be null, not simulated as zero');

      const customerPath = '/api/v1/reseller/customers';
      const customerCreate = await signedRequest('POST', customerPath, created.json.apiKey, created.json.apiSecret, {
        displayName: 'Acme Customer', email: 'BILLING@EXAMPLE.ORG', externalReference: 'crm-42', notes: 'Acceptance contact',
      });
      assert.strictEqual(customerCreate.status, 201, `Customer creation failed: ${customerCreate.text}`);
      const customerId = customerCreate.json.customer.id;
      assert.strictEqual(customerCreate.json.customer.email, 'billing@example.org');
      const storedCustomerNotes = await ctx.db.get(`SELECT notes_enc FROM reseller_customers WHERE id = ?`, [customerId]);
      assert.ok(storedCustomerNotes.notes_enc.startsWith('enc:v1:'), 'Customer notes must be encrypted at rest');
      assert.ok(!storedCustomerNotes.notes_enc.includes('Acceptance contact'));
      const customerDuplicate = await signedRequest('POST', customerPath, created.json.apiKey, created.json.apiSecret, {
        displayName: 'Duplicate', email: 'Billing@example.org',
      });
      assert.strictEqual(customerDuplicate.status, 409, 'Email duplicates must be unique within one reseller account');
      const customerSearchPath = `${customerPath}?search=acme&limit=10&offset=0`;
      const customerList = await signedRequest('GET', customerSearchPath, created.json.apiKey, created.json.apiSecret);
      assert.strictEqual(customerList.status, 200);
      assert.strictEqual(customerList.json.pagination.total, 1);
      const customerReadPath = `${customerPath}/${customerId}`;
      assert.strictEqual((await signedRequest('GET', customerReadPath, created.json.apiKey, created.json.apiSecret)).status, 200);
      const customerUpdate = await signedRequest('PUT', customerReadPath, created.json.apiKey, created.json.apiSecret, { displayName: 'Acme Updated', status: 'suspended' });
      assert.strictEqual(customerUpdate.status, 200, `Customer update failed: ${customerUpdate.text}`);
      assert.strictEqual(customerUpdate.json.customer.status, 'suspended');
      assert.strictEqual(customerUpdate.json.customer.email, 'billing@example.org', 'Partial updates must preserve omitted fields');
      assert.strictEqual(customerUpdate.json.customer.notes, 'Acceptance contact', 'Encrypted notes should be decrypted only for the owning reseller response');
      assert.strictEqual((await signedRequest('PUT', customerReadPath, created.json.apiKey, created.json.apiSecret, { status: 'deleted' })).status, 400);

      const secondResellerInsert = await ctx.db.run(
        `INSERT INTO users (username, password, email, role, is_active) VALUES ('api_reseller_two', ?, 'api-reseller-two@example.org', 'reseller', 1)`,
        [bcrypt.hashSync('ResellerPass!234', 10)]
      );
      const secondReseller = new SessionClient(baseUrl);
      assert.strictEqual((await secondReseller.request('POST', '/api/login', { username: 'api_reseller_two', password: 'ResellerPass!234' })).status, 200);
      assert.strictEqual((await secondReseller.request('GET', '/reseller/customers')).status, 200);
      const secondCustomerKey = await secondReseller.request('POST', '/api/v1/reseller/api-keys', { name: 'customer reader', permissions: ['customers.read'] });
      assert.strictEqual(secondCustomerKey.status, 201, `Second reseller customer key creation failed: ${secondCustomerKey.text}`);
      const foreignCustomerRead = await signedRequest('GET', customerReadPath, secondCustomerKey.json.apiKey, secondCustomerKey.json.apiSecret);
      assert.strictEqual(foreignCustomerRead.status, 404, 'A reseller must not read another reseller customer');
      const secondCustomerList = await signedRequest('GET', customerPath, secondCustomerKey.json.apiKey, secondCustomerKey.json.apiSecret);
      assert.strictEqual(secondCustomerList.json.pagination.total, 0, 'Customer list must be isolated to the authenticated reseller');

      const customerDelete = await signedRequest('DELETE', customerReadPath, created.json.apiKey, created.json.apiSecret);
      assert.strictEqual(customerDelete.status, 200);
      assert.strictEqual(customerDelete.json.deleted, true);
      assert.strictEqual((await signedRequest('GET', customerReadPath, created.json.apiKey, created.json.apiSecret)).status, 404);
      assert.ok(!(await ctx.db.get(`SELECT id FROM reseller_customers WHERE id = ?`, [customerId])), 'Delete must remove the contact record');
      assert.strictEqual((await signedRequest('POST', customerPath, created.json.apiKey, created.json.apiSecret, { displayName: 'Recreated', email: 'billing@example.org' })).status, 201, 'Deleted emails may be reused by their owner');

      const vpsListPath = '/api/v1/reseller/vps?limit=10&offset=0&engine=kvm';
      const vpsList = await signedRequest('GET', vpsListPath, created.json.apiKey, created.json.apiSecret);
      assert.strictEqual(vpsList.status, 200, `Signed paginated VPS list failed: ${vpsList.text}`);
      assert.ok(Array.isArray(vpsList.json.vps));
      assert.strictEqual(vpsList.json.pagination.limit, 10);
      assert.strictEqual(vpsList.json.pagination.offset, 0);
      assert.ok(Number.isInteger(vpsList.json.pagination.total));
      assert.strictEqual((await signedRequest('GET', '/api/v1/reseller/vps?limit=0', created.json.apiKey, created.json.apiSecret)).status, 400, 'Invalid pagination must be rejected');
      assert.strictEqual((await signedRequest('GET', '/api/v1/reseller/vps?engine=xen', created.json.apiKey, created.json.apiSecret)).status, 400, 'Unsupported engines must not be accepted as filters');

      const replayNonce = crypto.randomBytes(16).toString('hex');
      const replayHeaders = signResellerRequest({ apiKey: created.json.apiKey, apiSecret: created.json.apiSecret, method: 'GET', pathWithQuery: statsPath, nonce: replayNonce });
      const replayFirst = await new SessionClient(baseUrl).request('GET', statsPath, undefined, replayHeaders);
      assert.strictEqual(replayFirst.status, 200);
      const replaySecond = await new SessionClient(baseUrl).request('GET', statsPath, undefined, replayHeaders);
      assert.strictEqual(replaySecond.status, 401, 'A previously used nonce must be rejected');

      const stale = await signedRequest('GET', statsPath, created.json.apiKey, created.json.apiSecret, undefined, { timestamp: Math.floor(Date.now() / 1000) - 600 });
      assert.strictEqual(stale.status, 401, 'Old request timestamps must be rejected');

      const limitedScopePath = `/api/v1/reseller/vps/999999/start?engine=kvm`;
      const scopeDenied = await signedRequest('POST', limitedScopePath, created.json.apiKey, created.json.apiSecret, {});
      assert.strictEqual(scopeDenied.status, 403, 'A read-only key must not call lifecycle mutations');

      const badBodyHeaders = signResellerRequest({ apiKey: created.json.apiKey, apiSecret: created.json.apiSecret, method: 'POST', pathWithQuery: limitedScopePath, body: '{"action":"start"}' });
      const badBody = await new SessionClient(baseUrl).request('POST', limitedScopePath, '{"action":"stop"}', badBodyHeaders);
      assert.strictEqual(badBody.status, 401, 'Signature must bind the exact raw request body');

      const otherUser = new SessionClient(baseUrl);
      const bobLogin = await otherUser.request('POST', '/api/login', { username: 'bob_user', password: 'BobPass!123' });
      assert.strictEqual(bobLogin.status, 200);
      assert.strictEqual((await otherUser.request('GET', '/api/v1/reseller/api-keys')).status, 403, 'Non-resellers cannot access reseller key management');
      assert.strictEqual((await reseller.request('GET', '/api/v1/reseller/admin/accounts')).status, 403, 'Resellers cannot access admin reseller account oversight');

      const ipRestricted = await reseller.request('POST', '/api/v1/reseller/api-keys', {
        name: 'IP restricted test', permissions: ['stats.read'], ipAllowlist: ['192.0.2.77'], rateLimitPerMinute: 10,
      });
      assert.strictEqual(ipRestricted.status, 201);
      const ipDenied = await signedRequest('GET', statsPath, ipRestricted.json.apiKey, ipRestricted.json.apiSecret);
      assert.strictEqual(ipDenied.status, 403, 'Requests outside a key IP allowlist must be rejected');

      const rateKey = await reseller.request('POST', '/api/v1/reseller/api-keys', {
        name: 'Rate limited test', permissions: ['stats.read'], rateLimitPerMinute: 1,
      });
      assert.strictEqual(rateKey.status, 201);
      assert.strictEqual((await signedRequest('GET', statsPath, rateKey.json.apiKey, rateKey.json.apiSecret)).status, 200);
      assert.strictEqual((await signedRequest('GET', statsPath, rateKey.json.apiKey, rateKey.json.apiSecret)).status, 429, 'Per-key rate limits must be enforced');

      const adminPage = await adminClient.request('GET', '/admin/api-keys');
      assert.strictEqual(adminPage.status, 200);
      assert.ok(adminPage.text.includes('Reseller HMAC API Keys'), 'Admin key page should include reseller oversight controls');
      const adminList = await adminClient.request('GET', '/api/v1/reseller/admin/api-keys');
      assert.strictEqual(adminList.status, 200, `Admin key inspection failed: ${adminList.text}`);
      assert.ok(adminList.json.apiKeys.some((key) => key.id === created.json.id && key.userId === resellerId));
      assert.ok(!JSON.stringify(adminList.json).includes(created.json.apiSecret), 'Admin oversight must not reveal secrets');
      const disabledByAdmin = await adminClient.request('POST', `/api/v1/reseller/admin/api-keys/${created.json.id}/disable`, {});
      assert.strictEqual(disabledByAdmin.status, 200);
      assert.strictEqual((await signedRequest('GET', statsPath, created.json.apiKey, created.json.apiSecret)).status, 401);
      const adminRevoked = await adminClient.request('DELETE', `/api/v1/reseller/admin/api-keys/${ipRestricted.json.id}`);
      assert.strictEqual(adminRevoked.status, 200, 'Admin must be able to permanently revoke a reseller key');
      assert.strictEqual((await signedRequest('GET', statsPath, ipRestricted.json.apiKey, ipRestricted.json.apiSecret)).status, 401);

      const enabledByOwner = await reseller.request('POST', `/api/v1/reseller/api-keys/${created.json.id}/enable`, {});
      assert.strictEqual(enabledByOwner.status, 200);
      const rotated = await reseller.request('POST', `/api/v1/reseller/api-keys/${created.json.id}/rotate`, {});
      assert.strictEqual(rotated.status, 200, `Secret rotation failed: ${rotated.text}`);
      assert.notStrictEqual(rotated.json.apiKey, created.json.apiKey);
      assert.notStrictEqual(rotated.json.apiSecret, created.json.apiSecret);
      assert.strictEqual((await signedRequest('GET', statsPath, created.json.apiKey, created.json.apiSecret)).status, 401, 'Old credentials must be invalid after rotation');
      assert.strictEqual((await signedRequest('GET', statsPath, rotated.json.apiKey, rotated.json.apiSecret)).status, 200);

      const resellerAccounts = await adminClient.request('GET', '/api/v1/reseller/admin/accounts');
      assert.strictEqual(resellerAccounts.status, 200, `Admin reseller account listing failed: ${resellerAccounts.text}`);
      const resellerAccount = resellerAccounts.json.accounts.find((account) => account.id === resellerId);
      assert.ok(resellerAccount && resellerAccount.isActive);
      assert.deepStrictEqual(resellerAccount.usage, { totalVps: 0, cpuCores: 0, ramMb: 0, diskGb: 0 });
      assert.strictEqual((await adminClient.request('POST', '/api/v1/reseller/admin/accounts/not-an-id/suspend', {})).status, 400);
      const suspendedAccount = await adminClient.request('POST', `/api/v1/reseller/admin/accounts/${resellerId}/suspend`, {});
      assert.strictEqual(suspendedAccount.status, 200, `Admin reseller suspension failed: ${suspendedAccount.text}`);
      assert.strictEqual(suspendedAccount.json.keysDisabled, true);
      assert.strictEqual((await signedRequest('GET', statsPath, rotated.json.apiKey, rotated.json.apiSecret)).status, 401, 'Suspended reseller keys must stop working immediately');
      const resumedAccount = await adminClient.request('POST', `/api/v1/reseller/admin/accounts/${resellerId}/unsuspend`, {});
      assert.strictEqual(resumedAccount.status, 200);
      assert.strictEqual((await signedRequest('GET', statsPath, rotated.json.apiKey, rotated.json.apiSecret)).status, 401, 'Unsuspending an account must not silently re-enable credentials');
      const explicitlyEnabled = await reseller.request('POST', `/api/v1/reseller/api-keys/${created.json.id}/enable`, {});
      assert.strictEqual(explicitlyEnabled.status, 200);
      assert.strictEqual((await signedRequest('GET', statsPath, rotated.json.apiKey, rotated.json.apiSecret)).status, 200);

      const ownedInstance = await ctx.db.get(`SELECT vm_id FROM vms WHERE owner_id = 1 ORDER BY vm_id LIMIT 1`);
      if (ownedInstance) {
        const instancePath = `/api/v1/reseller/vps/${ownedInstance.vm_id}?engine=kvm`;
        const isolated = await signedRequest('GET', instancePath, rotated.json.apiKey, rotated.json.apiSecret);
        assert.strictEqual(isolated.status, 404, 'Reseller must not read another owner’s VM');
      }

      const logRows = await ctx.db.get(`SELECT COUNT(*) AS count FROM reseller_api_requests WHERE api_key_id = ?`, [created.json.id]);
      assert.ok(logRows.count >= 5, 'Successful and failed HMAC requests should be logged');
      await reseller.request('DELETE', `/api/v1/reseller/api-keys/${created.json.id}`);
      await reseller.request('DELETE', `/api/v1/reseller/api-keys/${rateKey.json.id}`);
    });

    // 15. LXC Snapshots, SHA-256 Archive Backup + Clean Restore, 7-Stage Offline Migration (+ Rollback) & Local/Remote WebSocket PTY Console
    await runStep('T14: LXC snapshots, SHA-256 backup + clean restore, 7-stage offline migration + rollback & WebSocket PTY console', async () => {
      // 14a. LXC Snapshots (create, list, mutate, restore, limit enforcement, delete)
      await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/files/content`, {
        path: '/etc/app-version.txt',
        content: 'release-v1.0-stable\n',
      });
      const snapCreate = await adminClient.request(
        'POST',
        `/api/v1/snapshots/lxc/${e2eUbuntuId}`,
        { description: 'Before risky upgrade' }
      );
      assert.strictEqual(snapCreate.status, 201, `Snapshot create failed: ${snapCreate.text}`);
      const snapId = snapCreate.json.snapshot.id;

      await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/files/content`, {
        path: '/etc/app-version.txt',
        content: 'release-v2.0-broken\n',
      });
      const snapRestore = await adminClient.request(
        'POST',
        `/api/v1/snapshots/lxc/${e2eUbuntuId}/${snapId}/restore`,
        {}
      );
      assert.strictEqual(snapRestore.status, 200, `Snapshot restore failed: ${snapRestore.text}`);
      const revertedVer = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eUbuntuId}/files/content?path=/etc/app-version.txt`
      );
      assert.strictEqual(revertedVer.json.content.trim(), 'release-v1.0-stable');

      // Enforce snapshot_limit
      await ctx.db.run(`UPDATE lxc_instances SET snapshot_limit = 1 WHERE id = ?`, [e2eUbuntuId]);
      const overLimit = await adminClient.request(
        'POST',
        `/api/v1/snapshots/lxc/${e2eUbuntuId}`,
        { description: 'Should hit limit' }
      );
      assert.ok(overLimit.status >= 400 && /Snapshot limit reached/i.test(overLimit.json.error));
      const snapDel = await adminClient.request(
        'DELETE',
        `/api/v1/snapshots/lxc/${e2eUbuntuId}/${snapId}`
      );
      assert.strictEqual(snapDel.status, 200);

      // 14b. SHA-256 Archive Backup + Integrity Verify + Clean Rootfs Restore
      const bkpCreate = await adminClient.request('POST', '/api/v1/backups', {
        engine: 'lxc',
        refId: e2eUbuntuId,
        label: 'pre_mig_gold',
      });
      assert.strictEqual(bkpCreate.status, 201, `LXC backup failed: ${bkpCreate.text}`);
      const lxcBkpId = bkpCreate.json.backup.backupId;
      assert.strictEqual(bkpCreate.json.backup.checksumSha256.length, 64);

      // Phase 7: local LXC backup archives are encrypted at rest (AES-256-GCM).
      const { isEncryptedArchive } = require('../lib/services/backup/backup-crypto');
      const lxcBkpRow = await ctx.db.get(
        `SELECT encrypted, encryption_alg, file_path FROM container_backups WHERE id = ?`,
        [lxcBkpId]
      );
      assert.strictEqual(Number(lxcBkpRow.encrypted), 1, 'Local LXC backup must be marked encrypted');
      assert.strictEqual(lxcBkpRow.encryption_alg, 'aes-256-gcm');
      assert.ok(isEncryptedArchive(lxcBkpRow.file_path), 'Stored backup archive must be encrypted on disk');
      assert.ok(
        !fs.existsSync(lxcBkpRow.file_path.replace(/\.enc$/, '')),
        'Original plaintext archive must be removed after encryption'
      );

      // Direct crypto round-trip + tamper detection (AES-GCM authentication).
      const { encryptArchive, decryptArchive } = require('../lib/services/backup/backup-crypto');
      const rtStamp = Date.now();
      const rtPlain = path.join(tmpRoot, `bkp-rt-${rtStamp}.tar.gz`);
      const rtCipher = `${rtPlain}.enc`;
      const rtOut = path.join(tmpRoot, `bkp-rt-${rtStamp}-out.tar.gz`);
      const rtPayload = crypto.randomBytes(4096);
      fs.writeFileSync(rtPlain, rtPayload);
      encryptArchive(rtPlain);
      assert.ok(fs.existsSync(rtCipher), 'encryptArchive must write a .enc file');
      assert.ok(!fs.existsSync(rtPlain), 'encryptArchive must remove the plaintext');
      decryptArchive(rtCipher, rtOut);
      assert.ok(Buffer.compare(fs.readFileSync(rtOut), rtPayload) === 0, 'Decrypt must recover the original bytes');
      // Tamper with the ciphertext -> GCM tag verification must fail.
      const tampered = Buffer.from(fs.readFileSync(rtCipher));
      tampered[tampered.length - 1] ^= 0xff;
      fs.writeFileSync(rtCipher, tampered);
      let tamperCaught = false;
      try {
        decryptArchive(rtCipher, rtOut);
      } catch {
        tamperCaught = true;
      }
      assert.ok(tamperCaught, 'Tampered encrypted archive must fail to decrypt (AES-GCM tag mismatch)');

      const bkpVerify = await adminClient.request('POST', `/api/v1/backups/${lxcBkpId}/verify`, {});
      assert.strictEqual(bkpVerify.status, 200);
      assert.strictEqual(bkpVerify.json.valid, true);

      // Phase 9: restore rehearsal (dry-run) on the encrypted local backup — must
      // report restorable without performing the restore, and decrypt + inspect the archive.
      const bkpRehearse = await adminClient.request(
        'POST',
        `/api/v1/backups/${lxcBkpId}/rehearse`,
        {}
      );
      assert.strictEqual(bkpRehearse.status, 200, `Rehearsal failed: ${bkpRehearse.text}`);
      assert.strictEqual(bkpRehearse.json.restorable, true, `Backup should be restorable: ${bkpRehearse.text}`);
      assert.strictEqual(bkpRehearse.json.encrypted, true);
      assert.strictEqual(bkpRehearse.json.checksumValid, true);
      assert.strictEqual(bkpRehearse.json.archiveValid, true);
      assert.ok(bkpRehearse.json.entryCount > 0, 'Rehearsal must report archive entries');
      assert.ok(bkpRehearse.json.topLevelDir, 'Rehearsal must report the top-level container dir');

      // Phase 9 negative case: a tampered (corrupt) encrypted archive must fail rehearsal.
      const negBkpCreate = await adminClient.request('POST', '/api/v1/backups', {
        engine: 'lxc',
        refId: e2eUbuntuId,
        label: 'pre_mig_neg',
      });
      assert.strictEqual(negBkpCreate.status, 201, `Neg-case backup failed: ${negBkpCreate.text}`);
      const negBkpId = negBkpCreate.json.backup.backupId;
      const negBkpRow = await ctx.db.get(
        `SELECT file_path FROM container_backups WHERE id = ?`,
        [negBkpId]
      );
      const negEncBuf = Buffer.from(fs.readFileSync(negBkpRow.file_path));
      negEncBuf[negEncBuf.length - 1] ^= 0xff; // corrupt the ciphertext
      fs.writeFileSync(negBkpRow.file_path, negEncBuf);
      const negRehearse = await adminClient.request(
        'POST',
        `/api/v1/backups/${negBkpId}/rehearse`,
        {}
      );
      assert.strictEqual(negRehearse.status, 200, `Neg rehearsal failed: ${negRehearse.text}`);
      assert.strictEqual(negRehearse.json.restorable, false, 'Tampered archive must not be restorable');
      assert.strictEqual(negRehearse.json.checksumValid, false);
      await adminClient.request('DELETE', `/api/v1/backups/${negBkpId}`);

      // Phase 10: backup destination — copy the encrypted local backup to the remote
      // node (backup replication) and verify the copy's integrity + list it.
      const bkpCopy = await adminClient.request('POST', `/api/v1/backups/${lxcBkpId}/copy`, {
        targetNodeId: remoteNodeId,
      });
      assert.strictEqual(bkpCopy.status, 201, `Backup copy failed: ${bkpCopy.text}`);
      assert.strictEqual(bkpCopy.json.copy.backupId, lxcBkpId);
      assert.strictEqual(bkpCopy.json.copy.targetNodeId, remoteNodeId);
      assert.strictEqual(bkpCopy.json.copy.status, 'completed');
      assert.strictEqual(bkpCopy.json.copy.encrypted, true, 'Copy must preserve encryption');
      assert.strictEqual(
        bkpCopy.json.copy.checksumSha256,
        bkpCreate.json.backup.checksumSha256,
        'Copy checksum must match the source backup'
      );
      const bkpCopies = await adminClient.request('GET', `/api/v1/backups/${lxcBkpId}/copies`);
      assert.strictEqual(bkpCopies.status, 200);
      assert.ok(bkpCopies.json.copies.length >= 1, 'Copies list must include the new copy');
      assert.strictEqual(bkpCopies.json.copies[0].target_node_id, remoteNodeId);

      // Mutate existing file AND add post-backup junk file, then restore archive backup!
      await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/files/content`, {
        path: '/etc/app-version.txt',
        content: 'corrupted-state\n',
      });
      await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/files/content`, {
        path: '/etc/post-backup-stale.txt',
        content: 'should-be-wiped-on-restore\n',
      });

      const bkpRestore = await adminClient.request(
        'POST',
        `/api/v1/backups/${lxcBkpId}/restore`,
        {}
      );
      assert.strictEqual(bkpRestore.status, 200, `LXC backup restore failed: ${bkpRestore.text}`);
      assert.strictEqual(bkpRestore.json.restored, true);
      assert.strictEqual(bkpRestore.json.status, 'running');

      const afterBkpVer = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eUbuntuId}/files/content?path=/etc/app-version.txt`
      );
      assert.strictEqual(afterBkpVer.json.content.trim(), 'release-v1.0-stable');
      const staleCheck = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eUbuntuId}/files/content?path=/etc/post-backup-stale.txt`
      );
      assert.strictEqual(staleCheck.status, 400, 'Post-backup stale file must be wiped by clean restore');

      // Phase 20: restore from a recorded backup copy on the remote node — the panel
      // must download + decrypt + verify the encrypted copy, then restore from it.
      await adminClient.request('POST', `/api/v1/lxc/${e2eUbuntuId}/files/content`, {
        path: '/etc/app-version.txt',
        content: 'corrupted-again\n',
      });
      const copyRestore = await adminClient.request(
        'POST',
        `/api/v1/backups/${lxcBkpId}/restore`,
        { copyId: bkpCopy.json.copy.copyId }
      );
      assert.strictEqual(copyRestore.status, 200, `Restore from copy failed: ${copyRestore.text}`);
      assert.strictEqual(copyRestore.json.restored, true);
      assert.strictEqual(copyRestore.json.sourceCopyId, bkpCopy.json.copy.copyId);
      const copyAfterVer = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eUbuntuId}/files/content?path=/etc/app-version.txt`
      );
      assert.strictEqual(copyAfterVer.json.content.trim(), 'release-v1.0-stable', 'Restore from copy must recover the backed-up content');

      // Negative: a copy id that does not belong to this backup must be rejected.
      const badCopyRestore = await adminClient.request(
        'POST',
        `/api/v1/backups/${lxcBkpId}/restore`,
        { copyId: 999999 }
      );
      assert.strictEqual(badCopyRestore.status, 400, `Unknown copy must be rejected: ${badCopyRestore.text}`);
      assert.match(badCopyRestore.json.error, /copy not found/i);

      // 14c. Local WebSocket LXC PTY Console (/ws/lxc/:id/console) + Unauth Rejection
      await new Promise((resolve, reject) => {
        const unauthWs = new WebSocket(`ws://127.0.0.1:${TEST_PORT}/ws/lxc/${e2eCustomId}/console`);
        unauthWs.on('unexpected-response', (_req, res) => {
          assert.strictEqual(res.statusCode, 401);
          resolve();
        });
        unauthWs.on('open', () => reject(new Error('Unauthenticated LXC console WS must not open')));
        unauthWs.on('error', () => resolve());
      });

      const localConsoleOut = await new Promise((resolve, reject) => {
        let out = '';
        const ws = new WebSocket(
          `ws://127.0.0.1:${TEST_PORT}/ws/lxc/${e2eCustomId}/console?cols=110&rows=32`,
          { headers: { Cookie: adminClient.cookie } }
        );
        const timer = setTimeout(() => {
          ws.close();
          reject(new Error(`Timed out waiting for local LXC PTY output. Got: ${out}`));
        }, 6000);
        ws.on('open', () => {
          ws.send(JSON.stringify({ type: 'resize', cols: 120, rows: 36 }));
          setTimeout(() => {
            ws.send(
              JSON.stringify({
                type: 'input',
                data: 'echo LXC_LOCAL_PTY_$CONTAINER_NAME:$((19+23))\n',
              })
            );
          }, 200);
        });
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'output') {
              out += msg.data;
              if (out.includes('LXC_LOCAL_PTY_e2e-custom-02:42')) {
                clearTimeout(timer);
                ws.close();
                resolve(out);
              }
            }
          } catch (_) {}
        });
        ws.on('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });
      assert.ok(localConsoleOut.includes('LXC_LOCAL_PTY_e2e-custom-02:42'));

      // 14d. Reinstall LXC Container (#2 custom -> ubuntu:24.04)
      const reinstRes = await adminClient.request('POST', `/api/v1/lxc/${e2eCustomId}/reinstall`, {
        templateSlug: 'ubuntu:24.04',
      });
      assert.strictEqual(reinstRes.status, 200, `Reinstall failed: ${reinstRes.text}`);
      assert.strictEqual(reinstRes.json.instance.status, 'running');
      assert.ok(reinstRes.json.rootPassword.length >= 16);

      // 14e. 7-Stage Verified Offline Migration: First test automatic pre-commit ROLLBACK on target conflict!
      // Phase 8: duplicate-run fencing — an active migration must block a second one.
      // Tested at the manager level (not via HTTP) so it exercises the exact fencing guard
      // without adding a mutation request that would count against the shared rate limiter.
      const lxcRowForFence = await ctx.db.get(
        `SELECT node_id, container_name FROM lxc_instances WHERE id = ?`,
        [e2eUbuntuId]
      );
      await ctx.db.run(
        `INSERT INTO vps_migrations
           (lxc_id, instance_type, instance_ref_id, container_name, source_node_id, target_node_id,
            strategy, migration_mode, status, progress, initiated_by)
         VALUES (?, 'lxc', ?, ?, ?, ?, 'offline_snapshot_transfer', 'offline_snapshot', 'exporting', 25, 1)`,
        [e2eUbuntuId, e2eUbuntuId, lxcRowForFence.container_name, lxcRowForFence.node_id, remoteNodeId]
      );
      let fenceError = null;
      try {
        await ctx.migrationManager.startOfflineLxcMigration({
          lxcId: e2eUbuntuId,
          targetNodeId: remoteNodeId,
          initiatedByUserId: 1,
        });
      } catch (e) {
        fenceError = e.message;
      }
      assert.ok(fenceError, 'Expected fencing guard to reject a second active migration');
      assert.match(fenceError, /active migration/i, `Fencing error expected: ${fenceError}`);
      // Remove the injected active row so the real migration below can run.
      await ctx.db.run(`DELETE FROM vps_migrations WHERE lxc_id = ? AND status = 'exporting'`, [e2eUbuntuId]);

      const conflictDir = path.join(tmpRoot, 'agent-lxc', 'e2e-ubuntu-01');
      fs.mkdirSync(conflictDir, { recursive: true });
      fs.writeFileSync(path.join(conflictDir, 'config'), 'lxc.uts.name = e2e-ubuntu-01\n');

      const failedMig = await adminClient.request('POST', '/api/v1/migrations', {
        lxcId: e2eUbuntuId,
        targetNodeId: remoteNodeId,
      });
      assert.strictEqual(failedMig.status, 500, 'Expected migration conflict failure');
      assert.match(failedMig.json.error, /safely rolled back/i);

      const migJobsAfterRollback = await adminClient.request('GET', '/api/v1/migrations');
      assert.strictEqual(migJobsAfterRollback.json.migrations[0].status, 'rolled_back');
      assert.strictEqual(migJobsAfterRollback.json.migrations[0].rollback_performed, 1);

      // Verify source container on localhost is STILL running and intact after rollback!
      const postRollbackTel = await adminClient.request(
        'GET',
        `/api/v1/instances/lxc/${e2eUbuntuId}/telemetry`
      );
      assert.strictEqual(postRollbackTel.json.telemetry.status, 'running');
      fs.rmSync(conflictDir, { recursive: true, force: true });

      // Now execute full 7-stage verified offline migration (localhost -> local-loopback-agent)!
      const okMig = await adminClient.request('POST', '/api/v1/migrations', {
        lxcId: e2eUbuntuId,
        targetNodeId: remoteNodeId,
        targetBridge: 'lxcbr0',
        targetIpv4: '10.88.20.50/24',
        targetGateway: '10.88.20.1',
      });
      assert.strictEqual(okMig.status, 201, `Offline migration failed: ${okMig.text}`);
      assert.strictEqual(okMig.json.migration.status, 'completed');
      assert.strictEqual(okMig.json.migration.progress, 100);
      assert.strictEqual(okMig.json.migration.checksum_sha256.length, 64);

      assert.ok(
        !fs.existsSync(path.join(process.env.TGVPANEL_LXC_PATH, 'e2e-ubuntu-01')),
        'Source container cleaned up after verified target cutover'
      );
      assert.ok(
        fs.existsSync(path.join(tmpRoot, 'agent-lxc', 'e2e-ubuntu-01', 'config')),
        'Target container active on remote Node Agent'
      );

      // Verify remote Node Agent file read, remote backup + SHA-256 verify + restore, remote reinstall & remote proxied WebSocket PTY console!
      const remoteFile = await adminClient.request(
        'GET',
        `/api/v1/lxc/${e2eUbuntuId}/files/content?path=/etc/app-version.txt`
      );
      assert.strictEqual(remoteFile.status, 200);
      assert.strictEqual(remoteFile.json.content.trim(), 'release-v1.0-stable');

      const remoteBkp = await adminClient.request('POST', '/api/v1/backups', {
        engine: 'lxc',
        refId: e2eUbuntuId,
        label: 'remote_agent_bkp',
      });
      assert.strictEqual(remoteBkp.status, 201, `Remote node backup failed: ${remoteBkp.text}`);
      const remoteBkpId = remoteBkp.json.backup.backupId;

      const remoteBkpVer = await adminClient.request(
        'POST',
        `/api/v1/backups/${remoteBkpId}/verify`,
        {}
      );
      assert.strictEqual(remoteBkpVer.status, 200);
      assert.strictEqual(remoteBkpVer.json.valid, true);

      const remoteBkpRestore = await adminClient.request(
        'POST',
        `/api/v1/backups/${remoteBkpId}/restore`,
        {}
      );
      assert.strictEqual(remoteBkpRestore.status, 200, `Remote restore failed: ${remoteBkpRestore.text}`);
      assert.strictEqual(remoteBkpRestore.json.status, 'running');

      // Remote Node Agent proxied WebSocket LXC PTY Console (testing early buffered frames on CONNECTING!)
      const remoteConsoleOut = await new Promise((resolve, reject) => {
        let out = '';
        const ws = new WebSocket(
          `ws://127.0.0.1:${TEST_PORT}/ws/lxc/${e2eUbuntuId}/console?cols=100&rows=30`,
          { headers: { Cookie: adminClient.cookie } }
        );
        const timer = setTimeout(() => {
          ws.close();
          reject(new Error(`Timed out waiting for remote proxied LXC PTY output. Got: ${out}`));
        }, 6000);
        ws.on('open', () => {
          // Immediately send input frame to exercise bridgeWebSockets CONNECTING queue!
          ws.send(
            JSON.stringify({
              type: 'input',
              data: 'echo REMOTE_AGENT_PTY_$CONTAINER_NAME:$((50+49))\n',
            })
          );
        });
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'output') {
              out += msg.data;
              if (out.includes('REMOTE_AGENT_PTY_e2e-ubuntu-01:99')) {
                clearTimeout(timer);
                ws.close();
                resolve(out);
              }
            }
          } catch (_) {}
        });
        ws.on('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });
      assert.ok(remoteConsoleOut.includes('REMOTE_AGENT_PTY_e2e-ubuntu-01:99'));

      // Remote Node Agent Reinstall -> must preserve 'running' state cleanly
      const remoteReinst = await adminClient.request(
        'POST',
        `/api/v1/lxc/${e2eUbuntuId}/reinstall`,
        { templateSlug: 'ubuntu:24.04' }
      );
      assert.strictEqual(remoteReinst.status, 200, `Remote reinstall failed: ${remoteReinst.text}`);
      assert.strictEqual(
        remoteReinst.json.instance.status,
        'running',
        'Remote reinstalled container must accurately report running status'
      );

      // Cleanly delete backups & all E2E LXC containers via API and verify DB + disk cleanup
      await adminClient.request('DELETE', `/api/v1/backups/${lxcBkpId}`);
      await adminClient.request('DELETE', `/api/v1/backups/${remoteBkpId}`);
      for (const id of [e2eUbuntuId, e2eCustomId, e2eOrphanId]) {
        const del = await adminClient.request('POST', `/api/v1/instances/lxc/${id}/action`, {
          action: 'delete',
        });
        assert.strictEqual(del.status, 200, `Delete LXC #${id} failed: ${del.text}`);
        const gone = await ctx.db.get(`SELECT id FROM lxc_instances WHERE id = ?`, [id]);
        assert.strictEqual(gone, undefined);
      }
      const extRow = await ctx.db.get(`SELECT id FROM lxc_instances WHERE container_name = 'ext-host-ct-04'`);
      if (extRow) {
        await adminClient.request('POST', `/api/v1/instances/lxc/${extRow.id}/action`, {
          action: 'delete',
        });
      }
    });

    // 15. KVM Nesting (/dev/kvm passthrough), WSL2 /proc telemetry fallback & redesigned LXC Detail Control Center
    // Phase 21: deleting a backup must clean up its recorded copies (rows +
    // files on their target nodes) so nothing is orphaned behind the deletion.
    await runStep('T36: Deleting a backup removes its copies (rows and node files)', async () => {
      const vm = await ctx.db.get(`SELECT vm_id FROM vms LIMIT 1`);
      assert.ok(vm, 'A KVM VM is required for the backup-deletion cleanup test');
      const dummyDisk = path.join(tmpRoot, `t36-disk-${vm.vm_id}.qcow2`);
      fs.writeFileSync(dummyDisk, crypto.randomBytes(65536));
      const savedDisk = (await ctx.db.get(`SELECT disk_file FROM vms WHERE vm_id = ?`, [vm.vm_id]))?.disk_file;
      await ctx.db.run(`UPDATE vms SET disk_file = ? WHERE vm_id = ?`, [dummyDisk, vm.vm_id]);

      try {
        const bkRes = await adminClient.request('POST', '/api/v1/backups', {
          engine: 'kvm',
          refId: vm.vm_id,
        });
        assert.strictEqual(bkRes.status, 201, `Backup creation failed: ${bkRes.text}`);
        const bkId = bkRes.json.backup.backupId || bkRes.json.backup.id;
        const backupFilePath = bkRes.json.backup.filePath;
        assert.ok(backupFilePath, 'Backup response must include the archive file path');

        const copyRes = await adminClient.request('POST', `/api/v1/backups/${bkId}/copy`, {
          targetNodeId: remoteNodeId,
        });
        assert.strictEqual(copyRes.status, 201, `Backup copy failed: ${copyRes.text}`);
        const copyId = copyRes.json.copy.copyId;
        const copyFilePath = copyRes.json.copy.filePath;
        assert.ok(copyFilePath, 'Copy response must include the copy file path');
        assert.ok(fs.existsSync(copyFilePath), 'Copy file must exist on the target node before deletion');

        const delRes = await adminClient.request(
          'DELETE',
          `/api/v1/backups/${bkId}`,
          {},
          { 'X-Forwarded-For': '198.51.100.53' }
        );
        assert.strictEqual(delRes.status, 200, `Backup deletion failed: ${delRes.text}`);

        const bkRow = await ctx.db.get(`SELECT id FROM container_backups WHERE id = ?`, [bkId]);
        assert.strictEqual(bkRow, undefined, 'Deleted backup row must be removed');
        assert.ok(!fs.existsSync(backupFilePath), 'Deleted backup archive file must be removed');

        const copyRow = await ctx.db.get(`SELECT id FROM backup_copies WHERE id = ?`, [copyId]);
        assert.strictEqual(copyRow, undefined, 'Copy row must be removed with its backup');
        assert.ok(!fs.existsSync(copyFilePath), 'Copy file must be removed from the target node');
      } finally {
        await ctx.db.run(`UPDATE vms SET disk_file = ? WHERE vm_id = ?`, [savedDisk, vm.vm_id]);
        try { fs.unlinkSync(dummyDisk); } catch { /* best effort */ }
      }
    });

    // Phase 22: webhook delivery retries — a failing delivery is retried with
    // bounded attempts + backoff, and the outcome (status, error, failure count)
    // is recorded honestly on the webhook row.
    await runStep('T37: Webhook deliveries retry with backoff and record honest delivery status', async () => {
      // Local hook receiver: fails (500) the first two attempts, then succeeds.
      let requestCount = 0;
      let capturedBody = '';
      let capturedSignature = '';
      const hookServer = http.createServer((req, res) => {
        requestCount += 1;
        let body = '';
        req.on('data', (c) => { body += c; });
        req.on('end', () => {
          capturedBody = body;
          capturedSignature = String(req.headers['x-hkvm-signature-256'] || '');
          if (requestCount <= 2) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end('{"error":"temporary"}');
          } else {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end('{"ok":true}');
          }
        });
      });
      await new Promise((resolve) => hookServer.listen(0, '127.0.0.1', resolve));
      const hookPort = hookServer.address().port;

      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

      try {
        const whRes = await adminClient.request('POST', '/api/v1/webhooks', {
          name: 't37-retry-hook',
          url: `http://127.0.0.1:${hookPort}/hook`,
          events: ['test.retry'],
          secret: 't37-signing-secret',
        });
        assert.strictEqual(whRes.status, 201, `Webhook creation failed: ${whRes.text}`);
        const retryHookId = whRes.json.id;

        // Unreachable receiver: connection refused on every attempt.
        const badWhRes = await adminClient.request('POST', '/api/v1/webhooks', {
          name: 't37-failing-hook',
          url: 'http://127.0.0.1:1/hook',
          events: ['test.retry'],
          secret: 't37-signing-secret',
        });
        assert.strictEqual(badWhRes.status, 201, `Webhook creation failed: ${badWhRes.text}`);
        const badHookId = badWhRes.json.id;

        await ctx.monitoringService.dispatchWebhookEvent('test.retry', { hello: 'world' });

        // Wait for both delivery chains (2s + 4s backoff) to settle.
        let retryRow = null;
        let badRow = null;
        for (let i = 0; i < 40; i += 1) {
          await sleep(500);
          retryRow = await ctx.db.get(`SELECT last_status_code, last_error, failure_count FROM webhooks WHERE id = ?`, [retryHookId]);
          badRow = await ctx.db.get(`SELECT last_status_code, last_error, failure_count FROM webhooks WHERE id = ?`, [badHookId]);
          if (retryRow?.last_status_code === 200 && badRow?.failure_count >= 3) break;
        }

        assert.strictEqual(requestCount, 3, 'Receiver must see the initial attempt plus two retries');
        assert.strictEqual(retryRow?.last_status_code, 200, 'Webhook must succeed after retries');
        assert.strictEqual(retryRow?.last_error, null, 'last_error must be cleared on success');
        assert.strictEqual(retryRow?.failure_count, 0, 'failure_count must reset on success');
        const expectedSig = `sha256=${crypto.createHmac('sha256', 't37-signing-secret').update(capturedBody).digest('hex')}`;
        assert.strictEqual(capturedSignature, expectedSig, 'Retried delivery must carry the valid HMAC signature');

        assert.strictEqual(badRow?.last_status_code, 0, 'Unreachable webhook must record a zero status code');
        assert.ok(badRow?.last_error, 'Unreachable webhook must record the failure reason');
        assert.strictEqual(badRow?.failure_count, 3, 'Unreachable webhook must stop after the bounded attempt count');
      } finally {
        await new Promise((resolve) => hookServer.close(() => resolve()));
        await ctx.db.run(`DELETE FROM webhooks WHERE name IN ('t37-retry-hook', 't37-failing-hook')`);
      }
    });

    // Phase 23: VPS expiration sweeper — expired LXC instances with
    // auto-suspend enabled are suspended through the normal lifecycle path,
    // warned_at is stamped, and owners receive an in-panel notification.
    await runStep('T38: Expiration sweeper suspends expired LXC VPSes and notifies owners', async () => {
      // Provision a dedicated local LXC instance for the sweep (T14's migration
      // removes the shared e2e containers before this point).
      const createRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 't38-expiry-ctr',
        hostname: 't38-expiry-ctr.hkvm.local',
        templateSlug: 'ubuntu:24.04',
        nodeId: 1,
        cpuCores: 1,
        ramMb: 512,
        diskGb: 5,
        bridge: 'lxcbr0',
        ipv4Address: '10.88.10.99/24',
        ipv4Gateway: '10.88.10.1',
        autostart: true,
        nesting: true,
        provisionOnHost: true,
      });
      assert.strictEqual(createRes.status, 201, `LXC provisioning failed: ${createRes.text}`);
      const lxcId = createRes.json.instance.refId;
      const lxcOwner = (await ctx.db.get(`SELECT user_id FROM lxc_instances WHERE id = ?`, [lxcId])).user_id;
      assert.strictEqual(createRes.json.instance.status, 'running');

      // Host container operations are stubbed so the sweep's host-verified
      // suspension is deterministic (same pattern as the T34 clone mocks).
      const cm = ctx.nodeManager.localRuntime.containerManager;
      const origStop = cm.stopContainer;
      const origInspect = cm.inspectContainer;
      cm.stopContainer = async () => {};
      cm.inspectContainer = async () => ({ state: 'stopped' });

      try {
        await ctx.db.run(
          `INSERT INTO vps_expiration (lxc_id, expires_at, expiration_days, auto_suspend_enabled)
           VALUES (?, datetime('now', '-1 day'), 30, 0)`,
          [lxcId]
        );

        // Negative first: auto-suspend disabled must leave the instance untouched.
        const sweepOff = await adminClient.request(
          'POST',
          '/api/v1/lxc/expirations/sweep',
          {},
          { 'X-Forwarded-For': '198.51.100.54' }
        );
        assert.strictEqual(sweepOff.status, 200, `Sweep failed: ${sweepOff.text}`);
        assert.strictEqual(sweepOff.json.evaluated, 0, 'Disabled auto-suspend must not be evaluated');
        const notSuspended = await ctx.db.get(`SELECT suspended FROM lxc_instances WHERE id = ?`, [lxcId]);
        assert.strictEqual(Number(notSuspended.suspended), 0, 'Instance must remain unsuspended');

        // Enable auto-suspend and sweep again — the instance must be suspended.
        await ctx.db.run(`UPDATE vps_expiration SET auto_suspend_enabled = 1 WHERE lxc_id = ?`, [lxcId]);
        const sweepOn = await adminClient.request(
          'POST',
          '/api/v1/lxc/expirations/sweep',
          {},
          { 'X-Forwarded-For': '198.51.100.55' }
        );
        assert.strictEqual(sweepOn.status, 200, `Sweep failed: ${sweepOn.text}`);
        assert.strictEqual(sweepOn.json.evaluated, 1, 'Expired instance must be evaluated');
        assert.strictEqual(sweepOn.json.suspended.length, 1, 'Expired instance must be suspended');
        assert.strictEqual(sweepOn.json.suspended[0].lxcId, lxcId);
        assert.strictEqual(sweepOn.json.suspended[0].ownerUserId, lxcOwner);

        const suspendedRow = await ctx.db.get(
          `SELECT suspended, suspended_reason, status FROM lxc_instances WHERE id = ?`,
          [lxcId]
        );
        assert.strictEqual(Number(suspendedRow.suspended), 1, 'Instance must be marked suspended');
        assert.match(suspendedRow.suspended_reason, /VPS expired/i, 'Suspension reason must record expiry');
        assert.strictEqual(suspendedRow.status, 'stopped', 'Suspended instance status must be stopped');

        const expRow = await ctx.db.get(`SELECT warned_at FROM vps_expiration WHERE lxc_id = ?`, [lxcId]);
        assert.ok(expRow.warned_at, 'warned_at must be stamped on evaluation');

        const notification = await ctx.db.get(
          `SELECT type, title FROM notifications WHERE user_id = ? AND type = 'warning' ORDER BY id DESC LIMIT 1`,
          [lxcOwner]
        );
        assert.ok(notification, 'Owner must receive an in-panel expiration notification');
        assert.match(notification.title, /expired and suspended/i);
      } finally {
        cm.stopContainer = origStop;
        cm.inspectContainer = origInspect;
        await ctx.db.run(`DELETE FROM vps_expiration WHERE lxc_id = ?`, [lxcId]);
        await ctx.db.run(`DELETE FROM notifications WHERE user_id = ? AND title LIKE 'VPS expired%'`, [lxcOwner]);
        await ctx.db.run(`DELETE FROM instances WHERE engine = 'lxc' AND ref_id = ?`, [lxcId]).catch(() => undefined);
        await ctx.db.run(`DELETE FROM lxc_instances WHERE id = ?`, [lxcId]).catch(() => undefined);
      }
    });

    // Phase 24: Per-VPS firewall policy — rules scoped to an instance are
    // enforced against that instance's concrete IPs (local iptables or the
    // node agent), with honest applied reporting and validation.
    await runStep('T39: Per-VPS firewall rules are instance-scoped, validated and enforced', async () => {
      // Provision a dedicated local LXC instance to scope rules against.
      const createRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 't39-fw-ctr',
        hostname: 't39-fw-ctr.hkvm.local',
        templateSlug: 'ubuntu:24.04',
        nodeId: 1,
        cpuCores: 1,
        ramMb: 512,
        diskGb: 5,
        bridge: 'lxcbr0',
        ipv4Address: '10.88.10.98/24',
        ipv4Gateway: '10.88.10.1',
        autostart: true,
        nesting: true,
        provisionOnHost: true,
      });
      assert.strictEqual(createRes.status, 201, `LXC provisioning failed: ${createRes.text}`);
      const lxcId = createRes.json.instance.refId;

      try {
        // Create a per-VPS ingress rule scoped to the instance.
        const ruleRes = await adminClient.request(
          'POST',
          `/api/v1/instances/lxc/${lxcId}/firewall-rules`,
          { direction: 'in', action: 'ACCEPT', protocol: 'tcp', destPort: '443', sourceCidr: '0.0.0.0/0', comment: 'Allow HTTPS' },
          { 'X-Forwarded-For': '198.51.100.56' }
        );
        assert.strictEqual(ruleRes.status, 201, `Per-VPS rule failed: ${ruleRes.text}`);
        const rule = ruleRes.json.rule;
        assert.strictEqual(rule.instance_type, 'lxc', 'Rule must be scoped to the lxc instance');
        assert.strictEqual(rule.instance_ref_id, lxcId, 'Rule must reference the instance id');
        assert.strictEqual(typeof rule.applied, 'boolean', 'Enforcement result must be reported honestly');

        // Per-instance listing and the global listing both surface the rule.
        const instRules = await adminClient.request('GET', `/api/v1/instances/lxc/${lxcId}/firewall-rules`);
        assert.strictEqual(instRules.status, 200, `Instance rule listing failed: ${instRules.text}`);
        assert.ok(instRules.json.rules.some((r) => r.id === rule.id), 'Rule must appear in per-instance listing');
        const allRules = await adminClient.request('GET', '/api/v1/network/firewall');
        assert.strictEqual(allRules.status, 200, `Global rule listing failed: ${allRules.text}`);
        assert.ok(allRules.json.rules.some((r) => r.id === rule.id), 'Rule must appear in global listing');

        // Honest validation: unknown instance and invalid engine are rejected.
        const badInstance = await adminClient.request(
          'POST',
          '/api/v1/instances/lxc/999999/firewall-rules',
          { direction: 'in', action: 'ACCEPT', protocol: 'all' },
          { 'X-Forwarded-For': '198.51.100.57' }
        );
        assert.strictEqual(badInstance.status, 400, `Unknown instance must be rejected: ${badInstance.text}`);
        const badEngine = await adminClient.request(
          'POST',
          '/api/v1/instances/xyz/1/firewall-rules',
          { direction: 'in', action: 'ACCEPT', protocol: 'all' },
          { 'X-Forwarded-For': '198.51.100.58' }
        );
        assert.strictEqual(badEngine.status, 400, `Invalid engine must be rejected: ${badEngine.text}`);

        // The node agent enforces instance-scoped rules per concrete IP and
        // rejects invalid IPs before touching iptables.
        const agentFw = (body) =>
          new Promise((resolve, reject) => {
            const data = JSON.stringify(body);
            const signed = signAgentRequest({
              nodeId: 'local-loopback-agent',
              apiKey: agentApiKey,
              hmacSecret: agentHmacSecret,
              method: 'POST',
              pathWithQuery: '/api/v1/network/firewall',
              bodyBuffer: data,
            });
            const r = http.request(
              {
                hostname: '127.0.0.1',
                port: AGENT_PORT,
                path: '/api/v1/network/firewall',
                method: 'POST',
                headers: { ...signed, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
              },
              (res) => {
                let txt = '';
                res.on('data', (c) => (txt += c));
                res.on('end', () => resolve({ status: res.statusCode, text: txt }));
              }
            );
            r.on('error', reject);
            r.end(data);
          });
        const badIp = await agentFw({ mode: 'add', direction: 'in', action: 'ACCEPT', protocol: 'tcp', instanceIps: ['not-an-ip'] });
        assert.strictEqual(badIp.status, 400, `Agent must reject invalid instance IPs: ${badIp.text}`);
        const goodIp = await agentFw({ mode: 'add', direction: 'in', action: 'ACCEPT', protocol: 'tcp', destPort: '8443', instanceIps: ['10.88.10.98'] });
        assert.strictEqual(goodIp.status, 200, `Agent must accept valid instance IPs: ${goodIp.text}`);
        const goodIpJson = JSON.parse(goodIp.text);
        assert.strictEqual(typeof goodIpJson.applied, 'boolean', 'Agent must report applied honestly');

        // Delete the rule and confirm it disappears from both listings.
        const delRes = await adminClient.request('DELETE', `/api/v1/network/firewall/${rule.id}`, undefined, { 'X-Forwarded-For': '198.51.100.59' });
        assert.strictEqual(delRes.status, 200, `Rule deletion failed: ${delRes.text}`);
        const afterDel = await adminClient.request('GET', `/api/v1/instances/lxc/${lxcId}/firewall-rules`);
        assert.strictEqual(afterDel.status, 200, `Instance rule listing failed after delete: ${afterDel.text}`);
        assert.ok(!afterDel.json.rules.some((r) => r.id === rule.id), 'Deleted rule must not appear in listing');
      } finally {
        await ctx.db.run(`DELETE FROM instances WHERE engine = 'lxc' AND ref_id = ?`, [lxcId]).catch(() => undefined);
        await ctx.db.run(`DELETE FROM lxc_instances WHERE id = ?`, [lxcId]).catch(() => undefined);
        await ctx.db.run(`DELETE FROM firewall_rules WHERE instance_type = 'lxc' AND instance_ref_id = ?`, [lxcId]).catch(() => undefined);
      }
    });

    // Phase 25: Reusable per-VPS firewall rule profiles — profiles hold an
    // ordered rule set; applying a profile to an instance materializes
    // instance-scoped firewall_rules rows enforced via the Phase 24 path.
    await runStep('T40: Reusable VPS firewall profiles create, validate, apply and cascade', async () => {
      // Create a profile with two rules.
      const createRes = await adminClient.request(
        'POST',
        '/api/v1/network/firewall-profiles',
        {
          name: 't40-web-standard',
          description: 'Standard web VPS policy',
          rules: [
            { direction: 'in', action: 'ACCEPT', protocol: 'tcp', destPort: '80', sourceCidr: '0.0.0.0/0' },
            { direction: 'in', action: 'ACCEPT', protocol: 'tcp', destPort: '443', sourceCidr: '0.0.0.0/0' },
          ],
        },
        { 'X-Forwarded-For': '198.51.100.60' }
      );
      assert.strictEqual(createRes.status, 201, `Profile creation failed: ${createRes.text}`);
      const profile = createRes.json.profile;
      assert.ok(profile.id, 'Profile must have an id');
      assert.strictEqual(profile.rules.length, 2, 'Profile must persist both rules');

      // Listing and detail expose the profile.
      const listRes = await adminClient.request('GET', '/api/v1/network/firewall-profiles');
      assert.strictEqual(listRes.status, 200, `Profile listing failed: ${listRes.text}`);
      const listed = listRes.json.profiles.find((p) => p.id === profile.id);
      assert.ok(listed, 'Profile must appear in listing');
      assert.strictEqual(Number(listed.rule_count), 2, 'Listing must report rule count');
      const detailRes = await adminClient.request('GET', `/api/v1/network/firewall-profiles/${profile.id}`);
      assert.strictEqual(detailRes.status, 200, `Profile detail failed: ${detailRes.text}`);
      assert.strictEqual(detailRes.json.profile.rules.length, 2, 'Detail must include rules');

      // Validation: invalid rule input is rejected.
      const badProfile = await adminClient.request(
        'POST',
        '/api/v1/network/firewall-profiles',
        { name: 't40-bad', rules: [{ direction: 'sideways', action: 'ACCEPT', protocol: 'tcp' }] },
        { 'X-Forwarded-For': '198.51.100.61' }
      );
      assert.strictEqual(badProfile.status, 400, `Invalid profile rule must be rejected: ${badProfile.text}`);

      // Provision a local LXC to apply the profile to.
      const lxcCreate = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 't40-fwprof-ctr',
        hostname: 't40-fwprof-ctr.hkvm.local',
        templateSlug: 'ubuntu:24.04',
        nodeId: 1,
        cpuCores: 1,
        ramMb: 512,
        diskGb: 5,
        bridge: 'lxcbr0',
        ipv4Address: '10.88.10.97/24',
        ipv4Gateway: '10.88.10.1',
        autostart: true,
        nesting: true,
        provisionOnHost: true,
      });
      assert.strictEqual(lxcCreate.status, 201, `LXC provisioning failed: ${lxcCreate.text}`);
      const lxcId = lxcCreate.json.instance.refId;

      try {
        // Apply the profile — both rules materialize as instance-scoped rules.
        const applyRes = await adminClient.request(
          'POST',
          `/api/v1/network/firewall-profiles/${profile.id}/apply`,
          { instanceType: 'lxc', instanceRefId: lxcId },
          { 'X-Forwarded-For': '198.51.100.62' }
        );
        assert.strictEqual(applyRes.status, 200, `Profile apply failed: ${applyRes.text}`);
        assert.strictEqual(applyRes.json.created.length, 2, 'Both profile rules must be materialized');
        for (const created of applyRes.json.created) {
          assert.ok(Number.isInteger(created.ruleId), 'Each applied rule must have a rule id');
          assert.strictEqual(typeof created.applied, 'boolean', 'Enforcement result must be reported honestly');
        }
        const scopedRows = await ctx.db.all(
          `SELECT id, instance_type, instance_ref_id, direction, action FROM firewall_rules
           WHERE instance_type = 'lxc' AND instance_ref_id = ? ORDER BY id`,
          [lxcId]
        );
        assert.strictEqual(scopedRows.length, 2, 'Instance must hold the two materialized rules');
        assert.ok(scopedRows.every((r) => r.instance_type === 'lxc' && r.instance_ref_id === lxcId), 'Rules must be instance-scoped');

        // Honest validation: unknown instance and unknown profile are rejected.
        const badApply = await adminClient.request(
          'POST',
          `/api/v1/network/firewall-profiles/${profile.id}/apply`,
          { instanceType: 'lxc', instanceRefId: 999999 },
          { 'X-Forwarded-For': '198.51.100.63' }
        );
        assert.strictEqual(badApply.status, 400, `Apply to unknown instance must be rejected: ${badApply.text}`);
        const badProfileApply = await adminClient.request(
          'POST',
          '/api/v1/network/firewall-profiles/999999/apply',
          { instanceType: 'lxc', instanceRefId: lxcId },
          { 'X-Forwarded-For': '198.51.100.64' }
        );
        assert.strictEqual(badProfileApply.status, 400, `Apply of unknown profile must be rejected: ${badProfileApply.text}`);

        // Deleting the profile cascades to its rule definitions.
        const delRes = await adminClient.request(
          'DELETE',
          `/api/v1/network/firewall-profiles/${profile.id}`,
          undefined,
          { 'X-Forwarded-For': '198.51.100.65' }
        );
        assert.strictEqual(delRes.status, 200, `Profile deletion failed: ${delRes.text}`);
        const afterDel = await adminClient.request('GET', '/api/v1/network/firewall-profiles');
        assert.strictEqual(afterDel.status, 200, `Profile listing failed after delete: ${afterDel.text}`);
        assert.ok(!afterDel.json.profiles.some((p) => p.id === profile.id), 'Deleted profile must not appear');
        const orphanRules = await ctx.db.all(`SELECT id FROM firewall_profile_rules WHERE profile_id = ?`, [profile.id]);
        assert.strictEqual(orphanRules.length, 0, 'Profile rules must cascade on delete');
        // Materialized instance rules from the deleted profile remain enforced
        // until explicitly removed (they are live host policy, not profile data).
        const stillScoped = await ctx.db.all(
          `SELECT id FROM firewall_rules WHERE instance_type = 'lxc' AND instance_ref_id = ?`,
          [lxcId]
        );
        assert.strictEqual(stillScoped.length, 2, 'Materialized rules must persist after profile deletion');
      } finally {
        await ctx.db.run(`DELETE FROM firewall_rules WHERE instance_type = 'lxc' AND instance_ref_id = ?`, [lxcId]).catch(() => undefined);
        await ctx.db.run(`DELETE FROM instances WHERE engine = 'lxc' AND ref_id = ?`, [lxcId]).catch(() => undefined);
        await ctx.db.run(`DELETE FROM lxc_instances WHERE id = ?`, [lxcId]).catch(() => undefined);
        await ctx.db.run(`DELETE FROM firewall_profile_rules WHERE profile_id = ?`, [profile.id]).catch(() => undefined);
        await ctx.db.run(`DELETE FROM firewall_profiles WHERE id = ?`, [profile.id]).catch(() => undefined);
      }
    });

    // Phase 26: Per-instance bandwidth accounting — a cumulative traffic
    // ledger fed by real telemetry counters (baseline first sample, delta
    // accumulation, honest skips) exposed via API with measured period usage.
    await runStep('T41: Per-instance bandwidth accounting ledger, API and honest period usage', async () => {
      const lxcCreate = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 't41-traffic-ctr',
        hostname: 't41-traffic-ctr.hkvm.local',
        templateSlug: 'ubuntu:24.04',
        nodeId: 1,
        cpuCores: 1,
        ramMb: 512,
        diskGb: 5,
        bridge: 'lxcbr0',
        ipv4Address: '10.88.10.96/24',
        ipv4Gateway: '10.88.10.1',
        autostart: true,
        nesting: true,
        provisionOnHost: true,
      });
      assert.strictEqual(lxcCreate.status, 201, `LXC provisioning failed: ${lxcCreate.text}`);
      const lxcId = lxcCreate.json.instance.refId;

      // Deterministic telemetry: controlled counters for our instance, skip
      // every other instance (their telemetry collection is not under test).
      const im = ctx.instanceManager;
      const origCollect = im.collectInstanceTelemetry;
      let counters = { rx: 1000, tx: 500 };
      im.collectInstanceTelemetry = async (engine, refId) => {
        if (engine === 'lxc' && Number(refId) === lxcId) {
          return { netRxBytes: counters.rx, netTxBytes: counters.tx };
        }
        throw new Error('not under test');
      };

      try {
        // First accumulation establishes the baseline: no usage counted yet.
        const acc1 = await ctx.monitoringService.accumulateInstanceTraffic();
        assert.ok(acc1.sampled >= 1, 'At least the test instance must be sampled');
        const ledger1 = await ctx.db.get(
          `SELECT rx_bytes, tx_bytes, last_rx_bytes, last_tx_bytes FROM instance_traffic
           WHERE instance_type = 'lxc' AND instance_id = ?`,
          [lxcId]
        );
        assert.ok(ledger1, 'Ledger row must exist after accumulation');
        assert.strictEqual(Number(ledger1.rx_bytes), 0, 'First sample must be a baseline (no usage counted)');
        assert.strictEqual(Number(ledger1.tx_bytes), 0, 'First sample must be a baseline (no usage counted)');
        assert.strictEqual(Number(ledger1.last_rx_bytes), 1000, 'Baseline must record the counter reading');

        // Second accumulation with increased counters adds only the delta.
        counters = { rx: 1500, tx: 800 };
        await ctx.monitoringService.accumulateInstanceTraffic();
        const ledger2 = await ctx.db.get(
          `SELECT rx_bytes, tx_bytes FROM instance_traffic WHERE instance_type = 'lxc' AND instance_id = ?`,
          [lxcId]
        );
        assert.strictEqual(Number(ledger2.rx_bytes), 500, 'Ledger must accumulate the rx delta');
        assert.strictEqual(Number(ledger2.tx_bytes), 300, 'Ledger must accumulate the tx delta');

        // Counter reset (lower reading) must not reduce the ledger.
        counters = { rx: 100, tx: 50 };
        await ctx.monitoringService.accumulateInstanceTraffic();
        const ledger3 = await ctx.db.get(
          `SELECT rx_bytes, tx_bytes FROM instance_traffic WHERE instance_type = 'lxc' AND instance_id = ?`,
          [lxcId]
        );
        assert.strictEqual(Number(ledger3.rx_bytes), 500, 'Counter reset must not reduce cumulative rx');
        assert.strictEqual(Number(ledger3.tx_bytes), 300, 'Counter reset must not reduce cumulative tx');

        // Seed real metrics_history samples and verify the API reports honest
        // cumulative totals plus measured period usage from sample deltas.
        await ctx.db.run(
          `INSERT INTO metrics_history
             (target_type, target_id, cpu_percent, ram_used_mb, ram_total_mb, disk_used_gb, disk_total_gb, net_rx_bytes, net_tx_bytes, load_avg_1)
           VALUES ('lxc', ?, 1, 1, 1, 1, 1, 200, 100, 0),
                  ('lxc', ?, 1, 1, 1, 1, 1, 500, 260, 0)`,
          [lxcId, lxcId]
        );
        const trafficRes = await adminClient.request('GET', `/api/v1/instances/lxc/${lxcId}/traffic`);
        assert.strictEqual(trafficRes.status, 200, `Traffic API failed: ${trafficRes.text}`);
        const traffic = trafficRes.json.traffic;
        assert.strictEqual(Number(traffic.rxBytes), 500, 'API must report cumulative rx from the ledger');
        assert.strictEqual(Number(traffic.txBytes), 300, 'API must report cumulative tx from the ledger');
        assert.strictEqual(Number(traffic.periodRxBytes), 300, 'Period rx must be the sum of positive sample deltas');
        assert.strictEqual(Number(traffic.periodTxBytes), 160, 'Period tx must be the sum of positive sample deltas');
        assert.strictEqual(Number(traffic.sampleCount), 2, 'API must report the sample count');

        // Honest validation: unknown instance and invalid engine rejected.
        const badTraffic = await adminClient.request('GET', '/api/v1/instances/lxc/999999/traffic');
        assert.notStrictEqual(badTraffic.status, 200, 'Unknown instance traffic must not succeed');
        const badEngine = await adminClient.request('GET', `/api/v1/instances/xyz/${lxcId}/traffic`);
        assert.strictEqual(badEngine.status, 400, `Invalid engine must be rejected: ${badEngine.text}`);
      } finally {
        im.collectInstanceTelemetry = origCollect;
        await ctx.db.run(`DELETE FROM instance_traffic WHERE instance_type = 'lxc' AND instance_id = ?`, [lxcId]).catch(() => undefined);
        await ctx.db.run(`DELETE FROM metrics_history WHERE target_type = 'lxc' AND target_id = ?`, [lxcId]).catch(() => undefined);
        await ctx.db.run(`DELETE FROM instances WHERE engine = 'lxc' AND ref_id = ?`, [lxcId]).catch(() => undefined);
        await ctx.db.run(`DELETE FROM lxc_instances WHERE id = ?`, [lxcId]).catch(() => undefined);
      }
    });

    // Phase 27: HAProxy load balancer manager — registry, rendered config
    // validation, start/reload/stop lifecycle, honest capability gating and
    // remote-node enforcement through the node agent.
    await runStep('T42: HAProxy load balancers render, validate, apply and gate honestly', async () => {
      const cmdRunner = require('../lib/node-agent/command-runner');
      const origRun = cmdRunner.runAllowlistedCommand;
      const origAvailable = cmdRunner.isBinaryAvailable;
      const haproxyDir = path.join(process.env.TGVPANEL_DATA_DIR || os.homedir(), 'haproxy');
      const calls = [];
      let haproxyPresent = true;
      let failValidation = false;

      cmdRunner.isBinaryAvailable = (binary) => (binary === 'haproxy' ? haproxyPresent : origAvailable(binary));
      cmdRunner.runAllowlistedCommand = async (binary, args, options) => {
        calls.push({ binary, args });
        if (binary === 'haproxy' && args[0] === '-c') {
          if (failValidation) return { exitCode: 1, stdout: '', stderr: 'parse error on line 3', timedOut: false, durationMs: 1 };
          return { exitCode: 0, stdout: 'Configuration file is valid', stderr: '', timedOut: false, durationMs: 1 };
        }
        if (binary === 'haproxy' && args[0] === '-D') {
          // Simulate HAProxy creating its pidfile.
          const pidIdx = args.indexOf('-p');
          if (pidIdx >= 0) fs.writeFileSync(args[pidIdx + 1], String(12345), { mode: 0o640 });
          return { exitCode: 0, stdout: '', stderr: '', timedOut: false, durationMs: 1 };
        }
        return { exitCode: 0, stdout: '', stderr: '', timedOut: false, durationMs: 1 };
      };

      try {
        // Create a load balancer with two backends.
        const createRes = await adminClient.request(
          'POST',
          '/api/v1/load-balancers',
          {
            name: 't42-web-lb',
            nodeId: 1,
            listenIp: '0.0.0.0',
            listenPort: 8080,
            protocol: 'tcp',
            algorithm: 'roundrobin',
            backends: [
              { name: 'app-1', target: '10.88.10.5', port: 8081, weight: 2 },
              { name: 'app-2', target: '10.88.10.6', port: 8081, weight: 1 },
            ],
          },
          { 'X-Forwarded-For': '198.51.100.70' }
        );
        assert.strictEqual(createRes.status, 201, `LB creation failed: ${createRes.text}`);
        const lb = createRes.json.loadBalancer;
        assert.strictEqual(lb.backends.length, 2, 'Both backends must persist');
        assert.strictEqual(lb.backends[0].target, '10.88.10.5');

        // Apply: config is written, validated and the process started.
        calls.length = 0;
        const applyRes = await adminClient.request(
          'POST',
          `/api/v1/load-balancers/${lb.id}/apply`,
          { mode: 'start' },
          { 'X-Forwarded-For': '198.51.100.71' }
        );
        assert.strictEqual(applyRes.status, 200, `LB apply failed: ${applyRes.text}`);
        assert.strictEqual(applyRes.json.applied, true, 'Apply must succeed with a valid config');
        assert.strictEqual(applyRes.json.validated, true, 'Config must validate');
        const cfgPath = path.join(haproxyDir, 't42-web-lb.cfg');
        const cfg = fs.readFileSync(cfgPath, 'utf8');
        assert.match(cfg, /frontend t42-web-lb_fe/, 'Rendered config must contain the frontend');
        assert.match(cfg, /bind 0.0.0.0:8080/, 'Rendered config must bind the listen address');
        assert.match(cfg, /server app-1 10.88.10.5:8081 weight 2 check/, 'Rendered config must contain backend servers');
        assert.ok(calls.some((c) => c.binary === 'haproxy' && c.args[0] === '-c'), 'Validation command must run');
        assert.ok(calls.some((c) => c.binary === 'haproxy' && c.args[0] === '-D'), 'Daemon start command must run');

        // Status reflects the running process (pidfile created by the stubbed start).
        const statusRes = await adminClient.request('GET', `/api/v1/load-balancers/${lb.id}/status`);
        assert.strictEqual(statusRes.status, 200, `LB status failed: ${statusRes.text}`);
        assert.strictEqual(statusRes.json.status.running, true, 'Status must report the running process');

        // Validation failure is recorded honestly and the process is not started.
        failValidation = true;
        const badApply = await adminClient.request(
          'POST',
          `/api/v1/load-balancers/${lb.id}/apply`,
          { mode: 'reload' },
          { 'X-Forwarded-For': '198.51.100.72' }
        );
        assert.strictEqual(badApply.status, 200, `LB apply must return 200 with honest failure: ${badApply.text}`);
        assert.strictEqual(badApply.json.applied, false, 'Failed validation must not apply');
        assert.strictEqual(badApply.json.validated, false, 'Failed validation must be reported');
        assert.match(badApply.json.error, /validation failed/i, 'Validation error must be surfaced');
        const errStatus = await adminClient.request('GET', `/api/v1/load-balancers/${lb.id}/status`);
        assert.match(errStatus.json.status.lastError, /validation failed/i, 'Last error must be recorded on the LB');

        // Capability gating: no haproxy binary means an honest refusal.
        failValidation = false;
        haproxyPresent = false;
        const noBinary = await adminClient.request(
          'POST',
          `/api/v1/load-balancers/${lb.id}/apply`,
          { mode: 'start' },
          { 'X-Forwarded-For': '198.51.100.73' }
        );
        assert.strictEqual(noBinary.status, 200, `LB apply must return 200 with honest refusal: ${noBinary.text}`);
        assert.strictEqual(noBinary.json.applied, false, 'Missing binary must refuse apply');
        assert.match(noBinary.json.error, /haproxy binary is not available/i);

        // Validation rejects malformed input.
        haproxyPresent = true;
        const badCreate = await adminClient.request(
          'POST',
          '/api/v1/load-balancers',
          { name: 't42-bad', listenPort: 70000, backends: [] },
          { 'X-Forwarded-For': '198.51.100.74' }
        );
        assert.strictEqual(badCreate.status, 400, `Invalid listenPort must be rejected: ${badCreate.text}`);

        // Update and delete cascade backends.
        const updRes = await adminClient.request(
          'PUT',
          `/api/v1/load-balancers/${lb.id}`,
          { listenPort: 8443, backends: [{ name: 'only', target: '10.88.10.9', port: 9000, weight: 1 }] },
          { 'X-Forwarded-For': '198.51.100.75' }
        );
        assert.strictEqual(updRes.status, 200, `LB update failed: ${updRes.text}`);
        assert.strictEqual(updRes.json.loadBalancer.backends.length, 1, 'Backends must be replaced on update');

        // Remote-node enforcement: the agent validates and applies the config.
        const remoteApply = () =>
          new Promise((resolve, reject) => {
            const body = JSON.stringify({ name: 't42-remote-lb', config: 'frontend x\n    bind 0.0.0.0:9000\n', mode: 'start' });
            const signed = signAgentRequest({
              nodeId: 'local-loopback-agent',
              apiKey: agentApiKey,
              hmacSecret: agentHmacSecret,
              method: 'POST',
              pathWithQuery: '/api/v1/load-balancers/apply',
              bodyBuffer: body,
            });
            const r = http.request(
              {
                hostname: '127.0.0.1',
                port: AGENT_PORT,
                path: '/api/v1/load-balancers/apply',
                method: 'POST',
                headers: { ...signed, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
              },
              (res) => {
                let txt = '';
                res.on('data', (c) => (txt += c));
                res.on('end', () => resolve({ status: res.statusCode, text: txt }));
              }
            );
            r.on('error', reject);
            r.end(body);
          });
        const agentLb = await remoteApply();
        assert.strictEqual(agentLb.status, 200, `Agent LB apply failed: ${agentLb.text}`);
        const agentLbJson = JSON.parse(agentLb.text);
        assert.strictEqual(agentLbJson.applied, true, 'Agent must apply a valid remote config');
        assert.strictEqual(agentLbJson.validated, true, 'Agent must validate the remote config');

        const delRes = await adminClient.request(
          'DELETE',
          `/api/v1/load-balancers/${lb.id}`,
          undefined,
          { 'X-Forwarded-For': '198.51.100.76' }
        );
        assert.strictEqual(delRes.status, 200, `LB delete failed: ${delRes.text}`);
        const afterDel = await ctx.db.all(`SELECT id FROM load_balancer_backends WHERE load_balancer_id = ?`, [lb.id]);
        assert.strictEqual(afterDel.length, 0, 'Backends must cascade on delete');
      } finally {
        cmdRunner.runAllowlistedCommand = origRun;
        cmdRunner.isBinaryAvailable = origAvailable;
        await ctx.db.run(`DELETE FROM load_balancer_backends`).catch(() => undefined);
        await ctx.db.run(`DELETE FROM load_balancers`).catch(() => undefined);
        if (fs.existsSync(path.join(haproxyDir, 't42-web-lb.cfg'))) fs.unlinkSync(path.join(haproxyDir, 't42-web-lb.cfg'));
        if (fs.existsSync(path.join(haproxyDir, 't42-web-lb.pid'))) fs.unlinkSync(path.join(haproxyDir, 't42-web-lb.pid'));
        if (fs.existsSync(path.join(haproxyDir, 't42-remote-lb.cfg'))) fs.unlinkSync(path.join(haproxyDir, 't42-remote-lb.cfg'));
      }
    });

    // Phase 28: Session inventory & revocation — panel sessions are now
    // persisted, enumerable by administrators and revocable (single or
    // per-user), replacing the in-memory-only default store.
    await runStep('T43: Session inventory lists active logins; revocation forces logout', async () => {
      // bob_user (no 2FA) logs in fresh, creating a persistent session.
      const bobClient = new SessionClient(baseUrl);
      const loginRes = await bobClient.request('POST', '/api/login', {
        username: 'bob_user',
        password: 'BobPass!123',
      });
      assert.strictEqual(loginRes.status, 200, `Bob login failed: ${loginRes.text}`);
      assert.strictEqual(loginRes.json.success, true, 'Bob login must complete without 2FA');

      const bobRow = await ctx.db.get(`SELECT id FROM users WHERE username = 'bob_user'`);
      const bobId = bobRow.id;

      // The SQLite session save commits asynchronously; poll for the row that
      // matches the client's actual cookie session id so assertions never race
      // the write (a stale row from an earlier test would be a false positive).
      const waitForSession = async () => {
        const cookieSid = decodeURIComponent(
          bobClient.cookie.replace(/^connect\.sid=s%3A/, '').split('.')[0]
        );
        for (let i = 0; i < 40; i++) {
          const row = await ctx.db.get(`SELECT sid FROM sessions WHERE sid = ?`, [cookieSid]);
          if (row) return row;
          await new Promise((r) => setTimeout(r, 50));
        }
        return null;
      };

      try {
        // The session is persisted in the store.
        const storeRow = await waitForSession();
        assert.ok(storeRow, 'Bob session must be persisted in the sessions table');

        // Customers cannot inventory or revoke sessions. This authenticated
        // request also triggers activity metadata (last seen / IP / user agent).
        const forbidden = await bobClient.request('GET', '/api/v1/sessions');
        assert.strictEqual(forbidden.status, 403, `Customer session inventory must be forbidden: ${forbidden.text}`);

        // Activity metadata is written asynchronously; poll briefly for it.
        let storeRowFull = null;
        for (let i = 0; i < 40; i++) {
          storeRowFull = await ctx.db.get(
            `SELECT sid, user_id, ip, user_agent, last_seen_at FROM sessions WHERE user_id = ?`,
            [bobId]
          );
          if (storeRowFull && storeRowFull.last_seen_at) break;
          await new Promise((r) => setTimeout(r, 50));
        }
        assert.ok(storeRowFull && storeRowFull.last_seen_at, 'Session activity must be recorded');
        assert.ok(storeRowFull.ip, 'Session IP must be recorded');

        // Administrator inventory includes both the admin and Bob sessions.
        const invRes = await adminClient.request('GET', '/api/v1/sessions');
        assert.strictEqual(invRes.status, 200, `Session inventory failed: ${invRes.text}`);
        const sessions = invRes.json.sessions;
        assert.ok(sessions.length >= 2, 'Inventory must list the admin and Bob sessions');
        const bobSession = sessions.find((s) => s.user_id === bobId);
        assert.ok(bobSession, 'Bob session must appear in the inventory');
        assert.strictEqual(bobSession.username, 'bob_user', 'Inventory must join the user name');

        // Revoking a single session forces an immediate logout.
        const revokeRes = await adminClient.request(
          'DELETE',
          `/api/v1/sessions/${encodeURIComponent(bobSession.sid)}`,
          undefined,
          { 'X-Forwarded-For': '198.51.100.80' }
        );
        assert.strictEqual(revokeRes.status, 200, `Session revocation failed: ${revokeRes.text}`);
        assert.strictEqual(revokeRes.json.revoked, 1, 'Revocation must report the destroyed session');
        const afterRevoke = await bobClient.request('GET', '/api/v1/instances');
        assert.notStrictEqual(afterRevoke.status, 200, 'Revoked session must not authenticate');

        // Log back in and verify per-user revocation clears every session.
        const login2 = await bobClient.request('POST', '/api/login', {
          username: 'bob_user',
          password: 'BobPass!123',
        });
        assert.strictEqual(login2.status, 200, `Bob re-login failed: ${login2.text}`);
        await waitForSession();
        const revokeAllRes = await adminClient.request(
          'DELETE',
          `/api/v1/sessions?userId=${bobId}`,
          undefined,
          { 'X-Forwarded-For': '198.51.100.81' }
        );
        assert.strictEqual(revokeAllRes.status, 200, `Per-user revocation failed: ${revokeAllRes.text}`);
        assert.ok(revokeAllRes.json.revoked >= 1, 'Per-user revocation must destroy the session');
        const afterRevokeAll = await bobClient.request('GET', '/api/v1/instances');
        assert.notStrictEqual(afterRevokeAll.status, 200, 'All-revoked user must not authenticate');
        const remaining = await ctx.db.get(`SELECT sid FROM sessions WHERE user_id = ?`, [bobId]);
        assert.strictEqual(remaining, undefined, 'No sessions must remain for the revoked user');
      } finally {
        await ctx.db.run(`DELETE FROM sessions WHERE user_id = ?`, [bobId]).catch(() => undefined);
      }
    });

    // Phase 29: Docker container manager (Area I) — panel-managed containers
    // are registered, rendered as docker run/lifecycle commands, executed via
    // the allowlisted command runner (locally or through the node agent) and
    // capability-gated honestly when the docker binary is absent.
    await runStep('T44: Docker container registry, rendered commands, lifecycle gating & agent enforcement', async () => {
      const dockerDir = path.join(tmpRoot, 'docker-test');
      fs.mkdirSync(dockerDir, { recursive: true });

      try {
        // 1. Registry CRUD with validation.
        const createRes = await adminClient.request('POST', '/api/v1/docker/containers', {
          name: 't44-web',
          nodeId: 1,
          image: 'nginx:latest',
          restartPolicy: 'unless-stopped',
          network: 'tgvpanel',
          ports: [{ hostPort: 8080, containerPort: 80, protocol: 'tcp' }],
          env: { APP_ENV: 'test' },
        });
        assert.strictEqual(createRes.status, 201, `Container create failed: ${createRes.text}`);
        const container = createRes.json.container;
        assert.strictEqual(container.name, 't44-web');
        assert.strictEqual(container.status, 'created');

        // Invalid inputs are rejected.
        const badName = await adminClient.request('POST', '/api/v1/docker/containers', {
          name: 'bad name!',
          image: 'nginx:latest',
        });
        assert.strictEqual(badName.status, 400, `Invalid container name must be rejected: ${badName.text}`);
        const badImage = await adminClient.request('POST', '/api/v1/docker/containers', {
          name: 't44-bad-image',
          image: 'Not A Valid Image',
        });
        assert.strictEqual(badImage.status, 400, `Invalid image must be rejected: ${badImage.text}`);
        const badPolicy = await adminClient.request('POST', '/api/v1/docker/containers', {
          name: 't44-bad-policy',
          image: 'nginx:latest',
          restartPolicy: 'sometimes',
        });
        assert.strictEqual(badPolicy.status, 400, `Invalid restart policy must be rejected: ${badPolicy.text}`);
        const dupRes = await adminClient.request('POST', '/api/v1/docker/containers', {
          name: 't44-web',
          image: 'nginx:latest',
        });
        assert.strictEqual(dupRes.status, 400, `Duplicate container name must be rejected: ${dupRes.text}`);

        // 2. Rendered commands are correct.
        const dockerManager = ctx.dockerManager;
        assert.ok(dockerManager, 'dockerManager must be wired into the runtime context');
        const runArgs = dockerManager.renderRunArgs(container);
        assert.deepStrictEqual(runArgs.slice(0, 4), ['run', '-d', '--name', 't44-web']);
        assert.ok(runArgs.includes('--restart'), 'Rendered run args must include --restart');
        assert.ok(runArgs.includes('--network'), 'Rendered run args must include --network');
        assert.ok(runArgs.includes('-p'), 'Rendered run args must include port mappings');
        assert.ok(runArgs.includes('8080:80/tcp'), 'Rendered run args must map host:container/proto');
        assert.ok(runArgs.includes('-e'), 'Rendered run args must include environment');
        assert.ok(runArgs.includes('APP_ENV=test'), 'Rendered run args must include KEY=VALUE env');
        assert.ok(runArgs[runArgs.length - 1] === 'nginx:latest', 'Rendered run args must end with the image');
        const runCmd = dockerManager.renderRunCommand(container);
        assert.ok(runCmd.startsWith('docker run -d --name t44-web'), `Rendered run command: ${runCmd}`);
        assert.strictEqual(
          dockerManager.renderLifecycleCommand(container, 'stop'),
          'docker stop t44-web'
        );
        assert.strictEqual(
          dockerManager.renderLifecycleCommand(container, 'remove'),
          'docker rm -f t44-web'
        );

        // 3. Lifecycle apply is capability-gated honestly (docker absent here).
        const applyRes = await adminClient.request(
          'POST',
          `/api/v1/docker/containers/${container.id}/apply`,
          { mode: 'create' },
          { 'X-Forwarded-For': '198.51.100.90' }
        );
        assert.strictEqual(applyRes.status, 200, `Container apply failed: ${applyRes.text}`);
        if (!applyRes.json.applied) {
          assert.ok(
            /docker binary is not available/i.test(applyRes.json.error || ''),
            `Honest capability-gating error expected: ${applyRes.json.error}`
          );
        }

        // 4. Status reports docker availability honestly.
        const statusRes = await adminClient.request('GET', `/api/v1/docker/containers/${container.id}/status`);
        assert.strictEqual(statusRes.status, 200, `Container status failed: ${statusRes.text}`);
        assert.strictEqual(statusRes.json.status.id, container.id);
        assert.strictEqual(statusRes.json.status.dockerAvailable, applyRes.json.applied, 'Status availability must match the apply result');

        // 5. Customers cannot manage containers.
        const bobClient = new SessionClient(baseUrl);
        await bobClient.request('POST', '/api/login', { username: 'bob_user', password: 'BobPass!123' });
        const forbiddenList = await bobClient.request('GET', '/api/v1/docker/containers');
        assert.strictEqual(forbiddenList.status, 403, `Customer container list must be forbidden: ${forbiddenList.text}`);

        // 6. Agent enforces the lifecycle command on the host (honest gating
        //    when docker is absent; a valid spec passes agent validation).
        const agentApply = await new Promise((resolve, reject) => {
          const body = JSON.stringify({
            name: 't44-web',
            image: 'nginx:latest',
            restart_policy: 'unless-stopped',
            network: 'tgvpanel',
            ports: [{ hostPort: 8080, containerPort: 80, protocol: 'tcp' }],
            env: { APP_ENV: 'test' },
            mode: 'create',
          });
          const signed = signAgentRequest({
            nodeId: 'local-loopback-agent',
            apiKey: agentApiKey,
            hmacSecret: agentHmacSecret,
            method: 'POST',
            pathWithQuery: '/api/v1/docker/apply',
            bodyBuffer: body,
          });
          const r = http.request(
            {
              hostname: '127.0.0.1',
              port: AGENT_PORT,
              path: '/api/v1/docker/apply',
              method: 'POST',
              headers: { ...signed, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
            },
            (res) => {
              const chunks = [];
              res.on('data', (c) => chunks.push(c));
              res.on('end', () => {
                const text = Buffer.concat(chunks).toString('utf8');
                resolve({ status: res.statusCode, text });
              });
            }
          );
          r.on('error', reject);
          r.end(body);
        });
        assert.strictEqual(agentApply.status, 200, `Agent docker apply failed: ${agentApply.text}`);
        const agentJson = JSON.parse(agentApply.text);
        if (!agentJson.applied) {
          assert.ok(
            /docker binary is not available/i.test(agentJson.error || ''),
            `Agent must report honest capability gating: ${agentJson.error}`
          );
        }
        const agentBad = await new Promise((resolve, reject) => {
          const body = JSON.stringify({ name: 'bad name!', image: 'nginx:latest', mode: 'create' });
          const signed = signAgentRequest({
            nodeId: 'local-loopback-agent',
            apiKey: agentApiKey,
            hmacSecret: agentHmacSecret,
            method: 'POST',
            pathWithQuery: '/api/v1/docker/apply',
            bodyBuffer: body,
          });
          const r = http.request(
            {
              hostname: '127.0.0.1',
              port: AGENT_PORT,
              path: '/api/v1/docker/apply',
              method: 'POST',
              headers: { ...signed, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
            },
            (res) => {
              const chunks = [];
              res.on('data', (c) => chunks.push(c));
              res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
            }
          );
          r.on('error', reject);
          r.end(body);
        });
        assert.strictEqual(agentBad.status, 400, `Agent must reject invalid container specs: ${agentBad.text}`);

        // 7. Update replaces the spec; delete removes the registry row.
        const updRes = await adminClient.request('PUT', `/api/v1/docker/containers/${container.id}`, {
          image: 'nginx:1.27-alpine',
          ports: [{ hostPort: 8443, containerPort: 443, protocol: 'tcp' }],
        });
        assert.strictEqual(updRes.status, 200, `Container update failed: ${updRes.text}`);
        assert.strictEqual(updRes.json.container.image, 'nginx:1.27-alpine');
        const updArgs = dockerManager.renderRunArgs(updRes.json.container);
        assert.ok(updArgs.includes('8443:443/tcp'), 'Updated ports must render into the run args');

        const listRes = await adminClient.request('GET', '/api/v1/docker/containers');
        assert.strictEqual(listRes.status, 200);
        assert.ok(listRes.json.containers.some((c) => c.name === 't44-web'), 'Registry list must include the container');

        const delRes = await adminClient.request('DELETE', `/api/v1/docker/containers/${container.id}`);
        assert.strictEqual(delRes.status, 200, `Container delete failed: ${delRes.text}`);
        const goneRes = await adminClient.request('GET', `/api/v1/docker/containers/${container.id}`);
        assert.strictEqual(goneRes.status, 404, `Deleted container must be gone: ${goneRes.text}`);
      } finally {
        await ctx.db.run(`DELETE FROM docker_containers WHERE name LIKE 't44-%'`).catch(() => undefined);
      }
    });

    // Phase 30: Billing & invoicing (Area K) — plans, subscriptions,
    // invoices and a credit ledger. Payments are recorded only after
    // administrator-verified confirmation with a payment reference.
    await runStep('T45: Billing plans, subscriptions, invoices, verified payments & credits', async () => {
      try {
        // 1. Plan CRUD with validation.
        const planRes = await adminClient.request('POST', '/api/v1/billing/plans', {
          name: 'T45 Starter',
          priceCents: 5000,
          billingCycle: 'monthly',
          description: 'Phase 30 test plan',
          features: ['1 vCPU', '2GB RAM'],
        });
        assert.strictEqual(planRes.status, 201, `Plan create failed: ${planRes.text}`);
        const plan = planRes.json.plan;
        assert.strictEqual(plan.name, 'T45 Starter');
        assert.strictEqual(plan.price_cents, 5000);

        const badPlan = await adminClient.request('POST', '/api/v1/billing/plans', {
          name: 'Bad Cycle Plan',
          priceCents: 100,
          billingCycle: 'weekly',
        });
        assert.strictEqual(badPlan.status, 400, `Invalid billing cycle must be rejected: ${badPlan.text}`);
        const badPrice = await adminClient.request('POST', '/api/v1/billing/plans', {
          name: 'Bad Price Plan',
          priceCents: -5,
        });
        assert.strictEqual(badPrice.status, 400, `Negative price must be rejected: ${badPrice.text}`);
        const dupPlan = await adminClient.request('POST', '/api/v1/billing/plans', {
          name: 'T45 Starter',
          priceCents: 100,
        });
        assert.strictEqual(dupPlan.status, 400, `Duplicate plan name must be rejected: ${dupPlan.text}`);

        const updPlan = await adminClient.request('PUT', `/api/v1/billing/plans/${plan.id}`, {
          priceCents: 7500,
        });
        assert.strictEqual(updPlan.status, 200, `Plan update failed: ${updPlan.text}`);
        assert.strictEqual(updPlan.json.plan.price_cents, 7500, 'Plan price must be updated');

        // 2. Subscription create issues the first invoice.
        const bobRow = await ctx.db.get(`SELECT id FROM users WHERE username = 'bob_user'`);
        const subRes = await adminClient.request('POST', '/api/v1/billing/subscriptions', {
          userId: bobRow.id,
          planId: plan.id,
          autoRenew: true,
        });
        assert.strictEqual(subRes.status, 201, `Subscription create failed: ${subRes.text}`);
        const subscription = subRes.json.subscription;
        assert.strictEqual(subscription.status, 'active');
        assert.ok(subscription.current_period_end, 'Subscription must have a period end');

        const invList = await adminClient.request('GET', '/api/v1/billing/invoices?userId=' + bobRow.id);
        assert.strictEqual(invList.status, 200, `Invoice list failed: ${invList.text}`);
        const firstInvoice = invList.json.invoices.find((i) => i.subscription_id === subscription.id);
        assert.ok(firstInvoice, 'First invoice must be issued on subscription create');
        assert.strictEqual(firstInvoice.amount_cents, 7500, 'Invoice amount must match the plan price');
        assert.strictEqual(firstInvoice.status, 'issued');
        assert.ok(/^INV-\d{8}-\d{4}$/.test(firstInvoice.invoice_number), `Invoice number format: ${firstInvoice.invoice_number}`);

        // 3. Renew advances the period and issues a renewal invoice.
        const renewRes = await adminClient.request('POST', `/api/v1/billing/subscriptions/${subscription.id}/renew`);
        assert.strictEqual(renewRes.status, 200, `Subscription renew failed: ${renewRes.text}`);
        assert.notStrictEqual(
          renewRes.json.subscription.current_period_end,
          subscription.current_period_end,
          'Renew must advance the period end'
        );
        const invAfterRenew = await adminClient.request('GET', '/api/v1/billing/invoices?userId=' + bobRow.id);
        assert.strictEqual(invAfterRenew.json.invoices.length, 2, 'Renew must issue a second invoice');

        // 4. Payment requires admin-verified confirmation with a reference.
        const missingRef = await adminClient.request('POST', `/api/v1/billing/invoices/${firstInvoice.id}/pay`, {});
        assert.strictEqual(missingRef.status, 400, `Payment without reference must be rejected: ${missingRef.text}`);

        const payRes = await adminClient.request('POST', `/api/v1/billing/invoices/${firstInvoice.id}/pay`, {
          paymentReference: 'T45-VERIFIED-TXN-001',
          method: 'admin-verified',
        });
        assert.strictEqual(payRes.status, 200, `Payment confirmation failed: ${payRes.text}`);
        assert.strictEqual(payRes.json.invoice.status, 'paid');
        assert.strictEqual(payRes.json.invoice.payment_reference, 'T45-VERIFIED-TXN-001');
        assert.ok(payRes.json.invoice.paid_at, 'Paid invoice must record paid_at');

        const doublePay = await adminClient.request('POST', `/api/v1/billing/invoices/${firstInvoice.id}/pay`, {
          paymentReference: 'T45-VERIFIED-TXN-002',
        });
        assert.strictEqual(doublePay.status, 400, `Double payment must be rejected: ${doublePay.text}`);

        // Payment posts a ledger entry and updates the balance.
        const creditsRes = await adminClient.request('GET', '/api/v1/billing/credits?userId=' + bobRow.id);
        assert.strictEqual(creditsRes.status, 200, `Credit list failed: ${creditsRes.text}`);
        const paymentEntry = creditsRes.json.credits.find((c) => c.type === 'payment');
        assert.ok(paymentEntry, 'Payment must post a credit-ledger entry');
        assert.strictEqual(paymentEntry.amount_cents, 7500);
        assert.strictEqual(paymentEntry.balance_after, 7500, 'Balance after payment must equal the amount');

        // 5. Customers cannot manage billing.
        const bobClient = new SessionClient(baseUrl);
        await bobClient.request('POST', '/api/login', { username: 'bob_user', password: 'BobPass!123' });
        const forbiddenPlans = await bobClient.request('GET', '/api/v1/billing/plans');
        assert.strictEqual(forbiddenPlans.status, 403, `Customer plan list must be forbidden: ${forbiddenPlans.text}`);
        const forbiddenPay = await bobClient.request('POST', `/api/v1/billing/invoices/${firstInvoice.id}/pay`, {
          paymentReference: 'bob-attempt',
        });
        assert.strictEqual(forbiddenPay.status, 403, `Customer payment must be forbidden: ${forbiddenPay.text}`);

        // 6. Credit adjustments and the resulting balance.
        const adjustRes = await adminClient.request('POST', '/api/v1/billing/credits', {
          userId: bobRow.id,
          type: 'credit',
          amountCents: 2500,
          reason: 'T45 goodwill',
        });
        assert.strictEqual(adjustRes.status, 201, `Credit adjustment failed: ${adjustRes.text}`);
        assert.strictEqual(adjustRes.json.balanceAfter, 10000, 'Balance must increase by the adjustment');

        const debitRes = await adminClient.request('POST', '/api/v1/billing/credits', {
          userId: bobRow.id,
          type: 'debit',
          amountCents: 1000,
          reason: 'T45 correction',
        });
        assert.strictEqual(debitRes.status, 201, `Credit debit failed: ${debitRes.text}`);
        assert.strictEqual(debitRes.json.balanceAfter, 9000, 'Balance must decrease by the debit');

        const badDebit = await adminClient.request('POST', '/api/v1/billing/credits', {
          userId: bobRow.id,
          type: 'debit',
          amountCents: 999999,
        });
        assert.strictEqual(badDebit.status, 400, `Debit exceeding balance must be rejected: ${badDebit.text}`);

        // 7. Cancel ends the subscription.
        const cancelRes = await adminClient.request('POST', `/api/v1/billing/subscriptions/${subscription.id}/cancel`);
        assert.strictEqual(cancelRes.status, 200, `Subscription cancel failed: ${cancelRes.text}`);
        assert.strictEqual(cancelRes.json.subscription.status, 'cancelled');
        assert.ok(cancelRes.json.subscription.cancelled_at, 'Cancel must record cancelled_at');

        // 8. Plan with active subscriptions cannot be deleted.
        const delActive = await adminClient.request('DELETE', `/api/v1/billing/plans/${plan.id}`);
        assert.strictEqual(delActive.status, 400, `Plan with active subscriptions must not be deleted: ${delActive.text}`);
      } finally {
        await ctx.db.run(`DELETE FROM credit_ledger WHERE reason LIKE 'T45%' OR reference LIKE 'T45%'`).catch(() => undefined);
        await ctx.db.run(`DELETE FROM invoices WHERE invoice_number LIKE 'INV-%' AND user_id IN (SELECT id FROM users WHERE username = 'bob_user')`).catch(() => undefined);
        await ctx.db.run(`DELETE FROM customer_subscriptions WHERE plan_id IN (SELECT id FROM billing_plans WHERE name LIKE 'T45%')`).catch(() => undefined);
        await ctx.db.run(`DELETE FROM billing_plans WHERE name LIKE 'T45%'`).catch(() => undefined);
      }
    });

    await runStep('T46: DDoS protection stats, settings, IP management & honest platform gating', async () => {
      const ctx = app.getHkvmV3Context();
      try {
        // 1. Stats endpoint is authenticated and returns the expected shape.
        const statsRes = await adminClient.request('GET', '/api/v1/ddos/stats');
        assert.strictEqual(statsRes.status, 200, `Stats failed: ${statsRes.text}`);
        assert.ok(statsRes.json.stats, 'Stats object present');
        assert.ok('total_requests' in statsRes.json.stats, 'total_requests present');
        assert.ok('critical_threats' in statsRes.json.stats, 'critical_threats present');
        assert.ok(typeof statsRes.json.linux === 'boolean', 'linux flag is boolean');
        assert.ok(typeof statsRes.json.monitoring === 'boolean', 'monitoring flag is boolean');

        // 2. Settings GET + PUT (admin only).
        const getSettings = await adminClient.request('GET', '/api/v1/ddos/settings');
        assert.strictEqual(getSettings.status, 200, `Settings GET failed: ${getSettings.text}`);
        assert.ok(getSettings.json.settings, 'Settings object present');
        assert.strictEqual(typeof getSettings.json.settings.rate_limit_per_minute, 'number');

        const putSettings = await adminClient.request('PUT', '/api/v1/ddos/settings', {
          rate_limit_per_minute: 75,
          block_duration: 7200,
        });
        assert.strictEqual(putSettings.status, 200, `Settings PUT failed: ${putSettings.text}`);
        assert.strictEqual(putSettings.json.settings.rate_limit_per_minute, 75, 'Rate limit updated');
        assert.strictEqual(putSettings.json.settings.block_duration, 7200, 'Block duration updated');

        // 3. Settings PUT is admin-only — operator is rejected.
        // Create an operator user inline for this check.
        const bcrypt = require('bcryptjs');
        const opHash = bcrypt.hashSync('OpPass!99', 10);
        await ctx.db.run(`INSERT OR IGNORE INTO users (username, password, email, role, is_active) VALUES ('op_user', ?, 'op@example.org', 'operator', 1)`, [opHash]);
        const opClient = new SessionClient(baseUrl);
        const opLogin = await opClient.request('POST', '/api/login', { username: 'op_user', password: 'OpPass!99' });
        assert.strictEqual(opLogin.status, 200, `Operator login failed: ${opLogin.text}`);
        const opSettings = await opClient.request('PUT', '/api/v1/ddos/settings', {
          rate_limit_per_minute: 1,
        });
        assert.ok([403, 401].includes(opSettings.status), `Operator must not update settings: ${opSettings.status}`);

        // 4. List IPs (may be empty on a fresh DB — that's honest).
        const ipsRes = await adminClient.request('GET', '/api/v1/ddos/ips?page=1&limit=10');
        assert.strictEqual(ipsRes.status, 200, `IP list failed: ${ipsRes.text}`);
        assert.ok(Array.isArray(ipsRes.json.ips), 'ips array present');
        assert.ok(ipsRes.json.pagination, 'pagination present');

        // 5. Operator can list IPs (read).
        const opIps = await opClient.request('GET', '/api/v1/ddos/ips');
        assert.strictEqual(opIps.status, 200, `Operator IP list failed: ${opIps.text}`);

        // 6. Block/unblock with a valid IPv4 — on non-Linux or missing iptables,
        //    the manager reports an honest error (no fake success).
        const testIp = '203.0.113.55';
        const blockRes = await adminClient.request('POST', `/api/v1/ddos/ips/${testIp}/block`, { reason: 't46' });
        // 200 = blocked on Linux with iptables; 400 = honest platform error. Both are valid.
        assert.ok([200, 400].includes(blockRes.status), `Block returned unexpected status: ${blockRes.status} — ${blockRes.text}`);
        if (blockRes.status === 200) {
          const unblockRes = await adminClient.request('POST', `/api/v1/ddos/ips/${testIp}/unblock`);
          assert.strictEqual(unblockRes.status, 200, `Unblock failed: ${unblockRes.text}`);
        }

        // 7. Block with an invalid IP must be rejected.
        const badIp = await adminClient.request('POST', '/api/v1/ddos/ips/not.an.ip/block');
        assert.strictEqual(badIp.status, 400, `Invalid IP must be rejected: ${badIp.text}`);

        // 8. Logs endpoint works.
        const logsRes = await adminClient.request('GET', '/api/v1/ddos/logs?limit=10');
        assert.strictEqual(logsRes.status, 200, `Logs failed: ${logsRes.text}`);
        assert.ok(Array.isArray(logsRes.json.logs), 'logs array present');

        // 9. Network analysis endpoint (Linux monitoring or honest empty).
        const naRes = await adminClient.request('GET', '/api/v1/ddos/network-analysis');
        assert.strictEqual(naRes.status, 200, `Network analysis failed: ${naRes.text}`);
        assert.ok('active_connections' in naRes.json, 'active_connections present');

        // 10. Clear IP (clean up any test data).
        await adminClient.request('DELETE', `/api/v1/ddos/ips/${testIp}`);
      } finally {
        // Restore defaults so other tests/runs are unaffected.
        await ctx.db.run(`UPDATE ddos_settings SET rate_limit_per_minute=60, block_duration=3600`).catch(() => undefined);
        await ctx.db.run(`DELETE FROM users WHERE username = 'op_user'`).catch(() => undefined);
      }
    });

    await runStep('T47: Enterprise DDoS protection — profiles, HTTP, firewall, nodes, VPS, Cloudflare, audit', async () => {
      const ctx = app.getHkvmV3Context();
      // Create operator client for role-gating checks.
      const bcrypt = require('bcryptjs');
      const opHash = bcrypt.hashSync('OpPass!99', 10);
      await ctx.db.run(`INSERT OR IGNORE INTO users (username, password, email, role, is_active) VALUES ('op_user', ?, 'op@example.org', 'operator', 1)`, [opHash]);
      const opClient = new SessionClient(baseUrl);
      const opLogin = await opClient.request('POST', '/api/login', { username: 'op_user', password: 'OpPass!99' });
      assert.strictEqual(opLogin.status, 200, `Operator login failed: ${opLogin.text}`);
      try {
        // 1. Enterprise stats include new fields (pps, bps, conn_rate, engine_health).
        const statsRes = await adminClient.request('GET', '/api/v1/ddos/stats');
        assert.strictEqual(statsRes.status, 200, `Stats failed: ${statsRes.text}`);
        const s = statsRes.json.stats;
        assert.ok('pps' in s, 'pps field present');
        assert.ok('bps' in s, 'bps field present');
        assert.ok('conn_rate' in s, 'conn_rate field present');
        assert.ok('engine_health' in s, 'engine_health field present');
        assert.ok('firewall_engine' in s, 'firewall_engine field present');
        assert.ok('attacks_detected' in s, 'attacks_detected field present');
        assert.ok('active_mitigations' in s, 'active_mitigations field present');

        // 2. Settings include enterprise thresholds.
        const settingsRes = await adminClient.request('GET', '/api/v1/ddos/settings');
        assert.strictEqual(settingsRes.status, 200);
        const cfg = settingsRes.json.settings;
        assert.strictEqual(typeof cfg.syn_cookies, 'number');
        assert.strictEqual(typeof cfg.ack_flood_threshold, 'number');
        assert.strictEqual(typeof cfg.icmp_flood_threshold, 'number');
        assert.strictEqual(typeof cfg.http_get_threshold, 'number');
        assert.strictEqual(typeof cfg.http_post_threshold, 'number');
        assert.strictEqual(typeof cfg.slowloris_threshold, 'number');
        assert.strictEqual(typeof cfg.dns_amp_threshold, 'number');
        assert.strictEqual(typeof cfg.emergency_mode, 'number');

        // 3. Profiles CRUD.
        const profRes = await adminClient.request('POST', '/api/v1/ddos/profiles', {
          name: 'T47 Test Profile',
          level: 'custom',
          auto_block: 1,
          block_duration: 1800,
          connection_limit: 2000,
          threat_threshold_medium: 150,
          threat_threshold_high: 600,
          threat_threshold_critical: 1200,
        });
        assert.strictEqual(profRes.status, 201, `Profile create failed: ${profRes.text}`);
        const profile = profRes.json.profile;
        assert.strictEqual(profile.name, 'T47 Test Profile');
        assert.strictEqual(profile.level, 'custom');

        const profList = await adminClient.request('GET', '/api/v1/ddos/profiles');
        assert.strictEqual(profList.status, 200);
        assert.ok(profList.json.profiles.some((p) => p.name === 'T47 Test Profile'), 'Profile in list');

        // Activate profile
        const activateRes = await adminClient.request('POST', `/api/v1/ddos/profiles/${profile.id}/activate`);
        assert.strictEqual(activateRes.status, 200, `Profile activate failed: ${activateRes.text}`);

        // 4. HTTP protection settings.
        const httpGet = await adminClient.request('GET', '/api/v1/ddos/http/settings');
        assert.strictEqual(httpGet.status, 200);
        assert.ok(httpGet.json.settings, 'HTTP settings present');
        assert.strictEqual(typeof httpGet.json.settings.http_get_threshold, 'number');

        const httpPut = await adminClient.request('PUT', '/api/v1/ddos/http/settings', {
          http_get_threshold: 250,
          slowloris_threshold: 15,
        });
        assert.strictEqual(httpPut.status, 200, `HTTP settings PUT failed: ${httpPut.text}`);
        assert.strictEqual(httpPut.json.settings.http_get_threshold, 250);

        // Operator cannot change HTTP settings.
        const opHttp = await opClient.request('PUT', '/api/v1/ddos/http/settings', { http_get_threshold: 1 });
        assert.ok([403, 401].includes(opHttp.status), `Operator must not update HTTP settings: ${opHttp.status}`);

        // 5. Firewall status and engine controls.
        const fwStatus = await adminClient.request('GET', '/api/v1/ddos/firewall/status');
        assert.strictEqual(fwStatus.status, 200);
        assert.ok('engine' in fwStatus.json, 'firewall engine present');
        assert.ok('nftables' in fwStatus.json, 'nftables flag present');

        // SYN cookies control (may fail on non-Linux — that's honest).
        const synRes = await adminClient.request('POST', '/api/v1/ddos/firewall/syn-cookies', { enabled: true });
        assert.ok([200, 400].includes(synRes.status), `SYN cookies returned unexpected: ${synRes.status}`);

        // Connection limit control.
        const connRes = await adminClient.request('POST', '/api/v1/ddos/firewall/connection-limit', { limit: 2000 });
        assert.ok([200, 400].includes(connRes.status), `Connection limit returned unexpected: ${connRes.status}`);

        // 6. Node status list.
        const nodesRes = await adminClient.request('GET', '/api/v1/ddos/nodes');
        assert.strictEqual(nodesRes.status, 200);
        assert.ok(Array.isArray(nodesRes.json.nodes), 'nodes array present');

        // 7. VPS policies.
        const vpsPut = await adminClient.request('PUT', '/api/v1/ddos/vps-policies/1', {
          vps_id: 1,
          instance_type: 'lxc',
          instance_ref_id: 1,
          enabled: 1,
          tcp_protection: 1,
          udp_protection: 1,
          connection_limit: 500,
          auto_block: 1,
          block_duration: 3600,
        });
        assert.strictEqual(vpsPut.status, 200, `VPS policy PUT failed: ${vpsPut.text}`);
        assert.strictEqual(vpsPut.json.policy.vps_id, 1);

        const vpsList = await adminClient.request('GET', '/api/v1/ddos/vps-policies');
        assert.strictEqual(vpsList.status, 200);
        assert.ok(vpsList.json.policies.some((p) => p.vps_id === 1), 'VPS policy in list');

        // 8. Whitelist add/remove.
        const wlAdd = await adminClient.request('POST', '/api/v1/ddos/whitelist', {
          ip: '203.0.113.100', reason: 't47 test',
        });
        assert.strictEqual(wlAdd.status, 200, `Whitelist add failed: ${wlAdd.text}`);
        const wlList = await adminClient.request('GET', '/api/v1/ddos/whitelist');
        assert.strictEqual(wlList.status, 200);
        assert.ok(wlList.json.whitelist.some((w) => w.ip === '203.0.113.100'), 'Whitelist entry present');

        // Whitelisted IP cannot be blocked.
        const wlBlock = await adminClient.request('POST', '/api/v1/ddos/ips/203.0.113.100/block', { reason: 'test' });
        assert.strictEqual(wlBlock.status, 400, `Whitelisted IP must not be blocked: ${wlBlock.status}`);

        const wlRemove = await adminClient.request('DELETE', '/api/v1/ddos/whitelist/203.0.113.100');
        assert.strictEqual(wlRemove.status, 200, `Whitelist remove failed: ${wlRemove.text}`);

        // 9. Cloudflare integration create/list/delete.
        const cfRes = await adminClient.request('POST', '/api/v1/ddos/integrations', {
          name: 'T47 CF', provider: 'cloudflare', zone: 'test-zone', securityLevel: 'medium',
        });
        assert.strictEqual(cfRes.status, 201, `Cloudflare create failed: ${cfRes.text}`);
        const cf = cfRes.json.integration;
        const cfList = await adminClient.request('GET', '/api/v1/ddos/integrations');
        assert.strictEqual(cfList.status, 200);
        assert.ok(cfList.json.integrations.some((i) => i.id === cf.id), 'Cloudflare in list');
        // API key must not be returned in plaintext.
        assert.ok(!cfList.json.integrations.find((i) => i.id === cf.id).api_key_enc, 'API key encrypted, not plaintext');

        const cfDelete = await adminClient.request('DELETE', `/api/v1/ddos/integrations/${cf.id}`);
        assert.strictEqual(cfDelete.status, 200);

        // 10. Attacks and mitigations endpoints.
        const atkRes = await adminClient.request('GET', '/api/v1/ddos/attacks?limit=10');
        assert.strictEqual(atkRes.status, 200);
        assert.ok(Array.isArray(atkRes.json.attacks), 'attacks array present');

        const mitRes = await adminClient.request('GET', '/api/v1/ddos/mitigations?active=1');
        assert.strictEqual(mitRes.status, 200);
        assert.ok(Array.isArray(mitRes.json.mitigations), 'mitigations array present');

        // 11. Audit log endpoint.
        const auditRes = await adminClient.request('GET', '/api/v1/ddos/audit?limit=10');
        assert.strictEqual(auditRes.status, 200);
        assert.ok(Array.isArray(auditRes.json.logs), 'audit logs array present');

        // 12. Network analysis includes enterprise attack types.
        const naRes = await adminClient.request('GET', '/api/v1/ddos/network-analysis');
        assert.strictEqual(naRes.status, 200);
        assert.ok('ack_flood_attacks' in naRes.json, 'ack_flood_attacks present');
        assert.ok('icmp_flood_attacks' in naRes.json, 'icmp_flood_attacks present');
        assert.ok('dns_amplification' in naRes.json, 'dns_amplification present');

        // 13. Profile assignment (to node).
        const assignRes = await adminClient.request('POST', `/api/v1/ddos/profiles/${profile.id}/assign`, { nodeId: 1 });
        assert.strictEqual(assignRes.status, 200, `Profile assign failed: ${assignRes.text}`);

        // Cleanup
        await adminClient.request('DELETE', `/api/v1/ddos/profiles/${profile.id}`);
        await adminClient.request('DELETE', `/api/v1/ddos/vps-policies/1`);
      } finally {
        // Restore defaults and clean up test data.
        await ctx.db.run(`UPDATE ddos_settings SET rate_limit_per_minute=60, block_duration=3600, http_get_threshold=300, slowloris_threshold=20`).catch(() => undefined);
        await ctx.db.run(`DELETE FROM ddos_profiles WHERE name LIKE 'T47%'`).catch(() => undefined);
        await ctx.db.run(`DELETE FROM ddos_profile_assignments`).catch(() => undefined);
        await ctx.db.run(`DELETE FROM ddos_vps_policies WHERE vps_id = 1`).catch(() => undefined);
        await ctx.db.run(`DELETE FROM ddos_whitelist WHERE ip = '203.0.113.100'`).catch(() => undefined);
        await ctx.db.run(`DELETE FROM ddos_integrations WHERE name LIKE 'T47%'`).catch(() => undefined);
        await ctx.db.run(`DELETE FROM users WHERE username = 'op_user'`).catch(() => undefined);
      }
    });

    await runStep('T15: LXC KVM Nesting (/dev/kvm passthrough), /proc RSS fallback & redesigned LXC Detail UI', async () => {
      const ctx = app.getHkvmV3Context();
      const { privilegedFs } = require('../lib/node-agent/command-runner');

      // Verify LXC Create Studio renders the KVM Nesting toggle (#cKvmNest)
      const createPage = await adminClient.request('GET', '/admin/instances/create?engine=lxc');
      assert.strictEqual(createPage.status, 200);
      assert.ok(createPage.text.includes('id="cKvmNest"'), 'Expected #cKvmNest toggle in LXC Create Studio');
      assert.ok(createPage.text.includes('/dev/kvm'), 'Expected /dev/kvm explanation in LXC Create Studio');

      // Provision a real LXC container with kvmNesting: true
      const createRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'kvm-nested-lxc-01',
        hostname: 'kvm-nested-01.hkvm.local',
        nodeId: 1,
        templateSlug: 'ubuntu-22.04',
        cpuCores: 4,
        ramMb: 4096,
        swapMb: 512,
        diskGb: 30,
        nesting: true,
        kvmNesting: true,
        autostart: true,
        provisionOnHost: true,
      });
      assert.strictEqual(createRes.status, 201, `Create KVM-nested LXC failed: ${createRes.text}`);
      const kvmCtId = createRes.json.instance.refId;

      const dbRow = await ctx.db.get(`SELECT kvm_nesting, nesting, autostart FROM lxc_instances WHERE id = ?`, [kvmCtId]);
      assert.strictEqual(dbRow.kvm_nesting, 1, 'Expected kvm_nesting=1 persisted in SQLite');

      const cfgPath = path.join(process.env.TGVPANEL_LXC_PATH, 'kvm-nested-lxc-01', 'config');
      const cfgTextOn = privilegedFs.readTextSync(cfgPath);
      assert.ok(
        cfgTextOn.includes('lxc.mount.entry = /dev/kvm dev/kvm none bind,optional,create=file 0 0'),
        'Expected /dev/kvm bind mount in container config'
      );
      assert.ok(
        cfgTextOn.includes('lxc.mount.entry = /dev/net/tun dev/net/tun none bind,optional,create=file 0 0'),
        'Expected /dev/net/tun bind mount in container config'
      );
      assert.ok(
        cfgTextOn.includes('devices.allow = c 10:232 rwm') && cfgTextOn.includes('devices.allow = c 10:200 rwm'),
        'Expected /dev/kvm (10:232) and /dev/net/tun (10:200) device allow rules'
      );
      assert.ok(
        cfgTextOn.includes('lxc.apparmor.profile = unconfined'),
        'Expected unconfined AppArmor profile when KVM nesting is enabled'
      );

      // Render redesigned LXC Detail Control Center (/lxc/:id)
      const detailPage = await adminClient.request('GET', `/lxc/${kvmCtId}`);
      assert.strictEqual(detailPage.status, 200, `GET /lxc/${kvmCtId} failed`);
      assert.ok(detailPage.text.includes('class="lxc-hero"'), 'Expected redesigned .lxc-hero header');
      assert.ok(detailPage.text.includes('id="pane-overview"'), 'Expected Overview & Specs pane');
      assert.ok(detailPage.text.includes('id="pane-resources"'), 'Expected Staff Resources & KVM pane');
      assert.ok(detailPage.text.includes('id="resKvmNesting" checked'), 'Expected #resKvmNesting checked for KVM-nested container');
      assert.ok(detailPage.text.includes('Enabled (/dev/kvm + /dev/net/tun)'), 'Expected KVM status badge on Overview pane');

      // Test WSL2 / undelegated cgroup-v2 /proc VmRSS telemetry fallback when lxc-info omits "Memory use:"
      const { execFileSync } = require('child_process');
      const omitMarker = path.join(process.env.TGVPANEL_LXC_PATH, 'kvm-nested-lxc-01', '.omit_mem_use');
      execFileSync('sudo', ['-n', 'touch', omitMarker]);
      const localCm = new LxcContainerManager(process.env.TGVPANEL_LXC_PATH);
      const inspected = await localCm.inspectContainer('kvm-nested-lxc-01');
      assert.strictEqual(inspected.state, 'running');
      assert.ok(inspected.pid > 0, 'Expected live container init PID');
      assert.ok(
        inspected.memoryBytes > 0,
        `Expected /proc descendant VmRSS fallback to report >0 bytes when lxc-info omits Memory use (got ${inspected.memoryBytes})`
      );
      const telFallback = await adminClient.request('GET', `/api/v1/instances/lxc/${kvmCtId}/telemetry`);
      assert.strictEqual(telFallback.status, 200);
      assert.strictEqual(telFallback.json.telemetry.status, 'running');
      execFileSync('sudo', ['-n', 'rm', '-f', omitMarker]);

      // Toggle kvmNesting OFF via PATCH /api/v1/lxc/:id -> verify rules cleanly stripped from config & DB
      const patchOff = await adminClient.request('PATCH', `/api/v1/lxc/${kvmCtId}`, {
        kvmNesting: false,
      });
      assert.strictEqual(patchOff.status, 200, `PATCH kvmNesting=false failed: ${patchOff.text}`);
      const dbRowOff = await ctx.db.get(`SELECT kvm_nesting FROM lxc_instances WHERE id = ?`, [kvmCtId]);
      assert.strictEqual(dbRowOff.kvm_nesting, 0);
      const cfgTextOff = privilegedFs.readTextSync(cfgPath);
      assert.ok(!cfgTextOff.includes('/dev/kvm'), 'Expected /dev/kvm mount removed when kvmNesting=false');
      assert.ok(!cfgTextOff.includes('10:232'), 'Expected c 10:232 rwm removed when kvmNesting=false');

      // Toggle kvmNesting back ON and reinstall -> verify reinstall preserves kvmNesting!
      const patchOn = await adminClient.request('PATCH', `/api/v1/lxc/${kvmCtId}`, {
        kvmNesting: true,
      });
      assert.strictEqual(patchOn.status, 200);
      const reinst = await adminClient.request('POST', `/api/v1/lxc/${kvmCtId}/reinstall`, {
        templateSlug: 'ubuntu:24.04',
      });
      assert.strictEqual(reinst.status, 200, `Reinstall failed: ${reinst.text}`);
      const cfgAfterReinst = privilegedFs.readTextSync(cfgPath);
      assert.ok(
        cfgAfterReinst.includes('lxc.mount.entry = /dev/kvm dev/kvm none bind,optional,create=file 0 0'),
        'Expected reinstall to preserve KVM nesting /dev/kvm passthrough'
      );

      // Cleanup container
      const del = await adminClient.request('POST', `/api/v1/instances/lxc/${kvmCtId}/action`, {
        action: 'delete',
      });
      assert.strictEqual(del.status, 200);
    });

    // 16. LXC Networking, Dangling stub-resolv.conf + WSL2 Tunnel DNS Fix, Netplan Sync & Live Repair API
    await runStep('T16: LXC Networking, stub-resolv.conf/WSL2 DNS fix, Netplan sync, Auto-IP & live repair-network API', async () => {
      const { execFileSync } = require('child_process');
      const { privilegedFs } = require('../lib/node-agent/command-runner');

      // Unit-verify subnet calculation & guest DNS resolver filtering (127.0.0.53 + WSL2 10.255.255.254 excluded!)
      assert.strictEqual(computeIpv4SubnetCidr('10.0.3.1', 24), '10.0.3.0/24');
      const filteredDns = resolveGuestDnsServers(
        '# systemd-resolved stub\nnameserver 127.0.0.53\nnameserver 10.255.255.254\nnameserver 192.168.50.1\n'
      );
      assert.ok(!filteredDns.includes('127.0.0.53'), 'Must strip host loopback stub 127.0.0.53');
      assert.ok(!filteredDns.includes('10.255.255.254'), 'Must strip non-bridge-routable WSL2 tunnel 10.255.255.254');
      assert.ok(filteredDns.includes('1.1.1.1') && filteredDns.includes('8.8.8.8'));
      assert.strictEqual(filteredDns.length, 3, 'Must respect glibc MAXNS=3 limit');

      // Verify built-in host BridgeDnsRelay (UDP + TCP + OS getaddrinfo synthesis for localhost!)
      const dgram = require('dgram');
      const { BridgeDnsRelay, parseDnsQuestion, synthesizeDnsFromOsLookup } = require('../lib/node-agent/dns-relay');
      // Build a real RFC 1035 query for "localhost" IN A (txId=0x4242)
      const qHeader = Buffer.from([0x42, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      const qBody = Buffer.concat([
        Buffer.from([9]),
        Buffer.from('localhost', 'ascii'),
        Buffer.from([0x00, 0x00, 0x01, 0x00, 0x01]),
      ]);
      const localhostQuery = Buffer.concat([qHeader, qBody]);
      const parsedQ = parseDnsQuestion(localhostQuery);
      assert.strictEqual(parsedQ.qname, 'localhost');
      assert.strictEqual(parsedQ.qtype, 1);

      const synthAns = await synthesizeDnsFromOsLookup(localhostQuery);
      assert.ok(synthAns && synthAns.length > localhostQuery.length, 'Expected synthesized A record for localhost');
      assert.strictEqual(synthAns.readUInt16BE(0), 0x4242);
      assert.strictEqual(synthAns.readUInt16BE(2) & 0x000f, 0, 'Expected NOERROR rcode');
      assert.ok(synthAns.readUInt16BE(6) >= 1, 'Expected ANCOUNT >= 1');

      const testRelay = new BridgeDnsRelay();
      // Point upstream to closed local port via env so relay exercises OS lookup fallback deterministically
      const prevDnsEnv = process.env.TGVPANEL_LXC_DNS;
      process.env.TGVPANEL_LXC_DNS = '127.0.0.254';
      const relayPort = await testRelay.ensureStarted();
      assert.ok(relayPort > 0, 'Expected BridgeDnsRelay to bind UDP+TCP port');
      const relayReply = await new Promise((resolve, reject) => {
        const client = dgram.createSocket('udp4');
        const t = setTimeout(() => {
          client.close();
          reject(new Error('BridgeDnsRelay UDP query timed out'));
        }, 4000);
        client.on('message', (msg) => {
          clearTimeout(t);
          client.close();
          resolve(msg);
        });
        client.send(localhostQuery, relayPort, '127.0.0.1');
      });
      assert.strictEqual(relayReply.readUInt16BE(0), 0x4242);
      assert.ok(relayReply.readUInt16BE(6) >= 1, 'BridgeDnsRelay resolved localhost over live UDP');
      testRelay.stop();
      if (prevDnsEnv === undefined) delete process.env.TGVPANEL_LXC_DNS;
      else process.env.TGVPANEL_LXC_DNS = prevDnsEnv;

      // Create an Ubuntu 22.04 container with static IP WITHOUT explicit gateway -> verify auto-gateway (.1),
      // dangling stub-resolv.conf symlink replacement, systemd-resolved drop-in, and Netplan 10-lxc.yaml sync!
      const createNetRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'net-fix-ubuntu-01',
        hostname: 'net-fix-01.hkvm.local',
        nodeId: 1,
        templateSlug: 'ubuntu-22.04',
        cpuCores: 2,
        ramMb: 1024,
        swapMb: 256,
        diskGb: 15,
        ipv4Address: '10.88.55.25/24',
        provisionOnHost: true,
      });
      assert.strictEqual(createNetRes.status, 201, `Create net-fix LXC failed: ${createNetRes.text}`);
      const netCtId = createNetRes.json.instance.refId;

      const ctDir = path.join(process.env.TGVPANEL_LXC_PATH, 'net-fix-ubuntu-01');
      const cfgTxt = privilegedFs.readTextSync(path.join(ctDir, 'config'));
      assert.ok(cfgTxt.includes('lxc.net.0.name = eth0'), 'Expected explicit eth0 interface name');
      assert.ok(cfgTxt.includes('lxc.net.0.ipv4.address = 10.88.55.25/24'), 'Expected static IPv4 CIDR');
      assert.ok(cfgTxt.includes('lxc.net.0.ipv4.gateway = 10.88.55.1'), 'Expected inferred .1 gateway when omitted');

      // Verify dangling ../run/systemd/resolve/stub-resolv.conf symlink was replaced by a real regular file!
      const resolvPath = path.join(ctDir, 'rootfs/etc/resolv.conf');
      const resolvMeta = privilegedFs.lstatMetaSync(resolvPath);
      assert.strictEqual(resolvMeta.isSymbolicLink, false, 'resolv.conf must be a regular file, not a dangling stub symlink');
      const resolvTxt = privilegedFs.readTextSync(resolvPath);
      assert.ok(resolvTxt.includes('nameserver 1.1.1.1') && resolvTxt.includes('nameserver 8.8.8.8'));
      assert.ok(!resolvTxt.includes('127.0.0.53'));

      // Verify systemd-resolved drop-in & Netplan 10-lxc.yaml were synchronized (so systemd-networkd never flushes eth0!)
      const dropinTxt = privilegedFs.readTextSync(
        path.join(ctDir, 'rootfs/etc/systemd/resolved.conf.d/99-hkvm-dns.conf')
      );
      assert.ok(dropinTxt.includes('DNS=1.1.1.1 8.8.8.8'));

      const netplanTxt = privilegedFs.readTextSync(path.join(ctDir, 'rootfs/etc/netplan/10-lxc.yaml'));
      assert.ok(netplanTxt.includes('dhcp4: false'), 'Netplan must disable dhcp4 when static/auto IP is set');
      assert.ok(netplanTxt.includes('10.88.55.25/24'), 'Netplan must match assigned IPv4 CIDR');
      assert.ok(netplanTxt.includes('via: 10.88.55.1'), 'Netplan must configure default route gateway');

      const nssTxt = privilegedFs.readTextSync(path.join(ctDir, 'rootfs/etc/nsswitch.conf'));
      assert.ok(!nssTxt.includes('[!UNAVAIL=return]'), 'nsswitch.conf must remove [!UNAVAIL=return] trap');
      assert.ok(nssTxt.includes('hosts:          files dns'), 'nsswitch.conf must prioritize direct files dns');

      // Verify collision-free auto-IP allocation helper
      const localCm = new LxcContainerManager(process.env.TGVPANEL_LXC_PATH);
      const autoIp1 = await localCm.allocateAutoBridgeIpv4('auto-ip-test-a', 'lxcbr0', '10.88.55.1', 24);
      assert.ok(autoIp1 && autoIp1.startsWith('10.88.55.') && autoIp1 !== '10.88.55.1/24' && autoIp1 !== '10.88.55.25/24');

      // Simulate broken DNS inside running container & invoke live POST /api/v1/lxc/:id/repair-network!
      execFileSync('sudo', ['-n', 'ln', '-sf', '../run/systemd/resolve/stub-resolv.conf', resolvPath]);
      const repairRes = await adminClient.request('POST', `/api/v1/lxc/${netCtId}/repair-network`, {});
      assert.strictEqual(repairRes.status, 200, `POST repair-network failed: ${repairRes.text}`);
      assert.strictEqual(repairRes.json.success, true);
      assert.strictEqual(repairRes.json.repair.ipv4Address, '10.88.55.25');
      assert.strictEqual(repairRes.json.repair.gateway, '10.88.55.1');
      assert.strictEqual(repairRes.json.repair.liveApplied, true);

      const liveNetLog = privilegedFs.readTextSync(path.join(ctDir, '.live_net'));
      assert.ok(liveNetLog.includes('ip link set eth0 up'), 'Expected live eth0 link up via lxc-attach');
      assert.ok(liveNetLog.includes('ip addr replace 10.88.55.25/24 dev eth0'), 'Expected live IPv4 injection');
      assert.ok(liveNetLog.includes('ip route replace default via 10.88.55.1 dev eth0'), 'Expected live default route injection');
      assert.ok(liveNetLog.includes('resolvectl dns eth0'), 'Expected live systemd-resolved DNS update via resolvectl');

      const repairedResolv = privilegedFs.readTextSync(resolvPath);
      assert.ok(repairedResolv.includes('nameserver 1.1.1.1'), 'Expected live repaired /etc/resolv.conf');

      // Also test remote Node Agent POST /api/v1/lxc/:id/repair-network via migrated/remote container
      const remoteCreate = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'net-fix-remote-02',
        nodeId: remoteNodeId,
        templateSlug: 'ubuntu-22.04',
        cpuCores: 1,
        ramMb: 512,
        diskGb: 10,
        ipv4Address: '10.88.66.30/24',
        provisionOnHost: true,
      });
      assert.strictEqual(remoteCreate.status, 201);
      const remoteCtId = remoteCreate.json.instance.refId;
      const remoteRepair = await adminClient.request('POST', `/api/v1/lxc/${remoteCtId}/repair-network`, {});
      assert.strictEqual(remoteRepair.status, 200, `Remote repair-network failed: ${remoteRepair.text}`);
      assert.strictEqual(remoteRepair.json.repair.ipv4Address, '10.88.66.30');

      // Cleanup both test containers
      await adminClient.request('POST', `/api/v1/instances/lxc/${netCtId}/action`, { action: 'delete' });
      await adminClient.request('POST', `/api/v1/instances/lxc/${remoteCtId}/action`, { action: 'delete' });
    });

    await runStep('T17: WSL2 BridgeDnsRelay TCP/AAAA fast-path, loop prevention & iptables-legacy/modprobe allowlist', async () => {
      const net = require('net');
      const { BridgeDnsRelay, synthesizeDnsFromOsLookup } = require('../lib/node-agent/dns-relay');
      const { isAllowlistedBinary } = require('../lib/node-agent/command-runner');

      // 1. Verify dual iptables-legacy & modprobe allowlist without weakening shell restrictions
      assert.ok(isAllowlistedBinary('lxc-copy'), 'Native LXC clone utility should be allowlisted');
      assert.ok(isAllowlistedBinary('iptables-legacy'), 'Expected iptables-legacy in allowlist');
      assert.ok(isAllowlistedBinary('ip6tables-legacy'), 'Expected ip6tables-legacy in allowlist');
      assert.ok(isAllowlistedBinary('modprobe'), 'Expected modprobe in allowlist');
      assert.ok(!isAllowlistedBinary('sh') && !isAllowlistedBinary('bash') && !isAllowlistedBinary('sudo'));

      // 2. Verify AAAA (qtype=28) synthesis returns instant empty NOERROR (rcode=0) instead of timing out when IPv4 exists
      const aaaaHeader = Buffer.from([0x51, 0x52, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      const ipv4OnlyHost = '127.0.0.1';
      const labels = ipv4OnlyHost.split('.').map((lbl) => Buffer.concat([Buffer.from([lbl.length]), Buffer.from(lbl, 'ascii')]));
      const aaaaQuery = Buffer.concat([aaaaHeader, ...labels, Buffer.from([0x00, 0x00, 0x1c, 0x00, 0x01])]);
      const aaaaSynth = await synthesizeDnsFromOsLookup(aaaaQuery);
      assert.ok(aaaaSynth && aaaaSynth.length >= 12);
      assert.strictEqual(aaaaSynth.readUInt16BE(0), 0x5152);
      assert.strictEqual(aaaaSynth.readUInt16BE(2) & 0x000f, 0, 'AAAA for IPv4-only host must return instant NOERROR');
      assert.strictEqual(aaaaSynth.readUInt16BE(6), 0, 'AAAA for IPv4-only host must have 0 answers');

      // 3. Verify live RFC 1035 DNS-over-TCP framing (2-byte big-endian length prefix) + bridge IP loop exclusion
      const relay = new BridgeDnsRelay();
      relay.addExcludedLoopIp('10.0.3.1');
      const port = await relay.ensureStarted();
      assert.ok(port > 0);

      const tcpQ = Buffer.concat([
        Buffer.from([0x77, 0x88, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        Buffer.from([9]),
        Buffer.from('localhost', 'ascii'),
        Buffer.from([0x00, 0x00, 0x01, 0x00, 0x01]),
      ]);
      const framed = Buffer.alloc(2 + tcpQ.length);
      framed.writeUInt16BE(tcpQ.length, 0);
      tcpQ.copy(framed, 2);

      const tcpReply = await new Promise((resolve, reject) => {
        const sock = net.createConnection({ host: '127.0.0.1', port }, () => {
          sock.write(framed);
        });
        let buf = Buffer.alloc(0);
        const timer = setTimeout(() => {
          sock.destroy();
          reject(new Error('TCP DNS relay query timed out'));
        }, 4000);
        sock.on('data', (chunk) => {
          buf = Buffer.concat([buf, chunk]);
          if (buf.length >= 2) {
            const len = buf.readUInt16BE(0);
            if (buf.length >= 2 + len) {
              clearTimeout(timer);
              sock.end();
              resolve(buf.subarray(2, 2 + len));
            }
          }
        });
        sock.on('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });

      assert.strictEqual(tcpReply.readUInt16BE(0), 0x7788);
      assert.strictEqual(tcpReply.readUInt16BE(2) & 0x000f, 0);
      assert.ok(tcpReply.readUInt16BE(6) >= 1, 'Expected TCP DNS relay to return >=1 A record for localhost');
      relay.stop();
    });

    await runStep('T18: LXC hard disk quota (sparse ext4 loop volume + live resize), cpuset isolation & cgroup preservation', async () => {
      const { execFileSync } = require('child_process');
      const {
        LxcContainerManager,
        parseCpuListSpec,
        selectContainerCpuset,
      } = require('../lib/node-agent/container-manager');
      const { findActiveMountSource, privilegedFs, canPasswordlessSudo, isRunningAsRoot } =
        require('../lib/node-agent/command-runner');

      // 1. Verify CPU list parser & deterministic vCPU pinning
      assert.deepStrictEqual(parseCpuListSpec('0-2,5'), [0, 1, 2, 5]);
      const pin1 = selectContainerCpuset('test', 1, [0, 1, 2, 3]);
      assert.strictEqual(pin1.split(',').length, 1, '1 vCPU must pin to 1 CPU');
      const pin2 = selectContainerCpuset('test', 2, [0, 1, 2, 3]);
      assert.strictEqual(pin2.split(',').length, 2, '2 vCPUs must pin to 2 distinct CPUs');
      assert.strictEqual(selectContainerCpuset('test', 2, [0, 1, 2, 3], '1-2'), '1-2');

      // 2. Verify writeManagedConfigSection writes memory.max, cpu.max, and cpuset.cpus
      const quotaStore = path.join(tmpRoot, 'quota-lxc-store');
      const ctName = 'quota-disk-e2e';
      const ctDir = path.join(quotaStore, ctName);
      const rootfsDir = path.join(ctDir, 'rootfs');
      fs.mkdirSync(path.join(rootfsDir, 'etc'), { recursive: true });
      fs.mkdirSync(path.join(rootfsDir, 'root'), { recursive: true });
      fs.writeFileSync(path.join(rootfsDir, 'etc', 'hostname'), `${ctName}\n`);
      fs.writeFileSync(path.join(rootfsDir, 'root', 'keep.txt'), 'HKVM_QUOTA_PRESERVED_DATA\n');
      fs.writeFileSync(
        path.join(ctDir, 'config'),
        `lxc.rootfs.path = dir:${rootfsDir}\nlxc.uts.name = ${ctName}\n`
      );

      const qCm = new LxcContainerManager(quotaStore);
      await qCm.writeManagedConfigSection(ctName, {
        hostname: ctName,
        cpuCores: 1,
        ramMb: 1024,
        swapMb: 512,
        nesting: true,
        kvmNesting: true,
        bridge: 'lxcbr0',
      });
      const cfgWritten = privilegedFs.readTextSync(path.join(ctDir, 'config'));
      assert.ok(cfgWritten.includes('memory.max = 1024M') || cfgWritten.includes('memory.limit_in_bytes = 1024M'));
      assert.ok(cfgWritten.includes('cpuset.cpus ='));

      // 3. Test real sparse ext4 loop quota volume creation (1 GB) + live online resize (2 GB)
      if (isRunningAsRoot() || canPasswordlessSudo()) {
        try {
          const mounted1G = await qCm.ensureContainerQuotaDisk(ctName, 1, { allowNonSystemStore: true });
          assert.strictEqual(mounted1G, true, 'Expected 1 GB sparse ext4 loop quota disk to mount');
          assert.ok(findActiveMountSource(rootfsDir), 'Expected active /dev/loopX mount on rootfs');

          const preserved = privilegedFs.readTextSync(path.join(rootfsDir, 'root', 'keep.txt'));
          assert.strictEqual(preserved.trim(), 'HKVM_QUOTA_PRESERVED_DATA');

          const df1Out = execFileSync('df', ['-B1', '--output=size', rootfsDir], { encoding: 'utf8' });
          const size1Bytes = parseInt(df1Out.trim().split('\n').pop().trim(), 10);
          assert.ok(
            size1Bytes > 850 * 1024 * 1024 && size1Bytes < 1150 * 1024 * 1024,
            `Expected ~1 GB filesystem in df (not host 32G!), got ${size1Bytes} bytes`
          );

          // Live online resize from 1 GB -> 2 GB while mounted!
          const resized2G = await qCm.ensureContainerQuotaDisk(ctName, 2, { allowNonSystemStore: true });
          assert.strictEqual(resized2G, true, 'Expected online live resize to 2 GB to succeed');
          const df2Out = execFileSync('df', ['-B1', '--output=size', rootfsDir], { encoding: 'utf8' });
          const size2Bytes = parseInt(df2Out.trim().split('\n').pop().trim(), 10);
          assert.ok(
            size2Bytes > 1800 * 1024 * 1024 && size2Bytes < 2200 * 1024 * 1024,
            `Expected ~2 GB filesystem after live resize, got ${size2Bytes} bytes`
          );
          assert.strictEqual(
            privilegedFs.readTextSync(path.join(rootfsDir, 'root', 'keep.txt')).trim(),
            'HKVM_QUOTA_PRESERVED_DATA'
          );
        } finally {
          await qCm.unmountQuotaDiskIfMounted(ctName, true);
          assert.strictEqual(findActiveMountSource(rootfsDir), null, 'Expected loop mount cleanly detached');
        }
      }
    });

    await runStep('T19: Real kernel cgroup v2 delegation (init.scope + hkvm.lxc), legacy hkvm.host migration & live RAM/CPU enforcement', async () => {
      const { spawn, execFileSync } = require('child_process');
      const {
        LxcContainerManager,
        resolveHostBaseCgroupV2Dir,
        ensureCgroupV2SubtreeDelegation,
        resolveLiveContainerCgroupV2Dir,
        readCgroupV2Type,
        isUsableDomainCgroupDir,
      } = require('../lib/node-agent/container-manager');
      const { privilegedFs, canPasswordlessSudo, isRunningAsRoot } =
        require('../lib/node-agent/command-runner');

      // 1. Verify `/init.scope` and legacy `/hkvm.host` stripping for liblxc & lxcfs `prune_init_scope` parity
      assert.strictEqual(resolveHostBaseCgroupV2Dir('0::/init.scope\n'), '/sys/fs/cgroup');
      assert.strictEqual(resolveHostBaseCgroupV2Dir('0::/hkvm.host\n'), '/sys/fs/cgroup');

      // 2. Verify granular `startContainer` cgroup fallback NEVER wipes `memory.max` or `cpuset.cpus`
      // when `devices.allow` fails on first start attempt!
      const stageCtRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'cgroup-stage-preserve-01',
        nodeId: 1,
        templateSlug: 'ubuntu-22.04',
        cpuCores: 1,
        ramMb: 1024,
        swapMb: 512,
        diskGb: 10,
        kvmNesting: true,
        provisionOnHost: true,
      });
      assert.strictEqual(stageCtRes.status, 201, `Create stage test LXC failed: ${stageCtRes.text}`);
      const stageCtId = stageCtRes.json.instance.refId;
      await adminClient.request('POST', `/api/v1/instances/lxc/${stageCtId}/action`, { action: 'stop' });

      const stageCtDir = path.join(process.env.TGVPANEL_LXC_PATH, 'cgroup-stage-preserve-01');
      privilegedFs.writeFileSync(path.join(stageCtDir, '.fail_cgroup_once'), '1');
      const stageStartRes = await adminClient.request('POST', `/api/v1/instances/lxc/${stageCtId}/action`, {
        action: 'start',
      });
      assert.strictEqual(stageStartRes.status, 200, `Staged start failed: ${stageStartRes.text}`);
      const postStageCfg = privilegedFs.readTextSync(path.join(stageCtDir, 'config'));
      assert.ok(
        postStageCfg.includes('memory.max = 1024M') || postStageCfg.includes('memory.limit_in_bytes = 1024M'),
        'Stage 1 devices strip must preserve memory.max = 1024M!'
      );
      assert.ok(postStageCfg.includes('cpuset.cpus ='), 'Stage 1 devices strip must preserve cpuset.cpus!');
      assert.ok(postStageCfg.includes('# hkvm.limits: ram_mb=1024'), 'Expected # hkvm.limits metadata comment');
      await adminClient.request('POST', `/api/v1/instances/lxc/${stageCtId}/action`, { action: 'delete' });

      // 3. Real Linux 6.8 cgroup v2 hierarchy test: legacy `/hkvm.host` evacuation -> `/init.scope`,
      // `/hkvm.lxc` controller delegation, live `memory.max` (1024 MiB -> 2048 MiB), `cpu.max`, & `nproc=1`!
      if ((isRunningAsRoot() || canPasswordlessSudo()) && fs.existsSync('/sys/fs/cgroup/cgroup.controllers')) {
        let sleeper = null;
        const payloadCg = '/sys/fs/cgroup/hkvm.lxc/lxc.payload.cgroup-e2e-01';
        const legacyHostCg = '/sys/fs/cgroup/hkvm.host';
        const legacyBrokenPayload = '/sys/fs/cgroup/hkvm.host/lxc.payload.broken-01';
        try {
          sleeper = spawn('sleep', ['30'], { stdio: 'ignore' });
          assert.ok(sleeper.pid > 1);

          // Simulate PR #13 broken state: process placed in `/sys/fs/cgroup/hkvm.host`
          execFileSync('sudo', ['-n', 'mkdir', '-p', legacyBrokenPayload]);
          privilegedFs.writeFileSync(path.join(legacyHostCg, 'cgroup.procs'), `${sleeper.pid}\n`);
          ensureCgroupV2SubtreeDelegation();

          const migratedCg = resolveLiveContainerCgroupV2Dir(sleeper.pid);
          assert.strictEqual(
            migratedCg,
            '/sys/fs/cgroup/init.scope',
            `Expected PID migrated from /hkvm.host into /init.scope, got ${migratedCg}`
          );

          const hkvmLxcSub = fs.readFileSync('/sys/fs/cgroup/hkvm.lxc/cgroup.subtree_control', 'utf8');
          assert.ok(hkvmLxcSub.includes('memory'), 'Expected +memory delegated on /sys/fs/cgroup/hkvm.lxc');
          assert.ok(hkvmLxcSub.includes('cpu'), 'Expected +cpu delegated on /sys/fs/cgroup/hkvm.lxc');
          assert.ok(hkvmLxcSub.includes('cpuset'), 'Expected +cpuset delegated on /sys/fs/cgroup/hkvm.lxc');

          // Verify `needsContainerCgroupRestartOrHeal` flags processes trapped in `/hkvm.host/lxc.payload.*`
          privilegedFs.writeFileSync(path.join(legacyBrokenPayload, 'cgroup.procs'), `${sleeper.pid}\n`);
          const cmTest = new LxcContainerManager(process.env.TGVPANEL_LXC_PATH);
          const brokenDiag = cmTest.needsContainerCgroupRestartOrHeal('broken-01', sleeper.pid, {
            ramMb: 1024,
            cpuCores: 1,
          });
          assert.strictEqual(brokenDiag.requiresRestart, true, 'Trapped /hkvm.host container must trigger restart');

          // Move sleeper into real `/sys/fs/cgroup/hkvm.lxc/lxc.payload.cgroup-e2e-01` and enforce 1024 MB + 1 vCPU!
          execFileSync('sudo', ['-n', 'mkdir', '-p', payloadCg]);
          privilegedFs.writeFileSync(path.join(payloadCg, 'cgroup.procs'), `${sleeper.pid}\n`);
          const enforced = await cmTest.enforceLiveContainerCgroups('cgroup-e2e-01', {
            ramMb: 1024,
            swapMb: 512,
            cpuCores: 1,
            cpuLimitPercent: 100,
            pid: sleeper.pid,
          });
          assert.strictEqual(enforced, true, 'Expected live cgroup v2 enforcement to succeed');
          assert.strictEqual(
            fs.readFileSync(path.join(payloadCg, 'memory.max'), 'utf8').trim(),
            String(1024 * 1024 * 1024),
            'Expected exact 1073741824 bytes (1024 MiB) in memory.max'
          );
          assert.strictEqual(
            fs.readFileSync(path.join(payloadCg, 'cpu.max'), 'utf8').trim(),
            '100000 100000',
            'Expected exact 1 vCPU CFS quota in cpu.max'
          );
          const cpusetAssigned = fs.readFileSync(path.join(payloadCg, 'cpuset.cpus'), 'utf8').trim();
          assert.strictEqual(cpusetAssigned.split(',').length, 1, 'Expected 1 CPU core pinned in cpuset.cpus');

          // Spawn a real subshell inside `payloadCg` and verify kernel `nproc` reports `1`!
          const nprocOut = execFileSync(
            'sudo',
            ['-n', 'sh', '-c', `echo $$ > ${payloadCg}/cgroup.procs && nproc`],
            { encoding: 'utf8' }
          ).trim();
          assert.strictEqual(nprocOut, '1', `Expected guest nproc inside 1-vCPU cgroup to be 1, got ${nprocOut}`);

          // Live hot-scale RAM to 2048 MiB without restart!
          await cmTest.enforceLiveContainerCgroups('cgroup-e2e-01', {
            ramMb: 2048,
            cpuCores: 1,
            pid: sleeper.pid,
          });
          assert.strictEqual(
            fs.readFileSync(path.join(payloadCg, 'memory.max'), 'utf8').trim(),
            String(2048 * 1024 * 1024),
            'Expected live RAM hot-scale to 2048 MiB in memory.max'
          );
        } finally {
          if (sleeper) {
            try { sleeper.kill('SIGKILL'); } catch (_) {}
            await new Promise((r) => setTimeout(r, 80));
          }
          for (const cg of [payloadCg, legacyBrokenPayload, legacyHostCg]) {
            try { execFileSync('sudo', ['-n', 'rmdir', cg]); } catch (_) {}
          }
        }

        // 4. Real Linux 6.8 cgroup-namespace `"domain threaded"` -> `"domain invalid"` (`ENOTSUP` / `-95`)
        // reproduction & live self-heal regression test (exact `cgfsng.c:3341` + `cgfsng.c:1539` fix)!
        const simCgnsRoot = '/sys/fs/cgroup/tgv_t19_cgns_root';
        const simInitScope = path.join(simCgnsRoot, 'init.scope');
        const simHkvmLxc = path.join(simCgnsRoot, 'hkvm.lxc');
        const simMonitor = path.join(simHkvmLxc, 'lxc.monitor.test');
        const simPayload = path.join(simHkvmLxc, 'lxc.payload.test');
        let hostPid1Sim = null;
        let monPidSim = null;
        let payPidSim = null;
        try {
          // Ensure parent `/sys/fs/cgroup` delegates all available controllers into `simCgnsRoot`
          ensureCgroupV2SubtreeDelegation('/sys/fs/cgroup');
          execFileSync('sudo', ['-n', 'mkdir', '-p', simCgnsRoot]);

          hostPid1Sim = spawn('sleep', ['30'], { stdio: 'ignore' });
          monPidSim = spawn('sleep', ['30'], { stdio: 'ignore' });
          payPidSim = spawn('sleep', ['30'], { stdio: 'ignore' });

          // Reproduce broken cgroup-namespace state: host task inside `simCgnsRoot/cgroup.procs`
          // while threaded controllers (`+cpu +cpuset +pids`) were enabled BEFORE evacuating `cgroup.procs`!
          privilegedFs.writeFileSync(path.join(simCgnsRoot, 'cgroup.procs'), `${hostPid1Sim.pid}\n`);
          privilegedFs.writeFileSync(path.join(simCgnsRoot, 'cgroup.subtree_control'), '+cpu +cpuset +pids');
          execFileSync('sudo', ['-n', 'mkdir', '-p', simInitScope, simHkvmLxc, simMonitor]);

          assert.strictEqual(readCgroupV2Type(simCgnsRoot), 'domain threaded');
          assert.strictEqual(readCgroupV2Type(simInitScope), 'domain invalid');
          assert.strictEqual(readCgroupV2Type(simHkvmLxc), 'domain invalid');
          assert.strictEqual(isUsableDomainCgroupDir(simHkvmLxc), false);

          // Confirm exact `liblxc` `cgfsng.c:3341` + `cgfsng.c:1539` `ENOTSUP` failures BEFORE heal
          const simAvailCtrls = fs
            .readFileSync(path.join(simCgnsRoot, 'cgroup.controllers'), 'utf8')
            .trim()
            .split(/\s+/)
            .filter(Boolean);
          const liblxcDelegateStr = simAvailCtrls.map((c) => `+${c}`).join(' ');
          assert.throws(
            () => privilegedFs.writeFileSync(path.join(simCgnsRoot, 'cgroup.subtree_control'), liblxcDelegateStr),
            /Operation not supported|ENOTSUP/i
          );
          assert.throws(
            () => privilegedFs.writeFileSync(path.join(simMonitor, 'cgroup.procs'), `${monPidSim.pid}\n`),
            /Operation not supported|ENOTSUP/i
          );

          // Now run `ensureCgroupV2SubtreeDelegation(simCgnsRoot)` — must heal `domain threaded` -> `domain`,
          // evacuate `hostPid1Sim` into `simCgnsRoot/init.scope`, and delegate ALL controllers on `hkvm.lxc`!
          ensureCgroupV2SubtreeDelegation(simCgnsRoot);

          assert.strictEqual(readCgroupV2Type(simCgnsRoot), 'domain');
          assert.strictEqual(fs.readFileSync(path.join(simCgnsRoot, 'cgroup.procs'), 'utf8').trim(), '');
          assert.strictEqual(readCgroupV2Type(simInitScope), 'domain');
          assert.ok(
            fs.readFileSync(path.join(simInitScope, 'cgroup.procs'), 'utf8').includes(String(hostPid1Sim.pid)),
            'Expected host process evacuated into simCgnsRoot/init.scope'
          );
          assert.strictEqual(readCgroupV2Type(simHkvmLxc), 'domain');
          assert.strictEqual(isUsableDomainCgroupDir(simHkvmLxc), true);

          // Verify `liblxc` `__cgfsng_delegate_controllers` + `cgfsng_monitor_enter` + payload limits now SUCCEED!
          privilegedFs.writeFileSync(path.join(simCgnsRoot, 'cgroup.subtree_control'), liblxcDelegateStr);
          privilegedFs.writeFileSync(path.join(simHkvmLxc, 'cgroup.subtree_control'), liblxcDelegateStr);
          execFileSync('sudo', ['-n', 'mkdir', '-p', simMonitor, simPayload]);
          privilegedFs.writeFileSync(path.join(simMonitor, 'cgroup.procs'), `${monPidSim.pid}\n`);
          privilegedFs.writeFileSync(path.join(simPayload, 'cgroup.procs'), `${payPidSim.pid}\n`);
          privilegedFs.writeFileSync(path.join(simPayload, 'memory.max'), `${512 * 1024 * 1024}\n`);
          assert.strictEqual(
            fs.readFileSync(path.join(simPayload, 'memory.max'), 'utf8').trim(),
            String(512 * 1024 * 1024)
          );

          // 5. Verify `restoreStrippedCgroupDirectivesIfReady()` heals a container `config` whose
          // `lxc.cgroup.dir = hkvm.lxc` and `lxc.cgroup2.memory.max` were stripped during an earlier failed start!
          const healCfgDir = path.join(process.env.TGVPANEL_LXC_PATH, 'stripped-test-heal');
          fs.mkdirSync(healCfgDir, { recursive: true });
          fs.writeFileSync(
            path.join(healCfgDir, 'config'),
            [
              '# --- BEGIN HKVM MANAGED CONFIG ---',
              '# hkvm.limits: ram_mb=1024 swap_mb=256 cpu_cores=2 cpu_pct=100 pinning=',
              'lxc.uts.name = stripped-test-heal',
              '# --- END HKVM MANAGED CONFIG ---',
              '',
            ].join('\n')
          );
          const cmHeal = new LxcContainerManager(process.env.TGVPANEL_LXC_PATH);
          const didRestore = cmHeal.restoreStrippedCgroupDirectivesIfReady('stripped-test-heal');
          assert.strictEqual(didRestore, true, 'Expected stripped cgroup directives to be restored');
          const restoredCfgTxt = fs.readFileSync(path.join(healCfgDir, 'config'), 'utf8');
          assert.ok(restoredCfgTxt.includes('lxc.cgroup.dir = hkvm.lxc'), 'Expected lxc.cgroup.dir = hkvm.lxc restored');
          assert.ok(restoredCfgTxt.includes('lxc.cgroup2.memory.max = 1024M'), 'Expected memory.max = 1024M restored');
          assert.ok(restoredCfgTxt.includes('lxc.cgroup2.cpu.max = 200000 100000'), 'Expected cpu.max = 200000 100000 restored');
          fs.rmSync(healCfgDir, { recursive: true, force: true });
        } finally {
          for (const p of [hostPid1Sim, monPidSim, payPidSim]) {
            if (p) {
              try { p.kill('SIGKILL'); } catch (_) {}
            }
          }
          await new Promise((r) => setTimeout(r, 80));
          for (const cg of [simPayload, simMonitor, simHkvmLxc, simInitScope, simCgnsRoot]) {
            try { execFileSync('sudo', ['-n', 'rmdir', cg]); } catch (_) {}
          }
        }
      }
    });

    await runStep('T20: KVM VM deletion (DELETE /api/vms/:id & Unified /api/v1/instances) permanently removes VM across page refreshes', async () => {
      const vmDir = path.join(os.homedir(), 'vms');
      fs.mkdirSync(vmDir, { recursive: true });

      // 1. Test `DELETE /api/vms/:vm_id` on a VM with active `vm_logs`, `vm_snapshots`, disk/seed files & `instances` registry row
      const disk1 = path.join(tmpRoot, 'vm-del-test-1.qcow2');
      const seed1 = path.join(tmpRoot, 'vm-del-test-1-seed.iso');
      fs.writeFileSync(disk1, 'qcow2-test-bytes');
      fs.writeFileSync(seed1, 'seed-test-bytes');

      const ins1 = await ctx.db.run(
        `INSERT INTO vms (vm_name, hostname, owner_id, memory, cpus, disk_size, disk_file, seed_file, status, password)
         VALUES ('delete-persist-vm-01', 'del-vm-01', 1, 2048, 2, '20G', ?, ?, 'stopped', ?)`,
        [disk1, seed1, encryptSecret('DelPass1!')]
      );
      const delVmId1 = ins1.lastID;
      await ctx.db.run(
        `INSERT INTO vm_logs (vm_id, action, status, message) VALUES (?, 'create', 'pending', 'VM created')`,
        [delVmId1]
      );
      await ctx.db.run(
        `INSERT INTO vm_logs (vm_id, action, status, message) VALUES (?, 'start', 'running', 'VM started')`,
        [delVmId1]
      );
      await ctx.db.run(
        `INSERT INTO vm_snapshots (vm_id, snapshot_name, size_gb, description) VALUES (?, 'pre-delete-snap', 0.5, 'test snap')`,
        [delVmId1]
      );
      await ctx.kvmAdapter.syncRegistryRow(delVmId1);

      // Verify VM appears in all 3 refresh endpoints BEFORE deletion
      const beforeAdminList = await adminClient.request('GET', '/api/admin/vms');
      assert.strictEqual(beforeAdminList.status, 200);
      assert.ok(beforeAdminList.json.some((v) => v.vm_id === delVmId1), 'Expected VM in /api/admin/vms before delete');

      const beforeUserList = await adminClient.request('GET', '/api/vms');
      assert.strictEqual(beforeUserList.status, 200);
      assert.ok(beforeUserList.json.some((v) => v.vm_id === delVmId1), 'Expected VM in /api/vms before delete');

      const beforeUnifiedList = await adminClient.request('GET', '/api/v1/instances?engine=kvm');
      assert.strictEqual(beforeUnifiedList.status, 200);
      assert.ok(
        beforeUnifiedList.json.instances.some((i) => i.engine === 'kvm' && i.refId === delVmId1),
        'Expected VM in /api/v1/instances before delete'
      );

      // Delete via `DELETE /api/vms/:vm_id` (used by `/admin/vms`, `/admin/vm/:id`, `/vm/:id`)
      const delRes1 = await adminClient.request('DELETE', `/api/vms/${delVmId1}`);
      assert.strictEqual(delRes1.status, 200, `DELETE /api/vms/${delVmId1} failed: ${delRes1.text}`);
      assert.strictEqual(delRes1.json.success, true);

      // Simulate page refresh immediately after delete — VM must NOT reappear anywhere!
      const afterAdminList = await adminClient.request('GET', '/api/admin/vms');
      assert.strictEqual(afterAdminList.status, 200);
      assert.ok(
        String(afterAdminList.headers['cache-control'] || '').includes('no-store'),
        'Expected Cache-Control: no-store on /api/admin/vms'
      );
      assert.strictEqual(
        afterAdminList.json.some((v) => v.vm_id === delVmId1),
        false,
        'Deleted VM must NOT reappear in /api/admin/vms on refresh!'
      );

      const afterUserList = await adminClient.request('GET', '/api/vms');
      assert.strictEqual(
        afterUserList.json.some((v) => v.vm_id === delVmId1),
        false,
        'Deleted VM must NOT reappear in /api/vms on refresh!'
      );

      const afterUnifiedList = await adminClient.request('GET', '/api/v1/instances?engine=kvm');
      assert.strictEqual(
        afterUnifiedList.json.instances.some((i) => i.engine === 'kvm' && i.refId === delVmId1),
        false,
        'Deleted VM must NOT reappear in /api/v1/instances on refresh!'
      );

      assert.strictEqual((await adminClient.request('GET', `/api/vms/${delVmId1}`)).status, 404);
      assert.strictEqual(fs.existsSync(disk1), false, 'Expected VM disk file removed');
      assert.strictEqual(fs.existsSync(seed1), false, 'Expected VM seed file removed');
      assert.strictEqual((await ctx.db.all(`SELECT * FROM vm_logs WHERE vm_id = ?`, [delVmId1])).length, 0);
      assert.strictEqual((await ctx.db.all(`SELECT * FROM vm_snapshots WHERE vm_id = ?`, [delVmId1])).length, 0);

      // 2. Test Unified Instance delete (`POST /api/v1/instances/kvm/:id/action` `{ action: 'delete' }`)
      const ins2 = await ctx.db.run(
        `INSERT INTO vms (vm_name, hostname, owner_id, memory, cpus, disk_size, status, password)
         VALUES ('delete-persist-vm-02', 'del-vm-02', 1, 1024, 1, '10G', 'stopped', ?)`,
        [encryptSecret('DelPass2!')]
      );
      const delVmId2 = ins2.lastID;
      await ctx.db.run(
        `INSERT INTO vm_logs (vm_id, action, status, message) VALUES (?, 'create', 'pending', 'VM 2 created')`,
        [delVmId2]
      );
      await ctx.db.run(
        `INSERT INTO vm_snapshots (vm_id, snapshot_name, size_gb, description) VALUES (?, 'snap-2', 0.2, 'snap')`,
        [delVmId2]
      );
      await ctx.kvmAdapter.syncRegistryRow(delVmId2);

      const delRes2 = await adminClient.request('POST', `/api/v1/instances/kvm/${delVmId2}/action`, {
        action: 'delete',
      });
      assert.strictEqual(delRes2.status, 200, `Unified KVM delete failed: ${delRes2.text}`);

      const afterAdminList2 = await adminClient.request('GET', '/api/admin/vms');
      assert.strictEqual(
        afterAdminList2.json.some((v) => v.vm_id === delVmId2),
        false,
        'Unified-deleted KVM VM must NOT reappear in /api/admin/vms!'
      );
      const afterUnifiedList2 = await adminClient.request('GET', '/api/v1/instances');
      assert.strictEqual(
        afterUnifiedList2.json.instances.some((i) => i.engine === 'kvm' && i.refId === delVmId2),
        false,
        'Unified-deleted KVM VM must NOT reappear in /api/v1/instances!'
      );
    });

    // 21. Advanced Node Studio Features (Pre-flight Probe, Inspector, Tags/Quotas, Cordon & Placement Advisor, Circuit Reset)
    await runStep('T21: Cluster Node Studio features (pre-flight probe, inspector detail, tags/quotas, cordon & placement advisor, circuit reset)', async () => {
      // 21a. Pre-flight connection probe against live loopback agent AND closed port
      const okProbe = await adminClient.request('POST', '/api/v1/nodes/test-connection', {
        url: `http://127.0.0.1:${AGENT_PORT}`,
        verifySsl: false,
      });
      assert.strictEqual(okProbe.status, 200, `Expected 200 from test-connection: ${okProbe.text}`);
      assert.strictEqual(okProbe.json.reachable, true);
      assert.strictEqual(okProbe.json.agentDetected, true);
      assert.ok(Number(okProbe.json.latencyMs) >= 1);

      const failProbe = await adminClient.request('POST', '/api/v1/nodes/test-connection', {
        url: 'http://127.0.0.1:59999',
        verifySsl: false,
        timeoutMs: 1200,
      });
      assert.strictEqual(failProbe.status, 200);
      assert.strictEqual(failProbe.json.reachable, false);
      assert.ok(String(failProbe.json.message || '').includes('Unreachable'));

      // 21b. Enriched /api/v1/nodes & /api/v1/nodes/1/detail
      const listRes = await adminClient.request('GET', '/api/v1/nodes');
      assert.strictEqual(listRes.status, 200);
      const localNode = listRes.json.nodes.find((n) => n.id === 1);
      assert.ok(localNode, 'Expected localhost node #1');
      assert.strictEqual(typeof localNode.total_instances, 'number');
      assert.strictEqual(typeof localNode.allocated_vcpus, 'number');
      assert.strictEqual(typeof localNode.allocated_ram_mb, 'number');

      const detailRes = await adminClient.request('GET', '/api/v1/nodes/1/detail');
      assert.strictEqual(detailRes.status, 200, `Node detail failed: ${detailRes.text}`);
      assert.strictEqual(detailRes.json.node.id, 1);
      assert.ok(Array.isArray(detailRes.json.instances), 'Expected hosted instances array in node detail');
      assert.ok(Array.isArray(detailRes.json.storagePools), 'Expected storagePools array in node detail');
      assert.ok(detailRes.json.liveStats && typeof detailRes.json.liveStats.cpuPercent === 'number');

      // 21c. Update tags, notes, maxInstances & Cordon (maintenanceMode), then verify Placement Advisor
      const patchCordon = await adminClient.request('PATCH', '/api/v1/nodes/1', {
        tags: 'nvme, production, controller',
        notes: 'Primary bare-metal NVMe controller',
        maxInstances: 250,
        maintenanceMode: true,
      });
      assert.strictEqual(patchCordon.status, 200, `PATCH node failed: ${patchCordon.text}`);
      assert.strictEqual(patchCordon.json.node.maintenance_mode, 1);
      assert.strictEqual(patchCordon.json.node.max_instances, 250);
      assert.deepStrictEqual(JSON.parse(patchCordon.json.node.tags), ['nvme', 'production', 'controller']);

      const placeCordoned = await adminClient.request('GET', '/api/v1/nodes/placement');
      assert.strictEqual(placeCordoned.status, 200);
      const localKvmRank = placeCordoned.json.kvm.find((c) => c.nodeId === 1);
      assert.strictEqual(localKvmRank.eligible, false, 'Cordoned node must be ineligible in Placement Advisor');

      const patchUncordon = await adminClient.request('PATCH', '/api/v1/nodes/1', {
        maintenanceMode: false,
      });
      assert.strictEqual(patchUncordon.status, 200);
      assert.strictEqual(patchUncordon.json.node.maintenance_mode, 0);

      const placeActive = await adminClient.request('GET', '/api/v1/nodes/placement');
      const localKvmRankAfter = placeActive.json.kvm.find((c) => c.nodeId === 1);
      assert.strictEqual(localKvmRankAfter.eligible, true, 'Uncordoned online node must be eligible in Placement Advisor');

      // 21d. Reset Circuit Breaker endpoint & UI markup verification
      const rstRes = await adminClient.request('POST', '/api/v1/nodes/1/reset-circuit', { probe: true });
      assert.strictEqual(rstRes.status, 200);
      assert.strictEqual(rstRes.json.node.circuit_state, 'closed');

      const nodesPage = await adminClient.request('GET', '/admin/nodes');
      assert.strictEqual(nodesPage.status, 200);
      assert.ok(nodesPage.text.includes('nodeInspectorModal'), 'Expected Node Inspector Modal on /admin/nodes');
      assert.ok(nodesPage.text.includes('placementAdvisorPanel'), 'Expected Smart Placement Advisor on /admin/nodes');
      assert.ok(nodesPage.text.includes('testNodeConnBtn'), 'Expected Test Reachability button on /admin/nodes');
      assert.ok(nodesPage.text.includes('nodesCardsWrap'), 'Expected Cards View container on /admin/nodes');
    });

    // 22. Multi-Node End-to-End Acceptance Suite (Self-Signed HTTPS Node Agent, 1-Command Join Token, TOFU TLS Pinning,
    //     Active Push Heartbeat, Stale Rotated-Cred Recovery, Remote Custom Template Staging, Remote LXC Lifecycle,
    //     Remote Storage statfs, Remote Port-Forward/Firewall, Multi-Node Sync-Host, Cross-Node Backup Restore & Remote WSS PTY)
    await runStep('T22: Multi-Node HTTPS self-signed pairing, TOFU TLS pinning, push heartbeat, remote LXC/storage/network/sync/migration & WSS PTY', async () => {
      const { execFileSync } = require('child_process');
      const { createNodeAgentServer } = require('../lib/node-agent/agent');
      const { NodeAgentAuthenticator } = require('../lib/node-agent/authentication');

      const HTTPS_AGENT_PORT = AGENT_PORT + 51;
      const sslDir = path.join(tmpRoot, 'https-agent-ssl');
      const httpsLxcDir = path.join(tmpRoot, 'https-agent-lxc');
      const httpsBackupDir = path.join(tmpRoot, 'https-agent-backups');
      const httpsDataDir = path.join(tmpRoot, 'https-agent-data');
      fs.mkdirSync(sslDir, { recursive: true });
      fs.mkdirSync(httpsLxcDir, { recursive: true });
      fs.mkdirSync(httpsBackupDir, { recursive: true });
      fs.mkdirSync(httpsDataDir, { recursive: true });
      rootOwnedCleanupDirs.push(httpsLxcDir);

      // 22a. Verify stale persisted node-agent-credentials.json is automatically superseded when .env bootstrap keys change!
      const staleCredsFile = path.join(httpsDataDir, 'node-agent-credentials.json');
      fs.writeFileSync(
        staleCredsFile,
        JSON.stringify({
          nodeId: 'stale-node',
          apiKeyHash: hashApiKey('old_dead_key'),
          hmacSecret: 'old_dead_hmac',
          envBootstrapHash: hashApiKey('old_dead_key:old_dead_hmac'),
        }),
        { mode: 0o600 }
      );
      const freshAuth = new NodeAgentAuthenticator({
        nodeId: 'fresh-node',
        rawApiKey: '  "new_env_key_123" \r\n',
        apiKeyHash: '',
        hmacSecret: " 'new_env_hmac_456' \r\n",
        envBootstrapHash: hashApiKey('new_env_key_123:new_env_hmac_456'),
        requireMtls: false,
        credentialsFilePath: staleCredsFile,
        loadPersistedCredentials: true,
      });
      assert.strictEqual(
        fs.existsSync(staleCredsFile),
        false,
        'Stale node-agent-credentials.json must be removed when .env bootstrap keys are updated'
      );
      const validFreshHdrs = signAgentRequest({
        nodeId: 'fresh-node',
        apiKey: 'new_env_key_123',
        hmacSecret: 'new_env_hmac_456',
        method: 'GET',
        pathWithQuery: '/api/v1/health',
      });
      const authVerify = freshAuth.verifyRawHeaders({
        method: 'GET',
        pathWithQuery: '/reverse-proxy-prefix/api/v1/health',
        rawBody: '',
        apiKeyHeader: validFreshHdrs['X-API-Key'],
        timestampHeader: validFreshHdrs['X-HKVM-Timestamp'],
        nonceHeader: validFreshHdrs['X-HKVM-Nonce'],
        signatureHeader: validFreshHdrs['X-HKVM-Signature'],
      });
      assert.strictEqual(authVerify.ok, true, `Expected sanitized env key + reverse-proxy path verification to pass: ${authVerify.reason}`);

      // Verify specific clock-skew diagnostic message (>300s drift)
      const skewedCheck = freshAuth.verifyRawHeaders({
        method: 'GET',
        pathWithQuery: '/api/v1/health',
        rawBody: '',
        apiKeyHeader: 'new_env_key_123',
        timestampHeader: String(Math.floor(Date.now() / 1000) - 900),
        nonceHeader: crypto.randomBytes(16).toString('hex'),
        signatureHeader: 'deadbeef',
      });
      assert.strictEqual(skewedCheck.ok, false);
      assert.match(skewedCheck.reason || '', /clock skew too large/i);

      // 22b. Generate a real self-signed X.509 TLS certificate (intentionally WITHOUT IP SAN to prove TOFU leaf pinning works even without SAN!)
      const certPath = path.join(sslDir, 'agent.crt');
      const keyPath = path.join(sslDir, 'agent.key');
      execFileSync('openssl', [
        'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '365',
        '-keyout', keyPath, '-out', certPath,
        '-subj', '/CN=eu-https-node-03.internal',
      ], { stdio: 'ignore' });
      const certPem = fs.readFileSync(certPath, 'utf8');

      // Register remote node initially pointing at an unreachable port with strict Verify SSL = true
      const regHttpsNode = await adminClient.request('POST', '/api/v1/nodes', {
        name: 'eu-https-node-03',
        hostname: 'eu-https-node-03.internal',
        ipAddress: '127.0.0.1',
        url: '127.0.0.1:59997', // schemeless URL auto-normalized!
        location: 'Amsterdam, NL',
        verifySsl: true,
      });
      assert.strictEqual(regHttpsNode.status, 201, `Register node failed: ${regHttpsNode.text}`);
      const httpsNodeId = regHttpsNode.json.node.id;
      assert.strictEqual(regHttpsNode.json.node.url, 'http://127.0.0.1:59997', 'Schemeless URL normalized cleanly');

      // Retrieve non-destructive bootstrap credentials (.env)
      const bootRes = await adminClient.request('GET', `/api/v1/nodes/${httpsNodeId}/bootstrap`);
      assert.strictEqual(bootRes.status, 200, `Bootstrap endpoint failed: ${bootRes.text}`);
      assert.strictEqual(bootRes.json.apiKey, regHttpsNode.json.bootstrapCredentials.apiKey);
      assert.ok(bootRes.json.envSnippet.includes('TGVPANEL_NODE_API_KEY='));

      // Generate a 1-Command Single-Use Join Token & redeem it with the HTTPS agent's self-signed PEM!
      const joinTokRes = await adminClient.request('POST', `/api/v1/nodes/${httpsNodeId}/join-token`, {
        controllerUrl: baseUrl,
        ttlMinutes: 30,
      });
      assert.strictEqual(joinTokRes.status, 201, `Join token generation failed: ${joinTokRes.text}`);
      assert.ok(joinTokRes.json.token.startsWith('tgv_join_'));
      assert.ok(joinTokRes.json.curlJoinCommand.includes('--join'));

      // Redeem join token without session cookie (simulating remote server running `menu.sh --join`)
      const bareNodeClient = new SessionClient(baseUrl);
      const redeemRes = await bareNodeClient.request('POST', `/api/v1/nodes/join/${joinTokRes.json.token}`, {
        endpointUrl: `https://127.0.0.1:${HTTPS_AGENT_PORT}`,
        ipAddress: '127.0.0.1',
        hostname: 'eu-https-node-03.internal',
        agentPort: HTTPS_AGENT_PORT,
        tlsCertPem: certPem,
        verifySsl: true,
      });
      assert.strictEqual(redeemRes.status, 200, `Join token redemption failed: ${redeemRes.text}`);
      assert.strictEqual(redeemRes.json.nodeId, httpsNodeId);
      assert.strictEqual(redeemRes.json.apiKey, regHttpsNode.json.bootstrapCredentials.apiKey);

      // Single-use enforcement: second redemption of the same join token MUST be rejected!
      const replayJoin = await bareNodeClient.request('POST', `/api/v1/nodes/join/${joinTokRes.json.token}`, {
        endpointUrl: `https://127.0.0.1:${HTTPS_AGENT_PORT}`,
      });
      assert.strictEqual(replayJoin.status, 400, 'Redeemed join token must reject reuse');
      assert.match(replayJoin.json.error || '', /already been redeemed/i);

      // Start the real standalone HTTPS Node Agent with self-signed TLS + interactiveHostShell + controllerUrl
      const httpsAgentInst = createNodeAgentServer({
        host: '127.0.0.1',
        port: HTTPS_AGENT_PORT,
        nodeId: String(httpsNodeId),
        apiKey: redeemRes.json.apiKey,
        hmacSecret: redeemRes.json.hmacSecret,
        tlsCertPath: certPath,
        tlsKeyPath: keyPath,
        lxcBaseDir: httpsLxcDir,
        backupDir: httpsBackupDir,
        dataDir: httpsDataDir,
        interactiveHostShell: true,
        controllerUrl: baseUrl,
        heartbeatIntervalMs: 120_000,
      });
      httpsAgentServer = httpsAgentInst.server;
      await new Promise((resolve) => httpsAgentServer.listen(HTTPS_AGENT_PORT, '127.0.0.1', resolve));

      // Pre-flight probe WITH strict verifySsl=true (unpinned probe) detects self-signed TGVPANEL agent & extracts PEM!
      const strictProbe = await adminClient.request('POST', '/api/v1/nodes/test-connection', {
        url: `https://127.0.0.1:${HTTPS_AGENT_PORT}`,
        verifySsl: true,
      });
      assert.strictEqual(strictProbe.status, 200);
      assert.strictEqual(strictProbe.json.reachable, false);
      assert.strictEqual(strictProbe.json.selfSignedAgentDetected, true, `Expected selfSignedAgentDetected: ${strictProbe.text}`);
      assert.ok(strictProbe.json.tls && strictProbe.json.tls.certPem.includes('BEGIN CERTIFICATE'));

      // 22c. Verify Active Outbound Agent -> Controller Push Heartbeat wakes node to ONLINE!
      const hbSent = await httpsAgentInst.sendHeartbeatOnce();
      assert.strictEqual(hbSent, true, 'Expected outbound HMAC push-heartbeat to succeed');
      const afterHbDetail = await adminClient.request('GET', `/api/v1/nodes/${httpsNodeId}/detail?live=0`);
      assert.strictEqual(afterHbDetail.status, 200);
      assert.strictEqual(afterHbDetail.json.node.status, 'online', 'Push-heartbeat must mark node online');
      assert.strictEqual(afterHbDetail.json.node.tls_pinned, 1, 'Join token cert must set tls_pinned=1');

      // Also verify Controller -> HTTPS Node Agent live check & TOFU trust-tls over pinned self-signed cert!
      const trustRes = await adminClient.request('POST', `/api/v1/nodes/${httpsNodeId}/trust-tls`, {});
      assert.strictEqual(trustRes.status, 200, `trust-tls failed: ${trustRes.text}`);
      assert.strictEqual(trustRes.json.probeOk, true, 'Expected live HTTPS probe after TOFU pin to succeed');

      // Verify all fixed Node Inspector diagnostic presets against the remote HTTPS node!
      for (const preset of ['uptime', 'uname', 'memory', 'disk', 'network_links', 'bridges', 'lxc_list', 'sysctl_net']) {
        const dRes = await adminClient.request('POST', `/api/v1/nodes/${httpsNodeId}/diagnostics/${preset}`, {});
        assert.strictEqual(dRes.status, 200, `Remote diagnostic preset ${preset} failed: ${dRes.text}`);
        assert.strictEqual(typeof dRes.json.output, 'string');
        assert.ok(dRes.json.output.length > 0);
      }

      // 22d. Remote Storage Pool statfs, Remote NAT Port Forwarding & Remote Firewall Rule
      const remotePoolPath = path.join(httpsDataDir, 'remote-nvme-pool');
      const createRemotePool = await adminClient.request('POST', '/api/v1/storage/pools', {
        nodeId: httpsNodeId,
        name: 'amsterdam-nvme-lxc',
        poolType: 'dir',
        engineScope: 'lxc',
        path: remotePoolPath,
      });
      assert.strictEqual(createRemotePool.status, 201, `Remote storage pool create failed: ${createRemotePool.text}`);
      assert.strictEqual(fs.existsSync(remotePoolPath), true, 'Remote Node Agent must create storage pool directory');
      const syncedPools = await adminClient.request('GET', '/api/v1/storage/pools?sync=1');
      const amsPool = (syncedPools.json.pools || []).find((p) => p.name === 'amsterdam-nvme-lxc');
      assert.ok(amsPool && Number(amsPool.total_bytes) > 0, 'Remote storage pool must report real remote statfs total_bytes');

      // 22e. Deploy LXC container onto Remote HTTPS Node using Controller-hosted Custom Template Archive!
      const remoteCustomCt = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'ct-https-remote-01',
        hostname: 'ct-https-remote-01.tgv.local',
        nodeId: httpsNodeId,
        templateSlug: 'custom:hkvm-os-3',
        cpuCores: 2,
        ramMb: 512,
        diskGb: 8,
        ipv4Address: '10.0.3.188/24',
        ipv4Gateway: '10.0.3.1',
        provisionOnHost: true,
      });
      assert.strictEqual(remoteCustomCt.status, 201, `Remote custom template LXC create failed: ${remoteCustomCt.text}`);
      const remoteCtId = remoteCustomCt.json.instance.refId;
      assert.strictEqual(remoteCustomCt.json.instance.nodeId, httpsNodeId);
      assert.strictEqual(
        fs.existsSync(path.join(httpsLxcDir, 'ct-https-remote-01', 'rootfs', 'etc', 'custom-release')),
        true,
        'Custom template archive must be auto-staged & unpacked on remote HTTPS Node Agent!'
      );

      // Attach a NAT Port Forward & Firewall Rule on the remote HTTPS node
      const remotePf = await adminClient.request('POST', '/api/v1/network/ports', {
        instanceType: 'lxc',
        instanceRefId: remoteCtId,
        guestPort: 22,
        hostPort: 24222,
        protocol: 'tcp',
        description: 'Remote SSH forward',
      });
      assert.strictEqual(remotePf.status, 201, `Remote port-forward failed: ${remotePf.text}`);

      const remoteFw = await adminClient.request('POST', '/api/v1/network/firewall', {
        nodeId: httpsNodeId,
        direction: 'in',
        action: 'ACCEPT',
        protocol: 'tcp',
        destPort: '24222',
        comment: 'Allow remote SSH forward',
      });
      assert.strictEqual(remoteFw.status, 201, `Remote firewall rule failed: ${remoteFw.text}`);

      // Create backup of ct-https-remote-01 on httpsNodeId, then migrate to remoteNodeId & restore cross-node!
      const remoteBkp = await adminClient.request('POST', '/api/v1/backups', {
        engine: 'lxc',
        refId: remoteCtId,
        label: 'pre-crossnode-mig',
      });
      assert.strictEqual(remoteBkp.status, 201, `Remote backup failed: ${remoteBkp.text}`);
      const remoteBkpId = remoteBkp.json.backup.backupId;

      const migCross = await adminClient.request('POST', '/api/v1/migrations', {
        lxcId: remoteCtId,
        targetNodeId: remoteNodeId,
        targetBridge: 'lxcbr0',
      });
      assert.strictEqual(migCross.status, 201, `Cross-agent migration failed: ${migCross.text}`);
      assert.strictEqual(migCross.json.migration.status, 'completed');

      // Verify port forward automatically relocated to target remoteNodeId!
      const pfAfterMig = await ctx.db.get(`SELECT * FROM port_forwards WHERE id = ?`, [
        remotePf.json.portForward.id,
      ]);
      assert.strictEqual(
        Number(pfAfterMig.node_id),
        Number(remoteNodeId),
        'Port forward must relocate to target node after LXC migration!'
      );

      // Restore backup (stored on httpsNodeId!) onto migrated container (now on remoteNodeId!)
      const crossRestore = await adminClient.request('POST', `/api/v1/backups/${remoteBkpId}/restore`, {});
      assert.strictEqual(crossRestore.status, 200, `Cross-node backup restore failed: ${crossRestore.text}`);
      assert.strictEqual(crossRestore.json.restored, true);

      // 22f. Multi-Node `sync-host`: create an untracked container directly on httpsNodeId and verify /api/v1/lxc/sync-host imports it with node_id = httpsNodeId!
      const untrackedDir = path.join(httpsLxcDir, 'untracked-remote-ct99');
      fs.mkdirSync(path.join(untrackedDir, 'rootfs', 'etc'), { recursive: true });
      fs.writeFileSync(
        path.join(untrackedDir, 'config'),
        'lxc.uts.name = untracked-remote-ct99\nlxc.rootfs.path = dir:' + path.join(untrackedDir, 'rootfs') + '\n'
      );
      const syncRemoteRes = await adminClient.request('POST', '/api/v1/lxc/sync-host', {});
      assert.strictEqual(syncRemoteRes.status, 200, `Multi-node sync-host failed: ${syncRemoteRes.text}`);
      assert.ok(
        (syncRemoteRes.json.imported || []).includes('untracked-remote-ct99'),
        `Expected untracked-remote-ct99 in imported list: ${syncRemoteRes.text}`
      );
      const importedRow = await ctx.db.get(
        `SELECT node_id FROM lxc_instances WHERE container_name = 'untracked-remote-ct99'`
      );
      assert.strictEqual(Number(importedRow.node_id), Number(httpsNodeId), 'Synced remote container must belong to remote node_id');

      // 22g. Bridged WSS Interactive Host PTY Shell to Remote HTTPS Node Agent (`/ws/nodes/:id/shell`)!
      const ptyOutput = await new Promise((resolve, reject) => {
        const ws = new WebSocket(
          `ws://127.0.0.1:${TEST_PORT}/ws/nodes/${httpsNodeId}/shell?cols=90&rows=24`,
          { headers: { Cookie: adminClient.cookie } }
        );
        let collected = '';
        const timer = setTimeout(() => {
          try { ws.close(); } catch (_) {}
          reject(new Error(`Timed out waiting for remote HTTPS PTY output (got: ${collected})`));
        }, 8000);
        ws.on('open', () => {
          ws.send(JSON.stringify({ type: 'input', data: 'echo MULTI_NODE_WSS_PTY_OK\r' }));
        });
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'output') {
              collected += msg.data;
              if (collected.includes('MULTI_NODE_WSS_PTY_OK')) {
                clearTimeout(timer);
                ws.close();
                resolve(collected);
              }
            } else if (msg.type === 'error') {
              clearTimeout(timer);
              ws.close();
              reject(new Error(`Remote PTY error: ${msg.message}`));
            }
          } catch (_) {}
        });
        ws.on('error', (e) => {
          clearTimeout(timer);
          reject(e);
        });
      });
      assert.ok(ptyOutput.includes('MULTI_NODE_WSS_PTY_OK'), 'Expected live PTY output bridged over WSS from remote node');
    });

    await runStep('T23: LXC VPS live CPU Load telemetry (systemd init.scope cgroup v2, cold first-load sample, memory>0 /proc cutime fallback & remote HTTPS node)', async () => {
      const { spawn, execFileSync } = require('child_process');
      const {
        resolveContainerPayloadCgroupV2Dir,
        readContainerCgroupResourceStats,
        ensureCgroupV2SubtreeDelegation,
        LxcContainerManager,
      } = require('../lib/node-agent/container-manager');
      const { privilegedFs, isRunningAsRoot, canPasswordlessSudo } =
        require('../lib/node-agent/command-runner');

      await adminClient.request('GET', '/lxc');

      // Provision a dedicated 1-vCPU LXC container for CPU telemetry verification
      const ctName = 'cpu-load-e2e-01';
      const createRes = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: ctName,
        hostname: 'cpu-load-e2e.tgvpanel.local',
        templateSlug: 'ubuntu:24.04',
        nodeId: 1,
        cpuCores: 1,
        cpuLimitPercent: 100,
        ramMb: 1024,
        swapMb: 256,
        diskGb: 10,
        startAfterCreate: true,
      });
      assert.strictEqual(createRes.status, 201, `Create ${ctName} failed: ${createRes.text}`);
      const lxcId = createRes.json.instance.refId;
      const ctDir = path.join(process.env.TGVPANEL_LXC_PATH, ctName);

      // Verify /lxc/:id UI template includes live formatCpuLoadPercent & 4s polling
      const detailHtml = await adminClient.request('GET', `/lxc/${lxcId}`);
      assert.strictEqual(detailHtml.status, 200);
      assert.ok(detailHtml.text.includes('formatCpuLoadPercent'), 'Expected formatCpuLoadPercent in /lxc/:id view');

      // Scenario 1: Real cgroup v2 `systemd` layout (`lxc.payload.<ct>/init.scope` idle PID 1
      // + `lxc.payload.<ct>/system.slice/worker.service` busy CPU worker) + cold first-load telemetry!
      if ((isRunningAsRoot() || canPasswordlessSudo()) && fs.existsSync('/sys/fs/cgroup/cgroup.controllers')) {
        ensureCgroupV2SubtreeDelegation();
        const payloadCg = `/sys/fs/cgroup/hkvm.lxc/lxc.payload.${ctName}`;
        const guestInitScope = `${payloadCg}/init.scope`;
        const guestWorkerSvc = `${payloadCg}/system.slice/worker.service`;
        let busyWorker = null;
        try {
          const ctInitPid = parseInt(fs.readFileSync(path.join(ctDir, '.pid'), 'utf8').trim(), 10);
          assert.ok(ctInitPid > 1, 'Expected running container init PID');

          execFileSync('sudo', ['-n', 'mkdir', '-p', guestInitScope, guestWorkerSvc]);
          // Move idle container PID 1 into `<payload>/init.scope` just like systemd does on boot
          privilegedFs.writeFileSync(path.join(guestInitScope, 'cgroup.procs'), `${ctInitPid}\n`);

          // Spawn a real CPU-burning worker inside `<payload>/system.slice/worker.service`
          busyWorker = spawn(process.execPath, ['-e', 'const end = Date.now() + 8000; while (Date.now() < end) { Math.sqrt(Math.random()); }'], {
            stdio: 'ignore',
          });
          privilegedFs.writeFileSync(path.join(guestWorkerSvc, 'cgroup.procs'), `${busyWorker.pid}\n`);

          const resolvedPayloadDir = resolveContainerPayloadCgroupV2Dir(ctName, ctInitPid);
          assert.strictEqual(
            resolvedPayloadDir,
            payloadCg,
            `Expected resolveContainerPayloadCgroupV2Dir to strip /init.scope and return ${payloadCg}, got ${resolvedPayloadDir}`
          );

          const cgStat1 = readContainerCgroupResourceStats(ctName, ctInitPid);
          assert.strictEqual(cgStat1.source, 'cgroup-v2');
          assert.ok(cgStat1.cpuUseSeconds !== null && cgStat1.cpuUseSeconds >= 0);

          // Cold first-visit telemetry request MUST immediately return > 5% CPU (not 0%!)
          const coldTel = await adminClient.request('GET', `/api/v1/instances/lxc/${lxcId}/telemetry`);
          assert.strictEqual(coldTel.status, 200, `Cold telemetry failed: ${coldTel.text}`);
          assert.ok(
            coldTel.json.telemetry.cpuPercent > 5,
            `Expected cold first-visit LXC CPU Load > 5%, got ${coldTel.json.telemetry.cpuPercent}%`
          );

          // Warm second telemetry poll after 250ms MUST also return > 5% CPU
          await new Promise((r) => setTimeout(r, 260));
          const warmTel = await adminClient.request('GET', `/api/v1/instances/lxc/${lxcId}/telemetry`);
          assert.strictEqual(warmTel.status, 200);
          assert.ok(
            warmTel.json.telemetry.cpuPercent > 5,
            `Expected warm LXC CPU Load > 5%, got ${warmTel.json.telemetry.cpuPercent}%`
          );
        } finally {
          if (busyWorker) {
            try { busyWorker.kill('SIGKILL'); } catch (_) {}
          }
          // Evacuate container init PID back to /sys/fs/cgroup/init.scope so we can cleanly rmdir test cgroups
          try {
            const ctInitPid = parseInt(fs.readFileSync(path.join(ctDir, '.pid'), 'utf8').trim(), 10);
            if (ctInitPid > 1) {
              privilegedFs.writeFileSync('/sys/fs/cgroup/init.scope/cgroup.procs', `${ctInitPid}\n`);
            }
          } catch (_) {}
          await new Promise((r) => setTimeout(r, 80));
          for (const d of [
            `${payloadCg}/system.slice/worker.service`,
            `${payloadCg}/system.slice`,
            `${payloadCg}/init.scope`,
            payloadCg,
          ]) {
            try { execFileSync('sudo', ['-n', 'rmdir', d]); } catch (_) {}
          }
        }
      }

      // Scenario 2: Undelegated /proc fallback when `Memory use:` > 0 AND `CPU use:` is missing,
      // PLUS monotonic `cutime + cstime` preservation across exited & reaped child processes!
      const parentProc = spawn(
        process.execPath,
        [
          '-e',
          `
          const { spawnSync } = require('child_process');
          // 1) Burn CPU in a short-lived child that exits and is immediately reaped
          spawnSync(process.execPath, ['-e', 'const t = Date.now() + 180; while (Date.now() < t) { Math.imul(12345, 67890); }']);
          process.stdout.write('REAPED\\n');
          // 2) Spawn a live busy child for live /proc telemetry measurement
          const { spawn } = require('child_process');
          const c = spawn(process.execPath, ['-e', 'const t = Date.now() + 5000; while (Date.now() < t) { Math.sqrt(987654321); }'], { stdio: 'ignore' });
          setTimeout(() => { try { c.kill('SIGKILL'); } catch (_) {} process.exit(0); }, 5000);
          `,
        ],
        { stdio: ['ignore', 'pipe', 'ignore'] }
      );
      try {
        await new Promise((resolve, reject) => {
          const t = setTimeout(() => reject(new Error('Timed out waiting for REAPED signal')), 4000);
          parentProc.stdout.on('data', (d) => {
            if (d.toString().includes('REAPED')) {
              clearTimeout(t);
              resolve();
            }
          });
        });

        const localCm = new LxcContainerManager(process.env.TGVPANEL_LXC_PATH);
        const procAfterReap = localCm.measureContainerProcTree(parentProc.pid);
        assert.ok(
          procAfterReap.cpuUseSeconds >= 0.05,
          `Expected reaped child CPU ticks (cutime+cstime) preserved >= 0.05s, got ${procAfterReap.cpuUseSeconds}s`
        );

        // Point container `.pid` at `parentProc.pid` (which lives in shared host cgroup, NOT lxc.payload.*)
        // AND touch `.omit_cpu_use` so `lxc-info` emits `Memory use: 64.25 MiB` (>0) while omitting `CPU use:`!
        const origPid = privilegedFs.readTextSync(path.join(ctDir, '.pid'));
        const omitCpuMarker = path.join(ctDir, '.omit_cpu_use');
        execFileSync('sudo', ['-n', 'touch', omitCpuMarker]);
        privilegedFs.writeFileSync(path.join(ctDir, '.pid'), `${parentProc.pid}\n`);
        try {
          const procTel = await adminClient.request('GET', `/api/v1/instances/lxc/${lxcId}/telemetry`);
          assert.strictEqual(procTel.status, 200);
          assert.ok(
            procTel.json.telemetry.ramUsedMb >= 60,
            `Expected Memory use > 60 MB preserved, got ${procTel.json.telemetry.ramUsedMb} MB`
          );
          assert.ok(
            procTel.json.telemetry.cpuPercent > 3,
            `Expected /proc CPU Load > 3% even when Memory use > 0 and lxc-info omits CPU use, got ${procTel.json.telemetry.cpuPercent}%`
          );
        } finally {
          privilegedFs.writeFileSync(path.join(ctDir, '.pid'), origPid);
          execFileSync('sudo', ['-n', 'rm', '-f', omitCpuMarker]);
        }
      } finally {
        try { execFileSync('pkill', ['-KILL', '-P', String(parentProc.pid)]); } catch (_) {}
        try { parentProc.kill('SIGKILL'); } catch (_) {}
      }

      // Scenario 3: Remote Node Agent live CPU Load telemetry (`?telemetry=1` over HMAC HTTP)
      if ((isRunningAsRoot() || canPasswordlessSudo()) && fs.existsSync('/sys/fs/cgroup/cgroup.controllers')) {
        const remCtName = 'cpu-rem-e2e-01';
        const remCreate = await adminClient.request('POST', '/api/v1/lxc', {
          containerName: remCtName,
          hostname: 'cpu-rem-e2e.tgvpanel.local',
          templateSlug: 'ubuntu:24.04',
          nodeId: remoteNodeId,
          cpuCores: 2,
          cpuLimitPercent: 100,
          ramMb: 1024,
          swapMb: 256,
          diskGb: 10,
          startAfterCreate: true,
        });
        assert.strictEqual(remCreate.status, 201, `Remote create failed: ${remCreate.text}`);
        const remLxcId = remCreate.json.instance.refId;
        const remCtDir = path.join(tmpRoot, 'agent-lxc', remCtName);
        const remPayloadCg = `/sys/fs/cgroup/hkvm.lxc/lxc.payload.${remCtName}`;
        let remWorker = null;
        try {
          const remInitPid = parseInt(privilegedFs.readTextSync(path.join(remCtDir, '.pid')).trim(), 10);
          execFileSync('sudo', ['-n', 'mkdir', '-p', `${remPayloadCg}/init.scope`]);
          privilegedFs.writeFileSync(`${remPayloadCg}/init.scope/cgroup.procs`, `${remInitPid}\n`);
          remWorker = spawn(process.execPath, ['-e', 'const end = Date.now() + 8000; while (Date.now() < end) { Math.sqrt(Math.random()); }'], {
            stdio: 'ignore',
          });
          privilegedFs.writeFileSync(`${remPayloadCg}/cgroup.procs`, `${remWorker.pid}\n`);

          const remColdTel = await adminClient.request('GET', `/api/v1/instances/lxc/${remLxcId}/telemetry`);
          assert.strictEqual(remColdTel.status, 200, `Remote cold telemetry failed: ${remColdTel.text}`);
          assert.ok(
            remColdTel.json.telemetry.cpuPercent > 5,
            `Expected remote LXC CPU Load > 5% on cold first open, got ${remColdTel.json.telemetry.cpuPercent}%`
          );
        } finally {
          if (remWorker) {
            try { remWorker.kill('SIGKILL'); } catch (_) {}
          }
          try {
            const remInitPid = parseInt(privilegedFs.readTextSync(path.join(remCtDir, '.pid')).trim(), 10);
            if (remInitPid > 1) {
              privilegedFs.writeFileSync('/sys/fs/cgroup/init.scope/cgroup.procs', `${remInitPid}\n`);
            }
          } catch (_) {}
          await new Promise((r) => setTimeout(r, 80));
          for (const d of [`${remPayloadCg}/init.scope`, remPayloadCg]) {
            try { execFileSync('sudo', ['-n', 'rmdir', d]); } catch (_) {}
          }
        }
      }
    });

    // 24. Proxmox VE 8 & 9 OS Templates on QEMU/KVM Virtual Machine Creation
    await runStep('T24: Proxmox VE 8 & 9 QEMU/KVM OS templates, Cloud-Init ISO bootstrap, NAT :8006 forwarding, reinstall & UI', async () => {
      const { isEncryptedSecret } = require('../lib/security/crypto-vault');
      const vmDir = path.join(os.homedir(), 'vms');
      const templatesDir = path.join(vmDir, 'templates');
      const cloudVmDir = path.join(os.homedir(), 'cloudvm');
      fs.mkdirSync(templatesDir, { recursive: true });
      fs.mkdirSync(cloudVmDir, { recursive: true });

      // 24a. Verify all built-in OS templates use local /images/os/*.svg icons & Proxmox VE 8/9 metadata
      const osTplRes = await adminClient.request('GET', '/api/os-templates');
      assert.strictEqual(osTplRes.status, 200);
      assert.strictEqual(osTplRes.json.ubuntu_22_cloud.icon, '/images/os/ubuntu.svg');
      assert.strictEqual(osTplRes.json.ubuntu_24_cloud.icon, '/images/os/ubuntu.svg');
      assert.strictEqual(osTplRes.json.debian_12_cloud.icon, '/images/os/debian.svg');
      assert.strictEqual(osTplRes.json.fedora_40_cloud.icon, '/images/os/fedora.svg');
      assert.strictEqual(osTplRes.json.centos_9_cloud.icon, '/images/os/centos.svg');
      assert.strictEqual(osTplRes.json.almalinux_9_cloud.icon, '/images/os/almalinux.svg');
      assert.ok(osTplRes.json.proxmox_ve_8, 'Expected proxmox_ve_8 in /api/os-templates');
      assert.ok(osTplRes.json.proxmox_ve_9, 'Expected proxmox_ve_9 in /api/os-templates');
      assert.strictEqual(osTplRes.json.proxmox_ve_8.name, 'Proxmox VE 8');
      assert.strictEqual(osTplRes.json.proxmox_ve_8.memory, 4096);
      assert.strictEqual(osTplRes.json.proxmox_ve_8.cpus, 4);
      assert.strictEqual(osTplRes.json.proxmox_ve_8.disk_size, '40G');
      assert.strictEqual(osTplRes.json.proxmox_ve_8.username, 'root');
      assert.strictEqual(osTplRes.json.proxmox_ve_8.web_port, 8006);
      assert.strictEqual(osTplRes.json.proxmox_ve_8.icon, '/images/os/proxmox.svg');
      assert.strictEqual(osTplRes.json.proxmox_ve_9.name, 'Proxmox VE 9');
      assert.strictEqual(osTplRes.json.proxmox_ve_9.proxmox_codename, 'trixie');
      assert.strictEqual(
        osTplRes.json.proxmox_ve_9.proxmox_gpg_url,
        'https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg'
      );
      assert.strictEqual(osTplRes.json.proxmox_ve_9.icon, '/images/os/proxmox.svg');
      for (const [k, tpl] of Object.entries(osTplRes.json)) {
        assert.strictEqual(
          String(tpl.icon || '').includes('imgur.com'),
          false,
          `Template ${k} must not use external imgur.com icon`
        );
      }

      const adminTplRes = await adminClient.request('GET', '/api/admin/templates');
      assert.strictEqual(adminTplRes.status, 200);
      const adminTplList = Array.isArray(adminTplRes.json) ? adminTplRes.json : (adminTplRes.json.templates || []);
      assert.ok(
        adminTplList.some((t) => t.template_key === 'proxmox_ve_8' && t.web_port === 8006),
        'Expected proxmox_ve_8 in /api/admin/templates'
      );
      assert.ok(
        adminTplList.some((t) => t.template_key === 'proxmox_ve_9' && t.web_port === 8006),
        'Expected proxmox_ve_9 in /api/admin/templates'
      );

      for (const svgName of ['proxmox.svg', 'ubuntu.svg', 'debian.svg', 'fedora.svg', 'centos.svg', 'almalinux.svg', 'linux.svg']) {
        const svgRes = await adminClient.request('GET', `/images/os/${svgName}`);
        assert.strictEqual(svgRes.status, 200, `Expected /images/os/${svgName} to return 200`);
        assert.ok(svgRes.text.includes('<svg'), `Expected valid SVG payload for ${svgName}`);
      }

      const builtinView8 = await adminClient.request('GET', '/admin/templates/builtin/proxmox_ve_8/edit');
      assert.strictEqual(builtinView8.status, 200);
      assert.ok(builtinView8.text.includes('Proxmox VE 8'));

      const vmCreateHtml = await adminClient.request('GET', '/admin/vm-create');
      assert.strictEqual(vmCreateHtml.status, 200);
      assert.ok(vmCreateHtml.text.includes('proxmoxWebPortGroup'), 'Expected Proxmox Web UI Port field in /admin/vm-create');
      assert.ok(vmCreateHtml.text.includes('isProxmoxTemplateKey'), 'Expected Proxmox template detection in /admin/vm-create');

      // 24b. Prepare cached cloud images & temporary qemu-img shim if host lacks qemu-img binary
      const origPath = process.env.PATH || '';
      const createdTemplateFiles = [];
      const createdVmIds = [];
      const deb12Cache = path.join(templatesDir, 'debian_12_cloud-template.qcow2');
      const pve9Cache = path.join(templatesDir, 'proxmox_ve_9-template.qcow2');
      const ubu22Cache = path.join(templatesDir, 'ubuntu_22_cloud-template.qcow2');
      for (const f of [deb12Cache, pve9Cache, ubu22Cache]) {
        if (!fs.existsSync(f)) {
          fs.writeFileSync(f, Buffer.from('QFI\xfb\x00\x00\x00\x03test-qcow2-template'));
          createdTemplateFiles.push(f);
        }
      }

      let hasRealQemuImg = false;
      try {
        require('child_process').execSync('command -v qemu-img', { stdio: 'pipe' });
        hasRealQemuImg = true;
      } catch (_) {}

      if (!hasRealQemuImg) {
        const fakeBinDir = path.join(tmpRoot, 'qemu-test-bin');
        fs.mkdirSync(fakeBinDir, { recursive: true });
        const fakeQemuImg = path.join(fakeBinDir, 'qemu-img');
        fs.writeFileSync(
          fakeQemuImg,
          `#!/bin/bash
set -e
CMD="$1"
shift
if [ "$CMD" = "convert" ]; then
  while [ "$#" -gt 2 ]; do shift; done
  cp "$1" "$2"
elif [ "$CMD" = "resize" ]; then
  exit 0
elif [ "$CMD" = "create" ]; then
  while [ "$#" -gt 2 ]; do shift; done
  printf 'QFI\\xfb' > "$1"
fi
`,
          { mode: 0o755 }
        );
        process.env.PATH = `${fakeBinDir}:${origPath}`;
      }

      try {
        // 24c. Create Proxmox VE 8 VM in NAT mode (verifies shared debian_12_cloud cache reuse, defaults & seed ISO)
        const createPve8 = await adminClient.request('POST', '/api/vms', {
          vm_name: 'pve8-hypervisor-01',
          os_template: 'proxmox_ve_8',
          hostname: 'pve8-node1',
          network_type: 'nat',
          ssh_port: 22806,
          custom_password: 'Pve8Root!Secret',
        });
        assert.strictEqual(createPve8.status, 200, `Proxmox VE 8 create failed: ${createPve8.text}`);
        assert.strictEqual(createPve8.json.success, true);
        assert.strictEqual(createPve8.json.config.memory, 4096);
        assert.strictEqual(createPve8.json.config.cpus, 4);
        assert.strictEqual(createPve8.json.config.disk_size, '40G');
        assert.strictEqual(createPve8.json.config.http_port, 8006);
        assert.strictEqual(createPve8.json.config.is_proxmox, true);
        const pve8VmId = createPve8.json.vm_id;
        createdVmIds.push(pve8VmId);

        // Verify password encrypted at rest in SQLite
        const rawPve8Row = await ctx.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [pve8VmId]);
        assert.ok(rawPve8Row, 'Expected pve8 VM row in vms table');
        assert.strictEqual(isEncryptedSecret(rawPve8Row.password), true, 'Proxmox VM password must be encrypted at rest');
        assert.strictEqual(rawPve8Row.username, 'root');
        assert.strictEqual(rawPve8Row.http_port, 8006);

        // Verify binary seed ISO exists, has CD001 + cidata PVD, and embeds valid 2-space Cloud-Init user-data
        assert.strictEqual(fs.existsSync(rawPve8Row.seed_file), true, 'Expected Proxmox seed ISO file on disk');
        const isoBytes = fs.readFileSync(rawPve8Row.seed_file);
        assert.strictEqual(isoBytes.subarray(16 * 2048 + 1, 16 * 2048 + 6).toString('ascii'), 'CD001');
        assert.strictEqual(isoBytes.subarray(16 * 2048 + 40, 16 * 2048 + 46).toString('ascii'), 'cidata');
        const isoText = isoBytes.toString('utf8');
        assert.ok(isoText.includes('#cloud-config'), 'Seed ISO must embed #cloud-config');
        assert.ok(isoText.includes('hostname: pve8-node1'), 'Seed ISO must configure short hostname');
        assert.ok(isoText.includes('fqdn: pve8-node1.proxmox.local'), 'Seed ISO must configure FQDN for pve-cluster');
        assert.ok(isoText.includes('root:Pve8Root!Secret'), 'Seed ISO must configure root@pam password');
        assert.ok(isoText.includes('CODENAME="bookworm"'), 'PVE 8 seed ISO must target bookworm repository');
        assert.ok(isoText.includes('pve-no-subscription'), 'Seed ISO must configure pve-no-subscription APT repo');
        assert.ok(isoText.includes('proxmox-default-kernel'), 'Seed ISO must install proxmox-default-kernel');
        assert.ok(isoText.includes('proxmox-ve postfix open-iscsi chrony'), 'Seed ISO must install proxmox-ve packages');
        assert.ok(isoText.includes('DPkg::Lock::Timeout "180"'), 'Seed ISO must configure global APT lock timeout');
        assert.ok(isoText.includes('tgvpanel-proxmox-status.sh'), 'Seed ISO must install SSH login status banner');
        assert.ok(isoText.includes('systemctl stop apt-daily.timer'), 'Seed ISO must stop apt-daily timers during bootstrap');
        assert.ok(isoText.includes('address 10.10.10.1/24'), 'NAT Proxmox seed ISO must configure internal vmbr0 bridge');
        assert.ok(isoText.includes('console=tty0 console=ttyS0,115200n8'), 'Seed ISO must preserve serial console in GRUB');

        // Verify generator produces 0 YAML indentation/tab warnings & valid bash syntax for both PVE 8 & PVE 9
        for (const tplKey of ['proxmox_ve_8', 'proxmox_ve_9']) {
          const generatedCfg = app.proxmoxHelpers.generateProxmoxCloudInitConfig({
            os_template: tplKey,
            hostname: 'pve-node1',
            username: 'root',
            password: 'PveRoot!Secret',
            network_type: 'nat',
          });
          for (const [idx, line] of generatedCfg.split('\n').entries()) {
            assert.strictEqual(line.includes('\t'), false, `${tplKey} line ${idx + 1} must not contain tabs`);
            const indent = line.match(/^ */)[0].length;
            assert.strictEqual(indent % 2, 0, `${tplKey} line ${idx + 1} indentation (${indent}) must be a multiple of 2`);
          }
          // Extract /usr/local/sbin/tgvpanel-install-proxmox.sh block and validate with bash -n
          const markerStart = '  - path: /usr/local/sbin/tgvpanel-install-proxmox.sh\n    permissions: \'0755\'\n    content: |\n';
          const markerEnd = '\n  - path: /etc/systemd/system/tgvpanel-proxmox-setup.service';
          const sIdx = generatedCfg.indexOf(markerStart);
          const eIdx = generatedCfg.indexOf(markerEnd);
          assert.ok(sIdx > 0 && eIdx > sIdx, `Expected installer script block in ${tplKey} cloud-config`);
          const extractedScript = generatedCfg
            .slice(sIdx + markerStart.length, eIdx)
            .split('\n')
            .map((l) => (l.startsWith('      ') ? l.slice(6) : l))
            .join('\n');
          const tmpScriptPath = path.join(tmpRoot, `check-${tplKey}.sh`);
          fs.writeFileSync(tmpScriptPath, extractedScript, 'utf8');
          require('child_process').execFileSync('/bin/bash', ['-n', tmpScriptPath]);
        }

        // Verify QEMU NAT netdev forwards BOTH SSH and Proxmox HTTPS :8006
        const natSpec8 = app.proxmoxHelpers.buildQemuNatNetdevSpec(rawPve8Row, 'n0');
        assert.strictEqual(
          natSpec8.netdevArg,
          'user,id=n0,hostfwd=tcp::22806-:22,hostfwd=tcp::8006-:8006'
        );

        // 24d. Second NAT Proxmox VE 9 VM auto-avoids port 8006 collision (-> 8007)
        const createPve9Nat = await adminClient.request('POST', '/api/vms', {
          vm_name: 'pve9-hypervisor-02',
          os_template: 'proxmox_ve_9',
          hostname: 'pve9-node2.lab.internal',
          network_type: 'nat',
          ssh_port: 22807,
          custom_password: 'Pve9Root!Secret',
        });
        assert.strictEqual(createPve9Nat.status, 200, `Proxmox VE 9 NAT create failed: ${createPve9Nat.text}`);
        assert.strictEqual(createPve9Nat.json.config.http_port, 8007, 'Second NAT Proxmox VM must auto-increment Web UI port to 8007');
        createdVmIds.push(createPve9Nat.json.vm_id);
        const rawPve9NatRow = await ctx.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [createPve9Nat.json.vm_id]);
        const natSpec9 = app.proxmoxHelpers.buildQemuNatNetdevSpec(rawPve9NatRow, 'n0');
        assert.strictEqual(
          natSpec9.netdevArg,
          'user,id=n0,hostfwd=tcp::22807-:22,hostfwd=tcp::8007-:8006'
        );

        // 24e. Static Public IPv4 Proxmox VE 9 VM configures bridged vmbr0 + trixie repository
        const createPve9Static = await adminClient.request('POST', '/api/vms', {
          vm_name: 'pve9-bridged-03',
          os_template: 'proxmox_ve_9',
          hostname: 'pve9-static',
          network_type: 'static_public',
          bridge_device: 'vmbr0',
          ipv4_address: '203.0.113.50',
          ipv4_gateway: '203.0.113.1',
          ipv4_netmask: '24',
          dns_servers: '1.1.1.1,8.8.8.8',
          custom_password: 'Pve9Static!Pass',
        });
        assert.strictEqual(createPve9Static.status, 200, `Proxmox VE 9 static create failed: ${createPve9Static.text}`);
        assert.strictEqual(createPve9Static.json.config.http_port, 8006);
        createdVmIds.push(createPve9Static.json.vm_id);
        const staticSeedText = fs.readFileSync(path.join(vmDir, `vm-${createPve9Static.json.vm_id}-seed.iso`), 'utf8');
        assert.ok(staticSeedText.includes('CODENAME="trixie"'), 'PVE 9 seed ISO must target trixie repository');
        assert.ok(
          staticSeedText.includes('proxmox-archive-keyring-trixie.gpg'),
          'PVE 9 seed ISO must use official proxmox-archive-keyring-trixie.gpg URL'
        );
        assert.ok(
          staticSeedText.includes('/etc/apt/sources.list.d/pve-install-repo.sources'),
          'PVE 9 seed ISO must configure DEB822 pve-install-repo.sources'
        );
        assert.ok(staticSeedText.includes('STATIC_IP="203.0.113.50"'), 'Static PVE seed ISO must embed static IPv4');
        assert.ok(staticSeedText.includes('bridge-ports ${PRIMARY_IFACE}'), 'Static PVE seed ISO must bridge primary NIC into vmbr0');

        // 24f. Verify enriched icon & metadata in /api/vms, /api/admin/vms, /api/vms/:id & detail views
        const detailPve8 = await adminClient.request('GET', `/api/vms/${pve8VmId}`);
        assert.strictEqual(detailPve8.status, 200);
        assert.strictEqual(detailPve8.json.template_icon, '/images/os/proxmox.svg');
        assert.strictEqual(detailPve8.json.template_name, 'Proxmox VE 8');
        assert.strictEqual(detailPve8.json.is_proxmox, true);
        assert.strictEqual(detailPve8.json.web_ui_port, 8006);
        assert.strictEqual(detailPve8.json.password, 'Pve8Root!Secret');

        const adminVmList = await adminClient.request('GET', '/api/admin/vms');
        const listedPve8 = adminVmList.json.find((v) => v.vm_id === pve8VmId);
        assert.ok(listedPve8, 'Expected Proxmox VM in /api/admin/vms');
        assert.strictEqual(listedPve8.template_icon, '/images/os/proxmox.svg');
        assert.strictEqual(listedPve8.is_proxmox, true);

        const adminDetailPage = await adminClient.request('GET', `/admin/vm/${pve8VmId}`);
        assert.strictEqual(adminDetailPage.status, 200);
        assert.ok(adminDetailPage.text.includes('Proxmox VE Web Console'), 'Expected Proxmox Web Console card in /admin/vm/:id');

        const userDetailPage = await adminClient.request('GET', `/vm/${pve8VmId}`);
        assert.strictEqual(userDetailPage.status, 200);
        assert.ok(userDetailPage.text.includes('Proxmox VE Web Console'), 'Expected Proxmox Web Console card in /vm/:id');

        // 24g. Verify reinstalling a standard Linux VM into Proxmox VE encrypts password & upgrades Web UI port
        const createUbu = await adminClient.request('POST', '/api/vms', {
          vm_name: 'reinstall-to-pve',
          os_template: 'ubuntu_22_cloud',
          hostname: 'reinstall-pve',
          network_type: 'nat',
          ssh_port: 22809,
          custom_password: 'InitialUbuntuPass!1',
        });
        assert.strictEqual(createUbu.status, 200, `Ubuntu VM create failed: ${createUbu.text}`);
        const reinstallVmId = createUbu.json.vm_id;
        createdVmIds.push(reinstallVmId);
        assert.strictEqual(createUbu.json.config.http_port, 80);

        const reinstallRes = await adminClient.request('POST', `/api/vms/${reinstallVmId}/reinstall`, {
          new_os_template: 'proxmox_ve_8',
          new_username: 'root',
          new_password: 'ReinstallPvePass!99',
          confirm: true,
        });
        assert.strictEqual(reinstallRes.status, 200, `Reinstall into Proxmox failed: ${reinstallRes.text}`);
        const afterReinstallRow = await ctx.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [reinstallVmId]);
        assert.strictEqual(afterReinstallRow.template_type, 'proxmox_ve_8');
        assert.strictEqual(isEncryptedSecret(afterReinstallRow.password), true, 'Reinstall must encrypt password at rest');
        assert.ok(afterReinstallRow.http_port >= 8006, `Expected Proxmox Web UI port >= 8006 after reinstall, got ${afterReinstallRow.http_port}`);
        const reinstallIsoText = fs.readFileSync(afterReinstallRow.seed_file, 'utf8');
        assert.ok(reinstallIsoText.includes('root:ReinstallPvePass!99'), 'Reinstalled Proxmox seed ISO must embed decrypted root password');
        assert.ok(reinstallIsoText.includes('proxmox-ve postfix open-iscsi chrony'), 'Reinstalled Proxmox seed ISO must include Proxmox bootstrap');
      } finally {
        process.env.PATH = origPath;
        for (const id of createdVmIds) {
          await adminClient.request('DELETE', `/api/vms/${id}`).catch(() => {});
        }
        for (const f of createdTemplateFiles) {
          try { fs.unlinkSync(f); } catch (_) {}
        }
      }
    });

    // 26. Cloudflare Tunnel / Domain-Only Node Registration (No Public IPv4 IP)
    await runStep('T25: Cloudflare Tunnel / domain-only node registration without IPv4 IP & --join domain preservation', async () => {
      const tls = require('tls');
      const {
        normalizeNodeEndpointUrl,
        isDomainHostname,
      } = require('../lib/services/nodes/NodeClient');

      // Bare domain defaults to https:// (Cloudflare Tunnel port 443)
      assert.strictEqual(isDomainHostname('cf-node01.example.com'), true);
      assert.strictEqual(isDomainHostname('203.0.113.10'), false);
      assert.strictEqual(isDomainHostname('localhost'), false);
      assert.strictEqual(
        normalizeNodeEndpointUrl('cf-node01.example.com'),
        'https://cf-node01.example.com'
      );
      assert.strictEqual(
        normalizeNodeEndpointUrl('https://cf-node01.example.com/api/v1/health'),
        'https://cf-node01.example.com'
      );

      // Admin UI renders #nIp as optional (no HTML5 required attribute blocking empty IPv4)
      const nodesPage = await adminClient.request('GET', '/admin/nodes');
      assert.strictEqual(nodesPage.status, 200);
      assert.ok(
        !/id="nIp"[^>]*\brequired\b/i.test(nodesPage.text),
        '#nIp must be optional so Cloudflare Tunnel / IPv6-only nodes without IPv4 can submit'
      );

      // Create node with blank ipAddress & blank hostname (Cloudflare Tunnel URL only)
      const createCfNode = await adminClient.request('POST', '/api/v1/nodes', {
        name: 'cf-tunnel-mumbai',
        hostname: '',
        ipAddress: '',
        url: 'cf-node01.example.com',
        location: 'Mumbai (Cloudflare Tunnel)',
        verifySsl: true,
      });
      assert.strictEqual(
        createCfNode.status,
        201,
        `Domain-only node create failed: ${createCfNode.text}`
      );
      const cfNodeId = createCfNode.json.node.id;
      try {
        assert.strictEqual(createCfNode.json.node.url, 'https://cf-node01.example.com');
        assert.strictEqual(createCfNode.json.node.hostname, 'cf-node01.example.com');
        assert.strictEqual(createCfNode.json.node.ip_address, 'cf-node01.example.com');
        assert.strictEqual(createCfNode.json.node.verify_ssl, 1);

        // Generated 1-command join script preserves TGVPANEL_ADVERTISE_URL for Tunnel domain
        const joinTokRes = await adminClient.request(
          'POST',
          `/api/v1/nodes/${cfNodeId}/join-token`,
          {
            controllerUrl: 'https://panel.example.com',
            ttlMinutes: 15,
          }
        );
        assert.strictEqual(joinTokRes.status, 201, `Join token create failed: ${joinTokRes.text}`);
        assert.ok(
          joinTokRes.json.curlJoinCommand.includes(
            'TGVPANEL_ADVERTISE_URL="https://cf-node01.example.com"'
          ),
          'Join command must embed TGVPANEL_ADVERTISE_URL when node uses a Tunnel/domain URL'
        );

        // Even if a CGNAT host runs --join without TGVPANEL_ADVERTISE_URL and posts its private LAN IP,
        // redeemJoinToken MUST NOT clobber the configured Cloudflare Tunnel domain!
        const dummySelfSignedPem =
          '-----BEGIN CERTIFICATE-----\nMIIB+TCCAWICAQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDEwMTAwMDAw\nMFoXDTM2MDEwMTAwMDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZI\nzj0CAQYIKoZIzj0DAQcDQgAE1111111111111111111111111111111111111111\n111111111111111111111111111111111111111111111TAAMAoGCCqGSM49BAMC\nA0cAMEQCIB111111111111111111111111111111111111111111AiB222222222\n222222222222222222222222222222222w==\n-----END CERTIFICATE-----';
        const bareNodeClient = new SessionClient(baseUrl);
        const redeemRes = await bareNodeClient.request(
          'POST',
          `/api/v1/nodes/join/${encodeURIComponent(joinTokRes.json.token)}`,
          {
            endpointUrl: 'https://192.168.88.50:8443',
            ipAddress: '192.168.88.50',
            hostname: 'cgnat-box.lan',
            agentPort: 8443,
            tlsCertPem: dummySelfSignedPem,
            verifySsl: true,
          }
        );
        assert.strictEqual(redeemRes.status, 200, `Join redeem failed: ${redeemRes.text}`);
        assert.strictEqual(
          redeemRes.json.url,
          'https://cf-node01.example.com',
          'Configured Cloudflare Tunnel domain must not be overwritten by private LAN IP during --join'
        );

        const afterNode = await ctx.nodeManager.getNodeById(cfNodeId);
        assert.strictEqual(afterNode.url, 'https://cf-node01.example.com');
        assert.strictEqual(afterNode.hostname, 'cf-node01.example.com');

        // Verify buildTlsOptionsForNode merges Mozilla rootCertificates + pinned PEM so Cloudflare Edge CA validates
        const tlsOpts = ctx.nodeManager.buildTlsOptionsForNode(afterNode, {
          tls_ca_pem: dummySelfSignedPem,
        });
        assert.strictEqual(tlsOpts.rejectUnauthorized, true);
        assert.ok(
          Array.isArray(tlsOpts.ca) &&
            tlsOpts.ca.length > tls.rootCertificates.length &&
            tlsOpts.ca.includes(dummySelfSignedPem),
          'TLS CA bundle must include both system root CAs (for Cloudflare Edge) and pinned node cert'
        );
      } finally {
        await adminClient.request('DELETE', `/api/v1/nodes/${cfNodeId}`).catch(() => {});
      }
    });

    // 27. Proxmox VE LXC Images + Local OS Logos on LXC Creation / Catalog / Detail
    await runStep('T26: Proxmox VE 8/9 LXC images, local OS logos (SVG) & first-boot bootstrap wiring', async () => {
      const {
        resolveProxmoxLxcCodename,
        isProxmoxLxcSpec,
        resolveDownloadReleaseCandidates,
        PROXMOX_LXC_GPG_URLS,
      } = require('../lib/node-agent/container-manager');
      const { StorageManager } = require('../lib/services/storage/StorageManager');

      // Unit: codename resolution + download mapping (Proxmox -> Debian base)
      assert.strictEqual(
        resolveProxmoxLxcCodename({ templateSlug: 'proxmox-ve-8', distro: 'debian', release: '12' }),
        'bookworm'
      );
      assert.strictEqual(
        resolveProxmoxLxcCodename({ templateSlug: 'proxmox-ve-9', distro: 'debian', release: '13' }),
        'trixie'
      );
      assert.strictEqual(
        resolveProxmoxLxcCodename({ templateSlug: 'ubuntu-24.04', distro: 'ubuntu', release: '24.04' }),
        null
      );
      assert.strictEqual(isProxmoxLxcSpec({ proxmoxCodename: 'trixie' }), true);
      assert.strictEqual(isProxmoxLxcSpec({ distro: 'ubuntu', release: '24.04' }), false);
      assert.strictEqual(PROXMOX_LXC_GPG_URLS.bookworm, 'https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg');
      assert.strictEqual(PROXMOX_LXC_GPG_URLS.trixie, 'https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg');
      const dlProxmox = resolveDownloadReleaseCandidates('proxmox', '8');
      assert.strictEqual(dlProxmox.distro, 'debian');
      assert.ok(dlProxmox.releases.includes('bookworm'), 'proxmox:8 must download Debian bookworm rootfs');

      // Unit: icon resolution always returns a local SVG path
      assert.strictEqual(
        StorageManager.resolveLxcTemplateIcon({ distro: 'proxmox', slug: 'proxmox-ve-9' }),
        '/images/os/proxmox.svg'
      );
      assert.strictEqual(
        StorageManager.resolveLxcTemplateIcon({ distro: 'rocky', slug: 'rockylinux-9' }),
        '/images/os/rocky.svg'
      );
      assert.strictEqual(
        StorageManager.resolveLxcTemplateIcon({ distro: 'kali', slug: 'kali-rolling' }),
        '/images/os/kali.svg'
      );
      assert.strictEqual(
        StorageManager.resolveLxcTemplateIcon({ distro: 'ubuntu', slug: 'ubuntu-24.04' }),
        '/images/os/ubuntu.svg'
      );

      // Local SVG files exist for every catalog distro (no external Imgur)
      for (const svgName of ['proxmox.svg', 'ubuntu.svg', 'debian.svg', 'fedora.svg', 'centos.svg', 'almalinux.svg', 'rocky.svg', 'kali.svg', 'alpine.svg', 'linux.svg']) {
        const svgPath = path.join(process.cwd(), 'public', 'images', 'os', svgName);
        assert.ok(fs.existsSync(svgPath), `Expected local OS logo at ${svgPath}`);
        const svgContent = fs.readFileSync(svgPath, 'utf8');
        assert.ok(svgContent.includes('<svg'), `Expected valid SVG at ${svgPath}`);
        assert.ok(!svgContent.includes('imgur.com'), `SVG must not reference Imgur: ${svgName}`);
      }

      // API: catalog contains Proxmox VE 8/9 LXC images with logos + PVE minimums
      const tplRes = await adminClient.request('GET', '/api/v1/lxc/templates?all=1');
      assert.strictEqual(tplRes.status, 200, `LXC templates list failed: ${tplRes.text}`);
      const tplList = tplRes.json.templates;
      const pve8 = tplList.find((t) => t.slug === 'proxmox-ve-8');
      const pve9 = tplList.find((t) => t.slug === 'proxmox-ve-9');
      assert.ok(pve8, 'Expected proxmox-ve-8 in LXC template catalog');
      assert.ok(pve9, 'Expected proxmox-ve-9 in LXC template catalog');
      assert.strictEqual(pve8.icon, '/images/os/proxmox.svg');
      assert.strictEqual(pve8.icon_path, '/images/os/proxmox.svg');
      assert.strictEqual(pve8.proxmox_codename, 'bookworm');
      assert.strictEqual(pve8.min_ram_mb, 4096);
      assert.strictEqual(pve8.min_disk_gb, 40);
      assert.strictEqual(pve8.distro, 'debian');
      assert.strictEqual(pve8.release, '12');
      assert.strictEqual(pve9.icon, '/images/os/proxmox.svg');
      assert.strictEqual(pve9.proxmox_codename, 'trixie');
      assert.strictEqual(pve9.min_ram_mb, 4096);
      assert.strictEqual(pve9.min_disk_gb, 40);
      assert.strictEqual(pve9.distro, 'debian');
      assert.strictEqual(pve9.release, '13');
      for (const t of tplList) {
        assert.ok(
          String(t.icon || '').startsWith('/images/os/') && String(t.icon || '').endsWith('.svg'),
          `LXC template ${t.slug} must use a local /images/os/*.svg logo, got: ${t.icon}`
        );
      }

      // UI: LXC create studio renders Proxmox filter + logo <img> (not text badges only)
      const createPage = await adminClient.request('GET', '/admin/instances/create?engine=lxc');
      assert.strictEqual(createPage.status, 200);
      assert.ok(createPage.text.includes('Proxmox VE'), 'LXC create page must mention Proxmox VE');
      assert.ok(createPage.text.includes('data-cat="proxmox"'), 'LXC create page must have a Proxmox category filter');
      assert.ok(createPage.text.includes('/images/os/proxmox.svg'), 'LXC create page must embed the Proxmox logo');
      assert.ok(createPage.text.includes('resolveLxcIconUrl'), 'LXC create page must resolve OS logos via resolveLxcIconUrl');
      assert.ok(createPage.text.includes('lxc-os-icon'), 'LXC create page must render OS logo icons');

      // UI: LXC templates catalog page renders logos
      const tplPage = await adminClient.request('GET', '/admin/lxc-templates');
      assert.strictEqual(tplPage.status, 200);
      assert.ok(tplPage.text.includes('LXC OS Template Catalog'), 'LXC templates page must render');

      // LXC create with Proxmox template (no host provisioning) enforces PVE minimums + bootstrap flag
      const pveCt = await adminClient.request('POST', '/api/v1/lxc', {
        containerName: 'ct-pve9-test',
        templateSlug: 'proxmox-ve-9',
        cpuCores: 2,
        ramMb: 1024,
        diskGb: 10,
        provisionOnHost: false,
      });
      assert.strictEqual(pveCt.status, 201, `Proxmox LXC create (no-provision) failed: ${pveCt.text}`);
      assert.strictEqual(pveCt.json.instance.osLabel, 'proxmox-ve-9');
      assert.ok(pveCt.json.instance.ramMb >= 4096, `Proxmox LXC must enforce >=4096MB RAM, got ${pveCt.json.instance.ramMb}`);
      assert.ok(pveCt.json.instance.diskGb >= 40, `Proxmox LXC must enforce >=40GB disk, got ${pveCt.json.instance.diskGb}`);
      const pveRefId = pveCt.json.instance.refId;
      try {
        const rawPve = await ctx.db.get(`SELECT * FROM lxc_instances WHERE id = ?`, [pveRefId]);
        assert.strictEqual(Number(rawPve.privileged), 1, 'Proxmox LXC must be privileged');
        assert.strictEqual(Number(rawPve.nesting), 1, 'Proxmox LXC must enable nesting');
        assert.strictEqual(Number(rawPve.kvm_nesting), 1, 'Proxmox LXC must enable KVM nesting (/dev/kvm)');
      } finally {
        await adminClient.request('DELETE', `/api/v1/instances/lxc/${pveRefId}`).catch(() => {});
      }
    });

    // 28. Proxmox LXC Bootstrap Robustness (Debian base + PVE on top; neofetch shows Debian by design)
    await runStep('T27: Proxmox LXC bootstrap robustness (apt-daily lock fix, reliable enable symlink, branding)', async () => {
      const { LxcContainerManager } = require('../lib/node-agent/container-manager');
      const { privilegedFs } = require('../lib/node-agent/command-runner');

      // privilegedFs.symlinkSync must exist (fixes silent enable failure on root-owned /var/lib/lxc)
      assert.strictEqual(typeof privilegedFs.symlinkSync, 'function', 'privilegedFs.symlinkSync must exist');

      // Offline-inject bootstrap into a fake rootfs and verify all files + symlink
      const fakeCtName = 'ct-pve-bootstrap-check';
      const fakeRootfs = path.join(tmpRoot, 'local-lxc', fakeCtName, 'rootfs');
      fs.mkdirSync(path.join(fakeRootfs, 'etc', 'systemd', 'system'), { recursive: true });
      fs.mkdirSync(path.join(fakeRootfs, 'etc'), { recursive: true });
      const cm = new LxcContainerManager(path.join(tmpRoot, 'local-lxc'));
      await cm.injectProxmoxLxcBootstrap(fakeCtName, 'bookworm', null);

      const scriptPath = path.join(fakeRootfs, 'usr', 'local', 'sbin', 'tgvpanel-install-proxmox.sh');
      const servicePath = path.join(fakeRootfs, 'etc', 'systemd', 'system', 'tgvpanel-proxmox-setup.service');
      const bannerPath = path.join(fakeRootfs, 'etc', 'profile.d', 'tgvpanel-proxmox-status.sh');
      const motdPath = path.join(fakeRootfs, 'etc', 'motd');
      const infoPath = path.join(fakeRootfs, 'etc', 'tgvpanel-proxmox-info');
      const linkPath = path.join(fakeRootfs, 'etc', 'systemd', 'system', 'multi-user.target.wants', 'tgvpanel-proxmox-setup.service');
      for (const p of [scriptPath, servicePath, bannerPath, motdPath, infoPath]) {
        assert.ok(fs.existsSync(p), `Expected bootstrap file at ${p}`);
      }
      assert.ok(fs.lstatSync(linkPath).isSymbolicLink(), 'Offline enable symlink must exist (systemd multi-user.target.wants)');
      assert.strictEqual(
        fs.readlinkSync(linkPath),
        '/etc/systemd/system/tgvpanel-proxmox-setup.service'
      );

      const script = fs.readFileSync(scriptPath, 'utf8');
      assert.ok(script.includes('apt-daily'), 'Bootstrap must stop apt-daily timers (APT lock fix)');
      assert.ok(script.includes('DPkg::Lock::Timeout=300'), 'Bootstrap must set APT lock timeout');
      assert.ok(script.includes('tee -a'), 'Bootstrap must tee output to log + journal');
      assert.ok(script.includes('proxmox-ve'), 'Bootstrap must install proxmox-ve');
      assert.ok(script.includes('pve-no-subscription'), 'Bootstrap must use pve-no-subscription repo');
      assert.ok(script.includes('proxmox-archive-keyring'), 'Bootstrap must install Proxmox GPG keyring');
      assert.ok(script.includes('bookworm'), 'Bootstrap must target bookworm for VE 8');

      const banner = fs.readFileSync(bannerPath, 'utf8');
      assert.ok(banner.includes('pveversion'), 'Banner must tell user to verify with pveversion');
      assert.ok(banner.includes('neofetch shows Debian'), 'Banner must explain neofetch shows Debian by design');
      assert.ok(banner.includes('/var/log/proxmox-install.log'), 'Banner must point to install log');

      const motd = fs.readFileSync(motdPath, 'utf8');
      assert.ok(motd.includes('Proxmox VE 8'), 'MOTD must brand the container as Proxmox VE 8');
      const info = fs.readFileSync(infoPath, 'utf8');
      assert.ok(info.includes('neofetch reports Debian'), 'Info file must explain Debian base');

      // Catalog descriptions must clarify Debian base (prevents "why Debian?" confusion)
      const tplRes = await adminClient.request('GET', '/api/v1/lxc/templates?all=1');
      const pve8 = tplRes.json.templates.find((t) => t.slug === 'proxmox-ve-8');
      assert.ok(pve8.description.includes('Debian 12 Bookworm base'), 'PVE 8 description must mention Debian base');
      assert.ok(pve8.description.includes('neofetch shows Debian'), 'PVE 8 description must explain neofetch behavior');
    });

    // 29. Proxmox LXC Full Audit Fixes (CPU floor, reinstall DB persist, apt retry, network preserve, UI sync)
    await runStep('T28: Proxmox LXC audit fixes (CPU floor, reinstall persist, apt retry, network preserve, UI sync)', async () => {
      const { LxcContainerManager } = require('../lib/node-agent/container-manager');

      // Bootstrap script must have apt retry + network backup/restore + pve-status helper
      const fakeCtName2 = 'ct-pve-audit-check';
      const fakeRootfs2 = path.join(tmpRoot, 'local-lxc', fakeCtName2, 'rootfs');
      fs.mkdirSync(path.join(fakeRootfs2, 'etc', 'systemd', 'system'), { recursive: true });
      fs.mkdirSync(path.join(fakeRootfs2, 'etc'), { recursive: true });
      const cm2 = new LxcContainerManager(path.join(tmpRoot, 'local-lxc'));
      await cm2.injectProxmoxLxcBootstrap(fakeCtName2, 'trixie', null);
      const script2 = fs.readFileSync(path.join(fakeRootfs2, 'usr', 'local', 'sbin', 'tgvpanel-install-proxmox.sh'), 'utf8');
      assert.ok(script2.includes('apt_retry'), 'Bootstrap must retry apt commands (3 attempts)');
      assert.ok(script2.includes('interfaces.tgvpanel-bak'), 'Bootstrap must backup container network config before PVE install');
      assert.ok(script2.includes('Restoring container eth0'), 'Bootstrap must restore container eth0 networking after PVE install');
      assert.ok(script2.includes('trixie'), 'Bootstrap must target trixie for VE 9');
      const pveStatusPath2 = path.join(fakeRootfs2, 'usr', 'local', 'bin', 'pve-status');
      assert.ok(fs.existsSync(pveStatusPath2), 'pve-status helper must be injected');
      assert.ok(fs.readFileSync(pveStatusPath2, 'utf8').includes('pveversion'), 'pve-status must check pveversion');
      const bashrc2 = fs.readFileSync(path.join(fakeRootfs2, 'root', '.bashrc'), 'utf8');
      assert.ok(bashrc2.includes('tgvpanel-proxmox-status.sh'), 'Root bashrc must hook Proxmox banner for PTY shells');

      // Create with 1 CPU must be bumped to 2 for Proxmox (direct adapter to avoid API rate-limit in full suite)
      const pveCpuCreated = await ctx.lxcAdapter.createLxcInstance({
        userId: 1,
        containerName: 'ct-pve-cpu-check',
        templateSlug: 'proxmox-ve-8',
        cpuCores: 1,
        ramMb: 1024,
        diskGb: 10,
        provisionOnHost: false,
      });
      assert.ok(pveCpuCreated.instance.cpuCores >= 2, `Proxmox LXC must enforce >=2 vCPU, got ${pveCpuCreated.instance.cpuCores}`);
      assert.ok(pveCpuCreated.instance.ramMb >= 4096, 'Proxmox LXC must enforce >=4096MB RAM');
      assert.ok(pveCpuCreated.instance.diskGb >= 40, 'Proxmox LXC must enforce >=40GB disk');
      assert.ok(
        String(pveCpuCreated.warning || '').includes('Proxmox VE bootstrap will NOT run'),
        'DB-only Proxmox create must warn that bootstrap will not run without host provisioning'
      );
      const pveCpuRefId = pveCpuCreated.instance.refId;
      try {
        const rawPveCpu = await ctx.db.get(`SELECT * FROM lxc_instances WHERE id = ?`, [pveCpuRefId]);
        assert.ok(Number(rawPveCpu.cpu_cores) >= 2, 'DB must persist bumped CPU for Proxmox');
        assert.ok(Number(rawPveCpu.ram_mb) >= 4096, 'DB must persist bumped RAM for Proxmox');
        assert.ok(Number(rawPveCpu.disk_gb) >= 40, 'DB must persist bumped disk for Proxmox');
        assert.strictEqual(Number(rawPveCpu.privileged), 1, 'DB must persist privileged for Proxmox');
        assert.strictEqual(Number(rawPveCpu.nesting), 1, 'DB must persist nesting for Proxmox');
        assert.strictEqual(Number(rawPveCpu.kvm_nesting), 1, 'DB must persist KVM nesting for Proxmox');
      } finally {
        await ctx.db.run(`DELETE FROM lxc_instances WHERE id = ?`, [pveCpuRefId]).catch(() => {});
        await ctx.db.run(`DELETE FROM instances WHERE engine = 'lxc' AND ref_id = ?`, [pveCpuRefId]).catch(() => {});
      }

      // UI must auto-sync Proxmox minimums + toggles + preset on select
      const createPage = await adminClient.request('GET', '/admin/instances/create?engine=lxc');
      assert.ok(createPage.text.includes('getDistroBrand(tpl).cat'), 'UI must detect Proxmox via getDistroBrand');
      assert.ok(createPage.text.includes('cPriv'), 'UI must reference privileged toggle');
      assert.ok(createPage.text.includes('neofetch'), 'UI must explain neofetch shows Debian');
      assert.ok(createPage.text.includes('pveversion'), 'UI must point to pveversion verify');

      // Detail page must show Proxmox info card (direct adapter create to avoid rate-limit)
      const pveDetailCreated = await ctx.lxcAdapter.createLxcInstance({
        userId: 1,
        containerName: 'ct-pve-detail-check',
        templateSlug: 'proxmox-ve-9',
        cpuCores: 4,
        ramMb: 4096,
        diskGb: 40,
        provisionOnHost: false,
      });
      const pveDetailRefId = pveDetailCreated.instance.refId;
      try {
        const detailPage = await adminClient.request('GET', `/lxc/${pveDetailRefId}`);
        assert.strictEqual(detailPage.status, 200);
        assert.ok(detailPage.text.includes('Proxmox VE Hypervisor'), 'LXC detail must show Proxmox info card');
        assert.ok(detailPage.text.includes('/var/log/proxmox-install.log'), 'LXC detail must point to install log');
        assert.ok(detailPage.text.includes('pve-status'), 'LXC detail must point to pve-status helper');
        assert.ok(detailPage.text.includes('/images/os/proxmox.svg'), 'LXC detail must show Proxmox logo');
        assert.ok(detailPage.text.includes('Cloudflare Quick Tunnel'), 'Proxmox LXC detail must expose the Cloudflare option');
        assert.ok(detailPage.text.includes('Install Cloudflare &amp; Start Tunnel'), 'Cloudflare button must install cloudflared and start the tunnel');
        assert.ok(detailPage.text.includes('Anyone with the generated URL'), 'Detail page must warn that the URL exposes the public Proxmox login page');
        await assert.rejects(
          ctx.lxcAdapter.startProxmoxCloudflareTunnel(pveDetailRefId),
          /rootfs is missing/i,
          'Cloudflare tunnel must not start when no container rootfs was provisioned'
        );
      } finally {
        await ctx.db.run(`DELETE FROM lxc_instances WHERE id = ?`, [pveDetailRefId]).catch(() => {});
        await ctx.db.run(`DELETE FROM instances WHERE engine = 'lxc' AND ref_id = ?`, [pveDetailRefId]).catch(() => {});
      }
    });

    // 30. Proxmox-only Cloudflare Quick Tunnel flow and live status/log extraction
    await runStep('T29: Proxmox Cloudflare Quick Tunnel (safe installer, progress logs, URL extraction)', async () => {
      const { LxcContainerManager } = require('../lib/node-agent/container-manager');
      const fakeCtName = 'ct-pve-cloudflare-status';
      const fakeRootfs = path.join(tmpRoot, 'local-lxc', fakeCtName, 'rootfs');
      fs.mkdirSync(path.join(fakeRootfs, 'var', 'lib', 'tgvpanel-cloudflare'), { recursive: true });
      fs.mkdirSync(path.join(fakeRootfs, 'var', 'log'), { recursive: true });
      fs.mkdirSync(path.join(fakeRootfs, 'root'), { recursive: true });
      fs.writeFileSync(
        path.join(fakeRootfs, 'var', 'lib', 'tgvpanel-cloudflare', 'status'),
        'state=ready\\nstep=Cloudflare Quick Tunnel is live\\nurl=https://sample-tunnel.trycloudflare.com\\n'
      );
      fs.writeFileSync(path.join(fakeRootfs, 'var', 'log', 'tgvpanel-cloudflare-setup.log'), '[3/7] Adding Cloudflare repository\\n');
      fs.writeFileSync(path.join(fakeRootfs, 'root', 'cloudflared.log'), 'Your quick Tunnel has been created! Visit it at https://sample-tunnel.trycloudflare.com\\n');
      const cm = new LxcContainerManager(path.join(tmpRoot, 'local-lxc'));

      // Build the fixed installer into a fake rootfs and validate its Bash syntax without needing host LXC.
      const scriptCtName = 'ct-pve-cloudflare-script';
      const scriptRootfs = path.join(tmpRoot, 'local-lxc', scriptCtName, 'rootfs');
      fs.mkdirSync(path.join(scriptRootfs, 'var', 'lib'), { recursive: true });
      fs.writeFileSync(path.join(scriptRootfs, 'var', 'lib', 'tgvpanel-proxmox-installed'), '');
      cm.inspectContainer = async () => ({ state: 'running' });
      await cm.startProxmoxCloudflareTunnel(scriptCtName).catch(() => {});
      const installerScript = path.join(scriptRootfs, 'usr', 'local', 'sbin', 'tgvpanel-cloudflare-setup.sh');
      assert.ok(fs.existsSync(installerScript), 'Cloudflare setup must write its fixed installer script into the Proxmox rootfs');
      require('child_process').execFileSync('bash', ['-n', installerScript]);

      // Exercise the same repo-disabling function against fixture sources (including both APT formats).
      const generatedInstaller = fs.readFileSync(installerScript, 'utf8');
      const disableFn = generatedInstaller.match(/^disable_enterprise_repositories\(\) \{[\s\S]*?^\}/m);
      assert.ok(disableFn, 'Installer must include Proxmox Enterprise repo handling');
      const aptFixtureDir = path.join(tmpRoot, 'cloudflare-apt-fixture');
      const aptSourceDir = path.join(aptFixtureDir, 'sources.list.d');
      fs.mkdirSync(aptSourceDir, { recursive: true });
      const pveListPath = path.join(aptSourceDir, 'pve-enterprise.list');
      const pveDeb822Path = path.join(aptSourceDir, 'pve-enterprise.sources');
      fs.writeFileSync(pveListPath, 'deb https://enterprise.proxmox.com/debian/pve bookworm pve-enterprise\ndeb http://download.proxmox.com/debian/pve bookworm pve-no-subscription\n');
      fs.writeFileSync(pveDeb822Path, 'Types: deb\nURIs: https://enterprise.proxmox.com/debian/pve\nSuites: bookworm\nComponents: pve-enterprise\n');
      const repoTestScript = path.join(tmpRoot, 'cloudflare-repo-test.sh');
      fs.writeFileSync(repoTestScript, disableFn[0].replace(/\/etc\/apt/g, aptFixtureDir) + '\ndisable_enterprise_repositories\n');
      require('child_process').execFileSync('bash', [repoTestScript]);
      assert.ok(fs.readFileSync(pveListPath, 'utf8').includes('# TGVPANEL disabled subscription-only repo'), 'Legacy PVE enterprise list entries must be disabled');
      assert.ok(fs.readFileSync(pveDeb822Path, 'utf8').includes('Enabled: no'), 'DEB822 PVE enterprise source stanzas must be disabled');
      assert.ok(fs.existsSync(pveListPath + '.tgvpanel.bak'), 'Original PVE enterprise list must be backed up');
      assert.ok(fs.existsSync(pveDeb822Path + '.tgvpanel.bak'), 'Original DEB822 PVE enterprise source must be backed up');

      const status = cm.getProxmoxCloudflareTunnelStatus(fakeCtName);
      assert.strictEqual(status.state, 'ready');
      assert.strictEqual(status.url, 'https://sample-tunnel.trycloudflare.com');
      assert.ok(status.setupLog.includes('Adding Cloudflare repository'), 'Status API must return live installer output');
      assert.ok(status.tunnelLog.includes('trycloudflare.com'), 'Status API must return /root/cloudflared.log');

      const managerSource = fs.readFileSync(path.resolve(__dirname, '../src/node-agent/container-manager.ts'), 'utf8');
      for (const required of [
        'https://pkg.cloudflare.com/cloudflare-main.gpg',
        'https://pkg.cloudflare.com/cloudflared',
        'disable_enterprise_repositories',
        'enterprise.proxmox.com',
        'Enabled: no',
        'apt-get install',
        'cloudflared tunnel --url https://localhost:8006 --no-tls-verify',
        'tgvpanel-cloudflared.service',
        "'/usr/bin/pveversion'",
        'trycloudflare\\\\.com',
      ]) {
        assert.ok(managerSource.includes(required), `Cloudflare flow must include ${required}`);
      }
      const controllerApi = fs.readFileSync(path.resolve(__dirname, '../src/api/v1/router.ts'), 'utf8');
      const nodeApi = fs.readFileSync(path.resolve(__dirname, '../src/node-agent/agent.ts'), 'utf8');
      assert.ok(controllerApi.includes("router.post('/lxc/:id/cloudflare-tunnel'"), 'Owner-authorized LXC Cloudflare start endpoint must exist');
      assert.ok(controllerApi.includes("router.get('/lxc/:id/cloudflare-tunnel'"), 'Authorized LXC Cloudflare status endpoint must exist');
      assert.ok(nodeApi.includes("app.post('/api/v1/containers/:name/cloudflare-tunnel'"), 'Remote Node Agent must support starting the tunnel');
      assert.ok(nodeApi.includes("app.get('/api/v1/containers/:name/cloudflare-tunnel'"), 'Remote Node Agent must relay live tunnel status');
    });


  } finally {
    const { execFileSync } = require('child_process');
    for (const storeDir of [
      path.join(tmpRoot, 'local-lxc'),
      path.join(tmpRoot, 'agent-lxc'),
      path.join(tmpRoot, 'https-agent-lxc'),
    ]) {
      try {
        if (fs.existsSync(storeDir)) {
          for (const entry of fs.readdirSync(storeDir)) {
            const pidFile = path.join(storeDir, entry, '.pid');
            if (fs.existsSync(pidFile)) {
              const p = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
              if (p > 0) {
                try { execFileSync('sudo', ['-n', 'kill', '-KILL', String(p)]); } catch (_) {}
              }
            }
          }
        }
      } catch (_) {}
    }
    for (const d of rootOwnedCleanupDirs) {
      try { execFileSync('sudo', ['-n', 'rm', '-rf', d]); } catch (_) {}
    }
    for (const shimPath of installedLxcShims) {
      try { execFileSync('sudo', ['-n', 'rm', '-f', shimPath]); } catch (_) {}
    }
    if (httpsAgentServer) await new Promise((r) => httpsAgentServer.close(() => r()));
    if (agentServer) await new Promise((r) => agentServer.close(() => r()));
    if (app && app.getHkvmV3Context()) {
      app.getHkvmV3Context().monitoringService.stopBackgroundLoop();
      app.getHkvmV3Context().backupManager.stopScheduleLoop();
      app.getHkvmV3Context().lxcAdapter.stopExpirationLoop();
      await app.getHkvmV3Context().db.close().catch(() => {});
    }
    if (app && app.server) {
      await new Promise((r) => app.server.close(() => r()));
    }
    try {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    } catch {
      try { execFileSync('sudo', ['-n', 'rm', '-rf', tmpRoot]); } catch (_) {}
    }
  }

  const failed = results.filter((r) => r.status === 'FAIL');
  console.log('\n--------------------------------------------------------------------');
  console.log(`  Summary: ${results.length - failed.length}/${results.length} Acceptance Suites Passed`);
  console.log('--------------------------------------------------------------------\n');
  process.exit(failed.length > 0 ? 1 : 0);
})();
