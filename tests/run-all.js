#!/usr/bin/env node
/**
 * HKVM V3 — End-to-End Integration, Security & Acceptance Test Suite
 *
 * Runs against an isolated temporary clone of data/hkvm.db so live database state
 * is never polluted. Exercises real SQLite, real Express + WebSocket server,
 * real standalone Node Agent HTTP/HMAC server, real AES-256-GCM/TOTP/CSRF/RBAC,
 * real Werkzeug pbkdf2/scrypt legacy HVM importer, and real node-pty restricted shell.
 */
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const sqlite3 = require('sqlite3');
const WebSocket = require('ws');

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hkvm-v3-acceptance-'));
const testDbPath = path.join(tmpRoot, 'hkvm.db');
const candidateBackupDb = path.resolve(__dirname, '../data/backups/hkvm_v2_initial.db');
const primaryRepoDb = path.resolve(__dirname, '../data/hkvm.db');
fs.copyFileSync(fs.existsSync(candidateBackupDb) ? candidateBackupDb : primaryRepoDb, testDbPath);

const TEST_PORT = 18940 + Math.floor(Math.random() * 500);
const AGENT_PORT = 19540 + Math.floor(Math.random() * 500);

process.env.HKVM_DATA_DIR = tmpRoot;
process.env.HKVM_DB_PATH = testDbPath;
process.env.HKVM_LXC_PATH = path.join(tmpRoot, 'local-lxc');
process.env.HKVM_BACKUP_DIR = path.join(tmpRoot, 'local-backups');
process.env.PORT = String(TEST_PORT);
process.env.HKVM_DISABLE_BACKGROUND_POLLER = 'true';
process.env.HKVM_ENABLE_NODE_SHELL = 'true';

const {
  getSecretBundle,
  encryptSecret,
  decryptSecret,
  isEncryptedSecret,
  generateApiKeyPair,
  hashApiKey,
  signAgentRequest,
  computeTotpCode,
  verifyTotpCode,
} = require('../lib/security/crypto-vault');
const { UnifiedDatabase } = require('../lib/db/database');
const { runMigrations } = require('../lib/db/migrations');
const { importHvmDatabase } = require('../lib/db/hvm-importer');
const { createNodeAgentServer } = require('../lib/node-agent/agent');
const { runAllowlistedCommand, buildSafeSpawnEnv } = require('../lib/node-agent/command-runner');
const {
  LxcContainerManager,
  resolveDownloadReleaseCandidates,
  computeIpv4SubnetCidr,
  resolveGuestDnsServers,
} = require('../lib/node-agent/container-manager');

const results = [];
async function runStep(name, fn) {
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
  console.log('  HKVM V3 — Unified Virtualization Panel Acceptance Test Suite');
  console.log('====================================================================\n');

  let agentServer = null;
  let app = null;
  let remoteNodeId = null;
  const installedLxcShims = [];
  const rootOwnedCleanupDirs = [];

  try {
    // 1. Pre-boot migration & schema preservation test on a clean HKVM V2 baseline DB
    await runStep('T01: Transactional SQLite backup & migrations v001..v007 preserve legacy HKVM data & rebrand default email', async () => {
      const v2ScratchPath = path.join(tmpRoot, 'v2_scratch.db');
      const v2Raw = new sqlite3.Database(v2ScratchPath);
      const v2Db = new UnifiedDatabase(v2Raw, v2ScratchPath);
      await v2Db.exec(`
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, email TEXT, full_name TEXT, role TEXT DEFAULT 'user', is_active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        INSERT INTO users (username, password, email, role) VALUES ('admin', '$2a$10$legacyhashplaceholder123456789012345678901234567', 'admin@hopingboyz.local', 'admin');
        CREATE TABLE vms (vm_id INTEGER PRIMARY KEY AUTOINCREMENT, vm_name TEXT, hostname TEXT, owner_id INTEGER, memory INTEGER DEFAULT 1024, cpus INTEGER DEFAULT 1, disk_size TEXT DEFAULT '20G', status TEXT DEFAULT 'stopped', password TEXT);
        CREATE TABLE vm_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, vm_id INTEGER, action TEXT, status TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE vm_snapshots (snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT, vm_id INTEGER, snapshot_name TEXT, size_gb REAL, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE os_templates (template_id INTEGER PRIMARY KEY AUTOINCREMENT, template_key TEXT UNIQUE, template_name TEXT, password TEXT);
        CREATE TABLE settings (setting_key TEXT PRIMARY KEY, setting_value TEXT, updated_at DATETIME);
        CREATE TABLE discord_settings (id INTEGER PRIMARY KEY, enabled INTEGER DEFAULT 0);
        CREATE TABLE user_discord_accounts (id INTEGER PRIMARY KEY, user_id INTEGER, discord_id TEXT);
      `);

      const migRes = await runMigrations(v2Db);
      assert.ok(migRes.applied.length >= 7, 'Expected v001..v007 migrations to apply');
      assert.ok(migRes.backupPath && fs.existsSync(migRes.backupPath), 'Expected pre-migration backup');

      const lxcCols = await v2Db.all(`PRAGMA table_info(lxc_instances)`);
      assert.ok(lxcCols.some((c) => c.name === 'kvm_nesting'), 'Expected kvm_nesting column on lxc_instances');

      const adminUser = await v2Db.get(`SELECT * FROM users WHERE username = 'admin'`);
      assert.ok(adminUser, 'Legacy admin user preserved');
      assert.strictEqual(adminUser.email, 'admin@shadowgamerind.local', 'Expected default email rebranded to ShadowGamerIND');
      const templates = await v2Db.all(`SELECT * FROM lxc_templates`);
      assert.ok(templates.length >= 15, 'Seeded LXC OS template catalog');
      await v2Db.close();

      // Ensure testDbPath also has all migrations applied cleanly
      const rawSqlite = new sqlite3.Database(testDbPath);
      const udb = new UnifiedDatabase(rawSqlite, testDbPath);
      await runMigrations(udb);
      await udb.close();
    });

    // 2. Cryptographic Vault & API Key Hashing
    await runStep('T02: Secret vault (.hkvm-secret), AES-256-GCM encryption & tamper rejection', async () => {
      const bundle = getSecretBundle();
      assert.ok(bundle.sessionSecret.length >= 32);
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

      const vm = await ctx.db.get(`SELECT vm_id FROM vms LIMIT 1`);
      await ctx.db.run(`UPDATE vms SET pid = ?, status = 'running' WHERE vm_id = ?`, [
        process.pid,
        vm.vm_id,
      ]);
      const tel = await ctx.kvmAdapter.getTelemetry(vm.vm_id);
      assert.strictEqual(tel.pid, process.pid);
      assert.ok(tel.ramUsedMb > 10, `Expected real RSS > 10MB from /proc/${process.pid}/status`);
      await ctx.db.run(`UPDATE vms SET pid = NULL, status = 'stopped' WHERE vm_id = ?`, [vm.vm_id]);

      const freezeKvm = await adminClient.request('POST', `/api/v1/instances/kvm/${vm.vm_id}/action`, {
        action: 'freeze',
      });
      assert.strictEqual(freezeKvm.status, 400);
      assert.match(freezeKvm.json.error, /only supported for LXC/i);
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
      }

      const aliceLxc = await ctx.db.get(`SELECT id FROM lxc_instances WHERE container_name = 'ct-alice-01'`);
      const userPages = ['/dashboard', '/instances', '/lxc', `/lxc/${aliceLxc.id}`, `/lxc/${aliceLxc.id}/console`, '/ports', '/security', '/profile'];
      for (const p of userPages) {
        const r = await adminClient.request('GET', p);
        assert.strictEqual(r.status, 200, `Expected 200 OK on user route ${p}, got ${r.status}`);
      }

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
    echo "CPU use:        1.35 seconds"
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
        path.join(process.env.HKVM_LXC_PATH, 'e2e-ubuntu-01', 'rootfs', 'etc', 'shadow')
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
      const orphanDir = path.join(process.env.HKVM_LXC_PATH, 'e2e-orphan-03');
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
        path.join(process.env.HKVM_LXC_PATH, 'e2e-orphan-03', '.fail_cgroup_once'),
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
        process.env.HKVM_LXC_PATH,
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
        path.join(process.env.HKVM_LXC_PATH, 'e2e-ubuntu-01', '.live_cgroup')
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

      const bkpVerify = await adminClient.request('POST', `/api/v1/backups/${lxcBkpId}/verify`, {});
      assert.strictEqual(bkpVerify.status, 200);
      assert.strictEqual(bkpVerify.json.valid, true);

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
        !fs.existsSync(path.join(process.env.HKVM_LXC_PATH, 'e2e-ubuntu-01')),
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

      const cfgPath = path.join(process.env.HKVM_LXC_PATH, 'kvm-nested-lxc-01', 'config');
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
      const omitMarker = path.join(process.env.HKVM_LXC_PATH, 'kvm-nested-lxc-01', '.omit_mem_use');
      execFileSync('sudo', ['-n', 'touch', omitMarker]);
      const localCm = new LxcContainerManager(process.env.HKVM_LXC_PATH);
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
      const prevDnsEnv = process.env.HKVM_LXC_DNS;
      process.env.HKVM_LXC_DNS = '127.0.0.254';
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
      if (prevDnsEnv === undefined) delete process.env.HKVM_LXC_DNS;
      else process.env.HKVM_LXC_DNS = prevDnsEnv;

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

      const ctDir = path.join(process.env.HKVM_LXC_PATH, 'net-fix-ubuntu-01');
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
      const localCm = new LxcContainerManager(process.env.HKVM_LXC_PATH);
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

      const stageCtDir = path.join(process.env.HKVM_LXC_PATH, 'cgroup-stage-preserve-01');
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
          const cmTest = new LxcContainerManager(process.env.HKVM_LXC_PATH);
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
      }
    });
  } finally {
    const { execFileSync } = require('child_process');
    for (const storeDir of [path.join(tmpRoot, 'local-lxc'), path.join(tmpRoot, 'agent-lxc')]) {
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
    if (agentServer) await new Promise((r) => agentServer.close(() => r()));
    if (app && app.getHkvmV3Context()) {
      app.getHkvmV3Context().monitoringService.stopBackgroundLoop();
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
