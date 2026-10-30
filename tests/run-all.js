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
const { runAllowlistedCommand } = require('../lib/node-agent/command-runner');
const { LxcContainerManager } = require('../lib/node-agent/container-manager');

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
      payload = typeof body === 'string' ? body : JSON.stringify(body);
      headers['Content-Type'] = headers['Content-Type'] || 'application/json';
      headers['Content-Length'] = Buffer.byteLength(payload);
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

  try {
    // 1. Pre-boot migration & schema preservation test on a clean HKVM V2 baseline DB
    await runStep('T01: Transactional SQLite backup & migrations v001..v005 preserve legacy HKVM data', async () => {
      const v2ScratchPath = path.join(tmpRoot, 'v2_scratch.db');
      const v2Raw = new sqlite3.Database(v2ScratchPath);
      const v2Db = new UnifiedDatabase(v2Raw, v2ScratchPath);
      await v2Db.exec(`
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, email TEXT, full_name TEXT, role TEXT DEFAULT 'user', is_active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        INSERT INTO users (username, password, email, role) VALUES ('admin', '$2a$10$legacyhashplaceholder123456789012345678901234567', 'admin@hkvm.local', 'admin');
        CREATE TABLE vms (vm_id INTEGER PRIMARY KEY AUTOINCREMENT, vm_name TEXT, hostname TEXT, owner_id INTEGER, memory INTEGER DEFAULT 1024, cpus INTEGER DEFAULT 1, disk_size TEXT DEFAULT '20G', status TEXT DEFAULT 'stopped', password TEXT);
        CREATE TABLE vm_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, vm_id INTEGER, action TEXT, status TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE vm_snapshots (snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT, vm_id INTEGER, snapshot_name TEXT, size_gb REAL, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE os_templates (template_id INTEGER PRIMARY KEY AUTOINCREMENT, template_key TEXT UNIQUE, template_name TEXT, password TEXT);
        CREATE TABLE settings (setting_key TEXT PRIMARY KEY, setting_value TEXT, updated_at DATETIME);
        CREATE TABLE discord_settings (id INTEGER PRIMARY KEY, enabled INTEGER DEFAULT 0);
        CREATE TABLE user_discord_accounts (id INTEGER PRIMARY KEY, user_id INTEGER, discord_id TEXT);
      `);

      const migRes = await runMigrations(v2Db);
      assert.ok(migRes.applied.length >= 5, 'Expected v001..v005 migrations to apply');
      assert.ok(migRes.backupPath && fs.existsSync(migRes.backupPath), 'Expected pre-migration backup');

      const adminUser = await v2Db.get(`SELECT * FROM users WHERE username = 'admin'`);
      assert.ok(adminUser, 'Legacy admin user preserved');
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
      const remoteNodeId = regRes.json.node.id;
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
        () => runAllowlistedCommand('uname', ['-a\0evil']),
        /Null byte|invalid/i
      );

      const fakeLxcBase = path.join(tmpRoot, 'lxc-jail');
      const ctRoot = path.join(fakeLxcBase, 'ct-jail-test', 'rootfs');
      fs.mkdirSync(path.join(ctRoot, 'etc'), { recursive: true });
      fs.writeFileSync(path.join(ctRoot, 'etc', 'hostname'), 'ct-jail-test\n');

      const cm = new LxcContainerManager(fakeLxcBase);
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

      // Also verify Safe Diagnostic Preset API over allowlisted command runner
      const diagRes = await adminClient.request('POST', '/api/v1/nodes/1/diagnostics/uname', {});
      assert.strictEqual(diagRes.status, 200, `Diag preset failed: ${diagRes.text}`);
    });
  } finally {
    if (agentServer) await new Promise((r) => agentServer.close(() => r()));
    if (app && app.getHkvmV3Context()) {
      app.getHkvmV3Context().monitoringService.stopBackgroundLoop();
      await app.getHkvmV3Context().db.close().catch(() => {});
    }
    if (app && app.server) {
      await new Promise((r) => app.server.close(() => r()));
    }
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }

  const failed = results.filter((r) => r.status === 'FAIL');
  console.log('\n--------------------------------------------------------------------');
  console.log(`  Summary: ${results.length - failed.length}/${results.length} Acceptance Suites Passed`);
  console.log('--------------------------------------------------------------------\n');
  process.exit(failed.length > 0 ? 1 : 0);
})();
