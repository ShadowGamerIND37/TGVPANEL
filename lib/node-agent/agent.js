"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LocalNodeRuntime = void 0;
exports.createNodeAgentServer = createNodeAgentServer;
const fs_1 = __importDefault(require("fs"));
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const path_1 = __importDefault(require("path"));
const express_1 = __importDefault(require("express"));
const ws_1 = require("ws");
const authentication_1 = require("./authentication");
const health_1 = require("./health");
const host_stats_1 = require("./host-stats");
const container_manager_1 = require("./container-manager");
const snapshot_manager_1 = require("./snapshot-manager");
const transfer_manager_1 = require("./transfer-manager");
const container_console_1 = require("./container-console");
const shell_manager_1 = require("./shell-manager");
const crypto_vault_1 = require("../security/crypto-vault");
/**
 * In-process runtime combining all Node Agent managers.
 * Used BOTH by the standalone remote Node Agent daemon (`startNodeAgentServer`)
 * AND directly by the HKVM controller for the `localhost` node.
 */
class LocalNodeRuntime {
    statsCollector;
    containerManager;
    snapshotManager;
    transferManager;
    consoleManager;
    shellManager;
    constructor(options) {
        this.statsCollector = new host_stats_1.HostStatsCollector();
        this.containerManager = new container_manager_1.LxcContainerManager(options?.lxcBaseDir);
        this.snapshotManager = new snapshot_manager_1.LxcSnapshotAndBackupManager(options?.backupDir, options?.lxcBaseDir);
        this.transferManager = new transfer_manager_1.LxcTransferManager(this.containerManager, this.snapshotManager);
        this.consoleManager = new container_console_1.LxcContainerConsoleManager(undefined, options?.lxcBaseDir);
        this.shellManager = new shell_manager_1.AdminNodeShellManager({
            interactiveEnabled: options?.interactiveHostShell,
            onAuditEvent: options?.onAuditEvent,
        });
    }
}
exports.LocalNodeRuntime = LocalNodeRuntime;
function createNodeAgentServer(opts = {}) {
    const host = opts.host || process.env.HKVM_AGENT_HOST || '0.0.0.0';
    const port = Number(opts.port || process.env.HKVM_AGENT_PORT || 5055);
    const nodeId = opts.nodeId || process.env.HKVM_NODE_ID || 'remote-node';
    const rawApiKey = opts.apiKey || process.env.HKVM_NODE_API_KEY || '';
    const hmacSecret = opts.hmacSecret || process.env.HKVM_NODE_HMAC_SECRET || '';
    if (!rawApiKey || !hmacSecret) {
        throw new Error('HKVM Node Agent requires HKVM_NODE_API_KEY and HKVM_NODE_HMAC_SECRET to start securely.');
    }
    const runtime = new LocalNodeRuntime({
        lxcBaseDir: opts.lxcBaseDir,
        backupDir: opts.backupDir,
    });
    const authenticator = new authentication_1.NodeAgentAuthenticator({
        nodeId,
        apiKeyHash: (0, crypto_vault_1.hashApiKey)(rawApiKey),
        hmacSecret,
        requireMtls: Boolean(opts.requireMtls || process.env.HKVM_NODE_MTLS === 'true'),
        credentialsFilePath: path_1.default.join(process.env.HKVM_DATA_DIR || path_1.default.resolve(process.cwd(), 'data'), 'node-agent-credentials.json'),
    });
    const app = (0, express_1.default)();
    app.use(express_1.default.json({
        limit: '64mb',
        verify: (req, _res, buf) => {
            req.rawBody = buf.toString('utf8');
        },
    }));
    // Authenticated REST endpoints
    app.use('/api/v1', authenticator.expressMiddleware());
    app.get('/api/v1/health', async (req, res) => {
        const report = await (0, health_1.getNodeHealthReport)(req.query.refresh === '1');
        res.json(report);
    });
    app.get('/api/v1/stats', async (_req, res) => {
        const stats = await runtime.statsCollector.collect();
        res.json(stats);
    });
    app.get('/api/v1/containers', async (_req, res) => {
        const list = await runtime.containerManager.listContainers();
        res.json({ containers: list });
    });
    app.get('/api/v1/containers/:name', async (req, res) => {
        try {
            const info = await runtime.containerManager.inspectContainer(req.params.name);
            res.json(info);
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers', async (req, res) => {
        try {
            const info = await runtime.containerManager.createContainer(req.body);
            res.status(201).json(info);
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/action', async (req, res) => {
        try {
            const { action, force, password, sshPublicKey } = req.body || {};
            const name = req.params.name;
            switch (action) {
                case 'start':
                    await runtime.containerManager.startContainer(name);
                    break;
                case 'stop':
                    await runtime.containerManager.stopContainer(name, Boolean(force));
                    break;
                case 'restart':
                    await runtime.containerManager.restartContainer(name);
                    break;
                case 'freeze':
                    await runtime.containerManager.freezeContainer(name);
                    break;
                case 'unfreeze':
                    await runtime.containerManager.unfreezeContainer(name);
                    break;
                case 'destroy':
                    await runtime.containerManager.destroyContainer(name);
                    break;
                case 'password':
                    await runtime.containerManager.setRootPassword(name, String(password || ''));
                    break;
                case 'ssh_key':
                    await runtime.containerManager.injectSshPublicKey(name, String(sshPublicKey || ''));
                    break;
                default:
                    return res.status(400).json({ error: `Unsupported container action: ${action}` });
            }
            const updated = await runtime.containerManager.inspectContainer(name);
            return res.json({ success: true, container: updated });
        }
        catch (err) {
            return res.status(500).json({ error: err.message });
        }
    });
    app.patch('/api/v1/containers/:name/resources', async (req, res) => {
        try {
            await runtime.containerManager.updateContainerResources(req.params.name, req.body || {});
            const info = await runtime.containerManager.inspectContainer(req.params.name);
            res.json({ success: true, container: info });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/reinstall', async (req, res) => {
        try {
            const info = await runtime.containerManager.reinstallContainer({
                ...req.body,
                containerName: req.params.name,
            });
            res.json({ success: true, container: info });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.get('/api/v1/containers/:name/processes', async (req, res) => {
        try {
            const processes = await runtime.containerManager.getContainerProcesses(req.params.name);
            res.json({ processes });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.get('/api/v1/containers/:name/logs', async (req, res) => {
        try {
            const logs = await runtime.containerManager.getContainerLogs(req.params.name);
            res.json({ logs });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    // Confined container file browser
    app.get('/api/v1/containers/:name/files', (req, res) => {
        try {
            const subPath = String(req.query.path || '/');
            const entries = runtime.containerManager.listRootfsDirectory(req.params.name, subPath);
            res.json({ path: subPath, entries });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    app.get('/api/v1/containers/:name/files/content', (req, res) => {
        try {
            const subPath = String(req.query.path || '/');
            const buf = runtime.containerManager.readRootfsFile(req.params.name, subPath);
            res.json({ path: subPath, contentBase64: buf.toString('base64'), size: buf.length });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/files/content', (req, res) => {
        try {
            const { path: subPath, contentBase64, content } = req.body || {};
            const data = typeof contentBase64 === 'string'
                ? Buffer.from(contentBase64, 'base64')
                : Buffer.from(String(content ?? ''), 'utf8');
            runtime.containerManager.writeRootfsFile(req.params.name, String(subPath || '/'), data);
            res.json({ success: true });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    app.delete('/api/v1/containers/:name/files', (req, res) => {
        try {
            const subPath = String(req.query.path || '');
            runtime.containerManager.deleteRootfsEntry(req.params.name, subPath);
            res.json({ success: true });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    // Snapshots & Backups
    app.get('/api/v1/containers/:name/snapshots', async (req, res) => {
        try {
            const snapshots = await runtime.snapshotManager.listSnapshots(req.params.name);
            res.json({ snapshots });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/snapshots', async (req, res) => {
        try {
            const snap = await runtime.snapshotManager.createSnapshot(req.params.name, String(req.body?.comment || ''));
            res.status(201).json({ snapshot: snap });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/snapshots/:snap/restore', async (req, res) => {
        try {
            await runtime.snapshotManager.restoreSnapshot(req.params.name, req.params.snap);
            res.json({ success: true });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.delete('/api/v1/containers/:name/snapshots/:snap', async (req, res) => {
        try {
            await runtime.snapshotManager.deleteSnapshot(req.params.name, req.params.snap);
            res.json({ success: true });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/backups', async (req, res) => {
        try {
            const artifact = await runtime.snapshotManager.createTarBackup(req.params.name, req.body?.label);
            res.status(201).json({ backup: artifact });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/containers/:name/backups/restore', async (req, res) => {
        try {
            const name = req.params.name;
            const { filePath, expectedSha256 } = req.body || {};
            const confined = runtime.snapshotManager.resolveConfinedBackupPath(String(filePath || ''));
            const before = await runtime.containerManager.inspectContainer(name);
            const wasRunning = before.state === 'running' || before.state === 'frozen';
            if (wasRunning) {
                await runtime.containerManager.stopContainer(name, false);
            }
            await runtime.snapshotManager.restoreTarBackup(confined, expectedSha256 ? String(expectedSha256) : undefined, name);
            if (wasRunning) {
                await runtime.containerManager.startContainer(name);
            }
            const after = await runtime.containerManager.inspectContainer(name);
            res.json({ success: true, container: after });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/backups/verify', async (req, res) => {
        try {
            const { filePath, expectedSha256 } = req.body || {};
            const confined = runtime.snapshotManager.resolveConfinedBackupPath(String(filePath || ''));
            if (!fs_1.default.existsSync(confined)) {
                return res.json({ valid: false, expectedSha256: expectedSha256 || null, actualSha256: null });
            }
            const actual = await runtime.snapshotManager.computeFileSha256(confined);
            const valid = !expectedSha256 || String(expectedSha256).toLowerCase() === actual.toLowerCase();
            return res.json({ valid, expectedSha256: expectedSha256 || null, actualSha256: actual });
        }
        catch (err) {
            return res.status(400).json({ error: err.message });
        }
    });
    app.delete('/api/v1/backups/file', (req, res) => {
        try {
            const filePath = String(req.body?.filePath || req.query.filePath || '');
            const confined = runtime.snapshotManager.resolveConfinedBackupPath(filePath);
            if (fs_1.default.existsSync(confined)) {
                fs_1.default.unlinkSync(confined);
            }
            res.json({ success: true });
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    // Offline migration export/import endpoints
    app.post('/api/v1/transfers/export', async (req, res) => {
        try {
            const bundle = await runtime.transferManager.prepareOfflineExport(String(req.body?.containerName || ''));
            const dataBase64 = fs_1.default.readFileSync(bundle.archivePath).toString('base64');
            res.json({ ...bundle, archiveBase64: dataBase64 });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/transfers/import', async (req, res) => {
        try {
            const { containerName, archiveBase64, expectedChecksumSha256, targetBridge, targetIpv4, targetGateway, startAfterImport, } = req.body || {};
            const buf = Buffer.from(String(archiveBase64 || ''), 'base64');
            const result = await runtime.transferManager.importAndVerifyBundle({
                containerName,
                archiveBufferOrPath: buf,
                expectedChecksumSha256,
                targetBridge,
                targetIpv4,
                targetGateway,
                startAfterImport,
            });
            res.json(result);
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/api/v1/diagnostics/:preset', async (req, res) => {
        try {
            const out = await runtime.shellManager.runDiagnosticPreset(req.params.preset, 'controller');
            res.json(out);
        }
        catch (err) {
            res.status(400).json({ error: err.message });
        }
    });
    // Credential rotation
    app.post('/api/v1/credentials/rotate', (req, res) => {
        const { newApiKey, newHmacSecret } = req.body || {};
        if (!newApiKey || !newHmacSecret) {
            return res.status(400).json({ error: 'newApiKey and newHmacSecret are required' });
        }
        authenticator.rotateCredentials(String(newApiKey), String(newHmacSecret));
        return res.json({ success: true, rotatedAt: new Date().toISOString() });
    });
    // Build HTTP or HTTPS server (with optional mTLS)
    let server;
    const certPath = opts.tlsCertPath || process.env.HKVM_AGENT_TLS_CERT;
    const keyPath = opts.tlsKeyPath || process.env.HKVM_AGENT_TLS_KEY;
    const caPath = opts.tlsCaPath || process.env.HKVM_AGENT_TLS_CA;
    if (certPath && keyPath && fs_1.default.existsSync(certPath) && fs_1.default.existsSync(keyPath)) {
        const httpsOpts = {
            cert: fs_1.default.readFileSync(certPath),
            key: fs_1.default.readFileSync(keyPath),
        };
        if (caPath && fs_1.default.existsSync(caPath)) {
            httpsOpts.ca = fs_1.default.readFileSync(caPath);
            httpsOpts.requestCert = true;
            httpsOpts.rejectUnauthorized = Boolean(opts.requireMtls);
        }
        server = https_1.default.createServer(httpsOpts, app);
    }
    else {
        server = http_1.default.createServer(app);
    }
    const wss = new ws_1.WebSocketServer({ noServer: true });
    server.on('upgrade', (req, socket, head) => {
        const authRes = authenticator.verifyWebSocketUpgrade(req);
        if (!authRes.ok) {
            socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
            socket.destroy();
            return;
        }
        const urlObj = new URL(req.url || '/', 'http://localhost');
        const consoleMatch = urlObj.pathname.match(/^\/ws\/containers\/([^/]+)\/console$/);
        if (consoleMatch) {
            wss.handleUpgrade(req, socket, head, (ws) => {
                try {
                    runtime.consoleManager.attachWebSocket(ws, decodeURIComponent(consoleMatch[1]), {
                        cols: Number(urlObj.searchParams.get('cols') || 100),
                        rows: Number(urlObj.searchParams.get('rows') || 30),
                    });
                }
                catch {
                    // handled inside attachWebSocket
                }
            });
            return;
        }
        if (urlObj.pathname === '/ws/host/shell') {
            wss.handleUpgrade(req, socket, head, (ws) => {
                runtime.shellManager.attachInteractiveHostPty(ws, 'controller-admin', {
                    cols: Number(urlObj.searchParams.get('cols') || 100),
                    rows: Number(urlObj.searchParams.get('rows') || 30),
                });
            });
            return;
        }
        socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
        socket.destroy();
    });
    return { app, server, runtime, authenticator, host, port };
}
if (require.main === module) {
    const instance = createNodeAgentServer();
    instance.server.listen(instance.port, instance.host, () => {
        console.log(`[HKVM Node Agent v3.0.0] Listening on ${instance.host}:${instance.port}`);
    });
}
