"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DockerManager = void 0;
const command_runner_1 = require("../../node-agent/command-runner");
const RESTART_POLICIES = ['no', 'always', 'unless-stopped', 'on-failure'];
const NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$/;
// Docker image reference: [registry/]repo[:tag|@digest] — repo segments must
// be lowercase alphanumeric with dots/underscores/dashes/slashes.
const IMAGE_RE = /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?(:\d+)?(\/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)*(:[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?(@[a-zA-Z0-9]+:[a-f0-9]{64})?$/;
/**
 * Docker container manager (Area I).
 *
 * Panel-managed containers are stored in a registry and rendered as
 * `docker run` / lifecycle commands that are executed on the target node via
 * the allowlisted command runner — locally or through the node agent. The
 * `docker` binary is capability-gated: when it is not installed on the host,
 * apply operations fail honestly and the failure is recorded on the row.
 */
class DockerManager {
    db;
    nodeManager;
    constructor(db, nodeManager) {
        this.db = db;
        this.nodeManager = nodeManager;
    }
    // --- Registry ---
    async listContainers() {
        return this.db.all(`SELECT c.*, n.name AS node_name
       FROM docker_containers c
       LEFT JOIN nodes n ON n.id = c.node_id
       ORDER BY c.id ASC`);
    }
    async getContainer(id) {
        return this.db.get(`SELECT c.*, n.name AS node_name
       FROM docker_containers c
       LEFT JOIN nodes n ON n.id = c.node_id
       WHERE c.id = ?`, [id]);
    }
    async getContainerByName(name) {
        return this.db.get(`SELECT * FROM docker_containers WHERE name = ?`, [name]);
    }
    parsePorts(input) {
        if (input === undefined || input === null || input === '')
            return [];
        let raw = input;
        if (typeof input === 'string') {
            try {
                raw = JSON.parse(input);
            }
            catch {
                throw new Error('ports must be a JSON array of {hostPort, containerPort, protocol}.');
            }
        }
        if (!Array.isArray(raw))
            throw new Error('ports must be an array of port mappings.');
        return raw.map((p, i) => {
            const hostPort = Number(p?.hostPort ?? p?.host ?? p?.published);
            const containerPort = Number(p?.containerPort ?? p?.container ?? p?.target);
            const protocol = String(p?.protocol || 'tcp').toLowerCase();
            if (!Number.isInteger(hostPort) || hostPort < 1 || hostPort > 65535) {
                throw new Error(`Port mapping #${i + 1}: hostPort must be between 1 and 65535.`);
            }
            if (!Number.isInteger(containerPort) || containerPort < 1 || containerPort > 65535) {
                throw new Error(`Port mapping #${i + 1}: containerPort must be between 1 and 65535.`);
            }
            if (protocol !== 'tcp' && protocol !== 'udp') {
                throw new Error(`Port mapping #${i + 1}: protocol must be tcp or udp.`);
            }
            return { hostPort, containerPort, protocol };
        });
    }
    parseEnv(input) {
        if (input === undefined || input === null || input === '')
            return {};
        let raw = input;
        if (typeof input === 'string') {
            try {
                raw = JSON.parse(input);
            }
            catch {
                throw new Error('env must be a JSON object of KEY=VALUE pairs.');
            }
        }
        if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
            throw new Error('env must be a JSON object of KEY=VALUE pairs.');
        }
        const out = {};
        for (const [key, value] of Object.entries(raw)) {
            const k = String(key).trim();
            if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) {
                throw new Error(`Invalid environment variable name: ${key}`);
            }
            out[k] = String(value);
        }
        return out;
    }
    validateContainerInput(input, existing) {
        const name = String(input.name ?? existing?.name ?? '').trim();
        if (!NAME_RE.test(name)) {
            throw new Error('Container name must start with an alphanumeric character and contain only alphanumeric characters, dots, dashes or underscores (max 63 chars).');
        }
        const image = String(input.image ?? existing?.image ?? '').trim();
        if (!IMAGE_RE.test(image)) {
            throw new Error('Image must be a valid Docker reference such as nginx:latest, registry.example.com/repo:tag or repo@sha256:digest.');
        }
        const restartPolicy = String(input.restartPolicy ?? existing?.restart_policy ?? 'unless-stopped').trim();
        if (!RESTART_POLICIES.includes(restartPolicy)) {
            throw new Error(`restartPolicy must be one of: ${RESTART_POLICIES.join(', ')}.`);
        }
        const network = String(input.network ?? existing?.network ?? 'tgvpanel').trim();
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$/.test(network)) {
            throw new Error('Network name is invalid.');
        }
        // Validated for type/range errors (throws on bad input).
        this.parsePorts(input.ports ?? (existing ? JSON.parse(existing.ports || '[]') : []));
        this.parseEnv(input.env ?? (existing ? JSON.parse(existing.env || '{}') : {}));
    }
    async createContainer(input) {
        this.validateContainerInput(input);
        const name = String(input.name).trim();
        const existing = await this.getContainerByName(name);
        if (existing)
            throw new Error(`A container named '${name}' already exists.`);
        const ports = this.parsePorts(input.ports);
        const env = this.parseEnv(input.env);
        const restartPolicy = String(input.restartPolicy || 'unless-stopped').trim();
        const network = String(input.network || 'tgvpanel').trim();
        const nodeId = Number(input.nodeId || 1);
        if (!Number.isInteger(nodeId) || nodeId < 1)
            throw new Error('nodeId must be a positive integer.');
        await this.db.run(`INSERT INTO docker_containers
        (name, node_id, image, ports, env, restart_policy, network, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'created')`, [name, nodeId, String(input.image).trim(), JSON.stringify(ports), JSON.stringify(env), restartPolicy, network]);
        return this.getContainerByName(name);
    }
    async updateContainer(id, input) {
        const existing = await this.getContainer(id);
        if (!existing)
            throw new Error('Container does not exist.');
        this.validateContainerInput(input, existing);
        const name = String(input.name ?? existing.name).trim();
        const duplicate = await this.getContainerByName(name);
        if (duplicate && Number(duplicate.id) !== Number(id)) {
            throw new Error(`A container named '${name}' already exists.`);
        }
        const ports = this.parsePorts(input.ports ?? JSON.parse(existing.ports || '[]'));
        const env = this.parseEnv(input.env ?? JSON.parse(existing.env || '{}'));
        const restartPolicy = String(input.restartPolicy ?? existing.restart_policy).trim();
        const network = String(input.network ?? existing.network).trim();
        const nodeId = input.nodeId !== undefined ? Number(input.nodeId) : Number(existing.node_id);
        if (!Number.isInteger(nodeId) || nodeId < 1)
            throw new Error('nodeId must be a positive integer.');
        await this.db.run(`UPDATE docker_containers
       SET name = ?, node_id = ?, image = ?, ports = ?, env = ?, restart_policy = ?, network = ?,
           updated_at = datetime('now')
       WHERE id = ?`, [name, nodeId, String(input.image ?? existing.image).trim(), JSON.stringify(ports), JSON.stringify(env), restartPolicy, network, id]);
        return this.getContainer(id);
    }
    async deleteContainer(id) {
        const existing = await this.getContainer(id);
        if (!existing)
            return false;
        await this.db.run(`DELETE FROM docker_containers WHERE id = ?`, [id]);
        return true;
    }
    // --- Command rendering ---
    /**
     * Renders the `docker run` argument list for a container spec. The rendered
     * command is what gets executed (locally or on the target node) and is also
     * exposed for display/validation.
     */
    renderRunArgs(container) {
        const ports = JSON.parse(container.ports || '[]');
        const env = JSON.parse(container.env || '{}');
        const args = [
            'run',
            '-d',
            '--name',
            String(container.name),
            '--restart',
            String(container.restart_policy || 'unless-stopped'),
            '--network',
            String(container.network || 'tgvpanel'),
        ];
        for (const p of ports) {
            args.push('-p', `${p.hostPort}:${p.containerPort}/${p.protocol || 'tcp'}`);
        }
        for (const [key, value] of Object.entries(env)) {
            args.push('-e', `${key}=${value}`);
        }
        args.push(String(container.image));
        return args;
    }
    renderRunCommand(container) {
        return `docker ${this.renderRunArgs(container).join(' ')}`;
    }
    lifecycleArgs(container, mode) {
        if (mode === 'start')
            return ['start', String(container.name)];
        if (mode === 'stop')
            return ['stop', String(container.name)];
        if (mode === 'restart')
            return ['restart', String(container.name)];
        return ['rm', '-f', String(container.name)];
    }
    renderLifecycleCommand(container, mode) {
        return `docker ${this.lifecycleArgs(container, mode).join(' ')}`;
    }
    // --- Lifecycle ---
    async isRemoteNode(nodeId) {
        if (!this.nodeManager)
            return false;
        const node = await this.nodeManager.getNodeById(nodeId);
        return Boolean(node && !node.is_local);
    }
    /**
     * Executes a container lifecycle action on the target node. Records honest
     * apply results on the container row.
     */
    async applyContainer(container, mode = 'create') {
        const nodeId = Number(container.node_id || 1);
        if (await this.isRemoteNode(nodeId)) {
            const node = await this.nodeManager.getNodeById(nodeId);
            if (!node || node.status !== 'online') {
                const error = 'Target node is not online.';
                await this.recordResult(container.id, false, error, mode);
                return { applied: false, error };
            }
            const res = await this.nodeManager.requestRemoteNode(nodeId, 'POST', '/api/v1/docker/apply', {
                name: container.name,
                image: container.image,
                ports: container.ports,
                env: container.env,
                restart_policy: container.restart_policy,
                network: container.network,
                mode,
            }, 15_000);
            const applied = Boolean(res?.applied);
            await this.recordResult(container.id, applied, res?.error || null, mode);
            return { applied, error: res?.error || null };
        }
        if (!(0, command_runner_1.isBinaryAvailable)('docker')) {
            const error = 'The docker binary is not available on this node.';
            await this.recordResult(container.id, false, error, mode);
            return { applied: false, error };
        }
        let applyRes;
        if (mode === 'create') {
            applyRes = await (0, command_runner_1.runAllowlistedCommand)('docker', this.renderRunArgs(container), {
                asRoot: true,
                timeoutMs: 30_000,
            });
        }
        else {
            applyRes = await (0, command_runner_1.runAllowlistedCommand)('docker', this.lifecycleArgs(container, mode), {
                asRoot: true,
                timeoutMs: 30_000,
            });
        }
        const applied = applyRes.exitCode === 0;
        const error = applied
            ? null
            : `docker ${mode} failed: ${(applyRes.stderr || applyRes.stdout).trim()}`;
        await this.recordResult(container.id, applied, error, mode);
        if (applied && mode === 'create') {
            const idMatch = applyRes.stdout.trim().split(/\s+/).filter(Boolean).pop() || '';
            if (/^[0-9a-f]{64}$/.test(idMatch)) {
                await this.db.run(`UPDATE docker_containers SET container_id = ? WHERE id = ?`, [idMatch, container.id]);
            }
        }
        return { applied, error };
    }
    async recordResult(containerId, applied, error, mode) {
        await this.db.run(`UPDATE docker_containers
       SET last_applied_at = CASE WHEN ? = 1 THEN datetime('now') ELSE last_applied_at END,
           last_error = ?,
           status = CASE
             WHEN ? = 1 AND ? = 'create' THEN 'running'
             WHEN ? = 1 AND ? = 'start' THEN 'running'
             WHEN ? = 1 AND ? = 'stop' THEN 'stopped'
             WHEN ? = 1 AND ? = 'remove' THEN 'removed'
             ELSE status
           END,
           updated_at = datetime('now')
       WHERE id = ?`, [
            applied ? 1 : 0,
            error,
            applied ? 1 : 0, mode,
            applied ? 1 : 0, mode,
            applied ? 1 : 0, mode,
            applied ? 1 : 0, mode,
            containerId,
        ]);
    }
    async getContainerStatus(id) {
        const container = await this.getContainer(id);
        if (!container)
            return null;
        const nodeId = Number(container.node_id || 1);
        let state = null;
        let available = null;
        if (await this.isRemoteNode(nodeId)) {
            const res = await this.nodeManager.requestRemoteNode(nodeId, 'POST', '/api/v1/docker/status', { name: container.name }, 10_000).catch(() => null);
            state = res?.state ?? null;
            available = res?.available ?? null;
        }
        else {
            available = (0, command_runner_1.isBinaryAvailable)('docker');
            if (available) {
                const inspect = await (0, command_runner_1.runAllowlistedCommand)('docker', ['inspect', '-f', '{{.State.Status}}', String(container.name)], {
                    asRoot: true,
                    timeoutMs: 10_000,
                });
                if (inspect.exitCode === 0) {
                    state = inspect.stdout.trim() || null;
                }
                else {
                    state = 'not-found';
                }
            }
        }
        return {
            id: container.id,
            name: container.name,
            node_id: container.node_id,
            state,
            dockerAvailable: available,
            status: container.status,
            last_applied_at: container.last_applied_at,
            last_error: container.last_error,
        };
    }
}
exports.DockerManager = DockerManager;
