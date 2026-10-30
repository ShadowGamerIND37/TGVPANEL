"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LxcContainerManager = void 0;
exports.resolveDownloadReleaseCandidates = resolveDownloadReleaseCandidates;
exports.isAppArmorProfileLoadable = isAppArmorProfileLoadable;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const command_runner_1 = require("./command-runner");
const middleware_1 = require("../security/middleware");
const DEFAULT_LXC_BASE = process.env.HKVM_LXC_PATH || '/var/lib/lxc';
const UBUNTU_RELEASE_MAP = {
    '18.04': 'bionic',
    '20.04': 'focal',
    '22.04': 'jammy',
    '24.04': 'noble',
    '24.10': 'oracular',
    '25.04': 'plucky',
    '25.10': 'questing',
    '26.04': 'resolute',
};
const DEBIAN_RELEASE_MAP = {
    '10': 'buster',
    '11': 'bullseye',
    '12': 'bookworm',
    '13': 'trixie',
    '14': 'forky',
};
const DEVUAN_RELEASE_MAP = {
    '4': 'chimaera',
    '5': 'daedalus',
};
/**
 * Translates human/LXD version identifiers (e.g. `ubuntu` + `24.04` or `debian` + `12`)
 * into canonical `images.linuxcontainers.org` release names expected by `lxc-create -t download`
 * (`noble`, `bookworm`, `current`, etc.), while retaining fallbacks.
 */
function resolveDownloadReleaseCandidates(rawDistro, rawRelease, fallbackRelease) {
    const distro = rawDistro.toLowerCase().replace(/[^a-z0-9_.-]/g, '') || 'ubuntu';
    const cleanRel = rawRelease.replace(/[^a-zA-Z0-9_.-]/g, '');
    const candidates = [];
    const pushUnique = (val) => {
        if (!val)
            return;
        const cleaned = val.replace(/[^a-zA-Z0-9_.-]/g, '');
        if (cleaned && !candidates.includes(cleaned)) {
            candidates.push(cleaned);
        }
    };
    if (distro === 'ubuntu') {
        if (UBUNTU_RELEASE_MAP[cleanRel]) {
            pushUnique(UBUNTU_RELEASE_MAP[cleanRel]);
        }
        pushUnique(cleanRel);
        for (const [ver, codename] of Object.entries(UBUNTU_RELEASE_MAP)) {
            if (codename === cleanRel.toLowerCase())
                pushUnique(ver);
        }
    }
    else if (distro === 'debian') {
        if (DEBIAN_RELEASE_MAP[cleanRel]) {
            pushUnique(DEBIAN_RELEASE_MAP[cleanRel]);
        }
        pushUnique(cleanRel);
        for (const [ver, codename] of Object.entries(DEBIAN_RELEASE_MAP)) {
            if (codename === cleanRel.toLowerCase())
                pushUnique(ver);
        }
    }
    else if (distro === 'devuan') {
        if (DEVUAN_RELEASE_MAP[cleanRel]) {
            pushUnique(DEVUAN_RELEASE_MAP[cleanRel]);
        }
        pushUnique(cleanRel);
    }
    else if (distro === 'kali' ||
        distro === 'archlinux' ||
        distro === 'voidlinux' ||
        distro === 'gentoo') {
        if (!cleanRel || cleanRel.toLowerCase() === 'rolling' || cleanRel.toLowerCase() === 'latest') {
            pushUnique('current');
        }
        pushUnique(cleanRel);
        pushUnique('current');
    }
    else if (distro === 'centos') {
        if (/^\d+$/.test(cleanRel)) {
            pushUnique(`${cleanRel}-Stream`);
        }
        pushUnique(cleanRel);
    }
    else {
        pushUnique(cleanRel);
    }
    if (fallbackRelease) {
        const fb = fallbackRelease.replace(/^images:[^/:]+[:/]/i, '');
        if (distro === 'ubuntu' && UBUNTU_RELEASE_MAP[fb])
            pushUnique(UBUNTU_RELEASE_MAP[fb]);
        if (distro === 'debian' && DEBIAN_RELEASE_MAP[fb])
            pushUnique(DEBIAN_RELEASE_MAP[fb]);
        pushUnique(fb);
    }
    if (candidates.length === 0) {
        candidates.push(distro === 'ubuntu' ? 'noble' : distro === 'debian' ? 'bookworm' : 'current');
    }
    return {
        distro,
        releases: candidates,
        archMapper: (rawArch) => {
            const a = (rawArch || 'amd64').toLowerCase().replace(/[^a-z0-9_.-]/g, '');
            if (a === 'x86_64' || a === 'x64')
                return 'amd64';
            if (a === 'aarch64')
                return 'arm64';
            return a || 'amd64';
        },
    };
}
function isAppArmorProfileLoadable() {
    try {
        if (!fs_1.default.existsSync('/sys/module/apparmor/parameters/enabled')) {
            return false;
        }
        const enabled = fs_1.default.readFileSync('/sys/module/apparmor/parameters/enabled', 'utf8').trim();
        if (enabled !== 'Y' && enabled !== '1') {
            return false;
        }
        return command_runner_1.privilegedFs.existsSync('/sys/kernel/security/apparmor/.load');
    }
    catch {
        return false;
    }
}
function readActiveCgroupV2Controllers() {
    try {
        if (!fs_1.default.existsSync('/sys/fs/cgroup/cgroup.controllers')) {
            return null;
        }
        const raw = fs_1.default.readFileSync('/sys/fs/cgroup/cgroup.controllers', 'utf8').trim();
        return new Set(raw.split(/\s+/).filter(Boolean));
    }
    catch {
        return null;
    }
}
function isCgroupV2SwapSupported() {
    return (fs_1.default.existsSync('/sys/fs/cgroup/memory.swap.max') ||
        fs_1.default.existsSync('/sys/fs/cgroup/init.scope/memory.swap.max') ||
        fs_1.default.existsSync('/sys/fs/cgroup/system.slice/memory.swap.max'));
}
class LxcContainerManager {
    lxcBaseDir;
    constructor(lxcBaseDir = DEFAULT_LXC_BASE) {
        this.lxcBaseDir = path_1.default.resolve(lxcBaseDir);
    }
    getBaseDir() {
        return this.lxcBaseDir;
    }
    getContainerDir(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        return path_1.default.join(this.lxcBaseDir, safeName);
    }
    getRootfsDir(containerName) {
        return path_1.default.join(this.getContainerDir(containerName), 'rootfs');
    }
    /**
     * Determines whether operations against `this.lxcBaseDir` require root (`sudo -n`).
     * System `/var/lib/lxc` requires root, whereas unprivileged temporary directories in tests do not.
     */
    needsRootForStore() {
        if ((0, command_runner_1.isRunningAsRoot)())
            return false;
        if (this.lxcBaseDir === '/var/lib/lxc' || this.lxcBaseDir.startsWith('/var/lib/lxc/')) {
            return true;
        }
        try {
            if (fs_1.default.existsSync(this.lxcBaseDir)) {
                fs_1.default.accessSync(this.lxcBaseDir, fs_1.default.constants.R_OK | fs_1.default.constants.W_OK | fs_1.default.constants.X_OK);
                return false;
            }
            const parent = path_1.default.dirname(this.lxcBaseDir);
            fs_1.default.accessSync(parent, fs_1.default.constants.R_OK | fs_1.default.constants.W_OK | fs_1.default.constants.X_OK);
            return false;
        }
        catch {
            return true;
        }
    }
    lxcPathArgs() {
        return ['-P', this.lxcBaseDir];
    }
    assertLxcInstalled() {
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-info') || !(0, command_runner_1.isBinaryAvailable)('lxc-create')) {
            throw new Error('LXC userland utilities (lxc-create / lxc-start / lxc-info) are not installed on this host.');
        }
    }
    ensureHostLxcDirectories() {
        command_runner_1.privilegedFs.mkdirpSync(this.lxcBaseDir, 0o755);
        if (this.lxcBaseDir === '/var/lib/lxc') {
            try {
                command_runner_1.privilegedFs.mkdirpSync('/var/cache/lxc', 0o755);
                command_runner_1.privilegedFs.mkdirpSync('/var/log/lxc', 0o755);
            }
            catch {
                // non-fatal if /var/log/lxc cannot be created
            }
        }
    }
    async ensureBridgeAvailable(bridgeName) {
        const safeBridge = middleware_1.SafeValidators.bridgeOrIface(bridgeName);
        if (fs_1.default.existsSync(`/sys/class/net/${safeBridge}`)) {
            return true;
        }
        if (!(0, command_runner_1.isBinaryAvailable)('ip')) {
            return false;
        }
        // Attempt to create and bring up the requested Linux bridge (e.g. lxcbr0 on fresh hosts/Codespaces)
        await (0, command_runner_1.runAllowlistedCommand)('ip', ['link', 'add', 'name', safeBridge, 'type', 'bridge'], {
            timeoutMs: 5000,
            asRoot: true,
        });
        await (0, command_runner_1.runAllowlistedCommand)('ip', ['link', 'set', safeBridge, 'up'], {
            timeoutMs: 5000,
            asRoot: true,
        });
        return fs_1.default.existsSync(`/sys/class/net/${safeBridge}`);
    }
    async listContainers() {
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-ls')) {
            return [];
        }
        if (!command_runner_1.privilegedFs.existsSync(this.lxcBaseDir)) {
            return [];
        }
        const lsRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-ls', [...this.lxcPathArgs(), '-1'], {
            timeoutMs: 10_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (lsRes.exitCode !== 0)
            return [];
        const names = lsRes.stdout
            .split('\n')
            .map((s) => s.trim())
            .filter(Boolean);
        const results = [];
        for (const name of names) {
            try {
                results.push(await this.inspectContainer(name));
            }
            catch {
                // skip invalid entries
            }
        }
        return results;
    }
    async inspectContainer(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const configPath = path_1.default.join(this.lxcBaseDir, safeName, 'config');
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-info')) {
            const existsOnDisk = command_runner_1.privilegedFs.existsSync(configPath);
            return {
                name: safeName,
                state: existsOnDisk ? 'stopped' : 'missing',
                pid: null,
                ips: [],
                cpuUseSeconds: 0,
                memoryBytes: 0,
                swapBytes: 0,
                rxBytes: 0,
                txBytes: 0,
                diskUsedBytes: this.measureDirBytesFast(path_1.default.join(this.lxcBaseDir, safeName, 'rootfs')),
            };
        }
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-info', [...this.lxcPathArgs(), '-n', safeName], {
            timeoutMs: 10_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            const existsOnDisk = command_runner_1.privilegedFs.existsSync(configPath);
            return {
                name: safeName,
                state: existsOnDisk ? 'stopped' : 'missing',
                pid: null,
                ips: [],
                cpuUseSeconds: 0,
                memoryBytes: 0,
                swapBytes: 0,
                rxBytes: 0,
                txBytes: 0,
                diskUsedBytes: 0,
            };
        }
        let state = 'stopped';
        let pid = null;
        const ips = [];
        let cpuUseSeconds = 0;
        let memoryBytes = 0;
        let rxBytes = 0;
        let txBytes = 0;
        for (const line of res.stdout.split('\n')) {
            const [rawKey, ...rest] = line.split(':');
            if (!rawKey || rest.length === 0)
                continue;
            const key = rawKey.trim().toLowerCase();
            const val = rest.join(':').trim();
            if (key === 'state') {
                const s = val.toLowerCase();
                if (s.includes('running'))
                    state = 'running';
                else if (s.includes('frozen'))
                    state = 'frozen';
                else
                    state = 'stopped';
            }
            else if (key === 'pid') {
                const n = parseInt(val, 10);
                if (!Number.isNaN(n) && n > 0)
                    pid = n;
            }
            else if (key === 'ip') {
                ips.push(val);
            }
            else if (key === 'cpu use') {
                cpuUseSeconds = parseFloat(val.replace(/[^0-9.]/g, '')) || 0;
            }
            else if (key === 'memory use') {
                memoryBytes = this.parseHumanSizeToBytes(val);
            }
            else if (key === 'rx bytes') {
                rxBytes += this.parseHumanSizeToBytes(val);
            }
            else if (key === 'tx bytes') {
                txBytes += this.parseHumanSizeToBytes(val);
            }
        }
        const diskUsedBytes = await this.getRootfsUsedBytes(safeName);
        return {
            name: safeName,
            state,
            pid,
            ips,
            cpuUseSeconds,
            memoryBytes,
            swapBytes: 0,
            rxBytes,
            txBytes,
            diskUsedBytes,
        };
    }
    parseHumanSizeToBytes(text) {
        const m = text.trim().match(/^([0-9.]+)\s*([KMGTPE]?i?B?)/i);
        if (!m)
            return 0;
        const num = parseFloat(m[1]) || 0;
        const unit = (m[2] || '').toUpperCase();
        if (unit.startsWith('K'))
            return Math.round(num * 1024);
        if (unit.startsWith('M'))
            return Math.round(num * 1024 * 1024);
        if (unit.startsWith('G'))
            return Math.round(num * 1024 * 1024 * 1024);
        if (unit.startsWith('T'))
            return Math.round(num * 1024 * 1024 * 1024 * 1024);
        return Math.round(num);
    }
    measureDirBytesFast(dirPath) {
        try {
            return command_runner_1.privilegedFs.lstatMetaSync(dirPath).size;
        }
        catch {
            return 0;
        }
    }
    async getRootfsUsedBytes(containerName) {
        const rootfs = this.getRootfsDir(containerName);
        if (!command_runner_1.privilegedFs.existsSync(rootfs))
            return 0;
        if ((0, command_runner_1.isBinaryAvailable)('du')) {
            const res = await (0, command_runner_1.runAllowlistedCommand)('du', ['-sb', rootfs], {
                timeoutMs: 8000,
                asRoot: this.needsRootForStore() || undefined,
            });
            if (res.exitCode === 0) {
                const bytes = parseInt(res.stdout.trim().split(/\s+/)[0] || '0', 10);
                if (!Number.isNaN(bytes))
                    return bytes;
            }
        }
        return 0;
    }
    async createFromLocalArchive(safeName, archivePath) {
        const resolvedArchive = path_1.default.resolve(archivePath);
        if (!fs_1.default.existsSync(resolvedArchive)) {
            throw new Error(`Custom LXC template archive not found at ${resolvedArchive}`);
        }
        const ctDir = this.getContainerDir(safeName);
        const rootfsDir = this.getRootfsDir(safeName);
        command_runner_1.privilegedFs.mkdirpSync(rootfsDir, 0o755);
        const tarRes = await (0, command_runner_1.runAllowlistedCommand)('tar', ['--numeric-owner', '-xpf', resolvedArchive, '-C', rootfsDir], {
            timeoutMs: 600_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (tarRes.exitCode !== 0) {
            command_runner_1.privilegedFs.rmRecursiveSync(ctDir);
            throw new Error(`Failed to unpack custom LXC rootfs archive: ${tarRes.stderr || tarRes.stdout}`);
        }
        const baseConfigLines = [
            '# Distribution configuration',
            ...(fs_1.default.existsSync('/usr/share/lxc/config/common.conf')
                ? ['lxc.include = /usr/share/lxc/config/common.conf']
                : []),
            `lxc.arch = ${process.arch === 'arm64' ? 'aarch64' : 'x86_64'}`,
            '',
            '# Container specific configuration',
            `lxc.rootfs.path = dir:${rootfsDir}`,
            `lxc.uts.name = ${safeName}`,
            '',
        ];
        command_runner_1.privilegedFs.writeFileSync(path_1.default.join(ctDir, 'config'), baseConfigLines.join('\n'), 0o640);
    }
    async applyOfflineRootPasswordHash(safeName, plainPassword) {
        if (!plainPassword || plainPassword.includes('\n') || plainPassword.includes('\0')) {
            return false;
        }
        if (!(0, command_runner_1.isBinaryAvailable)('openssl'))
            return false;
        const shadowPath = path_1.default.join(this.getRootfsDir(safeName), 'etc', 'shadow');
        if (!command_runner_1.privilegedFs.existsSync(shadowPath))
            return false;
        const hashRes = await (0, command_runner_1.runAllowlistedCommand)('openssl', ['passwd', '-6', '-stdin'], {
            stdinData: `${plainPassword}\n`,
            timeoutMs: 5000,
            asRoot: false,
        });
        const passwordHash = hashRes.stdout.trim();
        if (hashRes.exitCode !== 0 || !passwordHash.startsWith('$6$')) {
            return false;
        }
        try {
            const shadowContent = command_runner_1.privilegedFs.readTextSync(shadowPath);
            const lines = shadowContent.split('\n');
            let replaced = false;
            const updated = lines.map((line) => {
                if (line.startsWith('root:')) {
                    const parts = line.split(':');
                    parts[1] = passwordHash;
                    replaced = true;
                    return parts.join(':');
                }
                return line;
            });
            if (!replaced)
                return false;
            command_runner_1.privilegedFs.writeFileSync(shadowPath, updated.join('\n'), 0o640);
            return true;
        }
        catch {
            return false;
        }
    }
    async createContainer(spec) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(spec.containerName);
        const backing = spec.backingStore || 'dir';
        this.ensureHostLxcDirectories();
        // Clean up any leftover empty/corrupt directory if no valid container config exists
        const existingInfo = await this.inspectContainer(safeName);
        const ctDir = this.getContainerDir(safeName);
        if (existingInfo.state !== 'missing') {
            throw new Error(`LXC container "${safeName}" already exists on host (${existingInfo.state}).`);
        }
        if (command_runner_1.privilegedFs.existsSync(ctDir)) {
            command_runner_1.privilegedFs.rmRecursiveSync(ctDir);
        }
        if (spec.templateArchivePath && fs_1.default.existsSync(path_1.default.resolve(spec.templateArchivePath))) {
            await this.createFromLocalArchive(safeName, spec.templateArchivePath);
        }
        else {
            const { distro, releases, archMapper } = resolveDownloadReleaseCandidates(spec.distro, spec.release, spec.fallbackRelease);
            const arch = archMapper(spec.arch || 'amd64');
            const downloadEnv = {
                DOWNLOAD_KEYSERVER: process.env.LXC_DOWNLOAD_KEYSERVER || 'hkp://keyserver.ubuntu.com:80',
            };
            let created = false;
            let lastFailure = '';
            for (const relCandidate of releases) {
                const baseArgs = [
                    ...this.lxcPathArgs(),
                    '-n',
                    safeName,
                    '-B',
                    backing,
                    '-t',
                    'download',
                    '--',
                    '-d',
                    distro,
                    '-r',
                    relCandidate,
                    '-a',
                    arch,
                ];
                let createRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-create', baseArgs, {
                    timeoutMs: 600_000,
                    env: downloadEnv,
                    asRoot: this.needsRootForStore() || undefined,
                });
                const combinedOut = `${createRes.stderr}\n${createRes.stdout}`;
                if (createRes.exitCode !== 0 &&
                    process.env.HKVM_LXC_STRICT_GPG !== 'true' &&
                    /unable to fetch gpg key|gpg.*keyserver|gnupg/i.test(combinedOut)) {
                    if (command_runner_1.privilegedFs.existsSync(ctDir)) {
                        command_runner_1.privilegedFs.rmRecursiveSync(ctDir);
                    }
                    createRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-create', [...baseArgs, '--no-validate'], {
                        timeoutMs: 600_000,
                        env: downloadEnv,
                        asRoot: this.needsRootForStore() || undefined,
                    });
                }
                if (createRes.exitCode === 0) {
                    created = true;
                    break;
                }
                lastFailure = `lxc-create failed (${createRes.exitCode}): ${(createRes.stderr || createRes.stdout).trim()}`;
                if (command_runner_1.privilegedFs.existsSync(ctDir)) {
                    command_runner_1.privilegedFs.rmRecursiveSync(ctDir);
                }
                const retryNextRelease = /couldn't find a matching image|no matching image/i.test(`${createRes.stderr}\n${createRes.stdout}`);
                if (!retryNextRelease) {
                    break;
                }
            }
            if (!created) {
                throw new Error(lastFailure || `lxc-create failed for ${distro}:${spec.release} (${arch})`);
            }
        }
        try {
            await this.writeManagedConfigSection(safeName, {
                hostname: spec.hostname || safeName,
                cpuCores: spec.cpuCores,
                cpuShares: spec.cpuShares ?? 1024,
                cpuLimitPercent: spec.cpuLimitPercent ?? 100,
                cpuPinning: spec.cpuPinning || null,
                ramMb: spec.ramMb,
                swapMb: spec.swapMb ?? 512,
                nesting: spec.nesting !== false,
                privileged: spec.privileged !== false,
                apparmorProfile: spec.apparmorProfile || 'generated',
                autostart: Boolean(spec.autostart),
                bridge: spec.bridge || 'lxcbr0',
                ipv4Address: spec.ipv4Address || null,
                ipv4Gateway: spec.ipv4Gateway || null,
                ipv6Address: spec.ipv6Address || null,
                macAddress: spec.macAddress || null,
                mounts: spec.mounts || [],
            });
            if (spec.rootPassword) {
                await this.applyOfflineRootPasswordHash(safeName, spec.rootPassword);
            }
            if (spec.sshPublicKeys && spec.sshPublicKeys.length > 0) {
                for (const pubKey of spec.sshPublicKeys) {
                    await this.injectSshPublicKey(safeName, pubKey);
                }
            }
        }
        catch (cfgErr) {
            await this.destroyContainer(safeName).catch(() => {
                if (command_runner_1.privilegedFs.existsSync(ctDir))
                    command_runner_1.privilegedFs.rmRecursiveSync(ctDir);
            });
            throw cfgErr;
        }
        let startupWarning;
        try {
            await this.startContainer(safeName);
            if (spec.rootPassword) {
                await this.setRootPassword(safeName, spec.rootPassword).catch(() => undefined);
            }
        }
        catch (startErr) {
            const msg = String(startErr?.message || startErr);
            // If running inside an unprivileged outer container (e.g. unprivileged Docker/Codespace lacking CAP_SYS_ADMIN),
            // keep the provisioned container in stopped state and report the exact kernel restriction honestly.
            if (/operation not permitted|permission denied|failed to mount|unshare|namespace/i.test(msg)) {
                startupWarning = `Container rootfs and configuration created on disk, but automatic boot was blocked by outer host container capabilities: ${msg}`;
            }
            else {
                await this.destroyContainer(safeName).catch(() => {
                    if (command_runner_1.privilegedFs.existsSync(ctDir))
                        command_runner_1.privilegedFs.rmRecursiveSync(ctDir);
                });
                throw startErr;
            }
        }
        const info = await this.inspectContainer(safeName);
        if (startupWarning) {
            info.startupWarning = startupWarning;
        }
        return info;
    }
    async writeManagedConfigSection(containerName, cfg) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const configFile = path_1.default.join(this.getContainerDir(safeName), 'config');
        if (!command_runner_1.privilegedFs.existsSync(configFile)) {
            throw new Error(`Container config not found at ${configFile}`);
        }
        const existing = command_runner_1.privilegedFs.readTextSync(configFile);
        const markerStart = '# --- BEGIN HKVM MANAGED CONFIG ---';
        const markerEnd = '# --- END HKVM MANAGED CONFIG ---';
        let stripped = existing.replace(new RegExp(`${markerStart}[\\s\\S]*?${markerEnd}\\n?`, 'g'), '');
        // Strip template-copied default lxc.net.0.* and lxc.apparmor.* directives so HKVM's managed block is authoritative
        if (cfg.bridge !== undefined) {
            stripped = stripped.replace(/^\s*lxc\.net\.0(?:\.[a-zA-Z0-9_.-]+)?\s*=.*$/gm, '');
        }
        stripped = stripped.replace(/^\s*lxc\.apparmor\.(?:profile|allow_nesting)\s*=.*$/gm, '');
        stripped = stripped.replace(/\n{3,}/g, '\n\n');
        const cgroupV2Controllers = readActiveCgroupV2Controllers();
        const isCgroupV2 = cgroupV2Controllers !== null;
        const apparmorAvailable = isAppArmorProfileLoadable();
        const lines = [markerStart];
        if (cfg.hostname) {
            const cleanHost = cfg.hostname.replace(/[^a-zA-Z0-9.-]/g, '').slice(0, 63);
            if (cleanHost)
                lines.push(`lxc.uts.name = ${cleanHost}`);
        }
        if (cfg.autostart !== undefined) {
            lines.push(`lxc.start.auto = ${cfg.autostart ? 1 : 0}`);
        }
        if (cfg.nesting) {
            if (apparmorAvailable && fs_1.default.existsSync('/usr/share/lxc/config/nesting.conf')) {
                lines.push('lxc.include = /usr/share/lxc/config/nesting.conf');
            }
            else {
                lines.push('lxc.mount.auto = proc:mixed sys:rw cgroup:mixed');
            }
        }
        const requestedProfile = (cfg.apparmorProfile || 'generated').replace(/[^a-zA-Z0-9_.-]/g, '');
        const effectiveAppArmor = apparmorAvailable ? requestedProfile || 'generated' : 'unconfined';
        lines.push(`lxc.apparmor.profile = ${effectiveAppArmor}`);
        const cores = Math.max(1, Number(cfg.cpuCores || 1));
        const pct = Math.min(100, Math.max(5, Number(cfg.cpuLimitPercent || 100)));
        const quotaUs = Math.round(cores * 100_000 * (pct / 100));
        if (isCgroupV2 && cgroupV2Controllers) {
            if (cgroupV2Controllers.has('cpu')) {
                lines.push(`lxc.cgroup2.cpu.max = ${quotaUs} 100000`);
                if (cfg.cpuShares) {
                    const weight = Math.min(10000, Math.max(1, Math.round((cfg.cpuShares / 1024) * 100)));
                    lines.push(`lxc.cgroup2.cpu.weight = ${weight}`);
                }
            }
            if (cgroupV2Controllers.has('cpuset') &&
                cfg.cpuPinning &&
                /^[0-9,-]+$/.test(cfg.cpuPinning)) {
                lines.push(`lxc.cgroup2.cpuset.cpus = ${cfg.cpuPinning}`);
            }
            if (cgroupV2Controllers.has('memory')) {
                if (cfg.ramMb) {
                    lines.push(`lxc.cgroup2.memory.max = ${Math.max(64, cfg.ramMb)}M`);
                }
                if (cfg.swapMb !== undefined && isCgroupV2SwapSupported()) {
                    lines.push(`lxc.cgroup2.memory.swap.max = ${Math.max(0, cfg.swapMb)}M`);
                }
            }
        }
        else if (!isCgroupV2) {
            lines.push(`lxc.cgroup.cpu.cfs_period_us = 100000`);
            lines.push(`lxc.cgroup.cpu.cfs_quota_us = ${quotaUs}`);
            if (cfg.cpuShares) {
                lines.push(`lxc.cgroup.cpu.shares = ${Math.max(64, cfg.cpuShares)}`);
            }
            if (cfg.cpuPinning && /^[0-9,-]+$/.test(cfg.cpuPinning)) {
                lines.push(`lxc.cgroup.cpuset.cpus = ${cfg.cpuPinning}`);
            }
            if (cfg.ramMb) {
                lines.push(`lxc.cgroup.memory.limit_in_bytes = ${Math.max(64, cfg.ramMb)}M`);
            }
        }
        if (cfg.bridge) {
            const safeBridge = middleware_1.SafeValidators.bridgeOrIface(cfg.bridge);
            const isSystemStore = this.lxcBaseDir === '/var/lib/lxc' || this.lxcBaseDir.startsWith('/var/lib/lxc/');
            const bridgeReady = isSystemStore ? await this.ensureBridgeAvailable(safeBridge) : true;
            if (bridgeReady) {
                lines.push(`lxc.net.0.type = veth`);
                lines.push(`lxc.net.0.link = ${safeBridge}`);
                lines.push(`lxc.net.0.flags = up`);
                if (cfg.macAddress && /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(cfg.macAddress)) {
                    lines.push(`lxc.net.0.hwaddr = ${cfg.macAddress}`);
                }
                if (cfg.ipv4Address) {
                    const addrPart = cfg.ipv4Address.includes('/')
                        ? cfg.ipv4Address
                        : `${middleware_1.SafeValidators.ipv4(cfg.ipv4Address)}/24`;
                    lines.push(`lxc.net.0.ipv4.address = ${addrPart}`);
                }
                if (cfg.ipv4Gateway) {
                    lines.push(`lxc.net.0.ipv4.gateway = ${cfg.ipv4Gateway === 'auto' ? 'auto' : middleware_1.SafeValidators.ipv4(cfg.ipv4Gateway)}`);
                }
                if (cfg.ipv6Address) {
                    lines.push(`lxc.net.0.ipv6.address = ${middleware_1.SafeValidators.ipv6OrCidr(cfg.ipv6Address)}`);
                }
            }
            else {
                // Host does not have bridge interface and kernel denied creating one (e.g. nested container host)
                lines.push(`lxc.net.0.type = none`);
            }
        }
        if (Array.isArray(cfg.mounts)) {
            for (const m of cfg.mounts) {
                const guestRel = middleware_1.SafeValidators.safeContainerSubpath(m.guestTarget).replace(/^\//, '');
                if (!guestRel)
                    continue;
                const hostReal = path_1.default.resolve(m.hostSource);
                const roOpt = m.readOnly ? ',ro' : '';
                lines.push(`lxc.mount.entry = ${hostReal} ${guestRel} none bind,create=dir${roOpt} 0 0`);
            }
        }
        lines.push(markerEnd);
        command_runner_1.privilegedFs.writeFileSync(configFile, `${stripped.trimEnd()}\n\n${lines.join('\n')}\n`, 0o640);
    }
    async startContainer(containerName) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const info = await this.inspectContainer(safeName);
        if (info.state === 'running')
            return;
        if (info.state === 'frozen') {
            await this.unfreezeContainer(safeName);
            return;
        }
        const logFile = command_runner_1.privilegedFs.existsSync('/var/log/lxc')
            ? `/var/log/lxc/${safeName}.log`
            : path_1.default.join(this.getContainerDir(safeName), `${safeName}.log`);
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-start', [...this.lxcPathArgs(), '-n', safeName, '-d', '-l', 'ERROR', '-o', logFile], {
            timeoutMs: 30_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            let logDetails = '';
            if (command_runner_1.privilegedFs.existsSync(logFile)) {
                try {
                    const tail = command_runner_1.privilegedFs.readTextSync(logFile).trim().split('\n').slice(-12).join('\n');
                    if (tail)
                        logDetails = ` | Log: ${tail}`;
                }
                catch {
                    // ignore
                }
            }
            throw new Error(`lxc-start failed: ${(res.stderr || res.stdout).trim()}${logDetails}`);
        }
    }
    async stopContainer(containerName, force = false) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const info = await this.inspectContainer(safeName);
        if (info.state === 'stopped' || info.state === 'missing')
            return;
        const args = force
            ? [...this.lxcPathArgs(), '-n', safeName, '-k']
            : [...this.lxcPathArgs(), '-n', safeName, '-t', '15'];
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-stop', args, {
            timeoutMs: 25_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            const killRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-stop', [...this.lxcPathArgs(), '-n', safeName, '-k'], {
                timeoutMs: 10_000,
                asRoot: this.needsRootForStore() || undefined,
            });
            if (killRes.exitCode !== 0) {
                throw new Error(`lxc-stop failed: ${killRes.stderr || res.stderr}`);
            }
        }
    }
    async restartContainer(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        await this.stopContainer(safeName, false);
        await this.startContainer(safeName);
    }
    async freezeContainer(containerName) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-freeze', [...this.lxcPathArgs(), '-n', safeName], {
            timeoutMs: 15_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            throw new Error(`lxc-freeze failed: ${res.stderr || res.stdout}`);
        }
    }
    async unfreezeContainer(containerName) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-unfreeze', [...this.lxcPathArgs(), '-n', safeName], {
            timeoutMs: 15_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            throw new Error(`lxc-unfreeze failed: ${res.stderr || res.stdout}`);
        }
    }
    async destroyContainer(containerName) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        await this.stopContainer(safeName, true).catch(() => undefined);
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-destroy', [...this.lxcPathArgs(), '-n', safeName, '-f'], {
            timeoutMs: 60_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            const ctDir = this.getContainerDir(safeName);
            if (!command_runner_1.privilegedFs.existsSync(ctDir))
                return;
            throw new Error(`lxc-destroy failed: ${res.stderr || res.stdout}`);
        }
    }
    async reinstallContainer(spec) {
        const safeName = middleware_1.SafeValidators.containerName(spec.containerName);
        const info = await this.inspectContainer(safeName);
        if (info.state !== 'missing') {
            await this.destroyContainer(safeName);
        }
        return this.createContainer(spec);
    }
    async updateContainerResources(containerName, update) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        await this.writeManagedConfigSection(safeName, update);
        // Apply live cgroup limits immediately if container is running
        const info = await this.inspectContainer(safeName);
        if (info.state === 'running' && (0, command_runner_1.isBinaryAvailable)('lxc-cgroup')) {
            const isV2 = fs_1.default.existsSync('/sys/fs/cgroup/cgroup.controllers');
            const rootOpt = { timeoutMs: 5000, asRoot: this.needsRootForStore() || undefined };
            if (update.ramMb) {
                const key = isV2 ? 'memory.max' : 'memory.limit_in_bytes';
                await (0, command_runner_1.runAllowlistedCommand)('lxc-cgroup', [...this.lxcPathArgs(), '-n', safeName, key, `${Math.max(64, update.ramMb)}M`], rootOpt);
            }
            if (update.cpuCores) {
                const pct = Math.min(100, Math.max(5, Number(update.cpuLimitPercent || 100)));
                const quotaUs = Math.round(Math.max(1, update.cpuCores) * 100_000 * (pct / 100));
                if (isV2) {
                    await (0, command_runner_1.runAllowlistedCommand)('lxc-cgroup', [...this.lxcPathArgs(), '-n', safeName, 'cpu.max', `${quotaUs} 100000`], rootOpt);
                }
                else {
                    await (0, command_runner_1.runAllowlistedCommand)('lxc-cgroup', [...this.lxcPathArgs(), '-n', safeName, 'cpu.cfs_quota_us', `${quotaUs}`], rootOpt);
                }
            }
        }
    }
    /**
     * Resets root password inside container using `chpasswd` over stdin (`shell: false`),
     * with offline `/etc/shadow` SHA-512 hash fallback when container is stopped.
     * Zero shell interpolation of password characters.
     */
    async setRootPassword(containerName, newPassword) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        if (!newPassword || newPassword.includes('\n') || newPassword.includes('\0')) {
            throw new Error('Password contains invalid control characters.');
        }
        const info = await this.inspectContainer(safeName);
        if (info.state !== 'running') {
            const updatedOffline = await this.applyOfflineRootPasswordHash(safeName, newPassword);
            if (updatedOffline)
                return;
            throw new Error(`Container "${safeName}" is not running and /etc/shadow could not be updated.`);
        }
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'chpasswd'], {
            stdinData: `root:${newPassword}\n`,
            timeoutMs: 10_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            const fallback = await this.applyOfflineRootPasswordHash(safeName, newPassword);
            if (!fallback) {
                throw new Error(`Failed to update container root password: ${res.stderr || res.stdout}`);
            }
        }
    }
    async injectSshPublicKey(containerName, publicKey) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const trimmed = publicKey.trim();
        if (!/^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521))\s+[A-Za-z0-9+/=]+/.test(trimmed)) {
            throw new Error('Invalid OpenSSH public key format.');
        }
        const rootfs = this.getRootfsDir(safeName);
        if (!command_runner_1.privilegedFs.existsSync(rootfs)) {
            throw new Error(`Container rootfs does not exist at ${rootfs}`);
        }
        const sshDir = this.resolveConfinedRootfsPath(safeName, '/root/.ssh');
        command_runner_1.privilegedFs.mkdirpSync(sshDir, 0o700);
        const authKeysPath = path_1.default.join(sshDir, 'authorized_keys');
        const existing = command_runner_1.privilegedFs.existsSync(authKeysPath)
            ? command_runner_1.privilegedFs.readTextSync(authKeysPath)
            : '';
        if (!existing.includes(trimmed)) {
            const nextContent = existing
                ? `${existing.replace(/\n*$/, '\n')}${trimmed}\n`
                : `${trimmed}\n`;
            command_runner_1.privilegedFs.writeFileSync(authKeysPath, nextContent, 0o600);
        }
    }
    async getContainerProcesses(containerName) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [
            ...this.lxcPathArgs(),
            '-n',
            safeName,
            '--',
            'ps',
            '-eo',
            'pid,user,pcpu,pmem,comm',
            '--no-headers',
        ], {
            timeoutMs: 8000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0)
            return [];
        return res.stdout
            .trim()
            .split('\n')
            .filter(Boolean)
            .map((line) => {
            const cols = line.trim().split(/\s+/);
            return {
                pid: cols[0] || '',
                user: cols[1] || '',
                cpu: cols[2] || '0.0',
                mem: cols[3] || '0.0',
                command: cols.slice(4).join(' '),
            };
        });
    }
    async getContainerLogs(containerName, maxLines = 200) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const candidates = [
            `/var/log/lxc/${safeName}.log`,
            path_1.default.join(this.getContainerDir(safeName), `${safeName}.log`),
        ];
        for (const file of candidates) {
            if (command_runner_1.privilegedFs.existsSync(file)) {
                try {
                    const content = command_runner_1.privilegedFs.readTextSync(file);
                    return content.split('\n').slice(-maxLines).join('\n');
                }
                catch {
                    // ignore unreadable log candidate
                }
            }
        }
        return '';
    }
    /**
     * Resolves a user-supplied path strictly within `<lxcBaseDir>/<container>/rootfs`,
     * blocking both `..` traversal and symlink escapes outside `rootfs`.
     */
    resolveConfinedRootfsPath(containerName, subPath) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const rootfs = path_1.default.resolve(this.getRootfsDir(safeName));
        if (!command_runner_1.privilegedFs.existsSync(rootfs)) {
            throw new Error(`Container rootfs does not exist for "${safeName}".`);
        }
        const realRootfs = command_runner_1.privilegedFs.realpathSync(rootfs);
        const safeRel = middleware_1.SafeValidators.safeContainerSubpath(subPath).replace(/^\//, '');
        const joined = path_1.default.resolve(realRootfs, safeRel);
        if (joined !== realRootfs && !joined.startsWith(realRootfs + path_1.default.sep)) {
            throw new Error('Path traversal outside container rootfs denied.');
        }
        // Check existing parent/target realpath to prevent symlink escape
        const checkTarget = command_runner_1.privilegedFs.existsSync(joined) ? joined : path_1.default.dirname(joined);
        if (command_runner_1.privilegedFs.existsSync(checkTarget)) {
            const realTarget = command_runner_1.privilegedFs.realpathSync(checkTarget);
            if (realTarget !== realRootfs && !realTarget.startsWith(realRootfs + path_1.default.sep)) {
                throw new Error('Symlink escape outside container rootfs denied.');
            }
        }
        return joined;
    }
    listRootfsDirectory(containerName, subPath = '/') {
        const targetDir = this.resolveConfinedRootfsPath(containerName, subPath);
        const cleanRel = middleware_1.SafeValidators.safeContainerSubpath(subPath);
        const names = command_runner_1.privilegedFs.readdirNamesSync(targetDir);
        return names.map((name) => {
            const childPath = path_1.default.join(targetDir, name);
            let size = 0;
            let modifiedAt = new Date(0).toISOString();
            let isDirectory = false;
            try {
                const st = command_runner_1.privilegedFs.lstatMetaSync(childPath);
                size = st.size;
                modifiedAt = st.mtimeIso;
                isDirectory = st.isDirectory;
            }
            catch {
                // ignore broken symlink stat
            }
            return {
                name,
                path: cleanRel === '/' ? `/${name}` : `${cleanRel}/${name}`,
                isDirectory,
                size,
                modifiedAt,
            };
        });
    }
    readRootfsFile(containerName, subPath, maxBytes = 2 * 1024 * 1024) {
        const target = this.resolveConfinedRootfsPath(containerName, subPath);
        const st = command_runner_1.privilegedFs.lstatMetaSync(target);
        if (st.isSymbolicLink || !st.isFile) {
            throw new Error('Target is not a regular file.');
        }
        if (st.size > maxBytes) {
            throw new Error(`File exceeds maximum inline read size (${maxBytes} bytes).`);
        }
        return command_runner_1.privilegedFs.readFileSync(target, maxBytes);
    }
    writeRootfsFile(containerName, subPath, data) {
        const target = this.resolveConfinedRootfsPath(containerName, subPath);
        if (command_runner_1.privilegedFs.existsSync(target) && command_runner_1.privilegedFs.lstatMetaSync(target).isSymbolicLink) {
            throw new Error('Refusing to overwrite symlink inside container rootfs.');
        }
        command_runner_1.privilegedFs.mkdirpSync(path_1.default.dirname(target));
        command_runner_1.privilegedFs.writeFileSync(target, data);
    }
    deleteRootfsEntry(containerName, subPath) {
        const cleanRel = middleware_1.SafeValidators.safeContainerSubpath(subPath);
        if (cleanRel === '/') {
            throw new Error('Refusing to delete container root directory.');
        }
        const target = this.resolveConfinedRootfsPath(containerName, cleanRel);
        command_runner_1.privilegedFs.rmRecursiveSync(target);
    }
}
exports.LxcContainerManager = LxcContainerManager;
