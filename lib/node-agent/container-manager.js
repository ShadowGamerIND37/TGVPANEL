"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LxcContainerManager = void 0;
exports.ipv4ToUint32 = ipv4ToUint32;
exports.uint32ToIpv4 = uint32ToIpv4;
exports.prefixLenToNetmask = prefixLenToNetmask;
exports.computeIpv4SubnetCidr = computeIpv4SubnetCidr;
exports.resolveGuestDnsServers = resolveGuestDnsServers;
exports.resolveDownloadReleaseCandidates = resolveDownloadReleaseCandidates;
exports.isAppArmorProfileLoadable = isAppArmorProfileLoadable;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const command_runner_1 = require("./command-runner");
const dns_relay_1 = require("./dns-relay");
const middleware_1 = require("../security/middleware");
function ipv4ToUint32(ip) {
    const parts = ip.trim().split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
        return 0;
    }
    return (((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0);
}
function uint32ToIpv4(num) {
    const u = num >>> 0;
    return `${(u >>> 24) & 255}.${(u >>> 16) & 255}.${(u >>> 8) & 255}.${u & 255}`;
}
function prefixLenToNetmask(prefixLen) {
    const p = Math.min(32, Math.max(0, Math.floor(prefixLen)));
    const mask = p === 0 ? 0 : ((0xffffffff << (32 - p)) >>> 0);
    return uint32ToIpv4(mask);
}
function computeIpv4SubnetCidr(ip, prefixLen = 24) {
    const u = ipv4ToUint32(ip);
    if (!u)
        return null;
    const p = Math.min(32, Math.max(8, Math.floor(prefixLen)));
    const mask = (0xffffffff << (32 - p)) >>> 0;
    const net = (u & mask) >>> 0;
    return `${uint32ToIpv4(net)}/${p}`;
}
function isPrivateRfc1918Ipv4(ip) {
    const parts = ip.trim().split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n)))
        return false;
    if (parts[0] === 10)
        return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
        return true;
    if (parts[0] === 192 && parts[1] === 168)
        return true;
    return false;
}
/**
 * Resolves up to 3 reliable upstream IPv4 DNS servers suitable for inside an LXC container
 * (respecting glibc MAXNS=3 while filtering out host loopback 127.0.0.53 and WSL2's
 * non-bridge-routable 10.255.255.254 tunnel listener).
 */
function resolveGuestDnsServers(hostResolvConfContent) {
    const envDns = (process.env.HKVM_LXC_DNS || '').trim();
    if (envDns) {
        const custom = envDns
            .split(/[\s,]+/)
            .map((s) => s.trim())
            .filter((s) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s));
        if (custom.length > 0)
            return custom.slice(0, 3);
    }
    const hostCandidates = [];
    try {
        const raw = hostResolvConfContent !== undefined
            ? hostResolvConfContent
            : fs_1.default.existsSync('/etc/resolv.conf')
                ? fs_1.default.readFileSync('/etc/resolv.conf', 'utf8')
                : '';
        for (const line of raw.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#'))
                continue;
            const m = trimmed.match(/^nameserver\s+(\d{1,3}(?:\.\d{1,3}){3})\b/i);
            if (!m)
                continue;
            const ns = m[1];
            if (ns.startsWith('127.') ||
                ns.startsWith('0.') ||
                ns.startsWith('169.254.') ||
                ns === '10.255.255.254') {
                continue;
            }
            if (!hostCandidates.includes(ns))
                hostCandidates.push(ns);
        }
    }
    catch {
        // ignore host /etc/resolv.conf read errors
    }
    const ordered = ['1.1.1.1', '8.8.8.8'];
    for (const h of hostCandidates) {
        if (!ordered.includes(h))
            ordered.push(h);
    }
    if (ordered.length < 3 && !ordered.includes('1.0.0.1')) {
        ordered.push('1.0.0.1');
    }
    return ordered.slice(0, 3);
}
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
        const rootControllers = new Set(raw.split(/\s+/).filter(Boolean));
        if (fs_1.default.existsSync('/sys/fs/cgroup/cgroup.subtree_control')) {
            const subRaw = fs_1.default.readFileSync('/sys/fs/cgroup/cgroup.subtree_control', 'utf8').trim();
            const delegated = new Set(subRaw.split(/\s+/).filter(Boolean));
            // On WSL2 / nested container hosts where root subtree_control has not delegated controllers,
            // writing lxc.cgroup2.<ctrl>.* causes lxc-start to fail with ENOENT on child cgroup files.
            return new Set([...rootControllers].filter((c) => delegated.has(c)));
        }
        return rootControllers;
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
    inFlightCreations = new Set();
    constructor(lxcBaseDir = DEFAULT_LXC_BASE) {
        this.lxcBaseDir = path_1.default.resolve(lxcBaseDir);
    }
    isCreationInFlight(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        return this.inFlightCreations.has(safeName.toLowerCase());
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
    isSystemLxcStore() {
        return this.lxcBaseDir === '/var/lib/lxc' || this.lxcBaseDir.startsWith('/var/lib/lxc/');
    }
    bridgeHasPhysicalSlave(safeBridge) {
        try {
            const brifDir = `/sys/class/net/${safeBridge}/brif`;
            if (!fs_1.default.existsSync(brifDir))
                return false;
            for (const iface of fs_1.default.readdirSync(brifDir)) {
                if (fs_1.default.existsSync(`/sys/class/net/${iface}/device`)) {
                    return true;
                }
            }
            return false;
        }
        catch {
            return false;
        }
    }
    detectBridgeDhcpServer(safeBridge) {
        try {
            for (const pidFile of ['/run/lxc/dnsmasq.pid', '/var/run/lxc/dnsmasq.pid']) {
                if (safeBridge === 'lxcbr0' && fs_1.default.existsSync(pidFile)) {
                    const p = parseInt(fs_1.default.readFileSync(pidFile, 'utf8').trim(), 10);
                    if (p > 0 && fs_1.default.existsSync(`/proc/${p}`))
                        return true;
                }
            }
            if (!fs_1.default.existsSync('/proc'))
                return false;
            for (const ent of fs_1.default.readdirSync('/proc')) {
                if (!/^\d+$/.test(ent))
                    continue;
                try {
                    const cmd = fs_1.default.readFileSync(`/proc/${ent}/cmdline`, 'utf8').replace(/\0/g, ' ');
                    if (/(dnsmasq|dhcpd|kea-dhcp4|udhcpd)/i.test(cmd) &&
                        (cmd.includes(safeBridge) || (safeBridge === 'lxcbr0' && cmd.includes('lxc')))) {
                        return true;
                    }
                }
                catch {
                    // ignore exited proc
                }
            }
            return false;
        }
        catch {
            return false;
        }
    }
    async ensureIptablesRule(bin, table, chain, ruleArgs, insertTop = true) {
        const tblArgs = table === 'filter' ? [] : ['-t', table];
        const check = await (0, command_runner_1.runAllowlistedCommand)(bin, [...tblArgs, '-C', chain, ...ruleArgs], { timeoutMs: 4000, asRoot: true });
        if (check.exitCode === 0)
            return true;
        const addArgs = insertTop
            ? [...tblArgs, '-I', chain, '1', ...ruleArgs]
            : [...tblArgs, '-A', chain, ...ruleArgs];
        const add = await (0, command_runner_1.runAllowlistedCommand)(bin, addArgs, { timeoutMs: 4000, asRoot: true });
        return add.exitCode === 0;
    }
    /**
     * Ensures the Linux bridge exists, is UP, has an IPv4 gateway address (when operating as
     * a virtual NAT bridge such as `lxcbr0`), starts HKVM's host-side `BridgeDnsRelay`, enables
     * kernel forwarding/rp_filter sysctls, and installs idempotent MASQUERADE, FORWARD ACCEPT,
     * INPUT ACCEPT, TCPMSS clamping, and PREROUTING DNS REDIRECT rules across BOTH `iptables`
     * and `iptables-legacy` (preventing WSL2 / Docker Desktop / UFW split-brain packet drops).
     */
    async ensureBridgeNetworkReady(bridgeName) {
        const safeBridge = middleware_1.SafeValidators.bridgeOrIface(bridgeName);
        if (!(0, command_runner_1.isBinaryAvailable)('ip')) {
            return {
                ready: fs_1.default.existsSync(`/sys/class/net/${safeBridge}`),
                bridgeIp: null,
                prefixLen: 24,
                subnetCidr: null,
                hasDhcpServer: this.detectBridgeDhcpServer(safeBridge),
                natConfigured: false,
                dnsRelayPort: 0,
            };
        }
        if (!fs_1.default.existsSync(`/sys/class/net/${safeBridge}`)) {
            await (0, command_runner_1.runAllowlistedCommand)('ip', ['link', 'add', 'name', safeBridge, 'type', 'bridge'], {
                timeoutMs: 5000,
                asRoot: true,
            });
        }
        if (!fs_1.default.existsSync(`/sys/class/net/${safeBridge}`)) {
            return {
                ready: false,
                bridgeIp: null,
                prefixLen: 24,
                subnetCidr: null,
                hasDhcpServer: false,
                natConfigured: false,
                dnsRelayPort: 0,
            };
        }
        await (0, command_runner_1.runAllowlistedCommand)('ip', ['link', 'set', safeBridge, 'up'], {
            timeoutMs: 5000,
            asRoot: true,
        });
        let bridgeIp = null;
        let prefixLen = 24;
        const addrRes = await (0, command_runner_1.runAllowlistedCommand)('ip', ['-4', '-o', 'addr', 'show', 'dev', safeBridge], { timeoutMs: 5000, asRoot: true });
        const addrMatch = addrRes.stdout.match(/\binet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)\b/);
        if (addrMatch) {
            bridgeIp = addrMatch[1];
            prefixLen = parseInt(addrMatch[2], 10) || 24;
        }
        const isVirtualNatBridge = !this.bridgeHasPhysicalSlave(safeBridge);
        if (!bridgeIp && isVirtualNatBridge) {
            const routeRes = await (0, command_runner_1.runAllowlistedCommand)('ip', ['-4', 'route', 'show'], {
                timeoutMs: 5000,
            });
            const routesText = routeRes.stdout || '';
            const gatewayCandidates = ['10.0.3.1', '10.88.3.1', '10.99.3.1', '172.29.3.1'];
            let chosenGw = '10.0.3.1';
            for (const cand of gatewayCandidates) {
                const prefix3 = cand.split('.').slice(0, 3).join('.') + '.';
                if (!routesText.includes(prefix3)) {
                    chosenGw = cand;
                    break;
                }
            }
            const assignRes = await (0, command_runner_1.runAllowlistedCommand)('ip', ['addr', 'add', `${chosenGw}/24`, 'dev', safeBridge], { timeoutMs: 5000, asRoot: true });
            if (assignRes.exitCode === 0 || /File exists/i.test(assignRes.stderr)) {
                bridgeIp = chosenGw;
                prefixLen = 24;
            }
        }
        const subnetCidr = bridgeIp ? computeIpv4SubnetCidr(bridgeIp, prefixLen) : null;
        let natConfigured = false;
        let dnsRelayPort = 0;
        if (bridgeIp && subnetCidr && isVirtualNatBridge && isPrivateRfc1918Ipv4(bridgeIp)) {
            const dnsRelay = (0, dns_relay_1.getSharedBridgeDnsRelay)();
            dnsRelay.addExcludedLoopIp(bridgeIp);
            dnsRelayPort = await dnsRelay.ensureStarted().catch(() => 0);
            if ((0, command_runner_1.isBinaryAvailable)('modprobe')) {
                for (const mod of ['iptable_nat', 'nf_nat', 'xt_MASQUERADE', 'xt_REDIRECT', 'xt_TCPMSS']) {
                    await (0, command_runner_1.runAllowlistedCommand)('modprobe', [mod], {
                        timeoutMs: 3000,
                        asRoot: true,
                    }).catch(() => undefined);
                }
            }
            if ((0, command_runner_1.isBinaryAvailable)('sysctl')) {
                const sysctlKeys = [
                    'net.ipv4.ip_forward=1',
                    'net.ipv4.conf.all.forwarding=1',
                    'net.ipv4.conf.default.forwarding=1',
                    `net.ipv4.conf.${safeBridge}.forwarding=1`,
                    `net.ipv4.conf.${safeBridge}.rp_filter=0`,
                    'net.ipv4.conf.all.rp_filter=0',
                ];
                for (const kv of sysctlKeys) {
                    await (0, command_runner_1.runAllowlistedCommand)('sysctl', ['-w', kv], {
                        timeoutMs: 3000,
                        asRoot: true,
                    }).catch(() => undefined);
                }
            }
            // Program BOTH iptables (often iptables-nft) AND iptables-legacy if present on host:
            // on WSL2 + Docker Desktop / Ubuntu, Docker frequently sets `FORWARD DROP` in
            // iptables-legacy while `/usr/sbin/iptables` points to iptables-nft!
            const iptBins = [];
            if ((0, command_runner_1.isBinaryAvailable)('iptables'))
                iptBins.push('iptables');
            if ((0, command_runner_1.isBinaryAvailable)('iptables-legacy'))
                iptBins.push('iptables-legacy');
            for (const bin of iptBins) {
                const masqOk = await this.ensureIptablesRule(bin, 'nat', 'POSTROUTING', ['-s', subnetCidr, '!', '-d', subnetCidr, '-j', 'MASQUERADE'], true);
                if (masqOk)
                    natConfigured = true;
                // Top-of-chain FORWARD ACCEPT by both bridge device AND container CIDR (handles br_netfilter)
                await this.ensureIptablesRule(bin, 'filter', 'FORWARD', ['-i', safeBridge, '-j', 'ACCEPT'], true);
                await this.ensureIptablesRule(bin, 'filter', 'FORWARD', ['-o', safeBridge, '-j', 'ACCEPT'], true);
                await this.ensureIptablesRule(bin, 'filter', 'FORWARD', ['-s', subnetCidr, '-j', 'ACCEPT'], true);
                await this.ensureIptablesRule(bin, 'filter', 'FORWARD', ['-d', subnetCidr, '-j', 'ACCEPT'], true);
                // Clamp TCP MSS to path MTU (prevents `apt update` hanging at 0% [Working] on WSL2/PPPoE/Hotspot!)
                await this.ensureIptablesRule(bin, 'mangle', 'FORWARD', ['-i', safeBridge, '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--clamp-mss-to-pmtu'], true);
                await this.ensureIptablesRule(bin, 'mangle', 'FORWARD', ['-o', safeBridge, '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--clamp-mss-to-pmtu'], true);
                // Allow DHCP (67/68) and DNS (53 + dnsRelayPort) through host INPUT chain (UFW / INPUT DROP hosts)
                await this.ensureIptablesRule(bin, 'filter', 'INPUT', ['-i', safeBridge, '-p', 'udp', '--dport', '67', '-j', 'ACCEPT'], true);
                await this.ensureIptablesRule(bin, 'filter', 'INPUT', ['-s', subnetCidr, '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'], true);
                await this.ensureIptablesRule(bin, 'filter', 'INPUT', ['-s', subnetCidr, '-p', 'tcp', '--dport', '53', '-j', 'ACCEPT'], true);
                if (dnsRelayPort > 0) {
                    await this.ensureIptablesRule(bin, 'filter', 'INPUT', ['-s', subnetCidr, '-p', 'udp', '--dport', String(dnsRelayPort), '-j', 'ACCEPT'], true);
                    await this.ensureIptablesRule(bin, 'filter', 'INPUT', ['-s', subnetCidr, '-p', 'tcp', '--dport', String(dnsRelayPort), '-j', 'ACCEPT'], true);
                    await this.ensureIptablesRule(bin, 'nat', 'PREROUTING', ['-s', subnetCidr, '-d', bridgeIp, '-p', 'udp', '--dport', '53', '-j', 'REDIRECT', '--to-ports', String(dnsRelayPort)], true);
                    await this.ensureIptablesRule(bin, 'nat', 'PREROUTING', ['-s', subnetCidr, '-d', bridgeIp, '-p', 'tcp', '--dport', '53', '-j', 'REDIRECT', '--to-ports', String(dnsRelayPort)], true);
                }
            }
            if (!natConfigured && (0, command_runner_1.isBinaryAvailable)('nft')) {
                await (0, command_runner_1.runAllowlistedCommand)('nft', ['add', 'table', 'ip', 'hkvm_lxc_nat'], {
                    timeoutMs: 5000,
                    asRoot: true,
                });
                await (0, command_runner_1.runAllowlistedCommand)('nft', [
                    'add',
                    'chain',
                    'ip',
                    'hkvm_lxc_nat',
                    'postrouting',
                    '{ type nat hook postrouting priority 100 ; }',
                ], { timeoutMs: 5000, asRoot: true });
                await (0, command_runner_1.runAllowlistedCommand)('nft', ['flush', 'chain', 'ip', 'hkvm_lxc_nat', 'postrouting'], {
                    timeoutMs: 5000,
                    asRoot: true,
                });
                const nftMasq = await (0, command_runner_1.runAllowlistedCommand)('nft', [
                    'add',
                    'rule',
                    'ip',
                    'hkvm_lxc_nat',
                    'postrouting',
                    'ip',
                    'saddr',
                    subnetCidr,
                    'ip',
                    'daddr',
                    '!=',
                    subnetCidr,
                    'masquerade',
                ], { timeoutMs: 5000, asRoot: true });
                await (0, command_runner_1.runAllowlistedCommand)('nft', [
                    'add',
                    'chain',
                    'ip',
                    'hkvm_lxc_nat',
                    'forward',
                    '{ type filter hook forward priority -10 ; policy accept ; }',
                ], { timeoutMs: 5000, asRoot: true });
                if (dnsRelayPort > 0) {
                    await (0, command_runner_1.runAllowlistedCommand)('nft', [
                        'add',
                        'chain',
                        'ip',
                        'hkvm_lxc_nat',
                        'prerouting',
                        '{ type nat hook prerouting priority -100 ; }',
                    ], { timeoutMs: 5000, asRoot: true });
                    await (0, command_runner_1.runAllowlistedCommand)('nft', ['flush', 'chain', 'ip', 'hkvm_lxc_nat', 'prerouting'], {
                        timeoutMs: 5000,
                        asRoot: true,
                    });
                    await (0, command_runner_1.runAllowlistedCommand)('nft', [
                        'add',
                        'rule',
                        'ip',
                        'hkvm_lxc_nat',
                        'prerouting',
                        'ip',
                        'saddr',
                        subnetCidr,
                        'ip',
                        'daddr',
                        bridgeIp,
                        'udp',
                        'dport',
                        '53',
                        'redirect',
                        'to',
                        `:${dnsRelayPort}`,
                    ], { timeoutMs: 5000, asRoot: true });
                    await (0, command_runner_1.runAllowlistedCommand)('nft', [
                        'add',
                        'rule',
                        'ip',
                        'hkvm_lxc_nat',
                        'prerouting',
                        'ip',
                        'saddr',
                        subnetCidr,
                        'ip',
                        'daddr',
                        bridgeIp,
                        'tcp',
                        'dport',
                        '53',
                        'redirect',
                        'to',
                        `:${dnsRelayPort}`,
                    ], { timeoutMs: 5000, asRoot: true });
                }
                natConfigured = nftMasq.exitCode === 0;
            }
        }
        return {
            ready: true,
            bridgeIp,
            prefixLen,
            subnetCidr,
            hasDhcpServer: this.detectBridgeDhcpServer(safeBridge),
            natConfigured,
            dnsRelayPort,
        };
    }
    /**
     * Allocates a deterministic, collision-free IPv4 address from the bridge subnet when
     * no DHCP daemon (e.g. `dnsmasq`) is running on the bridge.
     */
    async allocateAutoBridgeIpv4(containerName, bridgeName, bridgeIp, prefixLen = 24) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const gwUint = ipv4ToUint32(bridgeIp);
        if (!gwUint || prefixLen < 16 || prefixLen > 29)
            return null;
        const mask = (0xffffffff << (32 - prefixLen)) >>> 0;
        const netBase = (gwUint & mask) >>> 0;
        const hostCount = (1 << (32 - prefixLen)) - 2;
        if (hostCount < 4)
            return null;
        const usedIps = new Set([bridgeIp]);
        // Scan existing container configs in lxcBaseDir
        try {
            if (command_runner_1.privilegedFs.existsSync(this.lxcBaseDir)) {
                for (const dirName of command_runner_1.privilegedFs.readdirNamesSync(this.lxcBaseDir)) {
                    const cfgPath = path_1.default.join(this.lxcBaseDir, dirName, 'config');
                    if (!command_runner_1.privilegedFs.existsSync(cfgPath))
                        continue;
                    try {
                        const txt = command_runner_1.privilegedFs.readTextSync(cfgPath);
                        const m = txt.match(/^\s*lxc\.net\.0\.ipv4\.address\s*=\s*(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?/m);
                        if (!m)
                            continue;
                        const ipOnly = m[1];
                        if (dirName === safeName) {
                            const candNet = (ipv4ToUint32(ipOnly) & mask) >>> 0;
                            if (candNet === netBase && ipOnly !== bridgeIp) {
                                return `${ipOnly}/${prefixLen}`;
                            }
                        }
                        else {
                            usedIps.add(ipOnly);
                        }
                    }
                    catch {
                        // ignore unreadable config
                    }
                }
            }
        }
        catch {
            // ignore scan failure
        }
        // Also avoid any active ARP neighbors on the bridge
        if ((0, command_runner_1.isBinaryAvailable)('ip') && this.isSystemLxcStore()) {
            const neighRes = await (0, command_runner_1.runAllowlistedCommand)('ip', ['-4', 'neigh', 'show', 'dev', middleware_1.SafeValidators.bridgeOrIface(bridgeName)], { timeoutMs: 4000 }).catch(() => null);
            if (neighRes && neighRes.stdout) {
                for (const line of neighRes.stdout.split('\n')) {
                    const m = line.trim().match(/^(\d+\.\d+\.\d+\.\d+)\b/);
                    if (m)
                        usedIps.add(m[1]);
                }
            }
        }
        const minHost = Math.min(100, Math.max(2, Math.floor(hostCount / 4)));
        const maxHost = Math.min(hostCount, 250);
        const poolSize = Math.max(1, maxHost - minHost + 1);
        let hash = 0;
        for (let i = 0; i < safeName.length; i++) {
            hash = (hash * 31 + safeName.charCodeAt(i)) >>> 0;
        }
        for (let i = 0; i < poolSize; i++) {
            const hostOffset = minHost + ((hash + i) % poolSize);
            const candidateIp = uint32ToIpv4((netBase + hostOffset) >>> 0);
            if (!usedIps.has(candidateIp)) {
                return `${candidateIp}/${prefixLen}`;
            }
        }
        for (let hostOffset = 2; hostOffset <= hostCount; hostOffset++) {
            const candidateIp = uint32ToIpv4((netBase + hostOffset) >>> 0);
            if (!usedIps.has(candidateIp)) {
                return `${candidateIp}/${prefixLen}`;
            }
        }
        return null;
    }
    resolveConfinedRootfsDir(containerName, relDir, createIfMissing = false) {
        const rootfs = path_1.default.resolve(this.getRootfsDir(containerName));
        if (!command_runner_1.privilegedFs.existsSync(rootfs))
            return null;
        const segments = relDir.split('/').filter(Boolean);
        let cur = rootfs;
        for (const seg of segments) {
            const next = path_1.default.join(cur, seg);
            if (!next.startsWith(rootfs + path_1.default.sep))
                return null;
            if (command_runner_1.privilegedFs.existsSync(next)) {
                const meta = command_runner_1.privilegedFs.lstatMetaSync(next);
                if (meta.isSymbolicLink || !meta.isDirectory) {
                    return null;
                }
            }
            else if (createIfMissing) {
                command_runner_1.privilegedFs.mkdirpSync(next, 0o755);
            }
            else {
                return null;
            }
            cur = next;
        }
        return cur;
    }
    /**
     * Configures guest DNS (`/etc/resolv.conf` + `systemd-resolved` drop-in) and guest
     * network manager config (`netplan`, `systemd-networkd`, `ifupdown`) strictly inside
     * the confined container rootfs so guest boot daemons never wipe liblxc's assigned IPv4
     * or point `/etc/resolv.conf` at a dead `127.0.0.53` stub.
     */
    configureGuestNetworkingAndDns(containerName, opts = {}) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const dnsList = (opts.dnsServers && opts.dnsServers.length > 0
            ? opts.dnsServers
            : resolveGuestDnsServers()).slice(0, 3);
        const etcDir = this.resolveConfinedRootfsDir(safeName, 'etc', false);
        if (!etcDir)
            return dnsList;
        // 1. Replace broken/dangling symlink /etc/resolv.conf with real regular file
        try {
            const resolvPath = path_1.default.join(etcDir, 'resolv.conf');
            command_runner_1.privilegedFs.unlinkSync(resolvPath);
            const resolvBody = ['# Managed by HKVM Panel', ...dnsList.map((ns) => `nameserver ${ns}`), 'options timeout:2 attempts:2', ''].join('\n');
            command_runner_1.privilegedFs.writeFileSync(resolvPath, resolvBody, 0o644);
        }
        catch {
            // non-fatal on read-only rootfs
        }
        // 2. Configure systemd-resolved upstream drop-in AND normalize /etc/nsswitch.conf
        // (`hosts: files resolve [!UNAVAIL=return] dns` on Ubuntu 22.04/24.04 blocks glibc from
        // falling back to /etc/resolv.conf when systemd-resolved in memory has stale/empty state!)
        try {
            const nssPath = path_1.default.join(etcDir, 'nsswitch.conf');
            if (command_runner_1.privilegedFs.existsSync(nssPath) && !command_runner_1.privilegedFs.lstatMetaSync(nssPath).isSymbolicLink) {
                const nssRaw = command_runner_1.privilegedFs.readTextSync(nssPath);
                if (/^hosts:.*\[!UNAVAIL=return\]/m.test(nssRaw)) {
                    const nssFixed = nssRaw.replace(/^hosts:.*$/m, 'hosts:          files dns');
                    command_runner_1.privilegedFs.writeFileSync(nssPath, nssFixed, 0o644);
                }
            }
        }
        catch {
            // ignore
        }
        try {
            const systemdDir = this.resolveConfinedRootfsDir(safeName, 'etc/systemd', false);
            if (systemdDir) {
                const dropinDir = this.resolveConfinedRootfsDir(safeName, 'etc/systemd/resolved.conf.d', true);
                if (dropinDir) {
                    const dropinContent = `[Resolve]\nDNS=${dnsList.join(' ')}\nFallbackDNS=1.0.0.1 8.8.4.4\n`;
                    command_runner_1.privilegedFs.writeFileSync(path_1.default.join(dropinDir, '99-hkvm-dns.conf'), dropinContent, 0o644);
                }
            }
        }
        catch {
            // ignore
        }
        const ipv4Cidr = opts.ipv4Cidr ? opts.ipv4Cidr.trim() : null;
        const gateway = opts.gateway && opts.gateway !== 'auto' ? opts.gateway.trim() : null;
        // 3. Synchronize Ubuntu Netplan (/etc/netplan/10-lxc.yaml) so systemd-networkd does not flush eth0!
        try {
            const netplanDir = this.resolveConfinedRootfsDir(safeName, 'etc/netplan', false);
            if (netplanDir) {
                const netplanFile = path_1.default.join(netplanDir, '10-lxc.yaml');
                if (ipv4Cidr) {
                    const cidrFormatted = ipv4Cidr.includes('/') ? ipv4Cidr : `${ipv4Cidr}/24`;
                    const routeBlock = gateway
                        ? `      routes:\n        - to: default\n          via: ${gateway}\n`
                        : '';
                    const yaml = [
                        '# Managed by HKVM Panel',
                        'network:',
                        '  version: 2',
                        '  ethernets:',
                        '    eth0:',
                        '      dhcp4: false',
                        '      addresses:',
                        `        - ${cidrFormatted}`,
                        routeBlock ? routeBlock.trimEnd() : '',
                        '      nameservers:',
                        `        addresses: [${dnsList.join(', ')}]`,
                        '',
                    ]
                        .filter((l) => l !== '')
                        .join('\n') + '\n';
                    command_runner_1.privilegedFs.unlinkSync(netplanFile);
                    command_runner_1.privilegedFs.writeFileSync(netplanFile, yaml, 0o600);
                }
                else if (opts.useDhcp) {
                    const yaml = [
                        '# Managed by HKVM Panel',
                        'network:',
                        '  version: 2',
                        '  ethernets:',
                        '    eth0:',
                        '      dhcp4: true',
                        '      nameservers:',
                        `        addresses: [${dnsList.join(', ')}]`,
                        '',
                    ].join('\n');
                    if (command_runner_1.privilegedFs.existsSync(netplanFile)) {
                        const existingYaml = command_runner_1.privilegedFs.readTextSync(netplanFile);
                        if (existingYaml.includes('Managed by HKVM Panel')) {
                            command_runner_1.privilegedFs.writeFileSync(netplanFile, yaml, 0o600);
                        }
                    }
                }
            }
        }
        catch {
            // ignore
        }
        // 4. Synchronize systemd-networkd (/etc/systemd/network/05-hkvm-eth0.network) when netplan is absent
        try {
            const netplanDir = this.resolveConfinedRootfsDir(safeName, 'etc/netplan', false);
            const networkdDir = this.resolveConfinedRootfsDir(safeName, 'etc/systemd/network', false);
            if (!netplanDir && networkdDir) {
                const unitPath = path_1.default.join(networkdDir, '05-hkvm-eth0.network');
                if (ipv4Cidr) {
                    const cidrFormatted = ipv4Cidr.includes('/') ? ipv4Cidr : `${ipv4Cidr}/24`;
                    const lines = [
                        '# Managed by HKVM Panel',
                        '[Match]',
                        'Name=eth0',
                        '',
                        '[Network]',
                        'DHCP=no',
                        'KeepConfiguration=yes',
                        `Address=${cidrFormatted}`,
                    ];
                    if (gateway)
                        lines.push(`Gateway=${gateway}`);
                    for (const ns of dnsList)
                        lines.push(`DNS=${ns}`);
                    lines.push('');
                    command_runner_1.privilegedFs.unlinkSync(unitPath);
                    command_runner_1.privilegedFs.writeFileSync(unitPath, lines.join('\n'), 0o644);
                }
                else if (opts.useDhcp && command_runner_1.privilegedFs.existsSync(unitPath)) {
                    command_runner_1.privilegedFs.unlinkSync(unitPath);
                }
            }
        }
        catch {
            // ignore
        }
        // 5. Synchronize Debian / Alpine /etc/network/interfaces if present
        try {
            const netIfDir = this.resolveConfinedRootfsDir(safeName, 'etc/network', false);
            if (netIfDir && ipv4Cidr) {
                const ifacesPath = path_1.default.join(netIfDir, 'interfaces');
                if (command_runner_1.privilegedFs.existsSync(ifacesPath) && !command_runner_1.privilegedFs.lstatMetaSync(ifacesPath).isSymbolicLink) {
                    const curTxt = command_runner_1.privilegedFs.readTextSync(ifacesPath);
                    if (/iface\s+eth0\s+inet\s+dhcp/i.test(curTxt) || curTxt.includes('# HKVM-ETH0')) {
                        const [ipOnly, pfxRaw] = (ipv4Cidr.includes('/') ? ipv4Cidr : `${ipv4Cidr}/24`).split('/');
                        const mask = prefixLenToNetmask(parseInt(pfxRaw || '24', 10) || 24);
                        const staticStanza = [
                            '# HKVM-ETH0',
                            'auto eth0',
                            'iface eth0 inet static',
                            `    address ${ipOnly}`,
                            `    netmask ${mask}`,
                            ...(gateway ? [`    gateway ${gateway}`] : []),
                        ].join('\n');
                        const stripped = curTxt
                            .replace(/# HKVM-ETH0[\s\S]*?(?=\n(?:auto|allow-|iface|source)\b|$)/g, '')
                            .replace(/^\s*auto\s+eth0\s*$/gm, '')
                            .replace(/^\s*iface\s+eth0\s+inet\s+dhcp\s*$/gim, '');
                        command_runner_1.privilegedFs.writeFileSync(ifacesPath, `${stripped.trimEnd()}\n\n${staticStanza}\n`, 0o644);
                    }
                }
            }
        }
        catch {
            // ignore
        }
        return dnsList;
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
    readContainerNetFromConfig(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const configPath = path_1.default.join(this.lxcBaseDir, safeName, 'config');
        if (!command_runner_1.privilegedFs.existsSync(configPath)) {
            return { bridge: null, ipv4Cidr: null, gateway: null };
        }
        try {
            const txt = command_runner_1.privilegedFs.readTextSync(configPath);
            const brMatches = [...txt.matchAll(/^\s*lxc\.net\.0\.link\s*=\s*(\S+)/gm)];
            const ipMatches = [...txt.matchAll(/^\s*lxc\.net\.0\.ipv4\.address\s*=\s*(\S+)/gm)];
            const gwMatches = [...txt.matchAll(/^\s*lxc\.net\.0\.ipv4\.gateway\s*=\s*(\S+)/gm)];
            return {
                bridge: brMatches.length > 0 ? brMatches[brMatches.length - 1][1].trim() : null,
                ipv4Cidr: ipMatches.length > 0 ? ipMatches[ipMatches.length - 1][1].trim() : null,
                gateway: gwMatches.length > 0 ? gwMatches[gwMatches.length - 1][1].trim() : null,
            };
        }
        catch {
            return { bridge: null, ipv4Cidr: null, gateway: null };
        }
    }
    async inspectContainer(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const configPath = path_1.default.join(this.lxcBaseDir, safeName, 'config');
        const cfgNet = this.readContainerNetFromConfig(safeName);
        const configuredIpv4 = cfgNet.ipv4Cidr ? cfgNet.ipv4Cidr.split('/')[0] : null;
        const configuredGateway = cfgNet.gateway || null;
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-info')) {
            const existsOnDisk = command_runner_1.privilegedFs.existsSync(configPath);
            return {
                name: safeName,
                state: existsOnDisk ? 'stopped' : 'missing',
                pid: null,
                ips: configuredIpv4 ? [configuredIpv4] : [],
                cpuUseSeconds: 0,
                memoryBytes: 0,
                swapBytes: 0,
                rxBytes: 0,
                txBytes: 0,
                diskUsedBytes: this.measureDirBytesFast(path_1.default.join(this.lxcBaseDir, safeName, 'rootfs')),
                configuredIpv4,
                configuredGateway,
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
                configuredIpv4,
                configuredGateway,
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
        if ((state === 'running' || state === 'frozen') && pid && pid > 0 && memoryBytes === 0) {
            const procStats = this.measureContainerProcTree(pid);
            if (procStats.memoryBytes > 0) {
                memoryBytes = procStats.memoryBytes;
            }
            if (cpuUseSeconds === 0 && procStats.cpuUseSeconds > 0) {
                cpuUseSeconds = procStats.cpuUseSeconds;
            }
        }
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
            configuredIpv4,
            configuredGateway,
        };
    }
    /**
     * Fallback live memory (VmRSS) & CPU time aggregator across `<initPid>` and all its
     * descendant processes in `/proc` for hosts (e.g. WSL2 / un-delegated cgroup v2) where
     * `lxc-info` does not emit `Memory use:` / `CPU use:`.
     */
    measureContainerProcTree(rootPid) {
        try {
            if (!fs_1.default.existsSync('/proc'))
                return { memoryBytes: 0, cpuUseSeconds: 0 };
            const entries = fs_1.default.readdirSync('/proc');
            const childrenByPpid = new Map();
            const ticksByPid = new Map();
            for (const ent of entries) {
                if (!/^\d+$/.test(ent))
                    continue;
                const p = parseInt(ent, 10);
                try {
                    const statRaw = fs_1.default.readFileSync(`/proc/${p}/stat`, 'utf8');
                    const closeParen = statRaw.lastIndexOf(')');
                    if (closeParen === -1)
                        continue;
                    const rest = statRaw.slice(closeParen + 2).trim().split(/\s+/);
                    const ppid = parseInt(rest[1] || '0', 10);
                    const utime = parseInt(rest[11] || '0', 10) || 0;
                    const stime = parseInt(rest[12] || '0', 10) || 0;
                    ticksByPid.set(p, utime + stime);
                    if (ppid > 0) {
                        const arr = childrenByPpid.get(ppid) || [];
                        arr.push(p);
                        childrenByPpid.set(ppid, arr);
                    }
                }
                catch {
                    // process exited between readdir and readFile
                }
            }
            const treePids = [];
            const visited = new Set();
            const queue = [rootPid];
            while (queue.length > 0) {
                const cur = queue.shift();
                if (visited.has(cur))
                    continue;
                visited.add(cur);
                treePids.push(cur);
                const kids = childrenByPpid.get(cur);
                if (kids) {
                    for (const k of kids) {
                        if (!visited.has(k))
                            queue.push(k);
                    }
                }
            }
            let totalRssBytes = 0;
            let totalTicks = 0;
            for (const tp of treePids) {
                totalTicks += ticksByPid.get(tp) || 0;
                try {
                    const statusTxt = fs_1.default.readFileSync(`/proc/${tp}/status`, 'utf8');
                    const m = statusTxt.match(/^VmRSS:\s*(\d+)\s*kB/m);
                    if (m) {
                        totalRssBytes += (parseInt(m[1], 10) || 0) * 1024;
                    }
                }
                catch {
                    // ignore exited child
                }
            }
            return {
                memoryBytes: totalRssBytes,
                cpuUseSeconds: Number((totalTicks / 100).toFixed(2)),
            };
        }
        catch {
            return { memoryBytes: 0, cpuUseSeconds: 0 };
        }
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
                asRoot: true,
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
            asRoot: true,
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
        const lockKey = safeName.toLowerCase();
        if (this.inFlightCreations.has(lockKey)) {
            throw new Error(`LXC container "${safeName}" is currently being provisioned (downloading OS template). Please wait for it to finish.`);
        }
        this.inFlightCreations.add(lockKey);
        try {
            const backing = spec.backingStore || 'dir';
            this.ensureHostLxcDirectories();
            // Clean up any leftover empty/corrupt/orphan directory if not registered in panel DB
            const existingInfo = await this.inspectContainer(safeName);
            const ctDir = this.getContainerDir(safeName);
            if (existingInfo.state !== 'missing') {
                if (spec.replaceOrphanOnHost) {
                    await this.destroyContainer(safeName).catch(() => undefined);
                    if (command_runner_1.privilegedFs.existsSync(ctDir)) {
                        command_runner_1.privilegedFs.rmRecursiveSync(ctDir);
                    }
                }
                else {
                    throw new Error(`LXC container "${safeName}" already exists on host (${existingInfo.state}).`);
                }
            }
            else if (command_runner_1.privilegedFs.existsSync(ctDir)) {
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
                    kvmNesting: Boolean(spec.kvmNesting),
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
                // Never discard a validly provisioned container if only initial auto-start failed:
                // keep it registered in 'stopped' state so the admin can inspect logs/config and start it.
                startupWarning = `Container rootfs and configuration were created on disk (status: stopped), but automatic startup encountered a host issue: ${msg}`;
            }
            const info = await this.inspectContainer(safeName);
            if (startupWarning) {
                info.startupWarning = startupWarning;
            }
            return info;
        }
        finally {
            this.inFlightCreations.delete(lockKey);
        }
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
                lines.push('lxc.mount.auto =');
                lines.push('lxc.mount.auto = proc:mixed sys:rw cgroup:mixed');
            }
        }
        const requestedProfile = (cfg.apparmorProfile || 'generated').replace(/[^a-zA-Z0-9_.-]/g, '');
        const effectiveAppArmor = apparmorAvailable && !cfg.kvmNesting ? requestedProfile || 'generated' : 'unconfined';
        lines.push(`lxc.apparmor.profile = ${effectiveAppArmor}`);
        if (cfg.kvmNesting) {
            if (isCgroupV2) {
                lines.push('lxc.cgroup2.devices.allow = c 10:232 rwm');
                lines.push('lxc.cgroup2.devices.allow = c 10:200 rwm');
            }
            else {
                lines.push('lxc.cgroup.devices.allow = c 10:232 rwm');
                lines.push('lxc.cgroup.devices.allow = c 10:200 rwm');
            }
            lines.push('lxc.mount.entry = /dev/kvm dev/kvm none bind,optional,create=file 0 0');
            lines.push('lxc.mount.entry = /dev/net/tun dev/net/tun none bind,optional,create=file 0 0');
        }
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
        let configuredGuestIpv4 = null;
        let configuredGuestGateway = null;
        let activeBridgeInfo = null;
        if (cfg.bridge) {
            const safeBridge = middleware_1.SafeValidators.bridgeOrIface(cfg.bridge);
            const isSystemStore = this.isSystemLxcStore();
            const bridgeInfo = isSystemStore
                ? await this.ensureBridgeNetworkReady(safeBridge)
                : {
                    ready: true,
                    bridgeIp: null,
                    prefixLen: 24,
                    subnetCidr: null,
                    hasDhcpServer: true,
                    natConfigured: false,
                    dnsRelayPort: 0,
                };
            activeBridgeInfo = bridgeInfo;
            if (bridgeInfo.ready) {
                lines.push(`lxc.net.0.type = veth`);
                lines.push(`lxc.net.0.link = ${safeBridge}`);
                lines.push(`lxc.net.0.flags = up`);
                lines.push(`lxc.net.0.name = eth0`);
                if (cfg.macAddress && /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(cfg.macAddress)) {
                    lines.push(`lxc.net.0.hwaddr = ${cfg.macAddress}`);
                }
                if (cfg.ipv4Address) {
                    configuredGuestIpv4 = cfg.ipv4Address.includes('/')
                        ? cfg.ipv4Address
                        : `${middleware_1.SafeValidators.ipv4(cfg.ipv4Address)}/24`;
                }
                else if (isSystemStore && !bridgeInfo.hasDhcpServer && bridgeInfo.bridgeIp) {
                    configuredGuestIpv4 = await this.allocateAutoBridgeIpv4(safeName, safeBridge, bridgeInfo.bridgeIp, bridgeInfo.prefixLen);
                }
                if (configuredGuestIpv4) {
                    lines.push(`lxc.net.0.ipv4.address = ${configuredGuestIpv4}`);
                }
                if (cfg.ipv4Gateway) {
                    configuredGuestGateway =
                        cfg.ipv4Gateway === 'auto' ? 'auto' : middleware_1.SafeValidators.ipv4(cfg.ipv4Gateway);
                }
                else if (configuredGuestIpv4) {
                    if (bridgeInfo.bridgeIp) {
                        configuredGuestGateway = bridgeInfo.bridgeIp;
                    }
                    else {
                        const [ipOnly, pfxRaw] = configuredGuestIpv4.split('/');
                        const pfx = parseInt(pfxRaw || '24', 10) || 24;
                        const sub = computeIpv4SubnetCidr(ipOnly, pfx);
                        if (sub) {
                            const netUint = ipv4ToUint32(sub.split('/')[0]);
                            const gwCandidate = uint32ToIpv4((netUint + 1) >>> 0);
                            configuredGuestGateway = gwCandidate !== ipOnly ? gwCandidate : 'auto';
                        }
                        else {
                            configuredGuestGateway = 'auto';
                        }
                    }
                }
                if (configuredGuestGateway) {
                    lines.push(`lxc.net.0.ipv4.gateway = ${configuredGuestGateway}`);
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
        const dnsServers = this.buildEffectiveGuestDnsList(activeBridgeInfo);
        // Ensure guest /etc/resolv.conf + netplan/networkd/interfaces match so DNS & routing work immediately
        this.configureGuestNetworkingAndDns(safeName, {
            ipv4Cidr: configuredGuestIpv4,
            gateway: configuredGuestGateway && configuredGuestGateway !== 'auto' ? configuredGuestGateway : null,
            useDhcp: !configuredGuestIpv4,
            dnsServers,
        });
    }
    buildEffectiveGuestDnsList(bridgeInfo) {
        const base = resolveGuestDnsServers();
        if (bridgeInfo && bridgeInfo.bridgeIp && bridgeInfo.dnsRelayPort > 0) {
            return [
                bridgeInfo.bridgeIp,
                ...base.filter((ip) => ip !== bridgeInfo.bridgeIp),
            ].slice(0, 3);
        }
        return base.slice(0, 3);
    }
    async prepareContainerNetworkPreStart(containerName, opts = {}) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const netCfg = this.readContainerNetFromConfig(safeName);
        const bridge = middleware_1.SafeValidators.bridgeOrIface(netCfg.bridge || opts.fallbackBridge || 'lxcbr0');
        let ipv4Cidr = netCfg.ipv4Cidr;
        let gateway = netCfg.gateway;
        let natConfigured = false;
        let activeBridgeInfo = null;
        if (this.isSystemLxcStore()) {
            const bridgeInfo = await this.ensureBridgeNetworkReady(bridge);
            activeBridgeInfo = bridgeInfo;
            natConfigured = bridgeInfo.natConfigured;
            const configFile = path_1.default.join(this.getContainerDir(safeName), 'config');
            const curCfgText = command_runner_1.privilegedFs.existsSync(configFile)
                ? command_runner_1.privilegedFs.readTextSync(configFile)
                : '';
            const hadNetTypeNone = /^\s*lxc\.net\.0\.type\s*=\s*none\b/m.test(curCfgText);
            let runningWithoutIp = false;
            if (opts.forceAutoIpIfRunningWithoutIp && !ipv4Cidr) {
                const curInfo = await this.inspectContainer(safeName);
                if (curInfo.state === 'running' && curInfo.ips.length === 0) {
                    runningWithoutIp = true;
                }
            }
            const needsAutoIp = !ipv4Cidr &&
                Boolean(bridgeInfo.bridgeIp) &&
                (!bridgeInfo.hasDhcpServer || runningWithoutIp);
            if (needsAutoIp && bridgeInfo.bridgeIp) {
                const autoIp = await this.allocateAutoBridgeIpv4(safeName, bridge, bridgeInfo.bridgeIp, bridgeInfo.prefixLen);
                if (autoIp) {
                    ipv4Cidr = autoIp;
                    gateway = bridgeInfo.bridgeIp;
                }
            }
            if (!gateway && bridgeInfo.bridgeIp) {
                gateway = bridgeInfo.bridgeIp;
            }
            if (bridgeInfo.ready && curCfgText && (hadNetTypeNone || !netCfg.bridge || needsAutoIp)) {
                const markerEnd = '# --- END HKVM MANAGED CONFIG ---';
                const netLines = [
                    `lxc.net.0.type = veth`,
                    `lxc.net.0.link = ${bridge}`,
                    `lxc.net.0.flags = up`,
                    `lxc.net.0.name = eth0`,
                    ...(ipv4Cidr ? [`lxc.net.0.ipv4.address = ${ipv4Cidr}`] : []),
                    ...(gateway ? [`lxc.net.0.ipv4.gateway = ${gateway}`] : []),
                ].join('\n');
                const cleaned = curCfgText
                    .replace(/^\s*lxc\.net\.0(?:\.(?:type|link|flags|name|ipv4\.address|ipv4\.gateway))?\s*=.*$/gm, '')
                    .replace(/\n{3,}/g, '\n\n');
                const updated = cleaned.includes(markerEnd)
                    ? cleaned.replace(markerEnd, `${netLines}\n${markerEnd}`)
                    : `${cleaned.trimEnd()}\n${netLines}\n`;
                command_runner_1.privilegedFs.writeFileSync(configFile, updated, 0o640);
            }
        }
        const effectiveDns = this.buildEffectiveGuestDnsList(activeBridgeInfo);
        const dnsServers = this.configureGuestNetworkingAndDns(safeName, {
            ipv4Cidr,
            gateway: gateway && gateway !== 'auto' ? gateway : null,
            useDhcp: !ipv4Cidr,
            dnsServers: effectiveDns,
        });
        return {
            bridge,
            ipv4Cidr,
            gateway,
            dnsServers,
            dnsRelayPort: activeBridgeInfo?.dnsRelayPort || 0,
            natConfigured,
        };
    }
    /**
     * Ensures a running container's host-side `veth` peer is enslaved to `bridge` and `UP`
     * (recovers containers whose bridge was recreated or bounced while the container stayed running).
     */
    async ensureRunningVethAttachedToBridge(containerName, bridge) {
        if (!this.isSystemLxcStore() || !(0, command_runner_1.isBinaryAvailable)('lxc-attach') || !(0, command_runner_1.isBinaryAvailable)('ip')) {
            return { eth0Exists: true };
        }
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const safeBridge = middleware_1.SafeValidators.bridgeOrIface(bridge);
        const linkRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'ip', '-o', 'link', 'show', 'dev', 'eth0'], { timeoutMs: 5000, asRoot: true }).catch(() => null);
        if (!linkRes || linkRes.exitCode !== 0) {
            return { eth0Exists: false };
        }
        const peerMatch = linkRes.stdout.match(/\beth0@if(\d+):/);
        if (peerMatch) {
            const hostIfIndex = parseInt(peerMatch[1], 10);
            if (hostIfIndex > 0) {
                const hostLinks = await (0, command_runner_1.runAllowlistedCommand)('ip', ['-o', 'link', 'show'], {
                    timeoutMs: 4000,
                }).catch(() => null);
                if (hostLinks && hostLinks.stdout) {
                    for (const line of hostLinks.stdout.split('\n')) {
                        const m = line.match(new RegExp(`^${hostIfIndex}:\\s+([^:@\\s]+)`));
                        if (m) {
                            const hostVeth = middleware_1.SafeValidators.bridgeOrIface(m[1]);
                            await (0, command_runner_1.runAllowlistedCommand)('ip', ['link', 'set', 'dev', hostVeth, 'master', safeBridge], { timeoutMs: 4000, asRoot: true }).catch(() => undefined);
                            await (0, command_runner_1.runAllowlistedCommand)('ip', ['link', 'set', 'dev', hostVeth, 'up'], {
                                timeoutMs: 4000,
                                asRoot: true,
                            }).catch(() => undefined);
                            break;
                        }
                    }
                }
            }
        }
        return { eth0Exists: true };
    }
    async applyLiveGuestNetworkIfNeeded(containerName, ipv4Cidr, gateway, dnsServers, force = false) {
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-attach'))
            return false;
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const info = await this.inspectContainer(safeName);
        if (info.state !== 'running')
            return false;
        const rootOpt = { timeoutMs: 8000, asRoot: this.needsRootForStore() || undefined };
        let applied = false;
        await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'ip', 'link', 'set', 'eth0', 'up'], rootOpt).catch(() => undefined);
        if (ipv4Cidr) {
            const ipOnly = ipv4Cidr.split('/')[0];
            const cidrFull = ipv4Cidr.includes('/') ? ipv4Cidr : `${ipv4Cidr}/24`;
            if (force || !info.ips.includes(ipOnly)) {
                const addrRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'ip', 'addr', 'replace', cidrFull, 'dev', 'eth0'], rootOpt).catch(() => null);
                if (addrRes && addrRes.exitCode === 0)
                    applied = true;
            }
            if (gateway && gateway !== 'auto') {
                const routeRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [
                    ...this.lxcPathArgs(),
                    '-n',
                    safeName,
                    '--',
                    'ip',
                    'route',
                    'replace',
                    'default',
                    'via',
                    gateway,
                    'dev',
                    'eth0',
                ], rootOpt).catch(() => null);
                if (routeRes && routeRes.exitCode === 0)
                    applied = true;
            }
        }
        else if (gateway && gateway !== 'auto') {
            // Even when IP came via DHCP, ensure a default route exists on eth0
            const defCheck = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'ip', '-4', 'route', 'show', 'default'], rootOpt).catch(() => null);
            if (defCheck && defCheck.exitCode === 0 && !defCheck.stdout.trim()) {
                await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [
                    ...this.lxcPathArgs(),
                    '-n',
                    safeName,
                    '--',
                    'ip',
                    'route',
                    'replace',
                    'default',
                    'via',
                    gateway,
                    'dev',
                    'eth0',
                ], rootOpt).catch(() => undefined);
            }
        }
        if (dnsServers.length > 0 && (force || this.isSystemLxcStore())) {
            const resolvBody = [
                '# Managed by HKVM Panel',
                ...dnsServers.map((ns) => `nameserver ${ns}`),
                'options timeout:2 attempts:2',
                '',
            ].join('\n');
            await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'rm', '-f', '/etc/resolv.conf'], rootOpt).catch(() => undefined);
            const teeRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'tee', '/etc/resolv.conf'], { ...rootOpt, stdinData: resolvBody }).catch(() => null);
            if (teeRes && teeRes.exitCode === 0)
                applied = true;
            // Also push DNS servers into live systemd-resolved (if running inside Ubuntu/Debian guest)
            await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'resolvectl', 'dns', 'eth0', ...dnsServers], { ...rootOpt, timeoutMs: 4000 }).catch(() => undefined);
            await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'resolvectl', 'flush-caches'], { ...rootOpt, timeoutMs: 4000 }).catch(() => undefined);
        }
        return applied;
    }
    /**
     * Repairs host bridge/NAT/FORWARD/DNS-relay rules, upgrades `lxc.net.0.type = none` if needed,
     * auto-assigns a collision-free IPv4 if the container lacks one, re-enslaves orphaned host
     * `veth` peers (or restarts the container if `eth0` was never created), and applies IP/route/DNS
     * live inside the guest.
     */
    async repairContainerNetworking(containerName, fallbackBridge = 'lxcbr0') {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        let pre = await this.prepareContainerNetworkPreStart(safeName, {
            forceAutoIpIfRunningWithoutIp: true,
            fallbackBridge,
        });
        let restartedForVeth = false;
        const beforeInfo = await this.inspectContainer(safeName);
        if (beforeInfo.state === 'running' && this.isSystemLxcStore()) {
            const vethCheck = await this.ensureRunningVethAttachedToBridge(safeName, pre.bridge);
            if (!vethCheck.eth0Exists) {
                // Container booted previously without an eth0 veth device (e.g. lxc.net.0.type = none):
                // restart it once so liblxc attaches the newly configured veth pair to the bridge.
                await this.stopContainer(safeName).catch(() => undefined);
                await this.startContainer(safeName);
                restartedForVeth = true;
                pre = await this.prepareContainerNetworkPreStart(safeName, {
                    forceAutoIpIfRunningWithoutIp: true,
                    fallbackBridge,
                });
            }
        }
        const liveApplied = await this.applyLiveGuestNetworkIfNeeded(safeName, pre.ipv4Cidr, pre.gateway, pre.dnsServers, true);
        const info = await this.inspectContainer(safeName);
        const resolvedIp = info.ips[0] || (pre.ipv4Cidr ? pre.ipv4Cidr.split('/')[0] : null) || info.configuredIpv4 || null;
        return {
            containerName: safeName,
            state: info.state,
            bridge: pre.bridge,
            ipv4Address: resolvedIp,
            gateway: pre.gateway && pre.gateway !== 'auto' ? pre.gateway : null,
            dnsServers: pre.dnsServers,
            dnsRelayPort: pre.dnsRelayPort || undefined,
            natConfigured: pre.natConfigured,
            liveApplied: liveApplied || restartedForVeth,
            restartedForVeth,
        };
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
        const preNet = await this.prepareContainerNetworkPreStart(safeName).catch(() => null);
        const logFile = command_runner_1.privilegedFs.existsSync('/var/log/lxc')
            ? `/var/log/lxc/${safeName}.log`
            : path_1.default.join(this.getContainerDir(safeName), `${safeName}.log`);
        const runStart = () => (0, command_runner_1.runAllowlistedCommand)('lxc-start', [...this.lxcPathArgs(), '-n', safeName, '-d', '-l', 'ERROR', '-o', logFile], {
            timeoutMs: 30_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        let res = await runStart();
        if (res.exitCode !== 0) {
            let logTail = '';
            if (command_runner_1.privilegedFs.existsSync(logFile)) {
                try {
                    logTail = command_runner_1.privilegedFs.readTextSync(logFile).trim().split('\n').slice(-15).join('\n');
                }
                catch {
                    // ignore
                }
            }
            // On WSL2 / nested container hosts where cgroup limits cannot be written into child cgroups,
            // automatically strip lxc.cgroup* lines and retry startup once.
            const combinedDiag = `${res.stderr}\n${res.stdout}\n${logTail}`;
            const configFile = path_1.default.join(this.getContainerDir(safeName), 'config');
            if (/cgroup|limits/i.test(combinedDiag) && command_runner_1.privilegedFs.existsSync(configFile)) {
                try {
                    const curCfg = command_runner_1.privilegedFs.readTextSync(configFile);
                    const nextCfg = curCfg.replace(/^\s*lxc\.cgroup2?\.[a-zA-Z0-9_.-]+\s*=.*$/gm, '');
                    if (nextCfg !== curCfg) {
                        command_runner_1.privilegedFs.writeFileSync(configFile, nextCfg, 0o640);
                        res = await runStart();
                    }
                }
                catch {
                    // ignore config rewrite error and surface original failure
                }
            }
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
        if (preNet && this.isSystemLxcStore()) {
            await this.applyLiveGuestNetworkIfNeeded(safeName, preNet.ipv4Cidr, preNet.gateway, preNet.dnsServers, false).catch(() => undefined);
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
        this.assertLxcInstalled();
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
        // Walk every existing path segment from rootfs downward to block intermediate or broken symlink escapes
        const segments = safeRel.split('/').filter(Boolean);
        let cursor = realRootfs;
        for (const seg of segments) {
            cursor = path_1.default.join(cursor, seg);
            let meta;
            try {
                meta = command_runner_1.privilegedFs.lstatMetaSync(cursor);
            }
            catch {
                break;
            }
            if (meta.isSymbolicLink) {
                let realTarget;
                try {
                    realTarget = command_runner_1.privilegedFs.realpathSync(cursor);
                }
                catch {
                    throw new Error('Symlink escape outside container rootfs denied.');
                }
                if (realTarget !== realRootfs && !realTarget.startsWith(realRootfs + path_1.default.sep)) {
                    throw new Error('Symlink escape outside container rootfs denied.');
                }
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
