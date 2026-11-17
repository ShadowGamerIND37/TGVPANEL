"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DdosManager = void 0;
const child_process_1 = require("child_process");
const util_1 = require("util");
const execFileAsync = (0, util_1.promisify)(child_process_1.execFile);
const DEFAULT_SETTINGS = {
    rate_limit_per_minute: 60,
    max_bandwidth_per_minute: 1048576,
    auto_block: 1,
    block_duration: 3600,
    threat_threshold_medium: 100,
    threat_threshold_high: 500,
    threat_threshold_critical: 1000,
    auto_block_syn_recv: 50,
    auto_block_high_connections: 150,
    auto_block_port_scan: 10,
    auto_block_time_wait: 300,
    intelligent_blocking: 1,
};
const isLinux = process.platform === 'linux';
function isValidIPv4(ip) {
    if (!ip || typeof ip !== 'string')
        return false;
    const match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!match)
        return false;
    for (let i = 1; i <= 4; i++) {
        const octet = parseInt(match[i], 10);
        if (octet < 0 || octet > 255)
            return false;
    }
    if (ip === '0.0.0.0' || ip === '127.0.0.1' || ip === '255.255.255.255')
        return false;
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.'))
        return false;
    if (ip.startsWith('169.254.'))
        return false;
    if (ip.startsWith('224.') || ip.startsWith('240.'))
        return false;
    return true;
}
/**
 * DDoS protection manager.
 *
 * Monitors live TCP/UDP connection state via `ss`/`netstat`, scores each
 * source IP for threat level, and automatically blocks high-threat IPs with
 * `iptables -A INPUT -s <ip> -j DROP`. Manual block/unblock and settings are
 * exposed through the v1 API. All network/firewall operations require a Linux
 * host with `ss`, `netstat`, and `iptables` available (honest capability
 * gating: on non-Linux or when tools are absent, monitoring returns empty data
 * and blocking reports a clear error rather than faking results).
 */
class DdosManager {
    db;
    settings = { ...DEFAULT_SETTINGS };
    stats = {
        total_requests: 0,
        total_blocked: 0,
        active_connections: 0,
        total_bandwidth: 0,
        total_connections: 0,
        suspicious_ips: 0,
        critical_threats: 0,
        high_threats: 0,
        medium_threats: 0,
        server_load: 0,
        memory_usage: 0,
        total_network_connections: 0,
        established_connections: 0,
        syn_recv_total: 0,
        last_scan: 0,
        total_ips: 0,
        blocked_ips: 0,
    };
    liveIPs = new Map();
    minuteTracker = new Map();
    monitorTimer = null;
    autoUnblockTimer = null;
    persistTimer = null;
    constructor(db) {
        this.db = db;
    }
    isLinux() {
        return isLinux;
    }
    async start() {
        await this.loadSettings();
        if (!isLinux) {
            console.warn('[DDoS] Non-Linux platform detected - network monitoring and iptables blocking are disabled.');
            return;
        }
        // Initial scan shortly after start, then continuous monitoring.
        setTimeout(() => { void this.analyzeNetworkActivity(); }, 1500);
        this.monitorTimer = setInterval(() => { void this.analyzeNetworkActivity(); }, 5000);
        this.autoUnblockTimer = setInterval(() => { void this.autoUnblockExpired(); }, 30000);
        this.persistTimer = setInterval(() => { void this.persistLiveData(); }, 5000);
        console.log('[DDoS] Real-time network monitoring started (5s interval)');
    }
    async stop() {
        if (this.monitorTimer)
            clearInterval(this.monitorTimer);
        if (this.autoUnblockTimer)
            clearInterval(this.autoUnblockTimer);
        if (this.persistTimer)
            clearInterval(this.persistTimer);
        this.monitorTimer = null;
        this.autoUnblockTimer = null;
        this.persistTimer = null;
    }
    async loadSettings() {
        const row = await this.db.get(`SELECT * FROM ddos_settings WHERE id = 1`);
        if (row) {
            this.settings = { ...DEFAULT_SETTINGS, ...row };
        }
    }
    getSettings() {
        return { ...this.settings };
    }
    async updateSettings(input) {
        const allowed = [
            'rate_limit_per_minute', 'max_bandwidth_per_minute', 'auto_block', 'block_duration',
            'threat_threshold_medium', 'threat_threshold_high', 'threat_threshold_critical',
            'auto_block_syn_recv', 'auto_block_high_connections', 'auto_block_port_scan',
            'auto_block_time_wait', 'intelligent_blocking',
        ];
        const next = { ...this.settings };
        for (const key of allowed) {
            if (input[key] !== undefined) {
                next[key] = Number(input[key]);
            }
        }
        await this.db.run(`UPDATE ddos_settings SET
         rate_limit_per_minute=?, max_bandwidth_per_minute=?, auto_block=?, block_duration=?,
         threat_threshold_medium=?, threat_threshold_high=?, threat_threshold_critical=?,
         auto_block_syn_recv=?, auto_block_high_connections=?, auto_block_port_scan=?,
         auto_block_time_wait=?, intelligent_blocking=?
       WHERE id = 1`, [
            next.rate_limit_per_minute, next.max_bandwidth_per_minute, next.auto_block, next.block_duration,
            next.threat_threshold_medium, next.threat_threshold_high, next.threat_threshold_critical,
            next.auto_block_syn_recv, next.auto_block_high_connections, next.auto_block_port_scan,
            next.auto_block_time_wait, next.intelligent_blocking,
        ]);
        this.settings = next;
        return { ...next };
    }
    getStats() {
        return { ...this.stats };
    }
    async runCmd(cmd) {
        const { stdout } = await execFileAsync(cmd, { shell: '/bin/bash', maxBuffer: 1024 * 1024 });
        return stdout;
    }
    async monitorActiveConnections() {
        if (!isLinux)
            return {};
        try {
            const out = await this.runCmd(`ss -ntu state established 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | sort | uniq -c | sort -nr | head -100`);
            const connections = {};
            for (const line of out.trim().split('\n').filter((l) => l.trim())) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 2) {
                    const count = parseInt(parts[0], 10);
                    const ip = parts[1];
                    if (isValidIPv4(ip))
                        connections[ip] = (connections[ip] || 0) + count;
                }
            }
            return connections;
        }
        catch {
            return {};
        }
    }
    async monitorSynFlood() {
        if (!isLinux)
            return {};
        try {
            const synFlood = {};
            const synRecv = await this.runCmd(`ss -ntu state syn-recv 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.' | sort | uniq -c | sort -nr | head -50`);
            for (const line of synRecv.trim().split('\n').filter((l) => l.trim())) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 2) {
                    const count = parseInt(parts[0], 10);
                    const ip = parts[1];
                    if (ip && count > 5)
                        synFlood[ip] = (synFlood[ip] || 0) + count;
                }
            }
            const synSent = await this.runCmd(`ss -ntu state syn-sent 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.' | sort | uniq -c | sort -nr | head -50`);
            for (const line of synSent.trim().split('\n').filter((l) => l.trim())) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 2) {
                    const count = parseInt(parts[0], 10);
                    const ip = parts[1];
                    if (ip && count > 3)
                        synFlood[ip] = (synFlood[ip] || 0) + count;
                }
            }
            return synFlood;
        }
        catch {
            return {};
        }
    }
    async detectPortScanning() {
        if (!isLinux)
            return {};
        try {
            const out = await this.runCmd(`ss -ntu 2>/dev/null | awk '{print $5}' | grep -E '^[0-9]+\\.' | sort | uniq | awk -F: '{print $1}' | uniq -c | sort -nr | head -50`);
            const scanners = {};
            for (const line of out.trim().split('\n').filter((l) => l.trim())) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 2) {
                    const portCount = parseInt(parts[0], 10);
                    const ip = parts[1];
                    if (portCount > 3 && ip && !ip.startsWith('10.') && !ip.startsWith('192.168.')) {
                        scanners[ip] = portCount;
                    }
                }
            }
            return scanners;
        }
        catch {
            return {};
        }
    }
    async detectUDPFlood() {
        if (!isLinux)
            return {};
        try {
            const out = await this.runCmd(`ss -nu 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.' | sort | uniq -c | sort -nr | head -50`);
            const udpFlood = {};
            for (const line of out.trim().split('\n').filter((l) => l.trim())) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 2) {
                    const count = parseInt(parts[0], 10);
                    const ip = parts[1];
                    if (count > 20 && ip)
                        udpFlood[ip] = count;
                }
            }
            return udpFlood;
        }
        catch {
            return {};
        }
    }
    async detectTimeWaitAbuse() {
        if (!isLinux)
            return {};
        try {
            const out = await this.runCmd(`ss -ntu state time-wait 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.' | sort | uniq -c | sort -nr | head -50`);
            const timeWait = {};
            for (const line of out.trim().split('\n').filter((l) => l.trim())) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 2) {
                    const count = parseInt(parts[0], 10);
                    const ip = parts[1];
                    if (count > 100 && ip)
                        timeWait[ip] = count;
                }
            }
            return timeWait;
        }
        catch {
            return {};
        }
    }
    async detectHighConnectionIPs() {
        if (!isLinux)
            return {};
        try {
            const out = await this.runCmd(`ss -ntu 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | sort | uniq -c | awk '$1 > 50 {print $1, $2}'`);
            const highConn = {};
            for (const line of out.trim().split('\n').filter((l) => l.trim())) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 2) {
                    const count = parseInt(parts[0], 10);
                    const ip = parts[1];
                    if (isValidIPv4(ip))
                        highConn[ip] = count;
                }
            }
            return highConn;
        }
        catch {
            return {};
        }
    }
    async getServerStats() {
        if (!isLinux) {
            return { load_1min: 0, memory_total: 0, memory_used: 0, memory_percent: 0, total_network_connections: 0, established_connections: 0 };
        }
        try {
            const empty = { load_1min: 0, memory_total: 0, memory_used: 0, memory_percent: 0, total_network_connections: 0, established_connections: 0 };
            const loadavg = await this.runCmd(`cat /proc/loadavg 2>/dev/null`);
            const loads = loadavg.trim().split(/\s+/);
            const meminfo = await this.runCmd(`free -m 2>/dev/null | grep Mem`);
            const memParts = meminfo.trim().split(/\s+/);
            const connCount = await this.runCmd(`ss -ntu 2>/dev/null | wc -l`);
            const estabCount = await this.runCmd(`ss -ntu state established 2>/dev/null | wc -l`);
            return {
                load_1min: parseFloat(loads[0]) || 0,
                memory_total: parseInt(memParts[1], 10) || 0,
                memory_used: parseInt(memParts[2], 10) || 0,
                memory_percent: memParts[1] ? Math.round(((parseInt(memParts[2], 10) || 0) / (parseInt(memParts[1], 10) || 1)) * 100) : 0,
                total_network_connections: (parseInt(connCount.trim(), 10) || 1) - 1,
                established_connections: (parseInt(estabCount.trim(), 10) || 1) - 1,
            };
        }
        catch {
            return { load_1min: 0, memory_total: 0, memory_used: 0, memory_percent: 0, total_network_connections: 0, established_connections: 0 };
        }
    }
    async analyzeNetworkActivity() {
        if (!isLinux)
            return;
        try {
            const [connections, synFlood, scanners, udpFlood, timeWaitAbuse, highConnIPs, serverStats] = await Promise.all([
                this.monitorActiveConnections(),
                this.monitorSynFlood(),
                this.detectPortScanning(),
                this.detectUDPFlood(),
                this.detectTimeWaitAbuse(),
                this.detectHighConnectionIPs(),
                this.getServerStats(),
            ]);
            const now = Date.now();
            const allIPs = [
                ...Object.keys(connections),
                ...Object.keys(synFlood),
                ...Object.keys(scanners),
                ...Object.keys(udpFlood),
                ...Object.keys(timeWaitAbuse),
                ...Object.keys(highConnIPs),
            ];
            const detectedIPs = new Set(allIPs.filter((ip) => isValidIPv4(ip)));
            this.stats.server_load = serverStats.load_1min;
            this.stats.memory_usage = serverStats.memory_percent;
            this.stats.total_network_connections = serverStats.total_network_connections;
            this.stats.established_connections = serverStats.established_connections;
            let criticalCount = 0;
            let highCount = 0;
            let mediumCount = 0;
            for (const ip of detectedIPs) {
                const connectionCount = connections[ip] || 0;
                const synCount = synFlood[ip] || 0;
                const portScanCount = scanners[ip] || 0;
                const udpCount = udpFlood[ip] || 0;
                const timeWaitCount = timeWaitAbuse[ip] || 0;
                const highConnCount = highConnIPs[ip] || 0;
                let threatScore = 0;
                const attackType = [];
                if (synCount > 20) {
                    threatScore += synCount * 10;
                    attackType.push('syn_flood');
                }
                else if (synCount > 10) {
                    threatScore += synCount * 5;
                    attackType.push('syn_attack');
                }
                if (highConnCount > 200) {
                    threatScore += highConnCount * 3;
                    attackType.push('massive_connection_flood');
                }
                else if (highConnCount > 100) {
                    threatScore += highConnCount * 2;
                    attackType.push('connection_flood');
                }
                else if (highConnCount > 50) {
                    threatScore += highConnCount;
                    attackType.push('high_connections');
                }
                if (timeWaitCount > 500) {
                    threatScore += timeWaitCount * 2;
                    attackType.push('time_wait_exhaustion');
                }
                else if (timeWaitCount > 200) {
                    threatScore += timeWaitCount;
                    attackType.push('time_wait_abuse');
                }
                if (connectionCount > 100) {
                    threatScore += connectionCount * 2;
                    if (!attackType.includes('connection_flood'))
                        attackType.push('connection_flood');
                }
                else if (connectionCount > 50) {
                    threatScore += connectionCount;
                    attackType.push('high_connections');
                }
                if (portScanCount > 10) {
                    threatScore += portScanCount * 15;
                    attackType.push('aggressive_scan');
                }
                else if (portScanCount > 5) {
                    threatScore += portScanCount * 10;
                    attackType.push('port_scan');
                }
                if (udpCount > 50) {
                    threatScore += udpCount * 5;
                    attackType.push('udp_flood');
                }
                else if (udpCount > 20) {
                    threatScore += udpCount * 3;
                    attackType.push('udp_attack');
                }
                if (!this.liveIPs.has(ip)) {
                    const existingIP = await this.db.get(`SELECT blocked, blocked_at FROM ddos_ips WHERE ip = ?`, [ip]);
                    this.liveIPs.set(ip, {
                        requests: 0,
                        bandwidth: 0,
                        threads: 0,
                        first_seen: now,
                        last_seen: now,
                        threat_level: 'low',
                        connections: 0,
                        attack_type: [],
                        threat_score: 0,
                        attack_details: {},
                        blocked: Boolean(existingIP?.blocked),
                        blocked_at: existingIP?.blocked_at ?? null,
                    });
                    await this.db.run(`INSERT OR IGNORE INTO ddos_ips (ip, first_seen, last_seen) VALUES (?, ?, ?)`, [ip, now, now]);
                }
                const live = this.liveIPs.get(ip);
                live.connections = connectionCount;
                live.last_seen = now;
                live.threat_score = threatScore;
                live.attack_type = attackType;
                live.syn_count = synCount;
                live.udp_count = udpCount;
                live.port_scan_count = portScanCount;
                live.high_conn_count = highConnCount;
                live.time_wait_count = timeWaitCount;
                if (threatScore >= this.settings.threat_threshold_critical) {
                    live.threat_level = 'critical';
                    criticalCount++;
                }
                else if (threatScore >= this.settings.threat_threshold_high) {
                    live.threat_level = 'high';
                    highCount++;
                }
                else if (threatScore >= this.settings.threat_threshold_medium) {
                    live.threat_level = 'medium';
                    mediumCount++;
                }
                else {
                    live.threat_level = 'low';
                }
                const shouldBlock = this.settings.auto_block && (live.threat_level === 'critical' ||
                    threatScore >= this.settings.threat_threshold_critical ||
                    (this.settings.intelligent_blocking && (synCount >= this.settings.auto_block_syn_recv ||
                        highConnCount >= this.settings.auto_block_high_connections ||
                        portScanCount >= this.settings.auto_block_port_scan ||
                        timeWaitCount >= this.settings.auto_block_time_wait ||
                        attackType.length >= 3 ||
                        (synCount > 20 && highConnCount > 100) ||
                        (portScanCount > 5 && synCount > 10) ||
                        (udpCount > 30 && connectionCount > 50))));
                if (shouldBlock) {
                    const alreadyBlocked = Boolean(live.blocked);
                    if (!alreadyBlocked) {
                        const result = await this.blockIP(ip, attackType.join(',') || 'auto');
                        if (result.success) {
                            live.blocked = true;
                            live.blocked_at = Date.now();
                            console.log(`[DDoS] AUTO-BLOCK: ${ip} (${live.threat_level}, score ${threatScore}) [${attackType.join(', ')}]`);
                        }
                    }
                }
            }
            this.stats.total_connections = Object.values(connections).reduce((a, b) => a + b, 0);
            this.stats.suspicious_ips = detectedIPs.size;
            this.stats.critical_threats = criticalCount;
            this.stats.high_threats = highCount;
            this.stats.medium_threats = mediumCount;
            this.stats.last_scan = now;
        }
        catch (err) {
            console.error('[DDoS] Network analysis error:', err);
        }
    }
    async persistLiveData() {
        const now = Date.now();
        for (const [ip, data] of this.liveIPs.entries()) {
            const d = data;
            await this.db.run(`INSERT INTO ddos_ips (ip, requests, bandwidth, threads, last_seen, threat_level, first_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(ip) DO UPDATE SET
           requests = requests + ?,
           bandwidth = bandwidth + ?,
           threads = ?,
           last_seen = ?,
           threat_level = ?`, [
                ip, d.requests, d.bandwidth, d.threads, d.last_seen, d.threat_level, d.first_seen,
                d.requests, d.bandwidth, d.threads, d.last_seen, d.threat_level,
            ]);
        }
    }
    async autoUnblockExpired() {
        if (this.settings.block_duration <= 0)
            return;
        const expireTime = Date.now() - this.settings.block_duration * 1000;
        const rows = await this.db.all(`SELECT ip FROM ddos_ips WHERE blocked = 1 AND blocked_at < ?`, [expireTime]);
        for (const row of rows) {
            const result = await this.unblockIP(row.ip);
            if (result.success)
                console.log(`[DDoS] Auto-unblocked: ${row.ip} (duration expired)`);
        }
    }
    async blockIP(ip, reason = 'manual') {
        if (!isLinux)
            return { success: false, message: 'Blocking requires a Linux host with iptables.' };
        if (!isValidIPv4(ip))
            return { success: false, message: 'Invalid IP address.' };
        try {
            const { stdout } = await execFileAsync(`iptables -L INPUT -n`, { shell: '/bin/bash' });
            if (stdout.includes(ip)) {
                await this.db.run(`UPDATE ddos_ips SET blocked = 1, blocked_at = ? WHERE ip = ?`, [Date.now(), ip]);
                return { success: true, message: 'Already blocked' };
            }
        }
        catch {
            // not found in iptables, proceed to block
        }
        try {
            await execFileAsync(`iptables -A INPUT -s ${ip} -j DROP`, { shell: '/bin/bash' });
            this.stats.total_blocked++;
            await this.db.run(`UPDATE ddos_ips SET blocked = 1, blocked_at = ? WHERE ip = ?`, [Date.now(), ip]);
            await this.db.run(`INSERT INTO ddos_attack_logs (ip, timestamp, requests, bandwidth, action) VALUES (?, ?, ?, ?, ?)`, [ip, Date.now(), this.liveIPs.get(ip)?.requests || 0, this.liveIPs.get(ip)?.bandwidth || 0, `blocked_${reason}`]);
            console.log(`[DDoS] Blocked: ${ip} (${reason})`);
            return { success: true, message: 'IP blocked' };
        }
        catch (err) {
            console.error(`[DDoS] Block failed for ${ip}:`, err.message);
            return { success: false, message: 'Block failed', error: err.message };
        }
    }
    async unblockIP(ip) {
        if (!isLinux)
            return { success: false, message: 'Unblocking requires a Linux host with iptables.' };
        if (!isValidIPv4(ip))
            return { success: false, message: 'Invalid IP address.' };
        try {
            await execFileAsync(`iptables -D INPUT -s ${ip} -j DROP`, { shell: '/bin/bash' });
            await this.db.run(`UPDATE ddos_ips SET blocked = 0, blocked_at = NULL WHERE ip = ?`, [ip]);
            await this.db.run(`INSERT INTO ddos_attack_logs (ip, timestamp, requests, bandwidth, action) VALUES (?, ?, ?, ?, ?)`, [ip, Date.now(), 0, 0, 'unblocked']);
            console.log(`[DDoS] Unblocked: ${ip}`);
            return { success: true, message: 'IP unblocked' };
        }
        catch (err) {
            console.error(`[DDoS] Unblock failed for ${ip}:`, err.message);
            return { success: false, message: 'Unblock failed', error: err.message };
        }
    }
    async listIps(opts = {}) {
        const page = Math.max(1, opts.page || 1);
        const limit = Math.min(200, Math.max(1, opts.limit || 50));
        const offset = (page - 1) * limit;
        const filter = opts.filter || 'all';
        let query = `SELECT * FROM ddos_ips`;
        const params = [];
        if (filter === 'blocked')
            query += ` WHERE blocked = 1`;
        else if (filter === 'active') {
            query += ` WHERE last_seen > ?`;
            params.push(Date.now() - 300000);
        }
        else if (filter === 'threat')
            query += ` WHERE threat_level IN ('high', 'critical')`;
        query += ` ORDER BY requests DESC LIMIT ? OFFSET ?`;
        params.push(limit, offset);
        const rows = await this.db.all(query, params);
        const count = await this.db.get(`SELECT COUNT(*) as total FROM ddos_ips`);
        return {
            ips: rows,
            pagination: {
                page,
                limit,
                total: count?.total || 0,
                pages: Math.ceil((count?.total || 0) / limit),
            },
        };
    }
    async getIp(ip) {
        const ipData = await this.db.get(`SELECT * FROM ddos_ips WHERE ip = ?`, [ip]);
        if (!ipData)
            return null;
        const logs = await this.db.all(`SELECT * FROM ddos_attack_logs WHERE ip = ? ORDER BY timestamp DESC LIMIT 100`, [ip]);
        return { ip: ipData, live: this.liveIPs.get(ip) || null, logs };
    }
    async clearIp(ip) {
        await this.db.run(`DELETE FROM ddos_ips WHERE ip = ?`, [ip]);
        await this.db.run(`DELETE FROM ddos_attack_logs WHERE ip = ?`, [ip]);
        this.liveIPs.delete(ip);
        this.minuteTracker.delete(ip);
        return { success: true, message: 'IP data cleared' };
    }
    async listLogs(limit = 100) {
        return this.db.all(`SELECT * FROM ddos_attack_logs ORDER BY timestamp DESC LIMIT ?`, [limit]);
    }
    async trackRequest(ip, contentLength) {
        const now = Date.now();
        const currentMinute = Math.floor(now / 60000);
        this.stats.total_requests++;
        this.stats.active_connections++;
        if (!this.liveIPs.has(ip)) {
            this.liveIPs.set(ip, {
                requests: 0, bandwidth: 0, threads: 0,
                first_seen: now, last_seen: now, threat_level: 'low',
            });
            void this.db.run(`INSERT OR IGNORE INTO ddos_ips (ip, first_seen, last_seen) VALUES (?, ?, ?)`, [ip, now, now]);
        }
        const live = this.liveIPs.get(ip);
        live.requests = (live.requests || 0) + 1;
        live.threads = (live.threads || 0) + 1;
        live.last_seen = now;
        live.bandwidth = (live.bandwidth || 0) + contentLength;
        const tracker = this.minuteTracker.get(ip);
        if (!tracker || tracker.minute !== currentMinute) {
            this.minuteTracker.set(ip, { minute: currentMinute, requests: 0, bandwidth: 0 });
        }
        const t = this.minuteTracker.get(ip);
        t.requests++;
        t.bandwidth += contentLength;
        this.stats.total_bandwidth += contentLength;
        const requests = t.requests;
        const bandwidth = t.bandwidth;
        let level = 'low';
        if (requests >= this.settings.threat_threshold_high || bandwidth >= this.settings.max_bandwidth_per_minute * 5)
            level = 'critical';
        else if (requests >= this.settings.threat_threshold_medium || bandwidth >= this.settings.max_bandwidth_per_minute * 2)
            level = 'high';
        else if (requests >= this.settings.rate_limit_per_minute || bandwidth >= this.settings.max_bandwidth_per_minute)
            level = 'medium';
        live.threat_level = level;
        if (this.settings.auto_block) {
            const exceedsRate = t.requests > this.settings.rate_limit_per_minute;
            const exceedsBw = t.bandwidth > this.settings.max_bandwidth_per_minute;
            if (exceedsRate || exceedsBw) {
                const reason = exceedsRate ? 'rate_limit' : 'bandwidth_limit';
                void this.blockIP(ip, reason);
            }
        }
        // Schedule thread decrement on response finish via a timeout (simplified)
        setTimeout(() => {
            const l = this.liveIPs.get(ip);
            if (l)
                l.threads = Math.max(0, (l.threads || 0) - 1);
            this.stats.active_connections = Math.max(0, this.stats.active_connections - 1);
        }, 60000);
    }
    async getNetworkAnalysis() {
        const [connections, synFlood, scanners] = await Promise.all([
            this.monitorActiveConnections(),
            this.monitorSynFlood(),
            this.detectPortScanning(),
        ]);
        const totalConnections = Object.values(connections).reduce((a, b) => a + b, 0);
        return {
            active_connections: connections,
            syn_flood_attacks: synFlood,
            port_scanners: scanners,
            total_connections: totalConnections,
            suspicious_count: Object.keys(synFlood).length + Object.keys(scanners).length,
            timestamp: Date.now(),
        };
    }
}
exports.DdosManager = DdosManager;
