"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RESELLER_API_SCOPES = void 0;
exports.signResellerRequest = signResellerRequest;
exports.createResellerHmacAuthMiddleware = createResellerHmacAuthMiddleware;
const crypto_1 = __importDefault(require("crypto"));
const crypto_vault_1 = require("./crypto-vault");
exports.RESELLER_API_SCOPES = [
    'vps.read', 'vps.start', 'vps.stop', 'vps.restart',
    'resources.read', 'stats.read',
    'customers.read', 'customers.create', 'customers.update', 'customers.delete',
    'api_keys.read', 'api_keys.create', 'api_keys.revoke',
];
function signResellerRequest(params) {
    const timestamp = String(params.timestamp ?? Math.floor(Date.now() / 1000));
    const nonce = params.nonce || crypto_1.default.randomBytes(16).toString('hex');
    const body = params.body === undefined
        ? Buffer.alloc(0)
        : Buffer.isBuffer(params.body) ? params.body : Buffer.from(params.body, 'utf8');
    const bodyHash = crypto_1.default.createHash('sha256').update(body).digest('hex');
    const canonical = `${timestamp}\n${nonce}\n${params.method.toUpperCase()}\n${params.pathWithQuery}\n${bodyHash}`;
    const signature = crypto_1.default.createHmac('sha256', params.apiSecret).update(canonical).digest('hex');
    return {
        'X-TGV-API-KEY': params.apiKey,
        'X-TGV-TIMESTAMP': timestamp,
        'X-TGV-NONCE': nonce,
        'X-TGV-SIGNATURE': signature,
    };
}
function getClientIp(req) {
    return String(req.ip || req.socket.remoteAddress || '').replace(/^::ffff:/, '');
}
async function writeRequestLog(db, values) {
    await db.run(`INSERT INTO reseller_api_requests
       (api_key_id, user_id, key_fingerprint, method, path, ip_address, status_code, success)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [values.apiKeyId || null, values.userId || null, values.keyFingerprint || null,
        values.method.slice(0, 12), values.path.slice(0, 512), values.ip.slice(0, 64), values.statusCode, values.success ? 1 : 0]).catch(() => undefined);
}
/**
 * HMAC request auth for /api/v1/reseller/*.
 * Canonical bytes: timestamp + LF + nonce + LF + uppercase method + LF + raw path/query + LF + lowercase SHA-256(raw body),
 * signed with HMAC-SHA256 using the one-time-displayed API secret. Timestamp skew is limited to five minutes.
 */
function createResellerHmacAuthMiddleware(db) {
    return async (req, res, next) => {
        const rawKey = String(req.headers['x-tgv-api-key'] || '').trim();
        if (!rawKey)
            return next(); // Permit normal TGVPANEL browser-session authentication.
        const timestampText = String(req.headers['x-tgv-timestamp'] || '').trim();
        const nonce = String(req.headers['x-tgv-nonce'] || '').trim();
        const providedSignature = String(req.headers['x-tgv-signature'] || '').trim().toLowerCase();
        const ip = getClientIp(req);
        const fingerprint = (0, crypto_vault_1.hashApiKey)(rawKey).slice(0, 16);
        const pathOnly = String(req.originalUrl || req.url || req.path).split('#')[0];
        let logUserId = null;
        let logKeyId = null;
        let logged = false;
        const log = async (statusCode, success) => {
            if (logged)
                return;
            logged = true;
            await writeRequestLog(db, {
                apiKeyId: logKeyId,
                userId: logUserId,
                keyFingerprint: fingerprint,
                method: req.method,
                path: pathOnly.split('?')[0],
                ip,
                statusCode,
                success,
            });
        };
        const reject = async (status, message) => {
            await log(status, false);
            return res.status(status).json({ error: message });
        };
        try {
            if (!/^tgvpk_[a-f0-9]{64}$/i.test(rawKey))
                return reject(401, 'Invalid reseller API key.');
            if (!/^\d{10}$/.test(timestampText) || Math.abs(Math.floor(Date.now() / 1000) - Number(timestampText)) > 300) {
                return reject(401, 'Invalid or expired request timestamp.');
            }
            if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce) || !/^[a-f0-9]{64}$/.test(providedSignature)) {
                return reject(401, 'Missing or malformed HMAC authentication headers.');
            }
            const row = await db.get(`SELECT k.*, u.username, u.role, u.is_active AS user_active
         FROM reseller_api_keys k JOIN users u ON u.id = k.user_id
         WHERE k.key_hash = ?`, [(0, crypto_vault_1.hashApiKey)(rawKey)]);
            if (!row || Number(row.is_active) !== 1 || Number(row.user_active) !== 1 || row.role !== 'reseller') {
                return reject(401, 'Invalid or inactive reseller API key.');
            }
            logUserId = Number(row.user_id);
            logKeyId = Number(row.id);
            if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) {
                return reject(401, 'Reseller API key has expired.');
            }
            const allowedIps = JSON.parse(row.ip_allowlist || '[]');
            if (!Array.isArray(allowedIps) || (allowedIps.length > 0 && !allowedIps.includes(ip))) {
                return reject(403, 'Source IP is not allowed for this reseller API key.');
            }
            const apiSecret = (0, crypto_vault_1.decryptSecret)(row.secret_enc);
            if (!apiSecret || !(0, crypto_vault_1.timingSafeEqualStr)((0, crypto_vault_1.hashApiKey)(apiSecret), String(row.secret_hash || ''))) {
                return reject(401, 'Reseller API key secret is invalid or unavailable.');
            }
            const bodyText = typeof req.rawBody === 'string' ? req.rawBody : '';
            const bodyHash = crypto_1.default.createHash('sha256').update(Buffer.from(bodyText, 'utf8')).digest('hex');
            const canonical = `${timestampText}\n${nonce}\n${req.method.toUpperCase()}\n${pathOnly}\n${bodyHash}`;
            const expected = crypto_1.default.createHmac('sha256', apiSecret).update(canonical).digest('hex');
            if (!(0, crypto_vault_1.timingSafeEqualStr)(expected, providedSignature))
                return reject(401, 'Invalid reseller API signature.');
            let permissions = [];
            try {
                const parsed = JSON.parse(row.permissions || '[]');
                if (Array.isArray(parsed))
                    permissions = parsed.filter((permission) => exports.RESELLER_API_SCOPES.includes(permission));
            }
            catch {
                permissions = [];
            }
            const nowSeconds = Math.floor(Date.now() / 1000);
            const windowStart = Math.floor(nowSeconds / 60) * 60;
            const rateLimit = Math.max(1, Math.min(6000, Number(row.rate_limit_per_minute) || 60));
            let rateLimited = false;
            try {
                await db.transaction(async () => {
                    const fresh = await db.get(`SELECT key_hash, secret_hash, rate_window_start, rate_window_count, is_active FROM reseller_api_keys WHERE id = ?`, [row.id]);
                    if (!fresh || Number(fresh.is_active) !== 1)
                        throw new Error('KEY_REVOKED');
                    if (fresh.key_hash !== row.key_hash || fresh.secret_hash !== row.secret_hash)
                        throw new Error('KEY_ROTATED');
                    const count = Number(fresh.rate_window_start) === windowStart ? Number(fresh.rate_window_count || 0) : 0;
                    await db.run(`INSERT INTO reseller_api_nonces (api_key_id, nonce, expires_at) VALUES (?, ?, datetime('now', '+10 minutes'))`, [row.id, nonce]);
                    if (count >= rateLimit) {
                        rateLimited = true;
                        await db.run(`DELETE FROM reseller_api_nonces WHERE expires_at < datetime('now')`);
                        return;
                    }
                    await db.run(`UPDATE reseller_api_keys SET rate_window_start = ?, rate_window_count = ?, last_used_at = datetime('now') WHERE id = ? AND is_active = 1`, [windowStart, count + 1, row.id]);
                    await db.run(`DELETE FROM reseller_api_nonces WHERE expires_at < datetime('now')`);
                });
            }
            catch (err) {
                if (String(err?.message).includes('UNIQUE constraint failed'))
                    return reject(401, 'Replay detected: nonce has already been used.');
                if (String(err?.message).includes('KEY_REVOKED'))
                    return reject(401, 'Reseller API key has been revoked.');
                if (String(err?.message).includes('KEY_ROTATED'))
                    return reject(401, 'Reseller API key was rotated during this request.');
                throw err;
            }
            if (rateLimited) {
                res.setHeader('Retry-After', '60');
                return reject(429, 'Reseller API key request rate limit exceeded.');
            }
            req.principal = {
                userId: Number(row.user_id),
                username: String(row.username),
                role: 'reseller',
                viaApiKey: true,
                apiKeyId: Number(row.id),
                apiPermissions: permissions,
                apiScopeType: 'reseller',
            };
            res.once('finish', () => {
                void log(res.statusCode, res.statusCode < 400);
            });
            return next();
        }
        catch (err) {
            return reject(500, 'Reseller API authentication failed.');
        }
    };
}
