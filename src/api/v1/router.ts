import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { isIP } from 'net';
import bcrypt from 'bcryptjs';
import { Router, Request, Response } from 'express';
import multer from 'multer';
import { HkvmRuntimeContext } from '../../context';
import { getNodeHealthReport } from '../../node-agent/health';
import {
  decryptSecret,
  encryptSecret,
  generateApiKeyPair,
  generateTotpQrDataUrl,
  generateTotpSecret,
  hashApiKey,
  verifyTotpCode,
} from '../../security/crypto-vault';
import {
  AuthenticatedPrincipal,
  createRateLimiter,
  requirePrincipal,
  requireRole,
} from '../../security/middleware';
import { importHvmDatabase, dryRunHvmImport } from '../../db/hvm-importer';
import { LifecycleAction, VirtualizationEngine } from '../../services/virtualization/VirtualizationAdapter';
import { RESELLER_API_SCOPES, createResellerHmacAuthMiddleware, ResellerApiScope } from '../../security/reseller-api-auth';

const templateUploadDir = path.resolve(process.cwd(), 'data', 'lxc-templates');
fs.mkdirSync(templateUploadDir, { recursive: true });

const templateUploader = multer({
  dest: templateUploadDir,
  limits: { fileSize: 4 * 1024 * 1024 * 1024 },
});

function pStr(val: string | string[] | undefined): string {
  return Array.isArray(val) ? val[0] || '' : val || '';
}

function pInt(val: string | string[] | undefined): number {
  return parseInt(pStr(val), 10);
}

async function runTrackedInstanceMutation<T>(
  ctx: HkvmRuntimeContext,
  principal: AuthenticatedPrincipal,
  engine: VirtualizationEngine,
  refId: number,
  action: string,
  worker: () => Promise<T>,
  requireOwnerOrStaff = false
): Promise<T> {
  await ctx.instanceManager.getAuthorizedInstance(principal, engine, refId, requireOwnerOrStaff);
  let result!: T;
  await ctx.instanceManager.tasks.runSync({
    engine,
    instanceRefId: refId,
    actorId: principal.userId,
    action,
    worker: async (reportProgress) => {
      await reportProgress(null, `Applying ${action.replace(/_/g, ' ')} operation`);
      result = await worker();
      await reportProgress(null, 'Operation completed; refreshing VPS record');
      // Do not persist adapter responses: they can contain passwords, keys, or host details.
      return { completed: true };
    },
  });
  return result;
}

function requireResellerScope(scope: ResellerApiScope) {
  return (req: Request, res: Response, next: () => void) => {
    const principal = req.principal;
    if (!principal) return res.status(401).json({ error: 'Authentication required.' });
    if (principal.role === 'admin' && !principal.viaApiKey) return next();
    if (principal.role !== 'reseller') return res.status(403).json({ error: 'Reseller account required.' });
    if (principal.viaApiKey && !(principal.apiPermissions || []).includes(scope)) {
      return res.status(403).json({ error: `API key lacks ${scope} permission.` });
    }
    return next();
  };
}

function parseResellerPermissions(value: unknown): ResellerApiScope[] {
  if (!Array.isArray(value) || value.length === 0 || value.some((scope) => typeof scope !== 'string' || !RESELLER_API_SCOPES.includes(scope as ResellerApiScope))) {
    throw new Error('Choose one or more supported reseller API permissions.');
  }
  return [...new Set(value)] as ResellerApiScope[];
}

function parseResellerIpAllowlist(value: unknown): string[] {
  if (value === undefined || value === null || value === '') return [];
  if (!Array.isArray(value) || value.length > 100) throw new Error('IP allowlist must be an array of at most 100 IPv4 or IPv6 addresses.');
  const ips = value.map((ip) => String(ip).trim());
  if (ips.some((ip) => isIP(ip) === 0)) throw new Error('IP allowlist entries must be exact IPv4 or IPv6 addresses. CIDR and wildcard entries are not accepted.');
  return [...new Set(ips)];
}

function parseResellerExpiry(value: unknown): string | null {
  if (value === undefined || value === null || value === '') return null;
  const date = new Date(String(value));
  if (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) throw new Error('Expiration must be a valid future date.');
  return date.toISOString();
}

function parseResellerCustomerFields(body: any, existing?: any) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Customer fields must be a JSON object.');
  const allowed = new Set(['displayName', 'email', 'externalReference', 'notes', 'status']);
  if (Object.keys(body).some((key) => !allowed.has(key))) throw new Error('Unsupported customer field.');
  const displayNameValue = body.displayName === undefined ? existing?.display_name : body.displayName;
  const emailValue = body.email === undefined ? existing?.email : body.email;
  if (typeof displayNameValue !== 'string' || typeof emailValue !== 'string') throw new Error('Customer display name and email must be strings.');
  const displayName = displayNameValue.trim();
  const email = emailValue.trim().toLowerCase();
  const externalReferenceValue = body.externalReference === undefined ? existing?.external_reference : body.externalReference;
  const notesValue = body.notes === undefined ? (existing?.notes_enc ? decryptSecret(existing.notes_enc) : null) : body.notes;
  if (externalReferenceValue !== undefined && externalReferenceValue !== null && typeof externalReferenceValue !== 'string') throw new Error('External reference must be a string or null.');
  if (notesValue !== undefined && notesValue !== null && typeof notesValue !== 'string') throw new Error('Customer notes must be a string or null.');
  const externalReference = typeof externalReferenceValue === 'string' && externalReferenceValue.trim() ? externalReferenceValue.trim() : null;
  const notes = typeof notesValue === 'string' && notesValue.trim() ? notesValue.trim() : null;
  const statusValue = body.status === undefined ? existing?.status || 'active' : body.status;
  if (typeof statusValue !== 'string') throw new Error('Customer status must be a string.');
  const status = statusValue.trim().toLowerCase();
  if (!displayName || displayName.length > 120) throw new Error('Customer display name is required and must be 120 characters or fewer.');
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('A valid customer email address is required (maximum 254 characters).');
  if (externalReference !== null && externalReference.length > 100) throw new Error('External reference must be 100 characters or fewer.');
  if (notes !== null && notes.length > 1000) throw new Error('Customer notes must be 1000 characters or fewer.');
  if (status !== 'active' && status !== 'suspended') throw new Error('Customer status must be active or suspended.');
  return { displayName, email, externalReference, notes, status };
}

function safeResellerCustomer(row: any) {
  return {
    id: Number(row.id),
    displayName: row.display_name,
    email: row.email,
    externalReference: row.external_reference,
    status: row.status,
    notes: row.notes_enc ? decryptSecret(row.notes_enc) || null : null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function safeResellerKey(row: any) {
  return {
    id: row.id,
    userId: row.user_id,
    username: row.username,
    name: row.name,
    description: row.description,
    keyPrefix: row.key_prefix,
    permissions: (() => { try { return JSON.parse(row.permissions || '[]'); } catch { return []; } })(),
    ipAllowlist: (() => { try { return JSON.parse(row.ip_allowlist || '[]'); } catch { return []; } })(),
    rateLimitPerMinute: row.rate_limit_per_minute,
    isActive: Boolean(row.is_active),
    lastUsedAt: row.last_used_at,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function createApiV1Router(ctx: HkvmRuntimeContext): Router {
  const router = Router();
  const apiMutationLimiter = createRateLimiter({
    windowMs: 60_000,
    max: 120,
    keyPrefix: 'api_v1_mut',
  });
  const authResetLimiter = createRateLimiter({
    windowMs: 15 * 60_000,
    max: 15,
    keyPrefix: 'api_v1_reset',
  });
  const passwordChangeLimiter = createRateLimiter({
    windowMs: 15 * 60_000,
    max: 8,
    keyPrefix: 'api_v1_password_change',
    message: 'Too many password change attempts. Please retry later.',
  });
  const backupScheduleLimiter = createRateLimiter({
    windowMs: 15 * 60_000,
    max: 30,
    keyPrefix: 'api_v1_backup_schedule',
    message: 'Too many backup schedule changes. Please retry later.',
  });
  const snapshotScheduleLimiter = createRateLimiter({
    windowMs: 15 * 60_000,
    max: 30,
    keyPrefix: 'api_v1_snapshot_schedule',
    message: 'Too many snapshot schedule changes. Please retry later.',
  });
  const resellerKeyMutationLimiter = createRateLimiter({
    windowMs: 15 * 60_000,
    max: 30,
    keyPrefix: 'api_v1_reseller_key_mutation',
    message: 'Too many reseller API key changes. Please retry later.',
  });
  const resellerAuthIpLimiter = createRateLimiter({
    windowMs: 60_000,
    max: 300,
    keyPrefix: 'api_v1_reseller_auth',
    message: 'Too many reseller API requests from this source IP.',
  });

  // --- Public / Unauthenticated Health & Password Reset Endpoints ---
  router.get('/health', async (_req: Request, res: Response) => {
    const report = await getNodeHealthReport();
    res.json({
      panel: 'TGVPANEL',
      version: '4.0.0',
      status: report.status,
      capabilities: report.capabilities,
      warnings: report.warnings,
      timestamp: report.timestamp,
    });
  });

  router.post(
    '/auth/password-reset/request',
    authResetLimiter,
    async (req: Request, res: Response) => {
      try {
        const identifier = String(req.body?.usernameOrEmail || '').trim();
        if (!identifier) {
          return res.status(400).json({ error: 'Username or email is required.' });
        }

        const user = await ctx.db.get<{ id: number; username: string }>(
          `SELECT id, username FROM users WHERE LOWER(username) = LOWER(?) OR (email IS NOT NULL AND LOWER(email) = LOWER(?))`,
          [identifier, identifier]
        );

        if (user) {
          const rawToken = crypto.randomBytes(32).toString('hex');
          const tokenHash = hashApiKey(rawToken);
          await ctx.db.run(
            `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, requested_ip)
             VALUES (?, ?, datetime('now', '+30 minutes'), ?)`,
            [user.id, tokenHash, req.ip || null]
          );
          await ctx.db.logActivity({
            userId: user.id,
            action: 'password_reset_requested',
            resourceType: 'user',
            resourceId: String(user.id),
            ipAddress: req.ip || null,
          });
          // Notify admins in-panel if SMTP is unconfigured
          const admins = await ctx.db.all<{ id: number }>(`SELECT id FROM users WHERE role = 'admin'`);
          for (const a of admins) {
            await ctx.monitoringService.createNotification({
              userId: a.id,
              type: 'info',
              title: 'Password Reset Requested',
              message: `Account "${user.username}" requested a password reset token.`,
            });
          }
        }

        return res.json({
          success: true,
          message: 'If the account exists, a password reset request has been recorded.',
        });
      } catch (err: any) {
        return res.status(500).json({ error: err.message });
      }
    }
  );

  router.post(
    '/auth/password-reset/confirm',
    authResetLimiter,
    async (req: Request, res: Response) => {
      try {
        const token = String(req.body?.token || '').trim();
        const newPassword = String(req.body?.newPassword || '');
        if (!token || newPassword.length < 8) {
          return res
            .status(400)
            .json({ error: 'Valid reset token and password (>= 8 chars) are required.' });
        }

        const tokenRow = await ctx.db.get<{ id: number; user_id: number }>(
          `SELECT id, user_id FROM password_reset_tokens
           WHERE token_hash = ? AND used_at IS NULL AND datetime(expires_at) > datetime('now')`,
          [hashApiKey(token)]
        );
        if (!tokenRow) {
          return res.status(400).json({ error: 'Invalid or expired password reset token.' });
        }

        const hashed = bcrypt.hashSync(newPassword, 10);
        await ctx.db.transaction(async () => {
          await ctx.db.run(`UPDATE users SET password = ? WHERE id = ?`, [
            hashed,
            tokenRow.user_id,
          ]);
          await ctx.db.run(
            `UPDATE password_reset_tokens SET used_at = datetime('now') WHERE id = ?`,
            [tokenRow.id]
          );
        });

        return res.json({ success: true });
      } catch (err: any) {
        return res.status(500).json({ error: err.message });
      }
    }
  );

  // --- Self-Authenticated Remote Node Pairing & Active Push-Heartbeat Endpoints ---
  router.post(
    '/nodes/join/:token',
    authResetLimiter,
    async (req: Request, res: Response) => {
      try {
        const callerIp =
          (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
          req.socket.remoteAddress ||
          '';
        const out = await ctx.nodeManager.redeemJoinToken({
          rawToken: pStr(req.params.token),
          endpointUrl: req.body?.endpointUrl ? String(req.body.endpointUrl) : undefined,
          ipAddress: req.body?.ipAddress ? String(req.body.ipAddress) : undefined,
          hostname: req.body?.hostname ? String(req.body.hostname) : undefined,
          agentPort: req.body?.agentPort ? Number(req.body.agentPort) : undefined,
          tlsCertPem: req.body?.tlsCertPem ? String(req.body.tlsCertPem) : null,
          verifySsl: req.body?.verifySsl !== undefined ? Boolean(req.body.verifySsl) : undefined,
          callerIp,
        });
        await ctx.db.logActivity({
          action: 'node_joined_via_token',
          resourceType: 'node',
          resourceId: String(out.nodeId),
          ipAddress: callerIp,
          details: { nodeName: out.nodeName, url: out.url },
        });
        return res.json(out);
      } catch (err: any) {
        return res.status(400).json({ error: err.message });
      }
    }
  );

  router.post('/nodes/agent-heartbeat', async (req: Request, res: Response) => {
    try {
      const rawBody =
        typeof (req as any).rawBody === 'string'
          ? (req as any).rawBody
          : req.body && Object.keys(req.body).length > 0
            ? JSON.stringify(req.body)
            : '';
      const out = await ctx.nodeManager.receiveAgentHeartbeat({
        headers: req.headers,
        rawBody,
        body: req.body || {},
      });
      return res.json(out);
    } catch (err: any) {
      return res.status(401).json({ error: err.message });
    }
  });

  // Reseller requests may use a session or replay-protected HMAC credentials.
  // This must run before generic principal enforcement so the signed key can establish a scoped principal.
  router.use('/reseller', resellerAuthIpLimiter, createResellerHmacAuthMiddleware(ctx.db));

  // --- All endpoints below require an authenticated principal (Session or Bearer API Key) ---
  router.use(requirePrincipal);
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      // Password changes have a stricter dedicated limiter below; avoid double-counting them.
      if (
        req.path === '/auth/password/change' ||
        req.path.startsWith('/backup-schedules/') ||
        req.path.startsWith('/snapshot-schedules/') ||
        req.path.startsWith('/reseller/')
      ) return next();
      return apiMutationLimiter(req, res, next);
    }
    return next();
  });

  // A password change is an interactive browser-session action, not a bearer-token
  // operation. Require the current password, throttle attempts, and audit success.
  router.post('/auth/password/change', passwordChangeLimiter, async (req: Request, res: Response) => {
    try {
      const session: any = (req as any).session;
      const principal = req.principal!;
      if (
        principal.viaApiKey ||
        principal.impersonatedBy ||
        !session ||
        Number(session.userId) !== principal.userId
      ) {
        return res.status(403).json({ error: 'Password changes require your own authenticated browser session.' });
      }

      const currentPassword = String(req.body?.currentPassword || '');
      const newPassword = String(req.body?.newPassword || '');
      if (!currentPassword || newPassword.length < 8 || newPassword.length > 1024) {
        return res.status(400).json({ error: 'Current password and a new password (8–1024 characters) are required.' });
      }

      const user = await ctx.db.get<{ password: string }>(
        `SELECT password FROM users WHERE id = ?`,
        [principal.userId]
      );
      if (!user) return res.status(404).json({ error: 'User not found.' });

      let currentPasswordIsValid = false;
      try {
        currentPasswordIsValid = bcrypt.compareSync(currentPassword, user.password);
      } catch {
        currentPasswordIsValid = false;
      }
      if (!currentPasswordIsValid) {
        await ctx.db.logActivity({
          userId: principal.userId,
          action: 'password_change_failed',
          resourceType: 'user',
          resourceId: String(principal.userId),
          ipAddress: req.ip || null,
          details: { reason: 'invalid_current_password' },
        });
        return res.status(400).json({ error: 'Current password is incorrect.' });
      }
      if (bcrypt.compareSync(newPassword, user.password)) {
        return res.status(400).json({ error: 'Choose a new password different from your current password.' });
      }

      const nextHash = bcrypt.hashSync(newPassword, 12);
      await ctx.db.transaction(async () => {
        await ctx.db.run(`UPDATE users SET password = ? WHERE id = ?`, [nextHash, principal.userId]);
        await ctx.db.logActivity({
          userId: principal.userId,
          action: 'password_changed',
          resourceType: 'user',
          resourceId: String(principal.userId),
          ipAddress: req.ip || null,
        });
      });
      return res.json({ success: true, message: 'Password changed successfully.' });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // --- 2FA (TOTP) Management ---
  router.post('/auth/2fa/setup', async (req: Request, res: Response) => {
    try {
      const secret = generateTotpSecret();
      const qr = await generateTotpQrDataUrl(req.principal!.username, secret, 'TGVPANEL');
      await ctx.db.run(`UPDATE users SET two_factor_secret_enc = ? WHERE id = ?`, [
        encryptSecret(secret),
        req.principal!.userId,
      ]);
      res.json({ secret, otpauthUrl: qr.otpauthUrl, qrDataUrl: qr.qrDataUrl });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/auth/2fa/enable', async (req: Request, res: Response) => {
    try {
      const code = String(req.body?.code || '');
      const row = await ctx.db.get<{ two_factor_secret_enc: string | null }>(
        `SELECT two_factor_secret_enc FROM users WHERE id = ?`,
        [req.principal!.userId]
      );
      if (!row?.two_factor_secret_enc) {
        return res.status(400).json({ error: 'Run 2FA setup first.' });
      }
      const secret = decryptSecret(row.two_factor_secret_enc);
      if (!verifyTotpCode(secret, code)) {
        return res.status(400).json({ error: 'Invalid 6-digit authenticator code.' });
      }
      await ctx.db.run(`UPDATE users SET two_factor_enabled = 1 WHERE id = ?`, [
        req.principal!.userId,
      ]);
      await ctx.db.logActivity({
        userId: req.principal!.userId,
        action: '2fa_enabled',
        resourceType: 'user',
        resourceId: String(req.principal!.userId),
      });
      return res.json({ success: true, twoFactorEnabled: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  router.post('/auth/2fa/disable', async (req: Request, res: Response) => {
    try {
      const code = String(req.body?.code || '');
      const row = await ctx.db.get<{ two_factor_secret_enc: string | null; two_factor_enabled: number }>(
        `SELECT two_factor_secret_enc, two_factor_enabled FROM users WHERE id = ?`,
        [req.principal!.userId]
      );
      if (row?.two_factor_enabled && row.two_factor_secret_enc) {
        const secret = decryptSecret(row.two_factor_secret_enc);
        if (!verifyTotpCode(secret, code) && req.principal!.role !== 'admin') {
          return res.status(400).json({ error: 'Invalid 6-digit authenticator code.' });
        }
      }
      await ctx.db.run(
        `UPDATE users SET two_factor_enabled = 0, two_factor_secret_enc = NULL WHERE id = ?`,
        [req.principal!.userId]
      );
      return res.json({ success: true, twoFactorEnabled: false });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // --- Admin User Impersonation (Audited) ---
  router.post(
    '/auth/impersonate/:userId',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const targetId = pInt(req.params.userId);
        const target = await ctx.db.get<any>(
          `SELECT id, username, role, email, full_name FROM users WHERE id = ?`,
          [targetId]
        );
        if (!target) return res.status(404).json({ error: 'Target user not found.' });

        const sess: any = (req as any).session;
        if (!sess) return res.status(400).json({ error: 'Browser session required for impersonation.' });

        sess.impersonatorAdminUser = sess.impersonatorAdminUser || {
          id: req.principal!.userId,
          username: req.principal!.username,
          role: req.principal!.role,
        };
        sess.impersonatorAdminId = sess.impersonatorAdminUser.id;
        sess.userId = target.id;
        sess.username = target.username;
        sess.role = target.role;
        sess.user = {
          id: target.id,
          username: target.username,
          role: target.role,
          email: target.email,
          full_name: target.full_name,
        };

        await ctx.db.logActivity({
          userId: sess.impersonatorAdminId,
          action: 'admin_impersonation_started',
          resourceType: 'user',
          resourceId: String(target.id),
          details: { targetUsername: target.username },
        });

        return res.json({ success: true, redirectTo: '/dashboard' });
      } catch (err: any) {
        return res.status(500).json({ error: err.message });
      }
    }
  );

  router.post('/auth/stop-impersonation', async (req: Request, res: Response) => {
    const sess: any = (req as any).session;
    if (!sess?.impersonatorAdminUser) {
      return res.status(400).json({ error: 'No active impersonation session.' });
    }
    sess.user = sess.impersonatorAdminUser;
    sess.userId = sess.impersonatorAdminUser.id;
    sess.username = sess.impersonatorAdminUser.username;
    sess.role = sess.impersonatorAdminUser.role;
    delete sess.impersonatorAdminUser;
    delete sess.impersonatorAdminId;
    return res.json({ success: true, redirectTo: '/admin/users' });
  });

  // --- Unified Instances (KVM + LXC) ---
  router.get('/instances', async (req: Request, res: Response) => {
    try {
      const engineParam = req.query.engine as VirtualizationEngine | undefined;
      const nodeIdParam = req.query.nodeId ? Number(req.query.nodeId) : undefined;
      const instances = await ctx.instanceManager.listAccessibleInstances(req.principal!, {
        engine: engineParam === 'kvm' || engineParam === 'lxc' ? engineParam : undefined,
        nodeId: nodeIdParam,
        status: req.query.status ? String(req.query.status) : undefined,
        search: req.query.search ? String(req.query.search) : undefined,
      });
      res.json({ instances });
    } catch (err: any) {
      res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post('/instances/bulk-action', async (req: Request, res: Response) => {
    try {
      const { action, targets } = req.body || {};
      if (!['start', 'stop', 'restart'].includes(action) || !Array.isArray(targets)) {
        return res.status(400).json({ error: 'Provide action (start|stop|restart) and targets array.' });
      }
      const parsedTargets = targets.map((t: any) =>
        typeof t === 'string'
          ? ctx.virtManager.parseInstanceUid(t)
          : { engine: t.engine as VirtualizationEngine, refId: Number(t.refId) }
      );
      const results = await ctx.instanceManager.bulkAction(
        req.principal!,
        parsedTargets,
        action
      );
      return res.json({ results });
    } catch (err: any) {
      return res.status(400).json({ error: err.message });
    }
  });

  router.get('/instances/:engine/:id', async (req: Request, res: Response) => {
    try {
      const engine = pStr(req.params.engine) as VirtualizationEngine;
      const refId = pInt(req.params.id);
      const instance = await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, refId);
      res.json({ instance });
    } catch (err: any) {
      res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.get('/tasks/:taskId', async (req: Request, res: Response) => {
    try {
      const task = await ctx.instanceManager.getAuthorizedTask(req.principal!, String(req.params.taskId || ''));
      return res.json({ task });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.get('/instances/:engine/:id/tasks', async (req: Request, res: Response) => {
    try {
      const engine = pStr(req.params.engine) as VirtualizationEngine;
      if (engine !== 'kvm' && engine !== 'lxc') return res.status(400).json({ error: 'Unsupported instance engine.' });
      const refId = pInt(req.params.id);
      const limit = req.query.limit === undefined ? 50 : Number(req.query.limit);
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        return res.status(400).json({ error: 'Task history limit must be between 1 and 100.' });
      }
      const tasks = await ctx.instanceManager.listInstanceTasks(req.principal!, engine, refId, limit);
      return res.json({ tasks });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.get('/instances/:engine/:id/telemetry', async (req: Request, res: Response) => {
    try {
      const engine = pStr(req.params.engine) as VirtualizationEngine;
      const refId = pInt(req.params.id);
      const telemetry = await ctx.instanceManager.getTelemetry(req.principal!, engine, refId);
      // Record-on-read: persist the real measured sample to metrics_history so
      // the instance metrics history endpoint returns honest data (best-effort).
      await ctx.monitoringService.recordInstanceMetrics(engine, refId, telemetry).catch(() => undefined);
      res.json({ telemetry });
    } catch (err: any) {
      res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.get('/instances/:engine/:id/metrics', async (req: Request, res: Response) => {
    try {
      const engine = pStr(req.params.engine) as VirtualizationEngine;
      const refId = pInt(req.params.id);
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, refId);
      const history = await ctx.monitoringService.getMetricsHistory(
        engine,
        refId,
        Number(req.query.hours || 24)
      );
      res.json({ history });
    } catch (err: any) {
      res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post('/instances/:engine/:id/action', async (req: Request, res: Response) => {
    try {
      const engine = pStr(req.params.engine) as VirtualizationEngine;
      const refId = pInt(req.params.id);
      const action = String(req.body?.action || '') as LifecycleAction;
      const allowed: LifecycleAction[] = [
        'start',
        'shutdown',
        'stop',
        'restart',
        'freeze',
        'unfreeze',
        'suspend',
        'unsuspend',
        'delete',
      ];
      if (!allowed.includes(action)) {
        return res.status(400).json({ error: `Invalid lifecycle action: ${action}` });
      }
      if (req.body?.async === true || req.body?.async === 'true') {
        const task = await ctx.instanceManager.startActionTask(
          req.principal!,
          engine,
          refId,
          action,
          req.body?.reason ? String(req.body.reason) : undefined,
          Boolean(req.body?.force)
        );
        return res.status(202).json({ success: true, task });
      }
      const instance = await ctx.instanceManager.executeActionTracked(
        req.principal!,
        engine,
        refId,
        action,
        req.body?.reason ? String(req.body.reason) : undefined,
        Boolean(req.body?.force)
      );
      return res.json({ success: true, instance });
    } catch (err: any) {
      const code =
        err.statusCode ||
        (/only supported for|Cannot start a suspended|is suspended and cannot be/i.test(
          String(err.message)
        )
          ? 400
          : 500);
      return res.status(code).json({ error: err.message });
    }
  });

  router.post('/instances/kvm/:id/disk/resize', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      const diskSize = String(req.body?.diskSize || '').trim();
      if (!diskSize) return res.status(400).json({ error: 'A target diskSize is required.' });
      const result = await ctx.instanceManager.resizeKvmDisk(req.principal!, refId, diskSize);
      return res.json({ success: true, ...result });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.get('/instances/kvm/:id/vnc', async (req: Request, res: Response) => {
    try {
      const vnc = await ctx.instanceManager.getKvmVncSettings(req.principal!, pInt(req.params.id));
      return res.json({ vnc });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post('/instances/kvm/:id/vnc', async (req: Request, res: Response) => {
    try {
      if (typeof req.body?.enabled !== 'boolean') return res.status(400).json({ error: 'enabled must be a boolean.' });
      const vnc = await ctx.instanceManager.setKvmVncEnabled(req.principal!, pInt(req.params.id), req.body.enabled);
      return res.json({ success: true, vnc, note: 'VNC configuration applies on the next VM start and is bound to loopback only.' });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post(
    '/instances/:engine/:id/service-lock',
    requireRole(['admin', 'subadmin', 'operator']),
    async (req: Request, res: Response) => {
      try {
        const engine = pStr(req.params.engine) as VirtualizationEngine;
        if (engine !== 'kvm' && engine !== 'lxc') return res.status(400).json({ error: 'Unsupported instance engine.' });
        if (typeof req.body?.locked !== 'boolean') return res.status(400).json({ error: 'locked must be a boolean.' });
        const instance = await ctx.instanceManager.setInstanceServiceLock(
          req.principal!, engine, pInt(req.params.id), req.body.locked, String(req.body?.reason || '')
        );
        return res.json({
          success: true,
          instance,
          note: req.body.locked
            ? 'Administrative service lock is active. It does not stop an already-running VPS, but blocks start/restart until staff unlocks it.'
            : 'Administrative service lock cleared.',
        });
      } catch (err: any) {
        return res.status(err.statusCode || 500).json({ error: err.message });
      }
    }
  );

  router.post('/instances/kvm/:id/clone', async (req: Request, res: Response) => {
    try {
      if (req.body?.acknowledgeGuestIdentityRisk !== true) {
        return res.status(400).json({ error: 'Confirm that the cloned guest disk initially contains the same OS identity, SSH host keys, and installed secrets as the source.' });
      }
      const clone = await ctx.instanceManager.cloneKvmInstance(
        req.principal!, pInt(req.params.id), String(req.body?.name || '')
      );
      return res.status(201).json({
        success: true,
        clone,
        warning: 'Only the primary disk is cloned. The VM is stopped and receives a new MAC and NAT SSH forwarding port, but its guest disk retains machine-id, SSH host keys, and secrets; regenerate them and verify guest networking before external use.'
      });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post('/instances/lxc/:id/clone', async (req: Request, res: Response) => {
    try {
      if (req.body?.acknowledgeGuestIdentityRisk !== true) {
        return res.status(400).json({ error: 'Confirm the copy contains the same guest machine identity, SSH keys, passwords and installed secrets as the source, and that its guest network configuration must be reviewed.' });
      }
      const clone = await ctx.instanceManager.cloneLxcInstance(
        req.principal!, pInt(req.params.id), String(req.body?.name || '')
      );
      return res.status(201).json({
        success: true,
        clone,
        warning: 'The copied LXC remains stopped with its host network detached to prevent duplicate IP/MAC use. Review guest identity, keys, secrets and in-guest static network settings before attaching a bridge and starting it. Directory-backed local or remote LXC only; lxc-copy must be installed on the target node.'
      });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post('/instances/kvm/:id/rescue', async (req: Request, res: Response) => {
    try {
      if (typeof req.body?.enabled !== 'boolean') return res.status(400).json({ error: 'enabled must be a boolean.' });
      const refId = pInt(req.params.id);
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, 'kvm', refId, true);
      const vm = await ctx.db.get<any>(`SELECT status FROM vms WHERE vm_id = ?`, [refId]);
      if (!vm) return res.status(404).json({ error: 'KVM VM not found.' });
      if (String(vm.status || '').toLowerCase() !== 'stopped') {
        return res.status(409).json({ error: 'Rescue ISO changes require a stopped VM.' });
      }
      let isoPath: string | null = null;
      let selectedIsoFilename: string | null = null;
      if (req.body.enabled) {
        const isoFilename = String(req.body.isoFilename || '').trim();
        selectedIsoFilename = isoFilename;
        if (!isoFilename || path.basename(isoFilename) !== isoFilename || !/\.iso$/i.test(isoFilename)) {
          return res.status(400).json({ error: 'Provide a rescue ISO filename (not a path) ending in .iso.' });
        }
        const isoRoot = path.resolve(os.homedir(), 'vms', 'iso');
        try {
          const realRoot = fs.realpathSync(isoRoot);
          isoPath = fs.realpathSync(path.join(realRoot, isoFilename));
          if (!isoPath.startsWith(realRoot + path.sep) || !fs.statSync(isoPath).isFile()) throw new Error('Invalid ISO file.');
        } catch {
          return res.status(400).json({ error: 'Rescue ISO was not found as a regular file inside the managed ISO directory.' });
        }
      }
      const outcome = await ctx.instanceManager.tasks.runSync({
        engine: 'kvm', instanceRefId: refId, actorId: req.principal!.userId,
        action: req.body.enabled ? 'rescue_iso_enable' : 'rescue_iso_disable',
        worker: async (reportProgress) => {
          await reportProgress(null, req.body.enabled ? 'Setting the operator-supplied rescue ISO as next boot media' : 'Restoring disk-first boot and detaching the rescue ISO');
          if (req.body.enabled) {
            await ctx.db.run(`UPDATE vms SET iso_attached = ?, boot_from_iso = 1 WHERE vm_id = ?`, [selectedIsoFilename, refId]);
          } else {
            await ctx.db.run(`UPDATE vms SET iso_attached = NULL, boot_from_iso = 0 WHERE vm_id = ?`, [refId]);
          }
          return { enabled: req.body.enabled, isoFilename: req.body.enabled ? selectedIsoFilename : null };
        },
      });
      return res.json({
        success: true,
        rescue: outcome.result,
        note: req.body.enabled
          ? 'Rescue media is configured for the next VM start. Start the stopped VM and open its serial/VNC console; after recovery, stop it and disable rescue to restore disk-first boot.'
          : 'Rescue media detached; the next VM start boots from the disk.',
      });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.get('/instances/kvm/:id/devices', async (req: Request, res: Response) => {
    try {
      const devices = await ctx.instanceManager.listKvmDevices(req.principal!, pInt(req.params.id));
      return res.json({ devices });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post('/instances/kvm/:id/devices/disks', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      const size = String(req.body?.size || '').trim();
      if (!size) return res.status(400).json({ error: 'A disk size is required.' });
      const disk = await ctx.instanceManager.attachKvmDisk(req.principal!, refId, size);
      return res.status(201).json({ success: true, disk, note: 'The disk is created and attached while the VM is stopped.' });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post('/instances/kvm/:id/devices/disks/:deviceId/attach', async (req: Request, res: Response) => {
    try {
      const disk = await ctx.instanceManager.reattachKvmDisk(req.principal!, pInt(req.params.id), String(req.params.deviceId || ''));
      return res.json({ success: true, disk });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.delete('/instances/kvm/:id/devices/disks/:deviceId', async (req: Request, res: Response) => {
    try {
      const disk = await ctx.instanceManager.detachKvmDisk(req.principal!, pInt(req.params.id), String(req.params.deviceId || ''));
      return res.json({ success: true, disk, note: 'Disk image preserved; only the device attachment was removed.' });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post('/instances/kvm/:id/devices/nics', async (req: Request, res: Response) => {
    try {
      const nic = await ctx.instanceManager.attachKvmNatNic(req.principal!, pInt(req.params.id));
      return res.status(201).json({ success: true, nic, note: 'User-mode NAT only; no host bridge is exposed.' });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.delete('/instances/kvm/:id/devices/nics/:deviceId', async (req: Request, res: Response) => {
    try {
      const nic = await ctx.instanceManager.detachKvmNic(req.principal!, pInt(req.params.id), String(req.params.deviceId || ''));
      return res.json({ success: true, nic });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  // --- LXC VPS Lifecycle, Configuration & File Management ---
  router.get('/lxc', async (req: Request, res: Response) => {
    const containers = await ctx.instanceManager.listAccessibleInstances(req.principal!, {
      engine: 'lxc',
    });
    res.json({ containers });
  });

  router.get('/lxc/templates', async (req: Request, res: Response) => {
    const includeDisabled =
      req.query.all === '1' && ctx.instanceManager.isStaff(req.principal!);
    const templates = await ctx.storageManager.listLxcTemplates(includeDisabled);
    res.json({ templates });
  });

  router.post(
    '/lxc/templates',
    requireRole(['admin', 'subadmin']),
    templateUploader.single('archive'),
    async (req: Request, res: Response) => {
      try {
        let checksum: string | null = null;
        const uploadedFile = (req as any).file;
        if (uploadedFile?.path) {
          checksum = await ctx.nodeManager.localRuntime.snapshotManager.computeFileSha256(
            uploadedFile.path
          );
        }
        const tpl = await ctx.storageManager.upsertLxcTemplate({
          slug: String(req.body?.slug || ''),
          name: String(req.body?.name || ''),
          distro: String(req.body?.distro || 'ubuntu'),
          release: String(req.body?.release || '24.04'),
          arch: String(req.body?.arch || 'amd64'),
          variant: String(req.body?.variant || 'default'),
          family: String(req.body?.family || 'debian'),
          category: req.body?.category ? String(req.body.category) : undefined,
          icon: req.body?.icon ? String(req.body.icon) : undefined,
          proxmoxCodename: req.body?.proxmoxCodename ? String(req.body.proxmoxCodename) : undefined,
          minDiskGb: Number(req.body?.minDiskGb || 5),
          minRamMb: Number(req.body?.minRamMb || 256),
          isCustom: Boolean(uploadedFile || req.body?.isCustom),
          filePath: uploadedFile?.path || null,
          checksumSha256: checksum,
          enabled: req.body?.enabled !== 'false' && req.body?.enabled !== false,
        });
        res.status(201).json({ template: tpl });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.patch(
    '/lxc/templates/:id',
    requireRole(['admin', 'subadmin']),
    async (req: Request, res: Response) => {
      await ctx.storageManager.toggleLxcTemplate(
        pInt(req.params.id),
        Boolean(req.body?.enabled)
      );
      res.json({ success: true });
    }
  );

  router.delete(
    '/lxc/templates/:id',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      await ctx.storageManager.deleteLxcTemplate(pInt(req.params.id));
      res.json({ success: true });
    }
  );

  router.post(
    '/lxc/sync-host',
    requireRole(['admin', 'subadmin', 'operator']),
    async (req: Request, res: Response) => {
      try {
        const targetNodeId =
          req.body?.nodeId !== undefined && req.body?.nodeId !== ''
            ? Number(req.body.nodeId)
            : undefined;
        const result = await ctx.lxcAdapter.syncHostContainers(
          req.principal!.userId,
          targetNodeId
        );
        res.json({ success: true, ...result });
      } catch (err: any) {
        res.status(500).json({ error: err.message });
      }
    }
  );

  router.post(
    '/lxc',
    requireRole(['admin', 'subadmin', 'operator']),
    async (req: Request, res: Response) => {
      req.setTimeout(660_000);
      res.setTimeout(660_000);
      try {
        const b = req.body || {};
        const created = await ctx.lxcAdapter.createLxcInstance({
          userId: Number(b.userId || req.principal!.userId),
          nodeId: b.nodeId ? Number(b.nodeId) : undefined,
          containerName: String(b.containerName || ''),
          hostname: b.hostname ? String(b.hostname) : undefined,
          templateSlug: b.templateSlug ? String(b.templateSlug) : 'ubuntu-24.04',
          cpuCores: Number(b.cpuCores || 1),
          cpuShares: Number(b.cpuShares || 1024),
          cpuLimitPercent: Number(b.cpuLimitPercent || 100),
          cpuPinning: b.cpuPinning ? String(b.cpuPinning) : null,
          ramMb: Number(b.ramMb || 1024),
          swapMb: Number(b.swapMb ?? 512),
          diskGb: Number(b.diskGb || 20),
          backingStore: b.backingStore || 'dir',
          privileged: b.privileged !== false,
          nesting: b.nesting !== false,
          kvmNesting: Boolean(b.kvmNesting),
          bridge: b.bridge ? String(b.bridge) : 'lxcbr0',
          ipv4Address: b.ipv4Address ? String(b.ipv4Address) : null,
          ipv4Gateway: b.ipv4Gateway ? String(b.ipv4Gateway) : null,
          ipv6Address: b.ipv6Address ? String(b.ipv6Address) : null,
          vlanId: b.vlanId ? Number(b.vlanId) : null,
          rootPassword: b.rootPassword ? String(b.rootPassword) : undefined,
          sshPublicKeys: Array.isArray(b.sshPublicKeys) ? b.sshPublicKeys : [],
          autostart: Boolean(b.autostart),
          bandwidthQuotaGb: Number(b.bandwidthQuotaGb || 0),
          expirationDays: Number(b.expirationDays || 0),
          autoSuspendEnabled: b.autoSuspendEnabled !== false,
          notes: b.notes ? String(b.notes) : undefined,
          provisionOnHost: b.provisionOnHost !== false,
        });

        await ctx.db
          .logActivity({
            userId: req.principal!.userId,
            action: 'lxc_created',
            resourceType: 'lxc',
            resourceId: String(created.instance.refId),
            details: {
              containerName: created.instance.name,
              nodeId: created.instance.nodeId,
              template: created.instance.osLabel,
            },
          })
          .catch(() => undefined);

        res.status(201).json(created);
      } catch (err: any) {
        const msg = String(err?.message || 'Failed to create LXC container');
        const status = /currently being provisioned|already exists/i.test(msg) ? 409 : 500;
        res.status(status).json({ error: msg });
      }
    }
  );

  router.patch(
    '/lxc/:id',
    requireRole(['admin', 'subadmin', 'operator']),
    async (req: Request, res: Response) => {
      try {
        const refId = pInt(req.params.id);
        const updated = await runTrackedInstanceMutation(
          ctx,
          req.principal!,
          'lxc',
          refId,
          'resize_config',
          () => ctx.lxcAdapter.resizeAndUpdateConfig(
            refId,
            req.body || {},
            req.body?.applyToHost !== false
          ),
          true
        );
        res.json({ success: true, instance: updated });
      } catch (err: any) {
        res.status(500).json({ error: err.message });
      }
    }
  );

  router.post('/lxc/:id/reinstall', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      const out = await runTrackedInstanceMutation(
        ctx,
        req.principal!,
        'lxc',
        refId,
        'reinstall',
        () => ctx.lxcAdapter.reinstallLxcInstance(
          refId,
          String(req.body?.templateSlug || 'ubuntu-24.04'),
          req.body?.rootPassword ? String(req.body.rootPassword) : undefined
        ),
        true
      );
      res.json(out);
    } catch (err: any) {
      res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post('/lxc/:id/cloudflare-tunnel', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      const status = await runTrackedInstanceMutation(
        ctx,
        req.principal!,
        'lxc',
        refId,
        'cloudflare_tunnel_start',
        () => ctx.lxcAdapter.startProxmoxCloudflareTunnel(refId),
        true
      );
      return res.status(202).json({ success: true, ...status });
    } catch (err: any) {
      return res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.get('/lxc/:id/cloudflare-tunnel', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, 'lxc', refId);
      const status = await ctx.lxcAdapter.getProxmoxCloudflareTunnelStatus(refId);
      return res.json(status);
    } catch (err: any) {
      return res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.post('/lxc/:id/repair-network', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      const out = await runTrackedInstanceMutation(
        ctx,
        req.principal!,
        'lxc',
        refId,
        'repair_network',
        () => ctx.lxcAdapter.repairLxcNetworking(refId),
        true
      );
      await ctx.db
        .logActivity({
          userId: req.principal!.userId,
          action: 'lxc_network_repaired',
          resourceType: 'lxc',
          resourceId: String(refId),
          details: out.repair as unknown as Record<string, unknown>,
        })
        .catch(() => undefined);
      res.json({ success: true, ...out });
    } catch (err: any) {
      res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post('/lxc/:id/password', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      const newPassword = await runTrackedInstanceMutation(
        ctx,
        req.principal!,
        'lxc',
        refId,
        'reset_password',
        () => ctx.lxcAdapter.resetRootPassword(
          refId,
          req.body?.password ? String(req.body.password) : undefined
        ),
        true
      );
      res.json({ success: true, rootPassword: newPassword });
    } catch (err: any) {
      res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post('/lxc/:id/ssh-key', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      await runTrackedInstanceMutation(
        ctx,
        req.principal!,
        'lxc',
        refId,
        'inject_ssh_key',
        () => ctx.lxcAdapter.injectSshKey(refId, String(req.body?.publicKey || ''))
      );
      res.json({ success: true });
    } catch (err: any) {
      res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.post(
    '/lxc/:id/renew',
    requireRole(['admin', 'subadmin']),
    async (req: Request, res: Response) => {
      try {
        const refId = pInt(req.params.id);
        const updated = await runTrackedInstanceMutation(
          ctx,
          req.principal!,
          'lxc',
          refId,
          'renew_expiration',
          () => ctx.lxcAdapter.renewExpiration(refId, Number(req.body?.days || 30)),
          true
        );
        res.json({ success: true, instance: updated });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.post(
    '/lxc/:id/transfer-owner',
    requireRole(['admin', 'subadmin']),
    async (req: Request, res: Response) => {
      try {
        const refId = pInt(req.params.id);
        const updated = await runTrackedInstanceMutation(
          ctx,
          req.principal!,
          'lxc',
          refId,
          'transfer_owner',
          () => ctx.lxcAdapter.transferOwnership(refId, Number(req.body?.userId)),
          true
        );
        res.json({ success: true, instance: updated });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.put('/lxc/:id/sharing', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      const userIds = Array.isArray(req.body?.userIds) ? req.body.userIds.map(Number) : [];
      const updated = await runTrackedInstanceMutation(
        ctx,
        req.principal!,
        'lxc',
        refId,
        'update_sharing',
        () => ctx.lxcAdapter.updateSharing(refId, userIds),
        true
      );
      res.json({ success: true, instance: updated });
    } catch (err: any) {
      res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.get('/lxc/:id/processes', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, 'lxc', refId);
      const processes = await ctx.lxcAdapter.getProcesses(refId);
      res.json({ processes });
    } catch (err: any) {
      res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.get('/lxc/:id/logs', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, 'lxc', refId);
      const logs = await ctx.lxcAdapter.getLogs(refId);
      res.json({ logs });
    } catch (err: any) {
      res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.get('/lxc/:id/files', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, 'lxc', refId);
      const subPath = String(req.query.path || '/');
      const entries = await ctx.lxcAdapter.listFiles(refId, subPath);
      res.json({ path: subPath, entries });
    } catch (err: any) {
      res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.get('/lxc/:id/files/content', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, 'lxc', refId);
      const subPath = String(req.query.path || '/');
      const buf = await ctx.lxcAdapter.readFile(refId, subPath);
      res.json({
        path: subPath,
        content: buf.toString('utf8'),
        contentBase64: buf.toString('base64'),
      });
    } catch (err: any) {
      res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.post('/lxc/:id/files/content', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      const subPath = String(req.body?.path || '');
      const buf =
        typeof req.body?.contentBase64 === 'string'
          ? Buffer.from(req.body.contentBase64, 'base64')
          : Buffer.from(String(req.body?.content ?? ''), 'utf8');
      await runTrackedInstanceMutation(
        ctx,
        req.principal!,
        'lxc',
        refId,
        'write_file',
        () => ctx.lxcAdapter.writeFile(refId, subPath, buf)
      );
      res.json({ success: true });
    } catch (err: any) {
      res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.delete('/lxc/:id/files', async (req: Request, res: Response) => {
    try {
      const refId = pInt(req.params.id);
      await runTrackedInstanceMutation(
        ctx,
        req.principal!,
        'lxc',
        refId,
        'delete_file',
        () => ctx.lxcAdapter.deleteFile(refId, String(req.query.path || ''))
      );
      res.json({ success: true });
    } catch (err: any) {
      res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  // --- Nodes Management (Admin / Staff) ---
  router.get(
    '/nodes',
    requireRole(['admin', 'subadmin', 'operator']),
    async (_req: Request, res: Response) => {
      const nodes = await ctx.nodeManager.listNodes();
      res.json({ nodes });
    }
  );

  router.post(
    '/nodes/test-connection',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const result = await ctx.nodeManager.probeEndpointConnection({
          url: String(req.body?.url || ''),
          verifySsl: req.body?.verifySsl !== false,
          timeoutMs: Number(req.body?.timeoutMs || 4000),
        });
        res.json(result);
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.get(
    '/nodes/placement',
    requireRole(['admin', 'subadmin', 'operator']),
    async (_req: Request, res: Response) => {
      const [kvm, lxc] = await Promise.all([
        ctx.nodeManager.rankPlacementCandidates('kvm'),
        ctx.nodeManager.rankPlacementCandidates('lxc'),
      ]);
      res.json({ kvm, lxc });
    }
  );

  router.post('/nodes', requireRole(['admin']), async (req: Request, res: Response) => {
    try {
      const out = await ctx.nodeManager.createNode(req.body || {});
      await ctx.db.logActivity({
        userId: req.principal!.userId,
        action: 'node_created',
        resourceType: 'node',
        resourceId: String(out.node.id),
        details: { name: out.node.name, url: out.node.url },
      });
      res.status(201).json(out);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  router.get(
    '/nodes/:id/detail',
    requireRole(['admin', 'subadmin', 'operator']),
    async (req: Request, res: Response) => {
      try {
        const nodeId = pInt(req.params.id);
        let node = await ctx.nodeManager.getNodeById(nodeId);
        if (!node) return res.status(404).json({ error: 'Node not found.' });

        let liveHealth: any = null;
        let liveStats: any = null;
        let latencyMs: number | null = node.latency_ms ?? null;
        if (req.query.live !== '0') {
          try {
            const probe = await ctx.nodeManager.checkNodeHealthAndStats(nodeId);
            node = probe.node;
            liveHealth = probe.health;
            liveStats = probe.stats;
            latencyMs = probe.latencyMs;
          } catch {
            node = (await ctx.nodeManager.getNodeById(nodeId)) || node;
          }
        }

        const [kvmRows, lxcRows, storagePools, recentMigrations] = await Promise.all([
          ctx.db
            .all<any>(
              `SELECT vm_id AS id, vm_name AS name, os_type, status,
                      COALESCE(cpus, cpu_cores, 1) AS cpu_cores,
                      COALESCE(memory, 0) AS ram_mb,
                      CAST(REPLACE(REPLACE(COALESCE(disk_size, '0'), 'G', ''), 'g', '') AS REAL) AS disk_gb,
                      ipv4_address AS ip_address
               FROM vms WHERE COALESCE(node_id, 1) = ? ORDER BY vm_id DESC`,
              [nodeId]
            )
            .catch(() => []),
          ctx.db
            .all<any>(
              `SELECT id, container_name AS name, hostname, os_template, distro, release, status,
                      COALESCE(cpu_cores, 1) AS cpu_cores,
                      COALESCE(ram_mb, 0) AS ram_mb,
                      COALESCE(disk_gb, 0) AS disk_gb,
                      ipv4_address AS ip_address
               FROM lxc_instances WHERE COALESCE(node_id, 1) = ? ORDER BY id DESC`,
              [nodeId]
            )
            .catch(() => []),
          ctx.db
            .all<any>(`SELECT * FROM storage_pools WHERE node_id = ? ORDER BY id ASC`, [nodeId])
            .catch(() => []),
          ctx.db
            .all<any>(
              `SELECT m.*, sn.name AS source_node_name, tn.name AS target_node_name
               FROM vps_migrations m
               LEFT JOIN nodes sn ON sn.id = m.source_node_id
               LEFT JOIN nodes tn ON tn.id = m.target_node_id
               WHERE m.source_node_id = ? OR m.target_node_id = ?
               ORDER BY m.id DESC LIMIT 10`,
              [nodeId, nodeId]
            )
            .catch(() => []),
        ]);

        const instances = [
          ...kvmRows.map((v: any) => ({
            id: v.id,
            engine: 'kvm',
            name: v.name,
            osLabel: v.os_type || 'KVM Guest',
            status: v.status || 'stopped',
            cpuCores: Number(v.cpu_cores || 1),
            ramMb: Number(v.ram_mb || 0),
            diskGb: Number(v.disk_gb || 0),
            ipAddress: v.ip_address || null,
            manageUrl: `/admin/vm/${v.id}`,
          })),
          ...lxcRows.map((c: any) => ({
            id: c.id,
            engine: 'lxc',
            name: c.name,
            osLabel: c.os_template || `${c.distro || 'linux'}:${c.release || ''}`,
            status: c.status || 'stopped',
            cpuCores: Number(c.cpu_cores || 1),
            ramMb: Number(c.ram_mb || 0),
            diskGb: Number(c.disk_gb || 0),
            ipAddress: c.ip_address || null,
            manageUrl: `/lxc/${c.id}`,
          })),
        ];

        const parseJsonArr = (raw: any): string[] => {
          if (!raw) return [];
          try {
            const p = JSON.parse(String(raw));
            return Array.isArray(p) ? p.map(String) : [];
          } catch {
            return [];
          }
        };

        return res.json({
          node: {
            ...node,
            parsedTags: parseJsonArr(node.tags),
            parsedStorageBackends: parseJsonArr(node.storage_backends),
            parsedNetworkBackends: parseJsonArr(node.network_backends),
          },
          latencyMs,
          liveHealth,
          liveStats,
          instances,
          storagePools,
          recentMigrations,
        });
      } catch (err: any) {
        return res.status(500).json({ error: err.message });
      }
    }
  );

  router.patch('/nodes/:id', requireRole(['admin']), async (req: Request, res: Response) => {
    try {
      const nodeId = pInt(req.params.id);
      const updated = await ctx.nodeManager.updateNode(nodeId, req.body || {});
      await ctx.db.logActivity({
        userId: req.principal!.userId,
        action: 'node_updated',
        resourceType: 'node',
        resourceId: String(nodeId),
        details: {
          name: updated.name,
          maintenanceMode: Boolean(updated.maintenance_mode),
          maxInstances: updated.max_instances,
        },
      });
      res.json({ node: updated });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  router.post(
    '/nodes/:id/reset-circuit',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const nodeId = pInt(req.params.id);
        let node = await ctx.nodeManager.resetCircuitBreaker(nodeId);
        let probeOk = false;
        if (req.body?.probe !== false) {
          try {
            const checked = await ctx.nodeManager.checkNodeHealthAndStats(nodeId, {
              bypassCircuit: true,
            });
            node = checked.node;
            probeOk = true;
          } catch {
            node = (await ctx.nodeManager.getNodeById(nodeId)) || node;
          }
        }
        res.json({ node, probeOk });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.get(
    '/nodes/:id/bootstrap',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const nodeId = pInt(req.params.id);
        const defaultOrigin = `${req.protocol}://${req.get('host') || 'localhost:8080'}`;
        const controllerUrl = req.query.controllerUrl
          ? pStr(req.query.controllerUrl as any)
          : defaultOrigin;
        const out = await ctx.nodeManager.getBootstrapCredentials(nodeId, controllerUrl);
        await ctx.db.logActivity({
          userId: req.principal!.userId,
          action: 'node_bootstrap_viewed',
          resourceType: 'node',
          resourceId: String(nodeId),
        });
        res.json(out);
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.post(
    '/nodes/:id/join-token',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const nodeId = pInt(req.params.id);
        const defaultOrigin = `${req.protocol}://${req.get('host') || 'localhost:8080'}`;
        const controllerUrl = String(req.body?.controllerUrl || defaultOrigin).trim();
        const ttlMinutes = req.body?.ttlMinutes ? Number(req.body.ttlMinutes) : 30;
        const out = await ctx.nodeManager.createJoinToken({
          nodeId,
          controllerUrl,
          createdByUserId: req.principal!.userId,
          ttlMinutes,
        });
        await ctx.db.logActivity({
          userId: req.principal!.userId,
          action: 'node_join_token_created',
          resourceType: 'node',
          resourceId: String(nodeId),
          details: { expiresAt: out.expiresAt, controllerUrl: out.controllerUrl },
        });
        res.status(201).json(out);
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.post(
    '/nodes/:id/trust-tls',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const nodeId = pInt(req.params.id);
        const out = await ctx.nodeManager.trustNodeTlsCertificate(nodeId);
        await ctx.db.logActivity({
          userId: req.principal!.userId,
          action: 'node_tls_trusted',
          resourceType: 'node',
          resourceId: String(nodeId),
          details: {
            fingerprintSha256: out.fingerprintSha256,
            subjectCN: out.subjectCN,
            probeOk: out.probeOk,
          },
        });
        res.json(out);
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.post(
    '/nodes/:id/evacuate-lxc',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const sourceNodeId = pInt(req.params.id);
        const targetNodeId = Number(req.body?.targetNodeId || 0);
        const targetBridge = String(req.body?.targetBridge || 'lxcbr0').trim() || 'lxcbr0';
        const cordonSource = req.body?.cordonSource !== false;

        if (!targetNodeId || targetNodeId === sourceNodeId) {
          return res.status(400).json({ error: 'Select a valid distinct target node for evacuation.' });
        }

        if (cordonSource) {
          await ctx.nodeManager.updateNode(sourceNodeId, { maintenanceMode: true });
        }

        const requestedIds: number[] | null = Array.isArray(req.body?.lxcIds)
          ? req.body.lxcIds.map((x: any) => Number(x)).filter((x: number) => x > 0)
          : null;

        const lxcOnSource = await ctx.db.all<{ id: number; container_name: string }>(
          `SELECT id, container_name FROM lxc_instances WHERE COALESCE(node_id, 1) = ? ORDER BY id ASC`,
          [sourceNodeId]
        );
        const targets = requestedIds
          ? lxcOnSource.filter((c) => requestedIds.includes(c.id))
          : lxcOnSource;

        const results: Array<{ lxcId: number; name: string; ok: boolean; jobId?: number; error?: string }> = [];
        for (const ct of targets) {
          try {
            const job = await ctx.migrationManager.startOfflineLxcMigration({
              lxcId: ct.id,
              targetNodeId,
              targetBridge,
              initiatedByUserId: req.principal!.userId,
            });
            results.push({ lxcId: ct.id, name: ct.container_name, ok: job.status === 'completed', jobId: job.id });
          } catch (err: any) {
            results.push({ lxcId: ct.id, name: ct.container_name, ok: false, error: err.message });
          }
        }

        await ctx.db.logActivity({
          userId: req.principal!.userId,
          action: 'node_evacuate_lxc',
          resourceType: 'node',
          resourceId: String(sourceNodeId),
          details: {
            targetNodeId,
            attempted: targets.length,
            succeeded: results.filter((r) => r.ok).length,
          },
        });

        return res.json({
          sourceNodeId,
          targetNodeId,
          cordonApplied: cordonSource,
          attempted: targets.length,
          succeeded: results.filter((r) => r.ok).length,
          failed: results.filter((r) => !r.ok).length,
          results,
        });
      } catch (err: any) {
        return res.status(400).json({ error: err.message });
      }
    }
  );

  router.delete('/nodes/:id', requireRole(['admin']), async (req: Request, res: Response) => {
    try {
      await ctx.nodeManager.deleteNode(pInt(req.params.id));
      res.json({ success: true });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  router.post(
    '/nodes/:id/check',
    requireRole(['admin', 'subadmin', 'operator']),
    async (req: Request, res: Response) => {
      try {
        const nodeId = pInt(req.params.id);
        const report = await ctx.nodeManager.checkNodeHealthAndStats(nodeId, {
          bypassCircuit: true,
        });
        if (report?.stats) {
          const s = report.stats;
          await ctx.db
            .run(
              `INSERT INTO metrics_history
                 (target_type, target_id, cpu_percent, ram_used_mb, ram_total_mb, disk_used_gb, disk_total_gb, net_rx_bytes, net_tx_bytes, load_avg_1)
               VALUES ('node', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              [
                nodeId,
                s.cpuPercent,
                s.ramUsedMb,
                s.ramTotalMb,
                s.diskUsedGb,
                s.diskTotalGb,
                s.netRxBytes,
                s.netTxBytes,
                s.loadAvg1,
              ]
            )
            .catch(() => undefined);
        }
        res.json(report);
      } catch (err: any) {
        res.status(502).json({ error: err.message });
      }
    }
  );

  router.post(
    '/nodes/:id/rotate-credentials',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const rotated = await ctx.nodeManager.rotateNodeCredentials(
          pInt(req.params.id)
        );
        res.json(rotated);
      } catch (err: any) {
        res.status(500).json({ error: err.message });
      }
    }
  );

  router.post(
    '/nodes/:id/diagnostics/:preset',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const nodeId = pInt(req.params.id);
        const node = await ctx.nodeManager.getNodeById(nodeId);
        if (!node) return res.status(404).json({ error: 'Node not found.' });

        const out = node.is_local
          ? await ctx.nodeManager.localRuntime.shellManager.runDiagnosticPreset(
              pStr(req.params.preset),
              req.principal!.username
            )
          : await ctx.nodeManager.requestRemoteNode(
              nodeId,
              'POST',
              `/api/v1/diagnostics/${encodeURIComponent(pStr(req.params.preset))}`
            );
        return res.json(out);
      } catch (err: any) {
        return res.status(400).json({ error: err.message });
      }
    }
  );

  router.get(
    '/nodes/:id/metrics',
    requireRole(['admin', 'subadmin', 'operator']),
    async (req: Request, res: Response) => {
      const history = await ctx.monitoringService.getMetricsHistory(
        'node',
        pInt(req.params.id),
        Number(req.query.hours || 24)
      );
      res.json({ history });
    }
  );

  // --- Storage Pools ---
  router.get(
    '/storage/pools',
    requireRole(['admin', 'subadmin', 'operator']),
    async (req: Request, res: Response) => {
      const pools =
        req.query.sync === '1'
          ? await ctx.storageManager.syncPoolCapacities()
          : await ctx.storageManager.listPools();
      res.json({ pools });
    }
  );

  router.post(
    '/storage/pools',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const pool = await ctx.storageManager.createPool(req.body || {});
        res.status(201).json({ pool });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.delete(
    '/storage/pools/:id',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        await ctx.storageManager.deletePool(pInt(req.params.id));
        res.json({ success: true });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  // --- Storage Orphan Image Detection (report-only; never deletes) ---
  router.get(
    '/storage/orphans',
    requireRole(['admin', 'subadmin', 'operator']),
    async (_req: Request, res: Response) => {
      try {
        const orphans = await ctx.storageManager.listOrphanImages();
        res.json({ orphans });
      } catch (err: any) {
        res.status(500).json({ error: err.message });
      }
    }
  );

  // --- ISO Library Inventory (honest size + SHA-256 checksum) ---
  router.get(
    '/iso/inventory',
    requireRole(['admin', 'subadmin', 'operator']),
    async (_req: Request, res: Response) => {
      try {
        const isoFiles = await ctx.storageManager.listIsoFiles();
        res.json({ isoFiles });
      } catch (err: any) {
        res.status(500).json({ error: err.message });
      }
    }
  );

  // --- Networking, Port Forwarding & Firewall ---
  router.get(
    '/network/pools',
    requireRole(['admin', 'subadmin', 'operator']),
    async (_req: Request, res: Response) => {
      const pools = await ctx.networkManager.listNetworkPools();
      const ips = await ctx.networkManager.listIpAllocations();
      res.json({ pools, ips });
    }
  );

  router.post(
    '/network/pools',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const pool = await ctx.networkManager.createNetworkPool(req.body || {});
        res.status(201).json({ pool });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.post(
    '/network/pools/:id/ips',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const rawList: string[] = Array.isArray(req.body?.ips)
          ? req.body.ips
          : String(req.body?.ips || '')
              .split(/[\s,]+/)
              .filter(Boolean);
        const added = await ctx.networkManager.addIpAddressesToPool(
          pInt(req.params.id),
          rawList.map((ip) => ({ ip }))
        );
        res.json({ success: true, added });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.get('/network/ports', async (req: Request, res: Response) => {
    const isStaff = ctx.instanceManager.isStaff(req.principal!);
    const forwards = await ctx.networkManager.listPortForwards({
      userId: isStaff && req.query.all === '1' ? undefined : req.principal!.userId,
    });
    const quota = await ctx.networkManager.getUserPortAllocation(req.principal!.userId);
    res.json({ forwards, quota });
  });

  router.post('/network/ports', async (req: Request, res: Response) => {
    try {
      const b = req.body || {};
      const engine = (b.instanceType === 'kvm' ? 'kvm' : 'lxc') as VirtualizationEngine;
      const refId = Number(b.instanceRefId);
      const inst = await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, refId);
      if (!inst.primaryIp) {
        return res
          .status(400)
          .json({ error: 'Instance does not have an assigned internal IPv4 address yet.' });
      }

      const result = await ctx.networkManager.createPortForward({
        userId: inst.ownerId,
        isAdmin: ctx.instanceManager.isStaff(req.principal!),
        nodeId: inst.nodeId,
        instanceType: engine,
        instanceRefId: refId,
        containerOrVmName: inst.name,
        guestIp: inst.primaryIp.split('/')[0],
        guestPort: Number(b.guestPort),
        hostPort: b.hostPort ? Number(b.hostPort) : undefined,
        protocol: b.protocol || 'tcp,udp',
        description: b.description ? String(b.description) : '',
      });
      return res.status(201).json(result);
    } catch (err: any) {
      return res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.delete('/network/ports/:id', async (req: Request, res: Response) => {
    try {
      await ctx.networkManager.deletePortForward(
        pInt(req.params.id),
        req.principal!.userId,
        ctx.instanceManager.isStaff(req.principal!)
      );
      res.json({ success: true });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  router.put(
    '/network/port-quota/:userId',
    requireRole(['admin', 'subadmin']),
    async (req: Request, res: Response) => {
      await ctx.networkManager.setUserPortQuota(
        pInt(req.params.userId),
        Number(req.body?.allocatedPorts || 0)
      );
      res.json({ success: true });
    }
  );

  router.get(
    '/network/firewall',
    requireRole(['admin', 'subadmin', 'operator']),
    async (_req: Request, res: Response) => {
      const rules = await ctx.networkManager.listFirewallRules();
      res.json({ rules });
    }
  );

  router.post(
    '/network/firewall',
    requireRole(['admin', 'subadmin']),
    async (req: Request, res: Response) => {
      try {
        const rule = await ctx.networkManager.createFirewallRule(req.body || {});
        res.status(201).json({ rule });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.delete(
    '/network/firewall/:id',
    requireRole(['admin', 'subadmin']),
    async (req: Request, res: Response) => {
      await ctx.networkManager.deleteFirewallRule(pInt(req.params.id));
      res.json({ success: true });
    }
  );

  // --- Scheduled Snapshot Policies ---
  router.get('/snapshot-schedules', async (req: Request, res: Response) => {
    try {
      const rawEngine = req.query.engine ? String(req.query.engine) : '';
      const refId = req.query.refId ? Number(req.query.refId) : undefined;
      if (rawEngine || refId !== undefined) {
        if ((rawEngine !== 'kvm' && rawEngine !== 'lxc') || !Number.isInteger(refId) || Number(refId) < 1) {
          return res.status(400).json({ error: 'Specify a valid engine and positive refId together.' });
        }
        await ctx.instanceManager.getAuthorizedInstance(req.principal!, rawEngine, Number(refId), true);
        const schedules = await ctx.backupManager.listSnapshotSchedules({ engine: rawEngine, refId: Number(refId) });
        return res.json({ schedules });
      }
      if (!ctx.instanceManager.isStaff(req.principal!)) {
        return res.status(403).json({ error: 'Specify an owned instance or use a staff account.' });
      }
      return res.json({ schedules: await ctx.backupManager.listSnapshotSchedules() });
    } catch (err: any) {
      return res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.put('/snapshot-schedules/:engine/:id', snapshotScheduleLimiter, async (req: Request, res: Response) => {
    try {
      const engine = pStr(req.params.engine);
      const refId = pInt(req.params.id);
      if (engine !== 'kvm' && engine !== 'lxc') return res.status(400).json({ error: 'Engine must be kvm or lxc.' });
      const instance = await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, refId, true);
      const schedule = await ctx.backupManager.upsertSnapshotSchedule({
        engine,
        refId,
        frequency: String(req.body?.frequency || '') as 'hourly' | 'daily' | 'weekly',
        retentionCount: Number(req.body?.retentionCount),
        actorId: req.principal!.userId,
        ownerUserId: instance.ownerId,
      });
      return res.json({ schedule });
    } catch (err: any) {
      return res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.delete('/snapshot-schedules/:engine/:id', snapshotScheduleLimiter, async (req: Request, res: Response) => {
    try {
      const engine = pStr(req.params.engine);
      const refId = pInt(req.params.id);
      if (engine !== 'kvm' && engine !== 'lxc') return res.status(400).json({ error: 'Engine must be kvm or lxc.' });
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, refId, true);
      await ctx.backupManager.deleteSnapshotSchedule(engine, refId, req.principal!.userId);
      return res.json({ success: true });
    } catch (err: any) {
      return res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  // --- Unified Snapshots & Backups ---
  router.get('/snapshots/:engine/:id', async (req: Request, res: Response) => {
    try {
      const engine = pStr(req.params.engine) as VirtualizationEngine;
      const refId = pInt(req.params.id);
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, refId);
      const snapshots = await ctx.backupManager.listSnapshots(engine, refId);
      res.json({ snapshots });
    } catch (err: any) {
      res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.post('/snapshots/:engine/:id', async (req: Request, res: Response) => {
    try {
      const engine = pStr(req.params.engine) as VirtualizationEngine;
      const refId = pInt(req.params.id);
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, refId);
      const snapshot = await ctx.backupManager.createSnapshot({
        engine,
        refId,
        name: req.body?.name,
        description: req.body?.description,
        actorId: req.principal!.userId,
      });
      res.status(201).json({ snapshot });
    } catch (err: any) {
      res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post('/snapshots/:engine/:id/:snapId/restore', async (req: Request, res: Response) => {
    try {
      const engine = pStr(req.params.engine) as VirtualizationEngine;
      const refId = pInt(req.params.id);
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, refId);
      await ctx.backupManager.restoreSnapshot(engine, refId, pInt(req.params.snapId));
      res.json({ success: true });
    } catch (err: any) {
      res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.delete('/snapshots/:engine/:id/:snapId', async (req: Request, res: Response) => {
    try {
      const engine = pStr(req.params.engine) as VirtualizationEngine;
      const refId = pInt(req.params.id);
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, refId);
      await ctx.backupManager.deleteSnapshot(engine, refId, pInt(req.params.snapId));
      res.json({ success: true });
    } catch (err: any) {
      res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.get('/backup-schedules', async (req: Request, res: Response) => {
    try {
      const rawEngine = req.query.engine ? String(req.query.engine) : '';
      const refId = req.query.refId ? Number(req.query.refId) : undefined;
      if (rawEngine || refId !== undefined) {
        if ((rawEngine !== 'kvm' && rawEngine !== 'lxc') || !Number.isInteger(refId) || Number(refId) < 1) {
          return res.status(400).json({ error: 'Specify a valid engine and positive refId together.' });
        }
        await ctx.instanceManager.getAuthorizedInstance(req.principal!, rawEngine, Number(refId), true);
        const schedules = await ctx.backupManager.listBackupSchedules({ engine: rawEngine, refId: Number(refId) });
        return res.json({ schedules });
      }
      if (!ctx.instanceManager.isStaff(req.principal!)) {
        return res.status(403).json({ error: 'Specify an owned instance or use a staff account.' });
      }
      return res.json({ schedules: await ctx.backupManager.listBackupSchedules() });
    } catch (err: any) {
      return res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.put('/backup-schedules/:engine/:id', backupScheduleLimiter, async (req: Request, res: Response) => {
    try {
      const engine = pStr(req.params.engine);
      const refId = pInt(req.params.id);
      if (engine !== 'kvm' && engine !== 'lxc') return res.status(400).json({ error: 'Engine must be kvm or lxc.' });
      const instance = await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, refId, true);
      const schedule = await ctx.backupManager.upsertBackupSchedule({
        engine,
        refId,
        frequency: String(req.body?.frequency || '') as 'hourly' | 'daily' | 'weekly',
        retentionCount: Number(req.body?.retentionCount),
        actorId: req.principal!.userId,
        ownerUserId: instance.ownerId,
      });
      return res.json({ schedule });
    } catch (err: any) {
      return res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.delete('/backup-schedules/:engine/:id', backupScheduleLimiter, async (req: Request, res: Response) => {
    try {
      const engine = pStr(req.params.engine);
      const refId = pInt(req.params.id);
      if (engine !== 'kvm' && engine !== 'lxc') return res.status(400).json({ error: 'Engine must be kvm or lxc.' });
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, refId, true);
      await ctx.backupManager.deleteBackupSchedule(engine, refId, req.principal!.userId);
      return res.json({ success: true });
    } catch (err: any) {
      return res.status(err.statusCode || 400).json({ error: err.message });
    }
  });

  router.get('/backups', async (req: Request, res: Response) => {
    const engine = req.query.engine as VirtualizationEngine | undefined;
    const refId = req.query.refId ? Number(req.query.refId) : undefined;
    if (engine && refId) {
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, refId);
      const backups = await ctx.backupManager.listBackups({ engine, refId });
      return res.json({ backups });
    }
    if (!ctx.instanceManager.isStaff(req.principal!)) {
      return res.status(403).json({ error: 'Specify engine and refId or use staff account.' });
    }
    const backups = await ctx.backupManager.listBackups();
    return res.json({ backups });
  });

  router.post('/backups', async (req: Request, res: Response) => {
    try {
      const engine = (req.body?.engine === 'kvm' ? 'kvm' : 'lxc') as VirtualizationEngine;
      const refId = Number(req.body?.refId);
      await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, refId);
      const backup = await ctx.backupManager.createBackup({
        engine,
        refId,
        label: req.body?.label,
        actorId: req.principal!.userId,
      });
      res.status(201).json({ backup });
    } catch (err: any) {
      res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.post(
    '/backups/:id/verify',
    requireRole(['admin', 'subadmin', 'operator']),
    async (req: Request, res: Response) => {
      try {
        const out = await ctx.backupManager.verifyBackupIntegrity(
          pInt(req.params.id)
        );
        res.json(out);
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.post(
    '/backups/:id/rehearse',
    requireRole(['admin', 'subadmin', 'operator']),
    async (req: Request, res: Response) => {
      try {
        const out = await ctx.backupManager.rehearseRestore(pInt(req.params.id));
        res.json(out);
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.post(
    '/backups/:id/copy',
    requireRole(['admin', 'subadmin']),
    async (req: Request, res: Response) => {
      try {
        const backupId = pInt(req.params.id);
        const targetNodeId = pInt(req.body?.targetNodeId);
        if (!targetNodeId) {
          return res.status(400).json({ error: 'targetNodeId is required.' });
        }
        const out = await ctx.backupManager.copyBackupToNode(
          backupId,
          targetNodeId,
          req.principal!.userId
        );
        res.status(201).json({ copy: out });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.get(
    '/backups/:id/copies',
    requireRole(['admin', 'subadmin', 'operator']),
    async (req: Request, res: Response) => {
      try {
        const copies = await ctx.backupManager.listBackupCopies(pInt(req.params.id));
        res.json({ copies });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.post('/backups/:id/restore', async (req: Request, res: Response) => {
    try {
      const backupId = pInt(req.params.id);
      const bkp = await ctx.backupManager.getBackupRecord(backupId);
      if (!bkp) {
        return res.status(404).json({ error: 'Backup record not found.' });
      }
      await ctx.instanceManager.getAuthorizedInstance(
        req.principal!,
        bkp.instance_type as VirtualizationEngine,
        Number(bkp.instance_ref_id)
      );
      let copyId: number | undefined;
      if (req.body?.copyId !== undefined) {
        copyId = Number(req.body.copyId);
        if (!Number.isInteger(copyId) || copyId <= 0) {
          return res.status(400).json({ error: 'copyId must be a positive integer.' });
        }
      }
      const out = await ctx.backupManager.restoreBackup(
        backupId,
        req.principal!.userId,
        { copyId }
      );
      return res.json({ success: true, ...out });
    } catch (err: any) {
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
  });

  router.delete(
    '/backups/:id',
    requireRole(['admin', 'subadmin']),
    async (req: Request, res: Response) => {
      try {
        await ctx.backupManager.deleteBackup(pInt(req.params.id));
        res.json({ success: true });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  // --- Offline Verified VPS Migrations ---
  router.get(
    '/migrations',
    requireRole(['admin', 'subadmin', 'operator']),
    async (_req: Request, res: Response) => {
      const migrations = await ctx.migrationManager.listMigrations();
      res.json({ migrations });
    }
  );

  router.post(
    '/migrations',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const job = await ctx.migrationManager.startOfflineLxcMigration({
          lxcId: Number(req.body?.lxcId),
          targetNodeId: Number(req.body?.targetNodeId),
          targetBridge: req.body?.targetBridge,
          targetIpv4: req.body?.targetIpv4,
          targetGateway: req.body?.targetGateway,
          initiatedByUserId: req.principal!.userId,
        });
        res.status(201).json({ migration: job });
      } catch (err: any) {
        res.status(500).json({ error: err.message });
      }
    }
  );

  // --- Notifications, API Keys, Webhooks, Alerts & Audit Logs ---
  router.get('/notifications', async (req: Request, res: Response) => {
    const notifications = await ctx.monitoringService.listUserNotifications(
      req.principal!.userId,
      req.query.unread === '1'
    );
    res.json({ notifications });
  });

  router.post('/notifications/read', async (req: Request, res: Response) => {
    await ctx.monitoringService.markNotificationsRead(
      req.principal!.userId,
      req.body?.id ? Number(req.body.id) : undefined
    );
    res.json({ success: true });
  });

  // --- Reseller HMAC API, scoped keys, usage logs, and owner-isolated VPS reads ---
  router.get('/reseller/api-keys', requireRole(['reseller']), requireResellerScope('api_keys.read'), async (req: Request, res: Response) => {
    const rows = await ctx.db.all<any>(
      `SELECT * FROM reseller_api_keys WHERE user_id = ? ORDER BY id DESC`,
      [req.principal!.userId]
    );
    return res.json({ apiKeys: rows.map(safeResellerKey) });
  });

  router.post('/reseller/api-keys', resellerKeyMutationLimiter, requireRole(['reseller']), requireResellerScope('api_keys.create'), async (req: Request, res: Response) => {
    try {
      const name = String(req.body?.name || '').trim();
      const description = String(req.body?.description || '').trim();
      if (!name || name.length > 80) return res.status(400).json({ error: 'Key name is required and must be 80 characters or fewer.' });
      if (description.length > 500) return res.status(400).json({ error: 'Description must be 500 characters or fewer.' });
      const permissions = parseResellerPermissions(req.body?.permissions || ['vps.read', 'stats.read']);
      const ipAllowlist = parseResellerIpAllowlist(req.body?.ipAllowlist);
      const expiresAt = parseResellerExpiry(req.body?.expiresAt);
      const rateLimit = Number(req.body?.rateLimitPerMinute ?? 60);
      if (!Number.isInteger(rateLimit) || rateLimit < 1 || rateLimit > 6000) return res.status(400).json({ error: 'Per-key rate limit must be an integer from 1 to 6000 requests per minute.' });
      const pair = generateApiKeyPair('tgvpk');
      const apiSecret = crypto.randomBytes(32).toString('base64url');
      let created: any;
      let keyLimitReached = false;
      await ctx.db.transaction(async () => {
        const activeCount = await ctx.db.get<{ count: number }>(
          `SELECT COUNT(*) AS count FROM reseller_api_keys WHERE user_id = ? AND is_active = 1`,
          [req.principal!.userId]
        );
        if (Number(activeCount?.count || 0) >= 20) {
          keyLimitReached = true;
          return;
        }
        created = await ctx.db.run(
          `INSERT INTO reseller_api_keys
             (user_id, name, description, key_prefix, key_hash, secret_hash, secret_enc,
              permissions, ip_allowlist, rate_limit_per_minute, expires_at, is_active)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
          [req.principal!.userId, name, description || null, pair.keyPrefix, pair.keyHash,
            hashApiKey(apiSecret), encryptSecret(apiSecret), JSON.stringify(permissions),
            JSON.stringify(ipAllowlist), rateLimit, expiresAt]
        );
      });
      if (keyLimitReached) return res.status(409).json({ error: 'A reseller may have at most 20 active API keys.' });
      await ctx.db.logActivity({
        userId: req.principal!.userId,
        action: 'reseller_api_key_created',
        resourceType: 'reseller_api_key',
        resourceId: String(created.lastID),
        details: { name, permissions, rateLimitPerMinute: rateLimit },
        ipAddress: req.ip || null,
      });
      return res.status(201).json({
        id: created.lastID,
        name,
        keyPrefix: pair.keyPrefix,
        apiKey: pair.rawKey,
        apiSecret,
        permissions,
        ipAllowlist,
        rateLimitPerMinute: rateLimit,
        expiresAt,
        secretShownOnce: true,
      });
    } catch (err: any) {
      return res.status(400).json({ error: err.message || 'Unable to create reseller API key.' });
    }
  });

  router.get('/reseller/api-keys/:id/usage', requireRole(['reseller']), requireResellerScope('api_keys.read'), async (req: Request, res: Response) => {
    const id = pInt(req.params.id);
    const owned = await ctx.db.get(`SELECT id FROM reseller_api_keys WHERE id = ? AND user_id = ?`, [id, req.principal!.userId]);
    if (!owned) return res.status(404).json({ error: 'API key not found.' });
    const limit = Math.max(1, Math.min(100, Number(req.query.limit) || 50));
    const offset = Math.max(0, Number(req.query.offset) || 0);
    const [summary, requests] = await Promise.all([
      ctx.db.get<any>(
        `SELECT COUNT(*) AS total, SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS succeeded,
                SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed,
                SUM(CASE WHEN created_at >= datetime('now', '-24 hours') THEN 1 ELSE 0 END) AS last_24h
         FROM reseller_api_requests WHERE api_key_id = ? AND user_id = ?`, [id, req.principal!.userId]),
      ctx.db.all<any>(
        `SELECT id, method, path, ip_address, status_code, success, created_at
         FROM reseller_api_requests WHERE api_key_id = ? AND user_id = ?
         ORDER BY id DESC LIMIT ? OFFSET ?`, [id, req.principal!.userId, limit, offset]),
    ]);
    return res.json({ usage: summary, requests, pagination: { limit, offset } });
  });

  router.get('/reseller/api-keys/:id', requireRole(['reseller']), requireResellerScope('api_keys.read'), async (req: Request, res: Response) => {
    const row = await ctx.db.get<any>(
      `SELECT * FROM reseller_api_keys WHERE id = ? AND user_id = ?`,
      [pInt(req.params.id), req.principal!.userId]
    );
    if (!row) return res.status(404).json({ error: 'API key not found.' });
    return res.json({ apiKey: safeResellerKey(row) });
  });

  router.put('/reseller/api-keys/:id', resellerKeyMutationLimiter, requireRole(['reseller']), requireResellerScope('api_keys.create'), async (req: Request, res: Response) => {
    try {
      const id = pInt(req.params.id);
      const existing = await ctx.db.get<any>(`SELECT * FROM reseller_api_keys WHERE id = ? AND user_id = ?`, [id, req.principal!.userId]);
      if (!existing) return res.status(404).json({ error: 'API key not found.' });
      const name = req.body?.name === undefined ? existing.name : String(req.body.name).trim();
      const description = req.body?.description === undefined ? existing.description : String(req.body.description).trim();
      const permissions = req.body?.permissions === undefined ? JSON.parse(existing.permissions) : parseResellerPermissions(req.body.permissions);
      const ipAllowlist = req.body?.ipAllowlist === undefined ? JSON.parse(existing.ip_allowlist) : parseResellerIpAllowlist(req.body.ipAllowlist);
      const expiresAt = req.body?.expiresAt === undefined ? existing.expires_at : parseResellerExpiry(req.body.expiresAt);
      const rateLimit = req.body?.rateLimitPerMinute === undefined ? Number(existing.rate_limit_per_minute) : Number(req.body.rateLimitPerMinute);
      if (!name || name.length > 80 || String(description || '').length > 500) return res.status(400).json({ error: 'Name or description exceeds its permitted length.' });
      if (!Number.isInteger(rateLimit) || rateLimit < 1 || rateLimit > 6000) return res.status(400).json({ error: 'Per-key rate limit must be an integer from 1 to 6000 requests per minute.' });
      await ctx.db.run(
        `UPDATE reseller_api_keys SET name = ?, description = ?, permissions = ?, ip_allowlist = ?,
         rate_limit_per_minute = ?, expires_at = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?`,
        [name, description || null, JSON.stringify(permissions), JSON.stringify(ipAllowlist), rateLimit, expiresAt, id, req.principal!.userId]
      );
      await ctx.db.logActivity({ userId: req.principal!.userId, action: 'reseller_api_key_updated', resourceType: 'reseller_api_key', resourceId: String(id), details: { name, permissions, rateLimitPerMinute: rateLimit }, ipAddress: req.ip || null });
      const updated = await ctx.db.get<any>(`SELECT * FROM reseller_api_keys WHERE id = ? AND user_id = ?`, [id, req.principal!.userId]);
      return res.json({ apiKey: safeResellerKey(updated) });
    } catch (err: any) {
      return res.status(400).json({ error: err.message || 'Unable to update reseller API key.' });
    }
  });

  router.post('/reseller/api-keys/:id/rotate', resellerKeyMutationLimiter, requireRole(['reseller']), requireResellerScope('api_keys.create'), async (req: Request, res: Response) => {
    const id = pInt(req.params.id);
    const owned = await ctx.db.get(`SELECT id FROM reseller_api_keys WHERE id = ? AND user_id = ?`, [id, req.principal!.userId]);
    if (!owned) return res.status(404).json({ error: 'API key not found.' });
    const pair = generateApiKeyPair('tgvpk');
    const apiSecret = crypto.randomBytes(32).toString('base64url');
    await ctx.db.transaction(async () => {
      const updated = await ctx.db.run(
        `UPDATE reseller_api_keys SET key_prefix = ?, key_hash = ?, secret_hash = ?, secret_enc = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?`,
        [pair.keyPrefix, pair.keyHash, hashApiKey(apiSecret), encryptSecret(apiSecret), id, req.principal!.userId]
      );
      if (!updated.changes) throw new Error('API key could not be rotated.');
      await ctx.db.run(`DELETE FROM reseller_api_nonces WHERE api_key_id = ?`, [id]);
    });
    await ctx.db.logActivity({ userId: req.principal!.userId, action: 'reseller_api_key_rotated', resourceType: 'reseller_api_key', resourceId: String(id), ipAddress: req.ip || null });
    return res.json({ id, apiKey: pair.rawKey, apiSecret, secretShownOnce: true });
  });

  for (const [action, enabled] of [['disable', 0], ['enable', 1]] as const) {
    router.post(`/reseller/api-keys/:id/${action}`, resellerKeyMutationLimiter, requireRole(['reseller']), requireResellerScope('api_keys.revoke'), async (req: Request, res: Response) => {
      const id = pInt(req.params.id);
      const updated = await ctx.db.run(
        `UPDATE reseller_api_keys SET is_active = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?`,
        [enabled, id, req.principal!.userId]
      );
      if (!updated.changes) return res.status(404).json({ error: 'API key not found.' });
      if (!enabled) await ctx.db.run(`DELETE FROM reseller_api_nonces WHERE api_key_id = ?`, [id]);
      await ctx.db.logActivity({ userId: req.principal!.userId, action: `reseller_api_key_${action}d`, resourceType: 'reseller_api_key', resourceId: String(id), ipAddress: req.ip || null });
      return res.json({ success: true, isActive: Boolean(enabled) });
    });
  }

  router.delete('/reseller/api-keys/:id', resellerKeyMutationLimiter, requireRole(['reseller']), requireResellerScope('api_keys.revoke'), async (req: Request, res: Response) => {
    const id = pInt(req.params.id);
    const deleted = await ctx.db.run(`DELETE FROM reseller_api_keys WHERE id = ? AND user_id = ?`, [id, req.principal!.userId]);
    if (!deleted.changes) return res.status(404).json({ error: 'API key not found.' });
    await ctx.db.logActivity({ userId: req.principal!.userId, action: 'reseller_api_key_revoked', resourceType: 'reseller_api_key', resourceId: String(id), ipAddress: req.ip || null });
    return res.json({ success: true });
  });

  router.get('/reseller/admin/accounts', requireRole(['admin']), async (req: Request, res: Response) => {
    const accounts = await ctx.db.all<any>(
      `SELECT id, username, email, full_name, is_active, created_at, last_login
       FROM users WHERE role = 'reseller' ORDER BY id DESC`
    );
    const instances = await ctx.instanceManager.listAccessibleInstances(req.principal!);
    const owned = new Map<number, typeof instances>();
    for (const instance of instances) {
      if (instance.ownerId === null || instance.ownerId === undefined) continue;
      const rows = owned.get(instance.ownerId) || [];
      rows.push(instance);
      owned.set(instance.ownerId, rows);
    }
    return res.json({
      accounts: accounts.map((account) => {
        const resources = owned.get(Number(account.id)) || [];
        return {
          id: Number(account.id),
          username: account.username,
          email: account.email,
          fullName: account.full_name,
          isActive: Boolean(account.is_active),
          createdAt: account.created_at,
          lastLogin: account.last_login,
          usage: {
            totalVps: resources.length,
            cpuCores: resources.reduce((sum, item) => sum + item.cpuCores, 0),
            ramMb: resources.reduce((sum, item) => sum + item.ramMb, 0),
            diskGb: Number(resources.reduce((sum, item) => sum + item.diskGb, 0).toFixed(2)),
          },
        };
      }),
    });
  });

  for (const action of ['suspend', 'unsuspend'] as const) {
    router.post(`/reseller/admin/accounts/:id/${action}`, requireRole(['admin']), async (req: Request, res: Response) => {
      const id = Number(req.params.id);
      if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid reseller account ID.' });
      const active = action === 'unsuspend';
      try {
        await ctx.db.transaction(async () => {
          const account = await ctx.db.get<any>(`SELECT id, role FROM users WHERE id = ?`, [id]);
          if (!account || account.role !== 'reseller') throw new Error('RESELLER_NOT_FOUND');
          await ctx.db.run(`UPDATE users SET is_active = ? WHERE id = ? AND role = 'reseller'`, [active ? 1 : 0, id]);
          if (!active) {
            await ctx.db.run(`UPDATE reseller_api_keys SET is_active = 0, updated_at = datetime('now') WHERE user_id = ?`, [id]);
            await ctx.db.run(`DELETE FROM reseller_api_nonces WHERE api_key_id IN (SELECT id FROM reseller_api_keys WHERE user_id = ?)`, [id]);
          }
        });
      } catch (err: any) {
        if (String(err?.message).includes('RESELLER_NOT_FOUND')) return res.status(404).json({ error: 'Reseller account not found.' });
        return res.status(500).json({ error: 'Unable to update reseller account status.' });
      }
      await ctx.db.logActivity({
        userId: req.principal!.userId,
        action: `reseller_account_${action}d`,
        resourceType: 'reseller_account',
        resourceId: String(id),
        details: { resellerUserId: id, keysDisabled: !active },
        ipAddress: req.ip || null,
      });
      return res.json({ success: true, resellerUserId: id, isActive: active, keysDisabled: !active });
    });
  }

  router.get('/reseller/admin/api-keys', requireRole(['admin']), async (req: Request, res: Response) => {
    const userId = req.query.userId === undefined ? undefined : Number(req.query.userId);
    if (userId !== undefined && (!Number.isInteger(userId) || userId < 1)) return res.status(400).json({ error: 'Invalid reseller user ID.' });
    const keys = await ctx.db.all<any>(
      `SELECT k.*, u.username FROM reseller_api_keys k JOIN users u ON u.id = k.user_id
       WHERE (? IS NULL OR k.user_id = ?) ORDER BY k.id DESC LIMIT 500`,
      [userId ?? null, userId ?? null]
    );
    return res.json({ apiKeys: keys.map(safeResellerKey) });
  });

  router.post('/reseller/admin/api-keys/:id/disable', resellerKeyMutationLimiter, requireRole(['admin']), async (req: Request, res: Response) => {
    const id = pInt(req.params.id);
    const updated = await ctx.db.run(`UPDATE reseller_api_keys SET is_active = 0, updated_at = datetime('now') WHERE id = ?`, [id]);
    if (!updated.changes) return res.status(404).json({ error: 'API key not found.' });
    await ctx.db.run(`DELETE FROM reseller_api_nonces WHERE api_key_id = ?`, [id]);
    await ctx.db.logActivity({ userId: req.principal!.userId, action: 'admin_disabled_reseller_api_key', resourceType: 'reseller_api_key', resourceId: String(id), ipAddress: req.ip || null });
    return res.json({ success: true, isActive: false });
  });

  router.delete('/reseller/admin/api-keys/:id', resellerKeyMutationLimiter, requireRole(['admin']), async (req: Request, res: Response) => {
    const id = pInt(req.params.id);
    const key = await ctx.db.get<{ user_id: number }>(`SELECT user_id FROM reseller_api_keys WHERE id = ?`, [id]);
    if (!key) return res.status(404).json({ error: 'API key not found.' });
    await ctx.db.run(`DELETE FROM reseller_api_keys WHERE id = ?`, [id]);
    await ctx.db.logActivity({ userId: req.principal!.userId, action: 'admin_revoked_reseller_api_key', resourceType: 'reseller_api_key', resourceId: String(id), details: { resellerUserId: key.user_id }, ipAddress: req.ip || null });
    return res.json({ success: true });
  });

  router.get('/reseller/customers', requireRole(['reseller']), requireResellerScope('customers.read'), async (req: Request, res: Response) => {
    const status = req.query.status === undefined ? undefined : String(req.query.status).trim().toLowerCase();
    const search = req.query.search === undefined ? undefined : String(req.query.search).trim();
    const limit = req.query.limit === undefined ? 50 : Number(req.query.limit);
    const offset = req.query.offset === undefined ? 0 : Number(req.query.offset);
    if (status !== undefined && status !== 'active' && status !== 'suspended') return res.status(400).json({ error: 'status must be active or suspended.' });
    if (search !== undefined && search.length > 100) return res.status(400).json({ error: 'search must be 100 characters or fewer.' });
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) return res.status(400).json({ error: 'limit must be an integer from 1 to 100.' });
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > 1000000) return res.status(400).json({ error: 'offset must be an integer from 0 to 1000000.' });
    const conditions = ['reseller_user_id = ?'];
    const params: any[] = [req.principal!.userId];
    if (status) { conditions.push('status = ?'); params.push(status); }
    if (search) {
      conditions.push(`(instr(lower(display_name), lower(?)) > 0 OR instr(lower(email), lower(?)) > 0 OR instr(lower(COALESCE(external_reference, '')), lower(?)) > 0)`);
      params.push(search, search, search);
    }
    const where = conditions.join(' AND ');
    const [summary, rows] = await Promise.all([
      ctx.db.get<{ count: number }>(`SELECT COUNT(*) AS count FROM reseller_customers WHERE ${where}`, params),
      ctx.db.all<any>(`SELECT * FROM reseller_customers WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`, [...params, limit, offset]),
    ]);
    return res.json({ customers: rows.map(safeResellerCustomer), pagination: { limit, offset, total: Number(summary?.count || 0) } });
  });

  router.post('/reseller/customers', requireRole(['reseller']), requireResellerScope('customers.create'), async (req: Request, res: Response) => {
    let fields: ReturnType<typeof parseResellerCustomerFields>;
    try { fields = parseResellerCustomerFields(req.body); }
    catch (err: any) { return res.status(400).json({ error: err.message }); }
    try {
      const created = await ctx.db.run(
        `INSERT INTO reseller_customers (reseller_user_id, display_name, email, external_reference, status, notes_enc)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [req.principal!.userId, fields.displayName, fields.email, fields.externalReference, fields.status, fields.notes ? encryptSecret(fields.notes) : null]
      );
      const row = await ctx.db.get<any>(`SELECT * FROM reseller_customers WHERE id = ? AND reseller_user_id = ?`, [created.lastID, req.principal!.userId]);
      await ctx.db.logActivity({ userId: req.principal!.userId, action: 'reseller_customer_created', resourceType: 'reseller_customer', resourceId: String(created.lastID), details: { status: fields.status }, ipAddress: req.ip || null });
      return res.status(201).json({ customer: safeResellerCustomer(row) });
    } catch (err: any) {
      if (String(err?.message).includes('UNIQUE constraint failed')) return res.status(409).json({ error: 'A customer with this email already exists in your account.' });
      return res.status(500).json({ error: 'Unable to create customer record.' });
    }
  });

  router.get('/reseller/customers/:id', requireRole(['reseller']), requireResellerScope('customers.read'), async (req: Request, res: Response) => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid customer ID.' });
    const row = await ctx.db.get<any>(`SELECT * FROM reseller_customers WHERE id = ? AND reseller_user_id = ?`, [id, req.principal!.userId]);
    if (!row) return res.status(404).json({ error: 'Customer not found.' });
    return res.json({ customer: safeResellerCustomer(row) });
  });

  router.put('/reseller/customers/:id', requireRole(['reseller']), requireResellerScope('customers.update'), async (req: Request, res: Response) => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid customer ID.' });
    const existing = await ctx.db.get<any>(`SELECT * FROM reseller_customers WHERE id = ? AND reseller_user_id = ?`, [id, req.principal!.userId]);
    if (!existing) return res.status(404).json({ error: 'Customer not found.' });
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body) || Object.keys(req.body).length === 0) return res.status(400).json({ error: 'Provide at least one customer field to update.' });
    let fields: ReturnType<typeof parseResellerCustomerFields>;
    try { fields = parseResellerCustomerFields(req.body, existing); }
    catch (err: any) { return res.status(400).json({ error: err.message }); }
    try {
      const updated = await ctx.db.run(
        `UPDATE reseller_customers SET display_name = ?, email = ?, external_reference = ?, status = ?, notes_enc = ?, updated_at = datetime('now')
         WHERE id = ? AND reseller_user_id = ?`,
        [fields.displayName, fields.email, fields.externalReference, fields.status, fields.notes ? encryptSecret(fields.notes) : null, id, req.principal!.userId]
      );
      if (!updated.changes) return res.status(404).json({ error: 'Customer not found.' });
      const row = await ctx.db.get<any>(`SELECT * FROM reseller_customers WHERE id = ? AND reseller_user_id = ?`, [id, req.principal!.userId]);
      await ctx.db.logActivity({ userId: req.principal!.userId, action: 'reseller_customer_updated', resourceType: 'reseller_customer', resourceId: String(id), details: { status: fields.status }, ipAddress: req.ip || null });
      return res.json({ customer: safeResellerCustomer(row) });
    } catch (err: any) {
      if (String(err?.message).includes('UNIQUE constraint failed')) return res.status(409).json({ error: 'A customer with this email already exists in your account.' });
      return res.status(500).json({ error: 'Unable to update customer record.' });
    }
  });

  router.delete('/reseller/customers/:id', requireRole(['reseller']), requireResellerScope('customers.delete'), async (req: Request, res: Response) => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid customer ID.' });
    const deleted = await ctx.db.run(
      `DELETE FROM reseller_customers WHERE id = ? AND reseller_user_id = ?`,
      [id, req.principal!.userId]
    );
    if (!deleted.changes) return res.status(404).json({ error: 'Customer not found.' });
    await ctx.db.logActivity({ userId: req.principal!.userId, action: 'reseller_customer_deleted', resourceType: 'reseller_customer', resourceId: String(id), ipAddress: req.ip || null });
    return res.json({ success: true, deleted: true });
  });

  router.get('/reseller/vps', requireRole(['reseller']), requireResellerScope('vps.read'), async (req: Request, res: Response) => {
    const engine = req.query.engine === undefined ? undefined : String(req.query.engine);
    const status = req.query.status === undefined ? undefined : String(req.query.status).trim();
    const search = req.query.search === undefined ? undefined : String(req.query.search).trim();
    const limit = req.query.limit === undefined ? 50 : Number(req.query.limit);
    const offset = req.query.offset === undefined ? 0 : Number(req.query.offset);
    if (engine !== undefined && engine !== 'kvm' && engine !== 'lxc') return res.status(400).json({ error: 'engine must be kvm or lxc.' });
    if (status !== undefined && (!status || status.length > 32 || !/^[a-zA-Z_-]+$/.test(status))) return res.status(400).json({ error: 'status must be a valid status filter of at most 32 characters.' });
    if (search !== undefined && search.length > 100) return res.status(400).json({ error: 'search must be 100 characters or fewer.' });
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) return res.status(400).json({ error: 'limit must be an integer from 1 to 100.' });
    if (!Number.isInteger(offset) || offset < 0 || offset > 1000000) return res.status(400).json({ error: 'offset must be an integer from 0 to 1000000.' });

    const matching = (await ctx.instanceManager.listAccessibleInstances(req.principal!, { engine: engine as VirtualizationEngine | undefined, status, search }))
      .filter((instance) => instance.ownerId === req.principal!.userId);
    return res.json({
      vps: matching.slice(offset, offset + limit),
      pagination: { limit, offset, total: matching.length },
    });
  });

  router.get('/reseller/vps/:id', requireRole(['reseller']), requireResellerScope('vps.read'), async (req: Request, res: Response) => {
    const id = pInt(req.params.id);
    const engine = String(req.query.engine || '');
    if (engine !== 'kvm' && engine !== 'lxc') return res.status(400).json({ error: 'Specify engine=kvm or engine=lxc.' });
    try {
      const instance = await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, id);
      if (instance.ownerId !== req.principal!.userId) return res.status(404).json({ error: 'VPS not found.' });
      return res.json({ vps: instance });
    } catch {
      return res.status(404).json({ error: 'VPS not found.' });
    }
  });

  for (const action of ['start', 'stop', 'restart'] as const) {
    const scope = `vps.${action}` as ResellerApiScope;
    router.post(`/reseller/vps/:id/${action}`, requireRole(['reseller']), requireResellerScope(scope), async (req: Request, res: Response) => {
      const engine = String(req.query.engine || req.body?.engine || '');
      const id = pInt(req.params.id);
      if (engine !== 'kvm' && engine !== 'lxc') return res.status(400).json({ error: 'Specify engine=kvm or engine=lxc.' });
      try {
        const instance = await ctx.instanceManager.getAuthorizedInstance(req.principal!, engine, id);
        if (instance.ownerId !== req.principal!.userId) return res.status(404).json({ error: 'VPS not found.' });
        const updated = await ctx.instanceManager.executeAction(req.principal!, engine, id, action, 'Reseller API request');
        return res.json({ vps: updated });
      } catch (err: any) { return res.status(err.statusCode || 400).json({ error: err.message }); }
    });
  }

  router.get('/reseller/stats', requireRole(['reseller']), requireResellerScope('stats.read'), async (req: Request, res: Response) => {
    const instances = (await ctx.instanceManager.listAccessibleInstances(req.principal!)).filter((instance) => instance.ownerId === req.principal!.userId);
    return res.json({ stats: {
      totalVps: instances.length,
      runningVps: instances.filter((instance) => instance.status === 'running').length,
      stoppedVps: instances.filter((instance) => instance.status === 'stopped').length,
      allocatedCpuCores: instances.reduce((sum, instance) => sum + instance.cpuCores, 0),
      allocatedRamMb: instances.reduce((sum, instance) => sum + instance.ramMb, 0),
      allocatedDiskGb: Number(instances.reduce((sum, instance) => sum + instance.diskGb, 0).toFixed(2)),
    } });
  });

  router.get('/reseller/resources', requireRole(['reseller']), requireResellerScope('resources.read'), async (req: Request, res: Response) => {
    const instances = (await ctx.instanceManager.listAccessibleInstances(req.principal!)).filter((instance) => instance.ownerId === req.principal!.userId);
    const telemetry = await Promise.all(instances.map((instance) =>
      ctx.instanceManager.getTelemetry(req.principal!, instance.engine, instance.refId).catch(() => null)
    ));
    const available = telemetry.filter((sample): sample is NonNullable<typeof sample> => sample !== null);
    const sumMeasured = (field: 'cpuPercent' | 'ramUsedMb' | 'ramTotalMb' | 'diskUsedGb' | 'netRxBytes' | 'netTxBytes') => {
      // Do not present a partial network total as a complete reseller aggregate when any VM
      // lacks a measured counter (notably KVM, which currently reports null honestly).
      if ((field === 'netRxBytes' || field === 'netTxBytes') && available.some((sample) => sample[field] === null)) {
        return null;
      }
      const values = available
        .map((sample) => sample[field])
        .filter((value): value is number => typeof value === 'number' && Number.isFinite(value));
      return values.length ? values.reduce((total, value) => total + value, 0) : null;
    };
    const measuredTimes = available.map((sample) => sample.measuredAt).filter(Boolean).sort();
    const measuredAt = measuredTimes.length ? measuredTimes[measuredTimes.length - 1] : null;
    return res.json({
      resources: {
        allocated: {
          vps: instances.length,
          cpuCores: instances.reduce((sum, instance) => sum + instance.cpuCores, 0),
          ramMb: instances.reduce((sum, instance) => sum + instance.ramMb, 0),
          diskGb: Number(instances.reduce((sum, instance) => sum + instance.diskGb, 0).toFixed(2)),
        },
        telemetry: {
          reportedInstances: available.length,
          unavailableInstances: instances.length - available.length,
          cpuPercent: sumMeasured('cpuPercent'),
          ramUsedMb: sumMeasured('ramUsedMb'),
          ramTotalMb: sumMeasured('ramTotalMb'),
          diskUsedGb: sumMeasured('diskUsedGb'),
          netRxBytes: sumMeasured('netRxBytes'),
          netTxBytes: sumMeasured('netTxBytes'),
          measuredAt,
        },
        limitsAvailable: false,
      },
    });
  });

  router.get('/reseller/resources/usage', requireRole(['reseller']), requireResellerScope('resources.read'), async (req: Request, res: Response) => {
    const instances = (await ctx.instanceManager.listAccessibleInstances(req.principal!)).filter((instance) => instance.ownerId === req.principal!.userId);
    const usage = await Promise.all(instances.map(async (instance) => ({
      engine: instance.engine,
      refId: instance.refId,
      name: instance.name,
      status: instance.status,
      allocatedCpuCores: instance.cpuCores,
      allocatedRamMb: instance.ramMb,
      allocatedDiskGb: instance.diskGb,
      telemetry: await ctx.instanceManager.getTelemetry(req.principal!, instance.engine, instance.refId).catch(() => null),
    })));
    return res.json({ usage });
  });

  router.get('/api-keys', async (req: Request, res: Response) => {
    const isAdmin = req.principal!.role === 'admin' && req.query.all === '1';
    const keys = isAdmin
      ? await ctx.db.all<any>(
          `SELECT k.id, k.user_id, u.username, k.name, k.description, k.key_prefix, k.permissions, k.ip_whitelist, k.is_active, k.last_used_at, k.expires_at, k.created_at
           FROM api_keys k JOIN users u ON u.id = k.user_id ORDER BY k.id DESC`
        )
      : await ctx.db.all<any>(
          `SELECT id, user_id, name, description, key_prefix, permissions, ip_whitelist, is_active, last_used_at, expires_at, created_at
           FROM api_keys WHERE user_id = ? ORDER BY id DESC`,
          [req.principal!.userId]
        );
    res.json({ apiKeys: keys });
  });

  router.post('/api-keys', async (req: Request, res: Response) => {
    try {
      const name = String(req.body?.name || '').trim();
      if (!name) return res.status(400).json({ error: 'API key name is required.' });

      const requestedPerms: string[] = Array.isArray(req.body?.permissions)
        ? req.body.permissions
        : ['read'];
      const safePerms = requestedPerms.filter(
        (p) => p === 'read' || p === 'write' || (p === 'admin' && req.principal!.role === 'admin')
      );
      const pair = generateApiKeyPair('hkvm_pat');

      const ins = await ctx.db.run(
        `INSERT INTO api_keys (user_id, name, description, key_prefix, key_hash, permissions, ip_whitelist, expires_at, is_active)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`,
        [
          req.principal!.userId,
          name,
          String(req.body?.description || ''),
          pair.keyPrefix,
          pair.keyHash,
          JSON.stringify(safePerms.length ? safePerms : ['read']),
          req.body?.ipWhitelist ? JSON.stringify(req.body.ipWhitelist) : null,
          req.body?.expiresAt || null,
        ]
      );

      return res.status(201).json({
        id: ins.lastID,
        name,
        keyPrefix: pair.keyPrefix,
        rawApiKey: pair.rawKey, // Returned ONCE at creation time
        permissions: safePerms,
      });
    } catch (err: any) {
      return res.status(400).json({ error: err.message });
    }
  });

  router.delete('/api-keys/:id', async (req: Request, res: Response) => {
    const id = pInt(req.params.id);
    if (req.principal!.role === 'admin') {
      await ctx.db.run(`DELETE FROM api_keys WHERE id = ?`, [id]);
    } else {
      await ctx.db.run(`DELETE FROM api_keys WHERE id = ? AND user_id = ?`, [
        id,
        req.principal!.userId,
      ]);
    }
    res.json({ success: true });
  });

  router.get('/webhooks', requireRole(['admin']), async (_req: Request, res: Response) => {
    const webhooks = await ctx.db.all<any>(
      `SELECT id, name, url, events, is_active, last_triggered_at, last_status_code, last_error, failure_count, created_at FROM webhooks ORDER BY id DESC`
    );
    res.json({ webhooks });
  });

  router.post('/webhooks', requireRole(['admin']), async (req: Request, res: Response) => {
    try {
      const name = String(req.body?.name || '').trim();
      const url = String(req.body?.url || '').trim();
      if (!name || !url.startsWith('http')) {
        return res.status(400).json({ error: 'Valid webhook name and HTTP(S) URL are required.' });
      }
      const events = Array.isArray(req.body?.events) ? req.body.events : ['*'];
      const secret = req.body?.secret ? String(req.body.secret) : crypto.randomBytes(24).toString('hex');
      const ins = await ctx.db.run(
        `INSERT INTO webhooks (user_id, name, url, secret_enc, events, is_active) VALUES (?, ?, ?, ?, ?, 1)`,
        [req.principal!.userId, name, url, encryptSecret(secret), JSON.stringify(events)]
      );
      return res.status(201).json({ id: ins.lastID, name, url, signingSecret: secret });
    } catch (err: any) {
      return res.status(400).json({ error: err.message });
    }
  });

  router.delete('/webhooks/:id', requireRole(['admin']), async (req: Request, res: Response) => {
    await ctx.db.run(`DELETE FROM webhooks WHERE id = ?`, [pInt(req.params.id)]);
    res.json({ success: true });
  });

  router.get(
    '/monitoring/overview',
    requireRole(['admin', 'subadmin', 'operator']),
    async (_req: Request, res: Response) => {
      const nodeMetrics = await ctx.db.all<any>(
        `SELECT * FROM metrics_history WHERE target_type = 'node' ORDER BY id DESC LIMIT 60`
      );
      const alertRules = await ctx.db.all<any>(`SELECT * FROM alert_rules ORDER BY id DESC`);
      res.json({ nodeMetrics, alertRules });
    }
  );

  router.get(
    '/monitoring/alerts',
    requireRole(['admin', 'subadmin', 'operator']),
    async (_req: Request, res: Response) => {
      const rules = await ctx.db.all<any>(`SELECT * FROM alert_rules ORDER BY id DESC`);
      res.json({ rules });
    }
  );

  router.post(
    '/monitoring/alerts',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      const b = req.body || {};
      const ins = await ctx.db.run(
        `INSERT INTO alert_rules (name, target_scope, metric, operator, threshold, severity, enabled)
         VALUES (?, ?, ?, ?, ?, ?, 1)`,
        [
          String(b.name || 'High Resource Alert'),
          b.targetScope === 'instance' ? 'instance' : 'node',
          String(b.metric || 'cpu_percent'),
          String(b.operator || '>='),
          Number(b.threshold || 90),
          String(b.severity || 'warning'),
        ]
      );
      res.status(201).json({ id: ins.lastID });
    }
  );

  router.delete(
    '/monitoring/alerts/:id',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      await ctx.db.run(`DELETE FROM alert_rules WHERE id = ?`, [pInt(req.params.id)]);
      res.json({ success: true });
    }
  );

  router.get(
    '/audit-logs',
    requireRole(['admin', 'subadmin']),
    async (req: Request, res: Response) => {
      const limit = Math.min(500, Math.max(10, Number(req.query.limit || 100)));
      const logs = await ctx.db.all<any>(
        `SELECT a.*, u.username
         FROM activity_logs a
         LEFT JOIN users u ON u.id = a.user_id
         ORDER BY a.id DESC
         LIMIT ?`,
        [limit]
      );
      res.json({ logs });
    }
  );

  router.post(
    '/database/backup',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      const out = await ctx.db.createBackup('manual_admin');
      await ctx.db.logActivity({
        userId: req.principal!.userId,
        action: 'database_manual_backup',
        resourceType: 'database',
        details: out,
      });
      res.json({ success: true, ...out });
    }
  );

  router.post(
    '/database/import-hvm',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const dbFilePath = path.resolve(String(req.body?.hvmDbPath || ''));
        const report = await importHvmDatabase(ctx.db, dbFilePath);
        res.json({ success: true, report });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  router.post(
    '/database/import-hvm/dry-run',
    requireRole(['admin']),
    async (req: Request, res: Response) => {
      try {
        const dbFilePath = path.resolve(String(req.body?.hvmDbPath || ''));
        const report = await dryRunHvmImport(ctx.db, dbFilePath);
        res.json({ success: true, report });
      } catch (err: any) {
        res.status(400).json({ error: err.message });
      }
    }
  );

  return router;
}
