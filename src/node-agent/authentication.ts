import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { IncomingMessage } from 'http';
import { Request, Response, NextFunction } from 'express';
import { hashApiKey, verifyAgentRequestSignature } from '../security/crypto-vault';

export interface AgentCredentialConfig {
  nodeId: string;
  apiKeyHash: string;
  hmacSecret: string;
  requireMtls: boolean;
  allowedControllerIps?: string[];
  credentialsFilePath?: string;
  loadPersistedCredentials?: boolean;
}

/**
 * Replay-protection nonce cache + HMAC/API-Key/mTLS authenticator for the TGVPANEL Node Agent.
 */
export class NodeAgentAuthenticator {
  private config: AgentCredentialConfig;
  private seenNonces = new Map<string, number>();
  private cleanupTimer: NodeJS.Timeout;

  constructor(config: AgentCredentialConfig) {
    this.config = { ...config };
    if (
      config.loadPersistedCredentials &&
      config.credentialsFilePath &&
      fs.existsSync(config.credentialsFilePath)
    ) {
      try {
        const persisted = JSON.parse(fs.readFileSync(config.credentialsFilePath, 'utf8'));
        if (persisted?.apiKeyHash && persisted?.hmacSecret) {
          this.config.apiKeyHash = String(persisted.apiKeyHash);
          this.config.hmacSecret = String(persisted.hmacSecret);
        }
      } catch {
        // fall back to env bootstrap credentials
      }
    }
    this.cleanupTimer = setInterval(() => {
      const cutoff = Date.now() - 10 * 60_000;
      for (const [nonce, ts] of this.seenNonces.entries()) {
        if (ts < cutoff) this.seenNonces.delete(nonce);
      }
    }, 60_000);
    if (typeof this.cleanupTimer.unref === 'function') this.cleanupTimer.unref();
  }

  public rotateCredentials(newRawApiKey: string, newHmacSecret: string): void {
    this.config.apiKeyHash = hashApiKey(newRawApiKey);
    this.config.hmacSecret = newHmacSecret;

    if (this.config.credentialsFilePath) {
      const dir = path.dirname(this.config.credentialsFilePath);
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(
        this.config.credentialsFilePath,
        JSON.stringify(
          {
            nodeId: this.config.nodeId,
            apiKeyHash: this.config.apiKeyHash,
            hmacSecret: this.config.hmacSecret,
            requireMtls: this.config.requireMtls,
            rotatedAt: new Date().toISOString(),
          },
          null,
          2
        ),
        { mode: 0o600 }
      );
    }
  }

  public verifyRawHeaders(params: {
    method: string;
    pathWithQuery: string;
    rawBody: string;
    apiKeyHeader?: string;
    timestampHeader?: string;
    nonceHeader?: string;
    signatureHeader?: string;
    remoteAddress?: string;
    tlsAuthorized?: boolean;
  }): { ok: boolean; status: number; reason?: string } {
    if (this.config.requireMtls && !params.tlsAuthorized) {
      return { ok: false, status: 403, reason: 'Mutual TLS client certificate required' };
    }

    if (
      this.config.allowedControllerIps &&
      this.config.allowedControllerIps.length > 0 &&
      params.remoteAddress
    ) {
      const cleanIp = params.remoteAddress.replace(/^::ffff:/, '');
      if (
        !this.config.allowedControllerIps.includes(cleanIp) &&
        !this.config.allowedControllerIps.includes('*')
      ) {
        return { ok: false, status: 403, reason: `Controller IP ${cleanIp} not allowlisted` };
      }
    }

    const providedKey = (params.apiKeyHeader || '').trim();
    if (!providedKey) {
      return { ok: false, status: 401, reason: 'Missing X-HKVM-Node-Key header' };
    }

    const providedHash = hashApiKey(providedKey);
    if (
      providedHash.length !== this.config.apiKeyHash.length ||
      !crypto.timingSafeEqual(
        Buffer.from(providedHash, 'utf8'),
        Buffer.from(this.config.apiKeyHash, 'utf8')
      )
    ) {
      return { ok: false, status: 401, reason: 'Invalid node API key' };
    }

    const ts = Number(params.timestampHeader || '0');
    const nonce = (params.nonceHeader || '').trim();
    const sig = (params.signatureHeader || '').trim();

    if (!ts || !nonce || !sig) {
      return {
        ok: false,
        status: 401,
        reason: 'Missing HMAC timestamp, nonce, or signature headers',
      };
    }

    if (this.seenNonces.has(nonce)) {
      return { ok: false, status: 409, reason: 'Replay detected: nonce already used' };
    }

    const validSig = verifyAgentRequestSignature({
      hmacSecret: this.config.hmacSecret,
      method: params.method,
      pathWithQuery: params.pathWithQuery,
      timestampSec: ts,
      nonce,
      rawBody: params.rawBody,
      signatureHex: sig,
      maxSkewSec: 300,
    });

    if (!validSig) {
      return { ok: false, status: 401, reason: 'HMAC signature verification failed or clock skewed' };
    }

    this.seenNonces.set(nonce, Date.now());
    return { ok: true, status: 200 };
  }

  public expressMiddleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      const rawBody =
        typeof (req as any).rawBody === 'string'
          ? (req as any).rawBody
          : req.body && Object.keys(req.body).length > 0
            ? JSON.stringify(req.body)
            : '';

      const tlsSock: any = req.socket;
      const result = this.verifyRawHeaders({
        method: req.method,
        pathWithQuery: req.originalUrl,
        rawBody,
        apiKeyHeader:
          (req.headers['x-hkvm-node-key'] as string | undefined) ||
          (req.headers['x-api-key'] as string | undefined),
        timestampHeader: req.headers['x-hkvm-timestamp'] as string | undefined,
        nonceHeader: req.headers['x-hkvm-nonce'] as string | undefined,
        signatureHeader: req.headers['x-hkvm-signature'] as string | undefined,
        remoteAddress: req.socket.remoteAddress,
        tlsAuthorized: Boolean(tlsSock?.authorized),
      });

      if (!result.ok) {
        return res.status(result.status).json({ error: result.reason });
      }
      return next();
    };
  }

  public verifyWebSocketUpgrade(req: IncomingMessage): { ok: boolean; reason?: string } {
    const urlObj = new URL(req.url || '/', 'http://localhost');
    const apiKey =
      (req.headers['x-hkvm-node-key'] as string) || urlObj.searchParams.get('key') || '';
    const ts =
      (req.headers['x-hkvm-timestamp'] as string) || urlObj.searchParams.get('ts') || '';
    const nonce =
      (req.headers['x-hkvm-nonce'] as string) || urlObj.searchParams.get('nonce') || '';
    const sig =
      (req.headers['x-hkvm-signature'] as string) || urlObj.searchParams.get('sig') || '';

    const tlsSock: any = req.socket;
    const res = this.verifyRawHeaders({
      method: 'GET',
      pathWithQuery: urlObj.pathname,
      rawBody: '',
      apiKeyHeader: apiKey,
      timestampHeader: ts,
      nonceHeader: nonce,
      signatureHeader: sig,
      remoteAddress: req.socket.remoteAddress,
      tlsAuthorized: Boolean(tlsSock?.authorized),
    });
    return { ok: res.ok, reason: res.reason };
  }
}
