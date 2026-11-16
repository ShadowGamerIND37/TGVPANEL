import { Request, Response, NextFunction } from 'express';
import { UnifiedDatabase } from '../db/database';
export declare const RESELLER_API_SCOPES: readonly ['vps.read', 'vps.start', 'vps.stop', 'vps.restart', 'resources.read', 'stats.read', 'customers.read', 'customers.create', 'customers.update', 'customers.delete', 'api_keys.read', 'api_keys.create', 'api_keys.revoke'];
export type ResellerApiScope = typeof RESELLER_API_SCOPES[number];
export interface ResellerSignedHeaders {
    'X-TGV-API-KEY': string;
    'X-TGV-TIMESTAMP': string;
    'X-TGV-NONCE': string;
    'X-TGV-SIGNATURE': string;
}
export declare function signResellerRequest(params: {
    apiKey: string;
    apiSecret: string;
    method: string;
    pathWithQuery: string;
    body?: Buffer | string;
    timestamp?: number;
    nonce?: string;
}): ResellerSignedHeaders;
/**
 * HMAC request auth for /api/v1/reseller/*.
 * Canonical bytes: timestamp + LF + nonce + LF + uppercase method + LF + raw path/query + LF + lowercase SHA-256(raw body),
 * signed with HMAC-SHA256 using the one-time-displayed API secret. Timestamp skew is limited to five minutes.
 */
export declare function createResellerHmacAuthMiddleware(db: UnifiedDatabase): (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
