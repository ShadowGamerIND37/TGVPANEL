import { Request, Response, NextFunction } from 'express';
import { UnifiedDatabase } from '../db/database';
export interface AuthenticatedPrincipal {
    userId: number;
    username: string;
    role: 'admin' | 'subadmin' | 'operator' | 'user' | 'readonly' | 'reseller';
    viaApiKey?: boolean;
    apiKeyId?: number;
    apiPermissions?: string[];
    apiScopeType?: 'reseller';
    impersonatedBy?: number;
}
declare global {
    namespace Express {
        interface Request {
            principal?: AuthenticatedPrincipal;
            csrfTokenValue?: string;
        }
    }
}
/**
 * Sliding-window in-memory rate limiter for auth, terminal, and mutation endpoints.
 */
/**
 * Parse a comma-separated list of trusted reverse-proxy addresses (exact IPs or IPv4 CIDRs).
 * Empty by default: the limiter then ignores client-supplied X-Forwarded-For and keys on the
 * socket peer, which prevents header spoofing from bypassing limits on directly-exposed panels.
 */
export declare function parseTrustedProxies(raw: string | undefined): string[];
/**
 * Whether the immediate socket peer is a trusted reverse proxy. Exact IPs and IPv4 CIDRs are
 * supported; IPv6 is matched exactly. A trusted peer's X-Forwarded-For is honored, otherwise the
 * limiter uses the socket address so an attacker cannot spoof the header to bypass limits.
 */
export declare function isIpTrustedByProxies(socketIp: string, trustedProxies: string[]): boolean;
export declare function createRateLimiter(options: {
    windowMs: number;
    max: number;
    keyPrefix: string;
    message?: string;
    trustedProxies?: string[];
}): (req: Request, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
/**
 * Security response headers & CSRF token injection into `res.locals.csrfToken`.
 */
export declare function securityHeadersAndCsrfMiddleware(req: Request, res: Response, next: NextFunction): void;
/**
 * Enforces CSRF token validation on state-mutating browser session requests.
 * Requests authenticated via `Authorization: Bearer <api_key>` or `X-API-Key` are exempt from cookie CSRF,
 * and standard XMLHttpRequest / fetch calls from HKVM's EJS templates pass either `X-CSRF-Token`, `_csrf`,
 * or same-origin JSON `Content-Type: application/json` + verified Origin/Referer.
 */
export declare function verifyCsrfMiddleware(req: Request, res: Response, next: NextFunction): void | Response<any, Record<string, any>>;
/**
 * Resolves either an active Express session OR a scoped API key (`Authorization: Bearer <key>` / `X-API-Key`).
 */
export declare function createUnifiedAuthMiddleware(db: UnifiedDatabase): (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
export declare function normalizeRole(role?: string | null): 'admin' | 'subadmin' | 'operator' | 'user' | 'readonly' | 'reseller';
export declare function requirePrincipal(req: Request, res: Response, next: NextFunction): void | Response<any, Record<string, any>>;
export declare function requireRole(allowedRoles: Array<'admin' | 'subadmin' | 'operator' | 'user' | 'readonly' | 'reseller'>): (req: Request, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
/**
 * Strict input validators preventing shell metacharacters, path traversal, and invalid identifiers.
 */
export declare const SafeValidators: {
    containerName(name: unknown): string;
    dockerContainerName(name: unknown): string;
    dockerImage(image: unknown): string;
    dockerRestartPolicy(policy: unknown): string;
    billingPlanName(name: unknown): string;
    billingCycle(cycle: unknown): string;
    loadBalancerName(name: unknown): string;
    snapshotName(name: unknown): string;
    bridgeOrIface(name: unknown): string;
    ipv4(ip: unknown): string;
    ipv6OrCidr(ip: unknown): string;
    portNumber(port: unknown, min?: number, max?: number): number;
    safeContainerSubpath(relPath: unknown): string;
};
