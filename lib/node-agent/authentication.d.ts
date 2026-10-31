import { IncomingMessage } from 'http';
import { Request, Response, NextFunction } from 'express';
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
export declare class NodeAgentAuthenticator {
    private config;
    private seenNonces;
    private cleanupTimer;
    constructor(config: AgentCredentialConfig);
    rotateCredentials(newRawApiKey: string, newHmacSecret: string): void;
    verifyRawHeaders(params: {
        method: string;
        pathWithQuery: string;
        rawBody: string;
        apiKeyHeader?: string;
        timestampHeader?: string;
        nonceHeader?: string;
        signatureHeader?: string;
        remoteAddress?: string;
        tlsAuthorized?: boolean;
    }): {
        ok: boolean;
        status: number;
        reason?: string;
    };
    expressMiddleware(): (req: Request, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
    verifyWebSocketUpgrade(req: IncomingMessage): {
        ok: boolean;
        reason?: string;
    };
}
