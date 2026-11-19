import type { UnifiedDatabase } from '../../db/database';
export interface GatewayConfig {
    id: number;
    name: string;
    provider: string;
    enabled: number;
    has_api_key: boolean;
    has_api_secret: boolean;
    has_webhook_secret: boolean;
    webhook_url: string | null;
    account_id: string | null;
    merchant_id: string | null;
    currency: string;
    is_default: number;
    last_test_at: number | null;
    last_test_status: string | null;
    created_at: string;
    updated_at: string;
}
export interface CreateOrderResult {
    success: boolean;
    order_id?: string;
    gateway_order_id?: string;
    checkout_url?: string;
    qr_url?: string;
    upi_intent?: string;
    redirect_url?: string;
    amount_cents: number;
    currency: string;
    error?: string;
    status?: string;
    is_manual?: boolean;
    message?: string;
}
export interface VerifyResult {
    success: boolean;
    status: string;
    utr?: string;
    payment_reference?: string;
    sender_name?: string;
    error?: string;
}
/**
 * Payment gateway integration manager.
 *
 * Supports three gateways:
 * - **FamGateway** (UPI, India): create order via `POST /api/create-order`,
 *   verify via `GET /api/verify-order.php` (server-to-server) or public
 *   `GET /api/checkout-status.php`. Webhooks use HMAC-SHA256 signatures.
 * - **Stripe**: create Checkout Session via Stripe API, verify via webhook
 *   signature (Stripe-Signature header).
 * - **PayPal**: create order via PayPal API, capture via webhook or polling.
 *
 * All API keys/secrets are encrypted at rest via the crypto-vault. Each
 * gateway can be independently enabled/disabled. Payments are only marked
 * paid after gateway verification (webhook or server-to-server polling).
 * No fake success — if the gateway API is unreachable, the order stays
 * pending with a clear error.
 */
export declare class PaymentGatewayManager {
    private db;
    private keyCache;
    constructor(db: UnifiedDatabase);
    listGateways(): Promise<GatewayConfig[]>;
    getGateway(id: number): Promise<GatewayConfig | null>;
    getEnabledGateways(): Promise<GatewayConfig[]>;
    getDefaultGateway(): Promise<GatewayConfig | null>;
    updateGateway(id: number, input: {
        enabled?: number;
        apiKey?: string;
        apiSecret?: string;
        webhookSecret?: string;
        webhookUrl?: string;
        accountId?: string;
        merchantId?: string;
        currency?: string;
        isDefault?: number;
    }): Promise<GatewayConfig | null>;
    testGateway(id: number): Promise<{
        success: boolean;
        message: string;
    }>;
    private getApiKey;
    private getApiSecret;
    private getWebhookSecret;
    private loadKeyCache;
    /**
     * Return true only when the URL is a public https URL (not localhost,
     * not a private/loopback IP). FamGateway rejects localhost/private
     * redirect_url values, so those must be omitted from the payload.
     */
    private isPublicHttpsUrl;
    /**
     * Create a payment order via the specified gateway.
     * Returns the checkout URL / QR / redirect data for the customer.
     */
    createOrder(gatewayId: number, amountCents: number, options: {
        userName?: string;
        userEmail?: string;
        userPhone?: string;
        redirectUrl?: string;
        invoiceId?: number;
        subscriptionId?: number;
        userId: number;
        planId?: number;
    }): Promise<CreateOrderResult>;
    /**
     * Create a manual/offline order when no payment gateway API key is
     * configured. The order is stored as 'pending' in the database and
     * can be marked as paid by an admin after manual confirmation.
     */
    createManualOrder(amountCents: number, options: {
        userId: number;
        planId?: number;
        userName?: string;
        userEmail?: string;
    }): Promise<CreateOrderResult>;
    /**
     * Verify a payment order's status via the gateway (server-to-server).
     */
    verifyOrder(gatewayId: number, gatewayOrderId: string): Promise<VerifyResult>;
    /**
     * Verify a webhook signature.
     */
    verifyWebhook(gatewayId: number, rawBody: string, signature: string, timestamp?: string): Promise<{
        valid: boolean;
        diagnostics?: {
            secretSource: string;
            receivedPrefix: string;
            expectedPrefix: string;
        };
    }>;
    /**
     * Mark a payment order as paid after verification.
     */
    markOrderPaid(orderId: string, utr?: string, paymentReference?: string): Promise<boolean>;
    listOrders(userId: number, limit?: number): Promise<unknown[]>;
    getOrder(orderId: string): Promise<unknown[] | null>;
}
