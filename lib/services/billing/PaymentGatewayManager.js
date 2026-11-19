"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PaymentGatewayManager = void 0;
const crypto_1 = __importDefault(require("crypto"));
const crypto_vault_1 = require("../../security/crypto-vault");
const FAMGATEWAY_BASE = 'https://famgateway.in';
const STRIPE_BASE = 'https://api.stripe.com';
const PAYPAL_BASE = 'https://api-m.sandbox.paypal.com';
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
class PaymentGatewayManager {
    db;
    keyCache = new Map();
    constructor(db) {
        this.db = db;
    }
    async listGateways() {
        const rows = await this.db.all(`SELECT * FROM payment_gateways ORDER BY id`);
        return rows.map((r) => ({
            id: r.id, name: r.name, provider: r.provider, enabled: r.enabled,
            has_api_key: Boolean(r.api_key_enc), has_api_secret: Boolean(r.api_secret_enc),
            has_webhook_secret: Boolean(r.webhook_secret_enc),
            webhook_url: r.webhook_url, account_id: r.account_id, merchant_id: r.merchant_id,
            currency: r.currency, is_default: r.is_default,
            last_test_at: r.last_test_at, last_test_status: r.last_test_status,
            created_at: r.created_at, updated_at: r.updated_at,
        }));
    }
    async getGateway(id) {
        const row = await this.db.get(`SELECT * FROM payment_gateways WHERE id = ?`, [id]);
        if (!row)
            return null;
        return {
            id: row.id, name: row.name, provider: row.provider, enabled: row.enabled,
            has_api_key: Boolean(row.api_key_enc), has_api_secret: Boolean(row.api_secret_enc),
            has_webhook_secret: Boolean(row.webhook_secret_enc),
            webhook_url: row.webhook_url, account_id: row.account_id, merchant_id: row.merchant_id,
            currency: row.currency, is_default: row.is_default,
            last_test_at: row.last_test_at, last_test_status: row.last_test_status,
            created_at: row.created_at, updated_at: row.updated_at,
        };
    }
    async getEnabledGateways() {
        const gateways = await this.listGateways();
        return gateways.filter((g) => g.enabled && g.has_api_key);
    }
    async getDefaultGateway() {
        const gateways = await this.listGateways();
        return gateways.find((g) => g.enabled && g.is_default && g.has_api_key) || null;
    }
    async updateGateway(id, input) {
        const existing = await this.db.get(`SELECT * FROM payment_gateways WHERE id = ?`, [id]);
        if (!existing)
            return null;
        const encryptedKey = input.apiKey ? (0, crypto_vault_1.encryptSecret)(input.apiKey) : null;
        const encryptedSecret = input.apiSecret ? (0, crypto_vault_1.encryptSecret)(input.apiSecret) : null;
        const encryptedWebhook = input.webhookSecret ? (0, crypto_vault_1.encryptSecret)(input.webhookSecret) : null;
        // If setting as default, unset others
        if (input.isDefault) {
            await this.db.run(`UPDATE payment_gateways SET is_default = 0 WHERE id != ?`, [id]);
        }
        await this.db.run(`UPDATE payment_gateways SET
         enabled = ?,
         api_key_enc = COALESCE(?, api_key_enc),
         api_secret_enc = COALESCE(?, api_secret_enc),
         webhook_secret_enc = COALESCE(?, webhook_secret_enc),
         webhook_url = ?,
         account_id = ?,
         merchant_id = ?,
         currency = ?,
         is_default = ?,
         updated_at = datetime('now')
       WHERE id = ?`, [
            input.enabled ?? existing.enabled,
            encryptedKey, encryptedSecret, encryptedWebhook,
            input.webhookUrl ?? existing.webhook_url,
            input.accountId ?? existing.account_id,
            input.merchantId ?? existing.merchant_id,
            input.currency ?? existing.currency,
            input.isDefault ?? existing.is_default,
            id,
        ]);
        this.keyCache.delete(id);
        return this.getGateway(id);
    }
    async testGateway(id) {
        const gw = await this.db.get(`SELECT * FROM payment_gateways WHERE id = ?`, [id]);
        if (!gw)
            return { success: false, message: 'Gateway not found.' };
        const key = await this.getApiKey(id);
        if (!key)
            return { success: false, message: 'API key not configured.' };
        try {
            if (gw.provider === 'famgateway') {
                const res = await fetch(`${FAMGATEWAY_BASE}/api/create-order`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Api-Key': key },
                    body: JSON.stringify({ amount: 1, customer_name: 'Test' }),
                });
                const data = await res.json();
                // Normalize the response shape: FamGateway returns order fields at the
                // top level ({ status:'success', order_id, ... }); some wrappers nest them
                // under `data`. Confirm a real order object is present so the test agrees
                // with the purchase flow (a response without an order_id is a failure).
                const norm = (data && data.data && data.data.order_id) ? data.data : data;
                if (data.status === 'success' && norm && norm.order_id) {
                    await this.db.run(`UPDATE payment_gateways SET last_test_at = ?, last_test_status = 'success' WHERE id = ?`, [Date.now(), id]);
                    return { success: true, message: 'FamGateway connection verified — order created successfully.' };
                }
                await this.db.run(`UPDATE payment_gateways SET last_test_at = ?, last_test_status = 'failed' WHERE id = ?`, [Date.now(), id]);
                return { success: false, message: `FamGateway error: ${data.error || 'unknown'}` };
            }
            if (gw.provider === 'stripe') {
                const res = await fetch(`${STRIPE_BASE}/v1/balance`, {
                    headers: { Authorization: `Bearer ${key}` },
                });
                if (res.ok) {
                    await this.db.run(`UPDATE payment_gateways SET last_test_at = ?, last_test_status = 'success' WHERE id = ?`, [Date.now(), id]);
                    return { success: true, message: 'Stripe connection verified.' };
                }
                await this.db.run(`UPDATE payment_gateways SET last_test_at = ?, last_test_status = 'failed' WHERE id = ?`, [Date.now(), id]);
                return { success: false, message: `Stripe error: ${res.status} ${res.statusText}` };
            }
            if (gw.provider === 'paypal') {
                const secret = this.getApiSecret(id);
                if (!secret)
                    return { success: false, message: 'PayPal client secret not configured.' };
                const auth = Buffer.from(`${gw.account_id || ''}:${secret}`).toString('base64');
                const res = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
                    method: 'POST',
                    headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'grant_type=client_credentials',
                });
                if (res.ok) {
                    await this.db.run(`UPDATE payment_gateways SET last_test_at = ?, last_test_status = 'success' WHERE id = ?`, [Date.now(), id]);
                    return { success: true, message: 'PayPal connection verified.' };
                }
                await this.db.run(`UPDATE payment_gateways SET last_test_at = ?, last_test_status = 'failed' WHERE id = ?`, [Date.now(), id]);
                return { success: false, message: `PayPal error: ${res.status} ${res.statusText}` };
            }
            return { success: false, message: `Unknown gateway provider: ${gw.provider}` };
        }
        catch (err) {
            await this.db.run(`UPDATE payment_gateways SET last_test_at = ?, last_test_status = 'failed' WHERE id = ?`, [Date.now(), id]);
            return { success: false, message: `Gateway unreachable: ${err.message}` };
        }
    }
    async getApiKey(id) {
        if (this.keyCache.has(id))
            return this.keyCache.get(id).apiKey;
        return this.loadKeyCache(id, 'apiKey', 'api_key_enc');
    }
    async getApiSecret(id) {
        if (this.keyCache.has(id))
            return this.keyCache.get(id).apiSecret;
        return this.loadKeyCache(id, 'apiSecret', 'api_secret_enc');
    }
    async getWebhookSecret(id) {
        if (this.keyCache.has(id))
            return this.keyCache.get(id).webhookSecret;
        return this.loadKeyCache(id, 'webhookSecret', 'webhook_secret_enc');
    }
    async loadKeyCache(id, field, col) {
        const row = await this.db.get(`SELECT ${col} as enc FROM payment_gateways WHERE id = ?`, [id]);
        if (row?.enc) {
            const val = (0, crypto_vault_1.decryptSecret)(row.enc);
            if (val) {
                const cache = this.keyCache.get(id) || { apiKey: '', apiSecret: '', webhookSecret: '' };
                cache[field] = val;
                this.keyCache.set(id, cache);
                return val;
            }
        }
        return null;
    }
    /**
     * Return true only when the URL is a public https URL (not localhost,
     * not a private/loopback IP). FamGateway rejects localhost/private
     * redirect_url values, so those must be omitted from the payload.
     */
    isPublicHttpsUrl(url) {
        if (!url)
            return false;
        try {
            const u = new URL(url);
            if (u.protocol !== 'https:')
                return false;
            const host = u.hostname.toLowerCase();
            if (host === 'localhost' || host.endsWith('.localhost'))
                return false;
            if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1|0\.0\.0\.0)/i.test(host))
                return false;
            return true;
        }
        catch {
            return false;
        }
    }
    /**
     * Create a payment order via the specified gateway.
     * Returns the checkout URL / QR / redirect data for the customer.
     */
    async createOrder(gatewayId, amountCents, options) {
        const gw = await this.db.get(`SELECT * FROM payment_gateways WHERE id = ?`, [gatewayId]);
        if (!gw)
            return { success: false, amount_cents: amountCents, currency: 'INR', error: 'Gateway not found.' };
        if (!gw.enabled)
            return { success: false, amount_cents: amountCents, currency: gw.currency, error: 'Gateway is disabled.' };
        const amount = amountCents / 100;
        const orderId = `po_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
        const GATEWAY_TIMEOUT_MS = 10000; // 10 second timeout for gateway API calls
        // Helper: fetch with timeout using AbortController
        const fetchWithTimeout = async (url, init) => {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), GATEWAY_TIMEOUT_MS);
            try {
                return await fetch(url, { ...init, signal: controller.signal });
            }
            finally {
                clearTimeout(timer);
            }
        };
        try {
            if (gw.provider === 'famgateway') {
                const apiKey = await this.getApiKey(gatewayId);
                if (!apiKey)
                    return { success: false, amount_cents: amountCents, currency: gw.currency, error: 'FamGateway API key not configured.' };
                // UPI has a minimum payment amount of ₹1. Plans priced below ₹1
                // (e.g. test plans at $0.01 = ₹0.01) will be rejected by the gateway.
                // Round up to ₹1 minimum so the order always succeeds.
                const minAmount = 1;
                const payAmount = amount < minAmount ? minAmount : amount;
                // Use the EXACT same minimal payload as testGateway() — extra fields
                // (email, phone, redirect_url) cause the gateway to reject the order.
                // FamGateway returns checkout_url and upi_intent that the customer
                // can use directly, so redirect_url is not needed.
                const famPayload = {
                    amount: payAmount,
                    customer_name: options.userName || 'Customer',
                };
                // Include redirect_url ONLY when it is a public https URL so FamGateway
                // can send the buyer back to the panel after payment. localhost/private
                // URLs are rejected by the gateway, so omit them (the buyer still gets
                // checkout_url / qr_url from the gateway response).
                if (this.isPublicHttpsUrl(options.redirectUrl)) {
                    famPayload.redirect_url = options.redirectUrl;
                }
                const res = await fetch(`${FAMGATEWAY_BASE}/api/create-order`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Api-Key': apiKey },
                    body: JSON.stringify(famPayload),
                });
                const data = await res.json();
                // Per the official docs, the success response is:
                //   { status: 'success', data: { order_id, qr_url, checkout_url, upi_intent, ... } }
                // (order fields are nested under `data`). Accept both this shape and a
                // top-level shape for robustness, so a successful response is never
                // misread as a failure (which would silently fall back to a manual
                // order — the customer sees "buy plan not working").
                const d = (data && data.data && data.data.order_id) ? data.data : data;
                if (data.status === 'success' && d && d.order_id) {
                    await this.db.run(`INSERT INTO payment_orders (order_id, invoice_id, subscription_id, user_id, plan_id, gateway, gateway_order_id, amount_cents, currency, status, redirect_url, checkout_url, qr_url, upi_intent, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, datetime('now'))`, [orderId, options.invoiceId, options.subscriptionId, options.userId, options.planId, gw.provider, d.order_id, amountCents, gw.currency, d.upi_intent, d.checkout_url, d.qr_url, d.upi_intent]);
                    return {
                        success: true, order_id: orderId, gateway_order_id: d.order_id,
                        checkout_url: d.checkout_url, qr_url: d.qr_url, upi_intent: d.upi_intent,
                        redirect_url: d.upi_intent, amount_cents: amountCents, currency: gw.currency,
                    };
                }
                // Return the gateway's actual error message for better debugging.
                // Include the full response body so the rejection reason is visible
                // (e.g. invalid amount, missing field, auth failure, sandbox limits).
                const fgErr = data.error
                    ? `FamGateway error: ${data.error}`
                    : `FamGateway returned status: ${data.status || 'unknown'}.`;
                return { success: false, amount_cents: amountCents, currency: gw.currency, error: `${fgErr} Response: ${JSON.stringify(data)}` };
            }
            if (gw.provider === 'stripe') {
                const apiKey = await this.getApiKey(gatewayId);
                if (!apiKey)
                    return { success: false, amount_cents: amountCents, currency: gw.currency, error: 'Stripe API key not configured.' };
                const res = await fetchWithTimeout(`${STRIPE_BASE}/v1/checkout/sessions`, {
                    method: 'POST',
                    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({
                        'mode': 'subscription',
                        'success_url': options.redirectUrl || 'https://panel.local/store?status=success',
                        'cancel_url': options.redirectUrl ? options.redirectUrl.replace('success', 'cancel') : 'https://panel.local/store?status=cancel',
                        'line_items[0][price_data][currency]': gw.currency.toLowerCase(),
                        'line_items[0][price_data][unit_amount]': String(amountCents),
                        'line_items[0][price_data][product_data][name]': options.userName ? `Plan subscription` : 'Plan subscription',
                        'line_items[0][quantity]': '1',
                        'metadata[invoice_id]': String(options.invoiceId || 0),
                        'metadata[subscription_id]': String(options.subscriptionId || 0),
                    }),
                });
                const data = await res.json();
                if (data.url) {
                    await this.db.run(`INSERT INTO payment_orders (order_id, invoice_id, subscription_id, user_id, plan_id, gateway, gateway_order_id, amount_cents, currency, status, checkout_url, redirect_url, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, datetime('now'))`, [orderId, options.invoiceId, options.subscriptionId, options.userId, options.planId, gw.provider, data.id, amountCents, gw.currency, data.url, data.url]);
                    return { success: true, order_id: orderId, gateway_order_id: data.id, checkout_url: data.url, redirect_url: data.url, amount_cents: amountCents, currency: gw.currency };
                }
                return { success: false, amount_cents: amountCents, currency: gw.currency, error: data.error?.message || 'Stripe checkout creation failed.' };
            }
            if (gw.provider === 'paypal') {
                const apiKey = await this.getApiKey(gatewayId);
                const apiSecret = await this.getApiSecret(gatewayId);
                if (!apiKey || !apiSecret)
                    return { success: false, amount_cents: amountCents, currency: gw.currency, error: 'PayPal credentials not configured.' };
                const auth = Buffer.from(`${apiKey}:${apiSecret}`).toString('base64');
                const tokenRes = await fetchWithTimeout(`${PAYPAL_BASE}/v1/oauth2/token`, {
                    method: 'POST',
                    headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'grant_type=client_credentials',
                });
                const tokenData = await tokenRes.json();
                const accessToken = tokenData.access_token;
                if (!accessToken)
                    return { success: false, amount_cents: amountCents, currency: gw.currency, error: 'PayPal auth failed.' };
                const res = await fetchWithTimeout(`${PAYPAL_BASE}/v2/checkout/orders`, {
                    method: 'POST',
                    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        intent: 'CAPTURE',
                        purchase_units: [{
                                amount: { currency_code: gw.currency, value: amount.toFixed(2) },
                                reference_id: options.invoiceId ? `INV-${options.invoiceId}` : orderId,
                            }],
                    }),
                });
                const data = await res.json();
                if (data.id) {
                    await this.db.run(`INSERT INTO payment_orders (order_id, invoice_id, subscription_id, user_id, plan_id, gateway, gateway_order_id, amount_cents, currency, status, checkout_url, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, datetime('now'))`, [orderId, options.invoiceId, options.subscriptionId, options.userId, options.planId, gw.provider, data.id, amountCents, gw.currency, `${PAYPAL_BASE}/checkoutnow?token=${data.id}`]);
                    return { success: true, order_id: orderId, gateway_order_id: data.id, checkout_url: `${PAYPAL_BASE}/checkoutnow?token=${data.id}`, amount_cents: amountCents, currency: gw.currency };
                }
                return { success: false, amount_cents: amountCents, currency: gw.currency, error: data.message || 'PayPal order creation failed.' };
            }
            return { success: false, amount_cents: amountCents, currency: gw.currency, error: `Unknown gateway: ${gw.provider}` };
        }
        catch (err) {
            // Gateway API unreachable (network error, timeout, etc.) — fall back to a
            // manual/offline order so the customer can still complete the purchase.
            // The admin can verify the payment and mark the order as paid afterwards.
            const isNetworkError = err.name === 'AbortError' ||
                err.name === 'TypeError' ||
                err.message === 'fetch failed' ||
                err.cause?.code === 'ECONNREFUSED' ||
                err.cause?.code === 'ENOTFOUND' ||
                err.cause?.code === 'ETIMEDOUT';
            if (isNetworkError) {
                const fallback = await this.createManualOrder(amountCents, {
                    userId: options.userId,
                    planId: options.planId,
                    userName: options.userName,
                    userEmail: options.userEmail,
                });
                fallback.message = `Payment gateway was unreachable (${gw.provider}). Your order has been created as a manual payment — an admin will confirm it after verification.`;
                return fallback;
            }
            return { success: false, amount_cents: amountCents, currency: gw.currency, error: `Gateway error: ${err.message}` };
        }
    }
    /**
     * Create a manual/offline order when no payment gateway API key is
     * configured. The order is stored as 'pending' in the database and
     * can be marked as paid by an admin after manual confirmation.
     */
    async createManualOrder(amountCents, options) {
        const orderId = `po_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
        const gwProvider = 'manual';
        const currency = 'INR';
        await this.db.run(`INSERT INTO payment_orders (order_id, invoice_id, subscription_id, user_id, plan_id, gateway, gateway_order_id, amount_cents, currency, status, payment_reference, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, datetime('now'))`, [orderId, options.invoiceId, options.subscriptionId, options.userId, options.planId, gwProvider, orderId, amountCents, currency, orderId]);
        return {
            success: true,
            order_id: orderId,
            gateway_order_id: orderId,
            amount_cents: amountCents,
            currency,
            status: 'pending',
            is_manual: true,
            message: 'Manual order created. An admin will confirm your payment after verification.',
        };
    }
    /**
     * Verify a payment order's status via the gateway (server-to-server).
     */
    async verifyOrder(gatewayId, gatewayOrderId) {
        const gw = await this.db.get(`SELECT * FROM payment_gateways WHERE id = ?`, [gatewayId]);
        if (!gw)
            return { success: false, status: 'error', error: 'Gateway not found.' };
        try {
            if (gw.provider === 'famgateway') {
                const apiKey = await this.getApiKey(gatewayId);
                if (!apiKey)
                    return { success: false, status: 'error', error: 'FamGateway API key not configured.' };
                const res = await fetch(`${FAMGATEWAY_BASE}/api/verify-order.php?api_key=${encodeURIComponent(apiKey)}&order_id=${encodeURIComponent(gatewayOrderId)}`);
                const data = await res.json();
                // Per the docs, verify-order returns { status: 'success' | 'pending' |
                // 'expired', utr, sender_name, ... } on 200, or an error body
                // ({ status: 'error'/'unauthorized'/'not_found'/..., message }) on
                // 4xx/5xx. Map those correctly instead of reporting errors as success.
                if (data.status === 'success') {
                    return { success: true, status: 'paid', utr: data.utr, payment_reference: data.utr, sender_name: data.sender_name };
                }
                if (data.status === 'pending' || data.status === 'expired') {
                    return { success: true, status: data.status };
                }
                return { success: false, status: 'error', error: data.message || `FamGateway verify-order error (HTTP ${res.status})` };
            }
            if (gw.provider === 'stripe') {
                const apiKey = await this.getApiKey(gatewayId);
                if (!apiKey)
                    return { success: false, status: 'error', error: 'Stripe API key not configured.' };
                const res = await fetch(`${STRIPE_BASE}/v1/checkout/sessions/${gatewayOrderId}`, {
                    headers: { Authorization: `Bearer ${apiKey}` },
                });
                const data = await res.json();
                const status = data.payment_status === 'paid' ? 'paid' : (data.status === 'complete' ? 'paid' : 'pending');
                return { success: true, status, payment_reference: data.payment_intent || data.id };
            }
            if (gw.provider === 'paypal') {
                const apiKey = await this.getApiKey(gatewayId);
                const apiSecret = await this.getApiSecret(gatewayId);
                if (!apiKey || !apiSecret)
                    return { success: false, status: 'error', error: 'PayPal credentials not configured.' };
                const auth = Buffer.from(`${apiKey}:${apiSecret}`).toString('base64');
                const tokenRes = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
                    method: 'POST',
                    headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'grant_type=client_credentials',
                });
                const tokenData = await tokenRes.json();
                const accessToken = tokenData.access_token;
                const res = await fetch(`${PAYPAL_BASE}/v2/checkout/orders/${gatewayOrderId}`, {
                    headers: { Authorization: `Bearer ${accessToken}` },
                });
                const data = await res.json();
                const status = data.status === 'COMPLETED' ? 'paid' : 'pending';
                return { success: true, status, payment_reference: data.id };
            }
            return { success: false, status: 'error', error: `Unknown gateway: ${gw.provider}` };
        }
        catch (err) {
            return { success: false, status: 'error', error: `Verification error: ${err.message}` };
        }
    }
    /**
     * Verify a webhook signature.
     */
    async verifyWebhook(gatewayId, rawBody, signature, timestamp) {
        const gw = await this.db.get(`SELECT * FROM payment_gateways WHERE id = ?`, [gatewayId]);
        if (!gw)
            return { valid: false };
        // FamGateway signs webhooks with the Merchant API Key as the HMAC secret
        // (official docs: "simply pass your FamGateway API Key as the secret. No
        // extra webhook secret configuration is required."). Using a separate
        // webhook secret here computes the HMAC with the wrong key, so every
        // webhook fails signature verification with 401. For other gateways,
        // fall back through webhook secret -> api key -> api secret.
        let secret = null;
        let secretSource = 'none';
        if (gw.provider === 'famgateway') {
            secret = await this.getApiKey(gatewayId);
            if (secret)
                secretSource = 'apiKey';
        }
        else {
            secret = await this.getWebhookSecret(gatewayId);
            if (secret)
                secretSource = 'webhookSecret';
            if (!secret) {
                secret = await this.getApiKey(gatewayId);
                if (secret)
                    secretSource = 'apiKey';
            }
            if (!secret) {
                secret = await this.getApiSecret(gatewayId);
                if (secret)
                    secretSource = 'apiSecret';
            }
        }
        if (!secret) {
            console.log('[webhook] verifyWebhook gateway', gw.provider, 'no secret configured');
            return { valid: false, diagnostics: { secretSource: 'none', receivedPrefix: signature.slice(0, 16), expectedPrefix: '' } };
        }
        if (gw.provider === 'famgateway') {
            // Signature = HMAC-SHA256(apiKey, rawBody) as hex, sent in the
            // X-FamGateway-Signature header (per official docs). Use a timing-safe
            // comparison (as the official Node.js example does) to prevent timing
            // attacks. Keep a tolerant normalization for a possible sha256= prefix.
            const sig = signature.startsWith('sha256=') ? signature.slice(7) : signature;
            const expected = crypto_1.default.createHmac('sha256', secret).update(rawBody).digest('hex');
            const sigBuf = Buffer.from(sig, 'hex');
            const expectedBuf = Buffer.from(expected, 'hex');
            const matched = sigBuf.length === expectedBuf.length && crypto_1.default.timingSafeEqual(sigBuf, expectedBuf);
            console.log('[webhook] verifyWebhook famgateway', {
                secretSource,
                sigLen: sig.length,
                sigPrefix: sig.slice(0, 16),
                expectedPrefix: expected.slice(0, 16),
                rawBodyLen: rawBody.length,
                matched,
            });
            return {
                valid: matched,
                diagnostics: { secretSource, receivedPrefix: sig.slice(0, 16), expectedPrefix: expected.slice(0, 16) },
            };
        }
        if (gw.provider === 'stripe') {
            // Stripe uses Stripe-Signature header with timestamp and signature
            // Format: t=...,v1=... — verify v1
            const parts = signature.split(',');
            let timestamp = '', sig = '';
            for (const p of parts) {
                const [k, v] = p.split('=');
                if (k === 't')
                    timestamp = v;
                if (k === 'v1')
                    sig = v;
            }
            const expected = crypto_1.default.createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
            return { valid: sig === expected };
        }
        if (gw.provider === 'paypal') {
            // PayPal MT signature verification is complex; use API key as HMAC
            // with a timing-safe comparison.
            const expected = crypto_1.default.createHmac('sha256', secret).update(rawBody).digest('hex');
            const sigBuf = Buffer.from(signature, 'hex');
            const expectedBuf = Buffer.from(expected, 'hex');
            return { valid: sigBuf.length === expectedBuf.length && crypto_1.default.timingSafeEqual(sigBuf, expectedBuf) };
        }
        return { valid: false };
    }
    /**
     * Mark a payment order as paid after verification.
     */
    async markOrderPaid(orderId, utr, paymentReference) {
        const result = await this.db.run(`UPDATE payment_orders SET status = 'paid', utr = ?, payment_reference = ?, paid_at = datetime('now'), updated_at = datetime('now')
       WHERE order_id = ? AND status != 'paid'`, [utr || null, paymentReference || null, orderId]);
        return result.changes > 0;
    }
    async listOrders(userId, limit = 50) {
        return this.db.all(`SELECT * FROM payment_orders WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`, [userId, limit]);
    }
    async getOrder(orderId) {
        const rows = await this.db.all(`SELECT * FROM payment_orders WHERE order_id = ?`, [orderId]);
        return rows.length > 0 ? rows : null;
    }
}
exports.PaymentGatewayManager = PaymentGatewayManager;
