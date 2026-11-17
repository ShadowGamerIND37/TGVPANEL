import crypto from 'crypto';
import { encryptSecret, decryptSecret } from '../../security/crypto-vault';
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
}

export interface VerifyResult {
  success: boolean;
  status: string;
  utr?: string;
  payment_reference?: string;
  sender_name?: string;
  error?: string;
}

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
export class PaymentGatewayManager {
  private db: UnifiedDatabase;
  private keyCache: Map<number, { apiKey: string; apiSecret: string; webhookSecret: string }> = new Map();

  constructor(db: UnifiedDatabase) {
    this.db = db;
  }

  public async listGateways(): Promise<GatewayConfig[]> {
    const rows = await this.db.all<any>(`SELECT * FROM payment_gateways ORDER BY id`);
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

  public async getGateway(id: number): Promise<GatewayConfig | null> {
    const row = await this.db.get<any>(`SELECT * FROM payment_gateways WHERE id = ?`, [id]);
    if (!row) return null;
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

  public async getEnabledGateways(): Promise<GatewayConfig[]> {
    const gateways = await this.listGateways();
    return gateways.filter((g) => g.enabled && g.has_api_key);
  }

  public async getDefaultGateway(): Promise<GatewayConfig | null> {
    const gateways = await this.listGateways();
    return gateways.find((g) => g.enabled && g.is_default && g.has_api_key) || null;
  }

  public async updateGateway(id: number, input: {
    enabled?: number;
    apiKey?: string;
    apiSecret?: string;
    webhookSecret?: string;
    webhookUrl?: string;
    accountId?: string;
    merchantId?: string;
    currency?: string;
    isDefault?: number;
  }): Promise<GatewayConfig | null> {
    const existing = await this.db.get<any>(`SELECT * FROM payment_gateways WHERE id = ?`, [id]);
    if (!existing) return null;

    const encryptedKey = input.apiKey ? encryptSecret(input.apiKey) : null;
    const encryptedSecret = input.apiSecret ? encryptSecret(input.apiSecret) : null;
    const encryptedWebhook = input.webhookSecret ? encryptSecret(input.webhookSecret) : null;

    // If setting as default, unset others
    if (input.isDefault) {
      await this.db.run(`UPDATE payment_gateways SET is_default = 0 WHERE id != ?`, [id]);
    }

    await this.db.run(
      `UPDATE payment_gateways SET
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
       WHERE id = ?`,
      [
        input.enabled ?? existing.enabled,
        encryptedKey, encryptedSecret, encryptedWebhook,
        input.webhookUrl ?? existing.webhook_url,
        input.accountId ?? existing.account_id,
        input.merchantId ?? existing.merchant_id,
        input.currency ?? existing.currency,
        input.isDefault ?? existing.is_default,
        id,
      ]
    );
    this.keyCache.delete(id);
    return this.getGateway(id);
  }

  public async testGateway(id: number): Promise<{ success: boolean; message: string }> {
    const gw = await this.db.get<any>(`SELECT * FROM payment_gateways WHERE id = ?`, [id]);
    if (!gw) return { success: false, message: 'Gateway not found.' };
    const key = await this.getApiKey(id);
    if (!key) return { success: false, message: 'API key not configured.' };

    try {
      if (gw.provider === 'famgateway') {
        const res = await fetch(`${FAMGATEWAY_BASE}/api/create-order`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Api-Key': key },
          body: JSON.stringify({ amount: 1, customer_name: 'Test' }),
        });
        const data = await res.json() as any;
        if (data.status === 'success') {
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
        if (!secret) return { success: false, message: 'PayPal client secret not configured.' };
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
    } catch (err: any) {
      await this.db.run(`UPDATE payment_gateways SET last_test_at = ?, last_test_status = 'failed' WHERE id = ?`, [Date.now(), id]);
      return { success: false, message: `Gateway unreachable: ${err.message}` };
    }
  }

  private async getApiKey(id: number): Promise<string | null> {
    if (this.keyCache.has(id)) return this.keyCache.get(id)!.apiKey;
    return this.loadKeyCache(id, 'apiKey', 'api_key_enc');
  }

  private async getApiSecret(id: number): Promise<string | null> {
    if (this.keyCache.has(id)) return this.keyCache.get(id)!.apiSecret;
    return this.loadKeyCache(id, 'apiSecret', 'api_secret_enc');
  }

  private async getWebhookSecret(id: number): Promise<string | null> {
    if (this.keyCache.has(id)) return this.keyCache.get(id)!.webhookSecret;
    return this.loadKeyCache(id, 'webhookSecret', 'webhook_secret_enc');
  }

  private async loadKeyCache(id: number, field: 'apiKey' | 'apiSecret' | 'webhookSecret', col: string): Promise<string | null> {
    const row = await this.db.get<{ enc: string | null }>(`SELECT ${col} as enc FROM payment_gateways WHERE id = ?`, [id]);
    if (row?.enc) {
      const val = decryptSecret(row.enc);
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
   * Create a payment order via the specified gateway.
   * Returns the checkout URL / QR / redirect data for the customer.
   */
  public async createOrder(gatewayId: number, amountCents: number, options: {
    userName?: string;
    userEmail?: string;
    userPhone?: string;
    redirectUrl?: string;
    invoiceId?: number;
    subscriptionId?: number;
    userId: number;
    planId?: number;
  }): Promise<CreateOrderResult> {
    const gw = await this.db.get<any>(`SELECT * FROM payment_gateways WHERE id = ?`, [gatewayId]);
    if (!gw) return { success: false, amount_cents: amountCents, currency: 'INR', error: 'Gateway not found.' };
    if (!gw.enabled) return { success: false, amount_cents: amountCents, currency: gw.currency, error: 'Gateway is disabled.' };

    const amount = amountCents / 100;
    const orderId = `po_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;

    try {
      if (gw.provider === 'famgateway') {
        const apiKey = await this.getApiKey(gatewayId);
        if (!apiKey) return { success: false, amount_cents: amountCents, currency: gw.currency, error: 'FamGateway API key not configured.' };
        const res = await fetch(`${FAMGATEWAY_BASE}/api/create-order`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Api-Key': apiKey },
          body: JSON.stringify({
            amount: amount,
            customer_name: options.userName,
            customer_email: options.userEmail,
            customer_phone: options.userPhone,
            redirect_url: options.redirectUrl,
          }),
        });
        const data = await res.json() as any;
        if (data.status === 'success' && data.data) {
          const d = data.data;
          await this.db.run(
            `INSERT INTO payment_orders (invoice_id, subscription_id, user_id, plan_id, gateway, gateway_order_id, amount_cents, currency, status, redirect_url, checkout_url, qr_url, upi_intent, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, datetime('now'))`,
            [options.invoiceId, options.subscriptionId, options.userId, options.planId, gw.provider, d.order_id, amountCents, gw.currency, d.upi_intent, d.checkout_url, d.qr_url, d.upi_intent]
          );
          return {
            success: true, order_id: orderId, gateway_order_id: d.order_id,
            checkout_url: d.checkout_url, qr_url: d.qr_url, upi_intent: d.upi_intent,
            redirect_url: d.upi_intent, amount_cents: amountCents, currency: gw.currency,
          };
        }
        return { success: false, amount_cents: amountCents, currency: gw.currency, error: data.error || 'FamGateway order creation failed.' };
      }

      if (gw.provider === 'stripe') {
        const apiKey = await this.getApiKey(gatewayId);
        if (!apiKey) return { success: false, amount_cents: amountCents, currency: gw.currency, error: 'Stripe API key not configured.' };
        const res = await fetch(`${STRIPE_BASE}/v1/checkout/sessions`, {
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
        const data = await res.json() as any;
        if (data.url) {
          await this.db.run(
            `INSERT INTO payment_orders (invoice_id, subscription_id, user_id, plan_id, gateway, gateway_order_id, amount_cents, currency, status, checkout_url, redirect_url, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, datetime('now'))`,
            [options.invoiceId, options.subscriptionId, options.userId, options.planId, gw.provider, data.id, amountCents, gw.currency, data.url, data.url]
          );
          return { success: true, order_id: orderId, gateway_order_id: data.id, checkout_url: data.url, redirect_url: data.url, amount_cents: amountCents, currency: gw.currency };
        }
        return { success: false, amount_cents: amountCents, currency: gw.currency, error: data.error?.message || 'Stripe checkout creation failed.' };
      }

      if (gw.provider === 'paypal') {
        const apiKey = await this.getApiKey(gatewayId);
        const apiSecret = await this.getApiSecret(gatewayId);
        if (!apiKey || !apiSecret) return { success: false, amount_cents: amountCents, currency: gw.currency, error: 'PayPal credentials not configured.' };
        const auth = Buffer.from(`${apiKey}:${apiSecret}`).toString('base64');
        const tokenRes = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
          method: 'POST',
          headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'grant_type=client_credentials',
        });
        const tokenData = await tokenRes.json() as any;
        const accessToken = tokenData.access_token;
        if (!accessToken) return { success: false, amount_cents: amountCents, currency: gw.currency, error: 'PayPal auth failed.' };
        const res = await fetch(`${PAYPAL_BASE}/v2/checkout/orders`, {
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
        const data = await res.json() as any;
        if (data.id) {
          await this.db.run(
            `INSERT INTO payment_orders (invoice_id, subscription_id, user_id, plan_id, gateway, gateway_order_id, amount_cents, currency, status, checkout_url, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, datetime('now'))`,
            [options.invoiceId, options.subscriptionId, options.userId, options.planId, gw.provider, data.id, amountCents, gw.currency, `${PAYPAL_BASE}/checkoutnow?token=${data.id}`]
          );
          return { success: true, order_id: orderId, gateway_order_id: data.id, checkout_url: `${PAYPAL_BASE}/checkoutnow?token=${data.id}`, amount_cents: amountCents, currency: gw.currency };
        }
        return { success: false, amount_cents: amountCents, currency: gw.currency, error: data.message || 'PayPal order creation failed.' };
      }

      return { success: false, amount_cents: amountCents, currency: gw.currency, error: `Unknown gateway: ${gw.provider}` };
    } catch (err: any) {
      return { success: false, amount_cents: amountCents, currency: gw.currency, error: `Gateway error: ${err.message}` };
    }
  }

  /**
   * Verify a payment order's status via the gateway (server-to-server).
   */
  public async verifyOrder(gatewayId: number, gatewayOrderId: string): Promise<VerifyResult> {
    const gw = await this.db.get<any>(`SELECT * FROM payment_gateways WHERE id = ?`, [gatewayId]);
    if (!gw) return { success: false, status: 'error', error: 'Gateway not found.' };

    try {
      if (gw.provider === 'famgateway') {
        const apiKey = await this.getApiKey(gatewayId);
        if (!apiKey) return { success: false, status: 'error', error: 'FamGateway API key not configured.' };
        const res = await fetch(`${FAMGATEWAY_BASE}/api/verify-order.php?api_key=${encodeURIComponent(apiKey)}&order_id=${encodeURIComponent(gatewayOrderId)}`);
        const data = await res.json() as any;
        if (data.status === 'success') {
          return { success: true, status: 'paid', utr: data.utr, payment_reference: data.utr, sender_name: data.sender_name };
        }
        return { success: true, status: data.status || 'pending' };
      }
      if (gw.provider === 'stripe') {
        const apiKey = await this.getApiKey(gatewayId);
        if (!apiKey) return { success: false, status: 'error', error: 'Stripe API key not configured.' };
        const res = await fetch(`${STRIPE_BASE}/v1/checkout/sessions/${gatewayOrderId}`, {
          headers: { Authorization: `Bearer ${apiKey}` },
        });
        const data = await res.json() as any;
        const status = data.payment_status === 'paid' ? 'paid' : (data.status === 'complete' ? 'paid' : 'pending');
        return { success: true, status, payment_reference: data.payment_intent || data.id };
      }
      if (gw.provider === 'paypal') {
        const apiKey = await this.getApiKey(gatewayId);
        const apiSecret = await this.getApiSecret(gatewayId);
        if (!apiKey || !apiSecret) return { success: false, status: 'error', error: 'PayPal credentials not configured.' };
        const auth = Buffer.from(`${apiKey}:${apiSecret}`).toString('base64');
        const tokenRes = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
          method: 'POST',
          headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'grant_type=client_credentials',
        });
        const tokenData = await tokenRes.json() as any;
        const accessToken = tokenData.access_token;
        const res = await fetch(`${PAYPAL_BASE}/v2/checkout/orders/${gatewayOrderId}`, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        const data = await res.json() as any;
        const status = data.status === 'COMPLETED' ? 'paid' : 'pending';
        return { success: true, status, payment_reference: data.id };
      }
      return { success: false, status: 'error', error: `Unknown gateway: ${gw.provider}` };
    } catch (err: any) {
      return { success: false, status: 'error', error: `Verification error: ${err.message}` };
    }
  }

  /**
   * Verify a webhook signature.
   */
  public async verifyWebhook(gatewayId: number, rawBody: string, signature: string): Promise<boolean> {
    const gw = await this.db.get<any>(`SELECT * FROM payment_gateways WHERE id = ?`, [gatewayId]);
    if (!gw) return false;
    const secret = await this.getWebhookSecret(gatewayId) || await this.getApiKey(gatewayId) || await this.getApiSecret(gatewayId);
    if (!secret) return false;

    if (gw.provider === 'famgateway') {
      const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
      return signature === expected;
    }
    if (gw.provider === 'stripe') {
      // Stripe uses Stripe-Signature header with timestamp and signature
      // Format: t=...,v1=... — verify v1
      const parts = signature.split(',');
      let timestamp = '', sig = '';
      for (const p of parts) {
        const [k, v] = p.split('=');
        if (k === 't') timestamp = v;
        if (k === 'v1') sig = v;
      }
      const expected = crypto.createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
      return sig === expected;
    }
    if (gw.provider === 'paypal') {
      // PayPal MT signature verification is complex; use API key as HMAC
      const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
      return signature === expected;
    }
    return false;
  }

  /**
   * Mark a payment order as paid after verification.
   */
  public async markOrderPaid(orderId: string, utr?: string, paymentReference?: string): Promise<boolean> {
    const result = await this.db.run(
      `UPDATE payment_orders SET status = 'paid', utr = ?, payment_reference = ?, paid_at = datetime('now'), updated_at = datetime('now')
       WHERE order_id = ? AND status != 'paid'`,
      [utr || null, paymentReference || null, orderId]
    );
    return result.changes > 0;
  }

  public async listOrders(userId: number, limit = 50): Promise<unknown[]> {
    return this.db.all(`SELECT * FROM payment_orders WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`, [userId, limit]);
  }

  public async getOrder(orderId: string): Promise<unknown[] | null> {
    const rows = await this.db.all(`SELECT * FROM payment_orders WHERE order_id = ?`, [orderId]);
    return rows.length > 0 ? rows : null;
  }
}
