"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BillingManager = void 0;
const BILLING_CYCLES = ['monthly', 'yearly', 'one-time'];
const PLAN_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9 _.-]{0,63}$/;
const PAYMENT_METHODS = ['manual', 'admin-verified', 'bank-transfer', 'cheque', 'famgateway', 'stripe', 'paypal'];
/**
 * Internal billing & invoicing manager (Area K).
 *
 * Plans, subscriptions, invoices and a credit ledger. Payments are recorded
 * ONLY after gateway verification (FamGateway/Stripe/PayPal webhook or
 * server-to-server polling) OR an administrator confirms receipt with a
 * verified payment reference. Nothing is marked paid without verified
 * confirmation.
 */
class BillingManager {
    db;
    constructor(db) {
        this.db = db;
    }
    // --- Plans ---
    async listPlans() {
        return this.db.all(`SELECT * FROM billing_plans ORDER BY id ASC`);
    }
    async getPlan(id) {
        return this.db.get(`SELECT * FROM billing_plans WHERE id = ?`, [id]);
    }
    parseFeatures(input) {
        if (input === undefined || input === null || input === '')
            return [];
        let raw = input;
        if (typeof input === 'string') {
            try {
                raw = JSON.parse(input);
            }
            catch {
                throw new Error('features must be a JSON array of strings.');
            }
        }
        if (!Array.isArray(raw))
            throw new Error('features must be an array of strings.');
        return raw.map((f) => String(f));
    }
    validatePlanInput(input, existing) {
        const name = String(input.name ?? existing?.name ?? '').trim();
        if (!PLAN_NAME_RE.test(name)) {
            throw new Error('Plan name must start with an alphanumeric character (max 64 chars).');
        }
        const priceCents = Number(input.priceCents ?? existing?.price_cents ?? 0);
        if (!Number.isInteger(priceCents) || priceCents < 0) {
            throw new Error('priceCents must be a non-negative integer.');
        }
        const cycle = String(input.billingCycle ?? existing?.billing_cycle ?? 'monthly').trim();
        if (!BILLING_CYCLES.includes(cycle)) {
            throw new Error(`billingCycle must be one of: ${BILLING_CYCLES.join(', ')}.`);
        }
        // Validate virtualization type
        const vtype = String(input.virtualizationType ?? existing?.virtualization_type ?? 'lxc').trim().toLowerCase();
        if (!['lxc', 'kvm', 'both'].includes(vtype)) {
            throw new Error("virtualizationType must be one of: 'lxc', 'kvm', 'both'.");
        }
        // Validate specs
        const cpu = input.cpuCores ?? existing?.cpu_cores;
        if (cpu !== undefined && (!Number.isInteger(Number(cpu)) || Number(cpu) < 1)) {
            throw new Error('cpuCores must be a positive integer.');
        }
        const ram = input.ramMb ?? existing?.ram_mb;
        if (ram !== undefined && (!Number.isInteger(Number(ram)) || Number(ram) < 128)) {
            throw new Error('ramMb must be at least 128.');
        }
        const storage = input.storageGb ?? existing?.storage_gb;
        if (storage !== undefined && (!Number.isInteger(Number(storage)) || Number(storage) < 1)) {
            throw new Error('storageGb must be at least 1.');
        }
        const bw = input.bandwidthGb ?? existing?.bandwidth_gb;
        if (bw !== undefined && (!Number.isInteger(Number(bw)) || Number(bw) < 1)) {
            throw new Error('bandwidthGb must be at least 1.');
        }
        const vps = input.vpsCount ?? existing?.vps_count;
        if (vps !== undefined && (!Number.isInteger(Number(vps)) || Number(vps) < 1)) {
            throw new Error('vpsCount must be at least 1.');
        }
        const sla = input.slaPercent ?? existing?.sla_percent;
        if (sla !== undefined && (Number(sla) < 0 || Number(sla) > 100)) {
            throw new Error('slaPercent must be between 0 and 100.');
        }
    }
    async createPlan(input) {
        this.validatePlanInput(input);
        const name = String(input.name).trim();
        const duplicate = await this.db.get(`SELECT id FROM billing_plans WHERE name = ?`, [name]);
        if (duplicate)
            throw new Error(`A plan named '${name}' already exists.`);
        const priceCents = Number(input.priceCents);
        const cycle = String(input.billingCycle || 'monthly').trim();
        const features = this.parseFeatures(input.features);
        await this.db.run(`INSERT INTO billing_plans (name, price_cents, billing_cycle, description, features, is_active, virtualization_type, cpu_cores, ram_mb, storage_gb, bandwidth_gb, vps_count, allowed_os, ports_count, dns_records, backups_included, sla_percent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
            name,
            priceCents,
            cycle,
            input.description ? String(input.description) : null,
            JSON.stringify(features),
            input.isActive === false ? 0 : 1,
            String(input.virtualizationType || 'lxc').toLowerCase(),
            Number(input.cpuCores ?? 1),
            Number(input.ramMb ?? 1024),
            Number(input.storageGb ?? 10),
            Number(input.bandwidthGb ?? 100),
            Number(input.vpsCount ?? 1),
            input.allowedOs ? JSON.stringify(input.allowedOs) : null,
            Number(input.portsCount ?? 0),
            Number(input.dnsRecords ?? 0),
            input.backupsIncluded === false ? 0 : 1,
            Number(input.slaPercent ?? 99.9),
        ]);
        return this.db.get(`SELECT * FROM billing_plans WHERE name = ?`, [name]);
    }
    async updatePlan(id, input) {
        const existing = await this.getPlan(id);
        if (!existing)
            throw new Error('Plan does not exist.');
        this.validatePlanInput(input, existing);
        const name = String(input.name ?? existing.name).trim();
        const duplicate = await this.db.get(`SELECT id FROM billing_plans WHERE name = ? AND id != ?`, [name, id]);
        if (duplicate)
            throw new Error(`A plan named '${name}' already exists.`);
        await this.db.run(`UPDATE billing_plans
       SET name = ?, price_cents = ?, billing_cycle = ?, description = ?, features = ?, is_active = ?,
           virtualization_type = ?, cpu_cores = ?, ram_mb = ?, storage_gb = ?, bandwidth_gb = ?, vps_count = ?,
           allowed_os = ?, ports_count = ?, dns_records = ?, backups_included = ?, sla_percent = ?
       WHERE id = ?`, [
            name,
            Number(input.priceCents ?? existing.price_cents),
            String(input.billingCycle ?? existing.billing_cycle),
            input.description !== undefined ? (input.description ? String(input.description) : null) : existing.description,
            JSON.stringify(this.parseFeatures(input.features ?? JSON.parse(existing.features || '[]'))),
            input.isActive === undefined ? existing.is_active : input.isActive ? 1 : 0,
            input.virtualizationType !== undefined ? String(input.virtualizationType).toLowerCase() : existing.virtualization_type,
            input.cpuCores !== undefined ? Number(input.cpuCores) : existing.cpu_cores,
            input.ramMb !== undefined ? Number(input.ramMb) : existing.ram_mb,
            input.storageGb !== undefined ? Number(input.storageGb) : existing.storage_gb,
            input.bandwidthGb !== undefined ? Number(input.bandwidthGb) : existing.bandwidth_gb,
            input.vpsCount !== undefined ? Number(input.vpsCount) : existing.vps_count,
            input.allowedOs !== undefined ? (input.allowedOs ? JSON.stringify(input.allowedOs) : null) : existing.allowed_os,
            input.portsCount !== undefined ? Number(input.portsCount) : existing.ports_count,
            input.dnsRecords !== undefined ? Number(input.dnsRecords) : existing.dns_records,
            input.backupsIncluded !== undefined ? (input.backupsIncluded ? 1 : 0) : existing.backups_included,
            input.slaPercent !== undefined ? Number(input.slaPercent) : existing.sla_percent,
            id,
        ]);
        return this.getPlan(id);
    }
    async deletePlan(id) {
        const existing = await this.getPlan(id);
        if (!existing)
            return false;
        const activeSubs = await this.db.get(`SELECT COUNT(*) AS count FROM customer_subscriptions WHERE plan_id = ? AND status = 'active'`, [id]);
        if (Number(activeSubs?.count || 0) > 0) {
            throw new Error('Plan has active subscriptions and cannot be deleted.');
        }
        await this.db.run(`DELETE FROM billing_plans WHERE id = ?`, [id]);
        return true;
    }
    // --- Subscriptions ---
    async listSubscriptions() {
        return this.db.all(`SELECT s.*, p.name AS plan_name, p.price_cents, p.billing_cycle,
              u.username AS user_name
       FROM customer_subscriptions s
       JOIN billing_plans p ON p.id = s.plan_id
       JOIN users u ON u.id = s.user_id
       ORDER BY s.id ASC`);
    }
    async getSubscription(id) {
        return this.db.get(`SELECT s.*, p.name AS plan_name, p.price_cents, p.billing_cycle,
              u.username AS user_name
       FROM customer_subscriptions s
       JOIN billing_plans p ON p.id = s.plan_id
       JOIN users u ON u.id = s.user_id
       WHERE s.id = ?`, [id]);
    }
    async computePeriodEnd(cycle, startIso) {
        // startIso is a SQLite datetime string (YYYY-MM-DD HH:MM:SS).
        const sql = cycle === 'yearly'
            ? `datetime(?, '+1 year')`
            : cycle === 'one-time'
                ? `date(?)`
                : `datetime(?, '+1 month')`;
        const row = await this.db.get(`SELECT ${sql} AS end`, [startIso]);
        return row?.end || startIso;
    }
    async createSubscription(input) {
        const userId = Number(input.userId);
        if (!Number.isInteger(userId) || userId < 1)
            throw new Error('userId must be a positive integer.');
        const user = await this.db.get(`SELECT id FROM users WHERE id = ?`, [userId]);
        if (!user)
            throw new Error('User does not exist.');
        const planId = Number(input.planId);
        if (!Number.isInteger(planId) || planId < 1)
            throw new Error('planId must be a positive integer.');
        const plan = await this.getPlan(planId);
        if (!plan)
            throw new Error('Plan does not exist.');
        const nowIso = new Date().toISOString().replace('T', ' ').slice(0, 19);
        const periodEnd = await this.computePeriodEnd(plan.billing_cycle, nowIso);
        const result = await this.db.run(`INSERT INTO customer_subscriptions
        (user_id, plan_id, status, auto_renew, started_at, current_period_start, current_period_end)
       VALUES (?, ?, 'active', ?, datetime('now'), ?, ?)`, [userId, planId, input.autoRenew === false ? 0 : 1, nowIso, periodEnd]);
        const subscriptionId = Number(result.lastID);
        await this.issueInvoiceForSubscription(subscriptionId);
        return this.getSubscription(subscriptionId);
    }
    async cancelSubscription(id) {
        const existing = await this.getSubscription(id);
        if (!existing)
            throw new Error('Subscription does not exist.');
        if (existing.status === 'cancelled')
            return existing;
        await this.db.run(`UPDATE customer_subscriptions
       SET status = 'cancelled', cancelled_at = datetime('now'), updated_at = datetime('now')
       WHERE id = ?`, [id]);
        return this.getSubscription(id);
    }
    async renewSubscription(id) {
        const existing = await this.getSubscription(id);
        if (!existing)
            throw new Error('Subscription does not exist.');
        if (existing.status !== 'active') {
            throw new Error('Only active subscriptions can be renewed.');
        }
        const periodEnd = await this.computePeriodEnd(existing.billing_cycle, existing.current_period_end);
        await this.db.run(`UPDATE customer_subscriptions
       SET current_period_start = current_period_end,
           current_period_end = ?,
           updated_at = datetime('now')
       WHERE id = ?`, [periodEnd, id]);
        await this.issueInvoiceForSubscription(id);
        return this.getSubscription(id);
    }
    // --- Invoices ---
    async listInvoices(userId) {
        if (userId !== undefined) {
            return this.db.all(`SELECT i.*, p.name AS plan_name, u.username AS user_name
         FROM invoices i
         JOIN billing_plans p ON p.id = i.plan_id
         JOIN users u ON u.id = i.user_id
         WHERE i.user_id = ?
         ORDER BY i.id DESC`, [userId]);
        }
        return this.db.all(`SELECT i.*, p.name AS plan_name, u.username AS user_name
       FROM invoices i
       JOIN billing_plans p ON p.id = i.plan_id
       JOIN users u ON u.id = i.user_id
       ORDER BY i.id DESC`);
    }
    async getInvoice(id) {
        return this.db.get(`SELECT i.*, p.name AS plan_name, u.username AS user_name
       FROM invoices i
       JOIN billing_plans p ON p.id = i.plan_id
       JOIN users u ON u.id = i.user_id
       WHERE i.id = ?`, [id]);
    }
    async nextInvoiceNumber() {
        const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
        const row = await this.db.get(`SELECT COUNT(*) AS count FROM invoices WHERE invoice_number LIKE ?`, [`INV-${day}-%`]);
        let seq = Number(row?.count || 0) + 1;
        // Guard against a same-day collision after deletions.
        for (let attempt = 0; attempt < 100; attempt++) {
            const candidate = `INV-${day}-${String(seq).padStart(4, '0')}`;
            const dup = await this.db.get(`SELECT id FROM invoices WHERE invoice_number = ?`, [candidate]);
            if (!dup)
                return candidate;
            seq += 1;
        }
        throw new Error('Unable to allocate a unique invoice number.');
    }
    async issueInvoiceForSubscription(subscriptionId) {
        const subscription = await this.getSubscription(subscriptionId);
        if (!subscription)
            throw new Error('Subscription does not exist.');
        const invoiceNumber = await this.nextInvoiceNumber();
        const result = await this.db.run(`INSERT INTO invoices
        (invoice_number, user_id, subscription_id, plan_id, amount_cents, billing_cycle,
         period_start, period_end, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'issued')`, [
            invoiceNumber,
            subscription.user_id,
            subscription.id,
            subscription.plan_id,
            subscription.price_cents,
            subscription.billing_cycle,
            subscription.current_period_start,
            subscription.current_period_end,
        ]);
        return this.getInvoice(Number(result.lastID));
    }
    /**
     * Records a payment ONLY after administrator-verified confirmation. The
     * caller must supply the payment reference (evidence the payment was
     * verified); no automated payment processing exists.
     */
    async confirmPayment(invoiceId, input, actorId) {
        const invoice = await this.getInvoice(invoiceId);
        if (!invoice)
            throw new Error('Invoice does not exist.');
        if (invoice.status === 'paid')
            throw new Error('Invoice is already paid.');
        if (invoice.status === 'cancelled')
            throw new Error('Cancelled invoices cannot be paid.');
        const paymentReference = String(input.paymentReference ?? '').trim();
        if (!paymentReference) {
            throw new Error('A payment reference (verified confirmation evidence) is required to record payment.');
        }
        const method = String(input.method || 'admin-verified').trim();
        if (!PAYMENT_METHODS.includes(method)) {
            throw new Error(`payment method must be one of: ${PAYMENT_METHODS.join(', ')}.`);
        }
        await this.db.run(`UPDATE invoices
       SET status = 'paid', paid_at = datetime('now'), payment_reference = ?, payment_method = ?,
           updated_at = datetime('now')
       WHERE id = ?`, [paymentReference, method, invoiceId]);
        const balance = await this.getCreditBalance(invoice.user_id);
        await this.db.run(`INSERT INTO credit_ledger (user_id, type, amount_cents, reason, reference, balance_after, created_by)
       VALUES (?, 'payment', ?, ?, ?, ?, ?)`, [
            invoice.user_id,
            invoice.amount_cents,
            `Payment confirmed for invoice ${invoice.invoice_number}`,
            paymentReference,
            balance + invoice.amount_cents,
            actorId,
        ]);
        return this.getInvoice(invoiceId);
    }
    // --- Credit ledger ---
    async listCredits(userId) {
        if (userId !== undefined) {
            return this.db.all(`SELECT * FROM credit_ledger WHERE user_id = ? ORDER BY id DESC`, [userId]);
        }
        return this.db.all(`SELECT * FROM credit_ledger ORDER BY id DESC`);
    }
    async getCreditBalance(userId) {
        const row = await this.db.get(`SELECT COALESCE(SUM(amount_cents), 0) AS total FROM credit_ledger WHERE user_id = ?`, [userId]);
        return Number(row?.total || 0);
    }
    async adjustCredit(input, actorId) {
        const userId = Number(input.userId);
        if (!Number.isInteger(userId) || userId < 1)
            throw new Error('userId must be a positive integer.');
        const user = await this.db.get(`SELECT id FROM users WHERE id = ?`, [userId]);
        if (!user)
            throw new Error('User does not exist.');
        const type = String(input.type ?? '').trim();
        if (!['credit', 'debit'].includes(type)) {
            throw new Error('type must be credit or debit.');
        }
        const amountCents = Number(input.amountCents);
        if (!Number.isInteger(amountCents) || amountCents <= 0) {
            throw new Error('amountCents must be a positive integer.');
        }
        const signed = type === 'credit' ? amountCents : -amountCents;
        const balance = await this.getCreditBalance(userId);
        const balanceAfter = balance + signed;
        if (balanceAfter < 0) {
            throw new Error('Resulting credit balance would be negative.');
        }
        await this.db.run(`INSERT INTO credit_ledger (user_id, type, amount_cents, reason, reference, balance_after, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?)`, [userId, type, amountCents, input.reason ? String(input.reason) : null, null, balanceAfter, actorId]);
        return { userId, type, amountCents, balanceAfter };
    }
    // --- Summary ---
    async getUserBillingSummary(userId) {
        const subscriptions = await this.db.all(`SELECT s.*, p.name AS plan_name FROM customer_subscriptions s
       JOIN billing_plans p ON p.id = s.plan_id
       WHERE s.user_id = ? ORDER BY s.id DESC`, [userId]);
        const invoices = await this.listInvoices(userId);
        const creditBalance = await this.getCreditBalance(userId);
        return { userId, subscriptions, invoices, creditBalance };
    }
}
exports.BillingManager = BillingManager;
