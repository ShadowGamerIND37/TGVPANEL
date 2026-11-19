import { UnifiedDatabase } from '../../db/database';
export interface BillingPlanInput {
    name?: string;
    priceCents?: number;
    billingCycle?: string;
    description?: string;
    features?: string[] | string;
    isActive?: boolean;
    virtualizationType?: string;
    cpuCores?: number;
    ramMb?: number;
    storageGb?: number;
    bandwidthGb?: number;
    vpsCount?: number;
    allowedOs?: string[] | string;
    portsCount?: number;
    dnsRecords?: number;
    backupsIncluded?: boolean;
    slaPercent?: number;
    defaultNodeId?: number | null;
}
export interface SubscriptionInput {
    userId?: number;
    planId?: number;
    autoRenew?: boolean;
    /** When false, the subscription is created as 'pending' and only becomes
     * 'active' after payment is confirmed. Defaults to true (active now). */
    activate?: boolean;
}
export interface PaymentConfirmationInput {
    paymentReference?: string;
    method?: string;
}
export interface CreditAdjustmentInput {
    userId?: number;
    type?: string;
    amountCents?: number;
    reason?: string;
}
/**
 * Internal billing & invoicing manager (Area K).
 *
 * Plans, subscriptions, invoices and a credit ledger. Payments are recorded
 * ONLY after gateway verification (FamGateway/Stripe/PayPal webhook or
 * server-to-server polling) OR an administrator confirms receipt with a
 * verified payment reference. Nothing is marked paid without verified
 * confirmation.
 */
export declare class BillingManager {
    private db;
    constructor(db: UnifiedDatabase);
    listPlans(): Promise<any[]>;
    getPlan(id: number): Promise<any>;
    private parseFeatures;
    private validatePlanInput;
    createPlan(input: BillingPlanInput): Promise<any>;
    updatePlan(id: number, input: BillingPlanInput): Promise<any>;
    deletePlan(id: number): Promise<boolean>;
    listSubscriptions(): Promise<any[]>;
    getSubscription(id: number): Promise<any>;
    private computePeriodEnd;
    createSubscription(input: SubscriptionInput): Promise<any>;
    /**
     * Activate a 'pending' subscription after payment is confirmed. Sets the
     * subscription to 'active', recording the payment confirmation. Used by the
     * store purchase flow so a plan only becomes active once payment is verified
     * (webhook or admin confirmation).
     */
    activateSubscription(id: number, paymentReference?: string): Promise<any>;
    cancelSubscription(id: number): Promise<any>;
    renewSubscription(id: number): Promise<any>;
    listInvoices(userId?: number): Promise<any[]>;
    getInvoice(id: number): Promise<any>;
    private nextInvoiceNumber;
    private issueInvoiceForSubscription;
    /**
     * Records a payment ONLY after administrator-verified confirmation. The
     * caller must supply the payment reference (evidence the payment was
     * verified); no automated payment processing exists.
     */
    confirmPayment(invoiceId: number, input: PaymentConfirmationInput, actorId: number): Promise<any>;
    listCredits(userId?: number): Promise<any[]>;
    getCreditBalance(userId: number): Promise<number>;
    adjustCredit(input: CreditAdjustmentInput, actorId: number): Promise<{
        userId: number;
        type: string;
        amountCents: number;
        balanceAfter: number;
    }>;
    getUserBillingSummary(userId: number): Promise<{
        userId: number;
        subscriptions: any[];
        invoices: any[];
        creditBalance: number;
    }>;
}
