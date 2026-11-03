/**
 * ConFuse Auth Middleware - Billing & Subscription Routes
 *
 * Mounted at /api/v1/billing (see index.ts): public plans catalogue,
 * authenticated subscription/usage + upgrade + customer-portal endpoints,
 * a webhook stub (no payment provider wired yet), and internal count-update
 * endpoints (x-api-key) called by the data connectors when repos/docs are
 * added or removed. Tier limits themselves live in services/billing.ts
 * (TIER_CONFIGS).
 */

import { Router, type Request, type Response } from 'express';
import express from 'express';
import { requireAuth } from '../auth.js';
import type { AuthenticatedRequest, Auth0Claims } from '../types/index.js';
import prisma from '../infra/db.js';
import {
    getUserSubscriptionDetails,
    createCheckoutSession,
    getCustomerPortalUrl,
    updateRepoCount,
    updateDocCount,
    TIER_CONFIGS,
} from '../services/billing.js';
import { logger } from '../utils/logger.js';

const billingRouter = Router();

/**
 * Public Plans API endpoint
 */
billingRouter.get('/plans', (_req: Request, res: Response) => {
    const plans = [
        {
            id: 'plan-free',
            name: 'Free',
            tier: 'free',
            price_monthly: 0,
            formatted_price: '₹0/month',
            description: 'For individual developers getting started with code and document intelligence.',
            features: {
                repositories: 'Up to 3 repos',
                documents: 'Up to 4 documents',
                storage: '256 MB max space',
                requests: '80,000 requests/month',
                security: 'Strong security (TLS 1.3, CSP, JWT)',
                team_collaboration: false,
            },
            limits: {
                max_repositories: TIER_CONFIGS.free.maxRepos,
                max_documents: TIER_CONFIGS.free.maxDocs,
                max_storage_bytes: TIER_CONFIGS.free.maxStorageBytes.toString(),
                max_storage_mb: 256,
                max_api_calls_per_month: TIER_CONFIGS.free.maxMonthlyRequests,
                max_connected_users: TIER_CONFIGS.free.maxConnectedUsers,
            },
        },
        {
            id: 'plan-pro',
            name: 'ConFuse Pro',
            tier: 'pro',
            price_monthly: 800,
            formatted_price: '₹800.00/month',
            description: 'For power developers and small projects needing higher storage and limits.',
            features: {
                repositories: 'Up to 5 repos',
                documents: 'Up to 10 documents',
                storage: '512 MB max space',
                requests: '160,000 requests/month',
                security: 'Strong security (TLS 1.3, CSP, JWT)',
                team_collaboration: false,
            },
            limits: {
                max_repositories: TIER_CONFIGS.pro.maxRepos,
                max_documents: TIER_CONFIGS.pro.maxDocs,
                max_storage_bytes: TIER_CONFIGS.pro.maxStorageBytes.toString(),
                max_storage_mb: 512,
                max_api_calls_per_month: TIER_CONFIGS.pro.maxMonthlyRequests,
                max_connected_users: TIER_CONFIGS.pro.maxConnectedUsers,
            },
        },
        {
            id: 'plan-team',
            name: 'ConFuse Team',
            tier: 'team',
            price_monthly: 2300,
            formatted_price: '₹2,300.00/month',
            description: 'For engineering teams requiring shared databases and advanced security controls.',
            features: {
                repositories: 'Up to 10 repos',
                documents: 'Up to 16 documents',
                storage: '1,024 MB (1 GB) max space',
                requests: '320,000 requests/month (main user)',
                connected_users: 'Max 3 connected users (READ-ONLY access)',
                security: 'Advanced Security & RBAC read-only db tokens',
                team_collaboration: true,
            },
            limits: {
                max_repositories: TIER_CONFIGS.team.maxRepos,
                max_documents: TIER_CONFIGS.team.maxDocs,
                max_storage_bytes: TIER_CONFIGS.team.maxStorageBytes.toString(),
                max_storage_mb: 1024,
                max_api_calls_per_month: TIER_CONFIGS.team.maxMonthlyRequests,
                max_connected_users: TIER_CONFIGS.team.maxConnectedUsers,
            },
        },
        {
            id: 'plan-enterprise',
            name: 'ConFuse Enterprise',
            tier: 'enterprise',
            price_monthly: 4000,
            formatted_price: '₹4,000.00+/month',
            description: 'For organizations needing high scale, custom quotas, and dedicated infrastructure.',
            features: {
                repositories: 'Custom / Unlimited repos',
                documents: 'Custom / Unlimited documents',
                storage: 'Dedicated Storage Quota (> 5 GB+)',
                requests: 'Custom High-Throughput (1,000,000+ req/mo)',
                connected_users: 'Unlimited Read Seats & Multi-User Admin Write Roles',
                security: 'Enterprise Security (SAML/SSO, Custom VPC/IP Isolation, Dedicated SLA)',
                team_collaboration: true,
            },
            limits: {
                max_repositories: null,
                max_documents: null,
                max_storage_bytes: TIER_CONFIGS.enterprise.maxStorageBytes.toString(),
                max_storage_mb: 5120,
                max_api_calls_per_month: TIER_CONFIGS.enterprise.maxMonthlyRequests,
                max_connected_users: TIER_CONFIGS.enterprise.maxConnectedUsers,
            },
        },
    ];

    res.json(plans);
});

/**
 * Get current user subscription details
 */
billingRouter.get('/subscription', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const user = await prisma.user.findUnique({
            where: { auth0Sub: claims.sub },
            select: { id: true },
        });

        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        const details = await getUserSubscriptionDetails(user.id);
        res.json({ success: true, data: details });
    } catch (error) {
        logger.error('[BILLING] Error getting subscription:', error);
        res.status(500).json({ error: 'Internal server error', details: error instanceof Error ? error.message : String(error) });
    }
});

/**
 * Create checkout session for upgrading tier
 */
billingRouter.post('/checkout', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const { tier } = req.body;

        if (!tier || !['pro', 'team', 'enterprise'].includes(tier)) {
            res.status(400).json({ error: 'Invalid tier specified' });
            return;
        }

        const user = await prisma.user.findUnique({
            where: { auth0Sub: claims.sub },
            select: { id: true },
        });

        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        const result = await createCheckoutSession(user.id, tier);
        res.json({ success: true, data: result });
    } catch (error) {
        logger.error('[BILLING] Error creating checkout:', error);
        res.status(500).json({ error: 'Internal server error', details: error instanceof Error ? error.message : String(error) });
    }
});

/**
 * Direct subscription upgrade endpoint (for completing tier updates / test card checkout validation)
 */
billingRouter.post('/upgrade', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const { tier } = req.body;

        if (!tier || !['free', 'pro', 'team', 'enterprise'].includes(tier)) {
            res.status(400).json({ error: 'Invalid tier specified' });
            return;
        }

        const user = await prisma.user.findUnique({
            where: { auth0Sub: claims.sub },
            select: { id: true },
        });

        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        const endsAt = new Date(Date.now() + 30 * 24 * 3600 * 1000); // 30 days from now

        await prisma.user.update({
            where: { id: user.id },
            data: {
                subscriptionTier: tier,
                subscriptionStatus: 'active',
                subscriptionEndsAt: endsAt,
            },
        });

        const details = await getUserSubscriptionDetails(user.id);
        res.json({ success: true, message: `Successfully upgraded to ${tier} tier`, data: details });
    } catch (error) {
        logger.error('[BILLING] Error upgrading user tier:', error);
        res.status(500).json({ error: 'Internal server error', details: error instanceof Error ? error.message : String(error) });
    }
});

/**
 * Get customer portal session link
 */
billingRouter.post('/portal', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const user = await prisma.user.findUnique({
            where: { auth0Sub: claims.sub },
            select: { id: true },
        });

        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        const result = await getCustomerPortalUrl(user.id);
        res.json({ success: true, data: result });
    } catch (error) {
        logger.error('[BILLING] Error getting portal:', error);
        res.status(500).json({ error: 'Internal server error', details: error instanceof Error ? error.message : String(error) });
    }
});

/**
 * Billing Webhook Receiver Stub
 */
billingRouter.post('/webhook', express.raw({ type: 'application/json' }), async (_req: Request, res: Response) => {
    res.status(200).json({ success: true, message: 'Webhook endpoint active' });
});

/**
 * Internal API: Update repository count for a user
 * Called by data connector services when repositories are added/removed
 */
billingRouter.post('/internal/update-repo-count', async (req: Request, res: Response) => {
    try {
        const { userId, delta } = req.body;

        if (!userId || typeof delta !== 'number') {
            res.status(400).json({ error: 'Invalid request: userId and delta required' });
            return;
        }

        // Validate internal API key
        const apiKey = req.headers['x-api-key'] as string;
        const config = (await import('../config.js')).config;
        if (apiKey !== config.internalApiKey) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }

        await updateRepoCount(userId, delta);
        res.json({ success: true });
    } catch (error) {
        logger.error('[BILLING] Error updating repo count:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * Internal API: Update document count for a user
 * Called by data connector services when documents are added/removed
 */
billingRouter.post('/internal/update-doc-count', async (req: Request, res: Response) => {
    try {
        const { userId, delta } = req.body;

        if (!userId || typeof delta !== 'number') {
            res.status(400).json({ error: 'Invalid request: userId and delta required' });
            return;
        }

        // Validate internal API key
        const apiKey = req.headers['x-api-key'] as string;
        const config = (await import('../config.js')).config;
        if (apiKey !== config.internalApiKey) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }

        await updateDocCount(userId, delta);
        res.json({ success: true });
    } catch (error) {
        logger.error('[BILLING] Error updating doc count:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default billingRouter;
