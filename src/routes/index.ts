/**
 * ConFuse Auth Middleware - Health & User Routes
 *
 * Consolidates health and onboarding/user routes to reduce file count:
 *   healthRouter — GET / (liveness) and GET /health (bounded DB probe)
 *   userRouter   — GET/POST /onboarding, DELETE / (account deletion)
 * Mounted at / and /api/v1/user respectively (see index.ts).
 */

import { Router, type Request, type Response } from 'express';
import prisma, { probeDatabaseHealth } from '../infra/db.js';
import { requireAuth } from '../auth.js';
import { createUserGraph } from '../services/user-graph.js';
import { logger } from '../utils/logger.js';
import type { AuthenticatedRequest, Auth0Claims } from '../types/index.js';

// Health routes
const healthRouter = Router();

healthRouter.get('/', (_req: Request, res: Response) => {
    res.status(200).send('OK');
});

healthRouter.get('/health', async (_req: Request, res: Response) => {
    // Bounded probe: /health is a liveness endpoint (Docker HEALTHCHECK 10 s,
    // LB probes, test harness 3 s) — it must answer even when the DB connect
    // is slow, reporting 'timeout' instead of blocking the request.
    const dbStatus = await probeDatabaseHealth();

    res.json({
        status: 'healthy',
        service: 'auth-middleware',
        database: dbStatus,
        timestamp: new Date().toISOString(),
    });
});

// User routes
const userRouter = Router();

userRouter.get('/onboarding', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const user = await prisma.user.findUnique({
            where: { auth0Sub: claims.sub },
            select: {
                onboardingCompleted: true,
                userIntent: true,
                dashboardPreset: true,
            }
        });

        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        res.json({
            success: true,
            data: user,
        });
    } catch (error) {
        logger.error('[ONBOARDING] GET error:', error);
        res.status(500).json({ error: 'Internal server error', details: error instanceof Error ? error.message : String(error) });
    }
});

userRouter.post('/onboarding', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const { userIntent, dashboardPreset, onboardingCompleted } = req.body;

        const user = await prisma.user.update({
            where: { auth0Sub: claims.sub },
            data: {
                userIntent,
                dashboardPreset,
                onboardingCompleted: onboardingCompleted ?? true,
            },
            select: {
                onboardingCompleted: true,
                userIntent: true,
                dashboardPreset: true,
            }
        });

        res.json({
            success: true,
            data: user,
        });
    } catch (error) {
        logger.error('[ONBOARDING] POST error:', error);
        res.status(500).json({ error: 'Internal server error', details: error instanceof Error ? error.message : String(error) });
    }
});

/**
 * GET /graph/setup — the user's knowledge-graph storage choice.
 *
 * Graphs are deliberately NOT provisioned at signup/login: the dashboard asks
 * the user to choose between a ConFuse-managed graph and BYODB, and only then
 * is a graph created. The choice lives in UserPreference.customSettings.
 */
userRouter.get('/graph/setup', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
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

        const pref = await prisma.userPreference.findUnique({
            where: { userId: user.id },
            select: { customSettings: true },
        });
        const settings = (pref?.customSettings ?? {}) as Record<string, unknown>;

        res.json({
            success: true,
            data: { mode: typeof settings['graphSetup'] === 'string' ? settings['graphSetup'] : null },
        });
    } catch (error) {
        logger.error('[GRAPH-SETUP] GET error:', error);
        res.status(500).json({ error: 'Internal server error', details: error instanceof Error ? error.message : String(error) });
    }
});

/**
 * POST /graph/setup — record the choice; provision only on 'managed'.
 *
 * This is the ONLY place the per-user `graph-<userId>` graph is created —
 * 'byodb' defers storage to a customer-owned FalkorDB configured through the
 * BYODB flow.
 */
userRouter.post('/graph/setup', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const { mode } = req.body as { mode?: string };

        if (mode !== 'managed' && mode !== 'byodb') {
            res.status(400).json({ error: "Invalid mode: expected 'managed' or 'byodb'" });
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

        if (mode === 'managed') {
            await createUserGraph(user.id);
        }

        const existing = await prisma.userPreference.findUnique({
            where: { userId: user.id },
        });
        const currentSettings = (existing?.customSettings ?? {}) as Record<string, unknown>;
        const nextSettings = { ...currentSettings, graphSetup: mode };

        const pref = existing
            ? await prisma.userPreference.update({
                  where: { userId: user.id },
                  data: { customSettings: nextSettings },
                  select: { customSettings: true },
              })
            : await prisma.userPreference.create({
                  data: { userId: user.id, customSettings: nextSettings },
                  select: { customSettings: true },
              });
        const settings = (pref?.customSettings ?? {}) as Record<string, unknown>;

        res.json({
            success: true,
            data: { mode: typeof settings['graphSetup'] === 'string' ? settings['graphSetup'] : mode },
        });
    } catch (error) {
        logger.error('[GRAPH-SETUP] POST error:', error);
        res.status(500).json({ error: 'Internal server error', details: error instanceof Error ? error.message : String(error) });
    }
});

userRouter.delete('/', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        
        // Find the internal user ID securely mapped from the verified Auth0 subject
        const user = await prisma.user.findUnique({
            where: { auth0Sub: claims.sub },
            select: { id: true }
        });

        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        const { deleteUserAccount } = await import('../services/user.js');
        await deleteUserAccount(user.id);

        res.json({
            success: true,
            message: 'User account and associated data successfully deleted.'
        });
    } catch (error) {
        logger.error('[USER_DELETE] DELETE error:', error);
        res.status(500).json({ error: 'Internal server error', details: error instanceof Error ? error.message : String(error) });
    }
});

export { healthRouter, userRouter };
