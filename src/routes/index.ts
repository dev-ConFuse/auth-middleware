/**
 * Consolidated routes for auth-middleware
 * Merges health and onboarding routes to reduce file count
 */

import { Router, type Request, type Response } from 'express';
import prisma, { probeDatabaseHealth } from '../infra/db.js';
import { requireAuth } from '../auth.js';
import { logger } from '../utils/logger.js';
import type { AuthenticatedRequest, Auth0Claims } from '../types/index.js';

// Health routes
const healthRoutes = Router();

healthRoutes.get('/', (_req: Request, res: Response) => {
    res.status(200).send('OK');
});

healthRoutes.get('/health', async (_req: Request, res: Response) => {
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
const userRoutes = Router();

userRoutes.get('/onboarding', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
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

userRoutes.post('/onboarding', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
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

userRoutes.delete('/', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
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

export { healthRoutes, userRoutes };
