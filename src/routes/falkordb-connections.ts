/**
 * ConFuse Auth Middleware - Customer-owned FalkorDB Connection Routes
 *
 * Public API (user JWT via requireAuth):
 *   GET    /falkordb-connections            — list connections (public DTOs)
 *   POST   /falkordb-connections/test       — test an unsaved payload
 *   POST   /falkordb-connections            — verify + create
 *   GET    /falkordb-connections/:id        — get one connection
 *   PATCH  /falkordb-connections/:id        — update (secret rotation/clear)
 *   DELETE /falkordb-connections/:id        — delete + purge secrets
 *   POST   /falkordb-connections/:id/test   — re-test a saved connection
 *
 * Internal API (x-internal-api-key):
 *   POST   /falkordb-connections/internal/:id/resolve — decrypted resolve
 *           for data-plane services. NEVER proxy this to the browser.
 */

import { Router, type Response } from 'express';
import { requireAuth } from '../auth.js';
import type { AuthenticatedRequest, Auth0Claims } from '../types/index.js';
import { config } from '../config.js';
import prisma from '../infra/db.js';
import { logger } from '../utils/logger.js';
import { safeEquals } from '../services/secret-store.js';
import {
    FalkorDbInputError,
    createConnection,
    deleteConnection,
    getConnection,
    listConnections,
    resolveFalkorDbConnection,
    testConnectionPayload,
    testSavedConnection,
    updateConnection,
} from '../services/falkordb/connections.js';

export const falkorDbConnectionsRouter = Router();

/** Resolve the internal user ID from the verified Auth0 subject. */
async function resolveCustomerId(claims: Auth0Claims): Promise<string | null> {
    const user = await prisma.user.findUnique({
        where: { auth0Sub: claims.sub },
        select: { id: true },
    });
    return user?.id ?? null;
}

function handleError(res: Response, error: unknown, context: string): void {
    if (error instanceof FalkorDbInputError) {
        void res.status(error.status).json({ error: error.message });
        return;
    }
    logger.error(`[FALKORDB-ROUTES] ${context}`, {
        error: error instanceof Error ? error.message : String(error),
    });
    void res.status(500).json({ error: 'Internal server error' });
}

/**
 * List all FalkorDB connections for the authenticated user.
 */
falkorDbConnectionsRouter.get('/', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const customerId = await resolveCustomerId(claims);
        if (!customerId) return void res.status(401).json({ error: 'User not found' });

        const connections = await listConnections(customerId);
        res.json({ connections });
    } catch (error) {
        handleError(res, error, 'Failed to list connections');
    }
});

/**
 * Test an unsaved connection payload. Nothing is persisted.
 */
falkorDbConnectionsRouter.post('/test', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const customerId = await resolveCustomerId(claims);
        if (!customerId) return void res.status(401).json({ error: 'User not found' });

        const testResult = await testConnectionPayload(req.body ?? {});
        res.json({ testResult });
    } catch (error) {
        handleError(res, error, 'Failed to test connection');
    }
});

/**
 * Get a single connection (public DTO — no secret values).
 */
falkorDbConnectionsRouter.get('/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const customerId = await resolveCustomerId(claims);
        if (!customerId) return void res.status(401).json({ error: 'User not found' });

        const connection = await getConnection(customerId, String(req.params.id));
        if (!connection) return void res.status(404).json({ error: 'Connection not found' });
        res.json({ connection });
    } catch (error) {
        handleError(res, error, 'Failed to get connection');
    }
});

/**
 * Verify + create a connection. When verification fails and the user has not
 * opted into `allowUnverified`, nothing is saved and the test result (with
 * actionable error codes/hints) is returned with HTTP 422.
 */
falkorDbConnectionsRouter.post('/', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const customerId = await resolveCustomerId(claims);
        if (!customerId) return void res.status(401).json({ error: 'User not found' });

        const { connection, testResult } = await createConnection(customerId, req.body ?? {});
        if (!connection) {
            return void res.status(422).json({
                error: 'Connection verification failed — nothing was saved',
                testResult,
            });
        }
        res.status(201).json({ connection, testResult });
    } catch (error) {
        handleError(res, error, 'Failed to create connection');
    }
});

/**
 * Update a connection. Secrets are write-only: send new values to rotate,
 * `clearPassword` / `clearCaCertificate` / `clearClientCertificate` /
 * `clearClientKey` to remove.
 */
falkorDbConnectionsRouter.patch('/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const customerId = await resolveCustomerId(claims);
        if (!customerId) return void res.status(401).json({ error: 'User not found' });

        const connection = await updateConnection(customerId, String(req.params.id), req.body ?? {});
        res.json({ connection });
    } catch (error) {
        if (error instanceof FalkorDbInputError && error.message === 'Connection not found') {
            return void res.status(404).json({ error: error.message });
        }
        handleError(res, error, 'Failed to update connection');
    }
});

/**
 * Delete a connection and purge its secrets.
 */
falkorDbConnectionsRouter.delete('/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const customerId = await resolveCustomerId(claims);
        if (!customerId) return void res.status(401).json({ error: 'User not found' });

        await deleteConnection(customerId, String(req.params.id));
        res.json({ success: true });
    } catch (error) {
        if (error instanceof FalkorDbInputError && error.message === 'Connection not found') {
            return void res.status(404).json({ error: error.message });
        }
        handleError(res, error, 'Failed to delete connection');
    }
});

/**
 * Re-test a saved connection and record the outcome.
 */
falkorDbConnectionsRouter.post('/:id/test', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const customerId = await resolveCustomerId(claims);
        if (!customerId) return void res.status(401).json({ error: 'User not found' });

        const testResult = await testSavedConnection(customerId, String(req.params.id));
        res.json({ testResult });
    } catch (error) {
        if (error instanceof FalkorDbInputError && error.message === 'Connection not found') {
            return void res.status(404).json({ error: error.message });
        }
        handleError(res, error, 'Failed to test connection');
    }
});

/**
 * INTERNAL service-to-service only: resolve a connection including decrypted
 * credentials. Guarded by the internal API key with a constant-time compare.
 * Never expose this endpoint through the frontend proxy.
 */
falkorDbConnectionsRouter.post('/internal/:id/resolve', async (req: AuthenticatedRequest, res: Response) => {
    const providedKey = String(req.header('x-internal-api-key') ?? '');
    if (!providedKey || !safeEquals(providedKey, config.internalApiKey)) {
        return void res.status(401).json({ error: 'Invalid internal API key' });
    }

    try {
        const customerId = String(req.body?.customerId ?? '');
        if (!customerId) return void res.status(400).json({ error: 'customerId is required' });

        const resolved = await resolveFalkorDbConnection(customerId, String(req.params.id));
        res.json({ resolved });
    } catch (error) {
        if (error instanceof FalkorDbInputError && error.message === 'Connection not found') {
            return void res.status(404).json({ error: error.message });
        }
        handleError(res, error, 'Failed to resolve connection');
    }
});