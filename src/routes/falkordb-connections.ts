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
import { createBYODBGraph } from '../services/graph.js';

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

        // Also fetch associated Graph records for each connection
        const connectionIds = connections.map(c => c.id);
        const graphs = await prisma.graph.findMany({
            where: {
                falkorDbConnectionId: { in: connectionIds },
                deletedAt: null,
            },
            select: {
                id: true,
                falkorDbConnectionId: true,
                workspaceId: true,
                name: true,
                type: true,
                status: true,
                createdAt: true,
            },
        });

        // Attach graph info to connections
        const graphByConnectionId = new Map(graphs.map(g => [g.falkorDbConnectionId!, g]));
        const connectionsWithGraph = connections.map(c => ({
            ...c,
            graph: graphByConnectionId.get(c.id) ?? null,
        }));

        res.json({ connections: connectionsWithGraph });
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
 * Get a single connection (public DTO — no secret values). Also returns associated Graph if exists.
 */
falkorDbConnectionsRouter.get('/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const customerId = await resolveCustomerId(claims);
        if (!customerId) return void res.status(401).json({ error: 'User not found' });

        const connection = await getConnection(customerId, String(req.params.id));
        if (!connection) return void res.status(404).json({ error: 'Connection not found' });

        // Also fetch associated Graph record if exists
        const graph = await prisma.graph.findFirst({
            where: { falkorDbConnectionId: String(req.params.id), deletedAt: null },
        });

        res.json({ connection, graph: graph ?? null });
    } catch (error) {
        handleError(res, error, 'Failed to get connection');
    }
});

/**
 * Verify + create a BYODB graph connection. When verification fails and the user has not
 * opted into `allowUnverified`, nothing is saved and the test result (with
 * actionable error codes/hints) is returned with HTTP 422.
 * 
 * Requires `workspaceId` in the request body to associate the graph with a workspace.
 */
falkorDbConnectionsRouter.post('/', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const customerId = await resolveCustomerId(claims);
        if (!customerId) return void res.status(401).json({ error: 'User not found' });

        // Extract workspaceId from request body
        const workspaceId = req.body?.workspaceId;
        if (!workspaceId) {
            return void res.status(400).json({ error: 'workspaceId is required' });
        }

        // At most ONE customer-owned (BYODB) connection per workspace — the
        // platform allows one ConFuse-managed graph AND one BYODB connection per workspace,
        // never two of either.
        const existingGraph = await prisma.graph.findFirst({
            where: {
                workspaceId,
                type: 'BYODB',
                deletedAt: null,
            },
        });
        if (existingGraph) {
            return void res.status(409).json({
                error: 'BYODB_LIMIT_REACHED: workspace already has a BYODB graph',
            });
        }

        // Use the Graph service which creates BOTH the FalkorDbConnection AND the Graph record
        const graph = await createBYODBGraph({
            workspaceId,
            name: req.body.name,
            host: req.body.host,
            port: req.body.port,
            username: req.body.username,
            password: req.body.password,
            graphName: req.body.graphName,
            tlsEnabled: req.body.tlsEnabled ?? false,
            caCertificate: req.body.caCertificate,
            deploymentType: req.body.deploymentType ?? 'cloud',
            userId: customerId,
        });

        const testResult = {
            success: true,
            steps: ['Graph record created', 'FalkorDB connection created'],
            message: 'BYODB graph created successfully',
        };

        res.status(201).json({ graph, testResult });
    } catch (error) {
        if (error instanceof Error && error.message === 'GRAPH_LIMIT_REACHED: Workspace already has a BYODB graph') {
            return void res.status(409).json({ error: 'BYODB_LIMIT_REACHED: workspace already has a BYODB graph' });
        }
        handleError(res, error, 'Failed to create BYODB graph');
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
 * Delete a connection and purge its secrets. Also deletes the associated Graph record.
 */
falkorDbConnectionsRouter.delete('/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const customerId = await resolveCustomerId(claims);
        if (!customerId) return void res.status(401).json({ error: 'User not found' });

        // First, find the Graph record associated with this connection
        const graph = await prisma.graph.findFirst({
            where: { falkorDbConnectionId: String(req.params.id), deletedAt: null },
        });

        // Delete the FalkorDB connection (which also purges secrets)
        await deleteConnection(customerId, String(req.params.id));

        // If there's an associated Graph record, soft-delete it
        if (graph) {
            await prisma.graph.update({
                where: { id: graph.id },
                data: {
                    status: 'DELETED',
                    deletedAt: new Date(),
                },
            });

            // Clear workspace's activeGraphId if it points to this graph
            const workspace = await prisma.workspace.findUnique({
                where: { id: graph.workspaceId },
            });
            if (workspace?.activeGraphId === graph.id) {
                await prisma.workspace.update({
                    where: { id: graph.workspaceId },
                    data: { activeGraphId: null },
                });
            }
        }

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