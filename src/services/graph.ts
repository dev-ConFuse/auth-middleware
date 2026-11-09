/**
 * ConFuse Auth Middleware - Workspace Graph Registry (workspace-byodb spec)
 *
 * Tracks the *logical* graphs attached to a workspace: at most one ConFuse
 * graph (service-managed FalkorDB) and one BYODB graph (customer-owned
 * FalkorDB endpoint whose credentials live in the secret store).
 *
 * NOT TO BE CONFUSED WITH `services/user-graph.ts` — that module provisions
 * the per-user `graph-<userId>` graphs on the service-owned FalkorDB only on
 * the user's explicit graph-setup choice (never at signup/login). This module
 * manages workspace-scoped graph *records* and their lifecycle
 * (create / switch / soft-delete).
 *
 * Status: implemented per .kiro/specs/workspace-byodb-architecture but not
 * yet exposed over HTTP routes.
 */

import { prisma } from '../infra/db.js';
import { generateGraphId } from './id-generator.js';
import { encryptSecret, decryptSecret } from './secret-store.js';

export interface CreateConFuseGraphInput {
  workspaceId: string;
  name: string;
  userId: string;
}

export interface CreateBYODBGraphInput {
  workspaceId: string;
  name: string;
  host: string;
  port: number;
  username?: string;
  password?: string;
  graphName: string;
  tlsEnabled: boolean;
  caCertificate?: string;
  deploymentType: 'cloud' | 'self_hosted';
  userId: string;
}

/**
 * Create the workspace's ConFuse graph record (at most one per workspace) and
 * point the workspace at it when it has no active graph yet.
 */
export async function createConFuseGraph(input: CreateConFuseGraphInput) {
  const existingGraph = await prisma.graph.findFirst({
    where: {
      workspaceId: input.workspaceId,
      type: 'CONFUSE',
      deletedAt: null,
    },
  });
  
  if (existingGraph) {
    throw new Error('GRAPH_LIMIT_REACHED: Workspace already has a ConFuse graph');
  }
  
  const graphId = generateGraphId();
  const confuseGraphName = `confuse_${input.workspaceId.toLowerCase()}`;
  
  const graph = await prisma.graph.create({
    data: {
      id: graphId,
      workspaceId: input.workspaceId,
      name: input.name,
      type: 'CONFUSE',
      status: 'ACTIVE',
    },
  });
  
  const workspace = await prisma.workspace.findUnique({
    where: { id: input.workspaceId },
  });
  
  if (!workspace?.activeGraphId) {
    await prisma.workspace.update({
      where: { id: input.workspaceId },
      data: { activeGraphId: graph.id },
    });
  }
  
  return graph;
}

/**
 * Create a BYODB graph record for a customer-owned FalkorDB endpoint (at most
 * one per workspace). Password / CA cert are write-only inputs: they go to the
 * secret store and only their refs are persisted on the connection row.
 */
export async function createBYODBGraph(input: CreateBYODBGraphInput) {
  const existingGraph = await prisma.graph.findFirst({
    where: {
      workspaceId: input.workspaceId,
      type: 'BYODB',
      deletedAt: null,
    },
  });
  
  if (existingGraph) {
    throw new Error('GRAPH_LIMIT_REACHED: Workspace already has a BYODB graph');
  }
  
  let passwordSecretRef: string | undefined;
  let caCertSecretRef: string | undefined;
  
  if (input.password) {
    passwordSecretRef = await encryptSecret(
      input.password,
      input.userId,
      'falkordb'
    );
  }
  
  if (input.caCertificate) {
    caCertSecretRef = await encryptSecret(
      input.caCertificate,
      input.userId,
      'falkordb'
    );
  }
  
  const connection = await prisma.falkorDbConnection.create({
    data: {
      customerId: input.userId,
      name: input.name,
      host: input.host,
      port: input.port,
      username: input.username,
      passwordSecretRef,
      graphName: input.graphName,
      tlsEnabled: input.tlsEnabled,
      caCertificateSecretRef: caCertSecretRef,
      deploymentType: input.deploymentType,
      status: 'active',
    },
  });
  
  const graphId = generateGraphId();
  
  const graph = await prisma.graph.create({
    data: {
      id: graphId,
      workspaceId: input.workspaceId,
      name: input.name,
      type: 'BYODB',
      status: 'ACTIVE',
      falkorDbConnectionId: connection.id,
    },
  });
  
  const workspace = await prisma.workspace.findUnique({
    where: { id: input.workspaceId },
  });
  
  if (!workspace?.activeGraphId) {
    await prisma.workspace.update({
      where: { id: input.workspaceId },
      data: { activeGraphId: graph.id },
    });
  }
  
  return graph;
}

/** Point the workspace at one of its existing, non-deleted ACTIVE graphs. */
export async function switchActiveGraph(
  workspaceId: string,
  graphId: string,
  userId: string
) {
  const graph = await prisma.graph.findFirst({
    where: {
      id: graphId,
      workspaceId,
      deletedAt: null,
      status: 'ACTIVE',
    },
  });
  
  if (!graph) {
    throw new Error('Graph not found or not available');
  }
  
  return prisma.workspace.update({
    where: { id: workspaceId },
    data: { activeGraphId: graphId },
  });
}

/**
 * Soft-delete a graph record and hard-delete its BYODB connection row in one
 * transaction; clears the workspace's active-graph pointer when it pointed
 * here. NOTE: unlike services/falkordb/connections.ts#deleteConnection, this
 * does NOT purge the connection's secret-store entries yet (follow-up).
 */
export async function deleteGraph(
  graphId: string,
  workspaceId: string,
  userId: string
) {
  const graph = await prisma.graph.findFirst({
    where: {
      id: graphId,
      workspaceId,
    },
  });
  
  if (!graph) {
    throw new Error('Graph not found');
  }
  
  await prisma.$transaction(async (tx) => {
    await tx.graph.update({
      where: { id: graphId },
      data: {
        status: 'DELETED',
        deletedAt: new Date(),
      },
    });
    
    const workspace = await tx.workspace.findUnique({
      where: { id: workspaceId },
    });
    
    if (workspace?.activeGraphId === graphId) {
      await tx.workspace.update({
        where: { id: workspaceId },
        data: { activeGraphId: null },
      });
    }
    
    if (graph.falkorDbConnectionId) {
      await tx.falkorDbConnection.delete({
        where: { id: graph.falkorDbConnectionId },
      });
    }
  });
  
  return { success: true };
}

/** List a workspace's non-deleted graphs with connection metadata (no secret fields). */
export async function listWorkspaceGraphs(workspaceId: string) {
  return prisma.graph.findMany({
    where: {
      workspaceId,
      deletedAt: null,
    },
    include: {
      falkorDbConnection: {
        select: {
          id: true,
          name: true,
          host: true,
          port: true,
          username: true,
          graphName: true,
          tlsEnabled: true,
          deploymentType: true,
          status: true,
        },
      },
    },
  });
}
