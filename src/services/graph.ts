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
