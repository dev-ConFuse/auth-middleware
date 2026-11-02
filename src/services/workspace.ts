/**
 * ConFuse Auth Middleware - Workspace & Membership Service (workspace-byodb spec)
 *
 * Workspaces group users (ADMIN / MEMBER roles) and own the graphs registered
 * in `services/graph.ts`. Invites for unknown emails are stored as expiring
 * pending-invitation tokens (7 days).
 *
 * Status: implemented per .kiro/specs/workspace-byodb-architecture but not
 * yet exposed over HTTP routes.
 */
import { prisma } from '../infra/db.js';
import { generateWorkspaceId } from './id-generator.js';

export interface CreateWorkspaceInput {
  name: string;
  userId: string;
}

export interface UpdateWorkspaceInput {
  name?: string;
  settings?: Record<string, any>;
}

/** Create a workspace and make the creating user its ADMIN (single transaction). */
export async function createWorkspace(input: CreateWorkspaceInput) {
  const workspaceId = generateWorkspaceId();
  
  return prisma.$transaction(async (tx) => {
    const workspace = await tx.workspace.create({
      data: {
        id: workspaceId,
        name: input.name,
      },
    });
    
    await tx.workspaceMember.create({
      data: {
        userId: input.userId,
        workspaceId: workspace.id,
        role: 'ADMIN',
      },
    });
    
    return workspace;
  });
}

/** Fetch a workspace (members, graphs, active graph) — throws unless the user is a member. */
export async function getWorkspace(workspaceId: string, userId: string) {
  const member = await prisma.workspaceMember.findUnique({
    where: {
      userId_workspaceId: { userId, workspaceId },
    },
  });
  
  if (!member) {
    throw new Error('Workspace not found or access denied');
  }
  
  return prisma.workspace.findUnique({
    where: { id: workspaceId },
    include: {
      members: {
        include: {
          user: {
            select: {
              id: true,
              name: true,
              email: true,
              picture: true,
            },
          },
        },
      },
      graphs: {
        where: {
          deletedAt: null,
        },
      },
      activeGraph: true,
    },
  });
}

/** List every workspace the user belongs to, with their role and member count. */
export async function listUserWorkspaces(userId: string) {
  const memberships = await prisma.workspaceMember.findMany({
    where: { userId },
    include: {
      workspace: {
        include: {
          activeGraph: true,
          _count: {
            select: { members: true },
          },
        },
      },
    },
  });
  
  return memberships.map((m) => ({
    ...m.workspace,
    role: m.role,
    joinedAt: m.joinedAt,
    memberCount: m.workspace._count.members,
  }));
}

/** Rename / reconfigure a workspace. ADMIN only. */
export async function updateWorkspace(
  workspaceId: string,
  userId: string,
  input: UpdateWorkspaceInput
) {
  const member = await prisma.workspaceMember.findUnique({
    where: {
      userId_workspaceId: { userId, workspaceId },
    },
  });
  
  if (!member || member.role !== 'ADMIN') {
    throw new Error('Admin access required');
  }
  
  return prisma.workspace.update({
    where: { id: workspaceId },
    data: input,
  });
}

/** Delete a workspace. ADMIN only — related rows go with it via FK cascade. */
export async function deleteWorkspace(workspaceId: string, userId: string) {
  const member = await prisma.workspaceMember.findUnique({
    where: {
      userId_workspaceId: { userId, workspaceId },
    },
  });
  
  if (!member || member.role !== 'ADMIN') {
    throw new Error('Admin access required');
  }
  
  return prisma.workspace.delete({
    where: { id: workspaceId },
  });
}

/**
 * Invite by email: existing users join immediately (MEMBER); unknown emails
 * get a 7-day pending-invitation token. ADMIN only.
 */
export async function inviteMember(
  workspaceId: string,
  adminId: string,
  email: string
) {
  const admin = await prisma.workspaceMember.findUnique({
    where: {
      userId_workspaceId: { userId: adminId, workspaceId },
    },
  });
  
  if (!admin || admin.role !== 'ADMIN') {
    throw new Error('Admin access required');
  }
  
  const invitedUser = await prisma.user.findUnique({
    where: { email },
  });
  
  if (invitedUser) {
    const existing = await prisma.workspaceMember.findUnique({
      where: {
        userId_workspaceId: {
          userId: invitedUser.id,
          workspaceId,
        },
      },
    });
    
    if (existing) {
      throw new Error('User is already a member');
    }
    
    return prisma.workspaceMember.create({
      data: {
        userId: invitedUser.id,
        workspaceId,
        role: 'MEMBER',
        invitedBy: adminId,
      },
    });
  }
  
  const token = crypto.randomUUID();
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7);
  
  return prisma.pendingInvitation.create({
    data: {
      email,
      workspaceId,
      invitedBy: adminId,
      token,
      expiresAt,
    },
  });
}

/** Remove a member (or self). ADMIN only; the last remaining admin cannot be removed. */
export async function removeMember(
  workspaceId: string,
  adminId: string,
  targetUserId: string
) {
  const admin = await prisma.workspaceMember.findUnique({
    where: {
      userId_workspaceId: { userId: adminId, workspaceId },
    },
  });
  
  if (!admin || admin.role !== 'ADMIN') {
    throw new Error('Admin access required');
  }
  
  if (adminId === targetUserId) {
    const adminCount = await prisma.workspaceMember.count({
      where: {
        workspaceId,
        role: 'ADMIN',
      },
    });
    
    if (adminCount <= 1) {
      throw new Error('Cannot remove the last admin');
    }
  }
  
  return prisma.workspaceMember.delete({
    where: {
      userId_workspaceId: {
        userId: targetUserId,
        workspaceId,
      },
    },
  });
}
