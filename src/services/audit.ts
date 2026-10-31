import { prisma } from '../infra/db.js';

export interface AuditLogInput {
  userId?: string;
  workspaceId?: string;
  action: string;
  entityType: string;
  entityId?: string;
  metadata?: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
}

export async function createAuditLog(input: AuditLogInput) {
  return prisma.auditLog.create({
    data: {
      userId: input.userId,
      workspaceId: input.workspaceId,
      action: input.action,
      entityType: input.entityType,
      entityId: input.entityId,
      metadata: input.metadata,
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
    },
  });
}

export async function getAuditLogs(
  workspaceId: string,
  options?: {
    userId?: string;
    action?: string;
    entityType?: string;
    limit?: number;
    offset?: number;
  }
) {
  const where: any = { workspaceId };
  
  if (options?.userId) where.userId = options.userId;
  if (options?.action) where.action = options.action;
  if (options?.entityType) where.entityType = options.entityType;
  
  return prisma.auditLog.findMany({
    where,
    orderBy: { timestamp: 'desc' },
    take: options?.limit || 50,
    skip: options?.offset || 0,
  });
}
