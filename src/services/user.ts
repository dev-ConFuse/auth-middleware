/**
 * ConFuse Auth Middleware - User Service
 * 
 * Handles user CRUD operations with Prisma
 */

import { User, UserProfile, CreateUserInput } from '../types/index.js';
import prisma from '../infra/db.js';
import { logger } from '../utils/logger.js';

/**
 * Ensures a user's FalkorDB graph exists, creating it if necessary
 * This is called for both new users and returning users to guarantee the graph exists
 */
async function ensureUserGraphExists(userId: string): Promise<void> {
    logger.info('[USER] Ensuring FalkorDB graph exists', { userId });
    try {
        const { createUserGraph } = await import('./user-graph.js');
        logger.info('[USER] createUserGraph module imported', { userId });
        await createUserGraph(userId);
        logger.info('[USER] FalkorDB graph ensured successfully', { userId });
    } catch (err) {
        logger.error('[USER] Failed to ensure FalkorDB graph', { 
            userId, 
            error: err instanceof Error ? err.message : String(err),
            stack: err instanceof Error ? err.stack : undefined
        });
        // Don't throw - allow user creation/login to proceed
    }
}

/**
 * Normalizes an Auth0 subject into a safe string before any database lookup.
 */
export function normalizeAuth0Sub(auth0Sub?: string | null): string | null {
    if (typeof auth0Sub !== 'string') {
        return null;
    }

    const normalized = auth0Sub.trim();
    return normalized.length > 0 ? normalized : null;
}

/**
 * Find or create user by Auth0 subject
 */
export async function findOrCreateByAuth0(input: CreateUserInput): Promise<User> {
    const auth0Sub = normalizeAuth0Sub(input.auth0Sub);
    logger.info('[USER] findOrCreateByAuth0 called', { auth0Sub, email: input.email ?? null });

    if (!auth0Sub) {
        logger.error('[USER] Missing auth0Sub in create/login request', { email: input.email ?? null });
        throw new Error('Cannot sync user without a valid Auth0 subject');
    }

    let { email, name, picture } = input;

    if (!email || email.trim() === '') {
        email = `${auth0Sub.replace(/[^a-zA-Z0-9]/g, '_')}@auth0.confuse.dev`;
    }

    // Try to find existing user by auth0Sub
    let user = await prisma.user.findUnique({
        where: { auth0Sub },
    });

    if (user) {
        logger.info('[USER] Found existing user by auth0Sub', { userId: user.id });
        // Update user info if changed
        user = await prisma.user.update({
            where: { id: user.id },
            data: {
                email: email || user.email,
                name: name ?? user.name,
                picture: picture ?? user.picture,
                lastLoginAt: new Date(),
            },
        });
        
        // Ensure FalkorDB graph exists for returning user
        logger.info('[USER] Calling ensureUserGraphExists for existing user', { userId: user.id });
        await ensureUserGraphExists(user.id);
        
        return user as User;
    }

    // Check if email already exists (different auth0 sub)
    const existingByEmail = await prisma.user.findUnique({
        where: { email },
    });

    if (existingByEmail) {
        logger.info('[USER] Found existing user by email, linking auth0Sub', { userId: existingByEmail.id });
        // Link auth0Sub to existing user
        user = await prisma.user.update({
            where: { id: existingByEmail.id },
            data: {
                auth0Sub,
                name: name ?? existingByEmail.name,
                picture: picture ?? existingByEmail.picture,
                lastLoginAt: new Date(),
            },
        });
        
        // Ensure FalkorDB graph exists for returning user
        logger.info('[USER] Calling ensureUserGraphExists for email-linked user', { userId: user.id });
        await ensureUserGraphExists(user.id);
        
        return user as User;
    }

    // Create new user
    logger.info('[USER] Creating new user in database', { auth0Sub, email });
    user = await prisma.user.create({
        data: {
            auth0Sub,
            email,
            name,
            picture,
            lastLoginAt: new Date(),
        },
    });
    logger.info('[USER] New user created in database', { userId: user.id });

    // Initialize the per-user FalkorDB graph - CRITICAL: must succeed
    logger.info('[USER] Calling ensureUserGraphExists for new user', { userId: user.id });
    await ensureUserGraphExists(user.id);

    // Create default preferences
    try {
        await prisma.userPreference.create({
            data: {
                userId: user.id,
            },
        });
    } catch (error) {
        logger.warn('[USER] Failed to create default preferences:', error);
    }

    return user as User;
}

/**
 * Find user by ID
 */
export async function findById(id: string): Promise<User | null> {
    const user = await prisma.user.findUnique({
        where: { id },
    });
    return user as User | null;
}

/**
 * Find user by auth0Sub
 */
export async function findByAuth0Sub(auth0Sub: string): Promise<User | null> {
    const normalized = normalizeAuth0Sub(auth0Sub);
    if (!normalized) {
        return null;
    }

    const user = await prisma.user.findUnique({
        where: { auth0Sub: normalized },
    });
    return user as User | null;
}

/**
 * Find user by email
 */
export async function findByEmail(email: string): Promise<User | null> {
    const normalizedEmail = typeof email === 'string' ? email.trim() : '';
    if (!normalizedEmail) {
        return null;
    }

    const user = await prisma.user.findUnique({
        where: { email: normalizedEmail },
    });
    return user as User | null;
}


/**
 * Get user profile (safe for client)
 */
export function toProfile(user: User): UserProfile {
    const createdAtStr = user.createdAt instanceof Date 
        ? user.createdAt.toISOString() 
        : (user.createdAt ? new Date(user.createdAt).toISOString() : new Date().toISOString());

    return {
        id: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        roles: user.roles || ['user'],
        createdAt: createdAtStr,
        onboardingCompleted: Boolean(user.onboardingCompleted),
        userIntent: user.userIntent || null,
        dashboardPreset: user.dashboardPreset || null,
        subscriptionTier: user.subscriptionTier || 'free',
        subscriptionStatus: user.subscriptionStatus || 'active',
    };
}


/**
 * Deletes a user account, including their FalkorDB graph and all related PostgreSQL data
 * (workspaces, preferences, api keys, sessions, accounts, etc).
 */
export async function deleteUserAccount(userId: string): Promise<void> {
    // First, delete the FalkorDB graph
    try {
        const { deleteUserGraph } = await import('./user-graph.js');
        await deleteUserGraph(userId);
    } catch (error) {
        logger.error(`[USER_DELETE] Failed to delete FalkorDB graph for user ${userId}:`, error);
        // We continue with the deletion even if graph deletion fails
        // to avoid putting the account in a stuck state.
    }

    // Second, delete the user from PostgreSQL.
    // Due to the 'onDelete: Cascade' rules in schema.prisma, this will also wipe:
    // Workspaces, Preferences, Sessions, ApiKeys, Accounts, etc.
    try {
        await prisma.user.delete({
            where: { id: userId }
        });
        logger.info(`[USER_DELETE] Successfully deleted user record ${userId} and cascaded data`);
    } catch (error) {
        logger.error(`[USER_DELETE] Failed to delete PostgreSQL user ${userId}:`, error);
        throw new Error(`Failed to delete user account: ${error instanceof Error ? error.message : String(error)}`);
    }
}
