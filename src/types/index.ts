/**
 * ConFuse Auth Middleware - Shared Type Definitions
 *
 * Hand-written wire/API projections shared across routes, services and the
 * gRPC layer. Prisma model types come from `@prisma/client`; these are the
 * contracts layered on top of them.
 */

import type { Request } from 'express';

// ============================================================================
// User Types
// ============================================================================

export interface User {
    id: string;
    auth0Sub: string;
    email: string;
    name: string | null;
    picture: string | null;
    roles: string[];
    createdAt: Date;
    updatedAt: Date;
    lastLoginAt: Date | null;
    onboardingCompleted: boolean;
    userIntent: string | null;
    dashboardPreset: string | null;
    subscriptionTier: string;
    subscriptionStatus?: string | null;
    subscriptionEndsAt?: Date | null;
    monthlyRequestCount: number;
    storageUsedBytes: bigint;
}

export interface UserProfile {
    id: string;
    email: string;
    name: string | null;
    picture: string | null;
    roles: string[];
    createdAt: string;
    onboardingCompleted: boolean;
    userIntent: string | null;
    dashboardPreset: string | null;
    /**
     * NOTE (known casing mismatch): this projection emits `subscriptionTier`
     * (camelCase) while the frontend reads `user.subscription_tier`
     * (snake_case) from auth responses. Documented deliberately — pick one
     * casing when the profile contract is next revisited.
     */
    subscriptionTier: string;
    subscriptionStatus?: string | null;
}


export interface CreateUserInput {
    auth0Sub: string;
    email: string;
    name?: string | null;
    picture?: string | null;
    roles?: string[];
}

// ============================================================================
// Auth0 Types
// ============================================================================

export interface Auth0Claims {
    sub: string;
    email?: string;
    name?: string;
    picture?: string;
    permissions?: string[];
    roles?: string[]; // Augmented by middleware
    /**
     * camelCase variant matching Prisma `User.subscriptionTier` and the
     * `toProfile()` projection. NOTE: the frontend currently reads the
     * snake_case key from auth responses — see the casing note on `UserProfile`.
     */
    subscriptionTier?: string;
    /** Subscription tier on the wire (gRPC `subscription_tier`, frontend `user.subscription_tier`); read by the rate limiter. */
    subscription_tier?: string;
    [key: string]: unknown;
}


// Session types removed as session management is handled by Auth0


// ============================================================================
// Express Extensions
// ============================================================================

export interface AuthenticatedRequest extends Request {
    user?: Auth0Claims;
}

// ============================================================================
// API Response Types
// ============================================================================


export interface AuthExchangeResponse {
    user: UserProfile;
}

// TokenRefreshResponse removed as we use Auth0 refresh tokens on client side

export interface TokenVerifyResponse {
    valid: boolean;
    claims?: Auth0Claims;
    subscription_tier?: string;
    error?: string;
}


