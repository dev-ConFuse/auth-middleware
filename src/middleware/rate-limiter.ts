/**
 * ConFuse Auth Middleware - Rate Limiter
 *
 * In-memory sliding-window rate limiting. Per-process only: counters are
 * not shared across replicas and reset on restart (fine for single-replica
 * deployments).
 */

import type { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger.js';

// ── In-memory store ──

const memoryStore = new Map<string, number[]>();

function memoryCleanupLoop() {
    setInterval(() => {
        const cutoff = Date.now() - 120_000; // 2 min
        for (const [key, timestamps] of memoryStore.entries()) {
            const filtered = timestamps.filter(t => t > cutoff);
            if (filtered.length === 0) memoryStore.delete(key);
            else memoryStore.set(key, filtered);
        }
    }, 60_000);
}
memoryCleanupLoop();

// ── Sliding Window Logic ──

interface RateLimitResult {
    allowed: boolean;
    remaining: number;
    limit: number;
    retryAfterSecs: number;
    resetAt: number;
}

function checkRateLimit(
    key: string,
    maxRequests: number,
    windowMs: number,
): RateLimitResult {
    const now = Date.now();
    const windowStart = now - windowMs;
    const resetAt = Math.ceil((now + windowMs) / 1000);

    // DSA: Timestamps are kept sorted (monotonically increasing).
    // Use binary search to find the cutoff point instead of O(n) Array.filter()
    // which allocated a new array on every request.
    let timestamps = memoryStore.get(key);
    if (!timestamps) {
        timestamps = [];
        memoryStore.set(key, timestamps);
    }

    // Binary search for the first timestamp > windowStart
    let lo = 0;
    let hi = timestamps.length;
    while (lo < hi) {
        const mid = (lo + hi) >>> 1;
        if (timestamps[mid] <= windowStart) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    // Remove expired entries in-place (O(1) amortized via splice from front)
    if (lo > 0) {
        timestamps.splice(0, lo);
    }

    // Append current timestamp (maintains sorted order)
    timestamps.push(now);

    const allowed = timestamps.length <= maxRequests;
    return {
        allowed,
        remaining: Math.max(0, maxRequests - timestamps.length),
        limit: maxRequests,
        retryAfterSecs: allowed ? 0 : Math.ceil(windowMs / 1000),
        resetAt,
    };
}

// ── Configuration ──

interface RateLimitTier {
    maxRequests: number;
    windowMs: number;
}

const TIERS: Record<string, RateLimitTier> = {
    auth: { maxRequests: 20, windowMs: 60_000 },       // 20 req/min for login/exchange
    refresh: { maxRequests: 30, windowMs: 60_000 },     // 30 req/min for token refresh
    api: { maxRequests: 120, windowMs: 60_000 },        // 120 req/min general API
    sessions: { maxRequests: 30, windowMs: 60_000 },    // 30 req/min for session ops
    pro_api: { maxRequests: 240, windowMs: 60_000 },    // 240 req/min for Pro
    team_api: { maxRequests: 480, windowMs: 60_000 },   // 480 req/min for Team
    enterprise_api: { maxRequests: 1000, windowMs: 60_000 }, // 1000 req/min for Enterprise
};

function getTierForPath(path: string, userTier: string = 'free'): RateLimitTier {
    if (path.includes('/auth0/exchange') || path.includes('/oauth')) return TIERS.auth;
    if (path.includes('/refresh')) return TIERS.refresh;
    if (path.includes('/sessions')) return TIERS.sessions;

    if (userTier === 'pro') return TIERS.pro_api;
    if (userTier === 'team') return TIERS.team_api;
    if (userTier === 'enterprise') return TIERS.enterprise_api;
    return TIERS.api;
}

// ── Express Middleware ──

function getClientKey(req: Request): string {
    // Prefer authenticated user ID, fall back to IP
    const user = (req as unknown as import('../types/index.js').AuthenticatedRequest).user;
    if (user?.sub) return `user:${user.sub}`;
    if (user?.id) return `user:${user.id}`;
    const forwarded = req.headers['x-forwarded-for'];
    const ip = typeof forwarded === 'string'
        ? forwarded.split(',')[0].trim()
        : req.ip || 'unknown';
    return `ip:${ip}`;
}

export function rateLimitMiddleware() {
    return (req: Request, res: Response, next: NextFunction): void => {
        const clientKey = getClientKey(req);
        const user = (req as unknown as import('../types/index.js').AuthenticatedRequest).user;
        const userTier = typeof (user as any)?.subscription_tier === 'string' ? (user as any).subscription_tier : 'free';

        const tier = getTierForPath(req.path, userTier);

        const limitKey = `ratelimit:auth:${clientKey}:${req.path.replace(/\//g, '_')}`;

        const result = checkRateLimit(limitKey, tier.maxRequests, tier.windowMs);

        // Set standard rate limit headers
        res.setHeader('X-RateLimit-Limit', result.limit.toString());
        res.setHeader('X-RateLimit-Remaining', result.remaining.toString());
        res.setHeader('X-RateLimit-Reset', result.resetAt.toString());

        if (!result.allowed) {
            res.setHeader('Retry-After', result.retryAfterSecs.toString());
            logger.warn(`[RATE-LIMIT] ${clientKey} exceeded ${result.limit} req/window on ${req.path}`);
            res.status(429).json({
                error: 'Too many requests',
                message: `Rate limit exceeded. Try again in ${result.retryAfterSecs}s`,
                retryAfter: result.retryAfterSecs,
            });
            return;
        }

        next();
    };
}
