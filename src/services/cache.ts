/**
 * ConFuse Auth Middleware - Token Cache Service
 *
 * In-memory token caching with TTL-based expiration and cache-first
 * validation. Per-process only: entries are lost on restart and are not
 * shared across replicas (fine for single-replica deployments).
 */

import { logger } from '../utils/logger.js';
import { config } from '../config.js';

// Token cache entry structure
interface CachedToken {
    userId: string;
    email: string;
    roles: string[];
    validatedAt: number;
    expiresAt: number;
}

// Cache statistics
interface CacheStats {
    hits: number;
    misses: number;
    errors: number;
}

class TokenCacheService {
    private isInitialized = false;
    private stats: CacheStats = { hits: 0, misses: 0, errors: 0 };
    private readonly memoryStore = new Map<string, CachedToken>();
    /** userId → token hashes, so all of a user's tokens can be evicted at once. */
    private readonly userIndex = new Map<string, Set<string>>();

    constructor() {
        this.isInitialized = true;
        logger.info('[TOKEN-CACHE] In-memory token cache initialized');
    }

    /**
     * Kept for API compatibility — nothing external to connect.
     */
    async initialize(): Promise<void> {
        this.isInitialized = true;
    }

    /**
     * Check if cache is available
     */
    isAvailable(): boolean {
        return this.isInitialized;
    }

    private invalidateMemory(tokenHash: string): void {
        const data = this.memoryStore.get(tokenHash);
        if (data) {
            const hashes = this.userIndex.get(data.userId);
            hashes?.delete(tokenHash);
            if (hashes && hashes.size === 0) {
                this.userIndex.delete(data.userId);
            }
        }
        this.memoryStore.delete(tokenHash);
    }

    private getMemoryToken(tokenHash: string): CachedToken | null {
        const data = this.memoryStore.get(tokenHash);
        if (!data) return null;
        if (data.expiresAt <= Date.now()) {
            this.invalidateMemory(tokenHash);
            return null;
        }
        return data;
    }

    /**
     * Get cached token data
     */
    async getToken(tokenHash: string): Promise<CachedToken | null> {
        const token = this.getMemoryToken(tokenHash);
        if (token) {
            this.stats.hits++;
            logger.debug(`[TOKEN-CACHE] Cache hit for token hash: ${tokenHash.substring(0, 8)}...`);
            return token;
        }
        this.stats.misses++;
        logger.debug(`[TOKEN-CACHE] Cache miss for token hash: ${tokenHash.substring(0, 8)}...`);
        return null;
    }

    /**
     * Cache validated token data
     */
    async setToken(tokenHash: string, data: CachedToken): Promise<void> {
        this.memoryStore.set(tokenHash, data);
        let hashes = this.userIndex.get(data.userId);
        if (!hashes) {
            hashes = new Set<string>();
            this.userIndex.set(data.userId, hashes);
        }
        hashes.add(tokenHash);
        logger.debug(`[TOKEN-CACHE] Cached token for hash: ${tokenHash.substring(0, 8)}... TTL: ${config.tokenCacheTtlSeconds}s`);
    }

    /**
     * Invalidate cached token
     */
    async invalidateToken(tokenHash: string): Promise<void> {
        this.invalidateMemory(tokenHash);
        logger.debug(`[TOKEN-CACHE] Invalidated token hash: ${tokenHash.substring(0, 8)}...`);
    }

    /**
     * Invalidate all tokens for a user
     */
    async invalidateUserTokens(userId: string): Promise<number> {
        const hashes = this.userIndex.get(userId);
        if (!hashes || hashes.size === 0) {
            logger.info(`[TOKEN-CACHE] No tokens found for user: ${userId}`);
            return 0;
        }
        const count = hashes.size;
        for (const hash of [...hashes]) {
            this.memoryStore.delete(hash);
        }
        this.userIndex.delete(userId);
        logger.info(`[TOKEN-CACHE] Invalidated ${count} tokens for user: ${userId}`);
        return count;
    }

    /**
     * Get cache statistics
     */
    getStats(): CacheStats & { hitRate: number } {
        const total = this.stats.hits + this.stats.misses;
        const hitRate = total > 0 ? (this.stats.hits / total) * 100 : 0;
        return { ...this.stats, hitRate };
    }

    /**
     * Health check
     */
    async healthCheck(): Promise<{ status: string; latencyMs: number }> {
        return {
            status: this.isAvailable() ? 'healthy' : 'not_initialized',
            latencyMs: 0,
        };
    }

    /**
     * Graceful shutdown (kept for API compatibility)
     */
    async shutdown(): Promise<void> {
        this.memoryStore.clear();
        this.userIndex.clear();
        logger.info('[TOKEN-CACHE] In-memory token cache cleared');
    }
}

// Singleton instance
export const tokenCache = new TokenCacheService();
