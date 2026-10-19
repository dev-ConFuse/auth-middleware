/**
 * ConFuse Auth Middleware - Complete Authentication System
 * 
 * Consolidated authentication, OAuth, and token management
 * Merged from: services/auth0.ts, services/oauth.ts, middleware/auth.ts, routes/auth.ts
 */

import { Router, type Request, type Response } from 'express';
import type { Response as ExpressResponse, NextFunction } from 'express';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { randomBytes, createHash } from 'crypto';

import { logger } from './utils/logger.js';
import { config } from './config.js';
import { tokenCache } from './services/cache.js';
import { findOrCreateByAuth0, findByAuth0Sub, findByEmail, toProfile } from './services/user.js';

import prisma from './infra/db.js';
import type { AuthenticatedRequest, AuthExchangeResponse, TokenVerifyResponse, Auth0Claims } from './types/index.js';

// ============================================================================
// OAUTH STATE MANAGEMENT (from services/oauth.ts)
// ============================================================================

export interface OAuthState {
    provider: string;
    userId?: string;
    redirectUri: string;
    codeVerifier?: string;
    createdAt: number;
    expiresAt: number;
}

export class OAuthStateService {
    private readonly PREFIX = 'oauth:state:';
    private readonly TTL = 600; // 10 minutes
    /**
     * In-memory state store (per-process): OAuth state must be consumed by the
     * same instance that created it — fine for single-replica deployments.
     */
    private readonly memoryStore = new Map<string, OAuthState>();

    private getStateKey(state: string): string {
        return `${this.PREFIX}${state}`;
    }

    private getMemoryState(state: string): OAuthState | null {
        const key = this.getStateKey(state);
        const value = this.memoryStore.get(key);
        if (!value) return null;

        if (Date.now() > value.expiresAt) {
            this.memoryStore.delete(key);
            return null;
        }

        return value;
    }

    /**
     * Generate secure random state
     */
    generateState(): string {
        return randomBytes(32).toString('hex');
    }

    /**
     * Generate PKCE Code Verifier and Challenge
     */
    generatePKCE(): { codeVerifier: string; codeChallenge: string } {
        const codeVerifier = randomBytes(32).toString('base64url');
        const codeChallenge = createHash('sha256')
            .update(codeVerifier)
            .digest('base64url');
        return { codeVerifier, codeChallenge };
    }

    /**
     * Store OAuth state
     */
    async storeState(state: string, data: Omit<OAuthState, 'createdAt' | 'expiresAt'>): Promise<void> {
        const stateData: OAuthState = {
            ...data,
            createdAt: Date.now(),
            expiresAt: Date.now() + (this.TTL * 1000)
        };
        this.memoryStore.set(this.getStateKey(state), stateData);
    }

    /**
     * Validate OAuth state
     */
    async validateState(state: string): Promise<OAuthState | null> {
        return this.getMemoryState(state);
    }

    /**
     * Consume OAuth state (delete after use)
     */
    async consumeState(state: string): Promise<void> {
        this.memoryStore.delete(this.getStateKey(state));
    }
}

// ============================================================================
// AUTH0 TOKEN MANAGEMENT (from services/auth0.ts)
// ============================================================================

// JWKS remote key set (cached by jose library)
let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

/**
 * Thrown when Auth0 could not be reached to verify a token (network/infra
 * failure), as opposed to the token actually being invalid. Callers map this
 * to 503 so clients retry instead of treating the user as unauthenticated.
 */
export class Auth0UnavailableError extends Error {
    constructor(message: string, options?: { cause?: unknown }) {
        super(message, options);
        this.name = 'Auth0UnavailableError';
    }
}

/** Network-level failure signatures produced by fetch/undici/jose. */
const TRANSIENT_AUTH0_ERROR = /fetch failed|network|econnreset|econnrefused|etimedout|timed out|enotfound|eai_again|aborted|timeout|expected 200 ok from the json web key set/i;

/** True for transport failures (retryable), false for crypto/claim failures. */
function isTransientAuth0Error(error: unknown): boolean {
    if (error instanceof Auth0UnavailableError) {
        return true;
    }
    if (!(error instanceof Error)) {
        return false;
    }
    // jose's JWKSTimeout plus fetch abort/timeout DOMException names.
    if (error.name === 'JWKSTimeout' || error.name === 'TimeoutError' || error.name === 'AbortError') {
        return true;
    }
    const cause = error.cause instanceof Error ? ` ${error.cause.message}` : '';
    return TRANSIENT_AUTH0_ERROR.test(`${error.message}${cause}`);
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Helper to resolve a user from Auth0 claims by checking auth0Sub first, then email.
 */
async function resolveUserFromClaims(claims: Auth0Claims) {
    const auth0Sub = typeof claims.sub === 'string' ? claims.sub.trim() : '';
    if (!auth0Sub) {
        logger.warn('[AUTH] Auth0 claims are missing a valid subject', { email: claims.email ?? null, claimKeys: Object.keys(claims ?? {}) });
        return null;
    }

    let user = await findByAuth0Sub(auth0Sub);
    if (!user && claims.email) {
        user = await findByEmail(claims.email);
    }
    return user;
}

/**
 * Get or create JWKS cache
 */
function getJWKS() {
    if (!jwks) {
        jwks = createRemoteJWKSet(
            new URL(config.auth0.jwksUri),
            { timeoutDuration: config.auth0.jwksTimeoutMs }
        );
    }
    return jwks;
}

/**
 * Hash token for cache key
 */
export function hashToken(token: string): string {
    let hash = 5381;
    for (let i = 0; i < token.length; i++) {
        hash = ((hash << 5) + hash) ^ token.charCodeAt(i);
    }
    return hash.toString(36);
}

/**
 * Verify Auth0 JWT token
 */
export async function verifyAuth0Token(token: string): Promise<Auth0Claims> {
    // Check cache first
    const tokenHash = hashToken(token);
    const cached = await tokenCache.getToken(tokenHash);
    if (cached && cached.email) {
        // Only use cache if email was captured (Auth0 access tokens may not embed email in JWT)
        return {
            sub: cached.userId,
            email: cached.email,
            roles: cached.roles,
        } as Auth0Claims;
    }

    const jwks = getJWKS();

    // Retry transient Auth0 outages (e.g. JWKS fetch ECONNRESET) before giving
    // up — a flaky network must never masquerade as an invalid token.
    let claims: Auth0Claims | undefined;
    let lastError: unknown;
    for (let attempt = 1; attempt <= config.auth0.jwksRetries; attempt++) {
        try {
            const { payload } = await jwtVerify(token, jwks, {
                issuer: config.auth0.issuer,
                audience: config.auth0.audience,
            });
            claims = payload as Auth0Claims;
            lastError = undefined;
            break;
        } catch (error) {
            lastError = error;
            if (!isTransientAuth0Error(error) || attempt === config.auth0.jwksRetries) {
                break;
            }
            logger.warn('[AUTH] Transient Auth0 failure, retrying', {
                attempt,
                maxAttempts: config.auth0.jwksRetries,
                message: error instanceof Error ? error.message : String(error),
            });
            await sleep(config.auth0.jwksRetryDelayMs * attempt);
        }
    }

    if (!claims) {
        const message = lastError instanceof Error ? lastError.message : 'Unknown error';
        if (isTransientAuth0Error(lastError)) {
            throw new Auth0UnavailableError(`Auth0 unavailable: ${message}`, { cause: lastError });
        }
        throw new Error(`Invalid token: ${message}`);
    }

    // Normalize payload to Auth0Claims for downstream use
    if (!claims.sub || typeof claims.sub !== 'string' || !claims.sub.trim()) {
        throw new Error('Invalid token: Auth0 token is missing a valid subject claim');
    }

    // Cache the validated token (best-effort — a cache hiccup must not fail a
    // token that was just verified)
    try {
        await tokenCache.setToken(tokenHash, {
            userId: claims.sub,
            email: claims.email || '',
            roles: extractRoles(claims),
            validatedAt: Date.now(),
            expiresAt: Date.now() + (config.tokenCacheTtlSeconds * 1000),
        });
    } catch (cacheError) {
        logger.warn('[AUTH] Token cache write failed', {
            message: cacheError instanceof Error ? cacheError.message : String(cacheError),
        });
    }

    return claims;
}


/**
 * Extract roles from Auth0 claims
 */
export function extractRoles(claims: Auth0Claims): string[] {
    const asRecord = claims as unknown as Record<string, unknown>;
    const rolesValue = asRecord['roles'] ?? asRecord['https://confuse.dev/roles'] ?? asRecord['http://confuse.dev/roles'] ?? [];
    return Array.isArray(rolesValue) ? (rolesValue as string[]) : [];
}

/**
 * Auth0 Management API Client
 */
export class Auth0ManagementClient {
    private static instance: Auth0ManagementClient;
    private accessToken: string | null = null;
    private tokenExpiresAt: number = 0;

    static getInstance(): Auth0ManagementClient {
        if (!Auth0ManagementClient.instance) {
            Auth0ManagementClient.instance = new Auth0ManagementClient();
        }
        return Auth0ManagementClient.instance;
    }

    private async getAccessToken(): Promise<string> {
        if (this.accessToken && Date.now() < this.tokenExpiresAt) {
            return this.accessToken;
        }

        try {
            const response = await fetch(`https://${config.auth0.domain}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client_id: config.auth0.clientId,
                    client_secret: config.auth0.clientSecret,
                    audience: `https://${config.auth0.domain}/api/v2/`,
                    grant_type: 'client_credentials'
                })
            });

            if (!response.ok) {
                throw new Error('Failed to get Auth0 management token');
            }

            const data = await response.json();
            this.accessToken = data.access_token;
            this.tokenExpiresAt = Date.now() + (data.expires_in * 1000) - 60000; // 1min buffer

            if (this.accessToken) {
                return this.accessToken;
            }
            throw new Error('No access token received');
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Auth0 management auth failed: ${message}`);
        }
    }

    async getUserProfile(userId: string): Promise<Record<string, unknown>> {
        const token = await this.getAccessToken();
        
        const response = await fetch(`https://${config.auth0.domain}/api/v2/users/${userId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            throw new Error(`Failed to get user profile: ${response.statusText}`);
        }

        return response.json();
    }

    async getUsersByEmail(email: string): Promise<Record<string, unknown>[]> {
        const token = await this.getAccessToken();
        
        const response = await fetch(`https://${config.auth0.domain}/api/v2/users-by-email?email=${encodeURIComponent(email)}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            throw new Error(`Failed to get users by email: ${response.statusText}`);
        }

        return response.json();
    }
}


// ============================================================================
// AUTHENTICATION MIDDLEWARE (from middleware/auth.ts)
// ============================================================================

/**
 * Extract bearer token from Authorization header
 */
export function extractBearerToken(req: Request): string | null {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }
    return authHeader.slice(7);
}

/**
 * Require Auth0 Access Token authentication (OAuth only — Google / Microsoft)
 */
export async function requireAuth(
    req: Request,
    res: ExpressResponse,
    next: NextFunction
): Promise<void> {
    const token = extractBearerToken(req);

    if (!token) {
        res.status(401).json({
            error: 'Authentication required',
            message: 'Please provide a valid Bearer token in the Authorization header',
        });
        return;
    }

    try {
        const claims = await verifyAuth0Token(token);
        // Augment claims with roles
        const claimsTyped = claims as Auth0Claims;
        claimsTyped.roles = extractRoles(claimsTyped);
        (req as AuthenticatedRequest).user = claimsTyped;
        next();
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid token';
        if (error instanceof Auth0UnavailableError) {
            logger.warn('[AUTH] Auth0 unreachable during token verification', { message });
            res.status(503).json({
                error: 'Auth service temporarily unavailable',
                message: 'Could not reach Auth0 to verify the token. Please retry.',
            });
            return;
        }
        res.status(401).json({
            error: 'Invalid token',
            message,
        });
    }
}


// ============================================================================
// AUTHENTICATION ROUTES (from routes/auth.ts)
// ============================================================================

// Standardized error response functions
function sendUserNotFound(res: Response, message?: string) {
    res.status(404).json({
        error: 'User not found',
        message: message || 'User not found'
    });
}

function sendConnectionNotFound(res: Response, provider: string) {
    res.status(404).json({ 
        error: `Connection for ${provider} not found or missing access token` 
    });
}

function sendInvalidApiKey(res: Response) {
    res.status(403).json({ error: 'Invalid API key' });
}

/**
 * Resolve provider aliases for OneDrive/Microsoft.
 * The account may be stored under any of these provider names depending
 * on the original auth flow (direct OAuth vs Auth0 sync).
 */
export function getProviderAliases(provider: string): string[] {
    if (['onedrive', 'microsoft', 'windowslive', 'waad'].includes(provider)) {
        return ['onedrive', 'microsoft', 'windowslive', 'waad'];
    }
    if (['google', 'google-oauth2', 'google_drive', 'gdrive'].includes(provider)) {
        return ['google', 'google-oauth2', 'google_drive', 'gdrive'];
    }
    return [provider];
}

// Create router
export const authRouter = Router();

// Initialize OAuth state service
export const oAuthStateService = new OAuthStateService();

/**
 * POST /auth/login
 * Verify Auth0 token, sync user to DB, and return profile
 */
authRouter.post('/login', async (req: Request, res: Response) => {
    try {

        // Extract Auth0 token using middleware function
        const auth0Token = extractBearerToken(req);
        if (!auth0Token) {
            res.status(401).json({
                error: 'Missing or invalid Authorization header',
                message: "Expected 'Authorization: Bearer <auth0_access_token>'",
            });
            return;
        }

        // Verify Auth0 token
        let claims;
        try {
            claims = await verifyAuth0Token(auth0Token);
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Unknown error';
            if (error instanceof Auth0UnavailableError) {
                logger.error('[AUTH-LOGIN] Auth0 unreachable during login', { message });
                res.status(503).json({
                    error: 'Auth service temporarily unavailable',
                    message: 'Could not reach Auth0 to verify the token. Please retry.',
                });
                return;
            }
            logger.warn('[AUTH-LOGIN] Auth0 token verification failed', { message });
            res.status(401).json({
                error: 'Invalid Auth0 token',
                message,
            });
            return;
        }

        // Fetch user profile from Auth0 /userinfo endpoint
        let userInfo: Record<string, unknown> = {};
        try {
            const userInfoRes = await fetch(`https://${config.auth0.domain}/userinfo`, {
                headers: { 'Authorization': `Bearer ${auth0Token}` }
            });
            if (userInfoRes.ok) {
                userInfo = await userInfoRes.json();
            }

            // Fetch from Auth0 Management API to get IdP access tokens for direct Google/Microsoft queries
            try {
                const mgmtClient = Auth0ManagementClient.getInstance();
                const fullProfile = await mgmtClient.getUserProfile(claims.sub);

                userInfo = { ...userInfo, ...(fullProfile as Record<string, unknown>) };

                // Directly query Google or Microsoft APIs for the full name if access token is available
                const identities: Array<Record<string, unknown>> = Array.isArray((fullProfile as Record<string, unknown>).identities)
                    ? ((fullProfile as Record<string, unknown>).identities as Array<Record<string, unknown>>)
                    : [];
                for (const identity of identities) {
                    const provider = String(identity['provider'] ?? '');
                    const accessToken = typeof identity['access_token'] === 'string' ? identity['access_token'] as string : '';
                    if (provider === 'google-oauth2' && accessToken) {
                        const googleRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
                            headers: { Authorization: `Bearer ${accessToken}` }
                        });
                        if (googleRes.ok) {
                            const googleUser = await googleRes.json() as Record<string, unknown>;
                            userInfo['name'] = (typeof googleUser['name'] === 'string' ? googleUser['name'] as string : userInfo['name']);
                            userInfo['picture'] = (typeof googleUser['picture'] === 'string' ? googleUser['picture'] as string : userInfo['picture']);
                        }
                    } else if (provider === 'windowslive' && accessToken) {
                        const msRes = await fetch('https://graph.microsoft.com/v1.0/me', {
                            headers: { Authorization: `Bearer ${accessToken}` }
                        });
                        if (msRes.ok) {
                            const msUser = await msRes.json() as Record<string, unknown>;
                            userInfo['name'] = (typeof msUser['displayName'] === 'string' ? msUser['displayName'] as string : userInfo['name']);
                        }
                    }
                }
            } catch (mgmtError) {
                logger.warn('[AUTH-LOGIN] Failed to fetch full Auth0 profile', { error: mgmtError });
            }

            // (provider extraction removed — not used)

        } catch (error) {
            logger.warn('[AUTH-LOGIN] Failed to fetch user info from Auth0', { error });
        }

        const email = typeof userInfo['email'] === 'string' ? userInfo['email'] as string : (typeof claims.email === 'string' ? claims.email : '');
        const name = typeof userInfo['name'] === 'string' ? userInfo['name'] as string : (typeof claims.name === 'string' ? claims.name : undefined);
        const picture = typeof userInfo['picture'] === 'string' ? userInfo['picture'] as string : (typeof claims.picture === 'string' ? claims.picture : undefined);

        const user = await findOrCreateByAuth0({
            auth0Sub: claims.sub,
            email,
            name,
            picture,
            roles: extractRoles(claims),
        });

        const response: AuthExchangeResponse = {
            user: toProfile(user),
        };

        res.json(response);

    } catch (error) {
        const errObj = error instanceof Error ? { message: error.message, stack: error.stack, name: error.name } : error;
        logger.error('[AUTH-LOGIN] Login error', { error: errObj });
        res.status(500).json({
            error: 'Internal server error',
            message: error instanceof Error ? error.message : 'Unknown error',
        });
    }
});

/**
 * GET /auth/me
 * Get current authenticated user
 */
authRouter.get('/me', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;

        const user = await resolveUserFromClaims(claims);

        if (!user) {
            sendUserNotFound(res, 'No account found for this email. Please sign up or call /auth/login first.');
            return;
        }

        res.json({
            user: toProfile(user),
        });

    } catch (error) {
        logger.error('[AUTH-ME] Get user error', { error });
        res.status(500).json({
            error: 'Internal server error',
        });
    }
});

/**
 * POST /auth/verify
 * Verify token without syncing user
 */
authRouter.post('/verify', async (req: Request, res: Response) => {
    try {
        const token = req.body?.token || extractBearerToken(req);

        if (!token) {
            res.status(400).json({
                error: 'Missing token',
            });
            return;
        }

        const claims = await verifyAuth0Token(token);

        const response: TokenVerifyResponse = {
            valid: true,
            claims: claims,
        };

        res.json(response);

    } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid token';
        if (error instanceof Auth0UnavailableError) {
            logger.warn('[AUTH-VERIFY] Auth0 unreachable during verification', { message });
            res.status(503).json({
                error: 'Auth service temporarily unavailable',
                message: 'Could not reach Auth0 to verify the token. Please retry.',
            });
            return;
        }
        const response: TokenVerifyResponse = {
            valid: false,
            error: message,
        };
        res.json(response);
    }
});

/**
 * POST /validate
 * Legacy endpoint for HTTP fallback from other services
 */
authRouter.post('/validate', async (req: Request, res: Response) => {
    try {
        const token = extractBearerToken(req);
        if (!token) {
            res.status(401).json({ error: 'Missing token' });
            return;
        }
        const claims = await verifyAuth0Token(token);
        const roles = extractRoles(claims as Auth0Claims);
        
        res.json({
            id: claims.sub,
            email: claims.email,
            name: claims.name,
            picture: claims.picture,
            roles: roles,
        });
    } catch (error) {
        if (error instanceof Auth0UnavailableError) {
            logger.warn('[AUTH-VALIDATE] Auth0 unreachable during validation', {
                message: error.message,
            });
            res.status(503).json({ error: 'Auth service temporarily unavailable' });
            return;
        }
        res.status(401).json({ error: 'Invalid token' });
    }
});

/**
 * POST /validate-api-key
 * Legacy endpoint for HTTP fallback
 */
authRouter.post('/validate-api-key', async (req: Request, res: Response) => {
    try {
        const apiKey = req.headers['x-api-key'] || req.body?.api_key;
        if (!apiKey) {
            res.status(401).json({ error: 'Missing API key' });
            return;
        }
        
        if (apiKey === config.internalApiKey) {
            res.json({
                id: 'internal-service-user',
                email: 'internal@confuse.dev',
                name: 'Internal Service',
                roles: ['service'],
                workspace_id: 'system',
            });
            return;
        }
        res.status(401).json({ error: 'Invalid API key' });
    } catch (error) {
        res.status(500).json({ error: 'Internal error' });
    }
});

/**
 * POST /internal/tokens
 * Internal endpoint for fetching tokens
 */
authRouter.post('/internal/tokens', async (req: Request, res: Response) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (apiKey !== config.internalApiKey) {
            res.status(401).json({ success: false, error: 'Invalid API key' });
            return;
        }
        const { userId, provider } = req.body;
        
        const providerAliases = getProviderAliases(provider);
        const account = await prisma.account.findFirst({
            where: { userId, provider: { in: providerAliases } }
        });
        if (!account || (!account.access_token && !account.refresh_token)) {
            res.status(404).json({ success: false, error: 'Connection invalid' });
            return;
        }
        const finalToken = await refreshTokenIfNeeded(account, provider);
        
        res.json({
            success: true,
            provider: account.provider,
            access_token: finalToken,
            refresh_token: account.refresh_token,
            token_type: 'Bearer'
        });
    } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        logger.error('[INTERNAL-TOKENS] Failed to fetch internal token', { error: errorMsg });
        res.status(500).json({ success: false, error: errorMsg });
    }
});


/**
 * GET /auth/connections
 * Get user's social connections
 */
authRouter.get('/connections', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const user = await resolveUserFromClaims(claims);

        if (!user) {
            sendUserNotFound(res);
            return;
        }

        const connections = await prisma.account.findMany({
            where: { userId: user.id },
            select: {
                provider: true,
                providerAccountId: true,
                type: true,
                scope: true,
            }
        });

        const data = connections.map((c: { providerAccountId: string; provider: string; type: string; scope: string | null }) => ({
            id: c.providerAccountId,
            platform: c.provider === 'google' ? 'google_drive' : (['windowslive', 'waad', 'microsoft', 'onedrive'].includes(c.provider) ? 'onedrive' : c.provider),
            type: c.type,
            scope: c.scope,
            username: null,
            is_active: true,
        }));

        res.json({
            success: true,
            data,
        });

    } catch (error) {
        logger.error('[AUTH-CONNECTIONS] Connections fetch error', { error });
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
    }
});

/**
 * GET /auth/oauth/url
 * Generate OAuth URL for providers
 * Supports: github, slack, notion
 */
authRouter.get('/oauth/url', async (req: Request, res: Response) => {
    try {
        const { provider, login_hint } = req.query;
        // Prefix state with provider so frontend callback can extract it
        const state = `${provider}:${randomBytes(16).toString('hex')}`;

        if (provider === 'github') {
            const clientId = config.github.clientId;
            const redirectUri = config.github.redirectUri;
            if (!clientId || !redirectUri) return void res.status(400).json({ error: 'GitHub OAuth not configured' });

            res.json({
                url: `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&scope=repo,read:user`,
                provider: 'github',
            });

        } else if (provider === 'gitlab') {
            const clientId = config.gitlab.clientId;
            const redirectUri = config.gitlab.redirectUri;
            if (!clientId || !redirectUri) return void res.status(400).json({ error: 'GitLab OAuth not configured' });
            res.json({
                url: `https://gitlab.com/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&state=${state}&scope=read_api%20read_repository`,
                provider: 'gitlab',
            });

        } else if (provider === 'bitbucket') {
            const clientId = config.bitbucket.clientId;
            const redirectUri = config.bitbucket.redirectUri;
            if (!clientId || !redirectUri) return void res.status(400).json({ error: 'Bitbucket OAuth not configured' });
            res.json({
                url: `https://bitbucket.org/site/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&state=${state}`,
                provider: 'bitbucket',
            });

        } else if (provider === 'slack') {
            const clientId = config.slack.clientId;
            const redirectUri = config.slack.redirectUri;
            if (!clientId || !redirectUri) {
                res.status(400).json({ error: 'Slack OAuth is not configured. Set SLACK_CLIENT_ID.' });
                return;
            }
            const scopes = 'channels:history,channels:read,users:read,team:read';
            res.json({
                url: `https://slack.com/oauth/v2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&scope=${scopes}`,
                provider: 'slack',
            });

        } else if (provider === 'notion') {
            const clientId = config.notion.clientId;
            const redirectUri = config.notion.redirectUri;
            if (!clientId || !redirectUri) {
                res.status(400).json({ error: 'Notion OAuth is not configured. Set NOTION_CLIENT_ID.' });
                return;
            }
            let notionUrl = `https://api.notion.com/v1/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&owner=user&state=${state}`;
            if (login_hint) {
                notionUrl += `&login_hint=${encodeURIComponent(login_hint as string)}`;
            }
            res.json({
                url: notionUrl,
                provider: 'notion',
            });


        } else if (provider === 'microsoft' || provider === 'onedrive') {
            const clientId = config.microsoft.clientId;
            const tenantId = config.microsoft.tenantId || 'common';
            const redirectUri = config.microsoft.redirectUri;
            if (!clientId || !redirectUri) {
                res.status(400).json({ error: 'Microsoft OAuth is not configured. Set MICROSOFT_CLIENT_ID.' });
                return;
            }
            const pkce = oAuthStateService.generatePKCE();
            const codeVerifier = pkce.codeVerifier;
            const codeChallenge = pkce.codeChallenge;
            await oAuthStateService.storeState(state, {
                provider,
                redirectUri,
                codeVerifier,
            });

            const scopes = 'https://graph.microsoft.com/Files.Read https://graph.microsoft.com/Files.ReadWrite offline_access https://graph.microsoft.com/User.Read';
            let msUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize?client_id=${clientId}&response_type=code&scope=${encodeURIComponent(scopes)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&response_mode=query&prompt=select_account&code_challenge=${codeChallenge}&code_challenge_method=S256`;
            if (login_hint) {
                msUrl += `&login_hint=${encodeURIComponent(login_hint as string)}`;
            }
            res.json({
                url: msUrl,
                provider: 'microsoft',
            });

        } else if (provider === 'dropbox') {
            const clientId = config.dropbox.clientId;
            const redirectUri = config.dropbox.redirectUri;
            if (!clientId || !redirectUri) {
                res.status(400).json({ error: 'Dropbox OAuth is not configured.' });
                return;
            }
            const pkce = oAuthStateService.generatePKCE();
            const codeVerifier = pkce.codeVerifier;
            const codeChallenge = pkce.codeChallenge;
            await oAuthStateService.storeState(state, {
                provider,
                redirectUri,
                codeVerifier,
            });

            res.json({
                url: `https://www.dropbox.com/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256&token_access_type=offline`,
                provider: 'dropbox',
            });

        } else {
            res.status(400).json({ error: `Unsupported provider: ${provider}` });
        }
    } catch (error) {
        logger.error('[AUTH-OAUTH-URL] Error', { error });
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * POST /auth/oauth/exchange
 * Exchange code for token and save connection
 * Supports: github, slack, notion, custom_apps
 */
authRouter.post('/oauth/exchange', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const user = await resolveUserFromClaims(claims);
        
        if (!user) {
            res.status(404).json({ error: 'No user account found for this email address. Please sign in with your primary Google or Microsoft account first.' });
            return;
        }

        const { provider, code, token: customToken, metadata } = req.body;
        
        if (provider === 'github') {
            const clientId = config.github.clientId;
            const clientSecret = config.github.clientSecret;
            if (!clientId || !clientSecret) return void res.status(400).json({ error: 'GitHub not configured' });

            const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    client_id: clientId,
                    client_secret: clientSecret,
                    code
                })
            });
            
            const tokenData = await tokenRes.json();
            
            if (tokenData.error) {
                logger.error('[AUTH-OAUTH-EXCHANGE] GitHub token error', { error: tokenData.error });
                res.status(400).json({ error: tokenData.error_description || tokenData.error });
                return;
            }
            
            const accessToken = tokenData.access_token;
            
            // Get user info to get providerAccountId
            const userRes = await fetch('https://api.github.com/user', {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/vnd.github.v3+json'
                }
            });
            
            const userData = await userRes.json();


            // Email match check removed to allow connecting accounts with different emails

            const providerAccountId = String(userData.id);
            
            await prisma.account.upsert({
                where: {
                    provider_providerAccountId: {
                        provider: 'github',
                        providerAccountId
                    }
                },
                update: {
                    userId: user.id,
                    type: 'oauth',
                    access_token: accessToken,
                    scope: tokenData.scope || 'repo',
                },
                create: {
                    userId: user.id,
                    type: 'oauth',
                    provider: 'github',
                    providerAccountId,
                    access_token: accessToken,
                    scope: tokenData.scope || 'repo',
                }
            });
            
            res.json({ success: true, message: 'GitHub connected successfully' });

        } else if (provider === 'gitlab') {
            const clientId = config.gitlab.clientId;
            const clientSecret = config.gitlab.clientSecret;
            const redirectUri = config.gitlab.redirectUri;
            if (!clientId || !clientSecret || !redirectUri) return void res.status(400).json({ error: 'GitLab not configured' });
            
            const tokenRes = await fetch('https://gitlab.com/oauth/token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    client_id: clientId,
                    client_secret: clientSecret,
                    code,
                    grant_type: 'authorization_code',
                    redirect_uri: redirectUri
                })
            });
            
            const tokenData = await tokenRes.json();
            
            if (tokenData.error) {
                logger.error('[AUTH-OAUTH-EXCHANGE] GitLab token error', { error: tokenData.error });
                res.status(400).json({ error: tokenData.error_description || tokenData.error });
                return;
            }
            
            const accessToken = tokenData.access_token;
            const refreshToken = tokenData.refresh_token;
            const expiresIn = tokenData.expires_in;
            
            // Get user info to get providerAccountId
            const userRes = await fetch('https://gitlab.com/api/v4/user', {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/json'
                }
            });
            
            const userData = await userRes.json();
            // Email match check removed to allow connecting accounts with different emails

            const providerAccountId = String(userData.id);
            
            await prisma.account.upsert({
                where: {
                    provider_providerAccountId: {
                        provider: 'gitlab',
                        providerAccountId
                    }
                },
                update: {
                    userId: user.id,
                    type: 'oauth',
                    access_token: accessToken,
                    refresh_token: refreshToken,
                    expires_at: expiresIn ? Math.floor(Date.now() / 1000) + expiresIn : null,
                    scope: tokenData.scope || 'read_api read_repository',
                },
                create: {
                    userId: user.id,
                    type: 'oauth',
                    provider: 'gitlab',
                    providerAccountId,
                    access_token: accessToken,
                    refresh_token: refreshToken,
                    expires_at: expiresIn ? Math.floor(Date.now() / 1000) + expiresIn : null,
                    scope: tokenData.scope || 'read_api read_repository',
                }
            });

            res.json({ success: true, message: 'GitLab connected successfully' });

        } else if (provider === 'bitbucket') {
            const clientId = config.bitbucket.clientId;
            const clientSecret = config.bitbucket.clientSecret;
            const redirectUri = config.bitbucket.redirectUri;
            if (!clientId || !clientSecret || !redirectUri) return void res.status(400).json({ error: 'Bitbucket not configured' });
            
            const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
            
            const tokenRes = await fetch('https://bitbucket.org/site/oauth2/access_token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': `Basic ${credentials}`,
                    'Accept': 'application/json'
                },
                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    code,
                    redirect_uri: redirectUri
                }).toString()
            });
            
            const tokenData = await tokenRes.json();
            
            if (tokenData.error) {
                logger.error('[AUTH-OAUTH-EXCHANGE] Bitbucket token error', { error: tokenData.error });
                res.status(400).json({ error: tokenData.error_description || tokenData.error });
                return;
            }
            
            const accessToken = tokenData.access_token;
            const refreshToken = tokenData.refresh_token;
            const expiresIn = tokenData.expires_in;
            
            // Get user info to get providerAccountId
            const userRes = await fetch('https://api.bitbucket.org/2.0/user', {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/json'
                }
            });
            
            const userData = await userRes.json();
            const providerAccountId = String(userData.account_id);
            
            await prisma.account.upsert({
                where: {
                    provider_providerAccountId: {
                        provider: 'bitbucket',
                        providerAccountId
                    }
                },
                update: {
                    userId: user.id,
                    type: 'oauth',
                    access_token: accessToken,
                    refresh_token: refreshToken,
                    expires_at: expiresIn ? Math.floor(Date.now() / 1000) + expiresIn : null,
                    scope: tokenData.scopes || 'repository',
                },
                create: {
                    userId: user.id,
                    type: 'oauth',
                    provider: 'bitbucket',
                    providerAccountId,
                    access_token: accessToken,
                    refresh_token: refreshToken,
                    expires_at: expiresIn ? Math.floor(Date.now() / 1000) + expiresIn : null,
                    scope: tokenData.scopes || 'repository',
                }
            });

            res.json({ success: true, message: 'Bitbucket connected successfully' });

        } else if (provider === 'slack') {
            const clientId = config.slack.clientId;
            const clientSecret = config.slack.clientSecret;
            const redirectUri = config.slack.redirectUri;

            if (!clientId || !clientSecret || !redirectUri) {
                res.status(400).json({ error: 'Slack OAuth is not configured. Set SLACK_CLIENT_ID and SLACK_CLIENT_SECRET env vars.' });
                return;
            }

            const tokenRes = await fetch('https://slack.com/api/oauth.v2.access', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    client_id: clientId,
                    client_secret: clientSecret,
                    code,
                    redirect_uri: redirectUri,
                }).toString(),
            });

            const tokenData = await tokenRes.json();

            if (!tokenData.ok) {
                logger.error('[AUTH-OAUTH-EXCHANGE] Slack token error', { error: tokenData.error });
                res.status(400).json({ error: tokenData.error || 'Slack OAuth failed' });
                return;
            }

            const accessToken = tokenData.access_token || tokenData.authed_user?.access_token;
            const teamId = tokenData.team?.id || 'unknown';
            const providerAccountId = tokenData.authed_user?.id || teamId;

            await prisma.account.upsert({
                where: {
                    provider_providerAccountId: {
                        provider: 'slack',
                        providerAccountId: String(providerAccountId),
                    }
                },
                update: {
                    userId: user.id,
                    type: 'oauth',
                    access_token: accessToken,
                    scope: tokenData.scope || '',
                },
                create: {
                    userId: user.id,
                    type: 'oauth',
                    provider: 'slack',
                    providerAccountId: String(providerAccountId),
                    access_token: accessToken,
                    scope: tokenData.scope || '',
                }
            });

            res.json({ success: true, message: 'Slack connected successfully' });

        } else if (provider === 'notion') {
            const clientId = config.notion.clientId;
            const clientSecret = config.notion.clientSecret;
            const redirectUri = config.notion.redirectUri;

            if (!clientId || !clientSecret || !redirectUri) {
                res.status(400).json({ error: 'Notion OAuth is not configured. Set NOTION_CLIENT_ID and NOTION_CLIENT_SECRET env vars.' });
                return;
            }

            // Notion uses Basic auth for token exchange
            const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

            const tokenRes = await fetch('https://api.notion.com/v1/oauth/token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Basic ${basicAuth}`,
                },
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    code,
                    redirect_uri: redirectUri,
                }),
            });

            const tokenData = await tokenRes.json();

            if (tokenData.error) {
                logger.error('[AUTH-OAUTH-EXCHANGE] Notion token error', { error: tokenData.error });
                res.status(400).json({ error: tokenData.error_description || tokenData.error });
                return;
            }

            const accessToken = tokenData.access_token;
            const workspaceId = tokenData.workspace_id || 'unknown';
            const providerAccountId = tokenData.owner?.user?.id || workspaceId;

            await prisma.account.upsert({
                where: {
                    provider_providerAccountId: {
                        provider: 'notion',
                        providerAccountId: String(providerAccountId),
                    }
                },
                update: {
                    userId: user.id,
                    type: 'oauth',
                    access_token: accessToken,
                    scope: 'read_content',
                },
                create: {
                    userId: user.id,
                    type: 'oauth',
                    provider: 'notion',
                    providerAccountId: String(providerAccountId),
                    access_token: accessToken,
                    scope: 'read_content',
                }
            });

            res.json({ success: true, message: 'Notion connected successfully' });



        } else if (provider === 'microsoft' || provider === 'onedrive') {
            const clientId = config.microsoft.clientId;
            const clientSecret = config.microsoft.clientSecret;
            const tenantId = config.microsoft.tenantId || 'consumers';
            const redirectUri = config.microsoft.redirectUri;

            if (!clientId || !redirectUri) {
                res.status(400).json({ error: 'Microsoft OAuth is not configured. Set MICROSOFT_CLIENT_ID and MICROSOFT_REDIRECT_URI env vars.' });
                return;
            }

            let codeVerifier: string | undefined;
            if (req.body.state) {
                const storedState = await oAuthStateService.validateState(req.body.state);
                if (storedState && storedState.codeVerifier) {
                    codeVerifier = storedState.codeVerifier;
                }
            }

            const bodyParams = new URLSearchParams({
                client_id: clientId,
                code,
                redirect_uri: redirectUri,
                grant_type: 'authorization_code'
            });
            
            if (codeVerifier) {
                bodyParams.append('code_verifier', codeVerifier);
            }
            
            // Public clients (e.g. SPAs) using PKCE will throw AADSTS700025 if client_secret is provided
            if (clientSecret && !codeVerifier) {
                bodyParams.append('client_secret', clientSecret);
            }

            const tokenRes = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Origin': config.frontendUrl
                },
                body: bodyParams.toString(),
            });

            const tokenData = await tokenRes.json();

            if (tokenData.error) {
                logger.error('[AUTH-OAUTH-EXCHANGE] Microsoft token error', { error: tokenData.error });
                res.status(400).json({ error: tokenData.error_description || tokenData.error });
                return;
            }

            const accessToken = tokenData.access_token;

            // Microsoft Graph /me
            const userRes = await fetch('https://graph.microsoft.com/v1.0/me', {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/json'
                }
            });

            const userData = await userRes.json();

            const providerAccountId = String(userData.id);

            await prisma.account.upsert({
                where: {
                    provider_providerAccountId: {
                        provider: 'onedrive',
                        providerAccountId
                    }
                },
                update: {
                    userId: user.id,
                    type: 'oauth',
                    access_token: accessToken,
                    refresh_token: tokenData.refresh_token,
                    scope: tokenData.scope,
                    expires_at: tokenData.expires_in ? Math.floor(Date.now() / 1000) + tokenData.expires_in : null,
                },
                create: {
                    userId: user.id,
                    type: 'oauth',
                    provider: 'onedrive',
                    providerAccountId,
                    access_token: accessToken,
                    refresh_token: tokenData.refresh_token,
                    scope: tokenData.scope,
                    expires_at: tokenData.expires_in ? Math.floor(Date.now() / 1000) + tokenData.expires_in : null,
                }
            });

            res.json({ success: true, message: 'Microsoft connected successfully' });

        } else if (provider === 'dropbox') {
            const clientId = config.dropbox.clientId;
            const clientSecret = config.dropbox.clientSecret;
            const redirectUri = config.dropbox.redirectUri;

            if (!clientId || !redirectUri) {
                res.status(400).json({ error: 'Dropbox OAuth is not configured.' });
                return;
            }

            let codeVerifier: string | undefined;
            if (req.body.state) {
                const storedState = await oAuthStateService.validateState(req.body.state);
                if (storedState && storedState.codeVerifier) {
                    codeVerifier = storedState.codeVerifier;
                }
            }

            const bodyParams = new URLSearchParams({
                client_id: clientId,
                code,
                redirect_uri: redirectUri,
                grant_type: 'authorization_code'
            });

            if (codeVerifier) {
                bodyParams.append('code_verifier', codeVerifier);
            }

            if (clientSecret && !codeVerifier) {
                bodyParams.append('client_secret', clientSecret);
            }

            const tokenRes = await fetch('https://api.dropboxapi.com/oauth2/token', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: bodyParams.toString(),
            });

            const tokenData = await tokenRes.json();

            if (tokenData.error) {
                logger.error('[AUTH-OAUTH-EXCHANGE] Dropbox token error', { error: tokenData.error });
                res.status(400).json({ error: tokenData.error_description || tokenData.error });
                return;
            }

            const accessToken = tokenData.access_token;

            // Get Dropbox user info
            const userRes = await fetch('https://api.dropboxapi.com/2/users/get_current_account', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                },
                body: 'null'
            });

            const userData = await userRes.json();

            if (userData.error) {
                logger.error('[AUTH-OAUTH-EXCHANGE] Dropbox user error', { error: userData.error });
                res.status(400).json({ error: 'Failed to get Dropbox user info' });
                return;
            }

            const providerAccountId = String(userData.account_id);

            await prisma.account.upsert({
                where: {
                    provider_providerAccountId: {
                        provider: 'dropbox',
                        providerAccountId
                    }
                },
                update: {
                    userId: user.id,
                    type: 'oauth',
                    access_token: accessToken,
                    refresh_token: tokenData.refresh_token,
                    scope: tokenData.scope,
                    expires_at: tokenData.expires_in ? Math.floor(Date.now() / 1000) + tokenData.expires_in : null,
                },
                create: {
                    userId: user.id,
                    type: 'oauth',
                    provider: 'dropbox',
                    providerAccountId,
                    access_token: accessToken,
                    refresh_token: tokenData.refresh_token,
                    scope: tokenData.scope,
                    expires_at: tokenData.expires_in ? Math.floor(Date.now() / 1000) + tokenData.expires_in : null,
                }
            });

            res.json({ success: true, message: 'Dropbox connected successfully' });


        } else if (provider === 'custom_apps') {
            // Custom apps use API key/token directly (no OAuth code exchange)
            if (!customToken) {
                res.status(400).json({ error: 'Token is required for custom app connections' });
                return;
            }

            const appName = metadata?.name || 'custom-app';
            const providerAccountId = metadata?.app_id || `custom-${Date.now()}`;

            await prisma.account.upsert({
                where: {
                    provider_providerAccountId: {
                        provider: 'custom_apps',
                        providerAccountId: String(providerAccountId),
                    }
                },
                update: {
                    userId: user.id,
                    type: 'api_key',
                    access_token: customToken,
                    scope: metadata?.scope || '',
                },
                create: {
                    userId: user.id,
                    type: 'api_key',
                    provider: 'custom_apps',
                    providerAccountId: String(providerAccountId),
                    access_token: customToken,
                    scope: metadata?.scope || '',
                }
            });

            res.json({ success: true, message: `Custom app "${appName}" connected successfully` });

        } else {
            res.status(400).json({ error: `Unsupported provider: ${provider}` });
        }
    } catch (error) {
        logger.error('[AUTH-OAUTH-EXCHANGE] Error', { error });
        res.status(500).json({ error: 'Internal server error' });
    }
});


/**
 * DELETE /auth/connections/:provider
 * Disconnect a social provider
 */
authRouter.delete('/connections/:provider', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const provider = req.params.provider as string;

        const claims = req.user as Auth0Claims;
        const user = await resolveUserFromClaims(claims);

        if (!user) {
            sendUserNotFound(res);
            return;
        }

        let targetProviders = [provider];
        if (provider === 'google_drive') targetProviders = ['google', 'google-oauth2'];
        if (provider === 'onedrive') targetProviders = ['windowslive', 'waad', 'microsoft', 'onedrive'];

        await prisma.account.deleteMany({
            where: {
                userId: user.id,
                provider: { in: targetProviders },
            },
        });

        res.json({
            success: true,
            message: `Disconnected ${provider} successfully`,
        });

    } catch (error) {
        logger.error('[AUTH-CONNECTIONS-DISCONNECT] Disconnect error', { error });
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
    }
});

/**
 * POST /auth/connections/sync
 * Sync user identities from Auth0 Management API
 */
authRouter.post('/connections/sync', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const user = await resolveUserFromClaims(claims);

        if (!user) {
            res.status(404).json({ error: 'No user account found for this email address. Please sign in with your primary Google or Microsoft account first.' });
            return;
        }

        const targetProvider = req.body.targetProvider as string | undefined;
        logger.info('[AUTH-CONNECTIONS] Starting sync', { email: user.email, targetProvider });

        const mgmtClient = Auth0ManagementClient.getInstance();
        // Step 1: Query Auth0 for all users that share the exact same email
        let auth0Users: Array<Record<string, unknown>> = [];
        if (user.email && user.email.trim() !== '') {
            auth0Users = await mgmtClient.getUsersByEmail(user.email);
        } else {
            const profile = await mgmtClient.getUserProfile(claims.sub);
            if (profile) {
                auth0Users = [profile];
            }
        }

        const results = [];

        // Step 2: Iterate over every matching user profile, and every identity within those profiles
        for (const auth0User of auth0Users) {
            const identities: Array<Record<string, unknown>> = Array.isArray((auth0User as Record<string, unknown>).identities)
                ? ((auth0User as Record<string, unknown>).identities as Array<Record<string, unknown>>)
                : [];

            for (const identity of identities) {
                const _providerName = String(identity['provider'] ?? '').replace('-oauth2', '');

                if (targetProvider) {
                    const normalizedTarget = targetProvider.replace('-oauth2', '').replace('google_drive', 'google').replace('windowslive', 'windowslive');
                    if (_providerName !== normalizedTarget) {
                        logger.info('[AUTH-CONNECTIONS] Skipping provider during sync', { provider: _providerName, targetProvider });
                        continue;
                    }
                }

                logger.info('[AUTH-CONNECTIONS] Syncing identity', { provider: _providerName, targetProvider });

                // Identity provider access tokens may not be present depending on Auth0 scope settings
                // We still want to record the connection so the UI updates and other parts can fallback to ENV tokens

                // Upsert the account record
                    const providerAccountId = typeof identity['user_id'] === 'string' ? identity['user_id'] as string : String(identity['user_id']);
                    const accessToken = typeof identity['access_token'] === 'string' ? identity['access_token'] as string : null;
                    const refreshToken = typeof identity['refresh_token'] === 'string' ? identity['refresh_token'] as string : null;
                    const scopeVal = typeof identity['scope'] === 'string' ? identity['scope'] as string : '';
                    const expiresAt = typeof identity['expires_at'] === 'number' ? Math.floor((identity['expires_at'] as number) * 1000) : (typeof identity['expires_at'] === 'string' && !isNaN(Number(identity['expires_at'])) ? Math.floor(Number(identity['expires_at']) * 1000) : null);

                    const result = await prisma.account.upsert({
                    where: {
                        provider_providerAccountId: {
                                provider: _providerName,
                            providerAccountId: providerAccountId,
                        }
                    },
                    update: {
                        type: 'oauth',
                            provider: _providerName,
                        providerAccountId: providerAccountId,
                        access_token: accessToken,
                        refresh_token: refreshToken,
                        scope: scopeVal,
                        expires_at: expiresAt,
                    },
                    create: {
                        userId: user.id,
                        type: 'oauth',
                        provider: _providerName,
                        providerAccountId: providerAccountId,
                        access_token: accessToken,
                        refresh_token: refreshToken,
                        scope: scopeVal,
                        expires_at: expiresAt,
                    },
                });
                results.push(result);
            }
        }

        res.json({
            success: true,
            synced: results.length,
            connections: results.map(c => ({
                id: c.providerAccountId,
                platform: c.provider === 'google' ? 'google_drive' : (['windowslive', 'waad', 'microsoft', 'onedrive'].includes(c.provider) ? 'onedrive' : c.provider),
                is_active: true,
            })),
        });

    } catch (error) {
        logger.error('Sync connections error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
    }
});

export async function refreshTokenIfNeeded(account: any, provider: string): Promise<string> {
    let finalAccessToken = account.access_token;
    
    let needsRefresh = false;
    if (!account.access_token && account.refresh_token) {
        needsRefresh = true;
    }
    if (provider === 'gitlab') {
        if (!account.access_token || (account.expires_at && account.expires_at < Date.now() / 1000 + 60)) {
            needsRefresh = true;
        } else {
            // Test token validity
            try {
                const testRes = await fetch('https://gitlab.com/api/v4/user', {
                    headers: { 'Authorization': `Bearer ${finalAccessToken}` }
                });
                if (testRes.status === 401) {
                    needsRefresh = true;
                }
            } catch (e) {
                // Ignore network errors here, let the actual request fail if so
            }
        }
    } else if (provider === 'microsoft' || provider === 'onedrive' || provider === 'windowslive' || provider === 'waad') {
        if (!account.access_token || (account.expires_at && account.expires_at < Date.now() / 1000 + 60)) {
            needsRefresh = true;
        } else {
            // Test token validity
            try {
                const testRes = await fetch('https://graph.microsoft.com/v1.0/me', {
                    headers: { 'Authorization': `Bearer ${finalAccessToken}` }
                });
                if (testRes.status === 401) {
                    needsRefresh = true;
                }
            } catch (e) {
                // Ignore network errors here, let the actual request fail if so
            }
        }
    } else if (!account.access_token && account.refresh_token) {
        needsRefresh = true;
    }

    if (needsRefresh && account.refresh_token) {
        try {
            let tokenRes;
            if (provider === 'gitlab') {
                tokenRes = await fetch('https://gitlab.com/oauth/token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        client_id: config.gitlab.clientId || '',
                        client_secret: config.gitlab.clientSecret || '',
                        refresh_token: account.refresh_token,
                        grant_type: 'refresh_token'
                    })
                });
            } else if (provider === 'microsoft' || provider === 'onedrive' || provider === 'windowslive' || provider === 'waad') {
                // Use 'common' to match the authorization flow — supports both personal and work accounts
                const tenantId = config.microsoft.tenantId || 'common';
                const clientId = config.microsoft.clientId || '';
                const clientSecret = config.microsoft.clientSecret || '';

                // Try refresh WITHOUT client_secret first (PKCE/public client flow).
                // If the app was registered as a public client or the user authenticated
                // via PKCE, Microsoft rejects requests that include client_secret (AADSTS700025).
                const baseParams: Record<string, string> = {
                    client_id: clientId,
                    refresh_token: account.refresh_token,
                    grant_type: 'refresh_token',
                    scope: 'https://graph.microsoft.com/Files.Read https://graph.microsoft.com/Files.ReadWrite offline_access https://graph.microsoft.com/User.Read'
                };

                tokenRes = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams(baseParams).toString()
                });

                // If public-client refresh failed and we have a client_secret,
                // retry as a confidential client (AADSTS700027).
                if (!tokenRes.ok && clientSecret) {
                    const errorData = await tokenRes.json().catch(() => ({}));
                    const errorCode = errorData?.error || '';
                    // AADSTS700027 = confidential client requires client_secret/assertion
                    // AADSTS7000218 = request must include client_secret
                    if (errorCode === 'invalid_client' || errorCode.includes('700027') || errorCode.includes('7000218')) {
                        logger.info('[TOKEN-REFRESH] Public client refresh rejected, retrying as confidential client', { provider });
                        tokenRes = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: new URLSearchParams({
                                ...baseParams,
                                client_secret: clientSecret
                            }).toString()
                        });
                    }
                }
            }

            if (tokenRes) {
                const tokenData = await tokenRes.json();
                if (!tokenData.error && tokenData.access_token) {
                    finalAccessToken = tokenData.access_token;
                    await prisma.account.update({
                        where: { id: account.id },
                        data: {
                            access_token: finalAccessToken,
                            refresh_token: tokenData.refresh_token || account.refresh_token,
                            expires_at: tokenData.expires_in ? Math.floor(Date.now() / 1000) + tokenData.expires_in : null
                        }
                    });
                    logger.info('[TOKEN-REFRESH] Successfully refreshed token', { provider, accountId: account.id });
                } else {
                    logger.error(`[TOKEN-REFRESH] ${provider} token refresh failed`, { error: tokenData.error, description: tokenData.error_description });
                    // Only clear the access_token — preserve refresh_token so we can retry.
                    // Microsoft refresh tokens are valid for up to 90 days;
                    // the failure might be transient (network, rate limit, etc.).
                    await prisma.account.update({
                        where: { id: account.id },
                        data: {
                            access_token: null,
                            expires_at: null
                        }
                    });
                    throw new Error(`Token refresh failed for ${provider}: ${tokenData.error_description || tokenData.error}`);
                }
            }
        } catch (err) {
            logger.error('[TOKEN-REFRESH] Error refreshing token', { provider, error: err instanceof Error ? err.message : String(err) });
            throw err;
        }
    }
    return finalAccessToken;
}

/**
 * GET /auth/connections/:provider/token
 * Fetch the decrypted access token for a connected provider
 */
authRouter.get('/connections/:provider/token', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const provider = req.params.provider as string;
        const claims = req.user as Auth0Claims;
        const user = await resolveUserFromClaims(claims);

        if (!user) {
            sendUserNotFound(res);
            return;
        }

        // We lookup the account that matches this user and provider (with alias resolution)
        const providerAliases = getProviderAliases(provider);
        const account = await prisma.account.findFirst({
            where: {
                userId: user.id,
                provider: { in: providerAliases },
            }
        });

        if (!account || (!account.access_token && !account.refresh_token)) {
            sendConnectionNotFound(res, provider);
            return;
        }

        const finalToken = await refreshTokenIfNeeded(account, provider);

        res.json({
            success: true,
            provider,
            access_token: finalToken
        });

    } catch (error) {
        logger.error('Get token error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
    }
});

/**
 * POST /auth/internal/tokens
 * Fetch the decrypted access token for a connected provider using internal API key
 */
authRouter.post('/internal/tokens', async (req: Request, res: Response) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (apiKey !== config.internalApiKey) {
            sendInvalidApiKey(res);
            return;
        }

        const { userId, provider } = req.body;

        if (!userId || !provider) {
            res.status(400).json({ error: 'Missing userId or provider' });
            return;
        }

        const providerAliases = getProviderAliases(provider);
        const account = await prisma.account.findFirst({
            where: {
                userId,
                provider: { in: providerAliases },
            }
        });

        if (!account || (!account.access_token && !account.refresh_token)) {
            sendConnectionNotFound(res, provider);
            return;
        }

        const finalToken = await refreshTokenIfNeeded(account, provider);

        res.json({
            success: true,
            provider,
            access_token: finalToken,
            refresh_token: account.refresh_token,
            token_type: 'Bearer' // Add if needed
        });

    } catch (error) {
        logger.error('Internal token error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
    }
});

export default authRouter;