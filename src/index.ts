/**
 * ConFuse Auth Middleware - Main Entry Point
 * 
 * Express application for Auth0-based authentication
 */

import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const helmet = require('helmet');
import { config } from './config.js';
import authRouter from './auth.js';
import { healthRoutes, userRoutes } from './routes/index.js';
import billingRouter from './routes/billing.js';
import { falkordbConnectionsRouter } from './routes/falkordb-connections.js';


import { randomUUID } from 'crypto';
import { logger, asyncLocalStorage } from './utils/logger.js';
import { rateLimitMiddleware, initRedis } from './middleware/rate-limiter.js';
import { securityHeadersMiddleware } from './middleware/security-headers.js';
import { startGrpcServer } from './infra/grpc.js';

// Global error handler for uncaught exceptions
process.on('uncaughtException', (error) => {
    logger.error('[AUTH-MIDDLEWARE] Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('[AUTH-MIDDLEWARE] Unhandled Rejection at:', promise, 'reason:', reason);
});

// Initialize Redis for rate limiting (with error handling)
try {
    initRedis();
    logger.info('[AUTH-MIDDLEWARE] Redis initialized for rate limiting');
} catch (error) {
    logger.warn('[AUTH-MIDDLEWARE] Redis initialization failed, rate limiting disabled:', error);
}

const app = express();

// Security middleware
logger.info('[AUTH-MIDDLEWARE] Setting up security middleware...');
app.use(helmet());
app.use(securityHeadersMiddleware());

// CORS configuration
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        // Allow localhost, confuse.site subdomains, and explicitly configured origins
        if (
            origin.includes('localhost') || 
            origin.endsWith('.confuse.site') ||
            config.corsOrigins.includes(origin)
        ) {
            callback(null, true);
        } else {
            callback(null, false);
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Authorization',
        'Content-Type',
        'X-Api-Key',
        'X-Span-Id',
        'X-Trace-Id',
        'X-Request-Id',
        'X-Correlation-Id',
        'x-user-id',
        'X-User-Id'
    ],
}));

// Body parsing
app.use(express.json());

// Rate limiting (after body parsing, before routes)
app.use(rateLimitMiddleware());

// Correlation ID and Request logging
app.use((req: Request, res: Response, next: NextFunction) => {
    const correlationId = (req.headers['x-correlation-id'] as string) || randomUUID();
    res.setHeader('X-Correlation-Id', correlationId);

    const store = new Map<string, string>();
    store.set('correlationId', correlationId);

    asyncLocalStorage.run(store, () => {
        const start = Date.now();
        logger.http(`[REQUEST] ${req.method} ${req.path} started`, {
            headers: { authorization: req.headers.authorization ? 'present' : 'absent', 'x-service-name': req.headers['x-service-name'] },
            ip: req.ip,
        });
        res.on('finish', () => {
            const duration = Date.now() - start;
            const level = res.statusCode >= 400 ? 'error' : 'info';
            const msg = `[RESPONSE] ${req.method} ${req.path} ${res.statusCode} ${duration}ms`;
            if (level === 'error') {
                logger.error(msg);
            } else {
                logger.http(msg);
            }
        });
        next();
    });
});

// Health & Metrics
app.use('/', healthRoutes);

// Authentication API
app.use('/api/auth', authRouter);

// Legacy Authentication API (for fallback endpoints)
app.use('/auth', authRouter);

// User Profile & Onboarding API
app.use('/api/v1/user', userRoutes);

// Billing & Subscription API
app.use('/api/v1/billing', billingRouter);

// Customer-owned FalkorDB Connections API
app.use('/api/v1/falkordb-connections', falkordbConnectionsRouter);


// User Stats (Dashboard mock data)
app.get('/api/users/stats', (req: Request, res: Response) => {
    res.json({
        context_requests: 1247,
        security_score: 98,
        total_users: 1,
        active_users: 1,
        api_calls: 3450,
        storage_used: 1024 * 1024 * 50,
        bandwidth_used: 1024 * 1024 * 100
    });
});

// 404 handler
app.use((req: Request, res: Response) => {
    logger.warn(`[AUTH-MIDDLEWARE] [404] Route not found: ${req.method} ${req.path}`);
    res.status(404).json({
        error: 'Not found',
        path: req.path,
    });
});

// Error handler
app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
    logger.error(`[AUTH-MIDDLEWARE] [ERROR] Unhandled error: ${err.message}`, { stack: err.stack });
    res.status(500).json({
        error: 'Internal server error',
        message: config.nodeEnv === 'development' ? err.message : undefined,
    });
});

// Start server
const PORT = config.port;

logger.info('[AUTH-MIDDLEWARE] ==================================================');
logger.info('[AUTH-MIDDLEWARE] Starting Auth Middleware Service...');
logger.info('[AUTH-MIDDLEWARE] ==================================================');
logger.info(`[AUTH-MIDDLEWARE] Timestamp: ${new Date().toISOString()}`);
logger.info(`[AUTH-MIDDLEWARE] Node version: ${process.version}`);
logger.info(`[AUTH-MIDDLEWARE] Environment: ${config.nodeEnv}`);

const server = app.listen(PORT, () => {
    logger.info('');
    logger.info('╔══════════════════════════════════════════════════════════╗');
    logger.info('║        🔐 ConFuse Auth Middleware (TypeScript)           ║');
    logger.info('╠══════════════════════════════════════════════════════════╣');
    logger.info(`║  🚀 Server running on http://localhost:${PORT}            ║`);
    logger.info(`║  📊 Environment: ${config.nodeEnv.padEnd(37)}║`);
    logger.info(`║  🌐 Auth0 Domain: ${config.auth0.domain.substring(0, 35).padEnd(36)}║`);
    logger.info('╚══════════════════════════════════════════════════════════╝');
    logger.info('');

    // Start gRPC Server
    try {
        startGrpcServer();
        logger.info('[AUTH-MIDDLEWARE] gRPC server started successfully');
    } catch (error) {
        logger.error('[AUTH-MIDDLEWARE] Failed to start gRPC server:', error);
    }
});

// Handle server errors
server.on('error', (error) => {
    logger.error('[AUTH-MIDDLEWARE] Server error:', error);
    process.exit(1);
});

export default app;
