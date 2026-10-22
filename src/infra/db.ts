import { PrismaClient } from '@prisma/client';
import { Pool } from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { setDefaultResultOrder } from 'node:dns';
import { setDefaultAutoSelectFamily } from 'node:net';
import { config } from '../config.js';

// Process-wide socket behaviour, set before any connection is opened.
// WHY: Node's happy-eyeballs abandons each connect attempt after its short
// per-attempt timeout, but the container-to-Neon path needs seconds per TCP
// handshake — every attempt was dying with a bare ETIMEDOUT (~800 ms) even
// though a plain IPv4 connect succeeds in 3-9 s. Prefer IPv4 (the runtime's
// IPv6 route is dead) and let a single attempt run to DB_CONNECT_TIMEOUT_MS.
setDefaultResultOrder('ipv4first');
setDefaultAutoSelectFamily(false);

const connectionString = config.databaseUrl;
// connectionTimeoutMillis: fail fast on a hung TCP connect so withDbRetry's
// attempts fit within a user's patience instead of one 20s+ OS-level stall.
const pool = new Pool({ connectionString, connectionTimeoutMillis: config.dbConnectTimeoutMs });
const adapter = new PrismaPg(pool);

/**
 * Prisma error codes meaning "the database could not be reached / gave up"
 * (as opposed to a query/constraint problem). Used to answer 503 instead of
 * a misleading 500 when the network path to PostgreSQL is broken.
 */
const TRANSIENT_DB_CODES = new Set(['P1001', 'P1002', 'P1008', 'P1017', 'P2024']);
// Socket/transport codes the PrismaPg driver adapter surfaces directly on the
// error object (seen in the wild: CODE=ETIMEDOUT with an empty message body).
const TRANSIENT_SOCKET_CODES = /^(ETIMEDOUT|ECONNRESET|ECONNREFUSED|ECONNABORTED|EHOSTUNREACH|ENETUNREACH|EAI_AGAIN|EPIPE|EPROTO|ENOTFOUND|UND_ERR_[A-Z_]+)$/i;
const TRANSIENT_DB_MESSAGE = /can't reach database|connection (refused|reset|terminated)|timeout exceeded when trying to connect|database is not reachable|connection timeout|timed out|econnrefused|etimedout|econnreset|eai_again|fetch failed/i;
const TRANSIENT_DB_KIND = /notreachable|socket|connection|timeout/i;

function classifyOne(error: object): boolean {
    const code = (error as { code?: unknown }).code;
    if (typeof code === 'string' && (TRANSIENT_DB_CODES.has(code) || TRANSIENT_SOCKET_CODES.test(code))) {
        return true;
    }
    // PrismaPg driver adapter wraps the transport error one level down.
    const kind = (error as { meta?: { driverAdapterError?: { cause?: { kind?: unknown } } } })
        .meta?.driverAdapterError?.cause?.kind;
    if (typeof kind === 'string' && TRANSIENT_DB_KIND.test(kind)) {
        return true;
    }
    const message = error instanceof Error ? error.message : String((error as { message?: unknown }).message ?? '');
    return TRANSIENT_DB_MESSAGE.test(message);
}

/** True when the failure is DB connectivity (retryable), not a query error. */
export function isDatabaseUnavailableError(error: unknown): boolean {
    let current: unknown = error;
    // Walk a short cause chain: adapters differ in where they attach the
    // socket error (top level, `cause`, or the driverAdapterError wrapper).
    for (let depth = 0; current && typeof current === 'object' && depth < 4; depth++) {
        if (classifyOne(current)) {
            return true;
        }
        current = (current as { cause?: unknown }).cause;
    }
    return false;
}

export type DbHealthStatus = 'connected' | 'disconnected' | 'timeout';

// Last resolved probe outcome. The bounded probe returns the cached value when
// the fresh query is still in flight (cold connects take seconds here), and the
// background completion keeps the reported status converging on the truth.
let lastDbStatus: DbHealthStatus = 'timeout';

/**
 * Bounded dependency probe for GET /health. Liveness must answer even while the
 * pool is still establishing a (slow) connect, so `SELECT 1` is raced against
 * DB_HEALTH_TIMEOUT_MS and the result is cached. The probe promise is
 * pre-settled to a status, so a late driver rejection can never become an
 * unhandled rejection.
 */
export async function probeDatabaseHealth(): Promise<DbHealthStatus> {
    const probe: Promise<DbHealthStatus> = prisma.$queryRaw`SELECT 1`.then(
        () => 'connected' as const,
        () => 'disconnected' as const,
    ).then((status) => {
        lastDbStatus = status;
        return status;
    });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const bound = new Promise<DbHealthStatus>((resolve) => {
        timer = setTimeout(() => resolve(lastDbStatus), config.dbHealthTimeoutMs);
    });
    try {
        return await Promise.race([probe, bound]);
    } finally {
        if (timer) {
            clearTimeout(timer);
        }
    }
}

/** Thrown by user sync when PostgreSQL is unreachable; routes map it to 503. */
export class DatabaseUnavailableError extends Error {
    constructor(message: string, options?: { cause?: unknown }) {
        super(message, options);
        this.name = 'DatabaseUnavailableError';
    }
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Retry a DB operation on transient connectivity failures (attempts/delay are
 * env-tuned per .cline/rules/env-policy.md), then classify the final failure so
 * routes can answer 503 instead of leaking driver internals as a 500.
 */
export async function withDbRetry<T>(operation: () => Promise<T>): Promise<T> {
    const maxAttempts = Math.max(1, config.dbRetryAttempts);
    let lastError: unknown;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            return await operation();
        } catch (error) {
            lastError = error;
            if (!isDatabaseUnavailableError(error) || attempt === maxAttempts) {
                break;
            }
            await sleep(config.dbRetryDelayMs * attempt);
        }
    }
    if (isDatabaseUnavailableError(lastError)) {
        throw new DatabaseUnavailableError(
            `Database unavailable: ${lastError instanceof Error ? lastError.message : 'unknown error'}`,
            { cause: lastError }
        );
    }
    throw lastError;
}

// Prevent multiple instances of Prisma Client in development
/* eslint-disable no-var */
declare global {
    var prisma: PrismaClient | undefined;
}
/* eslint-enable no-var */

export const prisma = global.prisma || new PrismaClient({ adapter });

if (process.env.NODE_ENV !== 'production') {
    global.prisma = prisma;
}

export default prisma;
