/**
 * ConFuse Auth Middleware - Customer-owned FalkorDB Connection Service
 *
 * One unified connection model for FalkorDB Cloud, self-hosted and BYOC
 * endpoints — there is NO per-deployment branching anywhere in this layer.
 * `deploymentType` is metadata for UI/reporting only.
 *
 * Secret handling rules:
 *   - Passwords / certificates are write-only inputs.
 *   - They are stored AES-256-GCM encrypted in the secret store under stable
 *     refs (`falkordb/<connectionId>/<purpose>`); the app DB stores refs only.
 *   - The connection flow verifies connectivity BEFORE persisting anything;
 *     when verification fails, nothing is saved unless `allowUnverified`.
 */

import { randomUUID } from 'crypto';
import type { FalkorDbConnection as FalkorDbConnectionRow } from '@prisma/client';
import prisma from '../../infra/db.js';
import type {
    FalkorDbConnection,
    FalkorDbConnectionInput,
    FalkorDbConnectionPublic,
    FalkorDbConnectionTestResult,
    FalkorDbDeploymentType,
    FalkorDbTestStatus,
    FalkorDbTopology,
    ResolvedFalkorDbConnection,
} from '../../types/falkordb.js';
import { logger } from '../../utils/logger.js';
import { redactSensitive } from '../../utils/redact.js';
import { deleteSecret, deleteSecretsByPrefix, getSecret, putSecret } from '../secret-store.js';
import { parseFalkorConnectionUrl, type FalkorDbTarget } from './client.js';
import { testFalkorDbConnection } from './connection-tester.js';

const MAX_SECRET_LENGTH = 64 * 1024; // 64KB — plenty for PEM material
const TOPOLOGIES: FalkorDbTopology[] = ['standalone', 'sentinel', 'cluster'];
const DEPLOYMENT_TYPES: FalkorDbDeploymentType[] = ['cloud', 'self_hosted', 'byoc', 'unknown'];

export class FalkorDbInputError extends Error {
    status = 400;
    constructor(message: string) {
        super(message);
        this.name = 'FalkorDbInputError';
    }
}

export interface NormalizedConnectionInput {
    name: string;
    host: string;
    port: number;
    username?: string;
    /** Write-only secret — never persisted to the app database. */
    password?: string;
    graphName: string;
    tlsEnabled: boolean;
    caCertificate?: string;
    clientCertificate?: string;
    clientKey?: string;
    topology: FalkorDbTopology;
    deploymentType?: FalkorDbDeploymentType;
    sentinelMasterName?: string;
}

function optionalText(value: unknown, field: string, max = 255): string | undefined {
    if (value === undefined || value === null || value === '') return undefined;
    if (typeof value !== 'string') throw new FalkorDbInputError(`${field} must be a string`);
    const trimmed = value.trim();
    if (!trimmed) return undefined;
    if (trimmed.length > max) {
        throw new FalkorDbInputError(`${field} must be at most ${max} characters`);
    }
    return trimmed;
}

function requireText(value: unknown, field: string, max = 255): string {
    const text = optionalText(value, field, max);
    if (!text) throw new FalkorDbInputError(`${field} is required`);
    return text;
}

function optionalSecret(value: unknown, field: string): string | undefined {
    if (value === undefined || value === null || value === '') return undefined;
    if (typeof value !== 'string') throw new FalkorDbInputError(`${field} must be a string`);
    if (value.length > MAX_SECRET_LENGTH) {
        throw new FalkorDbInputError(`${field} is too large`);
    }
    return value;
}

/**
 * Normalize a create/update/test payload into a fully resolved connection
 * description. Accepts either discrete fields or a `falkor://` / `falkors://`
 * connection URL (aliases: redis://, rediss://). Credentials found in a URL
 * are extracted into the password field — URLs themselves are never stored.
 */
export function normalizeConnectionInput(
    input: FalkorDbConnectionInput,
    existing?: NormalizedConnectionInput
): NormalizedConnectionInput {
    let urlHost: string | undefined;
    let urlPort: number | undefined;
    let urlTls: boolean | undefined;
    let urlUsername: string | undefined;
    let urlPassword: string | undefined;

    if (input.connectionUrl) {
        const parsed = parseFalkorConnectionUrl(input.connectionUrl);
        urlHost = parsed.host;
        urlPort = parsed.port;
        urlTls = parsed.tlsEnabled;
        urlUsername = parsed.username;
        urlPassword = parsed.password;
    }

    const host = optionalText(input.host, 'host') ?? urlHost ?? existing?.host;
    if (!host) {
        throw new FalkorDbInputError(
            'host is required (or provide a falkor:// / falkors:// connectionUrl)'
        );
    }

    const portCandidate = input.port ?? urlPort ?? existing?.port ?? 6379;
    const port = Number(portCandidate);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new FalkorDbInputError('port must be an integer between 1 and 65535');
    }

    const tlsEnabled = input.tlsEnabled ?? urlTls ?? existing?.tlsEnabled ?? false;
    const topologyCandidate = input.topology ?? existing?.topology ?? 'standalone';
    if (!TOPOLOGIES.includes(topologyCandidate)) {
        throw new FalkorDbInputError(`topology must be one of: ${TOPOLOGIES.join(', ')}`);
    }

    const deploymentTypeCandidate = input.deploymentType ?? existing?.deploymentType;
    if (deploymentTypeCandidate && !DEPLOYMENT_TYPES.includes(deploymentTypeCandidate)) {
        throw new FalkorDbInputError(
            `deploymentType must be one of: ${DEPLOYMENT_TYPES.join(', ')}`
        );
    }

    const sentinelMasterName =
        optionalText(input.sentinelMasterName, 'sentinelMasterName') ?? existing?.sentinelMasterName;
    if (topologyCandidate === 'sentinel' && !sentinelMasterName) {
        throw new FalkorDbInputError('sentinelMasterName is required for sentinel topology');
    }

    return {
        name: optionalText(input.name, 'name') ?? existing?.name ?? `${host}:${port}`,
        host,
        port,
        username: optionalText(input.username, 'username') ?? urlUsername ?? existing?.username,
        password: optionalSecret(input.password, 'password') ?? urlPassword,
        graphName: requireText(input.graphName ?? existing?.graphName, 'graphName'),
        tlsEnabled,
        caCertificate: optionalSecret(input.caCertificate, 'caCertificate') ?? existing?.caCertificate,
        clientCertificate:
            optionalSecret(input.clientCertificate, 'clientCertificate') ?? existing?.clientCertificate,
        clientKey: optionalSecret(input.clientKey, 'clientKey') ?? existing?.clientKey,
        topology: topologyCandidate,
        deploymentType: deploymentTypeCandidate,
        sentinelMasterName,
    };
}

type SecretPurpose = 'password' | 'ca-cert' | 'client-cert' | 'client-key';

function secretRefFor(connectionId: string, purpose: SecretPurpose): string {
    return `falkordb/${connectionId}/${purpose}`;
}

function toDomain(row: FalkorDbConnectionRow): FalkorDbConnection {
    return {
        id: row.id,
        customerId: row.customerId,
        name: row.name,
        host: row.host,
        port: row.port,
        username: row.username ?? undefined,
        passwordSecretRef: row.passwordSecretRef ?? undefined,
        graphName: row.graphName,
        tlsEnabled: row.tlsEnabled,
        caCertificateSecretRef: row.caCertificateSecretRef ?? undefined,
        clientCertificateSecretRef: row.clientCertificateSecretRef ?? undefined,
        clientKeySecretRef: row.clientKeySecretRef ?? undefined,
        topology: (row.topology as FalkorDbTopology | null) ?? undefined,
        deploymentType: (row.deploymentType as FalkorDbDeploymentType | null) ?? undefined,
        sentinelMasterName: row.sentinelMasterName ?? undefined,
        status: (row.status as 'active' | 'disabled') ?? 'active',
        lastTestedAt: row.lastTestedAt ?? null,
        lastTestStatus: (row.lastTestStatus as FalkorDbTestStatus | null) ?? null,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
    };
}

/** Public projection: secret refs become boolean flags, secrets never leave the server. */
export function toPublicConnection(row: FalkorDbConnectionRow): FalkorDbConnectionPublic {
    const domain = toDomain(row);
    return {
        id: domain.id,
        customerId: domain.customerId,
        name: domain.name,
        host: domain.host,
        port: domain.port,
        username: domain.username,
        hasPassword: Boolean(domain.passwordSecretRef),
        graphName: domain.graphName,
        tlsEnabled: domain.tlsEnabled,
        hasCaCertificate: Boolean(domain.caCertificateSecretRef),
        hasClientCertificate: Boolean(domain.clientCertificateSecretRef),
        hasClientKey: Boolean(domain.clientKeySecretRef),
        topology: domain.topology,
        deploymentType: domain.deploymentType,
        sentinelMasterName: domain.sentinelMasterName,
        status: domain.status,
        lastTestedAt: domain.lastTestedAt
            ? new Date(domain.lastTestedAt).toISOString()
            : null,
        lastTestStatus: domain.lastTestStatus,
        createdAt: new Date(domain.createdAt).toISOString(),
        updatedAt: new Date(domain.updatedAt).toISOString(),
    };
}

function buildTarget(normalized: NormalizedConnectionInput, credentials?: {
    password?: string;
    caCertificate?: string;
    clientCertificate?: string;
    clientKey?: string;
}): FalkorDbTarget {
    return {
        host: normalized.host,
        port: normalized.port,
        username: normalized.username,
        password: credentials?.password ?? normalized.password,
        tlsEnabled: normalized.tlsEnabled,
        caCertificate: credentials?.caCertificate ?? normalized.caCertificate,
        clientCertificate: credentials?.clientCertificate ?? normalized.clientCertificate,
        clientKey: credentials?.clientKey ?? normalized.clientKey,
        topology: normalized.topology,
        sentinelMasterName: normalized.sentinelMasterName,
    };
}

async function runConnectionTest(
    normalized: NormalizedConnectionInput,
    credentials?: {
        password?: string;
        caCertificate?: string;
        clientCertificate?: string;
        clientKey?: string;
    }
): Promise<FalkorDbConnectionTestResult> {
    try {
        return await testFalkorDbConnection({
            target: buildTarget(normalized, credentials),
            graphName: normalized.graphName,
        });
    } catch (error) {
        logger.error('[FALKORDB-CONNECTIONS] Unexpected test failure', {
            error: redactSensitive(error instanceof Error ? error.message : String(error)),
        });
        return {
            success: false,
            steps: [],
            error: {
                code: 'UNKNOWN',
                message: redactSensitive(
                    error instanceof Error ? error.message : String(error)
                ),
                hints: ['Check the connection settings and try again.'],
            },
            durationMs: 0,
        };
    }
}

/** Run the verification flow for an unsaved payload (nothing is persisted). */
export async function testConnectionPayload(
    input: FalkorDbConnectionInput
): Promise<FalkorDbConnectionTestResult> {
    const normalized = normalizeConnectionInput(input);
    return runConnectionTest(normalized);
}

export async function listConnections(customerId: string): Promise<FalkorDbConnectionPublic[]> {
    const rows = await prisma.falkorDBConnection.findMany({
        where: { customerId },
        orderBy: { createdAt: 'desc' },
    });
    return rows.map(toPublicConnection);
}

export async function getConnection(
    customerId: string,
    id: string
): Promise<FalkorDbConnectionPublic | null> {
    const row = await prisma.falkorDBConnection.findFirst({ where: { id, customerId } });
    return row ? toPublicConnection(row) : null;
}

async function storeSecrets(
    connectionId: string,
    customerId: string,
    normalized: NormalizedConnectionInput
): Promise<{
    passwordSecretRef?: string;
    caCertificateSecretRef?: string;
    clientCertificateSecretRef?: string;
    clientKeySecretRef?: string;
}> {
    const refs: {
        passwordSecretRef?: string;
        caCertificateSecretRef?: string;
        clientCertificateSecretRef?: string;
        clientKeySecretRef?: string;
    } = {};

    if (normalized.password) {
        refs.passwordSecretRef = secretRefFor(connectionId, 'password');
        await putSecret(refs.passwordSecretRef, customerId, normalized.password);
    }
    if (normalized.caCertificate) {
        refs.caCertificateSecretRef = secretRefFor(connectionId, 'ca-cert');
        await putSecret(refs.caCertificateSecretRef, customerId, normalized.caCertificate);
    }
    if (normalized.clientCertificate) {
        refs.clientCertificateSecretRef = secretRefFor(connectionId, 'client-cert');
        await putSecret(refs.clientCertificateSecretRef, customerId, normalized.clientCertificate);
    }
    if (normalized.clientKey) {
        refs.clientKeySecretRef = secretRefFor(connectionId, 'client-key');
        await putSecret(refs.clientKeySecretRef, customerId, normalized.clientKey);
    }
    return refs;
}

/**
 * Create a customer-owned FalkorDB connection.
 *
 * Flow: normalize input → run the verification flow (connect, authenticate,
 * PING, verify FalkorDB, verify graph) → persist secrets + row only when
 * verification passes (or `allowUnverified` is set). On failure nothing is
 * written and the test result is returned for display.
 */
export async function createConnection(
    customerId: string,
    input: FalkorDbConnectionInput
): Promise<{ connection: FalkorDbConnectionPublic | null; testResult: FalkorDbConnectionTestResult }> {
    const normalized = normalizeConnectionInput(input);
    const testResult = await runConnectionTest(normalized);

    if (!testResult.success && !input.allowUnverified) {
        logger.info('[FALKORDB-CONNECTIONS] Verification failed — connection not saved', {
            host: normalized.host,
            port: normalized.port,
        });
        return { connection: null, testResult };
    }

    const id = randomUUID();
    const secretRefs = await storeSecrets(id, customerId, normalized);

    const row = await prisma.falkorDBConnection.create({
        data: {
            id,
            customerId,
            name: normalized.name,
            host: normalized.host,
            port: normalized.port,
            username: normalized.username,
            graphName: normalized.graphName,
            tlsEnabled: normalized.tlsEnabled,
            topology: normalized.topology,
            deploymentType: normalized.deploymentType ?? 'unknown',
            sentinelMasterName: normalized.sentinelMasterName,
            ...secretRefs,
            lastTestedAt: new Date(),
            lastTestStatus: testResult.success ? 'passed' : 'failed',
        },
    });

    logger.info('[FALKORDB-CONNECTIONS] Connection created', {
        connectionId: id,
        host: normalized.host,
        tlsEnabled: normalized.tlsEnabled,
        topology: normalized.topology,
    });
    return { connection: toPublicConnection(row), testResult };
}

/**
 * Update a connection. Secret inputs are write-only: a supplied value is
 * rotated in the secret store, `clear*` flags delete the stored secret.
 * Existing secrets are never returned to the caller.
 */
export async function updateConnection(
    customerId: string,
    id: string,
    input: FalkorDbConnectionInput
): Promise<FalkorDbConnectionPublic> {
    const row = await prisma.falkorDBConnection.findFirst({ where: { id, customerId } });
    if (!row) throw new FalkorDbInputError('Connection not found');

    const existing = toDomain(row);
    const normalized = normalizeConnectionInput(input, {
        name: existing.name,
        host: existing.host,
        port: existing.port,
        username: existing.username,
        graphName: existing.graphName,
        tlsEnabled: existing.tlsEnabled,
        topology: existing.topology ?? 'standalone',
        deploymentType: existing.deploymentType,
        sentinelMasterName: existing.sentinelMasterName,
    });

    const data: Record<string, unknown> = {
        name: normalized.name,
        host: normalized.host,
        port: normalized.port,
        username: normalized.username,
        graphName: normalized.graphName,
        tlsEnabled: normalized.tlsEnabled,
        topology: normalized.topology,
        deploymentType: normalized.deploymentType ?? existing.deploymentType ?? 'unknown',
        sentinelMasterName: normalized.sentinelMasterName,
    };

    const secretUpdates: Array<{
        clear: boolean | undefined;
        value: string | undefined;
        existingRef: string | undefined;
        purpose: SecretPurpose;
        field: string;
    }> = [
        {
            clear: input.clearPassword,
            value: input.password,
            existingRef: existing.passwordSecretRef,
            purpose: 'password',
            field: 'passwordSecretRef',
        },
        {
            clear: input.clearCaCertificate,
            value: input.caCertificate,
            existingRef: existing.caCertificateSecretRef,
            purpose: 'ca-cert',
            field: 'caCertificateSecretRef',
        },
        {
            clear: input.clearClientCertificate,
            value: input.clientCertificate,
            existingRef: existing.clientCertificateSecretRef,
            purpose: 'client-cert',
            field: 'clientCertificateSecretRef',
        },
        {
            clear: input.clearClientKey,
            value: input.clientKey,
            existingRef: existing.clientKeySecretRef,
            purpose: 'client-key',
            field: 'clientKeySecretRef',
        },
    ];

    for (const update of secretUpdates) {
        if (update.clear) {
            if (update.existingRef) await deleteSecret(update.existingRef);
            data[update.field] = null;
        } else if (update.value) {
            const ref = update.existingRef ?? secretRefFor(id, update.purpose);
            await putSecret(ref, customerId, update.value);
            data[update.field] = ref;
        }
    }

    const updated = await prisma.falkorDBConnection.update({ where: { id }, data });
    logger.info('[FALKORDB-CONNECTIONS] Connection updated', { connectionId: id });
    return toPublicConnection(updated);
}

/** Delete a connection and purge all of its secrets from the secret store. */
export async function deleteConnection(customerId: string, id: string): Promise<void> {
    const row = await prisma.falkorDBConnection.findFirst({ where: { id, customerId } });
    if (!row) throw new FalkorDbInputError('Connection not found');

    await prisma.falkorDBConnection.delete({ where: { id } });
    await deleteSecretsByPrefix(`falkordb/${id}/`);
    logger.info('[FALKORDB-CONNECTIONS] Connection deleted', { connectionId: id });
}

/** Re-run the verification flow for a saved connection and record the outcome. */
export async function testSavedConnection(
    customerId: string,
    id: string
): Promise<FalkorDbConnectionTestResult> {
    const row = await prisma.falkorDBConnection.findFirst({ where: { id, customerId } });
    if (!row) throw new FalkorDbInputError('Connection not found');

    const domain = toDomain(row);
    let credentials: {
        password?: string;
        caCertificate?: string;
        clientCertificate?: string;
        clientKey?: string;
    } = {};
    try {
        credentials = {
            password: domain.passwordSecretRef
                ? (await getSecret(domain.passwordSecretRef)) ?? undefined
                : undefined,
            caCertificate: domain.caCertificateSecretRef
                ? (await getSecret(domain.caCertificateSecretRef)) ?? undefined
                : undefined,
            clientCertificate: domain.clientCertificateSecretRef
                ? (await getSecret(domain.clientCertificateSecretRef)) ?? undefined
                : undefined,
            clientKey: domain.clientKeySecretRef
                ? (await getSecret(domain.clientKeySecretRef)) ?? undefined
                : undefined,
        };
    } catch (error) {
        return {
            success: false,
            steps: [],
            error: {
                code: 'SECRET_ERROR',
                message: redactSensitive(
                    error instanceof Error ? error.message : String(error)
                ),
                hints: [
                    'Stored secrets could not be decrypted. Re-enter the password (and certificates) to rotate them.',
                ],
            },
            durationMs: 0,
        };
    }

    const normalized = normalizeConnectionInput(
        {
            name: domain.name,
            host: domain.host,
            port: domain.port,
            username: domain.username,
            graphName: domain.graphName,
            tlsEnabled: domain.tlsEnabled,
            topology: domain.topology,
            deploymentType: domain.deploymentType,
            sentinelMasterName: domain.sentinelMasterName,
        },
        undefined
    );
    const testResult = await runConnectionTest(normalized, credentials);

    await prisma.falkorDBConnection.update({
        where: { id },
        data: {
            lastTestedAt: new Date(),
            lastTestStatus: testResult.success ? 'passed' : 'failed',
        },
    });
    return testResult;
}

/**
 * INTERNAL ONLY: resolve a connection including decrypted secrets so a
 * data-plane service can build a client. The result must never be serialized
 * into a browser-facing response or written to logs/telemetry.
 */
export async function resolveFalkorDbConnection(
    customerId: string,
    id: string
): Promise<ResolvedFalkorDbConnection> {
    const row = await prisma.falkorDBConnection.findFirst({ where: { id, customerId } });
    if (!row) throw new FalkorDbInputError('Connection not found');

    const domain = toDomain(row);
    return {
        connection: domain,
        credentials: {
            password: domain.passwordSecretRef
                ? (await getSecret(domain.passwordSecretRef)) ?? undefined
                : undefined,
            caCertificate: domain.caCertificateSecretRef
                ? (await getSecret(domain.caCertificateSecretRef)) ?? undefined
                : undefined,
            clientCertificate: domain.clientCertificateSecretRef
                ? (await getSecret(domain.clientCertificateSecretRef)) ?? undefined
                : undefined,
            clientKey: domain.clientKeySecretRef
                ? (await getSecret(domain.clientKeySecretRef)) ?? undefined
                : undefined,
        },
    };
}