/**
 * ConFuse Auth Middleware - FalkorDB Connection Types
 *
 * One unified connection model for customer-owned FalkorDB endpoints.
 * FalkorDB Cloud, self-hosted and BYOC deployments are all treated as plain
 * FalkorDB endpoints — authentication and connectivity NEVER depend on the
 * deployment type. `deploymentType` is optional metadata for UI/reporting only.
 */

// ============================================================================
// Core domain model
// ============================================================================

export type FalkorDbTopology = 'standalone' | 'sentinel' | 'cluster';

export type FalkorDbDeploymentType = 'cloud' | 'self_hosted' | 'byoc' | 'unknown';

export type FalkorDbTestStatus = 'passed' | 'failed';

/**
 * Unified FalkorDB connection (Cloud / self-hosted / BYOC).
 *
 * NOTE: secrets are NEVER stored here. Only secret *references* are kept in
 * the application database; the actual password / certificates live in the
 * encrypted secret store (see services/secret-store.ts).
 */
export interface FalkorDbConnection {
    id: string;
    customerId: string;

    host: string;
    port: number;

    username?: string;
    passwordSecretRef?: string;

    graphName: string;

    tlsEnabled: boolean;

    caCertificateSecretRef?: string;
    clientCertificateSecretRef?: string;
    clientKeySecretRef?: string;

    topology?: FalkorDbTopology;
    deploymentType?: FalkorDbDeploymentType;

    // --- additive operational fields (non-secret) ---

    /** Human friendly connection name shown in the UI. */
    name: string;
    /** Required when topology === 'sentinel' (service/master name). */
    sentinelMasterName?: string;
    status: 'active' | 'disabled';
    lastTestedAt?: string | Date | null;
    lastTestStatus?: FalkorDbTestStatus | null;
    createdAt: string | Date;
    updatedAt: string | Date;
}

// ============================================================================
// API payloads (write-only secret fields, never echoed back)
// ============================================================================

/**
 * Payload used to create/update a connection or run an unsaved test.
 *
 * `connectionUrl` is an optional convenience (`falkor://host:port` /
 * `falkors://host:port`). Any credentials found in a URL are extracted into the
 * separate `username`/`password` fields and are never persisted as a URL.
 */
export interface FalkorDbConnectionInput {
    name?: string;

    connectionUrl?: string;

    host?: string;
    port?: number;

    username?: string;
    /** Write-only. Stored in the secret store, never in the app database. */
    password?: string;

    graphName?: string;

    tlsEnabled?: boolean;

    /** Write-only PEM material, stored in the secret store. */
    caCertificate?: string;
    clientCertificate?: string;
    clientKey?: string;

    topology?: FalkorDbTopology;
    deploymentType?: FalkorDbDeploymentType;
    sentinelMasterName?: string;

    /** Explicitly clear the stored password (rotation/removal). */
    clearPassword?: boolean;
    clearCaCertificate?: boolean;
    clearClientCertificate?: boolean;
    clearClientKey?: boolean;

    /**
     * When true, a connection may be saved even if verification fails
     * (e.g. network allowlist not in place yet). Default: false — the
     * connection flow verifies before saving.
     */
    allowUnverified?: boolean;
}

/**
 * Safe representation returned by the API: secret material is replaced by
 * boolean flags so clients can show "configured" state without ever receiving
 * the secret itself.
 */
export interface FalkorDbConnectionPublic {
    id: string;
    customerId: string;
    name: string;

    host: string;
    port: number;

    username?: string;
    hasPassword: boolean;

    graphName: string;

    tlsEnabled: boolean;
    hasCaCertificate: boolean;
    hasClientCertificate: boolean;
    hasClientKey: boolean;

    topology?: FalkorDbTopology;
    deploymentType?: FalkorDbDeploymentType;
    sentinelMasterName?: string;

    status: 'active' | 'disabled';
    lastTestedAt?: string | null;
    lastTestStatus?: FalkorDbTestStatus | null;
    createdAt: string;
    updatedAt: string;
}

// ============================================================================
// Connection test (verification flow) results
// ============================================================================

export type FalkorDbTestStepName =
    | 'connect'
    | 'authenticate'
    | 'ping'
    | 'falkordb'
    | 'graph';

export interface FalkorDbTestStep {
    name: FalkorDbTestStepName;
    ok: boolean;
    message: string;
    durationMs: number;
}

export type FalkorDbErrorCode =
    | 'INVALID_CONFIG'
    | 'DNS_FAILURE'
    | 'CONNECTION_REFUSED'
    | 'NETWORK_UNREACHABLE'
    | 'TCP_TIMEOUT'
    | 'TLS_ERROR'
    | 'AUTH_FAILED'
    | 'ACL_DENIED'
    | 'NOT_FALKORDB'
    | 'GRAPH_ERROR'
    | 'SECRET_ERROR'
    | 'UNKNOWN';

export interface FalkorDbTestError {
    code: FalkorDbErrorCode;
    /** Redacted, safe-to-display message. Never contains secrets. */
    message: string;
    hints: string[];
}

export interface FalkorDbConnectionTestResult {
    success: boolean;
    steps: FalkorDbTestStep[];
    server?: {
        version?: string;
        graphCount?: number;
    };
    graph?: {
        name: string;
        exists: boolean;
    };
    error?: FalkorDbTestError;
    durationMs: number;
}

// ============================================================================
// Internal resolved connection (service-to-service only)
// ============================================================================

/**
 * Fully resolved connection including decrypted secrets. Only used
 * server-side to build clients — NEVER serialized into API responses meant
 * for browsers, logs or telemetry.
 */
export interface ResolvedFalkorDbConnection {
    connection: FalkorDbConnection;
    credentials: {
        password?: string;
        caCertificate?: string;
        clientCertificate?: string;
        clientKey?: string;
    };
}