/**
 * ConFuse Auth Middleware - FalkorDB Client Factory
 *
 * Creates raw ioredis clients for customer-owned FalkorDB endpoints.
 * Supports:
 *   - Connection URL parsing: falkor://host:port | falkors://host:port
 *     (aliases: redis://, rediss://). Any credentials found in a URL are
 *     extracted into separate fields — secrets are NEVER kept in URLs.
 *   - Optional authentication (username/password) for ACL users.
 *   - TLS and mTLS (CA certificate, client certificate + key).
 *   - Topologies: standalone (default), sentinel, cluster.
 */

import { Redis, type Cluster, type RedisOptions } from 'ioredis';
import type { FalkorDbTopology } from '../../types/falkordb.js';

export const DEFAULT_FALKORDB_PORT = 6379;

export interface ParsedFalkorConnectionUrl {
    host: string;
    port: number;
    tlsEnabled: boolean;
    /** Extracted from the URL — move into secret fields, never persist in URLs. */
    username?: string;
    password?: string;
}

export interface FalkorDbTarget {
    host: string;
    port: number;
    username?: string;
    password?: string;
    tlsEnabled: boolean;
    caCertificate?: string;
    clientCertificate?: string;
    clientKey?: string;
    topology?: FalkorDbTopology;
    sentinelMasterName?: string;
}

export interface FalkorDbClientHandle {
    call(command: string, ...args: Array<string | number | Buffer>): Promise<unknown>;
    ping(): Promise<string>;
    close(): void;
    readonly raw: Redis | Cluster;
}

/**
 * Parse a FalkorDB connection URL.
 *
 * Supported schemes:
 *   falkor://host[:port]      — plaintext (TLS disabled)
 *   falkors://host[:port]     — TLS enabled
 *   redis://host[:port]       — alias of falkor://
 *   rediss://host[:port]      — alias of falkors://
 *
 * NOTE: `falkor://` and `falkors://` must NOT contain embedded passwords.
 * When userinfo is present it is parsed out and returned separately so the
 * caller can store it in the secret store — the URL itself is never persisted.
 */
export function parseFalkorConnectionUrl(url: string): ParsedFalkorConnectionUrl {
    const trimmed = url.trim();
    if (!trimmed) {
        throw new Error('Connection URL is empty');
    }

    let parsed: URL;
    try {
        parsed = new URL(trimmed);
    } catch {
        throw new Error(
            'Invalid connection URL. Expected falkor://host:port or falkors://host:port'
        );
    }

    const scheme = parsed.protocol.replace(/:$/, '').toLowerCase();
    let tlsEnabled: boolean;
    switch (scheme) {
        case 'falkors':
        case 'rediss':
            tlsEnabled = true;
            break;
        case 'falkor':
        case 'redis':
            tlsEnabled = false;
            break;
        default:
            throw new Error(
                `Unsupported connection URL scheme "${scheme}". Use falkor:// or falkors://`
            );
    }

    const host = parsed.hostname;
    if (!host) {
        throw new Error('Connection URL must include a host');
    }

    const port = parsed.port ? Number(parsed.port) : DEFAULT_FALKORDB_PORT;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error('Connection URL port must be between 1 and 65535');
    }

    if (parsed.pathname && parsed.pathname !== '/') {
        throw new Error(
            'Connection URL must not contain a path. Put the target graph name in the "graphName" field.'
        );
    }

    const username = parsed.username ? decodeURIComponent(parsed.username) : undefined;
    const password = parsed.password ? decodeURIComponent(parsed.password) : undefined;

    return { host, port, tlsEnabled, username, password };
}

/** Split a comma separated host list ("h1:6379,h2:6380") into sentinel/cluster nodes. */
function parseHostList(host: string, port: number): Array<{ host: string; port: number }> {
    return host
        .split(',')
        .map((entry) => entry.trim())
        .filter(Boolean)
        .map((entry) => {
            const [nodeHost, nodePort] = entry.split(':');
            const resolvedPort = nodePort ? Number(nodePort) : port;
            if (!Number.isInteger(resolvedPort) || resolvedPort < 1 || resolvedPort > 65535) {
                throw new Error(`Invalid port in host list entry "${entry}"`);
            }
            return { host: nodeHost, port: resolvedPort };
        });
}

function buildCommonOptions(target: FalkorDbTarget): RedisOptions {
    const options: RedisOptions = {
        connectTimeout: 10_000,
        // Health checks / provisioning should fail fast instead of retrying.
        maxRetriesPerRequest: 1,
        enableReadyCheck: true,
        // Explicit connect() so the "connect" step can be observed separately.
        lazyConnect: true,
        connectionName: 'confuse-falkordb-connector',
        // Never auto-reconnect in the test path; a single clear error is better.
        retryStrategy: () => null,
    };

    // Authentication is optional (some self-hosted setups run without ACL).
    if (target.password !== undefined && target.password !== '') {
        options.password = target.password;
        if (target.username) options.username = target.username;
    }

    if (target.tlsEnabled) {
        options.tls = {};
        if (target.caCertificate) options.tls.ca = target.caCertificate;
        if (target.clientCertificate) options.tls.cert = target.clientCertificate;
        if (target.clientKey) options.tls.key = target.clientKey;
    }

    return options;
}

/**
 * Create an ioredis client for the given target. The caller is responsible for
 * `connect()` and `close()`. Credentials stay in memory only — never logged.
 */
export function createFalkorClient(target: FalkorDbTarget): FalkorDbClientHandle {
    const topology = target.topology ?? 'standalone';
    const common = buildCommonOptions(target);

    let raw: Redis | Cluster;
    if (topology === 'sentinel') {
        if (!target.sentinelMasterName) {
            throw new Error('sentinelMasterName is required for sentinel topology');
        }
        raw = new Redis({
            ...common,
            sentinels: parseHostList(target.host, target.port),
            name: target.sentinelMasterName,
        });
    } else if (topology === 'cluster') {
        raw = new Redis.Cluster(parseHostList(target.host, target.port), {
            redisOptions: common,
        });
    } else {
        raw = new Redis({
            ...common,
            host: target.host,
            port: target.port,
        });
    }

    return {
        raw,
        call(command, ...args) {
            return raw.call(command, ...args) as Promise<unknown>;
        },
        ping() {
            return raw.ping();
        },
        close() {
            try {
                raw.disconnect();
            } catch {
                // Closing a never-connected client must not throw.
            }
        },
    };
}