/**
 * ConFuse Auth Middleware - FalkorDB Error Classification
 *
 * Turns raw driver/socket errors into actionable, secret-free diagnostics.
 * Pure functions — safe to unit test without any network or DB.
 *
 * All messages returned from here are passed through redactSensitive so a
 * credential-bearing URL or PEM block can never leak through an error path.
 */

import { redactSensitive } from '../../utils/redact.js';
import type { FalkorDbErrorCode, FalkorDbTestError } from '../../types/falkordb.js';

const NETWORK_HINTS = [
    'If this FalkorDB is not publicly reachable, pick one: (1) expose a public endpoint and allowlist ConFuse egress IPs in your firewall/security group, (2) site-to-site VPN, (3) VPC/network peering or private link, or (4) a customer-side connector/agent for highly private deployments.',
    'Verify the host and port are reachable from outside your network (try `nc -vz <host> <port>` from a public machine).',
];

const LEAST_PRIVILEGE_HINTS = [
    'Use a dedicated least-privilege ACL user for ConFuse instead of the default user, e.g. `ACL SETUSER confus on >STRONG_PASSWORD ~graph:* +@read +@write +@graph +ping +info +client +hello` — grant only the graph commands ConFuse needs.',
    'Confirm the ACL user is allowed to access the requested graph name (key pattern) and that `AUTH` is permitted for it.',
];

function classifyCode(message: string): FalkorDbErrorCode {
    const m = message.toLowerCase();
    if (/enotfound|eai_again|getaddrinfo|dns/.test(m)) return 'DNS_FAILURE';
    if (/econnrefused/.test(m)) return 'CONNECTION_REFUSED';
    if (/ehostunreach|enetunreach|network is unreachable/.test(m)) return 'NETWORK_UNREACHABLE';
    if (/etimedout|connect timeout|timed? ?out|timeout/.test(m)) return 'TCP_TIMEOUT';
    if (
        /cert_has_expired|self.signed|unable_to_verify|unable to get local issuer|depth_zero_self_signed|ssl3_get_record|wrong version number|tlsv1|ssl routines|handshake|certificate|econnreset.*ssl/i.test(m)
    ) {
        return 'TLS_ERROR';
    }
    if (/wrongpass|noauth|invalid password|invalid username-password|authentication|auth failed|wrong number of arguments for 'auth'/.test(m)) {
        return 'AUTH_FAILED';
    }
    if (/noperm|noaccess|not allowed|no permission|this user has no permissions/.test(m)) return 'ACL_DENIED';
    if (/unknown command|unsupported command|graph\.|graph is not loaded|module/.test(m)) return 'NOT_FALKORDB';
    return 'UNKNOWN';
}

/**
 * Build a structured, redacted error with hints from a raw error.
 * `context` is a short prefix like "Failed to connect" — it must not contain
 * secrets; it is redacted anyway as a safety net.
 */
export function classifyFalkorDbError(error: unknown, context: string): FalkorDbTestError {
    const rawMessage =
        error instanceof Error ? error.message : typeof error === 'string' ? error : String(error);
    const message = redactSensitive(rawMessage);
    const code = classifyCode(message);

    const hints: string[] = [];
    switch (code) {
        case 'DNS_FAILURE':
            hints.push('Check the hostname spelling. Private DNS names may not resolve from ConFuse infrastructure.');
            hints.push(...NETWORK_HINTS);
            break;
        case 'CONNECTION_REFUSED':
            hints.push(`Check that FalkorDB is listening on the configured port and that the port is correct.`);
            hints.push(...NETWORK_HINTS);
            break;
        case 'NETWORK_UNREACHABLE':
        case 'TCP_TIMEOUT':
            hints.push(...NETWORK_HINTS);
            break;
        case 'TLS_ERROR':
            hints.push('Make sure the TLS toggle matches the server: use falkors:// (TLS on) for TLS endpoints and falkor:// (TLS off) for plaintext.');
            hints.push('For self-signed or private CAs, paste the CA certificate in Advanced settings. For mTLS, provide both client certificate and client key.');
            break;
        case 'AUTH_FAILED':
            hints.push('Verify username and password. If the server uses `requirepass` only, leave the username empty.');
            hints.push(...LEAST_PRIVILEGE_HINTS);
            break;
        case 'ACL_DENIED':
            hints.push(...LEAST_PRIVILEGE_HINTS);
            break;
        case 'NOT_FALKORDB':
            hints.push('The endpoint speaks the Redis protocol but the FalkorDB module (GRAPH.*) is unavailable. Confirm this is a FalkorDB server, not plain Redis/Valkey.');
            break;
        case 'GRAPH_ERROR':
            hints.push('Check that the graph name is valid and that the ACL user can access it.');
            break;
        default:
            hints.push(...NETWORK_HINTS);
    }

    return { code, message: `${context}: ${message}`, hints };
}