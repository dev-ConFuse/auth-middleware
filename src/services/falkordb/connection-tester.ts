/**
 * ConFuse Auth Middleware - FalkorDB Connection Tester
 *
 * Implements the standard verification flow for customer-owned FalkorDB
 * endpoints (Cloud, self-hosted, BYOC — identical code path):
 *
 *   1. connect       — TCP/TLS connection to the endpoint
 *   2. authenticate  — AUTH with username/password when supplied
 *   3. ping          — PING to confirm the server responds
 *   4. falkordb      — GRAPH.LIST to verify the FalkorDB module is present
 *   5. graph         — verify the requested graph is reachable/creatable
 *
 * Every message and error that leaves this module is redacted; passwords and
 * TLS secrets never appear in logs, errors or results.
 */

import type {
    FalkorDbConnectionTestResult,
    FalkorDbErrorCode,
    FalkorDbTestError,
    FalkorDbTestStep,
    FalkorDbTestStepName,
} from '../../types/falkordb.js';
import { logger } from '../../utils/logger.js';
import { redactSensitive } from '../../utils/redact.js';
import { createFalkorClient, type FalkorDbClientHandle, type FalkorDbTarget } from './client.js';
import { classifyFalkorDbError } from './error-classifier.js';

const OVERALL_TIMEOUT_MS = 30_000;

interface TestFlowContext {
    /** Set once the client exists so the overall timeout can release the socket. */
    client: FalkorDbClientHandle | null;
}

export interface FalkorDbTestInput {
    target: FalkorDbTarget;
    /** Graph the customer wants to use. */
    graphName: string;
}

export async function testFalkorDbConnection(
    input: FalkorDbTestInput
): Promise<FalkorDbConnectionTestResult> {
    const startedAt = Date.now();
    const steps: FalkorDbTestStep[] = [];
    const ctx: TestFlowContext = { client: null };

    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const overallTimeout = new Promise<FalkorDbConnectionTestResult>((resolve) => {
        timeoutHandle = setTimeout(() => {
            // Release the socket so the abandoned flow settles quickly and its
            // result (discarded by the race below) is produced promptly.
            ctx.client?.close();
            resolve({
                success: false,
                steps,
                error: {
                    code: 'TCP_TIMEOUT',
                    message: redactSensitive(
                        `Connection test timed out after ${OVERALL_TIMEOUT_MS / 1000}s`
                    ),
                    hints: [
                        'The endpoint did not respond within the overall time budget.',
                        'Check network latency, firewalls or an unresponsive server, then try again.',
                    ],
                },
                durationMs: Date.now() - startedAt,
            });
        }, OVERALL_TIMEOUT_MS);
    });

    try {
        return await Promise.race([
            runTestFlow(input, startedAt, steps, ctx),
            overallTimeout,
        ]);
    } finally {
        clearTimeout(timeoutHandle);
    }
}

async function runTestFlow(
    input: FalkorDbTestInput,
    startedAt: number,
    steps: FalkorDbTestStep[],
    ctx: TestFlowContext
): Promise<FalkorDbConnectionTestResult> {
    const { target, graphName } = input;

    const stepStart = (): number => Date.now();
    const pushStep = (
        name: FalkorDbTestStepName,
        ok: boolean,
        message: string,
        from: number
    ): void => {
        steps.push({ name, ok, message: redactSensitive(message), durationMs: Date.now() - from });
    };

    if (!target.host) {
        return failure('INVALID_CONFIG', 'A host is required', [
            'Provide the FalkorDB hostname (or a falkor:// / falkors:// connection URL).',
        ]);
    }
    if (!graphName || !graphName.trim()) {
        return failure('INVALID_CONFIG', 'A graph name is required', [
            'Provide the graph name ConFuse should use for this connection.',
        ]);
    }

    function failure(
        code: FalkorDbErrorCode,
        message: string,
        hints: string[]
    ): FalkorDbConnectionTestResult {
        return {
            success: false,
            steps,
            error: { code, message: redactSensitive(message), hints },
            durationMs: Date.now() - startedAt,
        };
    }

    function finishWithError(error: FalkorDbTestError): FalkorDbConnectionTestResult {
        logger.warn('[FALKORDB-TEST] Connection test failed', {
            code: error.code,
            message: error.message,
            steps: steps.map((s) => `${s.name}:${s.ok ? 'ok' : 'fail'}`).join(','),
        });
        return {
            success: false,
            steps,
            error,
            durationMs: Date.now() - startedAt,
        };
    }

    let client: FalkorDbClientHandle | null = null;
    try {
        client = createFalkorClient(target);
        ctx.client = client;

        // ------------------------------------------------------------
        // 1. connect
        // ------------------------------------------------------------
        let t = stepStart();
        try {
            await client.raw.connect();
            pushStep('connect', true, `Connected to ${target.host}:${target.port}`, t);
        } catch (error) {
            const classified = classifyFalkorDbError(error, 'Connection failed');
            if (classified.code === 'AUTH_FAILED') {
                // Transport worked — the server closed us during auth.
                pushStep('connect', true, `Connected to ${target.host}:${target.port}`, t);
                t = stepStart();
                pushStep('authenticate', false, classified.message, t);
                return finishWithError(classified);
            }
            pushStep('connect', false, classified.message, t);
            return finishWithError(classified);
        }

        // ------------------------------------------------------------
        // 2. authenticate (only when credentials are supplied)
        // ------------------------------------------------------------
        t = stepStart();
        const hasPassword = Boolean(target.password && target.password !== '');
        try {
            if (hasPassword) {
                await (target.username
                    ? client.call('AUTH', target.username, target.password as string)
                    : client.call('AUTH', target.password as string));
                pushStep(
                    'authenticate',
                    true,
                    target.username
                        ? `Authenticated as ACL user "${target.username}"`
                        : 'Authenticated with password',
                    t
                );
            } else {
                pushStep('authenticate', true, 'No credentials supplied (anonymous access)', t);
            }
        } catch (error) {
            const classified = classifyFalkorDbError(error, 'Authentication failed');
            pushStep('authenticate', false, classified.message, t);
            return finishWithError(
                classified.code === 'UNKNOWN' ? { ...classified, code: 'AUTH_FAILED' } : classified
            );
        }

        // ------------------------------------------------------------
        // 3. ping
        // ------------------------------------------------------------
        t = stepStart();
        try {
            await client.ping();
            pushStep('ping', true, 'PING succeeded', t);
        } catch (error) {
            const classified = classifyFalkorDbError(error, 'PING failed');
            if (classified.code === 'AUTH_FAILED' && !hasPassword) {
                // The server requires credentials we were not given — attribute
                // the failure to the authenticate step for clearer UX.
                const authStep = steps.find((s) => s.name === 'authenticate');
                if (authStep) {
                    authStep.ok = false;
                    authStep.message = redactSensitive(
                        'Server requires authentication but no credentials were supplied'
                    );
                }
            }
            pushStep('ping', false, classified.message, t);
            return finishWithError(classified);
        }

        // ------------------------------------------------------------
        // 4. verify FalkorDB (GRAPH.LIST proves the FalkorDB module)
        // ------------------------------------------------------------
        t = stepStart();
        let graphNames: string[] = [];
        let serverVersion: string | undefined;
        try {
            const listReply = await client.call('GRAPH.LIST');
            graphNames = Array.isArray(listReply) ? listReply.map(String) : [];
            pushStep(
                'falkordb',
                true,
                `FalkorDB module present (${graphNames.length} graph(s) found)`,
                t
            );
        } catch (error) {
            const classified = classifyFalkorDbError(error, 'FalkorDB verification failed');
            pushStep('falkordb', false, classified.message, t);
            return finishWithError(
                classified.code === 'UNKNOWN' ? { ...classified, code: 'NOT_FALKORDB' } : classified
            );
        }

        // Optional server version (best effort — may be blocked by ACL).
        try {
            const info = String(await client.call('INFO', 'server'));
            const match = info.match(/redis_version:(\S+)/);
            if (match) serverVersion = match[1];
        } catch {
            serverVersion = undefined;
        }

        // ------------------------------------------------------------
        // 5. verify the requested graph
        // ------------------------------------------------------------
        t = stepStart();
        const graphExists = graphNames.includes(graphName);
        try {
            await client.call('GRAPH.QUERY', graphName, 'RETURN 1');
            pushStep(
                'graph',
                true,
                graphExists
                    ? `Graph "${graphName}" verified`
                    : `Graph "${graphName}" did not exist and was created — write access verified`,
                t
            );
            logger.info('[FALKORDB-TEST] Connection test passed', {
                host: target.host,
                port: target.port,
                graphName,
                graphExisted: graphExists,
            });
            return {
                success: true,
                steps,
                server: { version: serverVersion, graphCount: graphNames.length },
                graph: { name: graphName, exists: graphExists },
                durationMs: Date.now() - startedAt,
            };
        } catch (error) {
            const classified = classifyFalkorDbError(
                error,
                `Graph "${graphName}" verification failed`
            );
            pushStep('graph', false, classified.message, t);
            return finishWithError(
                classified.code === 'UNKNOWN' ? { ...classified, code: 'GRAPH_ERROR' } : classified
            );
        }
    } finally {
        client?.close();
    }
}