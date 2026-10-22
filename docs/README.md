# ConFuse Auth Middleware

Authentication and authorization service for the ConFuse platform. Validates
Auth0 tokens, manages social (OAuth) connections, API keys, billing tiers and
FalkorDB connection records.

> This is the canonical README for the service; **all documentation lives in
> [`docs/`](./)** (this folder). See [index.md](index.md) for the docs index.

**Service**: `auth-middleware/` · **HTTP port**: `3010` · **internal gRPC**: `50058`
**Stack**: Node 22, Express, TypeScript (ESM), Prisma (PostgreSQL), ioredis

## Role in ConFuse

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CLIENT REQUEST                             │
└───────────────────────────────┬─────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  AUTH-MIDDLEWARE (This Service)                      │
│              HTTP :3010 · internal-network gRPC :50058               │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐              │
│   │ Auth0       │   │  OAuth2     │   │  API Keys   │              │
│   │ Validation  │   │  Flows      │   │  Management │              │
│   └─────────────┘   └─────────────┘   └─────────────┘              │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ Authenticated Request
                                ▼
                    ┌───────────────────────┐
                    │   All other services  │
                    └───────────────────────┘
```

## API Endpoints (verified against source)

### Authentication (`src/auth.ts`, mounted at `/auth`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/login` | POST | Verify Auth0 token, sync user to DB, return profile |
| `/auth/me` | GET | Current authenticated user (requires auth) |
| `/auth/verify` | POST | Verify token without syncing user |
| `/auth/validate` | POST | Legacy HTTP fallback validation |
| `/auth/validate-api-key` | POST | Validate an API key |
| `/auth/internal/tokens` | POST | Internal token fetch (`X-API-Key` required) |

### Social connections

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/connections` | GET | List user's social connections (requires auth) |
| `/auth/connections/sync` | POST | Sync identities from Auth0 Management API |
| `/auth/connections/:provider` | DELETE | Disconnect a provider |
| `/auth/connections/:provider/token` | GET | Decrypted provider access token |
| `/auth/oauth/url` | GET | Build OAuth authorize URL (`?provider=`) |
| `/auth/oauth/exchange` | POST | Exchange OAuth code for stored connection |

### Health & platform

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Plain liveness (`OK`) |
| `/health` | GET | Health check incl. database status |
| `/billing/plans` | GET | Public plan tiers |
| `/billing/*` | — | Subscription, usage, checkout, portal (`src/routes/billing.ts`) |
| `/falkordb/connections*` | — | FalkorDB connection CRUD + test (`src/routes/falkordb-connections.ts`) |

Full request/response schemas: [api-reference.md](api-reference.md).

## How to run the microservice

```bash
# Install dependencies
npm install

# Configure environment (non-secret / secret split)
cp .map.env.example .map.env
cp .secret.env.example .secret.env

# Database setup
npm run prisma:push

# Run development server (HTTP :3010, gRPC :50058)
npm run dev
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | HTTP server port | `3010` |
| `GRPC_PORT` | Internal gRPC server port (do not expose on untrusted networks) | `50058` |
| `DATABASE_URL` | PostgreSQL connection | Required |
| `TOKEN_CACHE_TTL_SECONDS` | Token cache TTL | `900` |
| `DB_RETRY_ATTEMPTS` | Attempts for transient Postgres connectivity failures (see `src/infra/db.ts`) | `3` |
| `DB_RETRY_DELAY_MS` | Base backoff between DB retry attempts | `500` |
| `DB_CONNECT_TIMEOUT_MS` | pg connect timeout — sized to the slow container→Neon handshake | `15000` |
| `DB_HEALTH_TIMEOUT_MS` | Upper bound for the `/health` DB probe (liveness stays fast) | `1500` |
| `FEATURE_TOGGLE_SERVICE_URL` | Feature toggle service | `http://localhost:3099` |

See [configuration.md](configuration.md) for the complete list.
The gRPC listener uses plaintext transport; keep it on an isolated, trusted
service network or configure TLS before deploying across untrusted networks.

## Logging

Structured logging with prefixes:

- `[AUTH-MIDDLEWARE]` — service-level operations
- `[FEATURE-TOGGLE]` — feature toggle client operations
- `[REQUEST]` / `[RESPONSE]` — HTTP request lifecycle

## Feature Toggle Integration

| Toggle | Effect |
|--------|--------|
| `auth-bypass` | Use demo user instead of requiring authentication (dev only) |
| `debugLogging` | Enable verbose logging |
| `skipRateLimiting` | Disable rate limiting during testing |

## Documentation

| Document | Contents |
|----------|----------|
| [index.md](index.md) | Overview & docs index |
| [api-reference.md](api-reference.md) | Full endpoint reference |
| [architecture.md](architecture.md) | Internal architecture |
| [configuration.md](configuration.md) | Environment & deployment config |
| [integration.md](integration.md) | How other services integrate |

## License

MIT
