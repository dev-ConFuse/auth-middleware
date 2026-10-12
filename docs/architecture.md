# Auth Middleware Architecture

> Internal architecture and authentication flows

## System Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          AUTH-MIDDLEWARE                                  │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                         Request Layer                                │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │  Rate Limiter → CORS → Body Parser → Request Logger                 │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                    │                                      │
│                                    ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                          Router Layer                                │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │                                                                      │ │
│  │   /auth/*          /oauth/*          /api-keys/*      /sessions/*   │ │
│  │      │                 │                  │               │         │ │
│  │      ▼                 ▼                  ▼               ▼         │ │
│  │  ┌────────┐      ┌──────────┐       ┌──────────┐    ┌──────────┐   │ │
│  │  │  Auth  │      │  OAuth   │       │ API Key  │    │ Session  │   │ │
│  │  │ Routes │      │  Routes  │       │  Routes  │    │  Routes  │   │ │
│  │  └────────┘      └──────────┘       └──────────┘    └──────────┘   │ │
│  │                                                                      │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                    │                                      │
│                                    ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                         Service Layer                                │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │                                                                      │ │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐    │ │
│  │  │ JWT Service│  │OAuth Servce│  │ Key Service│  │Session Svc │    │ │
│  │  │            │  │            │  │            │  │            │    │ │
│  │  │• Sign      │  │• GitHub    │  │• Generate  │  │• Create    │    │ │
│  │  │• Verify    │  │• Google    │  │• Validate  │  │• Validate  │    │ │
│  │  │• Refresh   │  │• GitLab    │  │• Revoke    │  │• Destroy   │    │ │
│  │  │• Revoke    │  │• Exchange  │  │• List      │  │• List      │    │ │
│  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘    │ │
│  │                                                                      │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                    │                                      │
│                                    ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                          Data Layer                                  │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │      PostgreSQL                                                       │ │
│  │                                                                       │ │
│  │  • users  • api_keys  • sessions  • oauth_tokens  • audit_logs        │ │
│  │  (token cache, rate limits and OAuth state are in-memory per process) │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

## Authentication Flows

### 1. Email/Password Login

```
┌──────────┐     ┌──────────────────┐     ┌───────────┐
│  Client  │     │  Auth-Middleware │     │ PostgreSQL│
└────┬─────┘     └────────┬─────────┘     └─────┬─────┘
     │                    │                     │
     │ POST /auth/login   │                     │
     │ {email, password}  │                     │
     │───────────────────>│                     │
     │                    │                     │
     │                    │ SELECT user WHERE   │
     │                    │ email = ?           │
     │                    │────────────────────>│
     │                    │                     │
     │                    │     User record     │
     │                    │<────────────────────│
     │                    │                     │
     │                    │ bcrypt.compare      │
     │                    │ (password, hash)    │
     │                    │                     │
     │                    │ Generate JWT        │
     │                    │ (access + refresh)  │
     │                    │                     │
     │                    │ Store session       │
     │                    │────────────────────>│
     │                    │                     │
     │                    │ Log auth event      │
     │                    │────────────────────>│
     │                    │                     │
     │ {accessToken,      │                     │
     │  refreshToken,     │                     │
     │  user}             │                     │
     │<───────────────────│                     │
```

### 2. OAuth2 Flow (GitHub Example)

```
┌──────────┐   ┌───────────┐   ┌──────────────────┐   ┌────────┐
│  Client  │   │  Frontend │   │  Auth-Middleware │   │ GitHub │
└────┬─────┘   └─────┬─────┘   └────────┬─────────┘   └────┬───┘
     │               │                  │                  │
     │ Click         │                  │                  │
     │ "Login with   │                  │                  │
     │  GitHub"      │                  │                  │
     │──────────────>│                  │                  │
     │               │                  │                  │
     │               │ GET /oauth/github│                  │
     │               │─────────────────>│                  │
     │               │                  │                  │
     │               │ Redirect to      │                  │
     │               │ github.com/oauth │                  │
     │               │<─────────────────│                  │
     │               │                  │                  │
     │               │ ─────────────────────────────────────>
     │               │                  │   User authorizes │
     │               │ <─────────────────────────────────────
     │               │                  │                  │
     │               │ GET /oauth/      │                  │
     │               │ github/callback  │                  │
     │               │ ?code=xxx        │                  │
     │               │─────────────────>│                  │
     │               │                  │                  │
     │               │                  │ POST /oauth/token│
     │               │                  │─────────────────>│
     │               │                  │                  │
     │               │                  │ {access_token}   │
     │               │                  │<─────────────────│
     │               │                  │                  │
     │               │                  │ GET /user        │
     │               │                  │─────────────────>│
     │               │                  │                  │
     │               │                  │ {user profile}   │
     │               │                  │<─────────────────│
     │               │                  │                  │
     │               │                  │ Create/update    │
     │               │                  │ user, store      │
     │               │                  │ OAuth token      │
     │               │                  │                  │
     │               │ Redirect with    │                  │
     │               │ JWT token        │                  │
     │               │<─────────────────│                  │
     │               │                  │                  │
     │ Logged in     │                  │                  │
     │<──────────────│                  │                  │
```

### 3. Token Verification (By Other Services)

```
┌─────────────┐     ┌──────────────────┐
│ API-Backend │     │  Auth-Middleware │
└──────┬──────┘     └────────┬─────────┘
       │                     │
       │ GET /auth/verify    │
       │ Authorization:      │
       │ Bearer <token>      │
       │────────────────────>│
       │                     │
       │                     │ Check token cache
       │                     │ (in-memory)
       │                     │
       │                     │ JWT.verify(token,
       │                     │ secret)
       │                     │
       │ {valid: true,       │
       │  user: {...}}       │
       │<────────────────────│
```

### 4. API Key Validation

```
┌─────────────────┐     ┌──────────────────┐     ┌───────────┐
│ Data-Connector  │     │  Auth-Middleware │     │ PostgreSQL│
└────────┬────────┘     └────────┬─────────┘     └─────┬─────┘
         │                       │                     │
         │ POST /api-keys/       │                     │
         │ validate              │                     │
         │ {apiKey: "key_xxx"}   │                     │
         │──────────────────────>│                     │
         │                       │                     │
         │                       │ Hash key            │
         │                       │ SHA256(apiKey)      │
         │                       │                     │
         │                       │ SELECT * FROM       │
         │                       │ api_keys WHERE      │
         │                       │ key_hash = ?        │
         │                       │────────────────────>│
         │                       │                     │
         │                       │ {id, user_id,       │
         │                       │  scopes, expires}   │
         │                       │<────────────────────│
         │                       │                     │
         │                       │ Check expiry        │
         │                       │ Check scopes        │
         │                       │                     │
         │ {valid: true,         │                     │
         │  userId: "xxx",       │                     │
         │  scopes: ["read"]}    │                     │
         │<──────────────────────│                     │
```

## JWT Token Structure

### Access Token

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user-uuid-here",
    "email": "user@example.com",
    "name": "John Doe",
    "roles": ["user"],
    "iat": 1704067200,
    "exp": 1704070800,
    "iss": "confuse-auth",
    "aud": "https://api.confuse.dev"
  }
}
```

- **sub**: User ID (subject)
- **iat**: Issued at timestamp
- **exp**: Expiration (1 hour default)
- **iss**: Issuer (this service)
- **aud**: Audience (API consumers)

### Refresh Token

```json
{
  "payload": {
    "sub": "user-uuid-here",
    "jti": "unique-token-id",
    "iat": 1704067200,
    "exp": 1704672000,
    "type": "refresh"
  }
}
```

- **jti**: Unique token ID (for revocation)
- **exp**: Expiration (7 days default)
- **type**: Identifies as refresh token

## Security Measures

### Password Hashing

```typescript
// bcrypt with work factor 12
const hash = await bcrypt.hash(password, 12);
const isValid = await bcrypt.compare(password, hash);
```

### Rate Limiting

| Endpoint | Limit | Window |
|----------|-------|--------|
| POST /auth/login | 5 attempts | 15 minutes |
| POST /auth/register | 3 attempts | 1 hour |
| POST /auth/refresh | 10 attempts | 1 minute |
| POST /api-keys/validate | 100 requests | 1 minute |

### Token Blacklisting

Planned but not yet implemented — the `token_blacklist` Postgres table exists
but no code path reads or writes it yet. When implemented, token verification
must consult the blacklist before accepting a token.

### Audit Logging

All authentication events are logged:

```typescript
interface AuditLog {
  event: 'login' | 'logout' | 'token_refresh' | 'api_key_created' | ...;
  userId: string;
  ip: string;
  userAgent: string;
  success: boolean;
  metadata: object;
  timestamp: Date;
}
```
