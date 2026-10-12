# Auth Middleware Configuration

> Complete configuration guide for the ConFuse Auth-Middleware

## Environment Variables

### Required Variables

```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/confuse

# JWT Configuration
JWT_SECRET=your-secret-key-minimum-32-characters
JWT_ACCESS_EXPIRES_IN=1h
JWT_REFRESH_EXPIRES_IN=7d
```

### Optional Variables

```env
# Server
PORT=3001
HOST=0.0.0.0
NODE_ENV=development

# JWT Advanced
JWT_ISSUER=confuse-auth
JWT_AUDIENCE=https://api.confuse.dev
JWT_ALGORITHM=HS256

# Password Requirements
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBER=true
PASSWORD_REQUIRE_SPECIAL=false

# Session Settings
SESSION_MAX_AGE=86400000
SESSION_MAX_PER_USER=10

# Rate Limiting
RATE_LIMIT_LOGIN_MAX=5
RATE_LIMIT_LOGIN_WINDOW=900000
RATE_LIMIT_REGISTER_MAX=3
RATE_LIMIT_REGISTER_WINDOW=3600000


# Frontend URLs
FRONTEND_URL=http://localhost:3000
OAUTH_SUCCESS_REDIRECT=http://localhost:3000/auth/callback
OAUTH_FAILURE_REDIRECT=http://localhost:3000/auth/error

# Logging
LOG_LEVEL=info
LOG_FORMAT=json

# Email (for password reset)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
EMAIL_FROM=noreply@confuse.io
```

## Variable Details

### JWT_SECRET

**Critical security setting.** Must be:
- At least 32 characters
- Randomly generated
- Never committed to version control
- Same across all services that verify tokens

Generate a secure secret:
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### Database Configuration

The `DATABASE_URL` follows PostgreSQL format:

```
postgresql://[user]:[password]@[host]:[port]/[database]?[options]
```

**Required Tables:**
- `users` - User accounts
- `api_keys` - API keys
- `oauth_tokens` - OAuth provider tokens
- `sessions` - Active sessions
- `audit_logs` - Authentication events


### Rate Limiting Configuration

Control abuse prevention:

```env
# Login: 5 attempts per 15 minutes
RATE_LIMIT_LOGIN_MAX=5
RATE_LIMIT_LOGIN_WINDOW=900000

# Registration: 3 attempts per hour
RATE_LIMIT_REGISTER_MAX=3
RATE_LIMIT_REGISTER_WINDOW=3600000

# Token refresh: 10 per minute
RATE_LIMIT_REFRESH_MAX=10
RATE_LIMIT_REFRESH_WINDOW=60000

# API key validation: 100 per minute
RATE_LIMIT_API_KEY_MAX=100
RATE_LIMIT_API_KEY_WINDOW=60000
```

### Password Policy

Configure password requirements:

```env
PASSWORD_MIN_LENGTH=8
PASSWORD_MAX_LENGTH=128
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBER=true
PASSWORD_REQUIRE_SPECIAL=false
PASSWORD_BCRYPT_ROUNDS=12
```

## Configuration Files

### config/default.json

```json
{
  "server": {
    "port": 3001,
    "host": "0.0.0.0",
    "corsOrigins": ["http://localhost:3000"]
  },
  "jwt": {
    "accessExpiresIn": "1h",
    "refreshExpiresIn": "7d",
    "algorithm": "HS256"
  },
  "session": {
    "maxAge": 86400000,
    "maxPerUser": 10
  },
  "password": {
    "minLength": 8,
    "bcryptRounds": 12
  },
  "rateLimiting": {
    "login": {
      "max": 5,
      "windowMs": 900000
    }
  }
}
```

### config/production.json

```json
{
  "server": {
    "trustProxy": true,
    "corsOrigins": ["https://app.confuse.io"]
  },
  "jwt": {
    "accessExpiresIn": "15m",
    "refreshExpiresIn": "7d"
  },
  "password": {
    "bcryptRounds": 14
  }
}
```

## Secrets Management

### Local Development

```bash
# Generate .env from template
cp .env.example .env

# Generate secure JWT secret
echo "JWT_SECRET=$(openssl rand -hex 64)" >> .env
```

### Production

**Docker Secrets:**
```yaml
secrets:
  jwt_secret:
    external: true
  db_password:
    external: true

services:
  auth-middleware:
    secrets:
      - jwt_secret
      - db_password
```

**Kubernetes:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-secrets
type: Opaque
stringData:
  JWT_SECRET: "your-production-secret"
  DATABASE_URL: "postgresql://..."
```

## Environment-Specific Settings

### Development
```env
NODE_ENV=development
LOG_LEVEL=debug
LOG_FORMAT=pretty
JWT_ACCESS_EXPIRES_IN=24h  # Longer for dev convenience
```

### Staging
```env
NODE_ENV=staging
LOG_LEVEL=info
JWT_ACCESS_EXPIRES_IN=1h
```

### Production
```env
NODE_ENV=production
LOG_LEVEL=warn
JWT_ACCESS_EXPIRES_IN=15m  # Shorter for security
PASSWORD_BCRYPT_ROUNDS=14  # Higher for security
```
