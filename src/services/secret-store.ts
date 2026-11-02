/**
 * ConFuse Auth Middleware - Encrypted Secret Store (application-level vault)
 *
 * WHY THIS EXISTS (vs `.secret.env`):
 *   `.secret.env` / the AKS Secret hold *deploy-time* config known before
 *   boot. This module instead protects **runtime, user-supplied secrets** —
 *   BYODB FalkorDB passwords, CA certificates and client keys that customers
 *   submit through the API after deployment. Those cannot live in env files,
 *   so they are stored AES-256-GCM encrypted in the application database and
 *   referenced elsewhere by opaque `secretRef` strings only.
 *
 * SECRETREF INDIRECTION:
 *   Connection rows store refs (e.g. `falkordb/<id>/password`), never
 *   plaintext. This keeps API DTOs (`toPublicConnection`), logs and DB
 *   dumps safe by construction, and makes rotation (`putSecret` on the same
 *   ref) and revocation (`deleteSecretsByPrefix`) independent of the rows
 *   that reference them.
 *
 * KEY MANAGEMENT:
 *   The master key comes from `SECRETS_ENCRYPTION_KEY` (32 bytes, hex or
 *   base64) in `.secret.env`. `KEY_VERSION` is stored per row so keys can be
 *   rotated later; it is currently fixed at 1.
 */

import crypto from 'crypto';
import { prisma } from '../infra/db.js';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
// Stored on every row so the master key can be rotated per-secret later;
// currently everything is written with version 1.
const KEY_VERSION = 1;

function getMasterKey(): Buffer {
  const raw = (process.env.SECRETS_ENCRYPTION_KEY ?? process.env.ENCRYPTION_MASTER_KEY ?? '').trim();
  if (!raw) {
    throw new Error('SECRETS_ENCRYPTION_KEY not configured');
  }
  if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    return Buffer.from(raw, 'hex');
  }
  const decoded = Buffer.from(raw, 'base64');
  if (decoded.length !== 32) {
    throw new Error('SECRETS_ENCRYPTION_KEY must be a 32-byte key encoded as 64-char hex or base64');
  }
  return decoded;
}

/**
 * Encrypt `plaintext` (AES-256-GCM) and persist it, returning the generated
 * `secretRef` (`<purpose>::<uuid>`). Despite the name this WRITES to the
 * database — callers (e.g. graph.ts) keep only the returned ref, never the
 * value. Use `putSecret` when a stable, caller-chosen ref is needed.
 */
export async function encryptSecret(
  plaintext: string,
  ownerId: string,
  purpose: string = 'falkordb'
): Promise<string> {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getMasterKey(), iv);
  
  let ciphertext = cipher.update(plaintext, 'utf8', 'base64');
  ciphertext += cipher.final('base64');
  
  const authTag = cipher.getAuthTag();
  const secretRef = `${purpose}::${crypto.randomUUID()}`;
  
  await prisma.secret.create({
    data: {
      secretRef,
      ownerId,
      purpose,
      algorithm: ALGORITHM,
      keyVersion: KEY_VERSION,
      ciphertext,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
    },
  });
  
  return secretRef;
}

/**
 * Look up a `secretRef` and decrypt it. Throws when the ref is unknown or the
 * ciphertext fails authentication (wrong master key or tampered row).
 */
export async function decryptSecret(secretRef: string): Promise<string> {
  const secret = await prisma.secret.findUnique({
    where: { secretRef },
  });
  
  if (!secret) {
    throw new Error('Secret not found');
  }
  
  const iv = Buffer.from(secret.iv, 'base64');
  const authTag = Buffer.from(secret.authTag, 'base64');
  const decipher = crypto.createDecipheriv(ALGORITHM, getMasterKey(), iv);
  
  decipher.setAuthTag(authTag);
  
  let plaintext = decipher.update(secret.ciphertext, 'base64', 'utf8');
  plaintext += decipher.final('utf8');
  
  return plaintext;
}

/** Remove a single secret. Idempotent (deleteMany). */
export async function deleteSecret(secretRef: string): Promise<void> {
  await prisma.secret.deleteMany({
    where: { secretRef },
  });
}

/** Store (or rotate) a secret value under a stable reference (e.g. `falkordb/<id>/password`). */
export async function putSecret(
  secretRef: string,
  ownerId: string,
  value: string,
  purpose: string = 'falkordb'
): Promise<void> {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getMasterKey(), iv);
  let ciphertext = cipher.update(value, 'utf8', 'base64');
  ciphertext += cipher.final('base64');
  const authTag = cipher.getAuthTag();
  await prisma.secret.upsert({
    where: { secretRef },
    create: {
      secretRef,
      ownerId,
      purpose,
      algorithm: ALGORITHM,
      keyVersion: KEY_VERSION,
      ciphertext,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
    },
    update: {
      ownerId,
      purpose,
      algorithm: ALGORITHM,
      keyVersion: KEY_VERSION,
      ciphertext,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
    },
  });
}

/** Retrieve and decrypt a secret value. Returns null when the ref is absent. */
export async function getSecret(secretRef: string): Promise<string | null> {
  const secret = await prisma.secret.findUnique({
    where: { secretRef },
  });
  if (!secret) {
    return null;
  }
  const iv = Buffer.from(secret.iv, 'base64');
  const authTag = Buffer.from(secret.authTag, 'base64');
  const decipher = crypto.createDecipheriv(ALGORITHM, getMasterKey(), iv);
  decipher.setAuthTag(authTag);
  let plaintext = decipher.update(secret.ciphertext, 'base64', 'utf8');
  plaintext += decipher.final('utf8');
  return plaintext;
}

/** Delete every secret whose reference starts with the given prefix. */
export async function deleteSecretsByPrefix(prefix: string): Promise<number> {
  const result = await prisma.secret.deleteMany({
    where: { secretRef: { startsWith: prefix } },
  });
  return result.count;
}


/**
 * Constant-time string comparison helper (for internal API key checks).
 * Lives here because it guards secret material — any credential comparison
 * must reuse this instead of `===` to avoid timing side channels.
 */
export function safeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
