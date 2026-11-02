import crypto from 'crypto';
import { prisma } from '../infra/db.js';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
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


/** Constant-time string comparison helper (for internal API key checks). */
export function safeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
