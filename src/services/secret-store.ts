import crypto from 'crypto';
import { prisma } from '../infra/db.js';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const KEY_VERSION = 1;

function getMasterKey(): Buffer {
  const key = process.env.ENCRYPTION_MASTER_KEY;
  if (!key) {
    throw new Error('ENCRYPTION_MASTER_KEY not configured');
  }
  return Buffer.from(key, 'base64');
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
  const secretRef = ${purpose}::;
  
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
  await prisma.secret.delete({
    where: { secretRef },
  });
}
