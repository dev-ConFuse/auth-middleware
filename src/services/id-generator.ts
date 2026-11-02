import { randomUUID } from 'crypto';

/**
 * Generates a User ID with "UD" prefix followed by UUID v4 (without dashes).
 * Format: `UD{32 lowercase hex chars}`.
 *
 * @example "UD9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c"
 */
export function generateUserId(): string {
  return `UD${randomUUID().replace(/-/g, '')}`;
}

/**
 * Generates a Workspace ID with "WS" prefix followed by UUID v4 (without dashes).
 * Format: `WS{32 lowercase hex chars}`.
 *
 * @example "WS7f3e9d2a8b4c1f5e6d9a8b7c6d5e4f"
 */
export function generateWorkspaceId(): string {
  return `WS${randomUUID().replace(/-/g, '')}`;
}

/**
 * Generates a Graph ID with "GRF" prefix followed by UUID v4 (without dashes).
 * Format: `GRF{32 lowercase hex chars}`.
 *
 * @example "GRFa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5"
 */
export function generateGraphId(): string {
  return `GRF${randomUUID().replace(/-/g, '')}`;
}

/**
 * Validates that an entity ID matches the expected prefix and format.
 * Expected format: `{prefix}{32 hex chars}` — the prefix check is
 * case-sensitive by design, the hex body is case-insensitive.
 *
 * @param id - The entity ID to validate
 * @param expectedPrefix - The expected prefix ("UD", "WS", or "GRF")
 * @returns True when the ID is valid
 *
 * @example
 * validateEntityId("UD9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c", "UD") // true
 * validateEntityId("WS7f3e9d2a8b4c1f5e6d9a8b7c6d5e4f", "UD") // false (wrong prefix)
 * validateEntityId("UD123", "UD") // false (invalid UUID format)
 */
export function validateEntityId(id: string, expectedPrefix: string): boolean {
  if (!id || typeof id !== 'string') {
    return false;
  }

  // Check if ID starts with the expected prefix
  if (!id.startsWith(expectedPrefix)) {
    return false;
  }

  // Extract the UUID part (after the prefix)
  const uuidPart = id.slice(expectedPrefix.length);

  // Validate UUID format: exactly 32 hexadecimal characters (no dashes)
  const uuidRegex = /^[0-9a-f]{32}$/i;
  return uuidRegex.test(uuidPart);
}
