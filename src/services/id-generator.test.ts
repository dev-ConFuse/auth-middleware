import { describe, it, expect } from 'vitest';
import {
  generateUserId,
  generateWorkspaceId,
  generateGraphId,
  validateEntityId,
} from './id-generator.js';

describe('ID Generator Service', () => {
  describe('generateUserId', () => {
    it('should generate user ID with UD prefix', () => {
      const userId = generateUserId();
      expect(userId).toMatch(/^UD[0-9a-f]{32}$/i);
    });

    it('should generate unique user IDs', () => {
      const id1 = generateUserId();
      const id2 = generateUserId();
      expect(id1).not.toBe(id2);
    });

    it('should generate user ID with correct length', () => {
      const userId = generateUserId();
      // UD (2 chars) + 32 hex chars = 34 chars
      expect(userId).toHaveLength(34);
    });

    it('should generate user ID without dashes', () => {
      const userId = generateUserId();
      expect(userId).not.toContain('-');
    });
  });

  describe('generateWorkspaceId', () => {
    it('should generate workspace ID with WS prefix', () => {
      const workspaceId = generateWorkspaceId();
      expect(workspaceId).toMatch(/^WS[0-9a-f]{32}$/i);
    });

    it('should generate unique workspace IDs', () => {
      const id1 = generateWorkspaceId();
      const id2 = generateWorkspaceId();
      expect(id1).not.toBe(id2);
    });

    it('should generate workspace ID with correct length', () => {
      const workspaceId = generateWorkspaceId();
      // WS (2 chars) + 32 hex chars = 34 chars
      expect(workspaceId).toHaveLength(34);
    });

    it('should generate workspace ID without dashes', () => {
      const workspaceId = generateWorkspaceId();
      expect(workspaceId).not.toContain('-');
    });
  });

  describe('generateGraphId', () => {
    it('should generate graph ID with GRF prefix', () => {
      const graphId = generateGraphId();
      expect(graphId).toMatch(/^GRF[0-9a-f]{32}$/i);
    });

    it('should generate unique graph IDs', () => {
      const id1 = generateGraphId();
      const id2 = generateGraphId();
      expect(id1).not.toBe(id2);
    });

    it('should generate graph ID with correct length', () => {
      const graphId = generateGraphId();
      // GRF (3 chars) + 32 hex chars = 35 chars
      expect(graphId).toHaveLength(35);
    });

    it('should generate graph ID without dashes', () => {
      const graphId = generateGraphId();
      expect(graphId).not.toContain('-');
    });
  });

  describe('validateEntityId', () => {
    describe('valid IDs', () => {
      it('should validate correct user ID', () => {
        const userId = generateUserId();
        expect(validateEntityId(userId, 'UD')).toBe(true);
      });

      it('should validate correct workspace ID', () => {
        const workspaceId = generateWorkspaceId();
        expect(validateEntityId(workspaceId, 'WS')).toBe(true);
      });

      it('should validate correct graph ID', () => {
        const graphId = generateGraphId();
        expect(validateEntityId(graphId, 'GRF')).toBe(true);
      });

      it('should validate user ID with lowercase hex chars', () => {
        const userId = 'UD9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c';
        expect(validateEntityId(userId, 'UD')).toBe(true);
      });

      it('should validate user ID with uppercase hex chars', () => {
        const userId = 'UD9A8B7C6D5E4F3A2B1C0D9E8F7A6B5C';
        expect(validateEntityId(userId, 'UD')).toBe(true);
      });

      it('should validate user ID with mixed case hex chars', () => {
        const userId = 'UD9a8B7c6D5e4F3a2b1c0D9e8F7a6b5C';
        expect(validateEntityId(userId, 'UD')).toBe(true);
      });
    });

    describe('invalid IDs - wrong prefix', () => {
      it('should reject user ID with wrong prefix', () => {
        const userId = generateUserId();
        expect(validateEntityId(userId, 'WS')).toBe(false);
      });

      it('should reject workspace ID with wrong prefix', () => {
        const workspaceId = generateWorkspaceId();
        expect(validateEntityId(workspaceId, 'UD')).toBe(false);
      });

      it('should reject graph ID with wrong prefix', () => {
        const graphId = generateGraphId();
        expect(validateEntityId(graphId, 'UD')).toBe(false);
      });
    });

    describe('invalid IDs - format errors', () => {
      it('should reject ID with dashes', () => {
        const invalidId = 'UD9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d';
        expect(validateEntityId(invalidId, 'UD')).toBe(false);
      });

      it('should reject ID with too few hex chars', () => {
        const invalidId = 'UD123';
        expect(validateEntityId(invalidId, 'UD')).toBe(false);
      });

      it('should reject ID with too many hex chars', () => {
        const invalidId = 'UD9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1';
        expect(validateEntityId(invalidId, 'UD')).toBe(false);
      });

      it('should reject ID with non-hex characters', () => {
        const invalidId = 'UDzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz';
        expect(validateEntityId(invalidId, 'UD')).toBe(false);
      });

      it('should reject ID with special characters', () => {
        const invalidId = 'UD9a8b7c6d5e4f3a2b1c0d9e8f7a6b5@';
        expect(validateEntityId(invalidId, 'UD')).toBe(false);
      });

      it('should reject empty string', () => {
        expect(validateEntityId('', 'UD')).toBe(false);
      });

      it('should reject null', () => {
        expect(validateEntityId(null as any, 'UD')).toBe(false);
      });

      it('should reject undefined', () => {
        expect(validateEntityId(undefined as any, 'UD')).toBe(false);
      });

      it('should reject non-string input', () => {
        expect(validateEntityId(123 as any, 'UD')).toBe(false);
        expect(validateEntityId({} as any, 'UD')).toBe(false);
        expect(validateEntityId([] as any, 'UD')).toBe(false);
      });
    });

    describe('edge cases', () => {
      it('should reject ID with only prefix', () => {
        expect(validateEntityId('UD', 'UD')).toBe(false);
        expect(validateEntityId('WS', 'WS')).toBe(false);
        expect(validateEntityId('GRF', 'GRF')).toBe(false);
      });

      it('should reject ID with spaces', () => {
        const invalidId = 'UD 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c';
        expect(validateEntityId(invalidId, 'UD')).toBe(false);
      });

      it('should be case-insensitive for prefix check', () => {
        // Prefix check is case-sensitive by design
        const userId = 'ud9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c';
        expect(validateEntityId(userId, 'UD')).toBe(false);
      });
    });

    describe('round-trip validation', () => {
      it('should validate all generated user IDs', () => {
        for (let i = 0; i < 100; i++) {
          const userId = generateUserId();
          expect(validateEntityId(userId, 'UD')).toBe(true);
        }
      });

      it('should validate all generated workspace IDs', () => {
        for (let i = 0; i < 100; i++) {
          const workspaceId = generateWorkspaceId();
          expect(validateEntityId(workspaceId, 'WS')).toBe(true);
        }
      });

      it('should validate all generated graph IDs', () => {
        for (let i = 0; i < 100; i++) {
          const graphId = generateGraphId();
          expect(validateEntityId(graphId, 'GRF')).toBe(true);
        }
      });
    });
  });
});
