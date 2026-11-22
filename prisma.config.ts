/// <reference types="node" />

import { defineConfig } from 'prisma/config';
import { env } from 'node:process';

// Runtime DATABASE_URL is provided via environment variable (mounted .secret.env)
// Build-time DATABASE_URL is provided via --build-arg PRISMA_GENERATE_URL
// Priority: runtime DATABASE_URL > build-time PRISMA_GENERATE_URL > fallback
const url = env.DATABASE_URL || env.PRISMA_GENERATE_URL || 'postgresql://localhost:5432/postgres';

export default defineConfig({
  schema: 'prisma/schema.prisma',
  datasource: {
    url,
  },
});
