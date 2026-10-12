import { Redis } from 'ioredis';
import { logger } from '../utils/logger.js';
import { config } from '../config.js';

const falkordbHost = config.falkordbHost;
const falkordbPort = config.falkordbPort;
const falkordbUsername = config.falkordbUsername;
const falkordbPassword = config.falkordbPassword;

/**
 * Ensures that a FalkorDB graph is created and indexed for a user.
 */
export async function createUserGraph(userId: string): Promise<void> {
  const graphName = `graph-${userId}`;
  
  logger.info(`Starting FalkorDB graph creation for user: ${userId}`, {
    graphName,
    host: falkordbHost,
    port: falkordbPort,
    username: falkordbUsername,
    hasPassword: !!falkordbPassword
  });
  
  const redis = new Redis({
    host: falkordbHost,
    port: falkordbPort,
    username: falkordbUsername,
    password: falkordbPassword,
    connectTimeout: 10000, // 10 seconds connection timeout
    lazyConnect: false, // Connect immediately
    retryStrategy: (times: number) => {
      if (times > 3) {
        return null; // Stop retrying after 3 attempts
      }
      return Math.min(times * 200, 1000); // Exponential backoff
    },
  });

  try {
    logger.info(`FalkorDB connection established, creating graph: ${graphName}`);
    
    const indexQueries = [
      'CREATE INDEX FOR (c:Vector_Chunk) ON (c.id)',
      'CREATE INDEX FOR (c:Vector_Chunk) ON (c.source_id)',
      'CREATE INDEX FOR (c:Vector_Chunk) ON (c.chunk_type)',
      'CREATE INDEX FOR (c:Vector_Chunk) ON (c.owner_id)',
      `CREATE VECTOR INDEX FOR (c:Vector_Chunk) ON (c.embeddings) OPTIONS {dimension: ${config.embeddingDimension}, similarityFunction: 'cosine'}`,
      'CREATE INDEX FOR (e:Code_Entity) ON (e.name)',
      'CREATE INDEX FOR (e:Code_Entity) ON (e.entity_type)',
      'CREATE INDEX FOR (e:Code_Entity) ON (e.source_id)',
      'CREATE INDEX FOR (e:Code_Entity) ON (e.qualified_name)',
      'CREATE INDEX FOR (e:Code_Entity) ON (e.owner_id)',
      'CREATE INDEX FOR (p:Web_Page) ON (p.url)',
      'CREATE INDEX FOR (p:Web_Page) ON (p.domain)',
      'CREATE INDEX FOR (p:Web_Page) ON (p.source_id)',
      'CREATE INDEX FOR (p:Web_Page) ON (p.owner_id)',
      'CREATE INDEX FOR (r:Repository) ON (r.owner_id)'
    ];

    for (const query of indexQueries) {
      try {
        await redis.call('GRAPH.QUERY', graphName, query);
      } catch (err: any) {
        if (err.message && (err.message.includes('Index already exists') || err.message.includes('already indexed') || err.message.includes('already exists'))) {
          continue;
        }
        logger.warn(`Non-critical error creating index "${query}" on ${graphName}:`, { error: err.message });
      }
    }
    
    logger.info(`Successfully initialized graph ${graphName}`);
  } catch (error: any) {
    logger.error(`Error initializing FalkorDB graph for user ${userId}:`, {
      error: error.message,
      stack: error.stack
    });
  } finally {
    redis.disconnect();
    logger.info(`FalkorDB connection closed for ${graphName}`);
  }
}

/**
 * Deletes a FalkorDB graph for a user, dropping all nodes and edges.
 */
export async function deleteUserGraph(userId: string): Promise<void> {
  const graphName = `graph-${userId}`;
  
  const redis = new Redis({
    host: falkordbHost,
    port: falkordbPort,
    username: falkordbUsername,
    password: falkordbPassword,
    connectTimeout: 10000, // 10 seconds connection timeout
    lazyConnect: false, // Connect immediately
    retryStrategy: (times: number) => {
      if (times > 3) {
        return null; // Stop retrying after 3 attempts
      }
      return Math.min(times * 200, 1000); // Exponential backoff
    },
  });

  try {
    logger.info(`Deleting FalkorDB graph for user: ${userId} (${graphName})`);
    
    // GRAPH.DELETE will completely remove the graph and all its data
    await redis.call('GRAPH.DELETE', graphName);
    
    logger.info(`Successfully deleted graph ${graphName}`);
  } catch (error: any) {
    // If the graph doesn't exist, it's fine. We log it but don't fail.
    if (error.message && (error.message.includes('Invalid graph name') || error.message.includes('not found') || error.message.includes('no such graph'))) {
      logger.info(`Graph ${graphName} did not exist, nothing to delete.`);
    } else {
      logger.error(`Error deleting FalkorDB graph for user ${userId}:`, error);
    }
  } finally {
    redis.disconnect();
  }
}

