import { PrismaClient } from '@prisma/client';
import { generateGraphId } from '../src/services/id-generator.js';

const prisma = new PrismaClient();

async function migrateFalkorDbConnections() {
  console.log('Starting FalkorDB connection to Graph migration...');
  
  const connections = await prisma.falkorDbConnection.findMany({
    include: {
      customer: {
        include: {
          workspaceMembers: {
            where: { role: 'ADMIN' },
            take: 1,
            include: {
              workspace: true,
            },
          },
        },
      },
    },
  });
  
  console.log(`Found ${connections.length} FalkorDB connections`);
  
  let migrated = 0;
  let skipped = 0;
  
  for (const connection of connections) {
    try {
      const workspace = connection.customer.workspaceMembers[0]?.workspace;
      
      if (!workspace) {
        console.warn(`No workspace found for user ${connection.customerId}, skipping`);
        skipped++;
        continue;
      }
      
      // Check if graph already exists
      const existingGraph = await prisma.graph.findFirst({
        where: {
          workspaceId: workspace.id,
          falkorDbConnectionId: connection.id,
        },
      });
      
      if (existingGraph) {
        console.log(`Graph already exists for connection ${connection.id}, skipping`);
        skipped++;
        continue;
      }
      
      // Create Graph record
      const graphId = generateGraphId();
      
      await prisma.$transaction(async (tx) => {
        const graph = await tx.graph.create({
          data: {
            id: graphId,
            workspaceId: workspace.id,
            name: connection.name,
            type: 'BYODB',
            status: 'ACTIVE',
            falkorDbConnectionId: connection.id,
          },
        });
        
        // Set as active graph if workspace has none
        if (!workspace.activeGraphId) {
          await tx.workspace.update({
            where: { id: workspace.id },
            data: { activeGraphId: graph.id },
          });
        }
      });
      
      console.log(`Created Graph ${graphId} for connection ${connection.id}`);
      migrated++;
    } catch (error) {
      console.error(`Failed to migrate connection ${connection.id}:`, error);
    }
  }
  
  console.log(`\nMigration complete: ${migrated} migrated, ${skipped} skipped`);
}

migrateFalkorDbConnections()
  .then(() => {
    console.log('Migration successful');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Migration failed:', error);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
