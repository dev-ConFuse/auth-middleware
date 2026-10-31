import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function migrateSources() {
  console.log('Starting source workspace migration...');
  
  const sources = await prisma.source.findMany({
    include: {
      user: {
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
  
  console.log(`Found ${sources.length} sources to migrate`);
  
  let migrated = 0;
  let skipped = 0;
  
  for (const source of sources) {
    try {
      // Skip if already has workspaceId
      if (source.workspaceId && source.workspaceId !== source.userId) {
        console.log(`Source ${source.id} already has workspaceId, skipping`);
        skipped++;
        continue;
      }
      
      const workspace = source.user.workspaceMembers[0]?.workspace;
      
      if (!workspace) {
        console.warn(`No workspace found for user ${source.userId}, skipping source ${source.id}`);
        skipped++;
        continue;
      }
      
      // Update source with workspace information
      await prisma.source.update({
        where: { id: source.id },
        data: {
          workspaceId: workspace.id,
          createdBy: source.userId,
        },
      });
      
      console.log(`Migrated source ${source.id} to workspace ${workspace.id}`);
      migrated++;
    } catch (error) {
      console.error(`Failed to migrate source ${source.id}:`, error);
    }
  }
  
  console.log(`\nMigration complete: ${migrated} migrated, ${skipped} skipped`);
}

migrateSources()
  .then(() => {
    console.log('Migration successful');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Migration failed:', error);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
