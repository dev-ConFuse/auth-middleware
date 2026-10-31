import { PrismaClient } from '@prisma/client';
import { generateWorkspaceId } from '../src/services/id-generator.js';

const prisma = new PrismaClient();

async function createDefaultWorkspaces() {
  console.log('Starting default workspace creation...');
  
  const users = await prisma.user.findMany();
  console.log(`Found ${users.length} users`);
  
  let created = 0;
  let skipped = 0;
  
  for (const user of users) {
    try {
      // Check if user already has a workspace
      const existingMember = await prisma.workspaceMember.findFirst({
        where: { userId: user.id },
      });
      
      if (existingMember) {
        console.log(`User ${user.email} already has workspace, skipping`);
        skipped++;
        continue;
      }
      
      // Create default workspace
      const workspaceName = `${user.name || user.email.split('@')[0]}'s Workspace`;
      const workspaceId = generateWorkspaceId();
      
      await prisma.$transaction(async (tx) => {
        const workspace = await tx.workspace.create({
          data: {
            id: workspaceId,
            name: workspaceName,
          },
        });
        
        await tx.workspaceMember.create({
          data: {
            userId: user.id,
            workspaceId: workspace.id,
            role: 'ADMIN',
          },
        });
      });
      
      console.log(`Created workspace ${workspaceId} for user ${user.email}`);
      created++;
    } catch (error) {
      console.error(`Failed to create workspace for user ${user.email}:`, error);
    }
  }
  
  console.log(`\nMigration complete: ${created} created, ${skipped} skipped`);
}

createDefaultWorkspaces()
  .then(() => {
    console.log('Migration successful');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Migration failed:', error);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
