import { PrismaClient } from '@prisma/client';
import { config } from './config.js';

function createPrismaClient(): PrismaClient {
  if (config.server.isDev) {
    return new PrismaClient({
      log: [
        { level: 'query', emit: 'stdout' },
        { level: 'info', emit: 'stdout' },
        { level: 'warn', emit: 'stdout' },
        { level: 'error', emit: 'stdout' },
      ],
    });
  }

  return new PrismaClient({
    log: [
      { level: 'warn', emit: 'stdout' },
      { level: 'error', emit: 'stdout' },
    ],
  });
}

// Singleton – reuse the same connection across the process.
// In development with tsx watch the module cache is fresh on each restart,
// so a new client is created automatically.
export const db = createPrismaClient();

export async function disconnectDb(): Promise<void> {
  await db.$disconnect();
}
