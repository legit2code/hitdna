import './scripts/server-prelude.ts';
import { startServer } from './apps/server/main.ts';

startServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
