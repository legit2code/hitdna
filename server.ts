/**
 * Server Entry Point — Hit DNA Music Intelligence Platform
 * Engine: PF-02.M02 (Node Server Shell)
 * Architecture Version: 5.0.0
 */

import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import express from 'express';
import { createExpressApp } from './src/server/app.ts';
import { getServerConfig } from './src/config/environment.ts';

async function startServer() {
  const config = getServerConfig();
  const app = createExpressApp();

  // Vite middleware setup for development / static serving in production
  if (config.nodeEnv !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(config.port, config.host, () => {
    console.log(`[Hit DNA Server] Running on http://${config.host}:${config.port} (Phase P01 - PF-02)`);
  });
}

startServer().catch((err) => {
  console.error('[Hit DNA Server] Fatal startup failure:', err);
  process.exit(1);
});
