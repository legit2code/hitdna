/**
 * Express Application Configuration (PF-02.M02)
 * Separated from server listen logic to allow isolated integration tests.
 */

import express, { Express, Request, Response, NextFunction } from 'express';
import { apiRouter } from './routes.ts';
import { authenticateToken } from './authMiddleware.ts';
import { ErrorEnvelope } from '../contracts/system.ts';
import { getPublicClientConfig } from '../config/environment.ts';

export function createExpressApp(): Express {
  const app = express();

  app.use(express.json());
  app.use(authenticateToken);

  // Mount API routes
  app.use('/api', apiRouter);

  // Fallback 404 for unknown API routes
  app.use('/api/*', (_req: Request, res: Response) => {
    const errorResponse: ErrorEnvelope = {
      success: false,
      error: {
        code: 'ROUTE_NOT_FOUND',
        message: 'The requested API route does not exist.',
        phase: getPublicClientConfig().currentPhase,
        timestamp: new Date().toISOString(),
      },
    };
    res.status(404).json(errorResponse);
  });

  // Global error handler
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    const errorResponse: ErrorEnvelope = {
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: err.message || 'An unexpected error occurred.',
        phase: getPublicClientConfig().currentPhase,
        timestamp: new Date().toISOString(),
      },
    };
    res.status(500).json(errorResponse);
  });

  return app;
}
