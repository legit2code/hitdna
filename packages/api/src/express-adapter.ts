import { Request, Response, Router } from 'express';
import { ApplicationApiRouter, ApplicationApiRouterOptions, ApiRequestContext } from './router.ts';

export function createApiExpressRouter(routerOrOptions?: ApplicationApiRouter | ApplicationApiRouterOptions): Router {
  const apiRouter = routerOrOptions instanceof ApplicationApiRouter
    ? routerOrOptions
    : new ApplicationApiRouter(routerOrOptions);
  const router = Router();

  const toRequestContext = (req: Request): ApiRequestContext => ({
    headers: req.headers,
    params: req.params,
    query: req.query,
    body: req.body,
    requestId: (req.headers['x-request-id'] as string) || `req-${crypto.randomUUID()}`,
    url: req.originalUrl || req.url,
    method: req.method,
    principal: (req as any).principal,
  });

  const sendResponse = (res: Response, result: { statusCode: number; body: any; headers?: Record<string, string> }) => {
    if (result.headers) {
      for (const [key, val] of Object.entries(result.headers)) {
        res.setHeader(key, val);
      }
    }
    // R03 Task 4: Do not echo required_roles / current_roles in 401/403 bodies (log them instead)
    if ((result.statusCode === 401 || result.statusCode === 403) && result.body && typeof result.body === 'object') {
      const sanitizedBody = { ...result.body };
      if (sanitizedBody.error && typeof sanitizedBody.error === 'object') {
        const errObj = { ...sanitizedBody.error };
        if (errObj.details && typeof errObj.details === 'object') {
          const details = { ...errObj.details };
          if ('required_roles' in details || 'current_roles' in details || 'principal_roles' in details) {
            console.debug('[AUTH_ROLES_LOG]', { required_roles: details.required_roles, current_roles: details.current_roles || details.principal_roles });
            delete details.required_roles;
            delete details.current_roles;
            delete details.principal_roles;
            errObj.details = details;
          }
        }
        sanitizedBody.error = errObj;
      }
      if ('required_roles' in sanitizedBody || 'current_roles' in sanitizedBody || 'principal_roles' in sanitizedBody) {
        console.debug('[AUTH_ROLES_LOG]', { required_roles: sanitizedBody.required_roles, current_roles: sanitizedBody.current_roles || sanitizedBody.principal_roles });
        delete sanitizedBody.required_roles;
        delete sanitizedBody.current_roles;
        delete sanitizedBody.principal_roles;
      }
      return res.status(result.statusCode).json(sanitizedBody);
    }
    res.status(result.statusCode).json(result.body);
  };

  // System & Health
  router.get('/health', async (req, res) => {
    const result = await apiRouter.getHealth(toRequestContext(req));
    sendResponse(res, result);
  });

  router.get('/ready', async (req, res) => {
    const result = await apiRouter.getReadiness(toRequestContext(req));
    sendResponse(res, result);
  });

  router.get('/openapi.json', async (req, res) => {
    const result = await apiRouter.getOpenApiSpec(toRequestContext(req));
    sendResponse(res, result);
  });

  // Agent Registry
  router.get('/agents', async (req, res) => {
    const result = await apiRouter.listAgents(toRequestContext(req));
    sendResponse(res, result);
  });

  router.post('/agents', async (req, res) => {
    const result = await apiRouter.createAgent(toRequestContext(req));
    sendResponse(res, result);
  });

  router.get('/agents/:agentId', async (req, res) => {
    const result = await apiRouter.getAgent(toRequestContext(req));
    sendResponse(res, result);
  });

  router.post('/agents/:agentId/versions', async (req, res) => {
    const result = await apiRouter.registerAgentVersion(toRequestContext(req));
    sendResponse(res, result);
  });

  router.get('/agents/:agentId/versions/:versionId', async (req, res) => {
    const result = await apiRouter.getAgentVersion(toRequestContext(req));
    sendResponse(res, result);
  });

  // Analysis Runs
  router.post('/analysis/runs', async (req, res) => {
    const result = await apiRouter.createAnalysisRun(toRequestContext(req));
    sendResponse(res, result);
  });

  router.get('/analysis/runs/:runId', async (req, res) => {
    const result = await apiRouter.getAnalysisRun(toRequestContext(req));
    sendResponse(res, result);
  });

  router.get('/analysis/runs/:runId/findings', async (req, res) => {
    const result = await apiRouter.getAnalysisFindings(toRequestContext(req));
    sendResponse(res, result);
  });

  // Policy & Approvals
  router.post('/policy/evaluations', async (req, res) => {
    const result = await apiRouter.evaluatePolicyGate(toRequestContext(req));
    sendResponse(res, result);
  });

  router.post('/approvals', async (req, res) => {
    const result = await apiRouter.submitApproval(toRequestContext(req));
    sendResponse(res, result);
  });

  // Queues & DLQ
  router.get('/queues', async (req, res) => {
    const result = await apiRouter.listQueues(toRequestContext(req));
    sendResponse(res, result);
  });

  router.post('/dlq/jobs/:dlqId/replay', async (req, res) => {
    const result = await apiRouter.replayDlqJob(toRequestContext(req));
    sendResponse(res, result);
  });

  return router;
}
