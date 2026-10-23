import { ApplicationApiRouter, ApiRequestContext } from './router.ts';

export interface FastifyLikeInstance {
  get: (path: string, handler: (req: any, reply: any) => Promise<any>) => void;
  post: (path: string, handler: (req: any, reply: any) => Promise<any>) => void;
  put?: (path: string, handler: (req: any, reply: any) => Promise<any>) => void;
  delete?: (path: string, handler: (req: any, reply: any) => Promise<any>) => void;
}

export function registerFastifyApiRoutes(fastify: FastifyLikeInstance, apiRouter: ApplicationApiRouter = new ApplicationApiRouter()): void {
  const toRequestContext = (req: any): ApiRequestContext => ({
    headers: req.headers || {},
    params: req.params || {},
    query: req.query || {},
    body: req.body,
    requestId: req.headers?.['x-request-id'] || `req-${crypto.randomUUID()}`,
    url: req.url,
    method: req.method,
    principal: req.principal,
  });

  const sendReply = (reply: any, result: { statusCode: number; body: any; headers?: Record<string, string> }) => {
    if (result.headers && reply.header) {
      for (const [k, v] of Object.entries(result.headers)) {
        reply.header(k, v);
      }
    }
    return reply.code ? reply.code(result.statusCode).send(result.body) : reply.status(result.statusCode).json(result.body);
  };

  // Health
  fastify.get('/api/v1/health', async (req, reply) => sendReply(reply, await apiRouter.getHealth(toRequestContext(req))));
  fastify.get('/api/v1/ready', async (req, reply) => sendReply(reply, await apiRouter.getReadiness(toRequestContext(req))));
  fastify.get('/api/v1/openapi.json', async (req, reply) => sendReply(reply, await apiRouter.getOpenApiSpec(toRequestContext(req))));

  // Agents
  fastify.get('/api/v1/agents', async (req, reply) => sendReply(reply, await apiRouter.listAgents(toRequestContext(req))));
  fastify.post('/api/v1/agents', async (req, reply) => sendReply(reply, await apiRouter.createAgent(toRequestContext(req))));
  fastify.get('/api/v1/agents/:agentId', async (req, reply) => sendReply(reply, await apiRouter.getAgent(toRequestContext(req))));
  fastify.post('/api/v1/agents/:agentId/versions', async (req, reply) => sendReply(reply, await apiRouter.registerAgentVersion(toRequestContext(req))));
  fastify.get('/api/v1/agents/:agentId/versions/:versionId', async (req, reply) => sendReply(reply, await apiRouter.getAgentVersion(toRequestContext(req))));

  // Analysis
  fastify.post('/api/v1/analysis/runs', async (req, reply) => sendReply(reply, await apiRouter.createAnalysisRun(toRequestContext(req))));
  fastify.get('/api/v1/analysis/runs/:runId', async (req, reply) => sendReply(reply, await apiRouter.getAnalysisRun(toRequestContext(req))));
  fastify.get('/api/v1/analysis/runs/:runId/findings', async (req, reply) => sendReply(reply, await apiRouter.getAnalysisFindings(toRequestContext(req))));

  // Policy & Approvals
  fastify.post('/api/v1/policy/evaluations', async (req, reply) => sendReply(reply, await apiRouter.evaluatePolicyGate(toRequestContext(req))));
  fastify.post('/api/v1/approvals', async (req, reply) => sendReply(reply, await apiRouter.submitApproval(toRequestContext(req))));

  // Queues & DLQ
  fastify.get('/api/v1/queues', async (req, reply) => sendReply(reply, await apiRouter.listQueues(toRequestContext(req))));
  fastify.post('/api/v1/dlq/jobs/:dlqId/replay', async (req, reply) => sendReply(reply, await apiRouter.replayDlqJob(toRequestContext(req))));
}
