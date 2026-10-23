/**
 * Cloudflare Worker: Reliable Cron Scheduler for CAIM Discovery Cycles
 * 
 * Part of CAIM Discovery Scheduling Architecture:
 * Replaces in-process setInterval loop with an isolated external Cron Trigger.
 * 
 * Invariants:
 * 1. ZERO discovery logic runs inside this Worker.
 * 2. ZERO production database credentials exist or are touched here.
 * 3. Sole Responsibility: Calls GitHub REST API to dispatch `.github/workflows/discovery-cycle.yml`.
 * 4. Authentication: Uses scoped GITHUB_DISPATCH_TOKEN secret stored in Cloudflare Worker secrets.
 */

export interface Env {
  // Secret injected at runtime by Cloudflare Worker runtime
  GITHUB_DISPATCH_TOKEN: string;
  GITHUB_OWNER?: string;
  GITHUB_REPO?: string;
  GITHUB_WORKFLOW_FILE?: string;
  GITHUB_REF?: string;
}

export interface ScheduledController {
  cron: string;
  scheduledTime: number;
}

export interface ExecutionContext {
  waitUntil(promise: Promise<any>): void;
  passThroughOnException(): void;
}

export default {
  /**
   * Cloudflare Cron Trigger Handler
   * Fires according to the cron schedule defined in wrangler.toml (every 10 minutes)
   */
  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(dispatchDiscoveryWorkflow(env, `cron:${controller.cron}`));
  },

  /**
   * HTTP Fetch Handler
   * Allows health checks, verification, and manual dispatch triggers via POST /trigger.
   */
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'POST' && url.pathname === '/trigger') {
      try {
        const result = await dispatchDiscoveryWorkflow(env, 'http_manual_trigger');
        return new Response(JSON.stringify({ success: true, ...result }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    return new Response(
      JSON.stringify({
        service: 'caim-discovery-cron-scheduler',
        status: 'active',
        cadence: '*/10 * * * *',
        description: 'Reliable Cloudflare Cron Trigger dispatching GitHub Actions autonomous discovery cycles.',
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  },
};

/**
 * Dispatches the GitHub Actions workflow using GitHub's REST API.
 */
async function dispatchDiscoveryWorkflow(env: Env, triggerSource: string) {
  const token = env.GITHUB_DISPATCH_TOKEN;
  if (!token) {
    throw new Error(
      'Missing GITHUB_DISPATCH_TOKEN secret. Please configure via `wrangler secret put GITHUB_DISPATCH_TOKEN`.'
    );
  }

  const owner = env.GITHUB_OWNER || 'caim-project';
  const repo = env.GITHUB_REPO || 'caim';
  const workflowFile = env.GITHUB_WORKFLOW_FILE || 'discovery-cycle.yml';
  const ref = env.GITHUB_REF || 'main';

  const endpoint = `https://api.github.com/repos/${owner}/${repo}/actions/workflows/${workflowFile}/dispatches`;

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Accept': 'application/vnd.github.v3+json',
      'Authorization': `Bearer ${token}`,
      'User-Agent': 'CAIM-Cloudflare-Cron-Scheduler/1.0',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      ref,
      inputs: {
        reason: `Triggered by Cloudflare Worker (${triggerSource}) at ${new Date().toISOString()}`,
      },
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`GitHub API dispatch failed (${response.status} ${response.statusText}): ${errorText}`);
  }

  return {
    dispatched: true,
    workflow: `${owner}/${repo}/.github/workflows/${workflowFile}`,
    ref,
    timestamp: new Date().toISOString(),
  };
}
