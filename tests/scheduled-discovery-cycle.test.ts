import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { runStandaloneDiscoveryCycle } from '../scripts/run-discovery-cycle';
import { spawn, ChildProcess } from 'child_process';

describe('Scheduled Discovery Cycle: Standalone Runner & Reporting Invariants', () => {
  let serverProcess: ChildProcess | null = null;
  const API_PORT = process.env.TEST_PORT || '3105';
  const API_URL = `http://localhost:${API_PORT}`;

  beforeAll(async () => {
    // 1. Check if server is already running externally on the target port
    let isRunning = false;
    try {
      const res = await fetch(`${API_URL}/api/health`, { signal: AbortSignal.timeout(1000) });
      if (res.ok) {
        isRunning = true;
      }
    } catch {}

    // 2. If not running, start an in-process/background server instance
    if (!isRunning) {
      serverProcess = spawn(
        'npx',
        ['tsx', 'apps/server/index.ts'],
        {
          cwd: process.cwd(),
          env: {
            ...process.env,
            TEST_PORT: API_PORT,
            PORT: API_PORT,
            SKIP_VITE: 'true',
            NODE_ENV: 'test',
            CAIM_DISCOVERY_SERVICE_TOKEN: 'test-configured-discovery-token-sched',
          },
          stdio: 'ignore',
        }
      );

      const startWait = Date.now();
      while (Date.now() - startWait < 30000) {
        try {
          const res = await fetch(`${API_URL}/api/health`, { signal: AbortSignal.timeout(1000) });
          if (res.ok) {
            isRunning = true;
            break;
          }
        } catch {}
        await new Promise((r) => setTimeout(r, 500));
      }

      if (!isRunning) {
        if (serverProcess) serverProcess.kill('SIGTERM');
        throw new Error(`Failed to initialize CAIM server on ${API_URL} within 30 seconds`);
      }
    }
  }, 45000);

  afterAll(async () => {
    if (serverProcess) {
      serverProcess.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 500));
    }
  });

  it('enforces that runStandaloneDiscoveryCycle executes a single cycle and exits cleanly', async () => {
    // Run discovery cycle against the local server with limited candidates
    const result = await runStandaloneDiscoveryCycle({
      apiUrl: API_URL,
      serviceToken: 'test-configured-discovery-token-sched',
      queries: ['agent'],
      maxCandidatesTotal: 3,
      maxPagesPerSource: 1,
    });

    expect(result).toBeDefined();
    expect(result.success).toBe(true);
    expect(result.cycle_id).toMatch(/^cycle-sched-/);
    expect(result.candidates_processed).toBeGreaterThanOrEqual(1);
    expect(result.agents_ingested).toBeGreaterThanOrEqual(1);
  });

  it('rejects obsolete hardcoded service credential caim-discovery-service-secret-2026 with 401 Unauthorized', async () => {
    const res = await fetch(`${API_URL}/api/discovery/pipeline/report-cycle`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer caim-discovery-service-secret-2026',
      },
      body: JSON.stringify({
        cycle_id: 'test-cycle-obsolete-hardcoded-secret',
        candidates: [],
      }),
    });

    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.authenticated).toBe(false);
    expect(data.error).toContain('Unauthorized');
  });

  it('rejects unauthenticated cycle reports with 401 Unauthorized', async () => {
    const res = await fetch(`${API_URL}/api/discovery/pipeline/report-cycle`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer invalid-token-for-test',
      },
      body: JSON.stringify({
        cycle_id: 'test-cycle-invalid-auth',
        candidates: [],
      }),
    });

    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.authenticated).toBe(false);
    expect(data.error).toContain('Unauthorized');
  });

  it('updates autonomous discovery worker status without in-process timer', async () => {
    const statusRes = await fetch(`${API_URL}/api/discovery/pipeline/status`, {
      headers: {
        'Authorization': 'Bearer test-configured-discovery-token-sched',
      },
    });

    expect(statusRes.status).toBe(200);
    const status = await statusRes.json();
    expect(status.active).toBe(false); // In-process timer is stopped
    expect(status.next_run_at).toBeNull(); // No next timer scheduled internally
    expect(status.last_run_at).not.toBeNull(); // Last run is set from external report
    expect(status.total_analyzed).toBeGreaterThanOrEqual(1);
  });
});
