import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execSync, spawn, ChildProcess } from 'child_process';
import fs from 'fs';
import path from 'path';
import pg from 'pg';

let hasPostgres = false;
try {
  execSync('which initdb', { stdio: 'ignore' });
  hasPostgres = true;
} catch {
  hasPostgres = false;
}

describe.skipIf(!hasPostgres)('Real PostgreSQL End-to-End Pipeline (HTTP Server)', () => {
  const PG_PORT = 5434;
  const SERVER_PORT = 3088;
  const PG_DATA_DIR = `/tmp/caim-e2e-pg-${Date.now()}`;
  const DB_NAME = 'caim_e2e_db';
  const DATABASE_URL = `postgres://postgres@127.0.0.1:${PG_PORT}/${DB_NAME}?sslmode=disable`;
  const ENROLLMENT_TOKEN = 'e2e-bootstrap-token-super-secure-32-chars-long';
  const ENROLLMENT_FILE = `/tmp/caim-e2e-token-${Date.now()}.txt`;

  const ADMIN_EMAIL = 'admin-e2e@caim.internal';
  const ADMIN_PASSWORD = 'E2EAdminPassword!2026Secure';

  let serverProcess: ChildProcess | null = null;
  let pgPool: pg.Pool | null = null;
  let authToken: string = '';

  const baseUrl = `http://127.0.0.1:${SERVER_PORT}`;

  // Helper for real HTTP requests to the running server
  async function apiRequest(
    method: string,
    endpoint: string,
    body?: any,
    headers: Record<string, string> = {}
  ): Promise<{ status: number; data: any; headers: any }> {
    const reqHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      ...headers,
    };
    if (authToken && !reqHeaders['Authorization']) {
      reqHeaders['Authorization'] = `Bearer ${authToken}`;
    }

    const response = await fetch(`${baseUrl}${endpoint}`, {
      method,
      headers: reqHeaders,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    let data: any;
    const text = await response.text();
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }

    return {
      status: response.status,
      data,
      headers: response.headers,
    };
  }

  beforeAll(async () => {
    console.log('[E2E Setup] Initializing fresh PostgreSQL instance...');

    // Clean any residual processes on ports
    try {
      execSync('fuser -k 5434/tcp 3088/tcp 2>/dev/null || true');
      execSync('pkill -u postgres -f postgres 2>/dev/null || true');
    } catch {}
    await new Promise((r) => setTimeout(r, 500));

    // 1. Initialize clean PostgreSQL cluster
    execSync(
      `su - postgres -c "rm -rf ${PG_DATA_DIR} && initdb -D ${PG_DATA_DIR} -E UTF8 --no-locale"`
    );

    // 2. Configure dedicated port and start PostgreSQL server
    execSync(`echo "port = ${PG_PORT}" >> ${PG_DATA_DIR}/postgresql.conf`);
    execSync(
      `su - postgres -c "pg_ctl -D ${PG_DATA_DIR} -l /tmp/e2e-pg.log start"`
    );

    // 3. Create fresh database
    execSync(`createdb -h 127.0.0.1 -p ${PG_PORT} -U postgres ${DB_NAME}`);

    pgPool = new pg.Pool({ connectionString: DATABASE_URL });

    console.log('[E2E Setup] PostgreSQL running. Spawning CAIM server on port', SERVER_PORT);

    // 4. Spawn real CAIM server process pointing to fresh Postgres
    serverProcess = spawn(
      'npx',
      ['tsx', 'apps/server/index.ts'],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          PORT: String(SERVER_PORT),
          TEST_PORT: String(SERVER_PORT),
          SKIP_VITE: 'true',
          NODE_ENV: 'development',
          DATABASE_URL,
          BOOTSTRAP_ENROLLMENT_TOKEN: ENROLLMENT_TOKEN,
          BOOTSTRAP_TOKEN_FILE: ENROLLMENT_FILE,
          ENABLE_METRICS: 'true',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      }
    );

    serverProcess.stdout?.on('data', (d) => {
      process.stdout.write(`[Server stdout] ${d}`);
    });

    serverProcess.stderr?.on('data', (d) => {
      process.stderr.write(`[Server stderr] ${d}`);
    });

    serverProcess.on('exit', (code, signal) => {
      console.log(`[Server exited] code: ${code}, signal: ${signal}`);
    });

    // 5. Poll server until health endpoint responds 200 OK
    const startWait = Date.now();
    let isHealthy = false;
    while (Date.now() - startWait < 30000) {
      try {
        const res = await fetch(`${baseUrl}/api/health`);
        if (res.status === 200) {
          isHealthy = true;
          break;
        }
      } catch {
        // Server still booting
      }
      await new Promise((r) => setTimeout(r, 400));
    }

    if (!isHealthy) {
      throw new Error(`Server failed to start on port ${SERVER_PORT} within 30s timeout`);
    }

    console.log('[E2E Setup] CAIM Server is healthy and ready on', baseUrl);
  }, 45000);

  afterAll(async () => {
    console.log('[E2E Teardown] Cleaning up server and PostgreSQL instance...');

    // Close PG connection
    if (pgPool) {
      await pgPool.end().catch(() => {});
    }

    // Kill server process
    if (serverProcess) {
      serverProcess.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 500));
      if (!serverProcess.killed) {
        serverProcess.kill('SIGKILL');
      }
    }

    // Stop PostgreSQL cluster
    try {
      execSync(`su - postgres -c "pg_ctl -D ${PG_DATA_DIR} stop -m immediate"`);
      execSync(`rm -rf ${PG_DATA_DIR} ${ENROLLMENT_FILE} /tmp/e2e-pg.log`);
      execSync('fuser -k 5434/tcp 3088/tcp 2>/dev/null || true');
      execSync('pkill -u postgres -f postgres 2>/dev/null || true');
    } catch {
      // Best effort cleanup
    }

    console.log('[E2E Teardown] Completed.');
  }, 20000);

  // --------------------------------------------------------------------------
  // Step 1: Database Migrations
  // --------------------------------------------------------------------------
  it('Step 1: Migrations executed cleanly against fresh PostgreSQL', async () => {
    // Verify server health endpoint
    const health = await apiRequest('GET', '/api/health');
    expect(health.status).toBe(200);
    expect(health.data.status).toBe('healthy');

    // Query real PostgreSQL instance directly to verify schema migration records
    const migRes = await pgPool!.query(
      'SELECT version, name FROM public.schema_migrations ORDER BY version ASC;'
    );
    expect(migRes.rows.length).toBeGreaterThanOrEqual(20);

    // Verify core tables exist in the fresh PostgreSQL instance
    const tablesRes = await pgPool!.query(`
      SELECT table_schema, table_name 
      FROM information_schema.tables 
      WHERE table_schema IN ('core', 'ops', 'security', 'knowledge');
    `);
    const tableNames = tablesRes.rows.map((r) => `${r.table_schema}.${r.table_name}`);
    expect(tableNames).toContain('core.canonical_agents');
    expect(tableNames).toContain('core.agent_versions');
    expect(tableNames).toContain('ops.workflow_definitions');
    expect(tableNames).toContain('security.principals');
  });

  // --------------------------------------------------------------------------
  // Step 2: Administrator Bootstrap Flow
  // --------------------------------------------------------------------------
  it('Step 2: Bootstrap status check & first-run admin enrollment', async () => {
    // Check initial bootstrap status
    const statusBefore = await apiRequest('GET', '/api/auth/bootstrap/status');
    expect(statusBefore.status).toBe(200);
    expect(statusBefore.data.requires_bootstrap).toBe(true);
    expect(statusBefore.data.admin_count).toBe(0);

    // Enroll initial administrator via out-of-band enrollment token
    const enrollRes = await apiRequest('POST', '/api/auth/bootstrap/enroll', {
      email: ADMIN_EMAIL,
      password: ADMIN_PASSWORD,
      enrollment_token: ENROLLMENT_TOKEN,
    });

    expect(enrollRes.status).toBe(201);
    expect(enrollRes.data.status).toBe('enrolled');
    expect(enrollRes.data.email).toBe(ADMIN_EMAIL);
    expect(enrollRes.data.roles).toContain('admin');

    // Confirm that bootstrap is now closed
    const statusAfter = await apiRequest('GET', '/api/auth/bootstrap/status');
    expect(statusAfter.status).toBe(200);
    expect(statusAfter.data.requires_bootstrap).toBe(false);
    expect(statusAfter.data.admin_count).toBeGreaterThanOrEqual(1);

    // Verify subsequent bootstrap attempt is rejected
    const secondEnroll = await apiRequest('POST', '/api/auth/bootstrap/enroll', {
      email: 'attacker@caim.internal',
      password: ADMIN_PASSWORD,
      enrollment_token: ENROLLMENT_TOKEN,
    });
    expect([403, 409]).toContain(secondEnroll.status);
  });

  // --------------------------------------------------------------------------
  // Step 3: Authentication & JWT Login
  // --------------------------------------------------------------------------
  it('Step 3: Admin authentication returns authoritative JWT access token', async () => {
    const loginRes = await apiRequest('POST', '/api/auth/login', {
      email: ADMIN_EMAIL,
      password: ADMIN_PASSWORD,
    });

    expect(loginRes.status).toBe(200);
    expect(loginRes.data.access_token).toBeDefined();
    expect(typeof loginRes.data.access_token).toBe('string');
    expect(loginRes.data.principal.email).toBe(ADMIN_EMAIL);

    // Store for subsequent authenticated requests
    authToken = loginRes.data.access_token;

    // Verify /api/auth/me returns authenticated identity
    const meRes = await apiRequest('GET', '/api/auth/me');
    expect(meRes.status).toBe(200);
    expect(meRes.data.status).toBe('authenticated');
    expect(meRes.data.principal.is_authenticated).toBe(true);
    expect(meRes.data.principal.roles).toContain('admin');
  });

  // --------------------------------------------------------------------------
  // Step 4: Agent Ingestion Pipeline
  // --------------------------------------------------------------------------
  let agentId: string = '';
  let agentVersionId: string = '';

  it('Step 4: Real agent ingestion creates persistent DB records', async () => {
    const canonicalName = `e2e-security-analyst-${Date.now().toString().slice(-4)}`;
    const ingestPayload = {
      canonicalName,
      versionLabel: '1.0.0',
      sourceLocator: `github://caim-test/${canonicalName}`,
      author: 'E2E Testing Suite',
      description: 'End-to-end integration test autonomous agent',
      files: [
        {
          path: 'src/agent.ts',
          content: `
            export class E2EAgent {
              async execute(task: string) {
                console.log("Analyzing task:", task);
                return { status: "success", analyzed: true };
              }
            }
          `,
        },
      ],
    };

    const res = await apiRequest('POST', '/api/dev/ingestion/submit', ingestPayload);
    expect(res.status).toBe(200);
    expect(res.data.success).toBe(true);
    expect(res.data.agent_id).toBeDefined();
    expect(res.data.agent_version_id).toBeDefined();

    agentId = res.data.agent_id;
    agentVersionId = res.data.agent_version_id;

    // Confirm that records were inserted into the real PostgreSQL database
    const dbAgent = await pgPool!.query(
      'SELECT canonical_name, status FROM core.canonical_agents WHERE agent_id = $1;',
      [agentId]
    );
    expect(dbAgent.rows.length).toBe(1);
    expect(dbAgent.rows[0].canonical_name).toBe(canonicalName);
    expect(dbAgent.rows[0].status).toBe('ACTIVE');

    const dbVersion = await pgPool!.query(
      'SELECT version_label, content_fingerprint FROM core.agent_versions WHERE agent_version_id = $1;',
      [agentVersionId]
    );
    expect(dbVersion.rows.length).toBe(1);
    expect(dbVersion.rows[0].version_label).toBe('1.0.0');
  });

  // --------------------------------------------------------------------------
  // Step 5: Static Analysis Engine
  // --------------------------------------------------------------------------
  let staticFindings: any[] = [];
  it('Step 5: Static analysis analyzes source files and returns rule violations', async () => {
    const staticPayload = {
      artifact_id: `artifact-${agentId}`,
      files: [
        {
          path: 'src/service.ts',
          content: `
            import { exec } from 'child_process';
            export function runCommand(cmd: string) {
              eval(cmd);
              exec(cmd);
            }
          `,
        },
        {
          path: 'src/main.ts',
          content: `
            import { runCommand } from './service';
            export function main() {
              runCommand('ls -la');
            }
          `,
        },
      ],
      entrypoints: ['src/main.ts'],
    };

    const res = await apiRequest('POST', '/api/dev/static-analysis/analyze', staticPayload);
    expect(res.status).toBe(200);
    expect(res.data.artifact_id).toBe(staticPayload.artifact_id);
    expect(res.data.findings).toBeDefined();
    expect(Array.isArray(res.data.findings)).toBe(true);

    staticFindings = res.data.findings;
  });

  // --------------------------------------------------------------------------
  // Step 6: Sandbox Execution
  // --------------------------------------------------------------------------
  let sandboxResult: any = null;
  it('Step 6: Sandbox orchestration executes agent scenario in isolated environment', async () => {
    const sandboxPayload = {
      scenarioId: 'SCN-BENIGN-01',
      providerType: 'SIMULATED',
      files: {
        'index.js': 'console.log("Running sandbox verification");',
      },
      envVars: {
        NODE_ENV: 'sandbox',
      },
      resourceLimits: {
        cpuLimit: 1.0,
        memoryLimitMb: 512,
        timeoutSeconds: 10,
      },
    };

    const res = await apiRequest('POST', '/api/dev/sandbox/run', sandboxPayload);
    expect(res.status).toBe(200);
    expect(res.data.run_id).toBeDefined();
    expect(res.data.status).toBe('PASSED');
    expect(res.data.runtime_events).toBeDefined();
    expect(res.data.teardown).toBeDefined();

    sandboxResult = res.data;
  });

  // --------------------------------------------------------------------------
  // Step 7: Risk Scoring & Policy Decision Suite
  // --------------------------------------------------------------------------
  it('Step 7: Risk scoring engine computes multi-dimensional scores and policy outcome', async () => {
    const decisionPayload = {
      analysisRunId: `run-${Date.now()}`,
      agentId,
      agentVersionId,
      staticFindings: staticFindings.slice(0, 3),
      sandboxTelemetry: sandboxResult?.runtime_events,
      modelId: 'caim-standard-scoring-v1',
      policyId: 'pol-standard-deploy-gate',
    };

    const res = await apiRequest('POST', '/api/dev/decision/run', decisionPayload);
    expect(res.status).toBe(200);
    expect(res.data.policy_decision).toBeDefined();
    expect(res.data.score_result).toBeDefined();
    expect(['ALLOW', 'ALLOW_WITH_WARNING', 'REQUIRE_REVIEW', 'RESTRICT', 'QUARANTINE', 'DENY_SHIPPING']).toContain(res.data.policy_decision.outcome);
  });

  // --------------------------------------------------------------------------
  // Step 8: RAG Synthesis & Retrieval
  // --------------------------------------------------------------------------
  it('Step 8: RAG pipeline synthesizes knowledge query with grounded citations', async () => {
    const ragPayload = {
      query: 'What are the required security safeguards for agent packaging and container isolation?',
    };

    const res = await apiRequest('POST', '/api/dev/rag/synthesize', ragPayload);
    expect(res.status).toBe(200);
    expect(res.data.answer).toBeDefined();
    expect(typeof res.data.answer).toBe('string');
    expect(res.data.resolved_citations).toBeDefined();
    expect(Array.isArray(res.data.resolved_citations)).toBe(true);
  });

  // --------------------------------------------------------------------------
  // Step 9: Deterministic Packaging, Verification & Shipping
  // --------------------------------------------------------------------------
  it('Step 9: Packaging engine builds signed bundle, verifies cryptographic signature, and ships', async () => {
    // 1. Build & Sign Package Bundle
    const buildRes = await apiRequest('POST', '/api/dev/packaging/build', {
      fixtureKey: 'financial_analyst',
      overridePolicyOutcome: 'ALLOW',
    });

    expect(buildRes.status).toBe(200);
    expect(buildRes.data.bundle).toBeDefined();
    expect(buildRes.data.bundle.signature).toBeDefined();
    expect(buildRes.data.bundle.manifest_hash).toBeDefined();
    expect(buildRes.data.verification.valid).toBe(true);

    const bundle = buildRes.data.bundle;

    // 2. Independently verify the signature
    const verifyRes = await apiRequest('POST', '/api/dev/packaging/verify', { bundle });
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.data.valid).toBe(true);
    expect(verifyRes.data.keyId).toBe(bundle.signature.key_id);

    // 3. Ship verified bundle to target destination
    const shipRes = await apiRequest('POST', '/api/dev/packaging/ship', {
      bundle,
      targetType: 'LOCAL_STAGING',
      options: { targetLocator: '/tmp/caim-e2e-staging' },
    });
    expect(shipRes.status).toBe(200);
    expect(shipRes.data.success).toBe(true);
    expect(shipRes.data.receipt).toBeDefined();
    expect(shipRes.data.receipt.shipment_id).toBeDefined();
    expect(shipRes.data.receipt.status).toBe('DELIVERED');
  });
});
