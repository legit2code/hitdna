import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import crypto from 'node:crypto';
import { createTestDb } from '@caim/db/migrator.ts';
import {
  PgQueueAdapter,
  WorkflowRunCoordinator,
  WorkerSdk,
  setupPipelineDag,
  CAIM_PIPELINE_WORKFLOW_KEY,
  CAIM_PIPELINE_WORKFLOW_VERSION,
} from '@caim/workflow';

describe('Integration: Full Queue-Driven DAG Pipeline (Discovery -> Semantic -> Evaluation)', () => {
  let localServer: http.Server;
  let localBaseUrl: string;
  let dbClient: any;
  let queueAdapter: PgQueueAdapter;
  let coordinator: WorkflowRunCoordinator;
  let workerSdk: WorkerSdk;
  const tenantId = '44444444-4444-4444-8444-444444444444';

  const authenticAgentCode = `
    export class CalculatorService {
      private memory: number = 0;
      public add(val: number): number {
        this.memory += val;
        return this.memory;
      }
      public reset(): void {
        this.memory = 0;
      }
    }
    export function runCalculation(input: number): number {
      const calc = new CalculatorService();
      return calc.add(input);
    }
  `;

  beforeEach(async () => {
    // 1. Start a local HTTP fixture server (zero external network connection)
    localServer = http.createServer((req, res) => {
      if (req.url === '/entrypoint.ts' || req.url === '/manifest.json') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(authenticAgentCode);
      } else {
        res.writeHead(404);
        res.end('Not Found');
      }
    });

    await new Promise<void>((resolve) => {
      localServer.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = localServer.address() as AddressInfo;
    localBaseUrl = `http://127.0.0.1:${addr.port}`;

    // 2. Initialize in-memory test database (or EXTERNAL INFRA REQUIRED if Postgres DATABASE_URL is set)
    const memDb = createTestDb({ applyMigrations: true, applySeed: true });
    const pg = memDb.adapters.createPg();
    dbClient = new pg.Client();
    await dbClient.connect();

    // 3. Initialize Workflow and Queue Control Plane
    queueAdapter = new PgQueueAdapter(dbClient);
    coordinator = new WorkflowRunCoordinator(dbClient, queueAdapter);
    workerSdk = new WorkerSdk(dbClient, 'worker-integration-1', queueAdapter, coordinator);

    // 4. Setup and register 3-stage DAG
    const sharedArtifactStore = new Map<string, Array<{ path: string; content: string | Buffer }>>();
    await setupPipelineDag(coordinator, workerSdk, {
      db: dbClient,
      tenantId,
      artifactStore: sharedArtifactStore,
    });
  });

  afterEach(async () => {
    workerSdk.shutdown();
    if (localServer) {
      await new Promise<void>((resolve) => localServer.close(() => resolve()));
    }
  });

  it('feeds a local fixture agent through the full DAG and asserts persisted evidence rows, hashes, and final decision', async () => {
    const correlationId = `corr-dag-${crypto.randomUUID().slice(0, 8)}`;

    // Start Workflow Run with the root discovery job
    const { workflowRun, initialJobs } = await coordinator.startWorkflowRun({
      workflowKey: CAIM_PIPELINE_WORKFLOW_KEY,
      version: CAIM_PIPELINE_WORKFLOW_VERSION,
      correlationId,
      metadata: { tenantId },
    });

    expect(workflowRun.status).toBe('RUNNING');
    expect(initialJobs.length).toBe(1);

    // -------------------------------------------------------------------------
    // STAGE 1: Discovery
    // -------------------------------------------------------------------------
    const discMsg = await queueAdapter.dequeue('discovery-queue', 'worker-integration-1');
    expect(discMsg).not.toBeNull();

    // Inject authentic files directly representing the agent acquired from local test server
    (discMsg!.payload as any).targetUrl = `${localBaseUrl}/entrypoint.ts`;
    (discMsg!.payload as any).rawFiles = [
      { path: 'src/entrypoint.ts', content: authenticAgentCode },
    ];
    (discMsg!.payload as any).tenantId = tenantId;

    const discRes = await workerSdk.processJobMessage(discMsg!);
    expect(discRes.success).toBe(true);
    expect(discRes.result).toBeDefined();

    const discOutput = discRes.result as any;
    expect(discOutput.status).toBe('DISCOVERY_COMPLETED');
    expect(discOutput.artifactsCount).toBe(1);
    expect(discOutput.contentHash).toMatch(/^sha256:[a-f0-9]{64}$/);

    // Verify Stage 1 persisted rows
    const obsRows = await dbClient.query(`SELECT * FROM source.source_observations;`);
    expect(obsRows.rows.length).toBeGreaterThanOrEqual(1);

    const artRows = await dbClient.query(`SELECT * FROM source.artifacts;`);
    expect(artRows.rows.length).toBeGreaterThanOrEqual(1);
    expect(artRows.rows[0].content_hash).toBe(discOutput.contentHash);

    // -------------------------------------------------------------------------
    // STAGE 2: Semantic Analysis (automatically unblocked by coordinator)
    // -------------------------------------------------------------------------
    const semanticMsg = await queueAdapter.dequeue('semantic-queue', 'worker-integration-1');
    expect(semanticMsg).not.toBeNull();

    // Semantic job payload gets artifactId from discovery stage
    (semanticMsg!.payload as any).artifactId = discOutput.artifactId;
    (semanticMsg!.payload as any).sourceFiles = [
      { path: 'src/entrypoint.ts', content: authenticAgentCode },
    ];
    (semanticMsg!.payload as any).tenantId = tenantId;

    const semanticRes = await workerSdk.processJobMessage(semanticMsg!);
    expect(semanticRes.success).toBe(true);

    const semanticOutput = semanticRes.result as any;
    expect(semanticOutput.status).toBe('SEMANTIC_ANALYSIS_COMPLETED');
    expect(semanticOutput.astNodesCount).toBeGreaterThan(0);
    expect(semanticOutput.symbolsCount).toBeGreaterThan(0);

    // -------------------------------------------------------------------------
    // STAGE 3: Evaluation (automatically unblocked after semantic completes)
    // -------------------------------------------------------------------------
    const evalMsg = await queueAdapter.dequeue('evaluation-queue', 'worker-integration-1');
    expect(evalMsg).not.toBeNull();

    (evalMsg!.payload as any).tenantId = tenantId;
    const evalRes = await workerSdk.processJobMessage(evalMsg!);
    expect(evalRes.success).toBe(true);

    const evalOutput = evalRes.result as any;
    expect(evalOutput.status).toBeDefined();
    expect(evalOutput.gateStatus).toBeDefined();
    expect(evalOutput.decision).toBeDefined();
    expect(evalOutput.signatureSha256).toHaveLength(64);

    // -------------------------------------------------------------------------
    // VERIFY FINAL DAG OUTCOMES
    // -------------------------------------------------------------------------
    // 1. All evidence rows persisted with tenant context
    const evRows = await dbClient.query(`SELECT * FROM intel.evidence;`);
    expect(evRows.rows.length).toBeGreaterThanOrEqual(2);
    const discoveryEv = evRows.rows.find((r: any) => r.evidence_type === 'METADATA_MANIFEST');
    const semanticEv = evRows.rows.find((r: any) => r.evidence_type === 'AST_MATCH');
    expect(discoveryEv).toBeDefined();
    expect(semanticEv).toBeDefined();

    // 2. Entire workflow run completed
    const finalWfRun = await dbClient.query(
      `SELECT status FROM ops.workflow_runs WHERE workflow_run_id = $1;`,
      [workflowRun.workflow_run_id]
    );
    expect(finalWfRun.rows[0].status).toBe('COMPLETED');
  });
});
