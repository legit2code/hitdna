/**
 * Authentic Pipeline DAG (Discovery -> Semantic -> Evaluation)
 * Conforms to P09, R10 & Architecture V2.0.1 Specification
 *
 * Implements authoritative multi-stage DAG workflow control plane:
 * 1. Discovery: acquires authentic artifact, computes SHA-256 and version record
 * 2. Semantic: parses authentic sources, extracts AST facts, symbols, protocols & frameworks
 * 3. Evaluation: executes authentic Golden Corpus regression gates & persists EvaluationRun
 *
 * Enforces:
 * - Deterministic idempotency keys per workflow step
 * - Retry with exponential backoff on transient errors
 * - Dead-letter queue routing for poison pills and exhausted retries
 * - Strict tenant isolation on every job and repository write
 */

import {
  WorkflowDefinitionPayload,
  WorkflowDefinitionRecord,
  DurableReferencePayload,
  WorkflowRunRecord,
  JobRecord,
} from './types.ts';
import { WorkflowRunCoordinator } from './coordinator.ts';
import { WorkerSdk } from './worker-sdk.ts';
import { runDiscoveryJob, DiscoveryWorkerJob, DiscoveryJobResult } from '../../../workers/discovery/index.ts';
import { runSemanticJob, SemanticWorkerJob, SemanticJobResult } from '../../../workers/semantic/index.ts';
import { runEvaluationJob, EvaluationJob, EvaluationJobResult } from '../../../workers/evaluation/index.ts';

export const CAIM_PIPELINE_WORKFLOW_KEY = 'caim-pipeline-dag';
export const CAIM_PIPELINE_WORKFLOW_VERSION = '1.0.0';

export interface PipelineDagWorkerOptions {
  db?: any;
  repository?: any;
  tenantId?: string;
  corpusDir?: string;
  customTransport?: any;
  artifactStore?: Map<string, Array<{ path: string; content: string | Buffer }>>;
}

/**
 * Creates the canonical 3-stage DAG workflow definition.
 */
export function createPipelineDagDefinition(): WorkflowDefinitionPayload {
  return {
    name: 'Authentic Pipeline DAG: Discovery -> Semantic -> Evaluation',
    description: 'Queue-driven 3-stage DAG with durable references, retry backoff, and dead-letter safety',
    steps: [
      {
        stepKey: 'discovery',
        jobType: 'discovery',
        queueKey: 'discovery-queue',
        dependsOn: [],
        priority: 10,
        retryPolicy: {
          maxAttempts: 3,
          initialDelayMs: 100,
          maxDelayMs: 2000,
          multiplier: 2,
          enableJitter: false,
        },
      },
      {
        stepKey: 'semantic',
        jobType: 'semantic',
        queueKey: 'semantic-queue',
        dependsOn: ['discovery'],
        priority: 8,
        retryPolicy: {
          maxAttempts: 3,
          initialDelayMs: 100,
          maxDelayMs: 2000,
          multiplier: 2,
          enableJitter: false,
        },
      },
      {
        stepKey: 'evaluation',
        jobType: 'evaluation',
        queueKey: 'evaluation-queue',
        dependsOn: ['semantic'],
        priority: 5,
        retryPolicy: {
          maxAttempts: 3,
          initialDelayMs: 100,
          maxDelayMs: 2000,
          multiplier: 2,
          enableJitter: false,
        },
      },
    ],
  };
}

/**
 * Registers and wires all three worker handlers onto a WorkerSdk instance.
 */
export function registerPipelineDagHandlers(
  workerSdk: WorkerSdk,
  options: PipelineDagWorkerOptions = {}
): void {
  const artifactStore =
    options.artifactStore ||
    new Map<string, Array<{ path: string; content: string | Buffer }>>();

  // 1. Discovery Worker Handler
  workerSdk.registerHandler<any, DiscoveryJobResult>(
    'discovery',
    async (payload: any, ctx) => {
      const tenantId = payload.tenantId || options.tenantId;
      const res = await runDiscoveryJob({
        sourceId: payload.sourceId,
        sourceType: payload.sourceType || 'web_package',
        targetUrl: payload.targetUrl,
        version: payload.version,
        tenantId,
        rawFiles: payload.rawFiles,
        customTransport: payload.customTransport || options.customTransport,
        repository: options.repository,
        db: options.db,
      });

      // Save files to shared memory for downstream semantic analysis
      if (payload.rawFiles) {
        artifactStore.set(res.artifactId, payload.rawFiles);
      }

      return res;
    },
    { queueKey: 'discovery-queue' }
  );

  // 2. Semantic Worker Handler
  workerSdk.registerHandler<any, SemanticJobResult>(
    'semantic',
    async (payload: any, ctx) => {
      const tenantId = payload.tenantId || options.tenantId;
      const artifactId = payload.artifactId || payload.parameters?.artifactId || 'art-pipeline-1';
      const sourceFiles =
        payload.sourceFiles ||
        artifactStore.get(artifactId) ||
        payload.rawFiles ||
        [];

      const res = await runSemanticJob({
        artifactId,
        sourceFiles,
        entrypoints: payload.entrypoints,
        tenantId,
        repository: options.repository,
        db: options.db,
      });

      return res;
    },
    { queueKey: 'semantic-queue' }
  );

  // 3. Evaluation Worker Handler
  workerSdk.registerHandler<any, EvaluationJobResult>(
    'evaluation',
    async (payload: any, ctx) => {
      const tenantId = payload.tenantId || options.tenantId;
      const corpusDir = payload.corpusDir || options.corpusDir;

      const res = await runEvaluationJob({
        suiteId: payload.suiteId,
        goldenCorpusVersion: payload.goldenCorpusVersion,
        corpusDir,
        engineVersion: payload.engineVersion,
        baselineEngineVersion: payload.baselineEngineVersion,
        tenantId,
        repository: options.repository,
        db: options.db,
      });

      return res;
    },
    { queueKey: 'evaluation-queue' }
  );
}

/**
 * Registers the DAG workflow definition and wires handlers in one coordinated call.
 */
export async function setupPipelineDag(
  coordinator: WorkflowRunCoordinator,
  workerSdk: WorkerSdk,
  options: PipelineDagWorkerOptions = {}
): Promise<WorkflowDefinitionRecord> {
  const definition = createPipelineDagDefinition();
  const defRecord = await coordinator.registerWorkflowDefinition(
    CAIM_PIPELINE_WORKFLOW_KEY,
    CAIM_PIPELINE_WORKFLOW_VERSION,
    definition
  );

  registerPipelineDagHandlers(workerSdk, options);
  return defRecord;
}
