import crypto from "node:crypto";
import { ServerConfig } from "@caim/config";
import { PostgresDatabaseAdapter } from "@caim/db/postgres-adapter.ts";
import { DiagnosticService } from "@caim/workflow/diagnostic.ts";
import {
  createServerAuthHelper,
  AuthService,
  CapabilityGrantService,
  PlatformAuditService,
  RateLimiterEngine,
  CsrfProtectionEngine,
  ProductionBootstrapManager,
  resolveAuthorizedTenant,
} from "@caim/auth";
import {
  SourceAdapterRegistry,
  DiscoveryEngine,
  createMockHttpFetcher,
  BraveSearchProvider,
  QueryStrategyRegistry,
  FreshnessScheduler,
  ArtifactClassifier,
  IdentityResolver,
  ManualReviewQueue,
  RecursiveExpansionEngine,
  AutonomousDiscoveryWorker,
  LibraryAgentSummary,
  DiscoveryCandidate,
  DiscoveryGraphEngine,
  DiscoveryLineageService,
  AuthenticSourceAcquisitionService,
} from "@caim/source";
import { SyntaxIntelligencePipeline } from "@caim/syntax";
import { StaticAnalysisEngine } from "../../../workers/static-analysis/index.ts";
import { CompositionEngine } from "../../../workers/composition/index.ts";
import { SandboxOrchestrationEngine } from "../../../workers/sandbox-orchestrator/engine.ts";
import { StaticDynamicComparator } from "../../../workers/sandbox-orchestrator/comparison.ts";
import { SyntheticTargetService } from "../../../workers/sandbox-orchestrator/security/synthetic-target.ts";
import {
  DecisionOrchestrationEngine,
  ScoreModelRegistry,
  PolicyRegistry,
  PolicyOverrideManager,
  RecommendationEngine,
  UseCaseEngine,
} from "../../../workers/decision/index.ts";
import {
  initializeKnowledgeAndRetrieval,
  RagSynthesisPipeline,
  ContextAssembler,
} from "../../../workers/knowledge/index.ts";
import { AgentComposerEngine } from "../../../workers/composer/index.ts";
import {
  DeterministicPackageBundler,
  KmsSignerBoundary,
  SignatureVerifier,
  ShippingService,
  PackagingPolicyGate,
} from "@caim/packaging";
import { PlatformTelemetryEngine, AuditLogEngine, OpenTelemetryTracer } from "@caim/workflow/observability.ts";
import { GoldenCorpusEvaluationEngine } from "@caim/workflow/evaluation.ts";
import { generateUuid } from "@caim/workflow/queue.ts";
import {
  ReverificationWorker,
  VulnerabilityRecorrelationWorker,
  GoldenCorpusRegressionWorker,
  StaleAgentCleanupWorker,
  IScheduledWorker,
} from "@caim/workflow";
import { Request, Response } from "express";
import { resolveAnalysisTruthState, AnalysisTruthStateResolution } from "@caim/contracts/analysis-states.ts";

export interface ServiceContainer {
  config: ServerConfig;
  dbClient: any;
  dbAdapter: PostgresDatabaseAdapter | null;
  authHelper: ReturnType<typeof createServerAuthHelper>;
  authService: AuthService;
  platformAuditService: PlatformAuditService;
  capabilityGrantService: CapabilityGrantService;
  rateLimiterEngine: RateLimiterEngine;
  csrfProtectionEngine: CsrfProtectionEngine;
  diagnosticService: DiagnosticService;
  discoveryLineageService: DiscoveryLineageService;
  discoveryGraphEngine: DiscoveryGraphEngine;
  mockFetcher: any;
  sourceRegistry: SourceAdapterRegistry;
  discoveryEngine: DiscoveryEngine;
  braveSearchProvider: BraveSearchProvider;
  queryStrategyRegistry: QueryStrategyRegistry;
  freshnessScheduler: FreshnessScheduler;
  artifactClassifier: ArtifactClassifier;
  identityResolver: IdentityResolver;
  manualReviewQueue: ManualReviewQueue;
  recursiveExpansionEngine: RecursiveExpansionEngine;
  autonomousWorker: AutonomousDiscoveryWorker;
  syntheticTargetService: SyntheticTargetService;
  knowledgeCorpus: any;
  hybridRetrieval: any;
  ragPipeline: RagSynthesisPipeline;
  contextAssembler: ContextAssembler;
  composerEngine: AgentComposerEngine;
  kmsBoundary: KmsSignerBoundary;
  globalEvaluationEngine: GoldenCorpusEvaluationEngine;
  reverificationWorker: ReverificationWorker;
  vulnerabilityWorker: VulnerabilityRecorrelationWorker;
  goldenCorpusWorker: GoldenCorpusRegressionWorker;
  staleAgentWorker: StaleAgentCleanupWorker;
  scheduledWorkerMap: Map<string, IScheduledWorker>;
  globalAuditEngine: AuditLogEngine;
  globalTracer: OpenTelemetryTracer;
  shippingService: ShippingService;
  persistAnalysisOutputs: (options: {
    analysisRunId: string;
    agentId?: string;
    agentVersionId?: string;
    staticReport?: any;
    decisionResult?: any;
    securityClassification?: string;
    tx?: any;
    principal?: any;
    truthResolution?: AnalysisTruthStateResolution;
  }) => Promise<void>;
  handleProductIngestAgent: (req: Request, res: Response) => Promise<any>;
  handleProductListAgents: (_req: Request, res: Response) => Promise<any>;
  handleDiscoveryLineage: (req: Request, res: Response) => Promise<any>;
  handleDiscoveredDescendants: (req: Request, res: Response) => Promise<any>;
  handleProductTriggerAnalysis: (req: Request, res: Response) => Promise<any>;
  handleProductDiscoveryRun: (req: Request, res: Response) => Promise<any>;
  handleReportDiscoveryCycle: (req: Request, res: Response) => Promise<any>;
}

export async function createServiceContainer(
  dbClient: any,
  config: ServerConfig,
  dbAdapter: PostgresDatabaseAdapter | null
): Promise<ServiceContainer> {
  const authHelper = createServerAuthHelper({
    jwtSecret: config.auth?.jwtSecret,
    serviceSecret: config.auth?.serviceSecret,
    discoveryServiceToken: config.auth?.discoveryServiceToken,
    serviceTenantScopes: config.auth?.serviceTenantScopes,
    supabaseServiceKey: config.providers?.supabaseServiceKey,
  });
  const authService = new AuthService(dbClient);
  const platformAuditService = new PlatformAuditService(dbClient);
  const capabilityGrantService = new CapabilityGrantService(dbClient);
  const rateLimiterEngine = new RateLimiterEngine({ dbClient });
  const csrfProtectionEngine = new CsrfProtectionEngine();
  const diagnosticService = new DiagnosticService(dbClient);
  const discoveryLineageService = new DiscoveryLineageService(dbClient);
  const discoveryGraphEngine = new DiscoveryGraphEngine(dbClient);

  // Seed sample real control plane records for initial diagnostic inspection (development only)
  const isProduction = process.env.NODE_ENV === "production" || config.env === "production";
  if (!isProduction) {
    await diagnosticService.seedSampleDiagnosticData();
  }

  // Production Bootstrap Initialization:
  try {
    const bootstrapStatus = await ProductionBootstrapManager.checkBootstrapStatus(authService);
    if (bootstrapStatus.requires_bootstrap) {
      if (
        process.env.BOOTSTRAP_ADMIN_PASSWORD ||
        process.env.BOOTSTRAP_EXTERNAL_IDP_ID ||
        process.env.AUTO_BOOTSTRAP_ADMIN === "true" ||
        isProduction
      ) {
        const bootRes = await ProductionBootstrapManager.executeDeployTimeBootstrap(authService);
        console.log(`[CAIM Platform] ${bootRes.message}`);
      } else {
        const token = ProductionBootstrapManager.getOrCreateEnrollmentToken();
        console.log(`[CAIM Platform] System unbootstrapped. Out-of-band first-run enrollment token generated.`);
      }
    }
  } catch (bootErr: any) {
    if (isProduction) {
      const fatalErr = `[FATAL PRODUCTION ERROR] Production bootstrap initialization failed closed: ${bootErr.message}`;
      console.error(fatalErr);
      throw new Error(fatalErr);
    }
    console.warn(`[CAIM Platform] Bootstrap initialization notice: ${bootErr.message}`);
  }

  // P11 SOURCE ADAPTER & DISCOVERY APIS
  const mockFetcher = (!isProduction && config.env === "test") ? createMockHttpFetcher() : undefined;
  const sourceRegistry = SourceAdapterRegistry.createDefault({
    github: { token: config.providers?.githubToken, fetcher: mockFetcher },
    gitlab: { fetcher: mockFetcher },
    pypi: { fetcher: mockFetcher },
    npm: { fetcher: mockFetcher },
    huggingface: { token: config.providers?.huggingfaceApiKey, fetcher: mockFetcher },
    dockerhub: { fetcher: mockFetcher },
    codeberg: { fetcher: mockFetcher },
  });
  const discoveryEngine = new DiscoveryEngine(sourceRegistry);

  // P12 WEB SEARCH, CLASSIFIER, IDENTITY & GRAPH
  const braveSearchProvider = new BraveSearchProvider({
    apiKey: process.env.BRAVE_API_KEY,
    fetcher: (!isProduction && (!process.env.BRAVE_API_KEY || config.env === "test")) ? mockFetcher : undefined,
  });
  const queryStrategyRegistry = new QueryStrategyRegistry();
  const freshnessScheduler = new FreshnessScheduler();
  const artifactClassifier = new ArtifactClassifier();
  const identityResolver = new IdentityResolver();
  const manualReviewQueue = new ManualReviewQueue();
  const recursiveExpansionEngine = new RecursiveExpansionEngine(sourceRegistry);

  // Seed sample observation records into freshness scheduler in development/test only
  if (!isProduction && config.env !== 'production') {
    freshnessScheduler.recordObservation({
      source_locator: 'github://caim-org/autonomous-caim-agent',
      source_type: 'github',
      strategy_id: 'RULE_AGENT_DISCOVERY_PRIMARY',
      change_token: 'sha-20260822-abc',
      token_type: 'COMMIT_SHA',
      observed_at: new Date().toISOString(),
    });
    freshnessScheduler.recordObservation({
      source_locator: 'pypi://autonomous-caim-agent',
      source_type: 'pypi',
      strategy_id: 'RULE_PACKAGE_DIST_PYPI_NPM',
      change_token: '1.2.0',
      token_type: 'VERSION',
      observed_at: new Date(Date.now() - 90000000).toISOString(),
    });

    // Seed sample manual review item
    manualReviewQueue.enqueueConflict({
      candidate_locators: [
        'github://caim-community/caim-agent-unverified',
        'github://caim-org/autonomous-caim-agent',
      ],
      conflict_summary: 'Identical package name and claims, but different publisher organization and unverified signing certificate.',
      suggested_outcome: 'UNRESOLVED',
      confidence: 0.52,
      evidence: {
        publisher_match: 0.1,
        repo_match: 0.3,
        homepage_match: 0.8,
        manifest_match: 0.9,
        checksum_match: 0.0,
        distribution_match: 0.5,
        similarity_score: 0.85,
        composite_confidence: 0.52,
        details: ['High name similarity with discordant author identities', 'Mismatched git commit signing key'],
      },
    });
  }

  // P22 / P23 / P24 Knowledge & Retrieval (No automatic demo intelligence seeding)
  const { corpus: knowledgeCorpus, retrieval: hybridRetrieval } = await initializeKnowledgeAndRetrieval(
    config.geminiApiKey,
    dbClient,
    { seedDemoCorpus: config.env !== 'production' && process.env.CAIM_SEED_DEMO_KNOWLEDGE === 'true' }
  );
  const ragPipeline = new RagSynthesisPipeline(knowledgeCorpus, hybridRetrieval);
  const contextAssembler = new ContextAssembler();

  // Composer
  const composerEngine = new AgentComposerEngine({
    corpusManager: knowledgeCorpus,
    retrievalService: hybridRetrieval,
    dbClient,
  });
  const syntheticTargetService = new SyntheticTargetService();

  // Packaging & Signing
  const kmsBoundary = KmsSignerBoundary.createDefault('caim-release-key-01', 'v1');

  // Evaluation
  const globalEvaluationEngine = new GoldenCorpusEvaluationEngine();
  if (!isProduction && config.env !== 'production' && config.env !== 'test') {
    setTimeout(() => {
      void globalEvaluationEngine.evaluateEngineVersion({
        engineVersion: 'v2.0.1-certified',
        baselineEngineVersion: 'v2.0.0-certified',
        isConclusionChanging: false,
        evaluatorActorId: 'system-init@caim.internal'
      }).catch(() => {});
    }, 1000);
  }

  const persistAnalysisOutputs = async (options: {
    analysisRunId: string;
    agentId?: string;
    agentVersionId?: string;
    staticReport?: any;
    decisionResult?: any;
    securityClassification?: string;
    tx?: any;
    principal?: any;
    truthResolution?: AnalysisTruthStateResolution;
    isSystemContext?: boolean;
    systemAuditReason?: string;
  }) => {
    const { analysisRunId, agentId, agentVersionId, staticReport, decisionResult, securityClassification, tx, principal, truthResolution, isSystemContext, systemAuditReason } = options;

    const adapter = dbAdapter || dbClient;
    const executeOperation = async (callback: (queryFn: (sql: string, params?: any[]) => Promise<any>) => Promise<void>) => {
      if (tx && typeof tx.query === 'function') {
        await callback((sql, p) => tx.query(sql, p));
      } else if (adapter && typeof adapter.withSecurityContext === 'function' && principal) {
        await adapter.withSecurityContext(principal, async (contextTx: any) => {
          await callback((sql, p) => contextTx.query(sql, p));
        });
      } else if (isSystemContext && adapter && typeof adapter.withSystemContext === 'function') {
        const sysPrincipal = principal || {
          principal_id: 'caim-system-worker',
          is_authenticated: true,
          is_service: true,
          roles: ['system_admin'],
          tenant_id: null,
          accessible_scope_ids: ['*'],
          max_classification_rank: 3,
          grants: ['*'],
        };
        await adapter.withSystemContext(sysPrincipal, systemAuditReason || 'System worker persisting analytical outputs', async (contextTx: any) => {
          await callback((sql, p) => contextTx.query(sql, p));
        });
      } else {
        throw new Error('[SecurityBoundary] Denied: Attempted to persist analytical outputs without active security context or authorized principal.');
      }
    };

    await executeOperation(async (query) => {
      // 1. Mandatory Score results in intel.score_results
      if (decisionResult?.score_result) {
        await query(`
          INSERT INTO intel.score_results (
            score_result_id,
            analysis_run_id,
            score_model_id,
            overall_score,
            grade,
            calibration_version,
            truth_state
          ) VALUES (
            $1, $2, '00000000-0000-0000-0003-000000000001', $3, $4, '2.0.1', 'INFERRED'
          ) ON CONFLICT (analysis_run_id, score_model_id) DO UPDATE SET
            overall_score = EXCLUDED.overall_score,
            grade = EXCLUDED.grade,
            truth_state = EXCLUDED.truth_state;
        `, [
          generateUuid(),
          analysisRunId,
          decisionResult.score_result.overall_score,
          decisionResult.score_result.risk_band,
        ]);
      }

      // 2. Mandatory Policy decisions in intel.policy_decisions
      if (decisionResult?.policy_decision) {
        await query(`
          INSERT INTO intel.policy_decisions (
            decision_id,
            analysis_run_id,
            policy_version_id,
            decision,
            evaluation_summary,
            truth_state
          ) VALUES (
            $1, $2, '00000000-0000-0000-0003-000000000002', $3, $4, 'INFERRED'
          ) ON CONFLICT (analysis_run_id, policy_version_id) DO UPDATE SET
            decision = EXCLUDED.decision,
            evaluation_summary = EXCLUDED.evaluation_summary,
            truth_state = EXCLUDED.truth_state;
        `, [
          generateUuid(),
          analysisRunId,
          decisionResult.policy_decision.outcome === 'ALLOW' ? 'PASS' : (decisionResult.policy_decision.outcome === 'BLOCK' ? 'FAIL' : 'WARN'),
          `Policy decision: ${decisionResult.policy_decision.outcome}`,
        ]);
      }

      // 3. Static findings in analysis.static_findings
      if (staticReport?.findings && Array.isArray(staticReport.findings)) {
        for (const f of staticReport.findings) {
          await query(`
            INSERT INTO analysis.static_findings (
              finding_id,
              analysis_run_id,
              rule_id,
              finding_type,
              severity,
              confidence,
              message,
              truth_state,
              source_id,
              analyzer_version,
              observed_at
            ) VALUES (
              $1, $2, $3, $4, $5, $6, $7, 'STATICALLY_DERIVED', 'source-ast', '2.0.1', NOW()
            );
          `, [
            generateUuid(),
            analysisRunId,
            f.ruleId || 'ast-rule-001',
            f.type || 'VULNERABILITY',
            f.severity || 'HIGH',
            f.confidence || 0.95,
            f.title || f.description || 'Static finding',
          ]);
        }
      }

      // 4. Claims in intel.claims
      if (decisionResult?.policy_decision?.reasons && Array.isArray(decisionResult.policy_decision.reasons)) {
        for (const r of decisionResult.policy_decision.reasons) {
          await query(`
            INSERT INTO intel.claims (
              claim_id,
              analysis_run_id,
              claim_text,
              truth_state,
              source_id,
              analyzer_version,
              observed_at
            ) VALUES (
              $1, $2, $3, 'INFERRED', 'intel-policy-engine', '2.0.1', NOW()
            );
          `, [
            generateUuid(),
            analysisRunId,
            typeof r === 'string' ? r : (r.text || JSON.stringify(r)),
          ]);
        }
      }

      // 5. Entity classification in core.entity_refs
      if (agentId && agentVersionId && securityClassification && securityClassification !== 'DATA_UNAVAILABLE') {
        const classRes = await query(`
          SELECT security_classification_id FROM security.security_classifications WHERE code = $1 LIMIT 1;
        `, [securityClassification]);
        const classId = classRes.rows[0]?.security_classification_id || null;
        if (classId) {
          await query(`
            INSERT INTO core.entity_refs (
              entity_ref_id,
              entity_kind,
              native_id,
              agent_id,
              agent_version_id,
              analysis_run_id,
              security_classification_id,
              truth_state
            ) VALUES (
              $1, 'AGENT_VERSION', $2, $3, $4, $5, $6, 'OBSERVED'
            ) ON CONFLICT (entity_kind, native_id) DO UPDATE SET
              security_classification_id = EXCLUDED.security_classification_id,
              truth_state = EXCLUDED.truth_state;
          `, [
            generateUuid(),
            agentVersionId,
            agentId,
            agentVersionId,
            analysisRunId,
            classId,
          ]);
        }
      }

      // 6. Update analysis.analysis_runs with truth states and execution summary
      if (truthResolution) {
        await query(`
          UPDATE analysis.analysis_runs
          SET
            status = $1,
            static_status = $2,
            dynamic_status = $3,
            overall_status = $4,
            execution_summary = $5
          WHERE analysis_run_id = $6;
        `, [
          truthResolution.analysis_run_status,
          truthResolution.static_status,
          truthResolution.dynamic_status,
          truthResolution.overall_status,
          JSON.stringify(truthResolution.execution_summary),
          analysisRunId,
        ]);

        // Record static stage run
        await query(`
          INSERT INTO analysis.analysis_stage_runs (
            stage_run_id,
            analysis_run_id,
            engine_key,
            engine_version,
            status,
            started_at,
            completed_at,
            created_at
          ) VALUES (
            $1, $2, 'STATIC_AST_SCAN', '2.0.1', $3, NOW(), NOW(), NOW()
          ) ON CONFLICT DO NOTHING;
        `, [
          generateUuid(),
          analysisRunId,
          truthResolution.static_status === 'STATIC_COMPLETE' ? 'COMPLETED' : 'FAILED',
        ]);

        // Record dynamic stage run
        await query(`
          INSERT INTO analysis.analysis_stage_runs (
            stage_run_id,
            analysis_run_id,
            engine_key,
            engine_version,
            status,
            failure_code,
            started_at,
            completed_at,
            created_at
          ) VALUES (
            $1, $2, 'DYNAMIC_E2B_SANDBOX', '2.0.1', $3, $4, NOW(), NOW(), NOW()
          ) ON CONFLICT DO NOTHING;
        `, [
          generateUuid(),
          analysisRunId,
          truthResolution.dynamic_status === 'DYNAMIC_COMPLETE' ? 'COMPLETED' : (truthResolution.dynamic_status === 'DYNAMIC_FAILED' ? 'FAILED' : 'SKIPPED'),
          truthResolution.dynamic_status === 'DYNAMIC_NOT_VERIFIED' ? 'PROVIDER_UNAVAILABLE' : null,
        ]);
      }
    });
  };


  const handleProductIngestAgent = async (req: Request, res: Response) => {
    try {
      if (!req.principal || !req.principal.is_authenticated || req.principal.roles?.includes("anonymous")) {
        return res.status(401).json({
          error: "NO AUTHENTICATED PRINCIPAL: Authentication required for agent ingestion.",
          authenticated: false,
        });
      }

      const requestedTenant = (req.headers["x-tenant-id"] as string)
        || (req.body?.tenant_id as string)
        || (req.body?.tenantId as string);

      let authorizedTenantId: string;
      try {
        authorizedTenantId = resolveAuthorizedTenant(req.principal, requestedTenant);
        req.principal.tenant_id = authorizedTenantId;
        req.principal.tenantId = authorizedTenantId;
      } catch (err: any) {
        const status = err.name === 'UnauthorizedAccessError' ? 401 : 403;
        return res.status(status).json({
          error: err.message || "NO AUTHORIZED TENANT CONTEXT: Access denied for requested tenant.",
          authenticated: true,
        });
      }

      const {
        canonicalName,
        versionLabel,
        sourceLocator,
        framework,
        author,
        description,
        securityClassification,
        files,
        manifestContent,
        scoringModelId,
        policyId
      } = req.body || {};

      const name = (canonicalName && canonicalName.trim()) 
        || (sourceLocator ? sourceLocator.split('/').pop()?.replace(/\.git$/, '') : 'custom-agent') 
        || `agent-${Date.now().toString().slice(-4)}`;
      const vLabel = versionLabel || 'v1.0.0';
      const locator = sourceLocator || `github://caim-org/${name}`;

      // Resolve or create tenant scope for strict multi-tenant isolation
      let tenantScopeId = '00000000-0000-0000-0000-000000000001';
      if (authorizedTenantId && authorizedTenantId !== '00000000-0000-0000-0000-000000000000') {
        const scopeRes = await dbClient.query(
          `SELECT scope_id FROM security.access_scopes WHERE tenant_id = $1 LIMIT 1;`,
          [authorizedTenantId]
        );
        if (scopeRes.rows.length > 0) {
          tenantScopeId = scopeRes.rows[0].scope_id;
        } else {
          tenantScopeId = generateUuid();
          await dbClient.query(
            `INSERT INTO security.access_scopes (scope_id, scope_type, tenant_id, name)
             VALUES ($1, 'ORGANIZATION', $2, $3)
             ON CONFLICT DO NOTHING;`,
            [tenantScopeId, authorizedTenantId, `Scope for tenant ${authorizedTenantId}`]
          );
        }
      }

      // 1. Find or Insert Canonical Agent in core.canonical_agents
      let existingAgentRes = await dbClient.query(
        `SELECT * FROM core.canonical_agents WHERE canonical_name = $1 LIMIT 1;`,
        [name]
      );
      if (existingAgentRes.rows.length === 0) {
        const allAgents = await dbClient.query(`SELECT * FROM core.canonical_agents;`);
        const matched = allAgents.rows.find((r: any) => r.canonical_name?.toLowerCase() === name.toLowerCase());
        if (matched) {
          existingAgentRes = { rows: [matched] };
        }
      }
      let agentId: string;
      if (existingAgentRes.rows.length > 0) {
        agentId = existingAgentRes.rows[0].agent_id;
      } else {
        agentId = generateUuid();
        await dbClient.query(`
          INSERT INTO core.canonical_agents (agent_id, canonical_name, status, identity_confidence, created_at, updated_at)
          VALUES ($1, $2, 'ACTIVE', 1.0000, NOW(), NOW());
        `, [agentId, name]);
      }

      // 2. Insert Agent Version in core.agent_versions
      const agentVersionId = generateUuid();
      const contentPayload = (files && Array.isArray(files) && files.length > 0)
        ? files.map((f: any) => `${f.path}:${f.content}`).join('\n')
        : (manifestContent || `${name}:${vLabel}:${locator}`);
      const contentHash = `sha256:${crypto.createHash('sha256').update(contentPayload).digest('hex')}`;

      await dbClient.query(`
        INSERT INTO core.agent_versions (agent_version_id, agent_id, version_label, content_fingerprint, source_commit, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW());
      `, [agentVersionId, agentId, vLabel, contentHash, locator]);

      // 3. Find active workflow definition
      const wfDefRes = await dbClient.query(`SELECT workflow_definition_id FROM ops.workflow_definitions LIMIT 1;`);
      const wfDefId = wfDefRes.rows[0]?.workflow_definition_id || generateUuid();

      // 4. Create Workflow Run in ops.workflow_runs
      const workflowRunId = generateUuid();
      const correlationId = `corr-ingest-${Date.now()}`;
      await dbClient.query(`
        INSERT INTO ops.workflow_runs (workflow_run_id, workflow_definition_id, status, correlation_id, started_at, created_at)
        VALUES ($1, $2, 'RUNNING', $3, NOW(), NOW());
      `, [workflowRunId, wfDefId, correlationId]);

      // 5. Create Job in ops.jobs
      const jobId = generateUuid();
      const jobPayload = {
        agentId,
        agentVersionId,
        canonicalName: name,
        versionLabel: vLabel,
        sourceLocator: locator,
      };
      await dbClient.query(`
        INSERT INTO ops.jobs (job_id, workflow_run_id, queue_key, idempotency_key, priority, status, payload, created_at)
        VALUES ($1, $2, 'ingestion.submission', $3, 5, 'RUNNING', $4, NOW());
      `, [jobId, workflowRunId, `ingest:${agentVersionId}`, JSON.stringify(jobPayload)]);

      // 6. Create Job Attempt in ops.job_attempts
      const attemptId = generateUuid();
      await dbClient.query(`
        INSERT INTO ops.job_attempts (job_attempt_id, job_id, attempt_no, worker_id, leased_at, lease_expires_at, created_at)
        VALUES ($1, $2, 1, 'worker-ingestion-pool-1', NOW(), NOW() + INTERVAL '5 minutes', NOW());
      `, [attemptId, jobId]);

      // 7. Verify Authentic Source Acquisition & Enforce Invariant
      const rawInputFiles: Array<{ path: string; content: string }> | null = (files && Array.isArray(files) && files.length > 0)
        ? files
        : (manifestContent ? [{ path: 'manifest.json', content: manifestContent }] : null);

      const verification = AuthenticSourceAcquisitionService.verifyAndHashArtifact(
        { source_type: 'manual', display_name: name, source_locator: locator },
        rawInputFiles,
        { version_identity: vLabel }
      );

      const analysisRunId = generateUuid();
      const derivedFramework = framework || 'DATA_UNAVAILABLE';
      const frameworkTruthState = framework ? 'USER_DECLARED' : 'UNKNOWN';
      const derivedAuthor = author || 'DATA_UNAVAILABLE';
      const authorTruthState = author ? 'USER_DECLARED' : 'UNKNOWN';
      const derivedDescription = description || 'DATA_UNAVAILABLE';
      const descriptionTruthState = description ? 'USER_DECLARED' : 'UNKNOWN';
      const derivedSecurityClass = securityClassification || 'DATA_UNAVAILABLE';
      const securityClassTruthState = securityClassification ? 'USER_DECLARED' : 'UNKNOWN';
      const derivedLocator = sourceLocator || locator;
      const locatorTruthState = sourceLocator ? 'USER_DECLARED' : 'INFERRED';

      // If authentic source could not be acquired, retain candidate but NEVER perform synthetic analysis
      if (!verification.has_authentic_source) {
        const adapter = dbAdapter || dbClient;
        if (!adapter || typeof adapter.withSecurityContext !== 'function') {
          throw new Error('[SecurityBoundary] Denied: Database adapter with security context is required.');
        }
        await adapter.withSecurityContext(req.principal, async (tx: any) => {
          await tx.query(`
            INSERT INTO analysis.analysis_runs (
              analysis_run_id,
              agent_version_id,
              scope_id,
              pipeline_version,
              caim_version,
              ontology_version,
              trigger_type,
              status,
              started_at,
              completed_at,
              created_at
            ) VALUES (
              $1, $2, $3, '2.0.1', '2.0.1', 'v2.0.1', 'EVENT', 'ANALYSIS_NOT_PERFORMED', NOW(), NOW(), NOW()
            );
          `, [analysisRunId, agentVersionId, tenantScopeId]);
        });

        await dbClient.query(`UPDATE ops.jobs SET status = 'COMPLETED' WHERE job_id = $1;`, [jobId]);
        await dbClient.query(`UPDATE ops.job_attempts SET completed_at = NOW() WHERE job_attempt_id = $1;`, [attemptId]);
        await dbClient.query(`UPDATE ops.workflow_runs SET status = 'COMPLETED', completed_at = NOW() WHERE workflow_run_id = $1;`, [workflowRunId]);

        await platformAuditService.recordAuditEntry({
          principal_id: req.principal?.principal_id || 'product-user',
          action: 'AGENT_DISCOVERED',
          target_entity_type: 'AGENT_VERSION',
          target_entity_id: agentVersionId,
          outcome: 'SUCCESS',
          client_ip: req.ip,
          user_agent: req.headers['user-agent'] as string,
          correlation_id: correlationId,
          details: {
            agent_id: agentId,
            canonical_name: name,
            version_label: vLabel,
            candidate_status: 'DISCOVERED',
            source_status: 'SOURCE_UNAVAILABLE',
            analysis_status: 'ANALYSIS_NOT_PERFORMED',
            rejection_reason: verification.rejection_reason,
          },
        });

        return res.json({
          success: true,
          agent_id: agentId,
          agent_version_id: agentVersionId,
          canonical_name: name,
          version_label: vLabel,
          content_hash: contentHash,
          content_fingerprint: contentHash,
          framework: derivedFramework,
          author: derivedAuthor,
          description: derivedDescription,
          source_locator: derivedLocator,
          security_classification: derivedSecurityClass,
          workflow_run_id: workflowRunId,
          job_id: jobId,
          analysis_run_id: analysisRunId,
          candidate_status: 'DISCOVERED',
          source_status: 'SOURCE_UNAVAILABLE',
          analysis_status: 'ANALYSIS_NOT_PERFORMED',
          truthState: 'UNKNOWN',
          truth_state: 'UNKNOWN',
          epistemic_metadata: {
            framework: { value: derivedFramework, truthState: frameworkTruthState },
            author: { value: derivedAuthor, truthState: authorTruthState },
            description: { value: derivedDescription, truthState: descriptionTruthState },
            security_classification: { value: derivedSecurityClass, truthState: securityClassTruthState },
            source_locator: { value: derivedLocator, truthState: locatorTruthState },
            overall_score: { value: 'NOT_CALCULATED', truthState: 'UNKNOWN' },
            risk_band: { value: 'NOT_CALCULATED', truthState: 'UNKNOWN' },
            findings_count: { value: 'NOT_CALCULATED', truthState: 'UNKNOWN' },
            claims_count: { value: 'NOT_CALCULATED', truthState: 'UNKNOWN' },
          },
          analysis_run: {
            analysis_run_id: analysisRunId,
            pipeline_version: '2.0.1',
            status: 'ANALYSIS_NOT_PERFORMED',
            source_status: 'SOURCE_UNAVAILABLE',
            findings_count: 'NOT_CALCULATED',
            claims_count: 'NOT_CALCULATED',
            overall_score: 'NOT_CALCULATED',
            risk_band: 'NOT_CALCULATED',
            policy_outcome: 'NOT_CALCULATED',
            created_at: new Date().toISOString(),
          },
        });
      }

      // Authentic files are available: execute analysis pipeline
      const filesToAnalyze = verification.files.map(f => ({ path: f.path, content: f.content as string }));
      const staticReport = StaticAnalysisEngine.analyze({
        artifactId: `art-${agentId.slice(0, 8)}`,
        files: filesToAnalyze,
        entrypoints: verification.files.map(f => f.path),
        pipelineRunId: analysisRunId,
      });

      // Resolve explicit truth states separating static, dynamic, and overall status
      const truthResolution = resolveAnalysisTruthState({
        staticReport,
        isDynamicRequested: false,
      });

      // 8. Execute Real Decision Scoring Suite & Policy Evaluation
      const decisionResult = await DecisionOrchestrationEngine.runDecisionSuite({
        analysisRunId,
        entityRefId: agentVersionId,
        scoreModelKey: scoringModelId || 'caim-standard-risk-v2',
        policyKey: policyId || 'pol-enterprise-prod-v2',
        staticFindings: staticReport.findings,
        evidenceList: staticReport.findings.map((f, i) => ({
          evidence_id: `ev-${analysisRunId.slice(0, 8)}-${i + 1}`,
          analysis_run_id: analysisRunId,
          evidence_type: 'STATIC_CODE',
          description: f.description || f.title,
          confidence: f.confidence || 0.95,
          weight: 1.0,
          created_at: new Date().toISOString(),
        })),
        staticStatus: truthResolution.static_status,
        dynamicStatus: truthResolution.dynamic_status,
        overallStatus: truthResolution.overall_status,
        truthState: truthResolution.truth_state,
        why: truthResolution.why,
        evidenceClassesAvailable: truthResolution.evidence_classes_available,
        evidenceClassesMissing: truthResolution.evidence_classes_missing,
        staticOnlyConclusions: truthResolution.static_only_conclusions,
        executionSummary: truthResolution.execution_summary,
      });

      // 9. Persist Real Analysis Run Record & Analytical Outputs
      const adapter = dbAdapter || dbClient;
      if (!adapter || typeof adapter.withSecurityContext !== 'function') {
        throw new Error('[SecurityBoundary] Denied: Database adapter with security context is required.');
      }

      await adapter.withSecurityContext(req.principal, async (tx: any) => {
        await tx.query(`
          INSERT INTO analysis.analysis_runs (
            analysis_run_id,
            agent_version_id,
            scope_id,
            pipeline_version,
            caim_version,
            ontology_version,
            trigger_type,
            status,
            static_status,
            dynamic_status,
            overall_status,
            execution_summary,
            started_at,
            completed_at,
            created_at
          ) VALUES (
            $1, $2, $3, '2.0.1', '2.0.1', 'v2.0.1', 'EVENT', $4, $5, $6, $7, $8, NOW(), NOW(), NOW()
          );
        `, [
          analysisRunId,
          agentVersionId,
          tenantScopeId,
          truthResolution.analysis_run_status,
          truthResolution.static_status,
          truthResolution.dynamic_status,
          truthResolution.overall_status,
          JSON.stringify(truthResolution.execution_summary),
        ]);

        // 9b. Persist analytical outputs into intel and analysis tables within transaction
        await persistAnalysisOutputs({
          analysisRunId,
          agentId,
          agentVersionId,
          staticReport,
          decisionResult,
          securityClassification: securityClassification || undefined,
          tx,
          principal: req.principal,
          truthResolution,
        });
      });

      // 10. Complete Jobs & Workflow Run in Postgres DB
      await dbClient.query(`UPDATE ops.jobs SET status = 'COMPLETED' WHERE job_id = $1;`, [jobId]);
      await dbClient.query(`UPDATE ops.job_attempts SET completed_at = NOW() WHERE job_attempt_id = $1;`, [attemptId]);
      await dbClient.query(`UPDATE ops.workflow_runs SET status = 'COMPLETED', completed_at = NOW() WHERE workflow_run_id = $1;`, [workflowRunId]);

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'product-user',
        action: 'AGENT_INGESTED',
        target_entity_type: 'AGENT_VERSION',
        target_entity_id: agentVersionId,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        correlation_id: correlationId,
        details: {
          agent_id: agentId,
          canonical_name: name,
          version_label: vLabel,
          content_hash: contentHash,
          source_locator: locator,
          overall_score: decisionResult.score_result?.overall_score,
          risk_band: decisionResult.score_result?.risk_band,
          policy_outcome: decisionResult.policy_decision?.outcome,
          static_status: truthResolution.static_status,
          dynamic_status: truthResolution.dynamic_status,
          overall_status: truthResolution.overall_status,
        },
      });

      const overallScore = decisionResult.score_result ? decisionResult.score_result.overall_score : 'NOT_CALCULATED';
      const riskBand = decisionResult.score_result ? decisionResult.score_result.risk_band : 'NOT_CALCULATED';
      const findingsCount = staticReport.findings.length;
      const claimsCount = decisionResult.policy_decision?.reasons?.length ?? 0;

      res.json({
        success: true,
        agent_id: agentId,
        agent_version_id: agentVersionId,
        canonical_name: name,
        version_label: vLabel,
        content_hash: contentHash,
        content_fingerprint: contentHash,
        framework: derivedFramework,
        author: derivedAuthor,
        description: derivedDescription,
        source_locator: derivedLocator,
        security_classification: derivedSecurityClass,
        workflow_run_id: workflowRunId,
        job_id: jobId,
        analysis_run_id: analysisRunId,
        static_status: truthResolution.static_status,
        dynamic_status: truthResolution.dynamic_status,
        overall_status: truthResolution.overall_status,
        status: truthResolution.analysis_run_status,
        truthState: truthResolution.truth_state,
        truth_state: truthResolution.truth_state,
        executed: truthResolution.executed,
        not_verified: truthResolution.not_verified,
        why: truthResolution.why,
        static_only_conclusions: truthResolution.static_only_conclusions,
        evidence_classes_available: truthResolution.evidence_classes_available,
        evidence_classes_missing: truthResolution.evidence_classes_missing,
        execution_summary: truthResolution.execution_summary,
        epistemic_metadata: {
          framework: { value: derivedFramework, truthState: frameworkTruthState },
          author: { value: derivedAuthor, truthState: authorTruthState },
          description: { value: derivedDescription, truthState: descriptionTruthState },
          security_classification: { value: derivedSecurityClass, truthState: securityClassTruthState },
          source_locator: { value: derivedLocator, truthState: locatorTruthState },
          overall_score: { value: overallScore, truthState: truthResolution.truth_state },
          risk_band: { value: riskBand, truthState: truthResolution.truth_state },
          findings_count: { value: findingsCount, truthState: 'STATICALLY_DERIVED' },
          claims_count: { value: claimsCount, truthState: truthResolution.truth_state },
        },
        analysis_run: {
          analysis_run_id: analysisRunId,
          pipeline_version: '2.0.1',
          status: truthResolution.analysis_run_status,
          overall_status: truthResolution.overall_status,
          static_status: truthResolution.static_status,
          dynamic_status: truthResolution.dynamic_status,
          findings_count: findingsCount,
          claims_count: claimsCount,
          overall_score: overallScore,
          risk_band: riskBand,
          policy_outcome: decisionResult.policy_decision?.outcome || 'NOT_CALCULATED',
          truthState: truthResolution.truth_state,
          truth_state: truthResolution.truth_state,
          executed: truthResolution.executed,
          not_verified: truthResolution.not_verified,
          why: truthResolution.why,
          static_only_conclusions: truthResolution.static_only_conclusions,
          evidence_classes_available: truthResolution.evidence_classes_available,
          evidence_classes_missing: truthResolution.evidence_classes_missing,
          execution_summary: truthResolution.execution_summary,
          created_at: new Date().toISOString(),
        },
        static_report: staticReport,
        decision_suite: decisionResult,
      });
    } catch (err: any) {
      console.error("[Product Ingest Error]:", err);
      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'product-user',
        action: 'AGENT_INGESTED',
        target_entity_type: 'CANONICAL_AGENT',
        target_entity_id: req.body?.canonicalName || 'unknown-agent',
        outcome: 'ERROR',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { error: err.message || String(err) },
      });
      res.status(500).json({ error: err.message || "Failed to submit agent for ingestion" });
    }
  };


  const handleProductListAgents = async (req: Request, res: Response) => {
    try {
      if (!req.principal || !req.principal.is_authenticated || req.principal.roles?.includes("anonymous")) {
        return res.status(401).json({
          error: "NO AUTHENTICATED PRINCIPAL: Authentication required.",
          authenticated: false,
        });
      }

      const requestedTenant = (req.headers["x-tenant-id"] as string)
        || (req.query?.tenant_id as string)
        || (req.query?.tenantId as string);

      let authorizedTenantId: string;
      try {
        authorizedTenantId = resolveAuthorizedTenant(req.principal, requestedTenant);
        req.principal.tenant_id = authorizedTenantId;
        req.principal.tenantId = authorizedTenantId;
      } catch (err: any) {
        const status = err.name === 'UnauthorizedAccessError' ? 401 : 403;
        return res.status(status).json({
          error: err.message || "NO AUTHORIZED TENANT CONTEXT: Access denied for requested tenant.",
          authenticated: true,
        });
      }

      const adapter = dbAdapter || dbClient;
      if (!adapter || typeof adapter.withSecurityContext !== 'function') {
        throw new Error('[SecurityBoundary] Denied: Database adapter with security context is required.');
      }

      const rows = await adapter.withSecurityContext(req.principal, async (tx: any) => {
        const res = await tx.query(`
          SELECT 
            ca.agent_id,
            ca.canonical_name,
            ca.status,
            ca.identity_confidence,
            ca.created_at,
            av.agent_version_id,
            av.version_label,
            av.content_fingerprint,
            av.source_commit,
            ar.analysis_run_id,
            ar.status as analysis_status,
            ar.pipeline_version,
            ar.created_at as analysis_created_at,
            sr.overall_score,
            sr.grade as risk_band,
            (SELECT count(*)::int FROM analysis.static_findings sf WHERE sf.analysis_run_id = ar.analysis_run_id) as findings_count,
            (SELECT count(*)::int FROM intel.claims cl WHERE cl.analysis_run_id = ar.analysis_run_id) as claims_count,
            sc.code as security_classification
          FROM core.canonical_agents ca
          LEFT JOIN core.agent_versions av ON ca.agent_id = av.agent_id
          LEFT JOIN analysis.analysis_runs ar ON av.agent_version_id = ar.agent_version_id
          LEFT JOIN intel.score_results sr ON ar.analysis_run_id = sr.analysis_run_id
          LEFT JOIN core.entity_refs er ON (er.agent_version_id = av.agent_version_id OR (er.agent_id = ca.agent_id AND er.agent_version_id IS NULL))
          LEFT JOIN security.security_classifications sc ON er.security_classification_id = sc.security_classification_id
          ORDER BY ca.created_at DESC, av.created_at DESC;
        `);
        return res.rows;
      });

      const libraryList = autonomousWorker ? autonomousWorker.getLibrary() : [];
      const libraryMap = new Map<string, any>();
      for (const item of libraryList) {
        if (item.canonical_name) libraryMap.set(item.canonical_name.toLowerCase(), item);
        if (item.agent_id) libraryMap.set(item.agent_id, item);
      }

      const agentMap = new Map<string, any>();
      for (const row of rows) {
        const libMatch = libraryMap.get(row.canonical_name?.toLowerCase()) || libraryMap.get(row.agent_id);

        if (!agentMap.has(row.agent_id)) {
          const framework = libMatch?.framework && libMatch.framework !== 'DATA_UNAVAILABLE' 
            ? libMatch.framework 
            : 'DATA_UNAVAILABLE';
          const frameworkTruthState = framework !== 'DATA_UNAVAILABLE' ? (libMatch?.truthState || 'OBSERVED') : 'UNKNOWN';

          const author = libMatch?.author && libMatch.author !== 'DATA_UNAVAILABLE' 
            ? libMatch.author 
            : 'DATA_UNAVAILABLE';
          const authorTruthState = author !== 'DATA_UNAVAILABLE' ? (libMatch?.truthState || 'OBSERVED') : 'UNKNOWN';

          const secClass = row.security_classification 
            || (libMatch?.security_classification && libMatch.security_classification !== 'DATA_UNAVAILABLE' ? libMatch.security_classification : 'DATA_UNAVAILABLE');
          const secClassTruthState = secClass !== 'DATA_UNAVAILABLE' ? 'OBSERVED' : 'UNKNOWN';

          const description = libMatch?.description && libMatch.description !== 'DATA_UNAVAILABLE'
            ? libMatch.description
            : 'DATA_UNAVAILABLE';
          const descriptionTruthState = description !== 'DATA_UNAVAILABLE' ? (libMatch?.truthState || 'OBSERVED') : 'UNKNOWN';

          const sourceLocator = row.source_commit 
            || (libMatch?.source_locator && libMatch.source_locator !== 'DATA_UNAVAILABLE' ? libMatch.source_locator : 'DATA_UNAVAILABLE');
          const sourceLocatorTruthState = sourceLocator !== 'DATA_UNAVAILABLE' ? 'OBSERVED' : 'UNKNOWN';

          const agentTruthState = (framework !== 'DATA_UNAVAILABLE' && author !== 'DATA_UNAVAILABLE') ? 'OBSERVED' : 'UNKNOWN';

          agentMap.set(row.agent_id, {
            agent_id: row.agent_id,
            canonical_name: row.canonical_name,
            status: row.status,
            identity_confidence: Number(row.identity_confidence),
            created_at: row.created_at,
            description,
            framework,
            author,
            security_classification: secClass,
            source_locator: sourceLocator,
            truthState: agentTruthState,
            truth_state: agentTruthState,
            epistemic_metadata: {
              framework: { value: framework, truthState: frameworkTruthState },
              author: { value: author, truthState: authorTruthState },
              description: { value: description, truthState: descriptionTruthState },
              security_classification: { value: secClass, truthState: secClassTruthState },
              source_locator: { value: sourceLocator, truthState: sourceLocatorTruthState },
            },
            versions: [],
          });
        }
        const agent = agentMap.get(row.agent_id);
        if (row.agent_version_id && !agent.versions.some((v: any) => v.agent_version_id === row.agent_version_id)) {
          const vLocator = row.source_commit || agent.source_locator;
          const vSecClass = agent.security_classification;
          const versionTruthState = vLocator !== 'DATA_UNAVAILABLE' ? 'OBSERVED' : 'UNKNOWN';

          const analysisRuns = [];
          if (row.analysis_run_id) {
            const hasScore = row.overall_score !== null && row.overall_score !== undefined;
            const libScore = libMatch?.overall_score !== 'NOT_CALCULATED' ? libMatch?.overall_score : null;
            const score = hasScore 
              ? Number(row.overall_score) 
              : (libScore !== null && libScore !== undefined ? Number(libScore) : 'NOT_CALCULATED');
            const scoreTruthState = score !== 'NOT_CALCULATED' ? 'INFERRED' : 'UNKNOWN';

            const hasRiskBand = row.risk_band !== null && row.risk_band !== undefined;
            const libRiskBand = libMatch?.risk_band !== 'NOT_CALCULATED' ? libMatch?.risk_band : null;
            const riskBand = hasRiskBand 
              ? row.risk_band 
              : (libRiskBand ? libRiskBand : 'NOT_CALCULATED');
            const riskBandTruthState = riskBand !== 'NOT_CALCULATED' ? 'INFERRED' : 'UNKNOWN';

            const hasFindingsCount = row.findings_count !== null && row.findings_count !== undefined;
            const libFindings = libMatch?.findings_count !== 'NOT_CALCULATED' ? libMatch?.findings_count : null;
            const findingsCount = hasFindingsCount 
              ? Number(row.findings_count) 
              : (libFindings !== null && libFindings !== undefined ? Number(libFindings) : 'NOT_CALCULATED');
            const findingsTruthState = findingsCount !== 'NOT_CALCULATED' ? 'STATICALLY_DERIVED' : 'UNKNOWN';

            const hasClaimsCount = row.claims_count !== null && row.claims_count !== undefined;
            const libClaims = libMatch?.evidence_count !== 'NOT_CALCULATED' ? libMatch?.evidence_count : null;
            const claimsCount = hasClaimsCount 
              ? Number(row.claims_count) 
              : (libClaims !== null && libClaims !== undefined ? Number(libClaims) : 'NOT_CALCULATED');
            const claimsTruthState = claimsCount !== 'NOT_CALCULATED' ? 'INFERRED' : 'UNKNOWN';

            const runTruthState = score !== 'NOT_CALCULATED' ? 'INFERRED' : (findingsCount !== 'NOT_CALCULATED' ? 'STATICALLY_DERIVED' : 'UNKNOWN');

            analysisRuns.push({
              analysis_run_id: row.analysis_run_id,
              pipeline_version: row.pipeline_version || '2.0.1',
              status: row.analysis_status || 'COMPLETED',
              findings_count: findingsCount,
              claims_count: claimsCount,
              overall_score: score,
              risk_band: riskBand,
              truthState: runTruthState,
              truth_state: runTruthState,
              epistemic_metadata: {
                findings_count: { value: findingsCount, truthState: findingsTruthState },
                claims_count: { value: claimsCount, truthState: claimsTruthState },
                overall_score: { value: score, truthState: scoreTruthState },
                risk_band: { value: riskBand, truthState: riskBandTruthState },
              },
              created_at: row.analysis_created_at || new Date().toISOString()
            });
          }

          agent.versions.push({
            agent_version_id: row.agent_version_id,
            agent_id: row.agent_id,
            version_label: row.version_label || 'DATA_UNAVAILABLE',
            content_hash: row.content_fingerprint || 'DATA_UNAVAILABLE',
            source_locator: vLocator,
            security_classification: vSecClass,
            status: 'ACTIVE',
            truthState: versionTruthState,
            truth_state: versionTruthState,
            epistemic_metadata: {
              source_locator: { value: vLocator, truthState: vLocator !== 'DATA_UNAVAILABLE' ? 'OBSERVED' : 'UNKNOWN' },
              security_classification: { value: vSecClass, truthState: vSecClass !== 'DATA_UNAVAILABLE' ? 'OBSERVED' : 'UNKNOWN' },
            },
            created_at: row.created_at || new Date().toISOString(),
            analysis_runs: analysisRuns,
          });
        }
      }

      res.json(Array.from(agentMap.values()));
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to list agents" });
    }
  };


  const handleDiscoveryLineage = async (req: Request, res: Response) => {
    try {
      const { agentId } = req.params;
      const lineage = await discoveryLineageService.getDiscoveryLineage(agentId);
      res.json(lineage);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to retrieve discovery lineage" });
    }
  };

  const handleDiscoveredDescendants = async (req: Request, res: Response) => {
    try {
      const { agentId } = req.params;
      const descendants = await discoveryLineageService.getDiscoveredDescendants(agentId);
      res.json(descendants);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to retrieve discovered descendants" });
    }
  };



  const handleProductTriggerAnalysis = async (req: Request, res: Response) => {
    try {
      if (!req.principal || !req.principal.is_authenticated || req.principal.roles?.includes("anonymous")) {
        return res.status(401).json({
          error: "NO AUTHENTICATED PRINCIPAL: Authentication required.",
          authenticated: false,
        });
      }

      const requestedTenant = (req.headers["x-tenant-id"] as string)
        || (req.body?.tenant_id as string)
        || (req.body?.tenantId as string);

      let authorizedTenantId: string;
      try {
        authorizedTenantId = resolveAuthorizedTenant(req.principal, requestedTenant);
        req.principal.tenant_id = authorizedTenantId;
        req.principal.tenantId = authorizedTenantId;
      } catch (err: any) {
        const status = err.name === 'UnauthorizedAccessError' ? 401 : 403;
        return res.status(status).json({
          error: err.message || "NO AUTHORIZED TENANT CONTEXT: Access denied for requested tenant.",
          authenticated: true,
        });
      }

      let tenantScopeId = '00000000-0000-0000-0000-000000000001';
      if (authorizedTenantId && authorizedTenantId !== '00000000-0000-0000-0000-000000000000') {
        const scopeRes = await dbClient.query(
          `SELECT scope_id FROM security.access_scopes WHERE tenant_id = $1 LIMIT 1;`,
          [authorizedTenantId]
        );
        if (scopeRes.rows.length > 0) {
          tenantScopeId = scopeRes.rows[0].scope_id;
        } else {
          tenantScopeId = generateUuid();
          await dbClient.query(
            `INSERT INTO security.access_scopes (scope_id, scope_type, tenant_id, name)
             VALUES ($1, 'ORGANIZATION', $2, $3)
             ON CONFLICT DO NOTHING;`,
            [tenantScopeId, authorizedTenantId, `Scope for tenant ${authorizedTenantId}`]
          );
        }
      }

      const { agentId, agentVersionId, scoringModelId, policyId, sourceFiles } = req.body || {};

      if (!agentId || !agentVersionId) {
        await platformAuditService.recordAuditEntry({
          principal_id: req.principal?.principal_id || 'anonymous',
          action: 'ANALYSIS_TRIGGERED',
          target_entity_type: 'AGENT_VERSION',
          target_entity_id: 'missing_params',
          outcome: 'REFUSED',
          client_ip: req.ip,
          user_agent: req.headers['user-agent'] as string,
          details: { error: "Missing agentId or agentVersionId parameter" },
        });
        return res.status(400).json({ error: "Missing agentId or agentVersionId parameter" });
      }

      // Ensure canonical agent exists in DB
      const isAgentUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(agentId);
      let existingAgentRes;
      if (isAgentUuid) {
        existingAgentRes = await dbClient.query(`
          SELECT agent_id FROM core.canonical_agents WHERE agent_id = $1 LIMIT 1;
        `, [agentId]);
      }
      if (!existingAgentRes || existingAgentRes.rows.length === 0) {
        existingAgentRes = await dbClient.query(`
          SELECT agent_id FROM core.canonical_agents WHERE canonical_name = $1 LIMIT 1;
        `, [agentId]);
      }
      if (existingAgentRes.rows.length === 0) {
        const allAgents = await dbClient.query(`SELECT agent_id, canonical_name FROM core.canonical_agents;`);
        const matched = allAgents.rows.find((r: any) => r.canonical_name?.toLowerCase() === agentId.toLowerCase());
        if (matched) {
          existingAgentRes = { rows: [matched] };
        }
      }

      let realAgentId: string;
      if (existingAgentRes.rows.length > 0) {
        realAgentId = existingAgentRes.rows[0].agent_id;
      } else {
        realAgentId = isAgentUuid ? agentId : generateUuid();
        await dbClient.query(`
          INSERT INTO core.canonical_agents (agent_id, canonical_name, status, identity_confidence, created_at, updated_at)
          VALUES ($1, $2, 'ACTIVE', 0.9800, NOW(), NOW())
          ON CONFLICT (agent_id) DO NOTHING;
        `, [realAgentId, agentId]);
      }

      // Ensure agent version exists in DB
      const isVerUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(agentVersionId);
      let existingVerRes;
      if (isVerUuid) {
        existingVerRes = await dbClient.query(`
          SELECT agent_version_id FROM core.agent_versions WHERE agent_version_id = $1 LIMIT 1;
        `, [agentVersionId]);
      } else {
        existingVerRes = await dbClient.query(`
          SELECT agent_version_id FROM core.agent_versions WHERE agent_id = $1 AND version_label = $2 LIMIT 1;
        `, [realAgentId, agentVersionId]);
      }

      let realAgentVersionId: string;
      if (existingVerRes.rows.length > 0) {
        realAgentVersionId = existingVerRes.rows[0].agent_version_id;
      } else {
        realAgentVersionId = isVerUuid ? agentVersionId : generateUuid();
        const vFingerprint = `sha256:${crypto.createHash('sha256').update(`${realAgentId}:${agentVersionId}`).digest('hex')}`;
        await dbClient.query(`
          INSERT INTO core.agent_versions (agent_version_id, agent_id, version_label, content_fingerprint, source_commit, created_at)
          VALUES ($1, $2, $3, $4, 'manual_trigger', NOW())
          ON CONFLICT (agent_version_id) DO NOTHING;
        `, [realAgentVersionId, realAgentId, isVerUuid ? 'v1.0.0' : agentVersionId, vFingerprint]);
      }

      const wfDefRes = await dbClient.query(`SELECT workflow_definition_id FROM ops.workflow_definitions LIMIT 1;`);
      const wfDefId = wfDefRes.rows[0]?.workflow_definition_id || generateUuid();

      const workflowRunId = generateUuid();
      const correlationId = `corr-analysis-${Date.now()}`;
      await dbClient.query(`
        INSERT INTO ops.workflow_runs (workflow_run_id, workflow_definition_id, status, correlation_id, started_at, created_at)
        VALUES ($1, $2, 'RUNNING', $3, NOW(), NOW());
      `, [workflowRunId, wfDefId, correlationId]);

      const jobId = generateUuid();
      await dbClient.query(`
        INSERT INTO ops.jobs (job_id, workflow_run_id, queue_key, idempotency_key, priority, status, payload, created_at)
        VALUES ($1, $2, 'analysis.pipeline', $3, 10, 'RUNNING', $4, NOW());
      `, [jobId, workflowRunId, `wf:${workflowRunId}:analysis`, JSON.stringify({ agentId, agentVersionId })]);

      const attemptId = generateUuid();
      await dbClient.query(`
        INSERT INTO ops.job_attempts (job_attempt_id, job_id, attempt_no, worker_id, leased_at, lease_expires_at, created_at)
        VALUES ($1, $2, 1, 'worker-analysis-engine-1', NOW(), NOW() + INTERVAL '10 minutes', NOW());
      `, [attemptId, jobId]);

      const analysisRunId = generateUuid();

      // Enforce authentic source acquisition: reject synthetic generation
      const verification = AuthenticSourceAcquisitionService.verifyAndHashArtifact(
        { source_type: 'source-trigger', display_name: agentId },
        sourceFiles || null
      );

      if (!verification.has_authentic_source) {
        return res.status(422).json({
          success: false,
          error: 'SOURCE_UNAVAILABLE: Cannot perform analysis without authentic acquired source files. Generating synthetic source is strictly forbidden.',
          candidate_status: 'DISCOVERED',
          source_status: 'SOURCE_UNAVAILABLE',
          analysis_status: 'ANALYSIS_NOT_PERFORMED',
          overall_score: 'NOT_CALCULATED',
          risk_band: 'NOT_CALCULATED',
          policy_outcome: 'NOT_CALCULATED',
        });
      }

      const filesToAnalyze = verification.files.map(f => ({ path: f.path, content: f.content as string }));

      const staticReport = StaticAnalysisEngine.analyze({
        artifactId: `art-${agentId.slice(0, 8)}`,
        files: filesToAnalyze,
        entrypoints: verification.files.map(f => f.path),
        pipelineRunId: analysisRunId,
      });

      // Execute Real Dynamic Sandbox Verification via E2B Provider
      let dynamicRunResult: any = null;
      let staticDynamicComparison: any = null;
      let dynamicFindings: any[] = [];

      try {
        const fileMap: Record<string, string> = {};
        for (const f of filesToAnalyze) {
          fileMap[f.path] = f.content;
        }

        dynamicRunResult = await SandboxOrchestrationEngine.runScenario({
          providerType: 'E2B',
          artifactId: `art-${agentId.slice(0, 8)}`,
          files: fileMap,
          resourceLimits: {
            maxDurationMs: 15000,
            maxMemoryMb: 512,
            maxCpuPercentage: 50,
          },
        });

        // Correlate static AST findings against live dynamic events
        staticDynamicComparison = StaticDynamicComparator.compare(staticReport.findings, dynamicRunResult);

        const isRealE2B = dynamicRunResult?.provider_type === 'E2B';

        // Map confirmed matches
        dynamicFindings = staticDynamicComparison.confirmed_matches.map((m: any) => ({
          finding_id: m.finding_id,
          rule_id: m.rule_id,
          category: m.category,
          severity: m.severity,
          static_prediction: m.static_prediction,
          dynamic_evidence: {
            matched_event_ids: m.dynamic_evidence.matched_event_ids,
            summary: m.dynamic_evidence.summary,
            syscalls: m.dynamic_evidence.events?.map((e: any) => `${e.action} -> ${e.target}`),
            network_egress_attempted: m.dynamic_evidence.events?.filter((e: any) => e.category === 'NETWORK').map((e: any) => e.target),
            filesystem_access: m.dynamic_evidence.events?.filter((e: any) => e.category === 'FILESYSTEM').map((e: any) => e.target),
            exit_code: 0,
            raw_traces: dynamicRunResult.raw_traces,
          },
          concordance: m.concordance,
          notes: isRealE2B
            ? `E2B microVM live execution confirmed static prediction (sessionId: ${dynamicRunResult.session_id})`
            : `Simulated dynamic verification — E2B unavailable, results are not from live execution (sessionId: ${dynamicRunResult.session_id})`,
        }));

        // Add untriggered static findings as unmaterialized/dormant
        for (const uf of staticDynamicComparison.untriggered_static_findings) {
          dynamicFindings.push({
            finding_id: uf.finding_id,
            rule_id: uf.rule_id,
            category: uf.category,
            severity: uf.severity,
            static_prediction: uf.predicted_behavior,
            dynamic_evidence: {
              matched_event_ids: [],
              summary: `Static finding was not triggered during dynamic scenario (${uf.reason_not_triggered})`,
              raw_traces: dynamicRunResult.raw_traces,
            },
            concordance: 'UNREPRODUCED' as const,
            notes: isRealE2B
              ? `Dormant or unexecuted code path during E2B microVM dynamic scenario execution.`
              : `Dormant or unexecuted code path during simulated dynamic scenario execution.`,
          });
        }
      } catch (dynamicErr) {
        console.error("[E2B Dynamic Sandbox Error during analysis trigger]:", dynamicErr);
      }

      // Resolve explicit truth states separating static, dynamic, and overall status
      const truthResolution = resolveAnalysisTruthState({
        staticReport,
        dynamicRunResult,
        isDynamicRequested: true,
        dynamicProvider: 'E2B',
      });

      // Execute Real Decision Orchestration Suite with Dynamic Evidence and Evidence Classes
      const decisionResult = await DecisionOrchestrationEngine.runDecisionSuite({
        analysisRunId,
        entityRefId: agentVersionId,
        scoreModelKey: scoringModelId || 'caim-standard-risk-v2',
        policyKey: policyId || 'pol-enterprise-prod-v2',
        staticFindings: staticReport.findings,
        dynamicFindings: dynamicFindings,
        evidenceList: staticReport.findings.map((f, i) => ({
          evidence_id: `ev-${analysisRunId.slice(0, 8)}-${i + 1}`,
          analysis_run_id: analysisRunId,
          evidence_type: 'STATIC_CODE',
          description: f.description || f.title,
          confidence: f.confidence || 0.95,
          weight: 1.0,
          created_at: new Date().toISOString(),
        })),
        staticStatus: truthResolution.static_status,
        dynamicStatus: truthResolution.dynamic_status,
        overallStatus: truthResolution.overall_status,
        truthState: truthResolution.truth_state,
        why: truthResolution.why,
        evidenceClassesAvailable: truthResolution.evidence_classes_available,
        evidenceClassesMissing: truthResolution.evidence_classes_missing,
        staticOnlyConclusions: truthResolution.static_only_conclusions,
        executionSummary: truthResolution.execution_summary,
      });

      const adapter = dbAdapter || dbClient;
      if (!adapter || typeof adapter.withSecurityContext !== 'function') {
        throw new Error('[SecurityBoundary] Denied: Database adapter with security context is required.');
      }

      await adapter.withSecurityContext(req.principal, async (tx: any) => {
        await tx.query(`
          INSERT INTO analysis.analysis_runs (
            analysis_run_id,
            agent_version_id,
            scope_id,
            pipeline_version,
            caim_version,
            ontology_version,
            trigger_type,
            status,
            static_status,
            dynamic_status,
            overall_status,
            execution_summary,
            started_at,
            completed_at,
            created_at
          ) VALUES (
            $1, $2, $3, '2.0.1', '2.0.1', 'v2.0.1', 'MANUAL', $4, $5, $6, $7, $8, NOW(), NOW(), NOW()
          );
        `, [
          analysisRunId,
          realAgentVersionId,
          tenantScopeId,
          truthResolution.analysis_run_status,
          truthResolution.static_status,
          truthResolution.dynamic_status,
          truthResolution.overall_status,
          JSON.stringify(truthResolution.execution_summary),
        ]);

        // Persist analytical outputs into intel and analysis tables
        await persistAnalysisOutputs({
          analysisRunId,
          agentId: realAgentId,
          agentVersionId: realAgentVersionId,
          staticReport,
          decisionResult,
          tx,
          principal: req.principal,
          truthResolution,
        });
      });

      await dbClient.query(`UPDATE ops.jobs SET status = 'COMPLETED' WHERE job_id = $1;`, [jobId]);
      await dbClient.query(`UPDATE ops.job_attempts SET completed_at = NOW() WHERE job_attempt_id = $1;`, [attemptId]);
      await dbClient.query(`UPDATE ops.workflow_runs SET status = 'COMPLETED', completed_at = NOW() WHERE workflow_run_id = $1;`, [workflowRunId]);

      // Record in Central Append-Only Platform Audit Log
      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'anonymous',
        action: 'ANALYSIS_TRIGGERED',
        target_entity_type: 'AGENT_VERSION',
        target_entity_id: realAgentVersionId,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        correlation_id: correlationId,
        details: {
          agent_id: realAgentId,
          agent_version_id: realAgentVersionId,
          analysis_run_id: analysisRunId,
          workflow_run_id: workflowRunId,
          overall_score: decisionResult.score_result?.overall_score,
          risk_band: decisionResult.score_result?.risk_band,
          policy_outcome: decisionResult.policy_decision?.outcome,
          findings_count: staticReport.findings.length,
          static_status: truthResolution.static_status,
          dynamic_status: truthResolution.dynamic_status,
          overall_status: truthResolution.overall_status,
        },
      });

      const overallScore = decisionResult.score_result ? decisionResult.score_result.overall_score : 'NOT_CALCULATED';
      const riskBand = decisionResult.score_result ? decisionResult.score_result.risk_band : 'NOT_CALCULATED';
      const findingsCount = staticReport.findings ? staticReport.findings.length : 'NOT_CALCULATED';
      const claimsCount = decisionResult.policy_decision?.reasons ? decisionResult.policy_decision.reasons.length : 'NOT_CALCULATED';
      const policyOutcome = decisionResult.policy_decision?.outcome || 'NOT_CALCULATED';
      const runTruthState = truthResolution.truth_state;

      res.json({
        success: true,
        agent_id: realAgentId,
        agent_version_id: realAgentVersionId,
        workflow_run_id: workflowRunId,
        job_id: jobId,
        analysis_run_id: analysisRunId,
        static_status: truthResolution.static_status,
        dynamic_status: truthResolution.dynamic_status,
        overall_status: truthResolution.overall_status,
        status: truthResolution.analysis_run_status,
        truthState: runTruthState,
        truth_state: runTruthState,
        executed: truthResolution.executed,
        not_verified: truthResolution.not_verified,
        why: truthResolution.why,
        static_only_conclusions: truthResolution.static_only_conclusions,
        evidence_classes_available: truthResolution.evidence_classes_available,
        evidence_classes_missing: truthResolution.evidence_classes_missing,
        execution_summary: truthResolution.execution_summary,
        epistemic_metadata: {
          overall_score: { value: overallScore, truthState: runTruthState },
          risk_band: { value: riskBand, truthState: runTruthState },
          findings_count: { value: findingsCount, truthState: 'STATICALLY_DERIVED' },
          claims_count: { value: claimsCount, truthState: runTruthState },
          policy_outcome: { value: policyOutcome, truthState: runTruthState },
        },
        analysis_run: {
          analysis_run_id: analysisRunId,
          pipeline_version: '2.0.1',
          status: truthResolution.analysis_run_status,
          overall_status: truthResolution.overall_status,
          static_status: truthResolution.static_status,
          dynamic_status: truthResolution.dynamic_status,
          findings_count: findingsCount,
          claims_count: claimsCount,
          overall_score: overallScore,
          risk_band: riskBand,
          policy_outcome: policyOutcome,
          truthState: runTruthState,
          truth_state: runTruthState,
          executed: truthResolution.executed,
          not_verified: truthResolution.not_verified,
          why: truthResolution.why,
          static_only_conclusions: truthResolution.static_only_conclusions,
          evidence_classes_available: truthResolution.evidence_classes_available,
          evidence_classes_missing: truthResolution.evidence_classes_missing,
          execution_summary: truthResolution.execution_summary,
          created_at: new Date().toISOString(),
        },
        static_report: staticReport,
        dynamic_run: dynamicRunResult,
        static_dynamic_comparison: staticDynamicComparison,
        decision_suite: decisionResult,
      });

    } catch (err: any) {
      console.error("[Product Analysis Trigger Error]:", err);
      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'anonymous',
        action: 'ANALYSIS_TRIGGERED',
        target_entity_type: 'AGENT_VERSION',
        target_entity_id: req.body?.agentVersionId || 'unknown',
        outcome: 'ERROR',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { error: err.message || String(err) },
      });
      res.status(500).json({ error: err.message || "Failed to trigger analysis run" });
    }
  };


  const handleProductDiscoveryRun = async (req: Request, res: Response) => {
    try {
      const { criteria, sourceTypes, maxPagesPerSource, maxCandidatesTotal, correlationId } = req.body || {};
      const report = await discoveryEngine.runDiscovery({
        criteria: criteria || { query: "agent" },
        sourceTypes,
        maxPagesPerSource: maxPagesPerSource || 1,
        maxCandidatesTotal: maxCandidatesTotal || 20,
        correlationId,
      });

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'anonymous',
        action: 'DISCOVERY_RUN',
        target_entity_type: 'DISCOVERY_PIPELINE',
        target_entity_id: correlationId || `disc-${Date.now()}`,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        correlation_id: correlationId,
        details: {
          query: criteria?.query || 'agent',
          sources_scanned: sourceTypes || ['github', 'huggingface', 'npm', 'pypi', 'openclaw'],
          candidates_discovered: report.totalCandidates || report.packages?.length || 0,
        },
      });

      res.json(report);
    } catch (err: any) {
      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'anonymous',
        action: 'DISCOVERY_RUN',
        target_entity_type: 'DISCOVERY_PIPELINE',
        target_entity_id: req.body?.correlationId || 'disc-failed',
        outcome: 'ERROR',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { error: err.message || String(err) },
      });
      res.status(500).json({ error: err.message || "Discovery execution failed" });
    }
  };


  const autonomousWorker = new AutonomousDiscoveryWorker(
    discoveryEngine,
    sourceRegistry,
    async (candidate: DiscoveryCandidate): Promise<LibraryAgentSummary | null> => {
      try {
        const canonicalName = candidate.display_name || candidate.source_locator;
        const vLabel = (candidate.raw_metadata as any)?.version || 'v1.0.0';
        const locator = candidate.source_locator || `${candidate.source_type}://${canonicalName}`;
        const rawFramework = (candidate.raw_metadata as any)?.framework;
        const framework = rawFramework || 'DATA_UNAVAILABLE';
        const rawAuthor = (candidate.raw_metadata as any)?.author || (candidate.raw_metadata as any)?.owner;
        const author = rawAuthor || 'DATA_UNAVAILABLE';
        const rawDescription = candidate.summary || (candidate.raw_metadata as any)?.description;
        const description = rawDescription || 'DATA_UNAVAILABLE';

        // 1. Check or Insert Canonical Agent in Postgres
        let agentId: string;
        let existingAgentRes = await dbClient.query(`
          SELECT agent_id FROM core.canonical_agents WHERE canonical_name = $1 LIMIT 1;
        `, [canonicalName]);
        if (existingAgentRes.rows.length === 0) {
          const allAgents = await dbClient.query(`SELECT agent_id, canonical_name FROM core.canonical_agents;`);
          const matched = allAgents.rows.find((r: any) => r.canonical_name?.toLowerCase() === canonicalName.toLowerCase());
          if (matched) {
            existingAgentRes = { rows: [matched] };
          }
        }

        if (existingAgentRes.rows.length > 0) {
          agentId = existingAgentRes.rows[0].agent_id;
        } else {
          agentId = generateUuid();
          await dbClient.query(`
            INSERT INTO core.canonical_agents (agent_id, canonical_name, status, identity_confidence, created_at, updated_at)
            VALUES ($1, $2, 'ACTIVE', 0.9800, NOW(), NOW());
          `, [agentId, canonicalName]);
        }

        // 2. Insert Version in core.agent_versions
        const agentVersionId = generateUuid();
        const rawContent = `${canonicalName}:${vLabel}:${candidate.source_type}:${locator}`;
        const contentHash = `sha256:${crypto.createHash('sha256').update(rawContent).digest('hex')}`;
        await dbClient.query(`
          INSERT INTO core.agent_versions (agent_version_id, agent_id, version_label, content_fingerprint, source_commit, created_at)
          VALUES ($1, $2, $3, $4, $5, NOW())
          ON CONFLICT (agent_id, content_fingerprint) DO NOTHING;
        `, [agentVersionId, agentId, vLabel, contentHash, locator]);

        // 3. Verify Authentic Source Acquisition
        const rawFiles: Array<{ path: string; content: string }> | null = (candidate as any).acquired_files || (candidate.raw_metadata as any)?.acquired_files || null;
        const verification = AuthenticSourceAcquisitionService.verifyAndHashArtifact(
          candidate,
          rawFiles,
          { version_identity: vLabel }
        );

        if (!verification.has_authentic_source) {
          // Failure State: Retain discovered candidate truthfully without synthetic analysis
          const summary: LibraryAgentSummary = {
            agent_id: agentId,
            agent_version_id: agentVersionId,
            canonical_name: canonicalName,
            version_label: vLabel,
            source_type: candidate.source_type,
            source_locator: locator,
            author,
            description,
            framework,
            security_classification: 'DATA_UNAVAILABLE',
            discovered_at: new Date().toISOString(),
            analysis_status: 'ANALYSIS_NOT_PERFORMED',
            source_status: 'SOURCE_UNAVAILABLE',
            risk_band: 'NOT_CALCULATED',
            overall_score: 'NOT_CALCULATED',
            policy_outcome: 'NOT_CALCULATED',
            good_use_cases: [
              { title: 'NOT_CALCULATED', rationale: 'SOURCE_UNAVAILABLE: Actual source artifact not acquired. Analysis not performed.', risk_level: 'NOT_CALCULATED', truthState: 'UNKNOWN' }
            ],
            bad_use_cases: [
              { title: 'NOT_CALCULATED', rationale: 'SOURCE_UNAVAILABLE: Actual source artifact not acquired. Analysis not performed.', risk_level: 'NOT_CALCULATED', truthState: 'UNKNOWN' }
            ],
            findings_count: 'NOT_CALCULATED',
            evidence_count: 'NOT_CALCULATED',
            capabilities: [],
            truthState: 'UNKNOWN',
            truth_state: 'UNKNOWN',
            epistemic_metadata: {
              framework: { value: framework, truthState: rawFramework ? 'OBSERVED' : 'UNKNOWN' },
              author: { value: author, truthState: rawAuthor ? 'OBSERVED' : 'UNKNOWN' },
              description: { value: description, truthState: rawDescription ? 'OBSERVED' : 'UNKNOWN' },
              security_classification: { value: 'DATA_UNAVAILABLE', truthState: 'UNKNOWN' },
              overall_score: { value: 'NOT_CALCULATED', truthState: 'UNKNOWN' },
              risk_band: { value: 'NOT_CALCULATED', truthState: 'UNKNOWN' },
              findings_count: { value: 'NOT_CALCULATED', truthState: 'UNKNOWN' },
              evidence_count: { value: 'NOT_CALCULATED', truthState: 'UNKNOWN' },
            }
          };

          await platformAuditService.recordAuditEntry({
            principal_id: 'autonomous-worker',
            action: 'AGENT_DISCOVERED',
            target_entity_type: 'AGENT_VERSION',
            target_entity_id: agentVersionId,
            outcome: 'SUCCESS',
            details: {
              canonical_name: canonicalName,
              source_locator: locator,
              candidate_status: 'DISCOVERED',
              source_status: 'SOURCE_UNAVAILABLE',
              analysis_status: 'ANALYSIS_NOT_PERFORMED',
            },
          });

          return summary;
        }

        // 4. Authentic source acquired: execute analysis pipeline
        const filesToAnalyze = verification.files.map(f => ({ path: f.path, content: f.content as string }));
        const analysisRunId = generateUuid();
        const staticReport = StaticAnalysisEngine.analyze({
          artifactId: `art-${agentId.slice(0, 8)}`,
          files: filesToAnalyze,
          entrypoints: verification.files.map(f => f.path),
          pipelineRunId: analysisRunId,
        });

        // 5. Run Decision Orchestration Engine
        const decisionResult = await DecisionOrchestrationEngine.runDecisionSuite({
          analysisRunId,
          entityRefId: agentVersionId,
          scoreModelKey: 'caim-standard-risk-v2',
          policyKey: 'pol-enterprise-prod-v2',
          staticFindings: staticReport.findings,
          evidenceList: staticReport.findings.map((f, i) => ({
            evidence_id: `ev-${analysisRunId.slice(0, 8)}-${i + 1}`,
            analysis_run_id: analysisRunId,
            evidence_type: 'STATIC_CODE',
            description: f.description || f.title,
            confidence: f.confidence || 0.95,
            weight: 1.0,
            created_at: new Date().toISOString(),
          })),
        });

        // 6. Record Analysis Run in Database
        await dbClient.query(`
          INSERT INTO analysis.analysis_runs (
            analysis_run_id,
            agent_version_id,
            scope_id,
            pipeline_version,
            caim_version,
            ontology_version,
            trigger_type,
            status,
            started_at,
            completed_at,
            created_at
          ) VALUES (
            $1, $2, '00000000-0000-0000-0000-000000000001', '2.0.1', '2.0.1', 'v2.0.1', 'EVENT', 'COMPLETED', NOW(), NOW(), NOW()
          );
        `, [analysisRunId, agentVersionId]);

        // 6b. Persist analytical outputs into Postgres intel and analysis tables
        await persistAnalysisOutputs({
          analysisRunId,
          agentId,
          agentVersionId,
          staticReport,
          decisionResult,
        });

        const positiveUseCases = (decisionResult.use_case_evaluations || [])
          .filter(u => u.category === 'POSITIVE')
          .map(u => ({
            title: u.title,
            rationale: u.justification || 'Derived safe constrained operation.',
            risk_level: 'LOW' as const,
            truthState: 'INFERRED' as const
          }));

        const negativeUseCases = (decisionResult.use_case_evaluations || [])
          .filter(u => u.category === 'NEGATIVE')
          .map(u => ({
            title: u.title,
            rationale: u.justification || 'Derived elevated attack surface.',
            risk_level: 'HIGH' as const,
            truthState: 'INFERRED' as const
          }));

        const overallScore = decisionResult.score_result ? decisionResult.score_result.overall_score : 'NOT_CALCULATED';
        const riskBand = decisionResult.score_result ? (decisionResult.score_result.risk_band as any) : 'NOT_CALCULATED';
        const findingsCount = staticReport.findings ? staticReport.findings.length : 'NOT_CALCULATED';
        const evidenceCount = decisionResult.policy_decision?.reasons ? decisionResult.policy_decision.reasons.length : 'NOT_CALCULATED';

        const policyOutcome = decisionResult.policy_decision?.outcome
          ? ((decisionResult.policy_decision.outcome === 'ALLOW' || decisionResult.policy_decision.outcome === 'ALLOW_WITH_WARNING') 
              ? 'ALLOW' 
              : (decisionResult.policy_decision.outcome === 'REQUIRE_REVIEW' || decisionResult.policy_decision.outcome === 'RESTRICT') 
              ? 'CONDITIONAL' 
              : 'BLOCK')
          : 'NOT_CALCULATED';

        const summaryTruthState = overallScore !== 'NOT_CALCULATED' ? 'INFERRED' : 'UNKNOWN';

        const summary: LibraryAgentSummary = {
          agent_id: agentId,
          agent_version_id: agentVersionId,
          canonical_name: canonicalName,
          version_label: vLabel,
          source_type: candidate.source_type,
          source_locator: locator,
          author,
          description,
          framework,
          security_classification: 'DATA_UNAVAILABLE',
          discovered_at: new Date().toISOString(),
          analysis_status: 'ANALYSIS_COMPLETE',
          source_status: 'ACQUIRED',
          source_provenance: verification.provenance || undefined,
          risk_band: riskBand,
          overall_score: overallScore,
          policy_outcome: policyOutcome,
          good_use_cases: positiveUseCases.length > 0 ? positiveUseCases.slice(0, 3) : [
            { title: 'NOT_CALCULATED', rationale: 'DATA_UNAVAILABLE: No positive use-case evaluations derived from static or dynamic analysis.', risk_level: 'NOT_CALCULATED', truthState: 'UNKNOWN' }
          ],
          bad_use_cases: negativeUseCases.length > 0 ? negativeUseCases.slice(0, 3) : [
            { title: 'NOT_CALCULATED', rationale: 'DATA_UNAVAILABLE: No negative use-case evaluations derived from static or dynamic analysis.', risk_level: 'NOT_CALCULATED', truthState: 'UNKNOWN' }
          ],
          findings_count: findingsCount,
          evidence_count: evidenceCount,
          capabilities: ['Static AST', 'Taint Tracking', 'Policy Evaluation'],
          truthState: summaryTruthState,
          truth_state: summaryTruthState,
          epistemic_metadata: {
            framework: { value: framework, truthState: rawFramework ? 'OBSERVED' : 'UNKNOWN' },
            author: { value: author, truthState: rawAuthor ? 'OBSERVED' : 'UNKNOWN' },
            description: { value: description, truthState: rawDescription ? 'OBSERVED' : 'UNKNOWN' },
            security_classification: { value: 'DATA_UNAVAILABLE', truthState: 'UNKNOWN' },
            overall_score: { value: overallScore, truthState: overallScore !== 'NOT_CALCULATED' ? 'INFERRED' : 'UNKNOWN' },
            risk_band: { value: riskBand, truthState: riskBand !== 'NOT_CALCULATED' ? 'INFERRED' : 'UNKNOWN' },
            findings_count: { value: findingsCount, truthState: findingsCount !== 'NOT_CALCULATED' ? 'STATICALLY_DERIVED' : 'UNKNOWN' },
            evidence_count: { value: evidenceCount, truthState: evidenceCount !== 'NOT_CALCULATED' ? 'INFERRED' : 'UNKNOWN' },
          }
        };

        // Record autonomous agent ingestion in Platform Audit Log
        await platformAuditService.recordAuditEntry({
          principal_id: 'autonomous-worker',
          action: 'AGENT_INGESTED',
          target_entity_type: 'CANONICAL_AGENT',
          target_entity_id: agentId,
          outcome: 'SUCCESS',
          details: {
            canonical_name: canonicalName,
            version_label: vLabel,
            source_type: candidate.source_type,
            source_locator: locator,
            risk_band: summary.risk_band,
            overall_score: summary.overall_score,
            policy_outcome: summary.policy_outcome,
          },
        });

        return summary;
      } catch (err: any) {
        console.error('[AutonomousWorker Ingestion Error]:', err.message);
        return null;
      }
    }
  );

  // In-process setInterval has been removed; discovery cycles are scheduled externally
  // (via GitHub Actions & Cloudflare Trigger) and report in via POST /api/discovery/pipeline/report-cycle
  console.log('[CAIM Discovery] In-process setInterval scheduler disabled. External discovery cycle active.');


  const handleReportDiscoveryCycle = async (req: Request, res: Response) => {
    try {
      const payload = req.body || {};
      const {
        cycle_id = `cycle-${Date.now()}`,
        duration_ms = 0,
        candidates = [],
        edges = [],
        metrics = {},
        source_breakdown = {},
      } = payload;

      let agentsIngested = 0;
      let edgesCreated = 0;

      // 0. Ensure a root seed exists in source.discovery_roots
      let rootSeedId: string | null = null;
      try {
        const rootRes = await dbClient.query(`SELECT id FROM source.discovery_roots LIMIT 1;`);
        if (rootRes.rows.length > 0) {
          rootSeedId = rootRes.rows[0].id;
        } else {
          rootSeedId = generateUuid();
          await dbClient.query(`
            INSERT INTO source.discovery_roots (id, source_adapter, root_type, root_value)
            VALUES ($1, 'system', 'ECOSYSTEM_CATALOG', 'caim://catalog');
          `, [rootSeedId]);
        }
      } catch (rootErr: any) {
        console.warn('[Discovery Cycle Report] Root seed notice:', rootErr.message);
      }

      const candidateIdMap = new Map<string, string>();

      // 1. Ingest Discovered Candidates & Analysis Records
      for (const item of candidates) {
        const candidate = item.candidate || item;
        const analysis = item.analysis;
        const candidateSummary = analysis?.summary || item.summary;

        const canonicalName = candidate.display_name || candidate.source_locator || `agent-${generateUuid().slice(0, 8)}`;
        const vLabel = (candidate.raw_metadata as any)?.version || candidate.version_label || 'v1.0.0';
        const locator = candidate.source_locator || `${candidate.source_type}://${canonicalName}`;
        const rawFramework = (candidate.raw_metadata as any)?.framework || candidate.framework;
        const framework = rawFramework || 'DATA_UNAVAILABLE';
        const rawAuthor = (candidate.raw_metadata as any)?.author || (candidate.raw_metadata as any)?.owner || candidate.author;
        const author = rawAuthor || 'DATA_UNAVAILABLE';
        const rawDescription = candidate.summary || (candidate.raw_metadata as any)?.description || candidate.description;
        const description = rawDescription || 'DATA_UNAVAILABLE';

        const candidateDbId = generateUuid();
        candidateIdMap.set(locator, candidateDbId);
        try {
          await dbClient.query(`
            INSERT INTO source.discovery_candidates (
              id, candidate_id, canonical_url, normalized_url, candidate_type, domain, status, metadata_json
            ) VALUES ($1, $1, $2, $2, 'PACKAGE', $3, 'VERIFIED_AGENT', $4)
            ON CONFLICT (normalized_url) DO UPDATE SET last_seen_at = now();
          `, [
            candidateDbId,
            locator,
            candidate.source_type,
            JSON.stringify({ candidate_id: candidateDbId, canonical_name: canonicalName }),
          ]);
        } catch (candDbErr: any) {
          console.warn('[Discovery Cycle Report] Candidate insertion notice:', candDbErr.message);
        }

        // 1a. Check or Insert Canonical Agent in Postgres
        let agentId: string;
        let existingAgentRes = await dbClient.query(`
          SELECT agent_id FROM core.canonical_agents WHERE canonical_name = $1 LIMIT 1;
        `, [canonicalName]);
        if (existingAgentRes.rows.length === 0) {
          const allAgents = await dbClient.query(`SELECT agent_id, canonical_name FROM core.canonical_agents;`);
          const matched = allAgents.rows.find((r: any) => r.canonical_name?.toLowerCase() === canonicalName.toLowerCase());
          if (matched) {
            existingAgentRes = { rows: [matched] };
          }
        }

        if (existingAgentRes.rows.length > 0) {
          agentId = existingAgentRes.rows[0].agent_id;
        } else {
          agentId = generateUuid();
          await dbClient.query(`
            INSERT INTO core.canonical_agents (agent_id, canonical_name, status, identity_confidence, created_at, updated_at)
            VALUES ($1, $2, 'ACTIVE', 0.9800, NOW(), NOW());
          `, [agentId, canonicalName]);
        }

        // 1b. Insert or retrieve Version in core.agent_versions
        let agentVersionId = generateUuid();
        const rawContent = `${canonicalName}:${vLabel}:${candidate.source_type}:${locator}`;
        const contentHash = `sha256:${crypto.createHash('sha256').update(rawContent).digest('hex')}`;

        const existingVerRes = await dbClient.query(`
          SELECT agent_version_id FROM core.agent_versions
          WHERE agent_id = $1 AND content_fingerprint = $2 LIMIT 1;
        `, [agentId, contentHash]);

        if (existingVerRes.rows.length > 0) {
          agentVersionId = existingVerRes.rows[0].agent_version_id;
        } else {
          await dbClient.query(`
            INSERT INTO core.agent_versions (agent_version_id, agent_id, version_label, content_fingerprint, source_commit, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (agent_id, content_fingerprint) DO NOTHING;
          `, [agentVersionId, agentId, vLabel, contentHash, locator]);
        }

        // 1c. Persist Analysis Output if pre-computed by standalone runner
        if (analysis?.static_report && analysis?.decision_result) {
          const analysisRunId = analysis.analysis_run_id || generateUuid();
          await dbClient.query(`
            INSERT INTO analysis.analysis_runs (
              analysis_run_id,
              agent_version_id,
              scope_id,
              pipeline_version,
              caim_version,
              ontology_version,
              trigger_type,
              status,
              started_at,
              completed_at,
              created_at
            ) VALUES (
              $1, $2, '00000000-0000-0000-0000-000000000001', '2.0.1', '2.0.1', 'v2.0.1', 'EVENT', 'COMPLETED', NOW(), NOW(), NOW()
            );
          `, [analysisRunId, agentVersionId]);

          await persistAnalysisOutputs({
            analysisRunId,
            agentId,
            agentVersionId,
            staticReport: analysis.static_report,
            decisionResult: analysis.decision_result,
          });
        }

        // 1d. Register in Autonomous Worker's browsable library
        if (candidateSummary) {
          autonomousWorker.addPreAnalyzedAgent({
            ...candidateSummary,
            agent_id: agentId,
            agent_version_id: agentVersionId,
          });
        }

        agentsIngested++;
      }

      // 2. Ingest Discovered Graph Edges into source.discovery_edges
      const allEdges = [...edges];
      for (const item of candidates) {
        if (Array.isArray(item.edges)) {
          allEdges.push(...item.edges);
        }
      }

      for (const edge of allEdges) {
        try {
          const edgeId = edge.id || generateUuid();
          const targetCandidateId = (edge.target_candidate_id && candidateIdMap.has(edge.target_candidate_id))
            ? candidateIdMap.get(edge.target_candidate_id)!
            : (candidateIdMap.get(edge.discovered_url) || candidateIdMap.get(edge.normalized_url) || generateUuid());

          // Ensure candidate exists if generated
          try {
            await dbClient.query(`
              INSERT INTO source.discovery_candidates (
                id, candidate_id, canonical_url, normalized_url, candidate_type, domain, status, metadata_json
              ) VALUES ($1, $1, $2, $2, 'PACKAGE', 'discovered', 'DISCOVERED', '{}'::jsonb)
              ON CONFLICT (normalized_url) DO NOTHING;
            `, [targetCandidateId, edge.normalized_url || edge.discovered_url || `caim://${edgeId}`]);
          } catch {
            // ignore if already present
          }

          await dbClient.query(`
            INSERT INTO source.discovery_edges (
              id, root_seed_id, parent_edge_id, source_candidate_id, source_agent_id,
              target_candidate_id, discovered_url, normalized_url, edge_type,
              crawl_depth, extractor, evidence_type, evidence_location,
              decision, metadata_json, queued_at
            ) VALUES (
              $1, $2, $3, $4, $5,
              $6, $7, $8, $9,
              $10, $11, $12, $13,
              $14, $15, now()
            ) ON CONFLICT (id) DO NOTHING;
          `, [
            edgeId,
            edge.root_seed_id || rootSeedId || '00000000-0000-0000-0000-000000000001',
            edge.parent_edge_id || null,
            edge.source_candidate_id || null,
            edge.source_agent_id || null,
            targetCandidateId,
            edge.discovered_url || edge.normalized_url || 'https://unknown.source',
            edge.normalized_url || edge.discovered_url || 'https://unknown.source',
            edge.edge_type || 'ROOT_SOURCE',
            typeof edge.crawl_depth === 'number' ? edge.crawl_depth : 0,
            edge.extractor || 'STANDALONE_DISCOVERY_SCRIPT',
            edge.evidence_type || 'EXTERNAL_CRON_CYCLE',
            edge.evidence_location || 'github_actions',
            edge.decision || 'ACCEPTED',
            JSON.stringify(edge.metadata_json || { cycle_id }),
          ]);
          edgesCreated++;
        } catch (edgeErr: any) {
          console.warn('[Discovery Cycle Report] Edge insertion notice:', edgeErr.message);
        }
      }

      // 3. Update worker status counters
      autonomousWorker.recordExternalCycle({
        candidates_found: candidates.length,
        newly_analyzed: agentsIngested,
        duration_ms,
        error: null,
      });

      // 4. Audit Log
      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'service:service-discovery',
        action: 'DISCOVERY_CYCLE_REPORTED',
        target_entity_type: 'DISCOVERY_PIPELINE',
        target_entity_id: cycle_id,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: {
          cycle_id,
          candidates_reported: candidates.length,
          agents_ingested: agentsIngested,
          discovery_edges_created: edgesCreated,
          duration_ms,
          source_breakdown,
          metrics,
        },
      });

      res.status(200).json({
        success: true,
        cycle_id,
        candidates_processed: candidates.length,
        agents_ingested: agentsIngested,
        discovery_edges_created: edgesCreated,
        duration_ms,
      });
    } catch (err: any) {
      console.error('[Discovery Cycle Report Error]:', err);
      res.status(500).json({
        success: false,
        error: err.message || "Failed to process discovery cycle report",
      });
    }
  };


  // Scheduled background workers
  const reverificationWorker = new ReverificationWorker(dbClient, { intervalMs: 15 * 60 * 1000 });
  const vulnerabilityWorker = new VulnerabilityRecorrelationWorker(dbClient, { intervalMs: 20 * 60 * 1000 });
  const goldenCorpusWorker = new GoldenCorpusRegressionWorker(dbClient, {
    intervalMs: 30 * 60 * 1000,
    evaluationEngine: globalEvaluationEngine,
  });
  const staleAgentWorker = new StaleAgentCleanupWorker(dbClient, { intervalMs: 60 * 60 * 1000 });

  const globalAuditEngine = new AuditLogEngine();
  const globalTracer = new OpenTelemetryTracer();
  const shippingService = new ShippingService();

  const scheduledWorkerMap = new Map<string, IScheduledWorker>([
    ['reverification-worker', reverificationWorker],
    ['vulnerability-recorrelation-worker', vulnerabilityWorker],
    ['golden-corpus-regression-worker', goldenCorpusWorker],
    ['stale-agent-cleanup-worker', staleAgentWorker],
  ]);

  return {
    config,
    dbClient,
    dbAdapter,
    authHelper,
    authService,
    platformAuditService,
    capabilityGrantService,
    rateLimiterEngine,
    csrfProtectionEngine,
    diagnosticService,
    discoveryLineageService,
    discoveryGraphEngine,
    mockFetcher,
    sourceRegistry,
    discoveryEngine,
    braveSearchProvider,
    queryStrategyRegistry,
    freshnessScheduler,
    artifactClassifier,
    identityResolver,
    manualReviewQueue,
    recursiveExpansionEngine,
    autonomousWorker,
    syntheticTargetService,
    knowledgeCorpus,
    hybridRetrieval,
    ragPipeline,
    contextAssembler,
    composerEngine,
    kmsBoundary,
    globalEvaluationEngine,
    reverificationWorker,
    vulnerabilityWorker,
    goldenCorpusWorker,
    staleAgentWorker,
    scheduledWorkerMap,
    globalAuditEngine,
    globalTracer,
    shippingService,
    persistAnalysisOutputs,
    handleProductIngestAgent,
    handleProductListAgents,
    handleDiscoveryLineage,
    handleDiscoveredDescendants,
    handleProductTriggerAnalysis,
    handleProductDiscoveryRun,
    handleReportDiscoveryCycle,
  };
}
