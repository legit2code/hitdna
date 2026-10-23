import crypto from "node:crypto";
import { SandboxOrchestrationEngine, StaticDynamicComparator } from "../../../workers/sandbox-orchestrator/index.ts";
import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { requireDiagnosticAccess, requireProductUserAccess } from "../middleware/security.ts";
import { generateUuid } from "@caim/workflow/queue.ts";
import { StaticAnalysisEngine } from "../../../workers/static-analysis/index.ts";
import { DecisionOrchestrationEngine } from "../../../workers/decision/index.ts";
import { AuthenticSourceAcquisitionService } from "@caim/source";
import { resolveAnalysisTruthState } from "@caim/contracts/analysis-states.ts";
import { resolveAuthorizedTenant } from "@caim/auth";

export function registerIngestionRoutes(app: Express, container: ServiceContainer) {
  const {
    dbClient,
    dbAdapter,
    platformAuditService,
    persistAnalysisOutputs,
    handleProductIngestAgent,
    handleProductListAgents,
    handleDiscoveryLineage,
    handleDiscoveredDescendants,
    handleProductTriggerAnalysis,
    globalAuditEngine,
  } = container;

  app.post("/api/dev/ingestion/submit", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
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
        sourceLocator: locator,
        framework: framework || 'Node.js/TypeScript',
        author: author || 'CAIM Contributor',
        description: description || 'Autonomous Agent Analyzed via CAIM Assurance Platform',
        manifestContent: manifestContent || null,
      };
      await dbClient.query(`
        INSERT INTO ops.jobs (job_id, workflow_run_id, queue_key, idempotency_key, priority, status, payload, created_at)
        VALUES ($1, $2, 'analysis.pipeline', $3, 10, 'RUNNING', $4, NOW());
      `, [jobId, workflowRunId, `wf:${workflowRunId}:analysis`, JSON.stringify(jobPayload)]);

      // 6. Create Job Attempt in ops.job_attempts
      const attemptId = generateUuid();
      await dbClient.query(`
        INSERT INTO ops.job_attempts (job_attempt_id, job_id, attempt_no, worker_id, leased_at, lease_expires_at, created_at)
        VALUES ($1, $2, 1, 'worker-analysis-engine-1', NOW(), NOW() + INTERVAL '10 minutes', NOW());
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

      if (!verification.has_authentic_source) {
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
            $1, $2, '00000000-0000-0000-0000-000000000001', '2.0.1', '2.0.1', 'v2.0.1', 'MANUAL', 'ANALYSIS_NOT_PERFORMED', NOW(), NOW(), NOW()
          );
        `, [analysisRunId, agentVersionId]);

        await dbClient.query(`UPDATE ops.jobs SET status = 'COMPLETED' WHERE job_id = $1;`, [jobId]);
        await dbClient.query(`UPDATE ops.job_attempts SET completed_at = NOW() WHERE job_attempt_id = $1;`, [attemptId]);
        await dbClient.query(`UPDATE ops.workflow_runs SET status = 'COMPLETED', completed_at = NOW() WHERE workflow_run_id = $1;`, [workflowRunId]);

        await platformAuditService.recordAuditEntry({
          principal_id: req.principal?.principal_id || 'operator',
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
          framework: framework || 'DATA_UNAVAILABLE',
          author: author || 'DATA_UNAVAILABLE',
          description: description || 'DATA_UNAVAILABLE',
          source_locator: locator,
          security_classification: securityClassification || 'DATA_UNAVAILABLE',
          workflow_run_id: workflowRunId,
          job_id: jobId,
          candidate_status: 'DISCOVERED',
          source_status: 'SOURCE_UNAVAILABLE',
          analysis_status: 'ANALYSIS_NOT_PERFORMED',
          truthState: 'UNKNOWN',
          truth_state: 'UNKNOWN',
          epistemic_metadata: {
            framework: { value: framework || 'DATA_UNAVAILABLE', truthState: framework ? 'USER_DECLARED' : 'UNKNOWN' },
            author: { value: author || 'DATA_UNAVAILABLE', truthState: author ? 'USER_DECLARED' : 'UNKNOWN' },
            description: { value: description || 'DATA_UNAVAILABLE', truthState: description ? 'USER_DECLARED' : 'UNKNOWN' },
            security_classification: { value: securityClassification || 'DATA_UNAVAILABLE', truthState: securityClassification ? 'USER_DECLARED' : 'UNKNOWN' },
            source_locator: { value: locator, truthState: sourceLocator ? 'USER_DECLARED' : 'INFERRED' },
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

      const filesToAnalyze = verification.files.map(f => ({ path: f.path, content: f.content as string }));

      // 8. Execute Real Static Analysis Engine (workers/static-analysis)
      const staticReport = StaticAnalysisEngine.analyze({
        artifactId: `art-${agentId.slice(0, 8)}`,
        files: filesToAnalyze,
        entrypoints: verification.files.map(f => f.path),
        pipelineRunId: analysisRunId,
      });

      // 8b. Execute Real Dynamic Sandbox Verification via E2B Provider
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

        staticDynamicComparison = StaticDynamicComparator.compare(staticReport.findings, dynamicRunResult);

        const isRealE2B = dynamicRunResult?.provider_type === 'E2B';

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
        console.error("[E2B Ingestion Sandbox Error]:", dynamicErr);
      }

      // Resolve explicit truth states separating static, dynamic, and overall status
      const truthResolution = resolveAnalysisTruthState({
        staticReport,
        dynamicRunResult,
        isDynamicRequested: true,
        dynamicProvider: 'E2B',
      });

      // 9. Execute Real Decision Orchestration Suite with Dynamic Evidence
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

      // 10. Record AnalysisRun in analysis.analysis_runs
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
          static_status,
          dynamic_status,
          overall_status,
          execution_summary,
          started_at,
          completed_at,
          created_at
        ) VALUES (
          $1, $2, '00000000-0000-0000-0000-000000000001', '2.0.1', '2.0.1', 'v2.0.1', 'MANUAL', $3, $4, $5, $6, $7, NOW(), NOW(), NOW()
        );
      `, [
        analysisRunId,
        agentVersionId,
        truthResolution.analysis_run_status,
        truthResolution.static_status,
        truthResolution.dynamic_status,
        truthResolution.overall_status,
        JSON.stringify(truthResolution.execution_summary),
      ]);

      if (persistAnalysisOutputs) {
        await persistAnalysisOutputs({
          analysisRunId,
          agentId,
          agentVersionId,
          staticReport,
          decisionResult,
          securityClassification: securityClassification || undefined,
          truthResolution,
        });
      }

      // Record static findings in analysis.static_findings
      for (const finding of staticReport.findings) {
        const findingId = generateUuid();
        const validSeverity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].includes(finding.severity)
          ? finding.severity
          : 'MEDIUM';
        await dbClient.query(`
          INSERT INTO analysis.static_findings (
            finding_id, analysis_run_id, rule_id, finding_type, severity, confidence, message, raw_payload,
            truth_state, source_id, evidence_id, analyzer_version, observed_at, limitations, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), $13, NOW());
        `, [
          findingId,
          analysisRunId,
          finding.rule_id || 'R-STATIC-01',
          finding.title || 'STATIC_FINDING',
          validSeverity,
          finding.confidence || 0.95,
          finding.description || finding.title || 'Code analysis finding',
          JSON.stringify(finding),
          'STATICALLY_DERIVED',
          finding.rule_id || 'static-analyzer',
          null,
          '1.0.0',
          (finding as any).limitations || null,
        ]);
      }

      // 11. Complete Job and Workflow Run in Database
      await dbClient.query(`UPDATE ops.jobs SET status = 'COMPLETED' WHERE job_id = $1;`, [jobId]);
      await dbClient.query(`UPDATE ops.job_attempts SET completed_at = NOW() WHERE job_attempt_id = $1;`, [attemptId]);
      await dbClient.query(`UPDATE ops.workflow_runs SET status = 'COMPLETED', completed_at = NOW() WHERE workflow_run_id = $1;`, [workflowRunId]);

      // 12. Record Audit Event
      globalAuditEngine.recordEvent({
        actorType: 'USER',
        actorId: req.principal?.principal_id || 'system-ingest',
        action: 'CONFIG_UPDATED',
        targetType: 'CANONICAL_AGENT',
        targetId: agentId,
        correlation: { traceId: correlationId, requestId: jobId },
        details: {
          agentName: name,
          version: vLabel,
          overallScore: decisionResult.score_result.overall_score,
          riskBand: decisionResult.score_result.risk_band,
          policyOutcome: decisionResult.policy_decision.outcome
        }
      });

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'operator',
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
          overall_score: decisionResult.score_result.overall_score,
          risk_band: decisionResult.score_result.risk_band,
          policy_outcome: decisionResult.policy_decision.outcome,
        },
      });

      res.json({
        success: true,
        agent_id: agentId,
        agent_version_id: agentVersionId,
        canonical_name: name,
        version_label: vLabel,
        content_hash: contentHash,
        content_fingerprint: contentHash,
        framework: framework || 'Node.js/TypeScript',
        author: author || 'Community Contributor',
        description: description || 'Autonomous Agent Analyzed via CAIM Assurance Platform',
        source_locator: locator,
        security_classification: securityClassification || 'INTERNAL',
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
        analysis_run: {
          analysis_run_id: analysisRunId,
          pipeline_version: '2.0.1',
          status: truthResolution.analysis_run_status,
          overall_status: truthResolution.overall_status,
          static_status: truthResolution.static_status,
          dynamic_status: truthResolution.dynamic_status,
          findings_count: staticReport.findings.length,
          claims_count: decisionResult.policy_decision.reasons?.length || 6,
          overall_score: decisionResult.score_result.overall_score,
          risk_band: decisionResult.score_result.risk_band,
          policy_outcome: decisionResult.policy_decision.outcome,
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
      console.error("[Ingestion Submit Error]:", err);
      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'operator',
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
  });

  // 2. Trigger Analysis Run for existing agent
  app.post("/api/dev/analysis/trigger", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { agentId, agentVersionId, scoringModelId, policyId, sourceFiles } = req.body || {};

      if (!agentId || !agentVersionId) {
        await platformAuditService.recordAuditEntry({
          principal_id: req.principal?.principal_id || 'operator',
          action: 'ANALYSIS_TRIGGERED',
          target_entity_type: 'AGENT_VERSION',
          target_entity_id: agentVersionId || 'unknown',
          outcome: 'REFUSED',
          client_ip: req.ip,
          user_agent: req.headers['user-agent'] as string,
          details: { error: "Missing agentId or agentVersionId parameter" },
        });
        return res.status(400).json({ error: "Missing agentId or agentVersionId parameter" });
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

      // Resolve explicit truth states separating static, dynamic, and overall status
      const truthResolution = resolveAnalysisTruthState({
        staticReport,
        isDynamicRequested: false,
      });

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
          static_status,
          dynamic_status,
          overall_status,
          execution_summary,
          started_at,
          completed_at,
          created_at
        ) VALUES (
          $1, $2, '00000000-0000-0000-0000-000000000001', '2.0.1', '2.0.1', 'v2.0.1', 'MANUAL', $3, $4, $5, $6, $7, NOW(), NOW(), NOW()
        );
      `, [
        analysisRunId,
        agentVersionId,
        truthResolution.analysis_run_status,
        truthResolution.static_status,
        truthResolution.dynamic_status,
        truthResolution.overall_status,
        JSON.stringify(truthResolution.execution_summary),
      ]);

      if (persistAnalysisOutputs) {
        await persistAnalysisOutputs({
          analysisRunId,
          agentId,
          agentVersionId,
          staticReport,
          decisionResult,
          truthResolution,
        });
      }

      await dbClient.query(`UPDATE ops.jobs SET status = 'COMPLETED' WHERE job_id = $1;`, [jobId]);
      await dbClient.query(`UPDATE ops.job_attempts SET completed_at = NOW() WHERE job_attempt_id = $1;`, [attemptId]);
      await dbClient.query(`UPDATE ops.workflow_runs SET status = 'COMPLETED', completed_at = NOW() WHERE workflow_run_id = $1;`, [workflowRunId]);

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'operator',
        action: 'ANALYSIS_TRIGGERED',
        target_entity_type: 'AGENT_VERSION',
        target_entity_id: agentVersionId,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        correlation_id: correlationId,
        details: {
          agent_id: agentId,
          agent_version_id: agentVersionId,
          analysis_run_id: analysisRunId,
          workflow_run_id: workflowRunId,
          overall_score: decisionResult.score_result.overall_score,
          risk_band: decisionResult.score_result.risk_band,
          policy_outcome: decisionResult.policy_decision.outcome,
          findings_count: staticReport.findings.length,
          static_status: truthResolution.static_status,
          dynamic_status: truthResolution.dynamic_status,
          overall_status: truthResolution.overall_status,
        },
      });

      res.json({
        success: true,
        agent_id: agentId,
        agent_version_id: agentVersionId,
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
        analysis_run: {
          analysis_run_id: analysisRunId,
          pipeline_version: '2.0.1',
          status: truthResolution.analysis_run_status,
          overall_status: truthResolution.overall_status,
          static_status: truthResolution.static_status,
          dynamic_status: truthResolution.dynamic_status,
          findings_count: staticReport.findings.length,
          claims_count: decisionResult.policy_decision.reasons?.length || 6,
          overall_score: decisionResult.score_result.overall_score,
          risk_band: decisionResult.score_result.risk_band,
          policy_outcome: decisionResult.policy_decision.outcome,
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
      console.error("[Analysis Trigger Error]:", err);
      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'operator',
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
  });

  // 3. List Ingested Canonical Agents with Versions & Latest Analysis Runs
  app.get("/api/dev/ingestion/agents", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const rows = (await dbClient.query(`
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
          ar.created_at as analysis_created_at
        FROM core.canonical_agents ca
        LEFT JOIN core.agent_versions av ON ca.agent_id = av.agent_id
        LEFT JOIN analysis.analysis_runs ar ON av.agent_version_id = ar.agent_version_id
        ORDER BY ca.created_at DESC, av.created_at DESC;
      `)).rows;

      const agentMap = new Map<string, any>();
      for (const row of rows) {
        if (!agentMap.has(row.agent_id)) {
          agentMap.set(row.agent_id, {
            id: row.agent_id,
            name: row.canonical_name,
            status: row.status,
            identity_confidence: Number(row.identity_confidence),
            created_at: row.created_at,
            versions: [],
          });
        }
        const agent = agentMap.get(row.agent_id);
        if (row.agent_version_id && !agent.versions.some((v: any) => v.id === row.agent_version_id)) {
          agent.versions.push({
            id: row.agent_version_id,
            version: row.version_label || 'v1.0.0',
            fingerprint: row.content_fingerprint,
            sourceLocator: row.source_commit,
            analysisRunId: row.analysis_run_id,
            analysisStatus: row.analysis_status,
          });
        }
      }

      res.json(Array.from(agentMap.values()));
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to list ingested agents" });
    }
  });



  app.post("/api/agents", requireProductUserAccess, handleProductIngestAgent);
  app.post("/api/ingestion/submit", requireProductUserAccess, handleProductIngestAgent);



  app.get("/api/agents", requireProductUserAccess, handleProductListAgents);
  app.get("/api/ingestion/agents", requireProductUserAccess, handleProductListAgents);

  // 3. Register New Agent Version
  app.post("/api/agents/:agentId/versions", requireProductUserAccess, async (req: Request, res: Response) => {
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

      const { agentId } = req.params;
      const { versionLabel, sourceLocator, securityClassification, manifestContent } = req.body || {};
      const vLabel = versionLabel || `v1.${Date.now().toString().slice(-2)}.0`;
      const agentVersionId = generateUuid();
      const locator = sourceLocator || 'DATA_UNAVAILABLE';
      const contentPayload = manifestContent || `${agentId}:${vLabel}:${locator}`;
      const contentHash = `sha256:${crypto.createHash('sha256').update(contentPayload).digest('hex')}`;

      const adapter = dbAdapter || dbClient;
      if (!adapter || typeof adapter.withSecurityContext !== 'function') {
        throw new Error('[SecurityBoundary] Denied: Database adapter with security context is required.');
      }

      await adapter.withSecurityContext(req.principal, async (tx: any) => {
        await tx.query(`
          INSERT INTO core.agent_versions (agent_version_id, agent_id, version_label, content_fingerprint, source_commit, created_at)
          VALUES ($1, $2, $3, $4, $5, NOW());
        `, [agentVersionId, agentId, vLabel, contentHash, locator]);
      });

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'product-user',
        action: 'AGENT_INGESTED',
        target_entity_type: 'AGENT_VERSION',
        target_entity_id: agentVersionId,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: {
          agent_id: agentId,
          version_label: vLabel,
          content_hash: contentHash,
          source_locator: locator,
        },
      });

      const classification = securityClassification || 'DATA_UNAVAILABLE';
      const truthState = (sourceLocator && securityClassification) ? 'USER_DECLARED' : 'UNKNOWN';

      res.json({
        success: true,
        agent_version_id: agentVersionId,
        agent_id: agentId,
        version_label: vLabel,
        content_hash: contentHash,
        content_fingerprint: contentHash,
        source_locator: locator,
        security_classification: classification,
        status: 'ACTIVE',
        truthState,
        truth_state: truthState,
        epistemic_metadata: {
          source_locator: { value: locator, truthState: sourceLocator ? 'USER_DECLARED' : 'UNKNOWN' },
          security_classification: { value: classification, truthState: securityClassification ? 'USER_DECLARED' : 'UNKNOWN' },
        },
        created_at: new Date().toISOString(),
      });
    } catch (err: any) {
      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'product-user',
        action: 'AGENT_INGESTED',
        target_entity_type: 'AGENT_VERSION',
        target_entity_id: req.params.agentId || 'unknown',
        outcome: 'ERROR',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { error: err.message || String(err) },
      });
      res.status(500).json({ error: err.message || "Failed to register agent version" });
    }
  });


  app.get("/agents/:agentId/discovery-lineage", handleDiscoveryLineage);
  app.get("/api/agents/:agentId/discovery-lineage", handleDiscoveryLineage);
  app.get("/agents/:agentId/discovered-descendants", handleDiscoveredDescendants);
  app.get("/api/agents/:agentId/discovered-descendants", handleDiscoveredDescendants);



  app.post("/api/analysis/trigger", requireProductUserAccess, handleProductTriggerAnalysis);
  app.post("/api/analysis/runs", requireProductUserAccess, handleProductTriggerAnalysis);


}
