import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { requireDiagnosticAccess, requireProductUserAccess, requireAuthenticatedPrincipal } from "../middleware/security.ts";
import { SecurityClassificationRank } from "@caim/auth";
import {
  QueryUnderstandingEngine,
  RetrievalPlanner,
  HybridFusionReranker,
  DraftClaimExtractor,
  GroundingValidator,
} from "../../../workers/knowledge/index.ts";

export function registerKnowledgeRoutes(app: Express, container: ServiceContainer) {
  const { knowledgeCorpus, hybridRetrieval, ragPipeline, contextAssembler, dbClient, authService, autonomousWorker, platformAuditService } = container;

  app.get("/api/dev/knowledge/stats", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    const staleness = knowledgeCorpus.getStalenessReport();
    const vectorStats = await knowledgeCorpus.getVectorRepo().getStats();
    res.json({
      total_registered_objects: knowledgeCorpus.getRegistry().size(),
      total_projections: knowledgeCorpus.getProjections().size,
      total_chunks: Array.from(knowledgeCorpus.getChunks().values()).reduce((acc: number, c: any) => acc + (c?.length || 0), 0),
      staleness,
      vectorStats,
    });
  });

  app.post("/api/dev/knowledge/rebuild", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const report = await knowledgeCorpus.rebuildEntireCorpus();
      res.json(report);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/dev/retrieval/understand", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { query } = req.body;
    if (!query) {
      return res.status(400).json({ error: "Missing required query string" });
    }
    const understanding = QueryUnderstandingEngine.parseQuery(query);
    const plan = RetrievalPlanner.createPlan(understanding);
    res.json({ understanding, sample_plan: plan });
  });

  app.post("/api/dev/retrieval/execute", requireAuthenticatedPrincipal, async (req: Request, res: Response) => {
    try {
      const { query, scoped_agent_id, scoped_agent_version_id, budget_max_records } = req.body || {};
      if (!query) {
        return res.status(400).json({ error: "Missing required query string" });
      }

      // Authoritative server-side entitlement resolution:
      // Real entitlements are derived strictly from security.principals and verified grant/role tables,
      // NEVER trusted from client input.
      const entitlements = await authService.resolvePrincipalEntitlements(req.principal.principal_id, req.principal);
      const rank = entitlements.max_classification_rank;
      const vaultAccess = entitlements.has_vault_access;

      const result = await hybridRetrieval.retrieveContext(query, {
        caller_user_id: req.principal?.principal_id || 'anonymous-caller',
        caller_security_rank: rank,
        caller_has_vault_access: vaultAccess,
        scoped_agent_id,
        scoped_agent_version_id,
        budget_max_records: budget_max_records ? Number(budget_max_records) : 20,
      });

      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/dev/retrieval/audit-logs", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(hybridRetrieval.getAuditHistory());
  });

  // 22. P24 RAG Synthesis, Grounding & Citations
  app.post("/api/dev/rag/synthesize", requireAuthenticatedPrincipal, async (req: Request, res: Response) => {
    try {
      const { query, scoped_agent_id, scoped_agent_version_id, injected_draft_for_testing } = req.body || {};
      if (!query) {
        return res.status(400).json({ error: "Missing required query string" });
      }

      // Authoritative server-side entitlement resolution:
      // Real entitlements are derived strictly from security.principals and verified grant/role tables,
      // NEVER trusted from client input.
      const entitlements = await authService.resolvePrincipalEntitlements(req.principal.principal_id, req.principal);
      const rank = entitlements.max_classification_rank;
      const vaultAccess = entitlements.has_vault_access;

      const output = await ragPipeline.answerQuery(query, {
        caller_user_id: req.principal?.principal_id || 'anonymous-caller',
        caller_security_rank: rank,
        caller_has_vault_access: vaultAccess,
        scoped_agent_id,
        scoped_agent_version_id,
        injected_draft_for_testing,
      });

      res.json(output);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/dev/rag/context-package", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { query, scoped_agent_id, scoped_agent_version_id } = req.body || {};
      if (!query) {
        return res.status(400).json({ error: "Missing required query string" });
      }

      // Server-side entitlement lookup
      const entitlements = await authService.resolvePrincipalEntitlements(req.principal.principal_id, req.principal);
      const rank = entitlements.max_classification_rank;
      const vault = entitlements.has_vault_access;

      const retrievalResult = await hybridRetrieval.retrieveContext(query, {
        caller_security_rank: rank,
        caller_has_vault_access: vault,
        scoped_agent_id,
        scoped_agent_version_id,
      });

      const pkg = contextAssembler.assembleContextPackage(query, retrievalResult.documents, {
        caller_security_rank: rank,
        caller_has_vault: vault,
        target_agent_id: scoped_agent_id,
        target_version_id: scoped_agent_version_id,
      });

      res.json(pkg);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/dev/rag/grounding-check", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { draft_text, query } = req.body;
      if (!draft_text || !query) {
        return res.status(400).json({ error: "Missing draft_text or query" });
      }

      const retrievalResult = await hybridRetrieval.retrieveContext(query, {
        caller_security_rank: SecurityClassificationRank.INTERNAL,
      });

      const pkg = contextAssembler.assembleContextPackage(query, retrievalResult.documents);
      const claims = DraftClaimExtractor.extractDraftClaims(draft_text);
      const grounding = GroundingValidator.validateGrounding(claims, pkg);

      res.json({
        context_package_hash: pkg.package_hash,
        claims_count: claims.length,
        grounding,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/dev/rag/audit-history", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(ragPipeline.getAuditService().getHistory());
  });



  app.get("/api/library/agents", requireProductUserAccess, async (_req: Request, res: Response) => {
    try {
      const library = autonomousWorker.getLibrary();
      res.json(library);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to fetch library" });
    }
  });

  // Scoped Agent Natural-Language RAG Chat Interface
  app.post("/api/rag/chat", requireProductUserAccess, async (req: Request, res: Response) => {
    try {
      const { query, agentId, agentVersionId } = req.body || {};
      if (!query) {
        return res.status(400).json({ error: "Missing required 'query' parameter" });
      }

      const entitlements = await authService.resolvePrincipalEntitlements(req.principal?.principal_id || 'anonymous', req.principal);
      const rank = entitlements.max_classification_rank;
      const vaultAccess = entitlements.has_vault_access;

      const output = await ragPipeline.answerQuery(query, {
        caller_user_id: req.principal?.principal_id || 'analyst@caim.internal',
        caller_security_rank: rank,
        caller_has_vault_access: vaultAccess,
        scoped_agent_id: agentId,
        scoped_agent_version_id: agentVersionId,
      });

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'anonymous',
        action: 'RAG_SYNTHESIS_REQUESTED',
        target_entity_type: agentId ? 'CANONICAL_AGENT' : 'KNOWLEDGE_CORPUS',
        target_entity_id: agentId || 'global_corpus',
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: {
          query,
          scoped_agent_id: agentId,
          grounding_verdict: output.grounding_verdict,
          epistemic_decision: output.epistemic_decision,
          citations_count: output.resolved_citations?.length || 0,
        },
      });

      res.json({
        query,
        answer: output.answer,
        confidence: output.grounding_verdict === 'FULLY_GROUNDED' ? 0.96 : output.grounding_verdict === 'PARTIALLY_GROUNDED' ? 0.78 : 0.45,
        epistemic_status: output.epistemic_decision,
        citations: output.resolved_citations || [],
        grounding_audit: output.audit,
        scoped_agent_id: agentId,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || "RAG chat synthesis failed" });
    }
  });


}
