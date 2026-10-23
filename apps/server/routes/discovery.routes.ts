import { Express, Request, Response, NextFunction } from "express";
import { ServiceContainer } from "../services/container.ts";
import {
  requireDiagnosticAccess,
  requireProductUserAccess,
  requireDiscoveryServiceAuth,
  requireWorkerManagementAccess,
} from "../middleware/security.ts";
import { PlatformTelemetryEngine } from "@caim/workflow/observability.ts";

export function registerDiscoveryRoutes(app: Express, container: ServiceContainer) {
  const {
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
    platformAuditService,
    discoveryLineageService,
    handleProductDiscoveryRun,
    handleReportDiscoveryCycle,
  } = container;

  app.get("/api/dev/sources", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const adapters = sourceRegistry.getAll();
      const healthMap = await discoveryEngine.checkAllHealth();
      const searchHealth = await braveSearchProvider.health_check();

      const overview = adapters.map(a => ({
        sourceType: a.sourceType,
        sourceName: a.sourceName,
        adapterVersion: a.adapterVersion,
        policy: a.get_source_policy(),
        rateLimit: a.get_rate_limit_state(),
        health: healthMap[a.sourceType] || null,
      }));

      // Include Brave Search in diagnostics
      overview.push({
        sourceType: 'brave_search',
        sourceName: 'Brave Search API',
        adapterVersion: braveSearchProvider.providerVersion,
        policy: {
          source_type: 'brave_search',
          source_name: 'Brave Search API',
          auth_mode: process.env.BRAVE_API_KEY ? 'AUTHENTICATED' : 'DEGRADED',
          max_page_size: 20,
          rate_limit_per_minute: 60,
          retry_policy: { max_retries: 3, backoff_factor: 2, initial_delay_ms: 500 },
          supported_query_families: ['AGENT_DISCOVERY', 'TOOL_ECOSYSTEM', 'MODEL_WEIGHTS', 'CODE_REPOSITORY'],
          capabilities: {
            can_stream: false,
            can_search: true,
            provides_dependencies: false,
            provides_artifacts: false,
            requires_auth: true,
          },
        },
        rateLimit: braveSearchProvider.get_rate_limit_state(),
        health: searchHealth,
      });

      res.json(overview);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to list source adapters" });
    }
  });

  // 6. Run Source-Independent Discovery
  app.post("/api/dev/discovery/run", requireDiagnosticAccess, async (req: Request, res: Response) => {
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
        principal_id: req.principal?.principal_id || 'operator',
        action: 'DISCOVERY_PIPELINE_TRIGGERED',
        target_entity_type: 'DISCOVERY_SOURCES',
        target_entity_id: 'dev_discovery_run',
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        correlation_id: correlationId,
        details: {
          candidates_discovered: report.totalCandidates || (report.packages?.length || 0),
          status: report.status,
        },
      });
      res.json(report);
    } catch (err: any) {
      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'operator',
        action: 'DISCOVERY_PIPELINE_TRIGGERED',
        target_entity_type: 'DISCOVERY_SOURCES',
        target_entity_id: 'dev_discovery_run',
        outcome: 'ERROR',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { error: err.message || String(err) },
      });
      res.status(500).json({ error: err.message || "Discovery execution failed" });
    }
  });

  // 7. Polymorphic Locator Inspection
  app.post("/api/dev/discovery/inspect", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { locator } = req.body || {};
      if (!locator || typeof locator !== "string") {
        return res.status(400).json({ error: "Missing 'locator' string parameter" });
      }
      const adapter = sourceRegistry.resolveForLocator(locator);
      const [metadata, artifacts, relationships, changeToken] = await Promise.all([
        adapter.fetch_metadata(locator),
        adapter.resolve_artifact_locators(locator),
        adapter.enumerate_relationships(locator),
        adapter.get_change_token(locator),
      ]);
      res.json({
        sourceType: adapter.sourceType,
        locator,
        metadata,
        artifacts,
        relationships,
        changeToken,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Locator inspection failed" });
    }
  });

  // 8. Query Strategy Rules List & Toggle
  app.get("/api/dev/discovery/rules", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(queryStrategyRegistry.getAllRules());
  });

  app.post("/api/dev/discovery/rules/generate", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { seed, family, targetSource } = req.body || {};
    if (!seed || typeof seed !== "string") {
      return res.status(400).json({ error: "Missing 'seed' string" });
    }
    const queries = queryStrategyRegistry.generateQueries(seed, { family, targetSource });
    res.json(queries);
  });

  app.post("/api/dev/discovery/rules/toggle", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { ruleId, enabled } = req.body || {};
    if (!ruleId || typeof enabled !== "boolean") {
      return res.status(400).json({ error: "Missing ruleId or enabled boolean" });
    }
    const success = queryStrategyRegistry.setRuleEnabled(ruleId, enabled);
    res.json({ success, ruleId, enabled });
  });

  // 9. Web Search via Brave Provider
  app.post("/api/dev/discovery/search", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { query, count, freshness } = req.body || {};
      if (!query || typeof query !== "string") {
        return res.status(400).json({ error: "Missing 'query' string parameter" });
      }
      const searchResult = await braveSearchProvider.search(query, {
        count: count || 10,
        freshness,
      });
      res.json(searchResult);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Web search execution failed" });
    }
  });

  // 10. Freshness & Coverage Metrics
  app.get("/api/dev/discovery/freshness/metrics", requireDiagnosticAccess, (req: Request, res: Response) => {
    const window = (req.query.window as any) || "24h";
    const metrics = freshnessScheduler.computeMetrics(window);
    res.json(metrics);
  });

  app.post("/api/dev/discovery/freshness/record", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { source_locator, source_type, strategy_id, change_token, token_type } = req.body || {};
    if (!source_locator || !source_type) {
      return res.status(400).json({ error: "Missing source_locator or source_type" });
    }
    const evalResult = freshnessScheduler.recordObservation({
      source_locator,
      source_type,
      strategy_id,
      change_token,
      token_type,
    });
    res.json(evalResult);
  });

  // 11. Recursive Relationship Expansion
  app.post("/api/dev/discovery/expand", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { rootLocators, maxDepth, maxCandidatesTotal, maxCallsPerSource, maxTimeMs } = req.body || {};
      if (!Array.isArray(rootLocators) || rootLocators.length === 0) {
        return res.status(400).json({ error: "Missing 'rootLocators' array parameter" });
      }
      const report = await recursiveExpansionEngine.expand(rootLocators, {
        max_depth: maxDepth,
        max_total_candidates: maxCandidatesTotal,
        max_calls_per_source: maxCallsPerSource,
        max_time_ms: maxTimeMs,
      });
      res.json(report);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Recursive expansion failed" });
    }
  });

  // 12. Artifact Classification Taxonomy
  app.post("/api/dev/discovery/classify", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { candidate, locator } = req.body || {};
      let cand = candidate;
      let metadata;
      let artifacts;

      if (locator && typeof locator === "string") {
        const adapter = sourceRegistry.resolveForLocator(locator);
        const [metaRes, artRes] = await Promise.all([
          adapter.fetch_metadata(locator),
          adapter.resolve_artifact_locators(locator),
        ]);
        metadata = metaRes;
        artifacts = artRes;
        cand = {
          source_locator: locator,
          display_name: locator,
          source_type: adapter.sourceType,
          raw_metadata: metaRes.raw_metadata,
        };
      }

      if (!cand || !cand.source_locator) {
        return res.status(400).json({ error: "Missing candidate object or locator string" });
      }

      const classification = artifactClassifier.classify({
        candidate: cand,
        metadata,
        artifacts,
      });
      res.json(classification);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Classification failed" });
    }
  });

  // 13. Identity Resolution & Canonical Candidate Graph
  app.post("/api/dev/discovery/resolve-identity", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { observationA, observationB, observations } = req.body || {};

      if (observations && Array.isArray(observations)) {
        const graph = identityResolver.buildCandidateGraph(observations);
        return res.json(graph);
      }

      if (!observationA || !observationB) {
        return res.status(400).json({ error: "Must provide either (observationA and observationB) or observations array" });
      }

      const comparison = identityResolver.compare(observationA, observationB);
      res.json(comparison);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Identity resolution failed" });
    }
  });

  // 14. Manual Review Queue
  app.get("/api/dev/discovery/review-queue", requireDiagnosticAccess, (req: Request, res: Response) => {
    const status = req.query.status as any;
    const items = manualReviewQueue.listItems(status);
    res.json(items);
  });

  app.post("/api/dev/discovery/review-queue/resolve", requireDiagnosticAccess, (req: Request, res: Response) => {
    try {
      const { id, status, resolved_outcome, resolved_canonical_id, review_note } = req.body || {};
      if (!id || !status) {
        return res.status(400).json({ error: "Missing 'id' or 'status'" });
      }
      const reviewed_by = req.principal?.principal_id || "operator";
      const result = manualReviewQueue.resolveConflict(id, {
        status,
        resolved_outcome,
        resolved_canonical_id,
        reviewed_by,
        review_note,
      });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to resolve manual review item" });
    }
  });


  app.get("/api/observability/discovery-metrics", async (_req: Request, res: Response) => {
    try {
      const discMetrics = await discoveryLineageService.getDiscoveryMetrics();
      PlatformTelemetryEngine.setDiscoveryMetrics(discMetrics);
      res.json(discMetrics);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to retrieve discovery metrics" });
    }
  });


  app.get("/api/discovery/pipeline/status", requireProductUserAccess, (_req: Request, res: Response) => {
    res.json(autonomousWorker.getStatus());
  });



  app.post("/api/discovery/pipeline/report-cycle", requireDiscoveryServiceAuth, handleReportDiscoveryCycle);
  app.post("/api/discovery/cycle-report", requireDiscoveryServiceAuth, handleReportDiscoveryCycle);



  app.post("/api/discovery/pipeline/trigger", requireWorkerManagementAccess, async (req: Request, res: Response) => {
    try {
      const { queries } = req.body || {};
      const result = await autonomousWorker.runDiscoveryCycle(queries);

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'anonymous',
        action: 'DISCOVERY_TRIGGERED',
        target_entity_type: 'DISCOVERY_PIPELINE',
        target_entity_id: `cycle-${Date.now()}`,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: {
          queries: queries || ['agent', 'llm-tool'],
          candidates_discovered: result.candidates_found,
          agents_ingested: result.newly_analyzed,
        },
      });

      res.json({ success: true, ...result });
    } catch (err: any) {
      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'anonymous',
        action: 'DISCOVERY_TRIGGERED',
        target_entity_type: 'DISCOVERY_PIPELINE',
        target_entity_id: 'trigger-failed',
        outcome: 'ERROR',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { error: err.message || String(err) },
      });
      res.status(500).json({ error: err.message || "Failed to trigger discovery cycle" });
    }
  });



  app.post("/api/discovery/run", requireProductUserAccess, handleProductDiscoveryRun);
  app.get("/api/discovery/sources", requireProductUserAccess, async (_req: Request, res: Response) => {
    try {
      const adapters = sourceRegistry.getAll();
      const healthMap = await discoveryEngine.checkAllHealth();
      const overview = adapters.map(a => ({
        sourceType: a.sourceType,
        sourceName: a.sourceName,
        adapterVersion: a.adapterVersion,
        rateLimit: a.get_rate_limit_state(),
        health: healthMap[a.sourceType] || null,
      }));
      res.json(overview);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to get sources" });
    }
  });

  // 6. Evidence Query & Epistemic Graph (Product Scoped)

}
