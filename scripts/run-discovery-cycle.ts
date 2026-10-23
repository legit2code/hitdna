/**
 * Standalone Autonomous Discovery Cycle Runner
 * 
 * Part of CAIM Discovery Scheduling Refactor:
 * Runs ONE discovery cycle to completion in an isolated, disposable execution environment
 * (e.g. GitHub Actions, local runner, or test suite) and reports the results to the
 * CAIM server's authenticated reporting endpoint using a scoped service token.
 * 
 * INVARIANT: This script NEVER holds or uses direct production database credentials.
 * It interacts with the platform strictly via the authenticated HTTP reporting endpoint.
 */

import crypto from 'crypto';
import {
  SourceAdapterRegistry,
  DiscoveryEngine,
  DiscoveryCandidate,
  LibraryAgentSummary,
  AuthenticSourceAcquisitionService,
} from '@caim/source';
import { StaticAnalysisEngine } from '../workers/static-analysis/index.ts';
import { DecisionOrchestrationEngine } from '../workers/decision/index.ts';

export interface DiscoveryCycleOptions {
  apiUrl?: string;
  serviceToken?: string;
  queries?: string[];
  maxCandidatesTotal?: number;
  maxPagesPerSource?: number;
}

export interface CandidateAnalysisPackage {
  candidate: DiscoveryCandidate;
  analysis: {
    analysis_run_id: string;
    static_report: any;
    decision_result: any;
    summary: LibraryAgentSummary;
  };
  edges: Array<{
    id: string;
    root_seed_id: string;
    discovered_url: string;
    normalized_url: string;
    edge_type: string;
    crawl_depth: number;
    extractor: string;
    evidence_type: string;
    evidence_location: string;
    decision: string;
    metadata_json: Record<string, any>;
  }>;
}

export interface DiscoveryCycleReportPayload {
  cycle_id: string;
  duration_ms: number;
  source_breakdown: Record<string, any>;
  candidates: CandidateAnalysisPackage[];
  edges: Array<{
    id: string;
    root_seed_id: string;
    discovered_url: string;
    normalized_url: string;
    edge_type: string;
    crawl_depth: number;
    extractor: string;
    evidence_type: string;
    evidence_location: string;
    decision: string;
    metadata_json: Record<string, any>;
  }>;
  metrics: {
    total_discovered: number;
    total_analyzed: number;
    sources_count: number;
  };
}

export async function runStandaloneDiscoveryCycle(options: DiscoveryCycleOptions = {}) {
  const startTime = Date.now();
  const cycleId = `cycle-sched-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;

  const apiUrl = (options.apiUrl || process.env.CAIM_API_URL || 'http://localhost:3000').replace(/\/$/, '');
  const serviceToken = options.serviceToken ||
    process.env.CAIM_DISCOVERY_SERVICE_TOKEN ||
    process.env.SERVICE_TO_SERVICE_SECRET;

  if (!serviceToken) {
    throw new Error(
      'FATAL CONFIGURATION ERROR: Scoped service credential for discovery runner is missing. ' +
      'Set CAIM_DISCOVERY_SERVICE_TOKEN or SERVICE_TO_SERVICE_SECRET in the environment. ' +
      'Hardcoded fallback credentials have been permanently eliminated.'
    );
  }

  console.log(`[Discovery Runner] Initializing cycle ${cycleId}...`);
  console.log(`[Discovery Runner] Target API: ${apiUrl}`);
  console.log(`[Discovery Runner] Authenticating with scoped service identity (service-discovery)`);

  // 1. Initialize source adapter registry and discovery engine
  const registry = SourceAdapterRegistry.createDefault();
  const discoveryEngine = new DiscoveryEngine(registry);
  const registeredSources = registry.getAll().map(a => a.sourceType);

  console.log(`[Discovery Runner] Registered source adapters: [${registeredSources.join(', ')}]`);

  // 2. Determine search queries
  const queries = options.queries && options.queries.length > 0
    ? options.queries
    : ['agent', 'autonomous agent', 'llm tool', 'langchain agent', 'mcp server'];

  const selectedQuery = queries[Math.floor(Math.random() * queries.length)] || 'agent';
  console.log(`[Discovery Runner] Polling sources with query: "${selectedQuery}"...`);

  // 3. Run multi-source discovery
  const report = await discoveryEngine.runDiscovery({
    criteria: {
      query: selectedQuery,
      tags: ['autonomous', 'agent', 'llm', 'workflow'],
    },
    sourceTypes: registeredSources,
    maxPagesPerSource: options.maxPagesPerSource || 1,
    maxCandidatesTotal: options.maxCandidatesTotal || 15,
    correlationId: cycleId,
  });

  const discoveredPackages = report.packages || [];
  console.log(`[Discovery Runner] Discovery complete. Found ${discoveredPackages.length} candidate(s).`);

  // 4. Candidate Registration, Static Analysis, Decision Scoring, and Use-Case Evaluation
  const candidatePackages: CandidateAnalysisPackage[] = [];
  const cycleEdges: DiscoveryCycleReportPayload['edges'] = [];

  for (const pkg of discoveredPackages) {
    const candidate = pkg.candidate;
    const canonicalName = candidate.display_name || candidate.source_locator;
    const vLabel = (candidate.raw_metadata as any)?.version || 'v1.0.0';
    const locator = candidate.source_locator || `${candidate.source_type}://${canonicalName}`;
    const rawFramework = (candidate.raw_metadata as any)?.framework;
    const framework = rawFramework || 'DATA_UNAVAILABLE';
    const rawAuthor = (candidate.raw_metadata as any)?.author || (candidate.raw_metadata as any)?.owner;
    const author = rawAuthor || 'DATA_UNAVAILABLE';
    const rawDescription = candidate.summary || (candidate.raw_metadata as any)?.description;
    const description = rawDescription || 'DATA_UNAVAILABLE';

    const tempAgentId = crypto.randomUUID();
    const tempVersionId = crypto.randomUUID();
    const analysisRunId = crypto.randomUUID();

    // 4. Authentic Source Acquisition & Verification Invariant:
    // A discovered candidate may ONLY receive static analysis conclusions when
    // a REAL artifact belonging to that candidate has actually been acquired.
    // Manufacturing synthetic source files (e.g. src/agent.ts, manifest.json) is strictly prohibited.
    const rawAcquiredFiles: Array<{ path: string; content: string }> = (candidate as any).acquired_files || (candidate.raw_metadata as any)?.acquired_files || [];
    const verification = AuthenticSourceAcquisitionService.verifyAndHashArtifact(
      candidate,
      rawAcquiredFiles,
      { version_identity: vLabel }
    );
    const hasRealArtifact = verification.has_authentic_source;

    let staticReport: any = null;
    let decisionResult: any = null;
    let positiveUseCases: any[] = [];
    let negativeUseCases: any[] = [];
    let overallScore: number | 'NOT_CALCULATED' = 'NOT_CALCULATED';
    let riskBand: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' | 'NOT_CALCULATED' = 'NOT_CALCULATED';
    let findingsCount: number | 'NOT_CALCULATED' = 'NOT_CALCULATED';
    let evidenceCount: number | 'NOT_CALCULATED' = 'NOT_CALCULATED';
    let policyOutcome: 'ALLOW' | 'CONDITIONAL' | 'BLOCK' | 'NOT_CALCULATED' = 'NOT_CALCULATED';
    let analysisStatus: 'PRE_ANALYZED' | 'ANALYSIS_COMPLETE' | 'PENDING' | 'FAILED' | 'ANALYSIS_NOT_PERFORMED' = 'ANALYSIS_NOT_PERFORMED';
    let sourceStatus: 'DISCOVERED' | 'SOURCE_UNAVAILABLE' | 'ACQUIRED' | 'VERIFIED' = 'SOURCE_UNAVAILABLE';

    if (hasRealArtifact && verification.provenance) {
      sourceStatus = 'ACQUIRED';
      // Execute Static Analysis Engine only on authentic acquired files
      staticReport = StaticAnalysisEngine.analyze({
        artifactId: `art-${tempAgentId.slice(0, 8)}`,
        files: verification.files.map(f => ({ path: f.path, content: f.content as string })),
        entrypoints: verification.files.map((f) => f.path),
        pipelineRunId: analysisRunId,
      });

      // Execute Decision Orchestration Engine on authentic findings
      decisionResult = await DecisionOrchestrationEngine.runDecisionSuite({
        analysisRunId,
        entityRefId: tempVersionId,
        scoreModelKey: 'caim-standard-risk-v2',
        policyKey: 'pol-enterprise-prod-v2',
        staticFindings: staticReport.findings,
        evidenceList: staticReport.findings.map((f: any, i: number) => ({
          evidence_id: `ev-${analysisRunId.slice(0, 8)}-${i + 1}`,
          analysis_run_id: analysisRunId,
          evidence_type: 'STATIC_CODE',
          description: f.description || f.title,
          confidence: f.confidence || 0.95,
          weight: 1.0,
          created_at: new Date().toISOString(),
        })),
      });

      positiveUseCases = (decisionResult.use_case_evaluations || [])
        .filter((u: any) => u.category === 'POSITIVE')
        .map((u: any) => ({
          title: u.title,
          rationale: u.justification || 'Derived safe constrained operation.',
          risk_level: 'LOW' as const,
          truthState: 'INFERRED' as const,
        }));

      negativeUseCases = (decisionResult.use_case_evaluations || [])
        .filter((u: any) => u.category === 'NEGATIVE')
        .map((u: any) => ({
          title: u.title,
          rationale: u.justification || 'Derived elevated attack surface.',
          risk_level: 'HIGH' as const,
          truthState: 'INFERRED' as const,
        }));

      overallScore = decisionResult.score_result ? decisionResult.score_result.overall_score : 'NOT_CALCULATED';
      riskBand = decisionResult.score_result ? (decisionResult.score_result.risk_band as any) : 'NOT_CALCULATED';
      findingsCount = staticReport.findings ? staticReport.findings.length : 'NOT_CALCULATED';
      evidenceCount = decisionResult.policy_decision?.reasons ? decisionResult.policy_decision.reasons.length : 'NOT_CALCULATED';

      policyOutcome = decisionResult.policy_decision?.outcome
        ? ((decisionResult.policy_decision.outcome === 'ALLOW' || decisionResult.policy_decision.outcome === 'ALLOW_WITH_WARNING')
            ? 'ALLOW'
            : (decisionResult.policy_decision.outcome === 'REQUIRE_REVIEW' || decisionResult.policy_decision.outcome === 'RESTRICT')
            ? 'CONDITIONAL'
            : 'BLOCK')
        : 'NOT_CALCULATED';

      analysisStatus = 'ANALYSIS_COMPLETE';
    }

    const summaryTruthState = hasRealArtifact && overallScore !== 'NOT_CALCULATED' ? 'INFERRED' : 'UNKNOWN';

    const summary: LibraryAgentSummary = {
      agent_id: tempAgentId,
      agent_version_id: tempVersionId,
      canonical_name: canonicalName,
      version_label: vLabel,
      source_type: candidate.source_type,
      source_locator: locator,
      author,
      description,
      framework,
      security_classification: 'DATA_UNAVAILABLE',
      discovered_at: new Date().toISOString(),
      analysis_status: analysisStatus,
      source_status: sourceStatus,
      source_provenance: verification.provenance || undefined,
      risk_band: riskBand,
      overall_score: overallScore,
      policy_outcome: policyOutcome,
      good_use_cases: positiveUseCases.length > 0 ? positiveUseCases.slice(0, 3) : [
        { title: 'NOT_CALCULATED', rationale: 'SOURCE_UNAVAILABLE: Actual source artifact not acquired. Analysis not performed.', risk_level: 'NOT_CALCULATED', truthState: 'UNKNOWN' },
      ],
      bad_use_cases: negativeUseCases.length > 0 ? negativeUseCases.slice(0, 3) : [
        { title: 'NOT_CALCULATED', rationale: 'SOURCE_UNAVAILABLE: Actual source artifact not acquired. Analysis not performed.', risk_level: 'NOT_CALCULATED', truthState: 'UNKNOWN' },
      ],
      findings_count: findingsCount,
      evidence_count: evidenceCount,
      capabilities: Array.isArray((candidate.raw_metadata as any)?.capabilities)
        ? (candidate.raw_metadata as any).capabilities
        : [],
      truthState: summaryTruthState,
      truth_state: summaryTruthState,
      epistemic_metadata: {
        framework: { value: framework, truthState: rawFramework ? 'OBSERVED' : 'UNKNOWN' },
        author: { value: author, truthState: rawAuthor ? 'OBSERVED' : 'UNKNOWN' },
        description: { value: description, truthState: rawDescription ? 'OBSERVED' : 'UNKNOWN' },
        security_classification: { value: 'DATA_UNAVAILABLE', truthState: 'UNKNOWN' },
        overall_score: { value: overallScore, truthState: hasRealArtifact && overallScore !== 'NOT_CALCULATED' ? 'INFERRED' : 'UNKNOWN' },
        risk_band: { value: riskBand, truthState: hasRealArtifact && riskBand !== 'NOT_CALCULATED' ? 'INFERRED' : 'UNKNOWN' },
        findings_count: { value: findingsCount, truthState: hasRealArtifact && findingsCount !== 'NOT_CALCULATED' ? 'STATICALLY_DERIVED' : 'UNKNOWN' },
        evidence_count: { value: evidenceCount, truthState: hasRealArtifact && evidenceCount !== 'NOT_CALCULATED' ? 'INFERRED' : 'UNKNOWN' },
      },
    };

    // 4e. Build Discovery Edge representation
    const candidateEdge = {
      id: crypto.randomUUID(),
      root_seed_id: '00000000-0000-0000-0000-000000000001',
      discovered_url: locator,
      normalized_url: locator,
      edge_type: 'ROOT_SOURCE',
      crawl_depth: 0,
      extractor: `STANDALONE_DISCOVERY_${candidate.source_type.toUpperCase()}`,
      evidence_type: 'STANDALONE_RUNNER',
      evidence_location: `${candidate.source_type}://query=${encodeURIComponent(selectedQuery)}`,
      decision: policyOutcome === 'BLOCK' ? 'REJECTED' : 'ACCEPTED',
      metadata_json: {
        cycle_id: cycleId,
        source_type: candidate.source_type,
        overall_score: overallScore,
        risk_band: riskBand,
        policy_outcome: policyOutcome,
      },
    };

    candidatePackages.push({
      candidate,
      analysis: hasRealArtifact ? {
        analysis_run_id: analysisRunId,
        static_report: staticReport,
        decision_result: decisionResult,
        summary,
      } : undefined,
      edges: [candidateEdge],
    });

    cycleEdges.push(candidateEdge);
  }

  const durationMs = Date.now() - startTime;

  // 5. Assemble the payload for the reporting endpoint
  const payload: DiscoveryCycleReportPayload = {
    cycle_id: cycleId,
    duration_ms: durationMs,
    source_breakdown: report.sourceBreakdown || {},
    candidates: candidatePackages,
    edges: cycleEdges,
    metrics: {
      total_discovered: discoveredPackages.length,
      total_analyzed: candidatePackages.filter(p => p.analysis !== undefined).length,
      sources_count: registeredSources.length,
    },
  };

  console.log(`[Discovery Runner] Reporting ${candidatePackages.length} analyzed candidate(s) and ${cycleEdges.length} edge(s) to ${apiUrl}...`);

  // 6. Require authenticated service credential and report to endpoint
  if (!serviceToken) {
    throw new Error(
      'FATAL CONFIGURATION ERROR: Scoped service credential for discovery runner is missing. ' +
      'Set CAIM_DISCOVERY_SERVICE_TOKEN or SERVICE_TO_SERVICE_SECRET in the environment. ' +
      'Hardcoded fallback credentials have been permanently eliminated.'
    );
  }

  const endpointUrl = `${apiUrl}/api/discovery/pipeline/report-cycle`;
  const response = await fetch(endpointUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${serviceToken}`,
      'User-Agent': 'CAIM-Standalone-Discovery-Runner/1.0',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to report discovery cycle (${response.status} ${response.statusText}): ${errorBody}`);
  }

  const result = await response.json();
  console.log(`[Discovery Runner] SUCCESS! Cycle report processed by server:`, JSON.stringify(result, null, 2));
  console.log(`[Discovery Runner] Total execution time: ${durationMs}ms`);

  return {
    success: true,
    cycle_id: cycleId,
    candidates_count: candidatePackages.length,
    candidates_processed: result.candidates_processed ?? candidatePackages.length,
    agents_ingested: result.agents_ingested ?? candidatePackages.length,
    edges_count: cycleEdges.length,
    duration_ms: durationMs,
    server_response: result,
  };
}

// Direct CLI Execution
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('run-discovery-cycle.ts')) {
  runStandaloneDiscoveryCycle()
    .then(() => {
      console.log('[Discovery Runner] Discovery cycle completed cleanly. Exiting 0.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('[Discovery Runner FATAL]:', err.message || err);
      process.exit(1);
    });
}
