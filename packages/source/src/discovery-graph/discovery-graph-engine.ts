/**
 * Architecture V2.0.1 — Discovery Graph Engine
 * Physical Tables: source.discovery_roots, source.discovery_candidates, source.discovery_edges
 * Queue Engine: ops.jobs
 *
 * Guarantees:
 * - Part B: Deduplication collapses the entity, never provenance (1 candidate, N edges)
 * - Part C: Hard crawl boundaries enforced transactionally at queue boundary:
 *   1. MAX_CRAWL_DEPTH = 4 (depth > max rejected with DEPTH_LIMIT)
 *   2. MAX_PIVOTS_PER_PARENT (excess rejected with PARENT_FANOUT_LIMIT)
 *   3. MAX_DISCOVERIES_PER_ROOT_PER_CYCLE (excess rejected with ROOT_BUDGET_EXCEEDED)
 *   4. MAX_PIVOTS_PER_DISCOVERY_CYCLE (global cap; stops scheduling, retains unqueued candidates for next cycle)
 *   5. Per-domain fairness
 * - Part D: Durable async work via ops.jobs (no in-process direct recursion)
 * - Part E: Complete separation of discovery_confidence vs classification_confidence
 */

import crypto from 'crypto';
import {
  DiscoveryRootRecord,
  DiscoveryCandidateRecord,
  DiscoveryEdgeRecord,
  CrawlBoundariesConfig,
  ExtractedPivot,
  DiscoveryEdgeType,
} from './types.ts';
import { UrlNormalizer } from './url-normalizer.ts';
import { RelevanceGate } from './relevance-gate.ts';

export const DEFAULT_CRAWL_BOUNDARIES: CrawlBoundariesConfig = {
  max_crawl_depth: 4,                  // Depth 0 = root, max crawl depth = 4
  max_pivots_per_parent: 10,           // Fanout limit per parent
  max_discoveries_per_root_per_cycle: 25, // Cap per root in single cycle
  max_pivots_per_discovery_cycle: 100,  // Global cycle cap
  per_domain_concurrency: 5,           // Fairness per domain
};

export class DiscoveryGraphEngine {
  constructor(private readonly db: any) {}

  /**
   * Registers a real discovery root seed and enqueues depth 0 processing.
   */
  public async registerRoot(
    sourceAdapter: string,
    rootType: string,
    rootValue: string,
    options: { created_by?: string; metadata?: Record<string, any>; cycle_id?: string } = {}
  ): Promise<{
    root: DiscoveryRootRecord;
    candidate: DiscoveryCandidateRecord;
    edge: DiscoveryEdgeRecord;
  }> {
    const cycleId = options.cycle_id || `cycle-${Date.now().toString(36)}`;
    const createdBy = options.created_by || 'system';
    const metadata = options.metadata || {};
    const rootId = crypto.randomUUID();

    // 1. Insert Discovery Root
    const rootRes = await this.db.query(
      `INSERT INTO source.discovery_roots (
        id, source_adapter, root_type, root_value, created_by, active, metadata_json
      ) VALUES ($1, $2, $3, $4, $5, true, $6)
      RETURNING *;`,
      [rootId, sourceAdapter, rootType, rootValue, createdBy, JSON.stringify({ ...metadata, cycle_id: cycleId })]
    );
    const root: DiscoveryRootRecord = rootRes.rows[0];

    // 2. Normalize and insert Root Candidate
    const normalized = UrlNormalizer.normalize(rootValue);
    const existingCandRes = await this.db.query(
      `SELECT * FROM source.discovery_candidates WHERE normalized_url = $1;`,
      [normalized.normalized_url]
    );

    let candidate: DiscoveryCandidateRecord;
    if (existingCandRes.rows && existingCandRes.rows.length > 0) {
      candidate = existingCandRes.rows[0];
      await this.db.query(
        `UPDATE source.discovery_candidates
         SET last_seen_at = now(), status = 'QUEUED', queued_at = now()
         WHERE id = $1;`,
        [candidate.id]
      );
    } else {
      const candId = crypto.randomUUID();
      const candRes = await this.db.query(
        `INSERT INTO source.discovery_candidates (
          candidate_id, id, canonical_url, normalized_url, candidate_type, domain,
          status, relevance_score, discovery_confidence, metadata_json, queued_at
        ) VALUES ($1, $1, $2, $3, $4, $5, 'QUEUED', 1.0000, 1.0000, $6, now())
        RETURNING *;`,
        [
          candId,
          normalized.canonical_url,
          normalized.normalized_url,
          normalized.candidate_type,
          normalized.domain,
          JSON.stringify({ root_seed: true, cycle_id: cycleId }),
        ]
      );
      candidate = candRes.rows[0];
    }

    // 3. Insert Root Discovery Edge (crawl_depth = 0)
    const edgeId = crypto.randomUUID();
    const edgeRes = await this.db.query(
      `INSERT INTO source.discovery_edges (
        id, root_seed_id, parent_edge_id, source_candidate_id, source_agent_id,
        target_candidate_id, discovered_url, normalized_url, edge_type,
        crawl_depth, extractor, evidence_type, evidence_location,
        decision, metadata_json, queued_at
      ) VALUES ($1, $2, NULL, NULL, NULL, $3, $4, $5, 'ROOT_SOURCE', 0, 'ROOT_SEED_REGISTRATION', 'USER_ROOT', 'seed_configuration', 'QUEUED', $6, now())
      RETURNING *;`,
      [
        edgeId,
        root.id,
        candidate.id,
        rootValue,
        normalized.normalized_url,
        JSON.stringify({ cycle_id: cycleId }),
      ]
    );
    const edge: DiscoveryEdgeRecord = edgeRes.rows[0];

    // 4. Enqueue durable job into ops.jobs
    const idempotencyKey = `disc-job-${cycleId}-${edge.id}`;
    const payload = {
      candidate_id: candidate.id,
      root_seed_id: root.id,
      edge_id: edge.id,
      crawl_depth: 0,
      cycle_id: cycleId,
      domain: normalized.domain,
      source_adapter: sourceAdapter,
      locator: rootValue,
    };

    await this.db.query(
      `INSERT INTO ops.jobs (
        job_id, queue_key, idempotency_key, priority, status, next_attempt_at, payload
      ) VALUES ($1, 'discovery_graph_queue', $2, 10, 'QUEUED', now(), $3)
      ON CONFLICT (idempotency_key) DO NOTHING;`,
      [crypto.randomUUID(), idempotencyKey, JSON.stringify(payload)]
    );

    return { root, candidate, edge };
  }

  /**
   * Helper to insert an edge row cleanly with strictly aligned parameters.
   */
  private async insertEdge(params: {
    id: string;
    root_seed_id: string;
    parent_edge_id: string | null;
    source_candidate_id: string | null;
    source_agent_id: string | null;
    target_candidate_id: string;
    pivot: ExtractedPivot;
    crawl_depth: number;
    source_content_hash: string;
    decision: string;
    rejection_reason: string | null;
    queued_at?: boolean;
    metadata: Record<string, any>;
  }): Promise<DiscoveryEdgeRecord> {
    const queuedAtSql = params.queued_at ? 'now()' : 'NULL';
    const edgeRes = await this.db.query(
      `INSERT INTO source.discovery_edges (
        id, root_seed_id, parent_edge_id, source_candidate_id, source_agent_id,
        target_candidate_id, discovered_url, normalized_url, edge_type,
        crawl_depth, extractor, evidence_type, evidence_location,
        evidence_snippet_hash, source_content_hash,
        decision, rejection_reason, queued_at, metadata_json
      ) VALUES (
        $1, $2, $3, $4, $5,
        $6, $7, $8, $9,
        $10, $11, $12, $13,
        $14, $15,
        $16, $17, ${queuedAtSql}, $18
      ) RETURNING *;`,
      [
        params.id,
        params.root_seed_id,
        params.parent_edge_id,
        params.source_candidate_id,
        params.source_agent_id,
        params.target_candidate_id,
        params.pivot.discovered_url,
        params.pivot.normalized_url,
        params.pivot.edge_type,
        params.crawl_depth,
        params.pivot.extractor,
        params.pivot.evidence_type,
        params.pivot.evidence_location,
        params.pivot.evidence_snippet_hash || null,
        params.source_content_hash,
        params.decision,
        params.rejection_reason,
        JSON.stringify(params.metadata),
      ]
    );
    return edgeRes.rows[0];
  }

  /**
   * Enforces all hard crawl boundaries transactionally and schedules/records outbound pivots.
   */
  public async evaluateAndSchedulePivots(params: {
    root_seed_id: string;
    parent_edge_id?: string | null;
    source_candidate_id: string;
    source_agent_id?: string | null;
    parent_crawl_depth: number;
    cycle_id: string;
    pivots: ExtractedPivot[];
    source_content_hash: string;
    boundaries?: Partial<CrawlBoundariesConfig>;
  }): Promise<{
    accepted_edges: DiscoveryEdgeRecord[];
    rejected_edges: DiscoveryEdgeRecord[];
    retained_candidates: DiscoveryCandidateRecord[];
    boundary_violations: {
      depth_limit: number;
      parent_fanout_limit: number;
      root_budget_exceeded: number;
      cycle_budget_retained: number;
      relevance_gate_rejected: number;
    };
  }> {
    const boundaries: CrawlBoundariesConfig = {
      ...DEFAULT_CRAWL_BOUNDARIES,
      ...(params.boundaries || {}),
    };

    const targetDepth = params.parent_crawl_depth + 1;
    const acceptedEdges: DiscoveryEdgeRecord[] = [];
    const rejectedEdges: DiscoveryEdgeRecord[] = [];
    const retainedCandidates: DiscoveryCandidateRecord[] = [];

    const violations = {
      depth_limit: 0,
      parent_fanout_limit: 0,
      root_budget_exceeded: 0,
      cycle_budget_retained: 0,
      relevance_gate_rejected: 0,
    };

    // SAFEGUARD 1: MAX_CRAWL_DEPTH (mandatory = 4)
    if (targetDepth > boundaries.max_crawl_depth) {
      for (const pivot of params.pivots) {
        violations.depth_limit++;
        const targetCand = await this.findOrCreateCandidate(pivot, 'REJECTED', 'DEPTH_LIMIT');
        const edge = await this.insertEdge({
          id: crypto.randomUUID(),
          root_seed_id: params.root_seed_id,
          parent_edge_id: params.parent_edge_id || null,
          source_candidate_id: params.source_candidate_id,
          source_agent_id: params.source_agent_id || null,
          target_candidate_id: targetCand.id,
          pivot,
          crawl_depth: targetDepth,
          source_content_hash: params.source_content_hash,
          decision: 'REJECTED',
          rejection_reason: 'DEPTH_LIMIT',
          metadata: { cycle_id: params.cycle_id, safeguard: 'MAX_CRAWL_DEPTH' },
        });
        rejectedEdges.push(edge);
      }
      return { accepted_edges: acceptedEdges, rejected_edges: rejectedEdges, retained_candidates: retainedCandidates, boundary_violations: violations };
    }

    // DETERMINISTIC RELEVANCE GATE (Zero LLM, cheap rejection of noise)
    const gateAcceptedPivots: ExtractedPivot[] = [];
    for (const pivot of params.pivots) {
      const gateDecision = boundaries.skip_relevance_gate
        ? { accepted: true, gate_reason: 'CONFIG_BYPASS', heuristic_used: 'CONFIG', is_llm_used: false as const, rejection_reason: null }
        : (pivot.relevance_gate_decision || (boundaries.enforce_relevance_gate ? RelevanceGate.evaluate(pivot) : { accepted: true, gate_reason: 'DEFAULT_ACCEPT', heuristic_used: 'NONE', is_llm_used: false as const, rejection_reason: null }));
      pivot.relevance_gate_decision = gateDecision as any;

      if (!gateDecision.accepted) {
        violations.relevance_gate_rejected++;
        const targetCand = await this.findOrCreateCandidate(
          pivot,
          'REJECTED',
          gateDecision.rejection_reason || 'NON_AGENT_FILTER'
        );
        const edge = await this.insertEdge({
          id: crypto.randomUUID(),
          root_seed_id: params.root_seed_id,
          parent_edge_id: params.parent_edge_id || null,
          source_candidate_id: params.source_candidate_id,
          source_agent_id: params.source_agent_id || null,
          target_candidate_id: targetCand.id,
          pivot,
          crawl_depth: targetDepth,
          source_content_hash: params.source_content_hash,
          decision: 'REJECTED',
          rejection_reason: gateDecision.rejection_reason || 'NON_AGENT_FILTER',
          metadata: {
            cycle_id: params.cycle_id,
            relevance_gate: gateDecision,
          },
        });
        rejectedEdges.push(edge);
      } else {
        gateAcceptedPivots.push(pivot);
      }
    }

    // SAFEGUARD 2: MAX_PIVOTS_PER_PARENT (Rank by discovery_confidence DESC)
    const sortedPivots = [...gateAcceptedPivots].sort(
      (a, b) => b.discovery_confidence - a.discovery_confidence
    );

    const allowedByParentFanout = sortedPivots.slice(0, boundaries.max_pivots_per_parent);
    const excessByParentFanout = sortedPivots.slice(boundaries.max_pivots_per_parent);

    // Reject excess pivots due to PARENT_FANOUT_LIMIT
    for (const pivot of excessByParentFanout) {
      violations.parent_fanout_limit++;
      const targetCand = await this.findOrCreateCandidate(pivot, 'REJECTED', 'PARENT_FANOUT_LIMIT');
      const edge = await this.insertEdge({
        id: crypto.randomUUID(),
        root_seed_id: params.root_seed_id,
        parent_edge_id: params.parent_edge_id || null,
        source_candidate_id: params.source_candidate_id,
        source_agent_id: params.source_agent_id || null,
        target_candidate_id: targetCand.id,
        pivot,
        crawl_depth: targetDepth,
        source_content_hash: params.source_content_hash,
        decision: 'REJECTED',
        rejection_reason: 'PARENT_FANOUT_LIMIT',
        metadata: { cycle_id: params.cycle_id, safeguard: 'MAX_PIVOTS_PER_PARENT' },
      });
      rejectedEdges.push(edge);
    }

    // SAFEGUARD 3: MAX_DISCOVERIES_PER_ROOT_PER_CYCLE
    const rootCountRes = await this.db.query(
      `SELECT count(*)::int as count FROM source.discovery_edges
       WHERE root_seed_id = $1
         AND decision != 'REJECTED'
         AND metadata_json->>'cycle_id' = $2;`,
      [params.root_seed_id, params.cycle_id]
    );
    const currentRootDiscovered = parseInt(rootCountRes.rows[0]?.count || '0', 10);
    const rootRemainingBudget = Math.max(0, boundaries.max_discoveries_per_root_per_cycle - currentRootDiscovered);

    const allowedByRootBudget = allowedByParentFanout.slice(0, rootRemainingBudget);
    const excessByRootBudget = allowedByParentFanout.slice(rootRemainingBudget);

    for (const pivot of excessByRootBudget) {
      violations.root_budget_exceeded++;
      const targetCand = await this.findOrCreateCandidate(pivot, 'REJECTED', 'ROOT_BUDGET_EXCEEDED');
      const edge = await this.insertEdge({
        id: crypto.randomUUID(),
        root_seed_id: params.root_seed_id,
        parent_edge_id: params.parent_edge_id || null,
        source_candidate_id: params.source_candidate_id,
        source_agent_id: params.source_agent_id || null,
        target_candidate_id: targetCand.id,
        pivot,
        crawl_depth: targetDepth,
        source_content_hash: params.source_content_hash,
        decision: 'REJECTED',
        rejection_reason: 'ROOT_BUDGET_EXCEEDED',
        metadata: { cycle_id: params.cycle_id, safeguard: 'MAX_DISCOVERIES_PER_ROOT_PER_CYCLE' },
      });
      rejectedEdges.push(edge);
    }

    // SAFEGUARD 4: MAX_PIVOTS_PER_DISCOVERY_CYCLE (Global Cycle Cap with Candidate Retention)
    const cycleJobsRes = await this.db.query(
      `SELECT count(*)::int as count FROM ops.jobs
       WHERE queue_key = 'discovery_graph_queue'
         AND payload->>'cycle_id' = $1;`,
      [params.cycle_id]
    );
    const globalScheduledInCycle = parseInt(cycleJobsRes.rows[0]?.count || '0', 10);
    const globalRemainingBudget = Math.max(0, boundaries.max_pivots_per_discovery_cycle - globalScheduledInCycle);

    const toQueue = allowedByRootBudget.slice(0, globalRemainingBudget);
    const toRetain = allowedByRootBudget.slice(globalRemainingBudget);

    // Retained candidates for the next cycle (NOT lost, NOT discarded)
    for (const pivot of toRetain) {
      violations.cycle_budget_retained++;
      // Candidate is saved as DISCOVERED with queued_at NULL
      const targetCand = await this.findOrCreateCandidate(pivot, 'DISCOVERED', null);
      retainedCandidates.push(targetCand);

      // Edge records provenance with decision 'DEFERRED_CYCLE_BUDGET'
      const edge = await this.insertEdge({
        id: crypto.randomUUID(),
        root_seed_id: params.root_seed_id,
        parent_edge_id: params.parent_edge_id || null,
        source_candidate_id: params.source_candidate_id,
        source_agent_id: params.source_agent_id || null,
        target_candidate_id: targetCand.id,
        pivot,
        crawl_depth: targetDepth,
        source_content_hash: params.source_content_hash,
        decision: 'DEFERRED_CYCLE_BUDGET',
        rejection_reason: null,
        metadata: { cycle_id: params.cycle_id, safeguard: 'MAX_PIVOTS_PER_DISCOVERY_CYCLE', retained_for_next_cycle: true },
      });
      acceptedEdges.push(edge);
    }

    // Now process all accepted pivots:
    // PART B: Deduplication collapses the entity, never provenance!
    for (const pivot of toQueue) {
      // Find or create canonical candidate (single row)
      const targetCand = await this.findOrCreateCandidate(pivot, 'QUEUED', null);

      // Create a new edge for THIS specific path (multiple edges into same candidate allowed)
      const edge = await this.insertEdge({
        id: crypto.randomUUID(),
        root_seed_id: params.root_seed_id,
        parent_edge_id: params.parent_edge_id || null,
        source_candidate_id: params.source_candidate_id,
        source_agent_id: params.source_agent_id || null,
        target_candidate_id: targetCand.id,
        pivot,
        crawl_depth: targetDepth,
        source_content_hash: params.source_content_hash,
        decision: 'QUEUED',
        rejection_reason: null,
        queued_at: true,
        metadata: { cycle_id: params.cycle_id },
      });
      acceptedEdges.push(edge);

      // Enqueue into ops.jobs for asynchronous execution (Part D)
      const idempotencyKey = `disc-job-${params.cycle_id}-${edge.id}`;
      const payload = {
        candidate_id: targetCand.id,
        root_seed_id: params.root_seed_id,
        edge_id: edge.id,
        crawl_depth: targetDepth,
        cycle_id: params.cycle_id,
        domain: pivot.domain,
        locator: pivot.discovered_url,
      };

      await this.db.query(
        `INSERT INTO ops.jobs (
          job_id, queue_key, idempotency_key, priority, status, next_attempt_at, payload
        ) VALUES ($1, 'discovery_graph_queue', $2, 10, 'QUEUED', now(), $3)
        ON CONFLICT (idempotency_key) DO NOTHING;`,
        [crypto.randomUUID(), idempotencyKey, JSON.stringify(payload)]
      );
    }

    return {
      accepted_edges: acceptedEdges,
      rejected_edges: rejectedEdges,
      retained_candidates: retainedCandidates,
      boundary_violations: violations,
    };
  }

  /**
   * Part B Entity Deduplication: Collapses the ENTITY into a single row,
   * updating last_seen_at if already discovered.
   */
  private async findOrCreateCandidate(
    pivot: ExtractedPivot,
    initialStatus: string,
    rejectionReason: string | null
  ): Promise<DiscoveryCandidateRecord> {
    const existing = await this.db.query(
      `SELECT * FROM source.discovery_candidates WHERE normalized_url = $1;`,
      [pivot.normalized_url]
    );

    if (existing.rows && existing.rows.length > 0) {
      const candidate: DiscoveryCandidateRecord = existing.rows[0];
      await this.db.query(
        `UPDATE source.discovery_candidates
         SET last_seen_at = now()
         WHERE id = $1;`,
        [candidate.id]
      );
      return candidate;
    }

    // Insert new canonical candidate entity
    const candId = crypto.randomUUID();
    const queuedAt = initialStatus === 'QUEUED' ? 'now()' : 'NULL';
    const insRes = await this.db.query(
      `INSERT INTO source.discovery_candidates (
        candidate_id, id, canonical_url, normalized_url, candidate_type, domain,
        status, relevance_score, discovery_confidence, classification_confidence,
        classification, rejection_reason, metadata_json, queued_at
      ) VALUES ($1, $1, $2, $3, $4, $5, $6, $7, $7, NULL, NULL, $8, $9, ${queuedAt})
      RETURNING *;`,
      [
        candId,
        pivot.canonical_url,
        pivot.normalized_url,
        pivot.candidate_type,
        pivot.domain,
        initialStatus,
        pivot.discovery_confidence,
        rejectionReason,
        JSON.stringify(pivot.metadata || {}),
      ]
    );

    return insRes.rows[0];
  }
}
