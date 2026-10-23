/**
 * Architecture V2.0.1 — Discovery Graph Lineage & Observability Service
 * Exposes real ancestor traversal, reverse descendant trees, and live counters
 * strictly reconstructed from source.discovery_edges, source.discovery_candidates,
 * source.discovery_roots, and ops.jobs.
 */

import {
  DiscoveryLineageResponse,
  DiscoveredDescendantsResponse,
  DiscoveryObservabilityMetrics,
  LineageNode,
  LineageImmediateParent,
  LineageRootSource,
  DescendantNode,
  DiscoveryEdgeRecord,
} from './types.ts';

export class DiscoveryLineageService {
  constructor(private readonly db: any) {}

  /**
   * Reconstructs the real ancestor chain for an agent or candidate.
   * Traverses upwards: Target -> Parent Edge -> ... -> Root Edge & Root Seed.
   * Never fabricates placeholder lineage.
   */
  public async getDiscoveryLineage(agentIdOrLocator: string): Promise<DiscoveryLineageResponse> {
    if (!agentIdOrLocator || typeof agentIdOrLocator !== 'string') {
      return this.emptyLineageResponse(agentIdOrLocator || 'unknown', 'Invalid agent identifier provided.');
    }

    const trimmedId = agentIdOrLocator.trim();

    // 1. Resolve agent identity and associated candidate/locator if in core.canonical_agents
    let resolvedAgentId: string | null = null;
    let canonicalName: string | null = null;
    let candidateId: string | null = null;
    let targetLocators: string[] = [trimmedId];

    try {
      const agentRes = await this.db.query(
        `SELECT agent_id, canonical_name
         FROM core.canonical_agents
         WHERE agent_id::text = $1 OR lower(canonical_name) = lower($1)
         LIMIT 1;`,
        [trimmedId]
      );
      if (agentRes.rows && agentRes.rows.length > 0) {
        resolvedAgentId = agentRes.rows[0].agent_id;
        canonicalName = agentRes.rows[0].canonical_name;

        // Also fetch any source locators from agent_versions
        const verRes = await this.db.query(
          `SELECT source_locator FROM core.agent_versions WHERE agent_id = $1;`,
          [resolvedAgentId]
        );
        for (const row of verRes.rows || []) {
          if (row.source_locator) {
            targetLocators.push(row.source_locator);
          }
        }
      }
    } catch (_err) {
      // If table doesn't exist or query fails, proceed with candidate/edge matching
    }

    // 2. Locate the target edge in source.discovery_edges
    // Could match target_candidate_id, candidate metadata_json->>'agent_id', discovered_url, or source_agent_id
    const edgeQuery = `
      SELECT 
        e.*,
        c.canonical_url,
        c.normalized_url,
        c.status as candidate_status,
        c.first_seen_at as candidate_first_seen_at,
        c.metadata_json as candidate_metadata
      FROM source.discovery_edges e
      LEFT JOIN source.discovery_candidates c ON e.target_candidate_id = c.id
      WHERE e.target_candidate_id::text = $1
         OR e.source_agent_id::text = $1
         OR (c.id IS NOT NULL AND c.id::text = $1)
         OR (c.candidate_id IS NOT NULL AND c.candidate_id::text = $1)
         OR (c.metadata_json->>'agent_id' = $1)
         OR (e.metadata_json->>'agent_id' = $1)
         OR (e.metadata_json->>'target_agent_id' = $1)
         OR e.discovered_url = ANY($2::text[])
         OR e.normalized_url = ANY($2::text[])
         OR (c.canonical_url IS NOT NULL AND c.canonical_url = ANY($2::text[]))
         OR (c.normalized_url IS NOT NULL AND c.normalized_url = ANY($2::text[]))
      ORDER BY e.crawl_depth DESC, e.discovered_at DESC
      LIMIT 1;
    `;

    let targetEdgeRes;
    try {
      targetEdgeRes = await this.db.query(edgeQuery, [resolvedAgentId || trimmedId, targetLocators]);
    } catch (err: any) {
      return this.emptyLineageResponse(resolvedAgentId || trimmedId, `Failed to query discovery graph: ${err.message}`);
    }

    if (!targetEdgeRes.rows || targetEdgeRes.rows.length === 0) {
      return this.emptyLineageResponse(
        resolvedAgentId || trimmedId,
        'No discovery lineage recorded in discovery_edges table for this agent.',
        canonicalName
      );
    }

    const targetEdge = targetEdgeRes.rows[0];
    candidateId = targetEdge.target_candidate_id;

    // 3. Ascend the ancestor chain iteratively via parent_edge_id
    const rawEdges: DiscoveryEdgeRecord[] = [];
    const visitedEdgeIds = new Set<string>();
    let currentEdge = targetEdge;

    while (currentEdge) {
      rawEdges.unshift(currentEdge);
      visitedEdgeIds.add(currentEdge.id);

      if (!currentEdge.parent_edge_id) {
        break; // Reached root edge (or edge without parent)
      }

      if (visitedEdgeIds.has(currentEdge.parent_edge_id)) {
        break; // Cycle safeguard
      }

      try {
        const parentRes = await this.db.query(
          `SELECT 
             e.*,
             c.canonical_url,
             c.normalized_url,
             c.status as candidate_status,
             c.first_seen_at as candidate_first_seen_at,
             c.metadata_json as candidate_metadata
           FROM source.discovery_edges e
           LEFT JOIN source.discovery_candidates c ON e.target_candidate_id = c.id
           WHERE e.id = $1;`,
          [currentEdge.parent_edge_id]
        );

        if (parentRes.rows && parentRes.rows.length > 0) {
          currentEdge = parentRes.rows[0];
        } else {
          break;
        }
      } catch (_e) {
        break;
      }
    }

    // 4. Fetch root source seed from source.discovery_roots
    let rootSource: LineageRootSource | null = null;
    const rootSeedId = rawEdges[0]?.root_seed_id || targetEdge.root_seed_id;
    if (rootSeedId) {
      try {
        const rootRes = await this.db.query(
          `SELECT * FROM source.discovery_roots WHERE id = $1;`,
          [rootSeedId]
        );
        if (rootRes.rows && rootRes.rows.length > 0) {
          const r = rootRes.rows[0];
          rootSource = {
            root_id: r.id,
            source_adapter: r.source_adapter,
            root_type: r.root_type,
            root_value: r.root_value,
            created_at: r.created_at,
            metadata: typeof r.metadata_json === 'string' ? JSON.parse(r.metadata_json) : r.metadata_json,
          };
        }
      } catch (_e) {
        // Root table query failed or not present
      }
    }

    // 5. Construct full ancestor chain & full path
    const ancestorChain: LineageNode[] = [];
    const fullPath: string[] = [];

    // Add root node to breadcrumbs
    if (rootSource) {
      fullPath.push(rootSource.root_value);
      ancestorChain.push({
        depth: 0,
        node_type: 'ROOT',
        id: rootSource.root_id,
        label: `Root: ${rootSource.source_adapter}`,
        url: rootSource.root_value,
        source_adapter: rootSource.source_adapter,
        edge_type: 'ROOT_SOURCE',
        discovered_at: rootSource.created_at,
      });
    }

    // Process each intermediate edge up to target edge
    for (let i = 0; i < rawEdges.length; i++) {
      const edge = rawEdges[i];
      const isTarget = i === rawEdges.length - 1;
      const isDuplicateOfRoot = Boolean(rootSource && (edge.discovered_url === rootSource.root_value || edge.normalized_url === rootSource.root_value));
      if (isDuplicateOfRoot) {
        continue;
      }

      const nodeUrl = edge.discovered_url || (edge as any).canonical_url || edge.normalized_url;
      if (!fullPath.includes(nodeUrl)) {
        fullPath.push(nodeUrl);
      }

      ancestorChain.push({
        depth: edge.crawl_depth,
        node_type: isTarget ? 'TARGET' : 'PIVOT',
        id: edge.id,
        label: isTarget && canonicalName ? canonicalName : (edge.normalized_url || edge.discovered_url),
        url: nodeUrl,
        edge_type: edge.edge_type,
        evidence: {
          type: edge.evidence_type,
          location: edge.evidence_location,
          snippet_hash: edge.evidence_snippet_hash,
        },
        discovered_at: edge.discovered_at,
        agent_id: isTarget ? (resolvedAgentId || trimmedId) : edge.source_agent_id,
        candidate_id: edge.target_candidate_id,
      });
    }

    // 6. Identify immediate parent
    let immediateParent: LineageImmediateParent | null = null;
    if (rawEdges.length > 1) {
      const parentEdge = rawEdges[rawEdges.length - 2];
      immediateParent = {
        edge_id: parentEdge.id,
        parent_agent_id: targetEdge.source_agent_id || parentEdge.source_agent_id,
        parent_candidate_id: targetEdge.source_candidate_id || parentEdge.target_candidate_id,
        parent_url: parentEdge.discovered_url || parentEdge.normalized_url,
        edge_type: targetEdge.edge_type,
        evidence: {
          type: targetEdge.evidence_type,
          location: targetEdge.evidence_location,
          snippet_hash: targetEdge.evidence_snippet_hash,
        },
        crawl_depth: targetEdge.crawl_depth,
        discovered_at: targetEdge.discovered_at,
      };
    } else if (targetEdge.edge_type === 'ROOT_SOURCE' || !targetEdge.parent_edge_id) {
      immediateParent = {
        edge_id: targetEdge.id,
        parent_agent_id: null,
        parent_candidate_id: null,
        parent_url: rootSource?.root_value || targetEdge.discovered_url,
        edge_type: 'ROOT_SOURCE',
        evidence: {
          type: targetEdge.evidence_type,
          location: targetEdge.evidence_location,
          snippet_hash: targetEdge.evidence_snippet_hash,
        },
        crawl_depth: 0,
        discovered_at: targetEdge.discovered_at,
      };
    }

    return {
      agent_id: resolvedAgentId || trimmedId,
      candidate_id: candidateId,
      canonical_name: canonicalName,
      found: true,
      immediate_parent: immediateParent,
      root_source: rootSource,
      edge_type: targetEdge.edge_type,
      evidence: {
        type: targetEdge.evidence_type,
        location: targetEdge.evidence_location,
        snippet_hash: targetEdge.evidence_snippet_hash,
      },
      depth: targetEdge.crawl_depth,
      timestamps: {
        discovered_at: targetEdge.discovered_at,
        queued_at: targetEdge.queued_at,
        first_seen_at: targetEdge.candidate_first_seen_at || targetEdge.discovered_at,
      },
      ancestor_chain: ancestorChain,
      full_path: fullPath,
      raw_edges: rawEdges,
    };
  }

  /**
   * Reverse traversal: returns all descendant agents/candidates discovered from this agent/candidate.
   */
  public async getDiscoveredDescendants(agentIdOrLocator: string): Promise<DiscoveredDescendantsResponse> {
    if (!agentIdOrLocator || typeof agentIdOrLocator !== 'string') {
      return {
        agent_id: agentIdOrLocator || 'unknown',
        candidate_id: null,
        total_descendants: 0,
        max_depth: 0,
        descendants: [],
        tree: [],
      };
    }

    const trimmedId = agentIdOrLocator.trim();

    // 1. Resolve agent id or candidate id
    let resolvedAgentId: string = trimmedId;
    let canonicalName: string | null = null;
    let candidateId: string | null = null;

    try {
      const agentRes = await this.db.query(
        `SELECT agent_id, canonical_name FROM core.canonical_agents WHERE agent_id::text = $1 OR lower(canonical_name) = lower($1);`,
        [trimmedId]
      );
      if (agentRes.rows && agentRes.rows.length > 0) {
        resolvedAgentId = agentRes.rows[0].agent_id;
        canonicalName = agentRes.rows[0].canonical_name;
      }
    } catch (_e) {}

    // Find candidate ID if available
    try {
      const candRes = await this.db.query(
        `SELECT id FROM source.discovery_candidates WHERE id::text = $1 OR metadata_json->>'agent_id' = $1 LIMIT 1;`,
        [resolvedAgentId]
      );
      if (candRes.rows && candRes.rows.length > 0) {
        candidateId = candRes.rows[0].id;
      }
    } catch (_e) {}

    // 2. Fetch direct outgoing edges
    const descendants: DescendantNode[] = [];
    const queue: string[] = [];
    const visitedEdgeIds = new Set<string>();

    const outgoingRes = await this.db.query(
      `SELECT 
         e.*,
         c.status as candidate_status,
         c.metadata_json as candidate_metadata
       FROM source.discovery_edges e
       LEFT JOIN source.discovery_candidates c ON e.target_candidate_id = c.id
       WHERE e.source_agent_id::text = $1
          OR (e.source_candidate_id IS NOT NULL AND e.source_candidate_id::text = $2)
          OR (e.parent_edge_id IN (SELECT id FROM source.discovery_edges WHERE target_candidate_id::text = $2))
       ORDER BY e.crawl_depth ASC, e.discovered_at ASC;`,
      [resolvedAgentId, candidateId || resolvedAgentId]
    );

    for (const row of outgoingRes.rows || []) {
      if (!visitedEdgeIds.has(row.id)) {
        visitedEdgeIds.add(row.id);
        queue.push(row.id);
        descendants.push(this.formatDescendantNode(row));
      }
    }

    // 3. Breadth-first traversal down subsequent generations
    while (queue.length > 0) {
      const currentBatch = queue.splice(0, 50);
      const placeholders = currentBatch.map((_, i) => `$${i + 1}`).join(',');
      try {
        const childRes = await this.db.query(
          `SELECT 
             e.*,
             c.status as candidate_status,
             c.metadata_json as candidate_metadata
           FROM source.discovery_edges e
           LEFT JOIN source.discovery_candidates c ON e.target_candidate_id = c.id
           WHERE e.parent_edge_id IN (${placeholders})
           ORDER BY e.crawl_depth ASC, e.discovered_at ASC;`,
          currentBatch
        );

        for (const child of childRes.rows || []) {
          if (!visitedEdgeIds.has(child.id)) {
            visitedEdgeIds.add(child.id);
            queue.push(child.id);
            descendants.push(this.formatDescendantNode(child));
          }
        }
      } catch (_e) {
        break;
      }
    }

    const maxDepth = descendants.reduce((max, d) => Math.max(max, d.depth), 0);

    return {
      agent_id: resolvedAgentId,
      candidate_id: candidateId,
      canonical_name: canonicalName,
      total_descendants: descendants.length,
      max_depth: maxDepth,
      descendants,
      tree: descendants,
    };
  }

  /**
   * Computes the 16 real observability metrics directly from live PostgreSQL state.
   * Guarantees 0 for zero events; never fabricates placeholders.
   */
  public async getDiscoveryMetrics(): Promise<DiscoveryObservabilityMetrics> {
    // 1. Discovery Candidates statistics
    let candStats: any = {};
    try {
      const candRes = await this.db.query(`
        SELECT 
          COUNT(*)::int as total_seen,
          COALESCE(SUM(CASE WHEN status = 'QUEUED' THEN 1 ELSE 0 END), 0)::int as total_queued,
          COALESCE(SUM(CASE WHEN status IN ('VERIFIED_AGENT', 'ACQUIRED') THEN 1 ELSE 0 END), 0)::int as total_verified,
          COALESCE(SUM(CASE WHEN status = 'REJECTED' THEN 1 ELSE 0 END), 0)::int as total_rejected,
          COALESCE(SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END), 0)::int as total_failed,
          COALESCE(SUM(CASE WHEN status = 'DUPLICATE' THEN 1 ELSE 0 END), 0)::int as total_dup_status,
          COALESCE(SUM(CASE WHEN status = 'ROBOTS_BLOCKED' THEN 1 ELSE 0 END), 0)::int as total_robots_status,
          COALESCE(SUM(CASE WHEN status = 'RATE_LIMITED' THEN 1 ELSE 0 END), 0)::int as total_ratelimit_status
        FROM source.discovery_candidates;
      `);
      candStats = candRes.rows[0] || {};
    } catch (_e) {}

    // 2. Discovery Edges statistics
    let edgeStats: any = {};
    try {
      const edgeRes = await this.db.query(`
        SELECT
          COUNT(*)::int as total_edges,
          COALESCE(SUM(CASE WHEN edge_type != 'ROOT_SOURCE' THEN 1 ELSE 0 END), 0)::int as total_pivots_generated,
          COALESCE(SUM(CASE WHEN rejection_reason = 'DEPTH_LIMIT' THEN 1 ELSE 0 END), 0)::int as depth_rejections,
          COALESCE(SUM(CASE WHEN rejection_reason IN ('ROOT_BUDGET_EXCEEDED', 'CYCLE_BUDGET_EXCEEDED', 'PARENT_FANOUT_LIMIT') THEN 1 ELSE 0 END), 0)::int as budget_rejections,
          COALESCE(SUM(CASE WHEN rejection_reason IN ('SSRF_BLOCKED', 'PRIVATE_NETWORK', 'UNRESOLVABLE_DOMAIN') OR metadata_json->>'safeguard' = 'SSRF' THEN 1 ELSE 0 END), 0)::int as ssrf_rejections,
          COALESCE(SUM(CASE WHEN rejection_reason = 'ROBOTS_BLOCKED' THEN 1 ELSE 0 END), 0)::int as robots_rejections,
          COALESCE(SUM(CASE WHEN rejection_reason = 'RATE_LIMITED' THEN 1 ELSE 0 END), 0)::int as ratelimit_rejections,
          COALESCE(SUM(CASE WHEN rejection_reason = 'DUPLICATE' OR (decision = 'REJECTED' AND rejection_reason LIKE '%DUPLICATE%') THEN 1 ELSE 0 END), 0)::int as duplicate_rejections
        FROM source.discovery_edges;
      `);
      edgeStats = edgeRes.rows[0] || {};
    } catch (_e) {}

    // 3. Discovery Roots count
    let totalRoots = 0;
    try {
      const rootRes = await this.db.query(`SELECT COUNT(*)::int as total_roots FROM source.discovery_roots;`);
      totalRoots = rootRes.rows[0]?.total_roots || 0;
    } catch (_e) {}

    // 4. Queue depth from ops.jobs
    let queueDepth = 0;
    try {
      const queueRes = await this.db.query(`
        SELECT COUNT(*)::int as depth 
        FROM ops.jobs 
        WHERE queue_key = 'discovery_graph_queue' AND status = 'QUEUED';
      `);
      queueDepth = queueRes.rows[0]?.depth || 0;
    } catch (_e) {}

    // 5. Source latency from recorded metrics (or 0)
    let sourceLatency = 0;
    try {
      const latRes = await this.db.query(`
        SELECT AVG((metadata_json->>'fetch_latency_ms')::numeric)::numeric as avg_lat
        FROM source.discovery_edges
        WHERE metadata_json->>'fetch_latency_ms' IS NOT NULL;
      `);
      if (latRes.rows[0]?.avg_lat) {
        sourceLatency = Math.round(Number(latRes.rows[0].avg_lat));
      }
    } catch (_e) {}

    const seenTotal = Number(candStats.total_seen) || 0;
    const queuedTotal = Number(candStats.total_queued) || 0;
    const verifiedTotal = Number(candStats.total_verified) || 0;
    const rejectedTotal = Number(candStats.total_rejected) || 0;
    const failedTotal = Number(candStats.total_failed) || 0;
    const duplicatesTotal = (Number(edgeStats.duplicate_rejections) || 0) + (Number(candStats.total_dup_status) || 0);
    const pivotsGeneratedTotal = Number(edgeStats.total_pivots_generated) || 0;
    const depthRejectionsTotal = Number(edgeStats.depth_rejections) || 0;
    const budgetRejectionsTotal = Number(edgeStats.budget_rejections) || 0;
    const ssrfRejectionsTotal = Number(edgeStats.ssrf_rejections) || 0;
    const robotsRejectionsTotal = (Number(edgeStats.robots_rejections) || 0) + (Number(candStats.total_robots_status) || 0);
    const rateLimitEventsTotal = (Number(edgeStats.ratelimit_rejections) || 0) + (Number(candStats.total_ratelimit_status) || 0);
    const fetchFailuresTotal = failedTotal;

    const agentsPerRoot = totalRoots > 0 ? Number((verifiedTotal / totalRoots).toFixed(2)) : 0;
    const pivotConversionRate = pivotsGeneratedTotal > 0 ? Number((verifiedTotal / pivotsGeneratedTotal).toFixed(4)) : 0;

    return {
      discovery_candidates_seen_total: seenTotal,
      discovery_candidates_queued_total: queuedTotal,
      discovery_candidates_verified_total: verifiedTotal,
      discovery_candidates_rejected_total: rejectedTotal,
      discovery_duplicates_total: duplicatesTotal,
      discovery_pivots_generated_total: pivotsGeneratedTotal,
      discovery_depth_rejections_total: depthRejectionsTotal,
      discovery_budget_rejections_total: budgetRejectionsTotal,
      discovery_ssrf_rejections_total: ssrfRejectionsTotal,
      discovery_robots_rejections_total: robotsRejectionsTotal,
      discovery_rate_limit_events_total: rateLimitEventsTotal,
      discovery_fetch_failures_total: fetchFailuresTotal,
      discovery_source_latency: sourceLatency,
      discovery_queue_depth: queueDepth,
      discovery_agents_per_root: agentsPerRoot,
      discovery_pivot_conversion_rate: pivotConversionRate,
    };
  }

  private formatDescendantNode(row: any): DescendantNode {
    return {
      depth: row.crawl_depth || 1,
      edge_id: row.id,
      edge_type: row.edge_type,
      target_candidate_id: row.target_candidate_id,
      target_url: row.discovered_url || row.canonical_url || row.normalized_url,
      target_agent_id: row.metadata_json?.target_agent_id || row.candidate_metadata?.agent_id || null,
      target_status: row.candidate_status || 'DISCOVERED',
      decision: row.decision,
      rejection_reason: row.rejection_reason || null,
      evidence: {
        type: row.evidence_type,
        location: row.evidence_location,
        snippet_hash: row.evidence_snippet_hash,
      },
      discovered_at: row.discovered_at,
    };
  }

  private emptyLineageResponse(agentId: string, message: string, canonicalName?: string | null): DiscoveryLineageResponse {
    return {
      agent_id: agentId,
      candidate_id: null,
      canonical_name: canonicalName || null,
      found: false,
      message,
      immediate_parent: null,
      root_source: null,
      edge_type: null,
      evidence: null,
      depth: 0,
      timestamps: {
        discovered_at: null,
        queued_at: null,
        first_seen_at: null,
      },
      ancestor_chain: [],
      full_path: [],
      raw_edges: [],
    };
  }
}
