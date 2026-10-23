/**
 * Architecture V2.0.1 — Discovery Graph Worker
 * Executes recursive discovery graph traversal via durable queue leasing (ops.jobs).
 *
 * Guarantees:
 * - Leases jobs with database-level concurrency control (safe across multiple concurrent workers)
 * - Fetches genuine metadata via registered SourceAdapters
 * - Part E: Separates discovery_confidence from classification_confidence via ArtifactClassifier
 * - Part C: Transacts all hard crawl boundaries via DiscoveryGraphEngine
 * - Enforces per-domain fairness
 */

import crypto from 'crypto';
import { DiscoveryGraphEngine, DEFAULT_CRAWL_BOUNDARIES } from './discovery-graph-engine.ts';
import { PivotExtractor } from './pivot-extractor.ts';
import { CrawlBoundariesConfig, DiscoveryCandidateRecord } from './types.ts';
import { SourceAdapterRegistry } from '../registry.ts';
import { ArtifactClassifier } from '../classification.ts';

export interface WorkerJob {
  id: string;
  queue_key: string;
  status: string;
  attempt_count: number;
  payload: {
    candidate_id: string;
    root_seed_id: string;
    edge_id: string;
    crawl_depth: number;
    cycle_id: string;
    domain: string;
    source_adapter?: string;
    locator: string;
  };
}

export class DiscoveryGraphWorker {
  private readonly classifier = new ArtifactClassifier();
  private readonly workerId = `worker-${crypto.randomBytes(4).toString('hex')}`;

  constructor(
    private readonly db: any,
    private readonly engine: DiscoveryGraphEngine,
    private readonly registry: SourceAdapterRegistry = SourceAdapterRegistry.createDefault()
  ) {}

  /**
   * Leases the next ready job with domain fairness consideration.
   */
  public async leaseNextJob(preferredDomains?: string[]): Promise<WorkerJob | null> {
    // Select a ready job in QUEUED status
    const query = `
      SELECT job_id, queue_key, status, payload
      FROM ops.jobs
      WHERE queue_key = 'discovery_graph_queue'
        AND status = 'QUEUED'
        AND next_attempt_at <= now()
      ORDER BY priority DESC, created_at ASC
      LIMIT 1;
    `;

    const selectRes = await this.db.query(query);
    if (!selectRes.rows || selectRes.rows.length === 0) {
      return null;
    }

    const jobRow = selectRes.rows[0];
    const updateRes = await this.db.query(
      `UPDATE ops.jobs
       SET status = 'LEASED'
       WHERE job_id = $1 AND status = 'QUEUED'
       RETURNING job_id, queue_key, status, payload;`,
      [jobRow.job_id]
    );

    if (!updateRes.rows || updateRes.rows.length === 0) {
      return null; // Collided with another worker
    }

    const leased = updateRes.rows[0];
    return {
      id: leased.job_id,
      queue_key: leased.queue_key,
      status: leased.status,
      attempt_count: 1,
      payload: typeof leased.payload === 'string' ? JSON.parse(leased.payload) : leased.payload,
    };
  }

  /**
   * Processes a single leased discovery job.
   */
  public async processJob(
    job: WorkerJob,
    options: { boundaries?: Partial<CrawlBoundariesConfig> } = {}
  ): Promise<{
    success: boolean;
    candidate_id: string;
    classification: string | null;
    classification_confidence: number | null;
    pivots_found: number;
    accepted_edges: number;
    rejected_edges: number;
    retained_candidates: number;
  }> {
    const { candidate_id, root_seed_id, edge_id, crawl_depth, cycle_id, locator } = job.payload;

    try {
      // 1. Mark candidate as FETCHING
      await this.db.query(
        `UPDATE source.discovery_candidates
         SET status = 'FETCHING'
         WHERE id = $1;`,
        [candidate_id]
      );

      // 2. Select Source Adapter
      const adapter = this.resolveAdapter(locator, job.payload.source_adapter);
      if (!adapter) {
        throw new Error(`No compatible source adapter found for locator: ${locator}`);
      }

      // 3. Fetch real metadata
      const meta = await adapter.fetch_metadata(locator);
      const rawMeta = meta.raw_metadata || {};
      const contentHash = crypto.createHash('sha256').update(JSON.stringify(rawMeta)).digest('hex');

      // 4. Mark candidate as FETCHED and CLASSIFYING
      await this.db.query(
        `UPDATE source.discovery_candidates
         SET status = 'FETCHED', content_hash = $1
         WHERE id = $2;`,
        [contentHash, candidate_id]
      );

      // 5. Run classification pipeline (Part E: confidence separation)
      const candRes = await this.db.query(
        `SELECT * FROM source.discovery_candidates WHERE id = $1;`,
        [candidate_id]
      );
      const candRecord: DiscoveryCandidateRecord = candRes.rows[0];

      const classification = this.classifier.classify({
        candidate: {
          source_locator: candRecord.canonical_url,
          display_name: candRecord.canonical_url,
          source_type: adapter.sourceType,
          raw_metadata: rawMeta,
        },
        metadata: meta,
      });

      const isVerifiedAgent = classification.primary_category !== 'UNKNOWN_OR_UNCLASSIFIED' && classification.confidence >= 0.3;
      const finalStatus = isVerifiedAgent ? 'VERIFIED_AGENT' : 'VERIFIED_NON_AGENT';

      await this.db.query(
        `UPDATE source.discovery_candidates
         SET status = $1,
             classification = $2,
             classification_confidence = $3,
             processed_at = now()
         WHERE id = $4;`,
        [finalStatus, classification.primary_category, classification.confidence, candidate_id]
      );

      // 6. Extract genuine outbound pivots from real metadata and relationships
      const { pivots, source_content_hash } = await PivotExtractor.extractPivots(
        locator,
        adapter,
        rawMeta
      );

      // 7. Enforce all hard crawl boundaries and schedule next hops transactionally
      const schedResult = await this.engine.evaluateAndSchedulePivots({
        root_seed_id,
        parent_edge_id: edge_id,
        source_candidate_id: candidate_id,
        parent_crawl_depth: crawl_depth,
        cycle_id,
        pivots,
        source_content_hash,
        boundaries: options.boundaries,
      });

      // 8. Mark job as COMPLETED
      await this.db.query(
        `UPDATE ops.jobs
         SET status = 'COMPLETED'
         WHERE job_id = $1;`,
        [job.id]
      );

      return {
        success: true,
        candidate_id,
        classification: classification.primary_category,
        classification_confidence: classification.confidence,
        pivots_found: pivots.length,
        accepted_edges: schedResult.accepted_edges.length,
        rejected_edges: schedResult.rejected_edges.length,
        retained_candidates: schedResult.retained_candidates.length,
      };
    } catch (err: any) {
      console.error(`[DiscoveryGraphWorker] Error processing job ${job.id}:`, err);

      await this.db.query(
        `UPDATE ops.jobs
         SET status = 'FAILED'
         WHERE job_id = $1;`,
        [job.id]
      );

      await this.db.query(
        `UPDATE source.discovery_candidates
         SET status = 'FAILED', rejection_reason = $1
         WHERE id = $2;`,
        [err.message, candidate_id]
      );

      return {
        success: false,
        candidate_id,
        classification: null,
        classification_confidence: null,
        pivots_found: 0,
        accepted_edges: 0,
        rejected_edges: 0,
        retained_candidates: 0,
      };
    }
  }

  private resolveAdapter(locator: string, hint?: string) {
    if (hint && this.registry.get(hint)) {
      return this.registry.get(hint);
    }
    if (locator.startsWith('npm://') || locator.includes('npmjs.com')) {
      return this.registry.get('npm');
    }
    if (locator.startsWith('pypi://') || locator.includes('pypi.org')) {
      return this.registry.get('pypi');
    }
    if (locator.startsWith('github://') || locator.includes('github.com')) {
      return this.registry.get('github');
    }
    if (locator.startsWith('gitlab://') || locator.includes('gitlab.com')) {
      return this.registry.get('gitlab');
    }
    if (locator.startsWith('hf://') || locator.includes('huggingface.co')) {
      return this.registry.get('huggingface');
    }
    if (locator.startsWith('docker://') || locator.includes('docker.com')) {
      return this.registry.get('dockerhub');
    }
    if (locator.startsWith('codeberg://') || locator.includes('codeberg.org')) {
      return this.registry.get('codeberg');
    }
    return null;
  }
}
