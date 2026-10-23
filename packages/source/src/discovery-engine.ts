import crypto from 'crypto';
import {
  SourceAdapter,
  DiscoveryCriteria,
  DiscoveryResult,
  DiscoveryCandidate,
  CursorState,
  SourceMetadataResult,
  ResolvedArtifactLocatorsResult,
  DiscoveryRelationshipsResult,
  AdapterHealth,
} from './types.ts';
import { SourceAdapterRegistry } from './registry.ts';
import { ProvenanceRecord, ProvenanceRecordSchema } from '../../contracts/src/provenance.ts';

export interface DiscoveryRunOptions {
  criteria: DiscoveryCriteria;
  sourceTypes?: string[];
  maxPagesPerSource?: number;
  maxCandidatesTotal?: number;
  correlationId?: string;
}

export interface DiscoveredEntityPackage {
  candidate: DiscoveryCandidate;
  metadata: SourceMetadataResult;
  artifacts: ResolvedArtifactLocatorsResult;
  relationships: DiscoveryRelationshipsResult;
  provenance: ProvenanceRecord;
}

export interface DiscoveryRunReport {
  runId: string;
  correlationId: string;
  startedAt: string;
  completedAt: string;
  status: 'COMPLETED' | 'PARTIAL' | 'FAILED';
  totalCandidates: number;
  sourceBreakdown: Record<string, {
    candidatesDiscovered: number;
    pagesFetched: number;
    hasMore: boolean;
    rateLimitRemaining: number;
  }>;
  packages: DiscoveredEntityPackage[];
  provenance: ProvenanceRecord;
}

/**
 * Source-Independent Discovery Engine.
 * 
 * Invariant: Contains ZERO source-specific branching.
 * Operates strictly on the polymorphic SourceAdapter contract.
 */
export class DiscoveryEngine {
  constructor(private readonly registry: SourceAdapterRegistry) {}

  /**
   * Discovers candidates across one or multiple registered sources in a source-independent manner.
   */
  async runDiscovery(options: DiscoveryRunOptions): Promise<DiscoveryRunReport> {
    const startedAt = new Date().toISOString();
    const runId = crypto.randomUUID();
    const correlationId = options.correlationId || `disc-run-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const maxPages = options.maxPagesPerSource ?? 1;
    const maxTotal = options.maxCandidatesTotal ?? 100;

    // Resolve target adapters without source-specific conditionals
    const targetAdapters: SourceAdapter[] = options.sourceTypes && options.sourceTypes.length > 0
      ? options.sourceTypes.map((st) => this.registry.mustGet(st))
      : this.registry.getAll();

    const report: DiscoveryRunReport = {
      runId,
      correlationId,
      startedAt,
      completedAt: '',
      status: 'COMPLETED',
      totalCandidates: 0,
      sourceBreakdown: {},
      packages: [],
      provenance: this.generateEngineProvenance('DISCOVERY_RUN', runId, correlationId),
    };

    const allDiscoveredCandidates: DiscoveryCandidate[] = [];

    // Polymorphically query each adapter
    for (const adapter of targetAdapters) {
      let currentPage = 1;
      let currentCursor: CursorState | null = null;
      let sourceCandidateCount = 0;
      let hasMore = true;

      report.sourceBreakdown[adapter.sourceType] = {
        candidatesDiscovered: 0,
        pagesFetched: 0,
        hasMore: false,
        rateLimitRemaining: adapter.get_rate_limit_state().remaining,
      };

      while (currentPage <= maxPages && hasMore && allDiscoveredCandidates.length < maxTotal) {
        try {
          const result: DiscoveryResult = await adapter.discover(options.criteria, currentCursor);
          report.sourceBreakdown[adapter.sourceType].pagesFetched++;

          for (const candidate of result.candidates) {
            allDiscoveredCandidates.push(candidate);
            sourceCandidateCount++;
            if (allDiscoveredCandidates.length >= maxTotal) break;
          }

          hasMore = result.has_more && result.next_cursor !== null;
          currentCursor = result.next_cursor;
          currentPage++;
        } catch (err) {
          // Record partial failure without halting other independent sources
          report.status = 'PARTIAL';
          hasMore = false;
        }
      }

      report.sourceBreakdown[adapter.sourceType].candidatesDiscovered = sourceCandidateCount;
      report.sourceBreakdown[adapter.sourceType].hasMore = hasMore;
      report.sourceBreakdown[adapter.sourceType].rateLimitRemaining = adapter.get_rate_limit_state().remaining;
    }

    report.totalCandidates = allDiscoveredCandidates.length;

    // Polymorphically enrich candidates into complete discovery entity packages
    for (const candidate of allDiscoveredCandidates) {
      const adapter = this.registry.mustGet(candidate.source_type);
      try {
        const [metadata, artifacts, relationships] = await Promise.all([
          adapter.fetch_metadata(candidate.source_locator),
          adapter.resolve_artifact_locators(candidate),
          adapter.enumerate_relationships(candidate),
        ]);

        report.packages.push({
          candidate,
          metadata,
          artifacts,
          relationships,
          provenance: this.generateEngineProvenance(
            'ENRICH_CANDIDATE',
            candidate.source_locator,
            metadata.content_hash
          ),
        });
      } catch (err) {
        report.status = 'PARTIAL';
      }
    }

    report.completedAt = new Date().toISOString();
    return report;
  }

  /**
   * Health checks all registered source adapters polymorphically.
   */
  async checkAllHealth(): Promise<Record<string, AdapterHealth>> {
    const healthMap: Record<string, AdapterHealth> = {};
    const adapters = this.registry.getAll();
    const results = await Promise.all(adapters.map(async (a) => ({
      sourceType: a.sourceType,
      health: await a.health_check(),
    })));

    for (const r of results) {
      healthMap[r.sourceType] = r.health;
    }
    return healthMap;
  }

  /**
   * Generates engine-level provenance records.
   */
  private generateEngineProvenance(action: string, subjectId: string, correlationId?: string): ProvenanceRecord {
    const record: ProvenanceRecord = {
      provenance_id: crypto.randomUUID(),
      source_spans: [],
      input_hashes: [crypto.createHash('sha256').update(`${subjectId}:${correlationId}`).digest('hex')],
      rule_id: `DISCOVERY_ENGINE_${action.toUpperCase()}`,
      ruleset_version: '1.0.0',
      transformation_type: 'DIRECT_EXTRACTION',
      confidence: 1.0,
      derived_at: new Date().toISOString(),
      engine_signature: 'caim:discovery-engine:v1.0.0',
    };
    return ProvenanceRecordSchema.parse(record);
  }
}
