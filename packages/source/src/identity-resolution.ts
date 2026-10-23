import crypto from 'crypto';
import {
  IdentityResolutionOutcome,
  IdentityEvidenceScore,
  IdentityComparisonResult,
  IdentityCandidateGraph,
  IdentityCandidateNode,
  IdentityCandidateEdge,
  ArtifactClassification,
} from './types.ts';
import { ProvenanceRecord, ProvenanceRecordSchema } from '../../contracts/src/provenance.ts';

export interface EntityObservation {
  source_locator: string;
  source_type: string;
  display_name?: string;
  publisher?: string;
  repository_url?: string;
  homepage_url?: string;
  version?: string;
  checksums?: string[];
  classification?: ArtifactClassification;
  raw_metadata?: Record<string, unknown>;
  relationships?: Array<{ target_locator: string; relationship_type: string }>;
}

export class IdentityResolver {
  readonly resolverVersion = '1.0.0';

  /**
   * Compares two entity observations and evaluates identity evidence to derive resolution outcome.
   */
  compare(a: EntityObservation, b: EntityObservation): IdentityComparisonResult {
    // 1. Compute granular evidence dimensions
    const pubScore = this.evaluatePublisherMatch(a, b);
    const repoScore = this.evaluateRepoMatch(a, b);
    const homeScore = this.evaluateHomepageMatch(a, b);
    const manifestScore = this.evaluateManifestMatch(a, b);
    const checksumScore = this.evaluateChecksumMatch(a, b);
    const distScore = this.evaluateDistributionMatch(a, b);
    const simScore = this.evaluateSimilarity(a, b);

    const details: string[] = [];
    if (pubScore > 0.7) details.push(`Publisher match (${(pubScore * 100).toFixed(0)}%)`);
    if (repoScore > 0.7) details.push(`Repository reference match (${(repoScore * 100).toFixed(0)}%)`);
    if (homeScore > 0.7) details.push(`Homepage match (${(homeScore * 100).toFixed(0)}%)`);
    if (checksumScore > 0.9) details.push(`Artifact checksum identity match (${(checksumScore * 100).toFixed(0)}%)`);
    if (distScore > 0.7) details.push(`Cross-distribution linkage (${(distScore * 100).toFixed(0)}%)`);

    // Weighted composite confidence
    let composite = Number((
      pubScore * 0.20 +
      repoScore * 0.25 +
      homeScore * 0.15 +
      manifestScore * 0.15 +
      checksumScore * 0.15 +
      simScore * 0.10
    ).toFixed(3));

    const evidence: IdentityEvidenceScore = {
      publisher_match: pubScore,
      repo_match: repoScore,
      homepage_match: homeScore,
      manifest_match: manifestScore,
      checksum_match: checksumScore,
      distribution_match: distScore,
      similarity_score: simScore,
      composite_confidence: composite,
      details,
    };

    // Check relationship links
    const aLinksToB = a.relationships?.some(r => r.target_locator === b.source_locator);
    const bLinksToA = b.relationships?.some(r => r.target_locator === a.source_locator);
    const isFork = (a.relationships?.some(r => r.relationship_type === 'FORK_OF' && r.target_locator === b.source_locator)) ||
                 (b.relationships?.some(r => r.relationship_type === 'FORK_OF' && r.target_locator === a.source_locator)) ||
                 (a.raw_metadata?.fork === true && b.source_locator.includes((a.raw_metadata?.parent as any)?.full_name || '___'));

    // Check for mirror
    const isMirror = checksumScore === 1.0 && a.source_type !== b.source_type && simScore >= 0.9;

    let outcome: IdentityResolutionOutcome = 'DISTINCT';
    let isProvisional = false;
    const conflictReasons: string[] = [];

    if (a.source_locator === b.source_locator) {
      composite = 1.0;
      evidence.composite_confidence = 1.0;
      outcome = 'SAME_CANONICAL_AGENT';
    } else if (isMirror) {
      outcome = 'MIRROR';
    } else if (isFork) {
      outcome = 'FORK_OR_DERIVATIVE';
    } else if (checksumScore === 1.0 || repoScore === 1.0 || (pubScore >= 0.8 && manifestScore >= 0.85)) {
      // Check version differences
      const hasDiffVersions = a.version && b.version && a.version !== b.version;
      const isDiffDistribution = a.source_type !== b.source_type;

      if (hasDiffVersions) {
        outcome = 'SAME_AGENT_DIFFERENT_VERSION';
      } else if (isDiffDistribution) {
        outcome = 'SAME_AGENT_DIFFERENT_DISTRIBUTION';
      } else {
        outcome = 'SAME_CANONICAL_AGENT';
      }
    } else if (pubScore >= 0.7 && (aLinksToB || bLinksToA || simScore >= 0.6)) {
      outcome = 'RELATED_ENTITY';
    } else if (simScore >= 0.75 && pubScore < 0.3) {
      // Ambiguity / Conflict: High textual similarity but conflicting publishers
      outcome = 'UNRESOLVED';
      isProvisional = true;
      conflictReasons.push('High similarity in name/summary but mismatched publisher credentials');
    } else if (composite >= 0.40 && composite < 0.75) {
      outcome = 'UNRESOLVED';
      isProvisional = true;
      conflictReasons.push(`Insufficient composite confidence (${(composite * 100).toFixed(0)}%) for automated resolution`);
    } else {
      outcome = 'DISTINCT';
    }

    const inputHash = crypto.createHash('sha256')
      .update(`${a.source_locator}<=>${b.source_locator}:${outcome}`)
      .digest('hex');

    const provenance: ProvenanceRecord = ProvenanceRecordSchema.parse({
      provenance_id: crypto.randomUUID(),
      source_spans: [],
      input_hashes: [inputHash],
      rule_id: `IDENTITY_RESOLUTION_${outcome}`,
      ruleset_version: this.resolverVersion,
      transformation_type: 'CALIBRATED_INFERENCE',
      confidence: Math.max(0.5, composite),
      derived_at: new Date().toISOString(),
      engine_signature: `caim:identity-resolver:v${this.resolverVersion}`,
    });

    return {
      source_a_locator: a.source_locator,
      source_b_locator: b.source_locator,
      outcome,
      confidence: Math.max(0.3, composite),
      evidence,
      is_provisional: isProvisional,
      conflict_reasons: conflictReasons.length > 0 ? conflictReasons : undefined,
      resolved_at: new Date().toISOString(),
      provenance,
    };
  }

  /**
   * Resolves multiple source observations into a Canonical Candidate Graph without destroying ambiguity.
   */
  buildCandidateGraph(observations: EntityObservation[]): IdentityCandidateGraph {
    const nodes: IdentityCandidateNode[] = [];
    const edges: IdentityCandidateEdge[] = [];
    let unresolvedCount = 0;

    // Track clustering groups
    const clusters: Array<{
      canonicalId: string;
      primaryLocator: string;
      canonicalName: string;
      observations: EntityObservation[];
      isCanonical: boolean;
      provisional: boolean;
    }> = [];

    for (const obs of observations) {
      let assigned = false;

      for (const cluster of clusters) {
        const comparison = this.compare(obs, cluster.observations[0]);

        if (
          comparison.outcome === 'SAME_CANONICAL_AGENT' ||
          comparison.outcome === 'SAME_AGENT_DIFFERENT_VERSION' ||
          comparison.outcome === 'SAME_AGENT_DIFFERENT_DISTRIBUTION' ||
          comparison.outcome === 'MIRROR'
        ) {
          cluster.observations.push(obs);
          edges.push({
            from: obs.source_locator,
            to: cluster.observations[0].source_locator,
            outcome: comparison.outcome,
            confidence: comparison.confidence,
            evidence_summary: comparison.evidence.details.join(', ') || 'Identified equivalent entity',
            provenance_id: comparison.provenance.provenance_id,
          });
          assigned = true;
          break;
        } else if (comparison.outcome === 'FORK_OR_DERIVATIVE' || comparison.outcome === 'RELATED_ENTITY') {
          edges.push({
            from: obs.source_locator,
            to: cluster.observations[0].source_locator,
            outcome: comparison.outcome,
            confidence: comparison.confidence,
            evidence_summary: comparison.evidence.details.join(', ') || 'Related entity link',
            provenance_id: comparison.provenance.provenance_id,
          });
        } else if (comparison.outcome === 'UNRESOLVED') {
          unresolvedCount++;
          edges.push({
            from: obs.source_locator,
            to: cluster.observations[0].source_locator,
            outcome: 'UNRESOLVED',
            confidence: comparison.confidence,
            evidence_summary: comparison.conflict_reasons?.join('; ') || 'Ambiguous identity evidence',
            provenance_id: comparison.provenance.provenance_id,
          });
        }
      }

      if (!assigned) {
        const canonicalId = `cand-node-${crypto.createHash('sha256').update(obs.source_locator).digest('hex').substring(0, 12)}`;
        clusters.push({
          canonicalId,
          primaryLocator: obs.source_locator,
          canonicalName: obs.display_name || obs.source_locator,
          observations: [obs],
          isCanonical: true,
          provisional: false,
        });
      }
    }

    // Convert clusters to graph nodes
    for (const cluster of clusters) {
      const locators = cluster.observations.map(o => o.source_locator);
      const sources = Array.from(new Set(cluster.observations.map(o => o.source_type)));
      const versions = Array.from(new Set(cluster.observations.map(o => o.version).filter(Boolean) as string[]));
      const classifications = cluster.observations.map(o => o.classification?.primary_category).filter(Boolean);
      const primaryClassification = classifications[0] || 'AUTONOMOUS_AGENT';

      nodes.push({
        id: cluster.canonicalId,
        locators,
        primary_locator: cluster.primaryLocator,
        canonical_name: cluster.canonicalName,
        classification: primaryClassification as any,
        sources,
        versions,
        distributions: sources,
        metadata_summary: {
          total_observations: cluster.observations.length,
          locators,
        },
        confidence: 0.95,
        is_canonical: cluster.isCanonical,
        provisional: cluster.provisional,
      });
    }

    const inputHash = crypto.createHash('sha256')
      .update(nodes.map(n => n.id).join(','))
      .digest('hex');

    const graph_provenance: ProvenanceRecord = ProvenanceRecordSchema.parse({
      provenance_id: crypto.randomUUID(),
      source_spans: [],
      input_hashes: [inputHash],
      rule_id: 'CANONICAL_CANDIDATE_GRAPH_BUILD_V1',
      ruleset_version: this.resolverVersion,
      transformation_type: 'SYNTAX_TRANSFORMATION',
      confidence: 0.95,
      derived_at: new Date().toISOString(),
      engine_signature: `caim:candidate-graph:v${this.resolverVersion}`,
    });

    return {
      nodes,
      edges,
      unresolved_conflicts_count: unresolvedCount,
      graph_provenance,
    };
  }

  // --- Sub-dimension evaluators ---

  private evaluatePublisherMatch(a: EntityObservation, b: EntityObservation): number {
    const pubA = (a.publisher || '').toLowerCase().trim();
    const pubB = (b.publisher || '').toLowerCase().trim();
    if (!pubA || !pubB) return 0.5;
    if (pubA === pubB) return 1.0;
    if (pubA.includes(pubB) || pubB.includes(pubA)) return 0.85;
    return 0.0;
  }

  private evaluateRepoMatch(a: EntityObservation, b: EntityObservation): number {
    const repoA = this.normalizeRepoUrl(a.repository_url || a.source_locator);
    const repoB = this.normalizeRepoUrl(b.repository_url || b.source_locator);
    if (!repoA || !repoB) return 0.5;
    if (repoA === repoB) return 1.0;
    return 0.0;
  }

  private evaluateHomepageMatch(a: EntityObservation, b: EntityObservation): number {
    const homeA = (a.homepage_url || '').toLowerCase().trim();
    const homeB = (b.homepage_url || '').toLowerCase().trim();
    if (!homeA || !homeB) return 0.5;
    if (homeA === homeB) return 1.0;
    return 0.0;
  }

  private evaluateManifestMatch(a: EntityObservation, b: EntityObservation): number {
    const nameA = this.normalizeName(a.display_name || a.source_locator);
    const nameB = this.normalizeName(b.display_name || b.source_locator);
    if (nameA === nameB) return 1.0;
    if (nameA.includes(nameB) || nameB.includes(nameA)) return 0.85;
    return 0.0;
  }

  private evaluateChecksumMatch(a: EntityObservation, b: EntityObservation): number {
    if (!a.checksums?.length || !b.checksums?.length) return 0.5;
    const match = a.checksums.some(ca => b.checksums!.includes(ca));
    return match ? 1.0 : 0.0;
  }

  private evaluateDistributionMatch(a: EntityObservation, b: EntityObservation): number {
    const distTypes = ['pypi', 'npm', 'dockerhub', 'huggingface', 'github', 'gitlab', 'codeberg'];
    const hasDistA = distTypes.includes(a.source_type);
    const hasDistB = distTypes.includes(b.source_type);
    if (hasDistA && hasDistB && a.source_type !== b.source_type) {
      return 0.8;
    }
    return 0.5;
  }

  private evaluateSimilarity(a: EntityObservation, b: EntityObservation): number {
    const nameA = this.normalizeName(a.display_name || a.source_locator);
    const nameB = this.normalizeName(b.display_name || b.source_locator);
    if (nameA === nameB) return 1.0;

    const wordsA = new Set(nameA.split(/[-_/ ]+/));
    const wordsB = new Set(nameB.split(/[-_/ ]+/));
    const intersection = new Set([...wordsA].filter(x => wordsB.has(x)));
    const union = new Set([...wordsA, ...wordsB]);

    return union.size > 0 ? Number((intersection.size / union.size).toFixed(2)) : 0;
  }

  private normalizeName(name: string): string {
    return name.toLowerCase()
      .replace(/^(github|gitlab|pypi|npm|hf|docker|codeberg):\/\//, '')
      .replace(/^https?:\/\/[^/]+\//, '')
      .replace(/[@#]/g, '')
      .replace(/[-_.]+/g, ' ')
      .trim();
  }

  private normalizeRepoUrl(url?: string): string {
    if (!url) return '';
    return url.toLowerCase()
      .replace(/\.git$/, '')
      .replace(/^git\+/, '')
      .replace(/^https?:\/\//, '')
      .replace(/^(github|gitlab|codeberg):\/\//, '')
      .replace(/\/$/, '');
  }
}
