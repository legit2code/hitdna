import { RetrievedDocument } from './types.ts';

export interface RerankingWeights {
  relevance: number;
  exactness: number;
  evidence_strength: number;
  freshness: number;
  authority: number;
}

export const DEFAULT_RERANK_WEIGHTS: RerankingWeights = {
  relevance: 0.35,
  exactness: 0.25,
  evidence_strength: 0.15,
  freshness: 0.10,
  authority: 0.15,
};

export class HybridFusionReranker {
  /**
   * Performs deduplication by knowledge object id / entity ref id
   * and calculates multi-factor final rerank score.
   */
  public static fuseAndRerank(
    documents: RetrievedDocument[],
    maxResults: number = 20,
    weights: RerankingWeights = DEFAULT_RERANK_WEIGHTS
  ): RetrievedDocument[] {
    const dedupMap = new Map<string, RetrievedDocument>();

    for (const doc of documents) {
      const key = `${doc.object_type}:${doc.entity_ref_id}`;
      const existing = dedupMap.get(key);

      if (!existing) {
        dedupMap.set(key, { ...doc });
      } else {
        // Merge & boost multi-retriever hit
        existing.relevance_score = Math.max(existing.relevance_score, doc.relevance_score) + 0.05;
        existing.exactness_score = Math.max(existing.exactness_score, doc.exactness_score);
        existing.evidence_strength = Math.max(existing.evidence_strength, doc.evidence_strength);
        existing.authority_score = Math.max(existing.authority_score, doc.authority_score);
        if (doc.lineage_trail && doc.lineage_trail.length > (existing.lineage_trail?.length || 0)) {
          existing.lineage_trail = doc.lineage_trail;
        }
      }
    }

    const uniqueDocs = Array.from(dedupMap.values());

    for (const doc of uniqueDocs) {
      const score =
        (doc.relevance_score * weights.relevance) +
        (doc.exactness_score * weights.exactness) +
        (doc.evidence_strength * weights.evidence_strength) +
        (doc.freshness_score * weights.freshness) +
        (doc.authority_score * weights.authority);

      doc.final_rerank_score = Number(score.toFixed(4));
    }

    // Sort by final rerank score descending
    uniqueDocs.sort((a, b) => b.final_rerank_score - a.final_rerank_score);

    return uniqueDocs.slice(0, maxResults);
  }
}
