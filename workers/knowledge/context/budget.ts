import { ContextBudgetConfig, SerializedFact } from './types.ts';

export const DEFAULT_CONTEXT_BUDGET: ContextBudgetConfig = {
  max_total_tokens: 4000,
  max_exact_tokens: 1200,
  max_ontology_tokens: 800,
  max_lineage_tokens: 1200,
  max_vector_tokens: 800,
  chars_per_token: 4,
};

export class ContextBudgetManager {
  private config: ContextBudgetConfig;

  constructor(customConfig?: Partial<ContextBudgetConfig>) {
    this.config = { ...DEFAULT_CONTEXT_BUDGET, ...customConfig };
  }

  public estimateTokens(text: string): number {
    if (!text) return 0;
    const charsPerToken = this.config.chars_per_token || 4;
    return Math.ceil(text.length / charsPerToken);
  }

  public allocateFactsUnderBudget(facts: SerializedFact[]): {
    allocatedFacts: SerializedFact[];
    prunedFacts: SerializedFact[];
    totalTokens: number;
    budgetUtilization: number;
  } {
    const allocated: SerializedFact[] = [];
    const pruned: SerializedFact[] = [];

    // Track tokens by bucket
    const bucketTokens: Record<string, number> = {
      RELATIONAL_EXACT: 0,
      GRAPH_ONTOLOGY: 0,
      EVIDENCE_LINEAGE: 0,
      VECTOR_SEMANTIC: 0,
      OTHER: 0,
    };
    let totalTokens = 0;

    // Priority sorting:
    // 1. Relational Exact & Evidence Lineage
    // 2. Graph Ontology
    // 3. Vector Semantic
    const sortedFacts = [...facts].sort((a, b) => {
      const priorityOrder: Record<string, number> = {
        RELATIONAL_EXACT: 1,
        EVIDENCE_LINEAGE: 2,
        GRAPH_ONTOLOGY: 3,
        VECTOR_SEMANTIC: 4,
      };
      const prioA = priorityOrder[a.source_retriever] || 5;
      const prioB = priorityOrder[b.source_retriever] || 5;
      return prioA - prioB;
    });

    for (const fact of sortedFacts) {
      const factTokens = fact.token_estimate || this.estimateTokens(fact.formatted_content);
      const bucket = fact.source_retriever in bucketTokens ? fact.source_retriever : 'OTHER';

      // Check bucket-specific ceiling
      let bucketLimit = this.config.max_total_tokens;
      if (bucket === 'RELATIONAL_EXACT') bucketLimit = this.config.max_exact_tokens;
      else if (bucket === 'GRAPH_ONTOLOGY') bucketLimit = this.config.max_ontology_tokens;
      else if (bucket === 'EVIDENCE_LINEAGE') bucketLimit = this.config.max_lineage_tokens;
      else if (bucket === 'VECTOR_SEMANTIC') bucketLimit = this.config.max_vector_tokens;

      if (
        totalTokens + factTokens <= this.config.max_total_tokens &&
        bucketTokens[bucket] + factTokens <= bucketLimit
      ) {
        allocated.push(fact);
        totalTokens += factTokens;
        bucketTokens[bucket] += factTokens;
      } else {
        pruned.push(fact);
      }
    }

    const budgetUtilization = totalTokens / (this.config.max_total_tokens || 1);

    return {
      allocatedFacts: allocated,
      prunedFacts: pruned,
      totalTokens,
      budgetUtilization,
    };
  }
}
