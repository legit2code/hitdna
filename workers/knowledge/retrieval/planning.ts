import { 
  QueryUnderstandingResult, 
  RetrievalPlan 
} from './types.ts';
import { SecurityClassificationRank } from '@caim/auth/types.ts';

export class RetrievalPlanner {
  /**
   * Generates a typed RetrievalPlan configured for the specific intent,
   * security rank boundary, and cost ceiling.
   */
  public static createPlan(
    understanding: QueryUnderstandingResult,
    options: {
      max_security_rank?: SecurityClassificationRank;
      allow_vault_restricted?: boolean;
      budget_max_records?: number;
      budget_max_tokens?: number;
      composition_safe_only?: boolean;
      allowed_risk_bands?: Array<'LOW' | 'LOW_RISK' | 'MEDIUM' | 'HIGH' | 'HIGH_RISK' | 'CRITICAL'>;
      allowed_lifecycle_statuses?: string[];
    } = {}
  ): RetrievalPlan {
    const max_security_rank = options.max_security_rank ?? SecurityClassificationRank.PUBLIC_METADATA;
    const allow_vault_restricted = options.allow_vault_restricted ?? false;
    const budget_max_records = options.budget_max_records ?? 25;
    const budget_max_tokens = options.budget_max_tokens ?? 8192;
    const composition_safe_only = options.composition_safe_only ?? false;
    const allowed_risk_bands = options.allowed_risk_bands;
    const allowed_lifecycle_statuses = options.allowed_lifecycle_statuses;

    const modes: Array<'RELATIONAL_EXACT' | 'VECTOR_SEMANTIC' | 'GRAPH_ONTOLOGY' | 'EVIDENCE_LINEAGE'> = [];
    const top_k = {
      relational: 0,
      vector: 0,
      graph: 0,
      lineage: 0,
    };

    switch (understanding.intent) {
      case 'EXACT_LOOKUP':
        modes.push('RELATIONAL_EXACT', 'VECTOR_SEMANTIC');
        top_k.relational = 10;
        top_k.vector = 5;
        break;

      case 'EVIDENCE_LINEAGE':
        modes.push('EVIDENCE_LINEAGE', 'RELATIONAL_EXACT', 'VECTOR_SEMANTIC');
        top_k.lineage = 10;
        top_k.relational = 5;
        top_k.vector = 5;
        break;

      case 'ONTOLOGY_TRAVERSAL':
        modes.push('GRAPH_ONTOLOGY', 'VECTOR_SEMANTIC', 'RELATIONAL_EXACT');
        top_k.graph = 10;
        top_k.vector = 5;
        top_k.relational = 3;
        break;

      case 'VERSION_COMPARISON':
      case 'RISK_POLICY_STATUS':
        modes.push('RELATIONAL_EXACT', 'VECTOR_SEMANTIC', 'EVIDENCE_LINEAGE', 'GRAPH_ONTOLOGY');
        top_k.relational = 8;
        top_k.vector = 8;
        top_k.lineage = 6;
        top_k.graph = 4;
        break;

      case 'SEMANTIC_QUESTION':
      default:
        modes.push('RELATIONAL_EXACT', 'VECTOR_SEMANTIC', 'EVIDENCE_LINEAGE', 'GRAPH_ONTOLOGY');
        top_k.relational = 8;
        top_k.vector = 8;
        top_k.lineage = 6;
        top_k.graph = 4;
        break;
    }

    return {
      plan_id: `plan-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      query_understanding: understanding,
      retrieval_modes: modes,
      top_k_per_mode: top_k,
      hybrid_fusion_limit: budget_max_records,
      max_security_rank,
      allow_vault_restricted,
      budget_max_records,
      budget_max_tokens,
      composition_safe_only,
      allowed_risk_bands,
      allowed_lifecycle_statuses,
      created_at: new Date().toISOString(),
    };
  }
}
