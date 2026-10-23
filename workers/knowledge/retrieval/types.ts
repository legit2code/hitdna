import { 
  KnowledgeObjectType 
} from '../types.ts';
import { 
  SecurityClassificationCode, 
  SecurityClassificationRank 
} from '@caim/auth/types.ts';

export type QueryIntent =
  | 'EXACT_LOOKUP'
  | 'SEMANTIC_QUESTION'
  | 'ONTOLOGY_TRAVERSAL'
  | 'EVIDENCE_LINEAGE'
  | 'VERSION_COMPARISON'
  | 'RISK_POLICY_STATUS'
  | 'GENERAL_HYBRID';

export interface QueryUnderstandingResult {
  raw_query: string;
  normalized_query: string;
  intent: QueryIntent;
  extracted_entities: {
    cve_ids: string[];
    package_names: string[];
    symbols: string[];
    rule_ids: string[];
    claim_ids: string[];
    agent_names: string[];
    versions: string[];
  };
  temporal_filters?: {
    since?: string;
    until?: string;
  };
  scoped_agent_id?: string;
  scoped_agent_version_id?: string;
  resolved_ontology_concepts: string[];
  target_object_types: KnowledgeObjectType[];
  estimated_complexity: 'LOW' | 'MEDIUM' | 'HIGH';
  validated: boolean;
}

export interface RetrievalPlan {
  plan_id: string;
  query_understanding: QueryUnderstandingResult;
  retrieval_modes: Array<'RELATIONAL_EXACT' | 'VECTOR_SEMANTIC' | 'GRAPH_ONTOLOGY' | 'EVIDENCE_LINEAGE'>;
  top_k_per_mode: {
    relational: number;
    vector: number;
    graph: number;
    lineage: number;
  };
  hybrid_fusion_limit: number;
  max_security_rank: SecurityClassificationRank;
  allow_vault_restricted: boolean;
  budget_max_records: number;
  budget_max_tokens: number;
  composition_safe_only?: boolean;
  allowed_risk_bands?: Array<'LOW' | 'LOW_RISK' | 'MEDIUM' | 'HIGH' | 'HIGH_RISK' | 'CRITICAL'>;
  allowed_lifecycle_statuses?: string[];
  created_at: string;
}

export interface RetrievedDocument {
  doc_id: string;
  knowledge_object_id: string;
  entity_ref_id: string;
  object_type: KnowledgeObjectType;
  retriever_source: 'RELATIONAL_EXACT' | 'VECTOR_SEMANTIC' | 'GRAPH_ONTOLOGY' | 'EVIDENCE_LINEAGE';
  title: string;
  snippet: string;
  full_content: string;
  relevance_score: number;
  exactness_score: number;
  evidence_strength: number;
  freshness_score: number;
  authority_score: number;
  final_rerank_score: number;
  security_classification: SecurityClassificationCode;
  security_classification_rank: SecurityClassificationRank;
  vault_restricted: boolean;
  agent_id?: string | null;
  agent_version_id?: string | null;
  analysis_run_id?: string | null;
  exact_keywords: Record<string, any>;
  payload?: Record<string, any>;
  lineage_trail?: any;
}

export interface RetrievalExecutionAudit {
  query: string;
  caller_user_id?: string;
  caller_security_rank: SecurityClassificationRank;
  caller_has_vault_access: boolean;
  intent: QueryIntent;
  plan: RetrievalPlan;
  counts_by_retriever: {
    relational_exact: number;
    vector_semantic: number;
    graph_ontology: number;
    evidence_lineage: number;
  };
  filtered_out_unauthorized_count: number;
  fused_pre_rerank_count: number;
  final_returned_count: number;
  estimated_cost_units: number;
  duration_ms: number;
  timestamp: string;
}

export interface HybridRetrievalResult {
  documents: RetrievedDocument[];
  audit: RetrievalExecutionAudit;
}
