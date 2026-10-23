import { 
  SecurityClassificationCode, 
  SecurityClassificationRank 
} from '@caim/auth/types.ts';

export type KnowledgeObjectType =
  | 'agent'
  | 'version'
  | 'run'
  | 'finding'
  | 'evidence'
  | 'claim'
  | 'risk'
  | 'policy'
  | 'recommendation'
  | 'use_case'
  | 'ontology'
  | 'dependency'
  | 'vulnerability'
  | 'package';

export const ALL_KNOWLEDGE_OBJECT_TYPES: KnowledgeObjectType[] = [
  'agent',
  'version',
  'run',
  'finding',
  'evidence',
  'claim',
  'risk',
  'policy',
  'recommendation',
  'use_case',
  'ontology',
  'dependency',
  'vulnerability',
  'package',
];

export interface KnowledgeObject {
  knowledge_object_id: string;
  entity_ref_id: string;
  object_type: KnowledgeObjectType;
  agent_id?: string | null;
  agent_version_id?: string | null;
  analysis_run_id?: string | null;
  security_classification_id: string;
  security_classification_code: SecurityClassificationCode;
  projection_version: string;
  source_data_hash: string;
  created_at: string;
  updated_at: string;
}

export interface KnowledgeProjection {
  knowledge_projection_id: string;
  knowledge_object_id: string;
  entity_ref_id: string;
  object_type: KnowledgeObjectType;
  projection_type: string;
  projection_version: string;
  agent_id?: string | null;
  agent_version_id?: string | null;
  analysis_run_id?: string | null;
  security_classification: SecurityClassificationCode;
  security_classification_rank: SecurityClassificationRank;
  vault_restricted: boolean;
  document_text: string;
  summary: string;
  payload: Record<string, any>;
  exact_keywords: Record<string, string | string[] | number | boolean>;
  content_hash: string;
  stale: boolean;
  indexed_at?: string | null;
  created_at: string;
}

export interface KnowledgeChunk {
  knowledge_chunk_id: string;
  knowledge_projection_id: string;
  knowledge_object_id: string;
  sequence: number;
  chunk_version: string;
  content_hash: string;
  text_content: string;
  token_count: number;
  agent_id?: string | null;
  agent_version_id?: string | null;
  analysis_run_id?: string | null;
  security_classification: SecurityClassificationCode;
  security_classification_rank: SecurityClassificationRank;
  vault_restricted: boolean;
  exact_keywords: Record<string, any>;
  created_at: string;
}

export interface EmbeddingRecord {
  embedding_id: string;
  knowledge_chunk_id: string;
  knowledge_object_id: string;
  embedding_model_version: string;
  dimensions: number;
  vector: number[];
  agent_id?: string | null;
  agent_version_id?: string | null;
  analysis_run_id?: string | null;
  security_classification: SecurityClassificationCode;
  security_classification_rank: SecurityClassificationRank;
  vault_restricted: boolean;
  exact_keywords: Record<string, any>;
  created_at: string;
}

export interface IndexState {
  index_state_id: string;
  knowledge_object_id: string;
  index_type: string;
  index_version: string;
  source_version_hash: string;
  stale: boolean;
  last_indexed_at: string;
}

export interface KnowledgeChangeEvent {
  event_id: string;
  event_type:
    | 'ENTITY_CREATED'
    | 'ENTITY_UPDATED'
    | 'ENTITY_DELETED'
    | 'ANALYSIS_RUN_COMPLETED'
    | 'FINDINGS_INGESTED'
    | 'RISK_EVALUATED'
    | 'POLICY_DECIDED'
    | 'VAULT_UPDATED';
  entity_ref_id: string;
  object_type: KnowledgeObjectType;
  agent_id?: string;
  agent_version_id?: string;
  analysis_run_id?: string;
  timestamp: string;
  payload?: any;
}

export interface IndexingEligibilityResult {
  eligible: boolean;
  reason?: string;
  vault_restricted: boolean;
  target_index: 'GENERAL_VECTOR_INDEX' | 'VAULT_RESTRICTED_INDEX' | 'NONE';
}

export interface EmbeddingOptions {
  taskType?: 'RETRIEVAL_DOCUMENT' | 'RETRIEVAL_QUERY' | 'SEMANTIC_SIMILARITY' | 'CLASSIFICATION';
  outputDimensionality?: number;
}

export interface EmbeddingResult {
  vector: number[];
  dimensions: number;
  tokenCount?: number;
  model: string;
}

export type EmbeddingProviderStatus = 'CONFIGURED' | 'NOT_CONFIGURED' | 'MOCK_TEST_ONLY';

export interface EmbeddingProvider {
  readonly modelName: string;
  readonly dimensions: number;
  readonly status?: EmbeddingProviderStatus;
  isConfigured?(): boolean;
  generateEmbedding(text: string, options?: EmbeddingOptions): Promise<EmbeddingResult>;
  generateEmbeddings(texts: string[], options?: EmbeddingOptions): Promise<EmbeddingResult[]>;
}

export interface VectorSearchQuery {
  query_text: string;
  query_vector?: number[];
  top_k?: number;
  min_similarity?: number;
  agent_id?: string;
  agent_version_id?: string;
  object_types?: KnowledgeObjectType[];
  max_security_rank: SecurityClassificationRank;
  allow_vault_restricted?: boolean;
  exact_filters?: Record<string, any>;
  hybrid_keyword_boost?: number;
}

export interface VectorSearchResult {
  chunk_id: string;
  knowledge_object_id: string;
  knowledge_projection_id: string;
  similarity_score: number;
  hybrid_score: number;
  text_snippet: string;
  object_type: KnowledgeObjectType;
  agent_id?: string | null;
  agent_version_id?: string | null;
  security_classification: SecurityClassificationCode;
  vault_restricted: boolean;
  exact_keywords: Record<string, any>;
}

export interface StaleIndexReport {
  timestamp: string;
  total_objects: number;
  stale_objects_count: number;
  fresh_objects_count: number;
  stale_percentage: number;
  stale_entity_ref_ids: string[];
  reindex_recommended: boolean;
}

export interface RebuildReport {
  started_at: string;
  completed_at: string;
  duration_ms: number;
  projections_deleted: number;
  chunks_deleted: number;
  embeddings_deleted: number;
  objects_rebuilt: number;
  projections_rebuilt: number;
  chunks_created: number;
  embeddings_generated: number;
  success: boolean;
  error?: string;
}
