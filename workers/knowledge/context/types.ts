import { SecurityClassificationCode, SecurityClassificationRank } from '@caim/auth/types.ts';
import { RetrievedDocument } from '../retrieval/types.ts';

export interface ContextBudgetConfig {
  max_total_tokens: number; // e.g. 4000
  max_exact_tokens: number; // e.g. 1000
  max_ontology_tokens: number; // e.g. 800
  max_lineage_tokens: number; // e.g. 1200
  max_vector_tokens: number; // e.g. 1000
  chars_per_token?: number; // default ~4
}

export interface SerializedFact {
  fact_id: string;
  entity_ref_id: string;
  entity_type: string;
  security_classification: SecurityClassificationCode;
  security_rank: SecurityClassificationRank;
  agent_id?: string;
  agent_version_id?: string;
  analysis_run_id?: string;
  timestamp?: string;
  token_estimate: number;
  formatted_content: string;
  source_retriever: string;
  checksum: string;
  vault_restricted: boolean;
  title?: string;
  raw_content?: string;
  payload?: Record<string, any>;
  structured_attributes?: {
    severity?: string | null;
    cvss_score?: number | null;
    sinks?: string[];
    file_path?: string | null;
    line_number?: number | null;
    rule_id?: string | null;
    outcome?: string | null;
    package_name?: string | null;
    observation?: string | null;
    statement?: string | null;
    claim_state?: string | null;
    category?: string | null;
    fixed_version?: string | null;
  };
}

export interface EvidenceClaimBundle {
  bundle_id: string;
  claim_id?: string;
  statement?: string;
  claim_state?: string;
  confidence?: number;
  evidence_items: {
    evidence_id: string;
    evidence_type: string;
    evidence_class: string;
    source_locator?: string;
    observation: string;
  }[];
  finding_links?: {
    finding_id: string;
    rule_id?: string;
    file_path?: string;
    line_number?: number;
  }[];
  agent_id?: string;
  agent_version_id?: string;
}

export interface VersionGroupedContext {
  agent_id: string;
  agent_version_id: string;
  lifecycle_state?: string;
  runs: {
    run_id: string;
    timestamp?: string;
    facts: SerializedFact[];
    bundles: EvidenceClaimBundle[];
  }[];
  unassigned_facts: SerializedFact[];
}

export interface AssembledContextPackage {
  package_id: string;
  package_hash: string;
  assembled_at: string;
  query: string;
  target_agent_id?: string;
  target_version_id?: string;
  caller_security_rank: number;
  caller_has_vault: boolean;
  total_tokens_estimated: number;
  budget_utilization_ratio: number;
  facts_count: number;
  bundles_count: number;
  redundant_facts_pruned: number;
  version_groups: VersionGroupedContext[];
  isolated_prompt_context: string;
  serialized_facts: SerializedFact[];
  bundles: EvidenceClaimBundle[];
}
