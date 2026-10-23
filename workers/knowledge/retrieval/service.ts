import { 
  HybridRetrievalResult, 
  RetrievedDocument, 
  RetrievalExecutionAudit 
} from './types.ts';
import { QueryUnderstandingEngine } from './understanding.ts';
import { RetrievalPlanner } from './planning.ts';
import { MultiModalRetrievers } from './retrievers.ts';
import { HybridFusionReranker } from './reranker.ts';
import { KnowledgeCorpusManager } from '../reindex/scheduler.ts';
import { EmbeddingProvider } from '../types.ts';
import { 
  SecurityClassificationRank, 
  CLASSIFICATION_CODE_TO_RANK,
  SecurityClassificationCode 
} from '@caim/auth/types.ts';

export interface RetrievalContextOptions {
  caller_user_id?: string;
  caller_classification_code?: SecurityClassificationCode;
  caller_security_rank?: SecurityClassificationRank;
  caller_has_vault_access?: boolean;
  scoped_agent_id?: string;
  scoped_agent_version_id?: string;
  budget_max_records?: number;
  budget_max_tokens?: number;
  composition_safe_only?: boolean;
}

export class HybridRetrievalService {
  private corpus: KnowledgeCorpusManager;
  private provider: EmbeddingProvider;
  private auditHistory: RetrievalExecutionAudit[] = [];

  constructor(corpus: KnowledgeCorpusManager, provider: EmbeddingProvider) {
    this.corpus = corpus;
    this.provider = provider;
  }

  /**
   * Executes the full retrieval pipeline:
   * 1. Query Understanding & Schema Validation
   * 2. Typed Retrieval Planning with Cost Guard
   * 3. Multi-Modal Retrieval (Relational, Vector, Graph, Lineage)
   * 4. Strict Pre-Context Authorization Filtering (CRITICAL: Zero unauthorized leak before context assembly)
   * 5. Hybrid Deduplication & Multi-Factor Reranking
   * 6. Query Audit Logging
   */
  public async retrieveContext(
    rawQuery: string,
    options: RetrievalContextOptions = {}
  ): Promise<HybridRetrievalResult> {
    const startTime = Date.now();

    // Determine caller clearance rank
    const callerRank = options.caller_security_rank ?? (
      options.caller_classification_code ? CLASSIFICATION_CODE_TO_RANK[options.caller_classification_code] : SecurityClassificationRank.PUBLIC_METADATA
    );
    const callerHasVault = options.caller_has_vault_access ?? (options.caller_classification_code === 'VAULT_RESTRICTED');

    // 1. Query Understanding
    const understanding = QueryUnderstandingEngine.parseQuery(rawQuery);
    if (options.scoped_agent_id) understanding.scoped_agent_id = options.scoped_agent_id;
    if (options.scoped_agent_version_id) understanding.scoped_agent_version_id = options.scoped_agent_version_id;

    // 2. Retrieval Plan with Cost Guard
    const plan = RetrievalPlanner.createPlan(understanding, {
      max_security_rank: callerRank,
      allow_vault_restricted: callerHasVault,
      budget_max_records: options.budget_max_records ?? 20,
      budget_max_tokens: options.budget_max_tokens ?? 8192,
      composition_safe_only: options.composition_safe_only ?? false,
    });

    const gatheredDocs: RetrievedDocument[] = [];
    const counts = {
      relational_exact: 0,
      vector_semantic: 0,
      graph_ontology: 0,
      evidence_lineage: 0,
    };

    // 3. Multi-Modal Retrieval in order of planned priority
    for (const mode of plan.retrieval_modes) {
      if (mode === 'RELATIONAL_EXACT') {
        const relDocs = await MultiModalRetrievers.retrieveRelationalExact(plan, this.corpus);
        counts.relational_exact = relDocs.length;
        gatheredDocs.push(...relDocs);
      } else if (mode === 'GRAPH_ONTOLOGY') {
        const graphDocs = await MultiModalRetrievers.retrieveGraphOntology(plan, this.corpus);
        counts.graph_ontology = graphDocs.length;
        gatheredDocs.push(...graphDocs);
      } else if (mode === 'EVIDENCE_LINEAGE') {
        const lineageDocs = await MultiModalRetrievers.retrieveEvidenceLineage(plan, this.corpus);
        counts.evidence_lineage = lineageDocs.length;
        gatheredDocs.push(...lineageDocs);
      } else if (mode === 'VECTOR_SEMANTIC') {
        const vecDocs = await MultiModalRetrievers.retrieveVectorSemantic(plan, this.corpus, this.provider);
        counts.vector_semantic = vecDocs.length;
        gatheredDocs.push(...vecDocs);
      }
    }

    // 4. CRITICAL: Strict Pre-Context Authorization Gate
    // Filter out any unauthorized documents BEFORE results become context
    let unauthorizedFiltered = 0;
    const authorizedDocs: RetrievedDocument[] = [];

    for (const doc of gatheredDocs) {
      if (doc.security_classification_rank > callerRank) {
        unauthorizedFiltered++;
        continue;
      }
      if (doc.vault_restricted && !callerHasVault) {
        unauthorizedFiltered++;
        continue;
      }
      if (plan.composition_safe_only && !MultiModalRetrievers.isDocumentCompositionSafe(doc, this.corpus)) {
        unauthorizedFiltered++;
        continue;
      }
      authorizedDocs.push(doc);
    }

    // 5. Deduplication & Multi-Factor Reranking
    const finalDocs = HybridFusionReranker.fuseAndRerank(
      authorizedDocs,
      plan.hybrid_fusion_limit
    );

    const duration = Date.now() - startTime;
    const costUnits = (counts.relational_exact * 1) + (counts.vector_semantic * 3) + (counts.graph_ontology * 2) + (counts.evidence_lineage * 2);

    // 6. Query Audit
    const audit: RetrievalExecutionAudit = {
      query: rawQuery,
      caller_user_id: options.caller_user_id || 'anonymous-user',
      caller_security_rank: callerRank,
      caller_has_vault_access: callerHasVault,
      intent: understanding.intent,
      plan,
      counts_by_retriever: counts,
      filtered_out_unauthorized_count: unauthorizedFiltered,
      fused_pre_rerank_count: authorizedDocs.length,
      final_returned_count: finalDocs.length,
      estimated_cost_units: costUnits,
      duration_ms: duration,
      timestamp: new Date().toISOString(),
    };

    this.auditHistory.unshift(audit);
    if (this.auditHistory.length > 100) this.auditHistory.pop();

    return {
      documents: finalDocs,
      audit,
    };
  }

  public getAuditHistory(): RetrievalExecutionAudit[] {
    return this.auditHistory;
  }
}
