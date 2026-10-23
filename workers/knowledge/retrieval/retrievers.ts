import { 
  RetrievalPlan, 
  RetrievedDocument 
} from './types.ts';
import { KnowledgeCorpusManager } from '../reindex/scheduler.ts';
import { EmbeddingProvider } from '../types.ts';

export class MultiModalRetrievers {
  /**
   * Evaluates if a projection or document is authorized under composition risk filtering.
   * Default composition rule: only draw from agents classified LOW_RISK or explicitly APPROVED,
   * never from HIGH_RISK, CRITICAL, or QUARANTINED source agents.
   */
  public static isDocumentCompositionSafe(
    proj: { exact_keywords?: Record<string, any>; payload?: Record<string, any>; agent_id?: string | null; object_type?: string; entity_ref_id?: string },
    corpus: KnowledgeCorpusManager
  ): boolean {
    const kw = proj.exact_keywords || {};
    const payload = proj.payload || {};

    const riskBand = String(kw.risk_band || payload.risk_band || '').toUpperCase();
    const lifecycleStatus = String(
      kw.lifecycle_state || kw.lifecycle_status || kw.status || 
      payload.lifecycle_state || payload.lifecycle_status || payload.status || ''
    ).toUpperCase();

    // Explicitly forbidden statuses/risks
    if (riskBand.includes('HIGH') || riskBand.includes('CRITICAL')) return false;
    if (lifecycleStatus.includes('QUARANTIN') || lifecycleStatus.includes('REVOK') || lifecycleStatus.includes('REJECT')) return false;

    // Check parent agent projection if linked
    const targetAgentId = proj.agent_id || (proj.object_type === 'agent' ? proj.entity_ref_id : null);
    if (targetAgentId) {
      const parentAgentProj = Array.from(corpus.getProjections().values()).find(
        p => p.object_type === 'agent' && (p.entity_ref_id === targetAgentId || p.exact_keywords?.agent_id === targetAgentId)
      );
      
      if (parentAgentProj) {
        const pKw = parentAgentProj.exact_keywords || {};
        const pPayload = parentAgentProj.payload || {};
        const pRisk = String(pKw.risk_band || pPayload.risk_band || '').toUpperCase();
        const pStatus = String(
          pKw.lifecycle_state || pKw.lifecycle_status || pKw.status || 
          pPayload.lifecycle_state || pPayload.lifecycle_status || pPayload.status || ''
        ).toUpperCase();

        if (pRisk.includes('HIGH') || pRisk.includes('CRITICAL')) return false;
        if (pStatus.includes('QUARANTIN') || pStatus.includes('REVOK') || pStatus.includes('REJECT')) return false;
        if (pRisk.includes('LOW') || pStatus.includes('APPROV')) return true;
      }
    }

    // Direct check on this projection
    if (riskBand.includes('LOW') || lifecycleStatus.includes('APPROV')) return true;

    // If ontology or universal rule not linked to high-risk entity, allow
    if (proj.object_type === 'ontology' || proj.object_type === 'policy') return true;

    return false;
  }

  /**
   * 1. Relational & Exact Keyword Retriever
   */
  public static async retrieveRelationalExact(
    plan: RetrievalPlan,
    corpus: KnowledgeCorpusManager
  ): Promise<RetrievedDocument[]> {
    const understanding = plan.query_understanding;
    const { cve_ids, rule_ids, package_names, claim_ids, symbols, versions } = understanding.extracted_entities;
    const docs: RetrievedDocument[] = [];

    const projections = corpus.getProjections();

    for (const proj of projections.values()) {
      // Authorization Check Pre-Filter
      if (proj.security_classification_rank > plan.max_security_rank) continue;
      if (proj.vault_restricted && !plan.allow_vault_restricted) continue;

      // Composition Risk Filter: only LOW_RISK / APPROVED
      if (plan.composition_safe_only && !MultiModalRetrievers.isDocumentCompositionSafe(proj, corpus)) {
        continue;
      }

      // Scoped Agent & Version Filtering
      if (understanding.scoped_agent_id && proj.agent_id && proj.agent_id !== understanding.scoped_agent_id) {
        continue;
      }
      if (understanding.scoped_agent_version_id && proj.agent_version_id && proj.agent_version_id !== understanding.scoped_agent_version_id) {
        continue;
      }

      let exactScore = 0;
      const kw = proj.exact_keywords;

      // Match exact CVE
      if (cve_ids.length > 0 && kw.cve_id && cve_ids.includes(String(kw.cve_id).toUpperCase())) {
        exactScore += 1.0;
      }
      // Match exact Rule
      if (rule_ids.length > 0 && kw.rule_id && rule_ids.includes(String(kw.rule_id).toUpperCase())) {
        exactScore += 1.0;
      }
      // Match exact Package
      if (package_names.length > 0 && kw.package_name && package_names.includes(String(kw.package_name).toLowerCase())) {
        exactScore += 0.9;
      }
      // Match exact Claim
      if (claim_ids.length > 0 && kw.claim_id && claim_ids.includes(String(kw.claim_id))) {
        exactScore += 1.0;
      }
      // Match exact Symbol / File
      if (symbols.length > 0 && (kw.file_path || kw.entrypoint)) {
        for (const s of symbols) {
          if (String(kw.file_path || '').includes(s) || String(kw.entrypoint || '').includes(s)) {
            exactScore += 0.8;
          }
        }
      }
      // Match exact Version
      if (versions.length > 0 && kw.version_number && versions.includes(String(kw.version_number))) {
        exactScore += 0.7;
      }
      // Match Scoped Agent
      if (understanding.scoped_agent_id && (proj.agent_id === understanding.scoped_agent_id || proj.entity_ref_id === understanding.scoped_agent_id)) {
        exactScore += 0.8;
      }
      // Match query terms in document text / entity_ref_id
      const rawLower = understanding.raw_query.toLowerCase();
      if (rawLower.includes(proj.entity_ref_id.toLowerCase()) || rawLower.includes(proj.object_type.toLowerCase())) {
        exactScore += 0.75;
      }
      if (proj.vault_restricted && rawLower.includes('vault')) {
        exactScore += 0.85;
      }

      if (exactScore > 0) {
        docs.push({
          doc_id: `rel-${proj.knowledge_projection_id}`,
          knowledge_object_id: proj.knowledge_object_id,
          entity_ref_id: proj.entity_ref_id,
          object_type: proj.object_type,
          retriever_source: 'RELATIONAL_EXACT',
          title: proj.summary || `${proj.object_type} ${proj.entity_ref_id}`,
          snippet: proj.document_text.substring(0, 300),
          full_content: proj.document_text,
          relevance_score: Math.min(1.0, exactScore),
          exactness_score: Math.min(1.0, exactScore),
          evidence_strength: 0.9,
          freshness_score: 0.95,
          authority_score: 1.0, // Primary source database authority
          final_rerank_score: 0,
          security_classification: proj.security_classification,
          security_classification_rank: proj.security_classification_rank,
          vault_restricted: proj.vault_restricted,
          agent_id: proj.agent_id,
          agent_version_id: proj.agent_version_id,
          exact_keywords: proj.exact_keywords,
        });
      }
    }

    return docs.slice(0, plan.top_k_per_mode.relational || 10);
  }

  /**
   * 2. Vector Semantic Retriever
   */
  public static async retrieveVectorSemantic(
    plan: RetrievalPlan,
    corpus: KnowledgeCorpusManager,
    provider: EmbeddingProvider
  ): Promise<RetrievedDocument[]> {
    if (process.env.NODE_ENV === 'production') {
      if (provider.status === 'NOT_CONFIGURED' || provider.status === 'MOCK_TEST_ONLY' || (provider.isConfigured && !provider.isConfigured())) {
        throw new Error(
          '[FATAL PRODUCTION ERROR] Semantic vector retrieval requested but embedding provider is NOT_CONFIGURED or MOCK. Silent substitution of mock embeddings is strictly prohibited.'
        );
      }
    }
    if (provider.status === 'NOT_CONFIGURED' || (provider.isConfigured && !provider.isConfigured())) {
      return [];
    }

    const rawQuery = plan.query_understanding.raw_query;
    const queryEmb = await provider.generateEmbedding(rawQuery, { taskType: 'RETRIEVAL_QUERY' });

    const searchResults = await corpus.getVectorRepo().search({
      query_text: rawQuery,
      query_vector: queryEmb.vector,
      top_k: plan.top_k_per_mode.vector || 12,
      min_similarity: 0.01,
      max_security_rank: plan.max_security_rank,
      allow_vault_restricted: plan.allow_vault_restricted,
      agent_id: plan.query_understanding.scoped_agent_id,
      agent_version_id: plan.query_understanding.scoped_agent_version_id,
      object_types: plan.query_understanding.target_object_types.length > 0 ? plan.query_understanding.target_object_types : undefined,
    });

    const projections = corpus.getProjections();

    const filtered = searchResults.filter(r => {
      if (!plan.composition_safe_only) return true;
      const proj = projections.get(r.exact_keywords?.entity_ref_id || '') || projections.get(r.knowledge_object_id);
      return MultiModalRetrievers.isDocumentCompositionSafe(proj || r, corpus);
    });

    return filtered.map((r) => {
      const proj = projections.get(r.exact_keywords?.entity_ref_id || '');
      return {
        doc_id: `vec-${r.chunk_id}`,
        knowledge_object_id: r.knowledge_object_id,
        entity_ref_id: r.exact_keywords?.entity_ref_id || r.knowledge_object_id,
        object_type: r.object_type,
        retriever_source: 'VECTOR_SEMANTIC',
        title: proj?.summary || `Vector match (${r.object_type})`,
        snippet: r.text_snippet,
        full_content: proj?.document_text || r.text_snippet,
        relevance_score: r.similarity_score,
        exactness_score: 0.5,
        evidence_strength: 0.8,
        freshness_score: 0.9,
        authority_score: 0.85,
        final_rerank_score: 0,
        security_classification: r.security_classification,
        security_classification_rank: proj?.security_classification_rank ?? plan.max_security_rank,
        vault_restricted: r.vault_restricted,
        agent_id: r.agent_id,
        agent_version_id: r.agent_version_id,
        exact_keywords: r.exact_keywords,
      };
    });
  }

  /**
   * 3. Ontology & Concept Traversal Retriever (Multi-Hop)
   */
  public static async retrieveGraphOntology(
    plan: RetrievalPlan,
    corpus: KnowledgeCorpusManager
  ): Promise<RetrievedDocument[]> {
    const concepts = plan.query_understanding.resolved_ontology_concepts;
    const docs: RetrievedDocument[] = [];
    const projections = corpus.getProjections();

    for (const proj of projections.values()) {
      if (proj.security_classification_rank > plan.max_security_rank) continue;
      if (proj.vault_restricted && !plan.allow_vault_restricted) continue;
      if (plan.composition_safe_only && !MultiModalRetrievers.isDocumentCompositionSafe(proj, corpus)) continue;

      let graphMatch = false;
      let hops = 1;

      if (proj.object_type === 'ontology') {
        const text = proj.document_text.toUpperCase();
        for (const c of concepts) {
          if (text.includes(c) || text.includes(c.replace('CONCEPT-', ''))) {
            graphMatch = true;
            hops = 1;
            break;
          }
        }
      } else if (proj.object_type === 'finding' || proj.object_type === 'risk') {
        // Multi-hop connection between ontology concept and finding category
        const text = proj.document_text.toUpperCase();
        for (const c of concepts) {
          if (text.includes(c.replace('CONCEPT-', ''))) {
            graphMatch = true;
            hops = 2;
            break;
          }
        }
      }

      if (graphMatch) {
        docs.push({
          doc_id: `graph-${proj.knowledge_projection_id}`,
          knowledge_object_id: proj.knowledge_object_id,
          entity_ref_id: proj.entity_ref_id,
          object_type: proj.object_type,
          retriever_source: 'GRAPH_ONTOLOGY',
          title: `[Graph Traversal - Hop ${hops}] ${proj.summary || proj.entity_ref_id}`,
          snippet: proj.document_text.substring(0, 300),
          full_content: proj.document_text,
          relevance_score: hops === 1 ? 0.95 : 0.85,
          exactness_score: 0.8,
          evidence_strength: 0.9,
          freshness_score: 0.95,
          authority_score: 0.95,
          final_rerank_score: 0,
          security_classification: proj.security_classification,
          security_classification_rank: proj.security_classification_rank,
          vault_restricted: proj.vault_restricted,
          agent_id: proj.agent_id,
          agent_version_id: proj.agent_version_id,
          exact_keywords: { ...proj.exact_keywords, traversal_hops: hops },
        });
      }
    }

    return docs.slice(0, plan.top_k_per_mode.graph || 8);
  }

  /**
   * 4. Evidence Lineage Retriever (Claim -> Evidence -> Finding -> Run)
   */
  public static async retrieveEvidenceLineage(
    plan: RetrievalPlan,
    corpus: KnowledgeCorpusManager
  ): Promise<RetrievedDocument[]> {
    const claimIds = plan.query_understanding.extracted_entities.claim_ids;
    const docs: RetrievedDocument[] = [];
    const projections = corpus.getProjections();

    const targetClaims = Array.from(projections.values()).filter((p) => {
      if (p.object_type !== 'claim') return false;
      if (claimIds.length > 0) {
        return claimIds.includes(p.entity_ref_id) || claimIds.includes(String(p.exact_keywords?.claim_id));
      }
      if (
        plan.query_understanding.intent === 'EVIDENCE_LINEAGE' ||
        plan.query_understanding.target_object_types.includes('claim')
      ) {
        return true;
      }
      if (
        plan.query_understanding.scoped_agent_id &&
        p.agent_id === plan.query_understanding.scoped_agent_id
      ) {
        return true;
      }
      return false;
    });

    for (const claimProj of targetClaims) {
      if (claimProj.security_classification_rank > plan.max_security_rank) continue;
      if (claimProj.vault_restricted && !plan.allow_vault_restricted) continue;
      if (plan.composition_safe_only && !MultiModalRetrievers.isDocumentCompositionSafe(claimProj, corpus)) continue;

      const trail: string[] = [`Claim:${claimProj.entity_ref_id}`];

      // Add claim projection
      docs.push({
        doc_id: `lineage-claim-${claimProj.knowledge_projection_id}`,
        knowledge_object_id: claimProj.knowledge_object_id,
        entity_ref_id: claimProj.entity_ref_id,
        object_type: 'claim',
        retriever_source: 'EVIDENCE_LINEAGE',
        title: `Claim Lineage Root: ${claimProj.summary}`,
        snippet: claimProj.document_text.substring(0, 300),
        full_content: claimProj.document_text,
        relevance_score: 1.0,
        exactness_score: 0.95,
        evidence_strength: 0.95,
        freshness_score: 0.95,
        authority_score: 1.0,
        final_rerank_score: 0,
        security_classification: claimProj.security_classification,
        security_classification_rank: claimProj.security_classification_rank,
        vault_restricted: claimProj.vault_restricted,
        agent_id: claimProj.agent_id,
        agent_version_id: claimProj.agent_version_id,
        exact_keywords: claimProj.exact_keywords,
        lineage_trail: [...trail],
      });

      // Find supporting evidence
      const rawPayload = claimProj.payload;
      const linkedEvidenceIds: string[] = rawPayload?.evidence_links?.map((e: any) => e.evidence_id) || [];

      for (const evProj of projections.values()) {
        if (evProj.object_type === 'evidence' && (linkedEvidenceIds.includes(evProj.entity_ref_id) || evProj.entity_ref_id.includes(claimProj.entity_ref_id))) {
          if (evProj.security_classification_rank > plan.max_security_rank) continue;
          if (evProj.vault_restricted && !plan.allow_vault_restricted) continue;

          trail.push(`Evidence:${evProj.entity_ref_id}`);

          docs.push({
            doc_id: `lineage-ev-${evProj.knowledge_projection_id}`,
            knowledge_object_id: evProj.knowledge_object_id,
            entity_ref_id: evProj.entity_ref_id,
            object_type: 'evidence',
            retriever_source: 'EVIDENCE_LINEAGE',
            title: `Supporting Evidence: ${evProj.summary}`,
            snippet: evProj.document_text.substring(0, 300),
            full_content: evProj.document_text,
            relevance_score: 0.95,
            exactness_score: 0.9,
            evidence_strength: 1.0, // Ground truth observation
            freshness_score: 0.95,
            authority_score: 0.98,
            final_rerank_score: 0,
            security_classification: evProj.security_classification,
            security_classification_rank: evProj.security_classification_rank,
            vault_restricted: evProj.vault_restricted,
            agent_id: evProj.agent_id,
            agent_version_id: evProj.agent_version_id,
            exact_keywords: evProj.exact_keywords,
            lineage_trail: [...trail],
          });
        }
      }
    }

    return docs.slice(0, plan.top_k_per_mode.lineage || 10);
  }
}
