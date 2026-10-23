import { describe, it, expect, beforeEach } from 'vitest';
import { 
  KnowledgeCorpusManager, 
  DeterministicMockEmbeddingProvider,
  HybridRetrievalService,
  QueryUnderstandingEngine,
  RetrievalPlanner,
  seedCanonicalKnowledgeCorpus
} from '../workers/knowledge/index.ts';
import { SecurityClassificationRank } from '@caim/auth/types.ts';

describe('P22 & P23 Knowledge Projections & Hybrid Retrieval Plane', () => {
  let corpus: KnowledgeCorpusManager;
  let retrieval: HybridRetrievalService;
  let provider: DeterministicMockEmbeddingProvider;

  beforeEach(async () => {
    provider = new DeterministicMockEmbeddingProvider();
    corpus = new KnowledgeCorpusManager(provider);
    retrieval = new HybridRetrievalService(corpus, provider);
    await seedCanonicalKnowledgeCorpus(corpus);
  });

  it('1. Exact CVE / Package lookup finds exact vulnerability record deterministically', async () => {
    const result = await retrieval.retrieveContext('What is the CVSS score and status of CVE-2026-44012 in lodash?', {
      caller_security_rank: SecurityClassificationRank.INTERNAL,
    });

    expect(result.documents.length).toBeGreaterThan(0);
    const cveDoc = result.documents.find((d) => d.exact_keywords?.cve_id === 'CVE-2026-44012');
    expect(cveDoc).toBeDefined();
    expect(cveDoc?.retriever_source).toBe('RELATIONAL_EXACT');
    expect(cveDoc?.exactness_score).toBeGreaterThanOrEqual(0.9);
    expect(result.audit.counts_by_retriever.relational_exact).toBeGreaterThan(0);
  });

  it('2. Semantic question returns relevant matches via vector semantic retriever', async () => {
    const result = await retrieval.retrieveContext('How does the agent handle untrusted child process shell execution?', {
      caller_security_rank: SecurityClassificationRank.SENSITIVE,
    });

    expect(result.documents.length).toBeGreaterThan(0);
    expect(result.audit.counts_by_retriever.vector_semantic).toBeGreaterThan(0);
    const findingDoc = result.documents.find((d) => d.full_content.includes('child_process.exec') || d.full_content.includes('shell'));
    expect(findingDoc).toBeDefined();
  });

  it('3. Ontology multi-hop traversal connects concepts to matching findings and risks', async () => {
    const understanding = QueryUnderstandingEngine.parseQuery('Explain the direct injection concept and how it relates to our taxonomy');
    expect(understanding.intent).toBe('ONTOLOGY_TRAVERSAL');
    expect(understanding.resolved_ontology_concepts).toContain('CONCEPT-INJECTION');

    const result = await retrieval.retrieveContext('Explain the direct injection concept in our ontology taxonomy', {
      caller_security_rank: SecurityClassificationRank.INTERNAL,
    });

    const ontologyDoc = result.documents.find((d) => d.object_type === 'ontology');
    expect(ontologyDoc).toBeDefined();
    expect(ontologyDoc?.retriever_source).toBe('GRAPH_ONTOLOGY');
    expect(result.audit.counts_by_retriever.graph_ontology).toBeGreaterThan(0);
  });

  it('4. Claim -> Evidence Lineage traversal recovers full epistemic trail', async () => {
    const result = await retrieval.retrieveContext('What is the evidence behind claim-rce-vulnerability-verified?', {
      caller_security_rank: SecurityClassificationRank.SENSITIVE,
    });

    expect(result.documents.length).toBeGreaterThanOrEqual(2);
    const claimDoc = result.documents.find((d) => d.object_type === 'claim');
    const evidenceDoc = result.documents.find((d) => d.object_type === 'evidence');

    expect(claimDoc).toBeDefined();
    expect(evidenceDoc).toBeDefined();
    expect(evidenceDoc?.lineage_trail).toBeDefined();
    expect(result.audit.counts_by_retriever.evidence_lineage).toBeGreaterThan(0);
  });

  it('5. Version-scoped query restricts candidates to the specified agent version', async () => {
    const result = await retrieval.retrieveContext('Show all audit findings for agent-sentinel-core version 2.4.1', {
      scoped_agent_id: 'agent-sentinel-core',
      scoped_agent_version_id: 'ver-sentinel-2.4.1',
      caller_security_rank: SecurityClassificationRank.SENSITIVE,
    });

    expect(result.documents.length).toBeGreaterThan(0);
    for (const doc of result.documents) {
      if (doc.agent_id) {
        expect(doc.agent_id).toBe('agent-sentinel-core');
      }
    }
  });

  it('6. CRITICAL SECURITY GATE: Unauthorized user asking for vault-only fact receives ZERO vault objects', async () => {
    // Normal / Public / Internal caller asking directly for vault quantum secrets
    const unauthResult = await retrieval.retrieveContext('Tell me about the Quantum Enclave Encryption Master Key Blueprint in the vault', {
      caller_security_rank: SecurityClassificationRank.INTERNAL,
      caller_has_vault_access: false,
    });

    // Verify ABSOLUTELY ZERO vault-restricted items are returned to unauthorized caller
    const leakedVault = unauthResult.documents.filter((d) => d.vault_restricted || d.security_classification === 'VAULT_RESTRICTED');
    expect(leakedVault.length).toBe(0);

    // Verify authorized vault user DOES receive the vault record
    const authResult = await retrieval.retrieveContext('Tell me about the Quantum Enclave Encryption Master Key Blueprint in the vault', {
      caller_security_rank: SecurityClassificationRank.VAULT_RESTRICTED,
      caller_has_vault_access: true,
    });

    const vaultDoc = authResult.documents.find((d) => d.vault_restricted || d.entity_ref_id === 'vault-classified-payload-007');
    expect(vaultDoc).toBeDefined();
  });

  it('7. Corpus Rebuild deletes derivative state, re-indexes from source, and maintains integrity', async () => {
    const rebuildReport = await corpus.rebuildEntireCorpus();
    expect(rebuildReport.success).toBe(true);
    expect(rebuildReport.objects_rebuilt).toBeGreaterThan(0);
    expect(rebuildReport.projections_rebuilt).toBeGreaterThan(0);
    expect(rebuildReport.chunks_created).toBeGreaterThan(0);
    expect(rebuildReport.embeddings_generated).toBeGreaterThan(0);

    // Verify staleness detector confirms 0% stale objects after clean rebuild
    const staleness = corpus.getStalenessReport();
    expect(staleness.stale_objects_count).toBe(0);
    expect(staleness.stale_percentage).toBe(0);
  });
});
