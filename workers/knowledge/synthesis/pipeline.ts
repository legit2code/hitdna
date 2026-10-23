import { KnowledgeCorpusManager } from '../reindex/scheduler.ts';
import { HybridRetrievalService } from '../retrieval/service.ts';
import { ContextAssembler, ContextAssemblyOptions } from '../context/assembler.ts';
import { GeminiAnswerSynthesizer, AnswerSynthesizerOptions } from './engine.ts';
import { DraftClaimExtractor } from './claims.ts';
import { GroundingValidator } from './grounding.ts';
import { EpistemicDecisionEngine } from './epistemic.ts';
import { CitationResolver } from './citations.ts';
import { AnswerAuditService } from './audit.ts';
import { SynthesisOutput } from './types.ts';

export interface RagPipelineOptions {
  apiKey?: string;
  synthesizerOptions?: AnswerSynthesizerOptions;
  assemblyOptions?: ContextAssemblyOptions;
}

export class RagSynthesisPipeline {
  private corpus: KnowledgeCorpusManager;
  private retrieval: HybridRetrievalService;
  private assembler: ContextAssembler;
  private synthesizer: GeminiAnswerSynthesizer;
  private citationResolver: CitationResolver;
  private auditService: AnswerAuditService;

  constructor(
    corpus: KnowledgeCorpusManager,
    retrieval: HybridRetrievalService,
    options?: RagPipelineOptions
  ) {
    this.corpus = corpus;
    this.retrieval = retrieval;
    this.assembler = new ContextAssembler(options?.assemblyOptions?.budgetConfig);
    this.synthesizer = new GeminiAnswerSynthesizer(options?.synthesizerOptions);
    this.citationResolver = new CitationResolver(corpus);
    this.auditService = new AnswerAuditService();
  }

  /**
   * Executes the full RAG cycle:
   * 1. Retrieve authorized documents
   * 2. Assemble budget-limited, isolated context package
   * 3. Synthesize draft answer
   * 4. Extract draft claims
   * 5. Validate grounding & detect contradictions
   * 6. Apply epistemic decisions (Accept / Revise / Remove / Abstain)
   * 7. Resolve citations and strip fabricated/unauthorized IDs
   * 8. Log answer audit
   */
  public async answerQuery(
    query: string,
    options?: {
      caller_user_id?: string;
      caller_security_rank?: number;
      caller_has_vault_access?: boolean;
      scoped_agent_id?: string;
      scoped_agent_version_id?: string;
      injected_draft_for_testing?: string; // Allows test suites to test exact claim validation & contradiction branches
    }
  ): Promise<SynthesisOutput> {
    const startTime = Date.now();
    const callerRank = options?.caller_security_rank ?? 0;
    const callerVault = options?.caller_has_vault_access ?? false;

    // 1. Multi-Modal Retrieval with Pre-Context Authorization Gate
    const retrievalResult = await this.retrieval.retrieveContext(query, {
      caller_user_id: options?.caller_user_id,
      caller_security_rank: callerRank,
      caller_has_vault_access: callerVault,
      scoped_agent_id: options?.scoped_agent_id,
      scoped_agent_version_id: options?.scoped_agent_version_id,
    });

    // 2. Assemble Isolated Context Package
    const contextPackage = this.assembler.assembleContextPackage(
      query,
      retrievalResult.documents,
      {
        caller_security_rank: callerRank,
        caller_has_vault: callerVault,
        target_agent_id: options?.scoped_agent_id,
        target_version_id: options?.scoped_agent_version_id,
      }
    );

    // 3. Synthesize Draft Answer (or use test-injected draft in non-production)
    if (process.env.NODE_ENV === 'production' && options?.injected_draft_for_testing) {
      throw new Error('[FATAL SECURITY VIOLATION] injected_draft_for_testing is strictly prohibited in production mode.');
    }
    let rawDraft = options?.injected_draft_for_testing;
    let modelUsed = 'test-injected';
    let promptVersion = 'rag-prompt-v2026.08.1';

    if (!rawDraft) {
      const draftResult = await this.synthesizer.synthesizeDraftAnswer(query, contextPackage);
      rawDraft = draftResult.draftText;
      modelUsed = draftResult.modelUsed;
      promptVersion = draftResult.promptVersion;
    }

    // 4. Extract Draft Claims
    const draftClaims = DraftClaimExtractor.extractDraftClaims(rawDraft);

    // 5. Validate Grounding & Contradictions
    const groundingResult = GroundingValidator.validateGrounding(draftClaims, contextPackage);

    // 6. Epistemic Decision Engine
    const epistemic = EpistemicDecisionEngine.evaluateDecision(
      rawDraft,
      groundingResult.validatedClaims,
      groundingResult.verdict,
      contextPackage,
      {
        query,
        contradictionReason: groundingResult.contradictionReason,
        evidenceConflicts: groundingResult.evidenceConflicts,
      }
    );

    // 7. Resolve Citations on the Draft and Final Answer
    const draftCitations = this.citationResolver.resolveCitations(
      rawDraft,
      contextPackage,
      callerRank,
      callerVault
    );
    const finalCitations = this.citationResolver.resolveCitations(
      epistemic.finalAnswer,
      contextPackage,
      callerRank,
      callerVault
    );

    const seenInvalid = new Set<string>();
    const invalidCitations = [];
    for (const inv of [...draftCitations.invalidCitations, ...finalCitations.invalidCitations]) {
      if (!seenInvalid.has(inv.citation_raw)) {
        seenInvalid.add(inv.citation_raw);
        invalidCitations.push(inv);
      }
    }
    const validCitations = finalCitations.validCitations;

    // Filter out invalid or fabricated citations from final answer
    let sanitizedFinalAnswer = epistemic.finalAnswer;
    for (const inv of invalidCitations) {
      sanitizedFinalAnswer = sanitizedFinalAnswer.replace(inv.citation_raw, '').trim();
    }

    // 8. Log Answer Audit Record
    const latency_ms = Date.now() - startTime;
    const auditRecord = this.auditService.logSynthesis({
      model_name: modelUsed,
      prompt_version: promptVersion,
      context_package_hash: contextPackage.package_hash,
      query,
      caller_user_id: options?.caller_user_id,
      draft_claims_count: draftClaims.length,
      grounded_claims_count: groundingResult.groundedClaims.length,
      unsupported_claims_count: groundingResult.unsupportedClaims.length,
      contradictions_count: groundingResult.contradictedClaims.length,
      conflicts_count: (groundingResult.evidenceConflicts || []).length,
      grounding_verdict: groundingResult.verdict,
      epistemic_decision: epistemic.decision,
      total_citations_emitted: validCitations.length + invalidCitations.length,
      valid_citations_count: validCitations.length,
      invalid_citations_count: invalidCitations.length,
      abstention_reason: epistemic.abstentionReason,
      latency_ms,
    });

    return {
      answer: sanitizedFinalAnswer,
      raw_draft_answer: rawDraft,
      epistemic_decision: epistemic.decision,
      grounding_verdict: groundingResult.verdict,
      abstention: epistemic.decision === 'ABSTAIN',
      abstention_reason: epistemic.abstentionReason,
      missing_evidence: epistemic.missingEvidence,
      evidence_conflicts: epistemic.evidenceConflicts,
      draft_claims: groundingResult.validatedClaims,
      grounded_claims: groundingResult.groundedClaims,
      unsupported_claims: groundingResult.unsupportedClaims,
      contradicted_claims: groundingResult.contradictedClaims,
      resolved_citations: validCitations,
      invalid_citations: invalidCitations,
      context_package: contextPackage,
      audit: auditRecord,
    };
  }

  public getAuditService(): AnswerAuditService {
    return this.auditService;
  }

  public getCitationResolver(): CitationResolver {
    return this.citationResolver;
  }
}
