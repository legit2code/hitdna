import { DraftClaim } from './types.ts';

export class DraftClaimExtractor {
  /**
   * Parses synthesized text into discrete draft claims for grounding verification.
   */
  public static extractDraftClaims(text: string): DraftClaim[] {
    if (!text || text.trim().length === 0) return [];

    // Split text into sentences/propositions
    const sentences = text
      .split(/(?<=[.!?\]])\s+(?=[A-Z0-9\[])/)
      .map((s) => s.trim())
      .filter((s) => s.length > 5);

    const citationRegex = /\[(?:citation:)?(agent|version|run|claim|evidence|finding|runtime|file|file_line|dependency|vulnerability|cve|policy|package):([^\]]+)\]/gi;

    const draftClaims: DraftClaim[] = [];

    sentences.forEach((sentence) => {
      // Find all citation tags attached to this sentence
      const citations = Array.from(sentence.matchAll(citationRegex)).map((m) => m[0]);

      // Strip citation tags to evaluate substantive content
      const cleanStatement = sentence.replace(citationRegex, '').trim();

      if (cleanStatement.length < 3) {
        // This chunk was just citations! Attach them to the previous claim if one exists
        if (draftClaims.length > 0 && citations.length > 0) {
          const prev = draftClaims[draftClaims.length - 1];
          for (const cit of citations) {
            if (!prev.citation_tags.includes(cit)) {
              prev.citation_tags.push(cit);
            }
          }
        }
        return;
      }

      // Check if statement contains substantive factual assertions
      const isSubstantive = this.isSubstantiveStatement(cleanStatement);

      draftClaims.push({
        claim_index: draftClaims.length,
        statement: cleanStatement,
        is_substantive: isSubstantive,
        citation_tags: citations,
        grounding_score: 0,
        supported: false,
        contradicted: false,
        supporting_evidence_ids: [],
        supporting_fact_ids: [],
      });
    });

    return draftClaims;
  }

  private static isSubstantiveStatement(statement: string): boolean {
    const lower = statement.toLowerCase();

    // Check for non-substantive filler or conversational opening/closing
    const nonSubstantivePatterns = [
      /^here (is|are) the/i,
      /^in summary,?/i,
      /^based on the provided/i,
      /^hello/i,
      /^to answer your question/i,
      /^please note that/i,
      /^let me know/i,
    ];

    for (const pattern of nonSubstantivePatterns) {
      if (pattern.test(lower)) {
        // If it's short and matches filler, not substantive
        if (statement.length < 40) return false;
      }
    }

    // Must contain domain entities, actions, or metrics
    const domainKeywords = [
      'vulnerability', 'cve', 'risk', 'taint', 'sink', 'source', 'exec', 'agent',
      'version', 'score', 'cvss', 'finding', 'mitigated', 'blocked', 'policy',
      'evidence', 'sandbox', 'evasion', 'honeytoken', 'dep', 'package', 'flow',
      'line', 'ast', 'commit', 'sha', 'critical', 'high', 'medium', 'low', 'clean'
    ];

    const hasDomainKeyword = domainKeywords.some((kw) => lower.includes(kw));
    return hasDomainKeyword || statement.split(' ').length >= 6;
  }
}
