import { CitationTargetType, ResolvedCitation } from './types.ts';
import { KnowledgeCorpusManager } from '../reindex/scheduler.ts';
import { AssembledContextPackage } from '../context/types.ts';

export class CitationResolver {
  private corpus: KnowledgeCorpusManager;

  constructor(corpus: KnowledgeCorpusManager) {
    this.corpus = corpus;
  }

  /**
   * Extracts all citation tags from text and resolves them against the authoritative corpus.
   * Never permits fabricated citation IDs.
   */
  public resolveCitations(
    text: string,
    contextPackage: AssembledContextPackage,
    callerSecurityRank: number = 0,
    callerHasVault: boolean = false
  ): {
    validCitations: ResolvedCitation[];
    invalidCitations: ResolvedCitation[];
    allCitations: ResolvedCitation[];
  } {
    const citationRegex = /\[(?:citation:)?(agent|version|run|claim|evidence|finding|runtime|file|file_line|dependency|vulnerability|cve|policy|package):([^\]]+)\]/gi;

    const matches = Array.from(text.matchAll(citationRegex));
    const allCitations: ResolvedCitation[] = [];
    const validCitations: ResolvedCitation[] = [];
    const invalidCitations: ResolvedCitation[] = [];

    const seenTags = new Set<string>();

    for (const match of matches) {
      const rawTag = match[0];
      if (seenTags.has(rawTag)) continue;
      seenTags.add(rawTag);

      const rawType = match[1].toLowerCase();
      const rawId = match[2].trim();

      const targetType = this.normalizeTargetType(rawType);
      const resolved = this.verifyCitationTarget(rawTag, targetType, rawId, contextPackage, callerSecurityRank, callerHasVault);

      allCitations.push(resolved);
      if (resolved.is_valid) {
        validCitations.push(resolved);
      } else {
        invalidCitations.push(resolved);
      }
    }

    return { validCitations, invalidCitations, allCitations };
  }

  private normalizeTargetType(rawType: string): CitationTargetType {
    switch (rawType) {
      case 'cve':
      case 'vulnerability':
        return 'vulnerability';
      case 'file':
      case 'file_line':
        return 'file_line';
      case 'dep':
      case 'dependency':
        return 'dependency';
      case 'pkg':
      case 'package':
        return 'package';
      case 'agent':
        return 'agent';
      case 'version':
        return 'version';
      case 'run':
        return 'run';
      case 'claim':
        return 'claim';
      case 'evidence':
        return 'evidence';
      case 'finding':
        return 'finding';
      case 'runtime':
        return 'runtime';
      case 'policy':
        return 'policy';
      default:
        return 'finding';
    }
  }

  private verifyCitationTarget(
    rawTag: string,
    targetType: CitationTargetType,
    targetId: string,
    contextPackage: AssembledContextPackage,
    callerSecurityRank: number,
    callerHasVault: boolean
  ): ResolvedCitation {
    // 1. Check if it exists in the assembled context package facts
    const contextFact = contextPackage.serialized_facts.find((f) => {
      if (f.entity_ref_id === targetId || f.fact_id.includes(targetId)) return true;
      if (f.entity_ref_id.toLowerCase() === targetId.toLowerCase()) return true;
      if (targetType === 'vulnerability' && f.formatted_content.toLowerCase().includes(targetId.toLowerCase())) return true;
      if (targetType === 'file_line' && f.formatted_content.toLowerCase().includes(targetId.toLowerCase())) return true;
      return false;
    });

    if (contextFact) {
      if (contextFact.vault_restricted && !callerHasVault) {
        return {
          citation_raw: rawTag,
          target_type: targetType,
          target_id: targetId,
          is_valid: false,
          rejection_reason: 'UNAUTHORIZED: Citation targets a vault-restricted object without caller grant.',
        };
      }

      if (contextFact.security_rank > callerSecurityRank) {
        return {
          citation_raw: rawTag,
          target_type: targetType,
          target_id: targetId,
          is_valid: false,
          rejection_reason: 'UNAUTHORIZED: Citation classification exceeds caller clearance rank.',
        };
      }

      return {
        citation_raw: rawTag,
        target_type: targetType,
        target_id: targetId,
        is_valid: true,
        resolved_summary: `Verified context entity (${contextFact.entity_type}:${contextFact.entity_ref_id})`,
        security_classification: contextFact.security_classification,
      };
    }

    // 2. Check authoritative knowledge corpus registry
    const registryObject =
      this.corpus.getRegistry().getByEntityRefId(targetId) ||
      this.corpus.getRegistry().getObject(targetId) ||
      this.corpus.getRegistry().getByEntityRefId(targetId.toLowerCase());

    if (registryObject) {
      return {
        citation_raw: rawTag,
        target_type: targetType,
        target_id: targetId,
        is_valid: true,
        resolved_summary: `Authoritative registry match (${registryObject.object_type}:${registryObject.entity_ref_id})`,
        security_classification: registryObject.security_classification_code,
      };
    }

    // 3. Fallback check on bundle evidence IDs & source locators
    for (const bundle of contextPackage.bundles) {
      if (bundle.claim_id === targetId) {
        return {
          citation_raw: rawTag,
          target_type: 'claim',
          target_id: targetId,
          is_valid: true,
          resolved_summary: `Claim bundle match (${bundle.bundle_id})`,
        };
      }
      for (const ev of bundle.evidence_items) {
        if (ev.evidence_id === targetId || ev.source_locator === targetId) {
          return {
            citation_raw: rawTag,
            target_type: 'evidence',
            target_id: targetId,
            source_locator: ev.source_locator,
            is_valid: true,
            resolved_summary: `Evidence item match (${ev.evidence_id} - ${ev.evidence_type})`,
          };
        }
      }
      if (bundle.finding_links) {
        for (const fl of bundle.finding_links) {
          if (fl.finding_id === targetId || fl.rule_id === targetId) {
            return {
              citation_raw: rawTag,
              target_type: 'finding',
              target_id: targetId,
              source_locator: `${fl.file_path}#${fl.line_number}`,
              is_valid: true,
              resolved_summary: `Finding match (${fl.finding_id})`,
            };
          }
        }
      }
    }

    // 4. Citation does not resolve to any authorized stored object -> Reject as fabricated!
    return {
      citation_raw: rawTag,
      target_type: targetType,
      target_id: targetId,
      is_valid: false,
      rejection_reason: `FABRICATED_OR_UNRESOLVABLE: Citation ID "${targetId}" does not resolve to any authorized stored object.`,
    };
  }
}
