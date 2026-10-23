import { RetrievedDocument } from '../retrieval/types.ts';
import { EvidenceClaimBundle } from './types.ts';

export class EvidenceClaimBundleBuilder {
  /**
   * Identifies related claims, evidence, and findings, binding them into coherent bundles
   * for grounding validation and multi-hop synthesis.
   */
  public static buildBundles(docs: RetrievedDocument[]): EvidenceClaimBundle[] {
    const bundles: EvidenceClaimBundle[] = [];
    const claimDocs = docs.filter((d) => d.object_type === 'claim');
    const evidenceDocs = docs.filter((d) => d.object_type === 'evidence');
    const findingDocs = docs.filter((d) => d.object_type === 'finding');

    // Build map of evidence by id
    const evidenceMap = new Map<string, RetrievedDocument>();
    for (const ev of evidenceDocs) {
      evidenceMap.set(ev.entity_ref_id, ev);
    }

    // Build bundles from claims
    for (const c of claimDocs) {
      const payload = c.payload || {};
      const evidenceLinks: Array<{ evidence_id: string }> = payload.evidence_links || [];
      const evidenceItems: EvidenceClaimBundle['evidence_items'] = [];

      for (const link of evidenceLinks) {
        const evDoc = evidenceMap.get(link.evidence_id);
        if (evDoc) {
          const evPayload = evDoc.payload || {};
          evidenceItems.push({
            evidence_id: evDoc.entity_ref_id,
            evidence_type: evPayload.evidence_type || 'OBSERVATION',
            evidence_class: evPayload.evidence_class || 'DIRECT_OBSERVATION',
            source_locator: evPayload.source_locator || evDoc.exact_keywords?.symbol_name,
            observation: evPayload.observation || evDoc.full_content,
          });
        }
      }

      // Find related findings
      const relatedFindings = findingDocs
        .filter((f) => f.analysis_run_id === c.analysis_run_id && f.agent_id === c.agent_id)
        .map((f) => ({
          finding_id: f.entity_ref_id,
          rule_id: f.exact_keywords?.rule_id || (f.payload?.rule_id as string),
          file_path: f.exact_keywords?.symbol_name || (f.payload?.file_path as string),
          line_number: f.payload?.line_number as number,
        }));

      bundles.push({
        bundle_id: `bundle-${c.entity_ref_id}`,
        claim_id: c.entity_ref_id,
        statement: payload.statement || c.full_content,
        claim_state: payload.claim_state || 'SUPPORTED',
        confidence: payload.confidence || 0.95,
        evidence_items: evidenceItems,
        finding_links: relatedFindings.length > 0 ? relatedFindings : undefined,
        agent_id: c.agent_id,
        agent_version_id: c.agent_version_id,
      });
    }

    // Handle orphaned evidence that was retrieved without a direct parent claim
    const linkedEvidenceIds = new Set(
      bundles.flatMap((b) => b.evidence_items.map((e) => e.evidence_id))
    );

    for (const ev of evidenceDocs) {
      if (!linkedEvidenceIds.has(ev.entity_ref_id)) {
        const evPayload = ev.payload || {};
        bundles.push({
          bundle_id: `bundle-orphan-${ev.entity_ref_id}`,
          evidence_items: [
            {
              evidence_id: ev.entity_ref_id,
              evidence_type: evPayload.evidence_type || 'DIRECT_OBSERVATION',
              evidence_class: evPayload.evidence_class || 'DIRECT_OBSERVATION',
              source_locator: evPayload.source_locator,
              observation: evPayload.observation || ev.full_content,
            },
          ],
          agent_id: ev.agent_id,
          agent_version_id: ev.agent_version_id,
        });
      }
    }

    return bundles;
  }
}
