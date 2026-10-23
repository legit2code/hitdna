import crypto from 'crypto';
import {
  ManualReviewItem,
  ManualReviewStatus,
  IdentityResolutionOutcome,
  IdentityEvidenceScore,
} from './types.ts';
import { ProvenanceRecord, ProvenanceRecordSchema } from '../../contracts/src/provenance.ts';

export class ManualReviewQueue {
  private queue = new Map<string, ManualReviewItem>();

  /**
   * Enqueues an unresolved identity conflict or high-value anomaly for operator review.
   */
  enqueueConflict(entry: {
    candidate_locators: string[];
    conflict_summary: string;
    suggested_outcome: IdentityResolutionOutcome;
    confidence: number;
    evidence: IdentityEvidenceScore;
  }): ManualReviewItem {
    const id = `rev-${crypto.randomUUID().substring(0, 8)}`;
    const now = new Date().toISOString();

    const item: ManualReviewItem = {
      id,
      created_at: now,
      updated_at: now,
      candidate_locators: entry.candidate_locators,
      conflict_summary: entry.conflict_summary,
      suggested_outcome: entry.suggested_outcome,
      confidence: entry.confidence,
      evidence: entry.evidence,
      status: 'PENDING_REVIEW',
    };

    this.queue.set(id, item);
    return item;
  }

  getItem(id: string): ManualReviewItem | undefined {
    return this.queue.get(id);
  }

  listItems(status?: ManualReviewStatus): ManualReviewItem[] {
    const all = Array.from(this.queue.values());
    if (!status) return all;
    return all.filter(item => item.status === status);
  }

  getPendingCount(): number {
    return this.listItems('PENDING_REVIEW').length;
  }

  /**
   * Applies an operator review decision to an unresolved identity conflict.
   */
  resolveConflict(id: string, decision: {
    status: 'RESOLVED_CANONICAL' | 'RESOLVED_DISTINCT' | 'REJECTED';
    resolved_outcome?: IdentityResolutionOutcome;
    resolved_canonical_id?: string;
    reviewed_by: string;
    review_note?: string;
  }): { item: ManualReviewItem; provenance: ProvenanceRecord } {
    const item = this.queue.get(id);
    if (!item) {
      throw new Error(`Manual review item ${id} not found`);
    }

    item.status = decision.status;
    item.resolved_outcome = decision.resolved_outcome || (decision.status === 'RESOLVED_CANONICAL' ? 'SAME_CANONICAL_AGENT' : 'DISTINCT');
    item.resolved_canonical_id = decision.resolved_canonical_id;
    item.reviewed_by = decision.reviewed_by;
    item.review_note = decision.review_note;
    item.updated_at = new Date().toISOString();

    const inputHash = crypto.createHash('sha256')
      .update(`${id}:${decision.status}:${decision.reviewed_by}`)
      .digest('hex');

    const provenance: ProvenanceRecord = ProvenanceRecordSchema.parse({
      provenance_id: crypto.randomUUID(),
      source_spans: [],
      input_hashes: [inputHash],
      rule_id: 'MANUAL_IDENTITY_REVIEW_AUDIT_V1',
      ruleset_version: '1.0.0',
      transformation_type: 'EXTERNAL_ENRICHMENT',
      confidence: 1.0,
      derived_at: new Date().toISOString(),
      engine_signature: 'caim:manual-review:queue:v1.0.0',
    });

    return { item, provenance };
  }
}
