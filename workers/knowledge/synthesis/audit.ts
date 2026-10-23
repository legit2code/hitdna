import { AnswerAuditRecord, EpistemicDecision, GroundingVerdict, ResolvedCitation } from './types.ts';
import crypto from 'crypto';

export class AnswerAuditService {
  private auditHistory: AnswerAuditRecord[] = [];
  private readonly MAX_HISTORY = 200;

  public logSynthesis(record: Omit<AnswerAuditRecord, 'audit_id' | 'timestamp'>): AnswerAuditRecord {
    const audit_id = `audit-rag-${crypto.randomBytes(6).toString('hex')}`;
    const timestamp = new Date().toISOString();

    const fullRecord: AnswerAuditRecord = {
      audit_id,
      timestamp,
      ...record,
    };

    this.auditHistory.unshift(fullRecord);
    if (this.auditHistory.length > this.MAX_HISTORY) {
      this.auditHistory.pop();
    }

    return fullRecord;
  }

  public getHistory(limit: number = 50): AnswerAuditRecord[] {
    return this.auditHistory.slice(0, limit);
  }

  public getAuditRecord(auditId: string): AnswerAuditRecord | undefined {
    return this.auditHistory.find((r) => r.audit_id === auditId);
  }
}
