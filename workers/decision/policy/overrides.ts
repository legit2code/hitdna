/**
 * Policy Override & Audit Trail Manager (Architecture V2.0.1)
 * Records and audits authorized overrides of policy decisions with role-based sign-off.
 */

import { PolicyOverrideRecord, PolicyOutcome } from '../types.ts';

export interface CreateOverrideInput {
  analysisRunId: string;
  originalOutcome: PolicyOutcome;
  overriddenOutcome: PolicyOutcome;
  reason: string;
  justificationDetails?: string;
  approverId: string;
  approverRole: string;
}

export class PolicyOverrideManager {
  private static readonly overrides: Map<string, PolicyOverrideRecord[]> = new Map(); // Keyed by analysisRunId

  /**
   * Applies an authorized policy override with full audit trail.
   */
  public static applyOverride(input: CreateOverrideInput): PolicyOverrideRecord {
    if (!input.approverId || !input.approverRole) {
      throw new Error('Policy override requires an authenticated approverId and approverRole.');
    }
    if (!input.reason || input.reason.trim().length < 10) {
      throw new Error('Policy override requires a descriptive justification reason (min 10 chars).');
    }

    const runOverrides = this.overrides.get(input.analysisRunId) || [];
    // Mark previous active overrides as SUPERSEDED
    for (const prev of runOverrides) {
      if (prev.status === 'ACTIVE') {
        prev.status = 'SUPERSEDED';
      }
    }

    const newOverride: PolicyOverrideRecord = {
      override_id: `ovr-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      analysis_run_id: input.analysisRunId,
      original_outcome: input.originalOutcome,
      overridden_outcome: input.overriddenOutcome,
      reason: input.reason.trim(),
      justification_details: input.justificationDetails,
      approver_id: input.approverId,
      approver_role: input.approverRole,
      status: 'ACTIVE',
      created_at: new Date().toISOString(),
    };

    runOverrides.push(newOverride);
    this.overrides.set(input.analysisRunId, runOverrides);
    return newOverride;
  }

  /**
   * Retrieves the current active override for a run if one exists.
   */
  public static getActiveOverride(analysisRunId: string): PolicyOverrideRecord | undefined {
    const list = this.overrides.get(analysisRunId) || [];
    return list.find((o) => o.status === 'ACTIVE');
  }

  /**
   * Retrieves full audit history of overrides for a run.
   */
  public static getOverrideHistory(analysisRunId: string): PolicyOverrideRecord[] {
    return this.overrides.get(analysisRunId) || [];
  }

  /**
   * Revokes an active override.
   */
  public static revokeOverride(overrideId: string, revokerId: string): boolean {
    for (const list of this.overrides.values()) {
      const record = list.find((o) => o.override_id === overrideId);
      if (record && record.status === 'ACTIVE') {
        record.status = 'REVOKED';
        return true;
      }
    }
    return false;
  }

  public static clear(): void {
    this.overrides.clear();
  }
}
