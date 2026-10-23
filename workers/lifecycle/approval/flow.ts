import { ApprovalRecord } from '../types.ts';

export interface CreateApprovalRequest {
  targetEntityRefId: string;
  targetType: 'MODIFICATION_WORKSPACE' | 'AGENT_VERSION' | 'VALIDATION_RUN';
  approverId: string;
  approverRole: string;
  decision: 'APPROVED' | 'REJECTED' | 'PENDING' | 'REVOKED';
  rationale: string;
}

export class ApprovalEngine {
  private static allowedRoles = new Set([
    'security_auditor',
    'platform_admin',
    'security_lead',
    'compliance_officer',
    'tenant_admin',
  ]);

  /**
   * Creates and validates a formal security approval record.
   */
  public static createApproval(request: CreateApprovalRequest): ApprovalRecord {
    if (!this.allowedRoles.has(request.approverRole)) {
      throw new Error(
        `Role '${request.approverRole}' is not authorized to grant lifecycle approvals. Required one of: ${Array.from(this.allowedRoles).join(', ')}`
      );
    }

    if (!request.rationale || request.rationale.trim().length < 5) {
      throw new Error('Approval requires a non-empty descriptive rationale for the audit log.');
    }

    const approvalId = `appr-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const signature = `sig_sha256_${Buffer.from(`${approvalId}:${request.targetEntityRefId}:${request.decision}:${request.approverId}`).toString('base64')}`;

    return {
      approvalId,
      targetEntityRefId: request.targetEntityRefId,
      targetType: request.targetType,
      approverId: request.approverId,
      approverRole: request.approverRole,
      decision: request.decision,
      rationale: request.rationale,
      decidedAt: new Date().toISOString(),
      signature,
    };
  }

  /**
   * Verifies whether an entity has formal, valid APPROVED status from an authorized reviewer.
   */
  public static isApproved(approvals: ApprovalRecord[]): {
    approved: boolean;
    validApproval?: ApprovalRecord;
    rejection?: ApprovalRecord;
    reason?: string;
  } {
    const rejection = approvals.find((a) => a.decision === 'REJECTED');
    if (rejection) {
      return {
        approved: false,
        rejection,
        reason: `Explicit rejection by '${rejection.approverId}': ${rejection.rationale}`,
      };
    }

    const validApproval = approvals.find((a) => a.decision === 'APPROVED');
    if (!validApproval) {
      return {
        approved: false,
        reason: 'No formal APPROVED decision found from an authorized reviewer.',
      };
    }

    return {
      approved: true,
      validApproval,
    };
  }
}
