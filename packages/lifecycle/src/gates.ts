import { LifecycleEntityKind } from './registry.ts';

export interface PolicyDecisionRecord {
  readonly policyRuleId?: string;
  readonly policyName?: string;
  readonly decision: 'PASS' | 'FAIL' | 'WARN' | 'MANUAL_REVIEW';
  readonly outcomeReason?: string;
}

export interface RiskRecord {
  readonly riskId?: string;
  readonly severity: 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  readonly title?: string;
  readonly mitigated?: boolean;
}

export interface ApprovalRecord {
  readonly approvalId?: string;
  readonly approverId: string;
  readonly approverRole: string;
  readonly decision: 'APPROVED' | 'REJECTED';
  readonly reason?: string;
  readonly decidedAt?: string;
}

export interface PolicyGateContext {
  readonly entityRefId: string;
  readonly entityKind: LifecycleEntityKind;
  readonly fromState: string | null;
  readonly toState: string;
  readonly actorRef: string;
  readonly correlationId: string;
  readonly actorRoles?: string[];
  readonly policyDecisions?: PolicyDecisionRecord[];
  readonly risks?: RiskRecord[];
  readonly approvals?: ApprovalRecord[];
  readonly validationRunStatus?: 'PASSED' | 'FAILED' | 'ERROR' | 'REQUIRES_REVIEW';
  readonly customAttributes?: Record<string, unknown>;
}

export interface GateCheckResult {
  readonly allowed: boolean;
  readonly gateKey: string;
  readonly reason?: string;
  readonly violations: string[];
}

export type PolicyGateEvaluatorFn = (context: PolicyGateContext) => Promise<GateCheckResult> | GateCheckResult;

// 1. POLICY_PASS_GATE
export const policyPassGateEvaluator: PolicyGateEvaluatorFn = (context) => {
  const violations: string[] = [];
  if (context.policyDecisions && context.policyDecisions.length > 0) {
    for (const pd of context.policyDecisions) {
      if (pd.decision === 'FAIL') {
        violations.push(`Policy '${pd.policyName || pd.policyRuleId || 'Unnamed'}' evaluated to FAIL: ${pd.outcomeReason || 'Policy rule violated'}`);
      }
    }
  }

  if (violations.length > 0) {
    return {
      allowed: false,
      gateKey: 'POLICY_PASS_GATE',
      reason: 'One or more security policies evaluated to FAIL',
      violations,
    };
  }

  return {
    allowed: true,
    gateKey: 'POLICY_PASS_GATE',
    violations: [],
  };
};

// 2. ZERO_CRITICAL_RISKS_GATE
export const zeroCriticalRisksGateEvaluator: PolicyGateEvaluatorFn = (context) => {
  const violations: string[] = [];
  if (context.risks && context.risks.length > 0) {
    for (const r of context.risks) {
      if (!r.mitigated && (r.severity === 'CRITICAL' || r.severity === 'HIGH')) {
        violations.push(`Unmitigated ${r.severity} risk: ${r.title || r.riskId || 'Risk identified'}`);
      }
    }
  }

  if (violations.length > 0) {
    return {
      allowed: false,
      gateKey: 'ZERO_CRITICAL_RISKS_GATE',
      reason: 'Unmitigated HIGH or CRITICAL severity risks detected',
      violations,
    };
  }

  return {
    allowed: true,
    gateKey: 'ZERO_CRITICAL_RISKS_GATE',
    violations: [],
  };
};

// 3. EXPLICIT_APPROVAL_GATE
export const explicitApprovalGateEvaluator: PolicyGateEvaluatorFn = (context) => {
  const violations: string[] = [];
  const approvals = context.approvals || [];
  
  const validApproval = approvals.find(a => a.decision === 'APPROVED');
  const rejectedApproval = approvals.find(a => a.decision === 'REJECTED');

  if (rejectedApproval) {
    violations.push(`Explicit rejection recorded by approver '${rejectedApproval.approverId}': ${rejectedApproval.reason || 'No reason provided'}`);
  }

  if (!validApproval) {
    violations.push('No formal APPROVED sign-off recorded from an authorized reviewer');
  }

  if (violations.length > 0) {
    return {
      allowed: false,
      gateKey: 'EXPLICIT_APPROVAL_GATE',
      reason: 'Required manual or security approval is missing or rejected',
      violations,
    };
  }

  return {
    allowed: true,
    gateKey: 'EXPLICIT_APPROVAL_GATE',
    violations: [],
  };
};

// 4. VALIDATION_PASSED_GATE
export const validationPassedGateEvaluator: PolicyGateEvaluatorFn = (context) => {
  const violations: string[] = [];
  if (!context.validationRunStatus) {
    violations.push('No validation run status provided; regression verification is required');
  } else if (context.validationRunStatus !== 'PASSED') {
    violations.push(`Validation run status is '${context.validationRunStatus}' (must be 'PASSED')`);
  }

  if (violations.length > 0) {
    return {
      allowed: false,
      gateKey: 'VALIDATION_PASSED_GATE',
      reason: 'Validation run has not passed regression and differential criteria',
      violations,
    };
  }

  return {
    allowed: true,
    gateKey: 'VALIDATION_PASSED_GATE',
    violations: [],
  };
};

// 5. QUARANTINE_LIFT_GATE
export const quarantineLiftGateEvaluator: PolicyGateEvaluatorFn = (context) => {
  const violations: string[] = [];
  const actorRoles = context.actorRoles || [];
  const isAdmin = actorRoles.includes('platform_admin') || actorRoles.includes('security_lead');

  if (!isAdmin) {
    violations.push(`Actor '${context.actorRef}' lacks required platform_admin or security_lead role to lift quarantine`);
  }

  const approvals = context.approvals || [];
  const hasAdminApproval = approvals.some(a => a.decision === 'APPROVED' && (a.approverRole === 'platform_admin' || a.approverRole === 'security_lead'));
  if (!hasAdminApproval) {
    violations.push('Lifting quarantine requires an explicit signed administrative approval record');
  }

  if (violations.length > 0) {
    return {
      allowed: false,
      gateKey: 'QUARANTINE_LIFT_GATE',
      reason: 'Quarantine lift requirements not met',
      violations,
    };
  }

  return {
    allowed: true,
    gateKey: 'QUARANTINE_LIFT_GATE',
    violations: [],
  };
};

// Evaluator Registry
export class PolicyGateRegistry {
  private static evaluators = new Map<string, PolicyGateEvaluatorFn>([
    ['POLICY_PASS_GATE', policyPassGateEvaluator],
    ['ZERO_CRITICAL_RISKS_GATE', zeroCriticalRisksGateEvaluator],
    ['EXPLICIT_APPROVAL_GATE', explicitApprovalGateEvaluator],
    ['VALIDATION_PASSED_GATE', validationPassedGateEvaluator],
    ['QUARANTINE_LIFT_GATE', quarantineLiftGateEvaluator],
  ]);

  public static registerGate(key: string, evaluator: PolicyGateEvaluatorFn): void {
    this.evaluators.set(key, evaluator);
  }

  public static getEvaluator(key: string): PolicyGateEvaluatorFn | undefined {
    return this.evaluators.get(key);
  }

  public static async evaluateGate(gateKey: string, context: PolicyGateContext): Promise<GateCheckResult> {
    const evaluator = this.evaluators.get(gateKey);
    if (!evaluator) {
      // Default: if no specific evaluator is registered, allow but log
      return {
        allowed: true,
        gateKey,
        violations: [],
      };
    }
    return await evaluator(context);
  }
}
