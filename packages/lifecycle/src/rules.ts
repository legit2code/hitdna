import { LifecycleEntityKind } from './registry.ts';

export interface TransitionRule {
  readonly fromState: string | null;
  readonly toState: string;
  readonly action: string;
  readonly description: string;
  readonly requiresReason: boolean;
  readonly policyGated: boolean;
  readonly gateKey?: string;
  readonly allowedRoles?: string[];
}

export type TransitionRuleTable = Record<string, TransitionRule[]>; // Keyed by `${fromState ?? '__GENESIS__'}`

export function buildRuleTable(rules: TransitionRule[]): TransitionRuleTable {
  const table: TransitionRuleTable = {};
  for (const rule of rules) {
    const key = rule.fromState === null ? '__GENESIS__' : rule.fromState;
    if (!table[key]) {
      table[key] = [];
    }
    table[key].push(rule);
  }
  return table;
}

// 1. ANALYSIS_RUN Rules
export const ANALYSIS_RUN_RULES: TransitionRule[] = [
  // Genesis
  { fromState: null, toState: 'PENDING', action: 'INITIALIZE', description: 'Initialize analysis run', requiresReason: true, policyGated: false },
  // From PENDING
  { fromState: 'PENDING', toState: 'QUEUED', action: 'QUEUE', description: 'Queue analysis run for execution', requiresReason: false, policyGated: false },
  { fromState: 'PENDING', toState: 'RUNNING', action: 'START_DIRECT', description: 'Directly start analysis run', requiresReason: false, policyGated: false },
  { fromState: 'PENDING', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel pending analysis run', requiresReason: true, policyGated: false },
  // From QUEUED
  { fromState: 'QUEUED', toState: 'RUNNING', action: 'START', description: 'Worker picks up queued run and starts execution', requiresReason: false, policyGated: false },
  { fromState: 'QUEUED', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel queued analysis run', requiresReason: true, policyGated: false },
  // From RUNNING
  { fromState: 'RUNNING', toState: 'STAGE_EXECUTION', action: 'START_STAGES', description: 'Begin executing analyzer stages in sequence or DAG', requiresReason: false, policyGated: false },
  { fromState: 'RUNNING', toState: 'EVALUATING_POLICIES', action: 'START_EVALUATION', description: 'Direct evaluation transition when stages skipped/cached', requiresReason: false, policyGated: false },
  { fromState: 'RUNNING', toState: 'PARTIAL', action: 'PARTIAL_COMPLETE', description: 'Analysis completed with partial evidence (e.g. static complete, dynamic unverified)', requiresReason: false, policyGated: false },
  { fromState: 'RUNNING', toState: 'FAILED', action: 'FAIL', description: 'Execution failed at run setup or dependency resolution', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel running analysis', requiresReason: true, policyGated: false },
  // From STAGE_EXECUTION
  { fromState: 'STAGE_EXECUTION', toState: 'EVALUATING_POLICIES', action: 'STAGES_COMPLETE', description: 'All analyzer stages completed; begin policy evaluation', requiresReason: false, policyGated: false },
  { fromState: 'STAGE_EXECUTION', toState: 'PARTIAL', action: 'PARTIAL_COMPLETE', description: 'Stages completed with partial evidence (e.g. static complete, dynamic unverified)', requiresReason: false, policyGated: false },
  { fromState: 'STAGE_EXECUTION', toState: 'FAILED', action: 'FAIL_STAGE', description: 'Fatal analyzer stage failure occurred', requiresReason: true, policyGated: false },
  { fromState: 'STAGE_EXECUTION', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel stage execution', requiresReason: true, policyGated: false },
  // From EVALUATING_POLICIES
  { fromState: 'EVALUATING_POLICIES', toState: 'COMPLETED', action: 'COMPLETE', description: 'Policies and scoring evaluated successfully with clean posture', requiresReason: false, policyGated: true, gateKey: 'POLICY_PASS_GATE' },
  { fromState: 'EVALUATING_POLICIES', toState: 'PARTIAL', action: 'PARTIAL_COMPLETE', description: 'Static analysis complete but dynamic analysis unverified; partial evaluation completed', requiresReason: false, policyGated: false },
  { fromState: 'EVALUATING_POLICIES', toState: 'REQUIRES_REVIEW', action: 'FLAG_REVIEW', description: 'Policy evaluation surfaced warnings or high risks requiring manual review', requiresReason: true, policyGated: false },
  { fromState: 'EVALUATING_POLICIES', toState: 'REANALYZING', action: 'REANALYZE_REQUESTED', description: 'Policy ruleset requested incremental reanalysis with updated weights', requiresReason: true, policyGated: false },
  { fromState: 'EVALUATING_POLICIES', toState: 'FAILED', action: 'POLICY_REJECT_FAIL', description: 'Policy evaluation rejected run due to hard security violations', requiresReason: true, policyGated: false },
  { fromState: 'EVALUATING_POLICIES', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel during policy evaluation', requiresReason: true, policyGated: false },
  // From REQUIRES_REVIEW
  { fromState: 'REQUIRES_REVIEW', toState: 'IN_REVIEW', action: 'START_REVIEW', description: 'Security reviewer opens case and begins audit', requiresReason: true, policyGated: false, allowedRoles: ['security_auditor', 'platform_admin', 'tenant_admin'] },
  { fromState: 'REQUIRES_REVIEW', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel unreviewed run', requiresReason: true, policyGated: false },
  // From IN_REVIEW
  { fromState: 'IN_REVIEW', toState: 'COMPLETED', action: 'APPROVE_REVIEW', description: 'Reviewer approves analysis with explicit sign-off', requiresReason: true, policyGated: true, gateKey: 'EXPLICIT_APPROVAL_GATE', allowedRoles: ['security_auditor', 'platform_admin'] },
  { fromState: 'IN_REVIEW', toState: 'REANALYZING', action: 'REQUEST_REANALYSIS', description: 'Reviewer requests targeted reanalysis with updated parameters', requiresReason: true, policyGated: false, allowedRoles: ['security_auditor', 'platform_admin'] },
  { fromState: 'IN_REVIEW', toState: 'FAILED', action: 'REJECT_FAIL', description: 'Reviewer rejects analysis due to unacceptable risks', requiresReason: true, policyGated: false, allowedRoles: ['security_auditor', 'platform_admin'] },
  // From REANALYZING
  { fromState: 'REANALYZING', toState: 'RUNNING', action: 'RESTART_RUN', description: 'Reanalysis worker picks up run', requiresReason: true, policyGated: false },
  { fromState: 'REANALYZING', toState: 'STAGE_EXECUTION', action: 'RESTART_STAGES', description: 'Re-executing specific stages', requiresReason: true, policyGated: false },
  { fromState: 'REANALYZING', toState: 'FAILED', action: 'FAIL', description: 'Reanalysis attempt failed', requiresReason: true, policyGated: false },
  { fromState: 'REANALYZING', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel reanalysis', requiresReason: true, policyGated: false },
  // From PARTIAL
  { fromState: 'PARTIAL', toState: 'COMPLETED', action: 'VERIFY_DYNAMIC', description: 'Subsequent dynamic verification completed or manual verification accepted', requiresReason: true, policyGated: false },
  { fromState: 'PARTIAL', toState: 'ARCHIVED', action: 'ARCHIVE', description: 'Archive partially completed run', requiresReason: false, policyGated: false },
  { fromState: 'PARTIAL', toState: 'FAILED', action: 'FAIL', description: 'Mark partial run as failed', requiresReason: true, policyGated: false },
  { fromState: 'PARTIAL', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel partial run', requiresReason: true, policyGated: false },
];

// 2. ANALYSIS_STAGE_RUN Rules
export const ANALYSIS_STAGE_RUN_RULES: TransitionRule[] = [
  // Genesis
  { fromState: null, toState: 'PENDING', action: 'INITIALIZE', description: 'Initialize stage run', requiresReason: false, policyGated: false },
  // From PENDING
  { fromState: 'PENDING', toState: 'RUNNING', action: 'START', description: 'Stage begins execution', requiresReason: false, policyGated: false },
  { fromState: 'PENDING', toState: 'SKIPPED', action: 'SKIP', description: 'Stage skipped due to conditions or cache', requiresReason: true, policyGated: false },
  { fromState: 'PENDING', toState: 'CANCELLED', action: 'CANCEL', description: 'Stage cancelled before start', requiresReason: true, policyGated: false },
  // From RUNNING
  { fromState: 'RUNNING', toState: 'COMPLETED', action: 'COMPLETE', description: 'Stage completed with output recorded', requiresReason: false, policyGated: false },
  { fromState: 'RUNNING', toState: 'FAILED', action: 'FAIL', description: 'Stage execution encountered error', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'TIMED_OUT', action: 'TIMEOUT', description: 'Stage execution exceeded deadline', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'SKIPPED', action: 'SKIP_RUNTIME', description: 'Stage skipped during runtime check', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'CANCELLED', action: 'CANCEL', description: 'Stage cancelled while running', requiresReason: true, policyGated: false },
];

// 3. AGENT_VERSION Rules
export const AGENT_VERSION_RULES: TransitionRule[] = [
  // Genesis
  { fromState: null, toState: 'DRAFT', action: 'CREATE_DRAFT', description: 'Create draft agent version', requiresReason: true, policyGated: false },
  { fromState: null, toState: 'DISCOVERED', action: 'DISCOVER', description: 'Direct discovery of agent version from external adapter', requiresReason: true, policyGated: false },
  // From DRAFT
  { fromState: 'DRAFT', toState: 'DISCOVERED', action: 'DISCOVER', description: 'Mark draft as discovered from repo/manifest', requiresReason: false, policyGated: false },
  { fromState: 'DRAFT', toState: 'ANALYZING', action: 'ANALYZE', description: 'Trigger analysis on draft version', requiresReason: false, policyGated: false },
  // From DISCOVERED
  { fromState: 'DISCOVERED', toState: 'ANALYZING', action: 'START_ANALYSIS', description: 'Dispatch analysis pipeline for discovered agent', requiresReason: false, policyGated: false },
  { fromState: 'DISCOVERED', toState: 'QUARANTINED', action: 'QUARANTINE_DIRECT', description: 'Immediate quarantine due to blacklisted publisher or malicious signature', requiresReason: true, policyGated: false },
  // From ANALYZING
  { fromState: 'ANALYZING', toState: 'ANALYZED', action: 'ANALYSIS_SUCCEEDED', description: 'All analytical stages completed and synthesized', requiresReason: false, policyGated: false },
  { fromState: 'ANALYZING', toState: 'QUARANTINED', action: 'QUARANTINE_FINDINGS', description: 'Critical security vulnerability or evasion detected during analysis', requiresReason: true, policyGated: false },
  // From ANALYZED
  { fromState: 'ANALYZED', toState: 'VALIDATING', action: 'START_VALIDATION', description: 'Start regression and validation run against baseline', requiresReason: false, policyGated: false },
  { fromState: 'ANALYZED', toState: 'PENDING_REVIEW', action: 'FLAG_FOR_REVIEW', description: 'Policy evaluation requires manual review', requiresReason: true, policyGated: false },
  { fromState: 'ANALYZED', toState: 'APPROVED', action: 'AUTO_APPROVE', description: 'All policy gates satisfied, auto-approved for release pipeline', requiresReason: true, policyGated: true, gateKey: 'ZERO_CRITICAL_RISKS_GATE' },
  { fromState: 'ANALYZED', toState: 'QUARANTINED', action: 'QUARANTINE', description: 'Quarantine version due to severe security risks', requiresReason: true, policyGated: false },
  // From VALIDATING
  { fromState: 'VALIDATING', toState: 'APPROVED', action: 'VALIDATION_PASSED', description: 'Validation run completed with zero regressions', requiresReason: true, policyGated: true, gateKey: 'VALIDATION_PASSED_GATE' },
  { fromState: 'VALIDATING', toState: 'PENDING_REVIEW', action: 'VALIDATION_DIFF_REVIEW', description: 'Breaking diffs or unexpected behavioral changes detected', requiresReason: true, policyGated: false },
  { fromState: 'VALIDATING', toState: 'REVIEW_REJECTED', action: 'VALIDATION_REJECTED', description: 'Validation failure rejects the candidate version', requiresReason: true, policyGated: false },
  { fromState: 'VALIDATING', toState: 'QUARANTINED', action: 'VALIDATION_QUARANTINE', description: 'Validation discovered dangerous behavioral drift', requiresReason: true, policyGated: false },
  // From PENDING_REVIEW
  { fromState: 'PENDING_REVIEW', toState: 'IN_REVIEW', action: 'START_SECURITY_REVIEW', description: 'Security reviewer actively auditing version', requiresReason: true, policyGated: false, allowedRoles: ['security_auditor', 'platform_admin'] },
  { fromState: 'PENDING_REVIEW', toState: 'QUARANTINED', action: 'QUARANTINE_TRIAGE', description: 'Triage team quarantines version before full audit', requiresReason: true, policyGated: false },
  // From IN_REVIEW
  { fromState: 'IN_REVIEW', toState: 'APPROVED', action: 'APPROVE_SIGN_OFF', description: 'Reviewer signs off and approves version', requiresReason: true, policyGated: true, gateKey: 'EXPLICIT_APPROVAL_GATE', allowedRoles: ['security_auditor', 'platform_admin'] },
  { fromState: 'IN_REVIEW', toState: 'REVIEW_REJECTED', action: 'REJECT_SIGN_OFF', description: 'Reviewer rejects version release', requiresReason: true, policyGated: false, allowedRoles: ['security_auditor', 'platform_admin'] },
  { fromState: 'IN_REVIEW', toState: 'QUARANTINED', action: 'QUARANTINE_CRITICAL', description: 'Reviewer discovers critical exploit; moves to quarantine', requiresReason: true, policyGated: false },
  // From REVIEW_REJECTED
  { fromState: 'REVIEW_REJECTED', toState: 'ANALYZING', action: 'REANALYZE_REMEDY', description: 'Re-trigger analysis after applying remediation patches', requiresReason: true, policyGated: false },
  { fromState: 'REVIEW_REJECTED', toState: 'ARCHIVED', action: 'ARCHIVE_REJECTED', description: 'Archive rejected version', requiresReason: true, policyGated: false },
  // From QUARANTINED
  { fromState: 'QUARANTINED', toState: 'IN_REVIEW', action: 'UNQUARANTINE_REVIEW', description: 'Lift quarantine under controlled forensic review', requiresReason: true, policyGated: true, gateKey: 'QUARANTINE_LIFT_GATE', allowedRoles: ['platform_admin'] },
  { fromState: 'QUARANTINED', toState: 'REVOKED', action: 'REVOKE_QUARANTINED', description: 'Permanently revoke quarantined version', requiresReason: true, policyGated: false, allowedRoles: ['platform_admin'] },
  // From APPROVED
  { fromState: 'APPROVED', toState: 'PROMOTED', action: 'PROMOTE', description: 'Promote version to staging or target catalog', requiresReason: true, policyGated: true, gateKey: 'ZERO_CRITICAL_RISKS_GATE' },
  { fromState: 'APPROVED', toState: 'RELEASED', action: 'RELEASE_DIRECT', description: 'Direct release to production', requiresReason: true, policyGated: true, gateKey: 'POLICY_PASS_GATE' },
  // From PROMOTED
  { fromState: 'PROMOTED', toState: 'RELEASED', action: 'RELEASE', description: 'Publish promoted version to general availability', requiresReason: true, policyGated: true, gateKey: 'POLICY_PASS_GATE' },
  { fromState: 'PROMOTED', toState: 'DEPRECATED', action: 'DEPRECATE', description: 'Deprecate promoted version before release', requiresReason: true, policyGated: false },
  // From RELEASED
  { fromState: 'RELEASED', toState: 'DEPRECATED', action: 'DEPRECATE', description: 'Deprecate live version', requiresReason: true, policyGated: false },
  { fromState: 'RELEASED', toState: 'SUPERSEDED', action: 'SUPERSEDE', description: 'Supersede live version with next release', requiresReason: true, policyGated: false },
  { fromState: 'RELEASED', toState: 'REVOKED', action: 'REVOKE_EMERGENCY', description: 'Emergency revocation of active version', requiresReason: true, policyGated: false, allowedRoles: ['security_auditor', 'platform_admin'] },
  // From Terminal States to ARCHIVED
  { fromState: 'DEPRECATED', toState: 'ARCHIVED', action: 'ARCHIVE', description: 'Archive deprecated version', requiresReason: true, policyGated: false },
  { fromState: 'SUPERSEDED', toState: 'ARCHIVED', action: 'ARCHIVE', description: 'Archive superseded version', requiresReason: true, policyGated: false },
  { fromState: 'REVOKED', toState: 'ARCHIVED', action: 'ARCHIVE', description: 'Archive revoked version', requiresReason: true, policyGated: false },
];

// 4. VALIDATION_RUN Rules
export const VALIDATION_RUN_RULES: TransitionRule[] = [
  { fromState: null, toState: 'PENDING', action: 'INITIALIZE', description: 'Initialize validation run', requiresReason: false, policyGated: false },
  { fromState: 'PENDING', toState: 'RUNNING', action: 'START', description: 'Begin validation comparison', requiresReason: false, policyGated: false },
  { fromState: 'PENDING', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel pending validation', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'PASSED', action: 'PASS', description: 'Validation passed all regression criteria', requiresReason: false, policyGated: true, gateKey: 'VALIDATION_PASSED_GATE' },
  { fromState: 'RUNNING', toState: 'REQUIRES_REVIEW', action: 'DIFF_DETECTED', description: 'Significant diffs detected, requiring human review', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'FAILED', action: 'FAIL', description: 'Validation failed critical criteria', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'ERROR', action: 'EXECUTION_ERROR', description: 'Execution error during validation replay', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel running validation', requiresReason: true, policyGated: false },
  { fromState: 'REQUIRES_REVIEW', toState: 'PASSED', action: 'APPROVE_DIFF', description: 'Reviewer approves diffs as intended behavioral changes', requiresReason: true, policyGated: true, gateKey: 'EXPLICIT_APPROVAL_GATE', allowedRoles: ['security_auditor', 'platform_admin'] },
  { fromState: 'REQUIRES_REVIEW', toState: 'FAILED', action: 'REJECT_DIFF', description: 'Reviewer rejects validation diffs', requiresReason: true, policyGated: false },
  { fromState: 'REQUIRES_REVIEW', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel review', requiresReason: true, policyGated: false },
];

// 5. MODIFICATION_WORKSPACE Rules
export const MODIFICATION_WORKSPACE_RULES: TransitionRule[] = [
  { fromState: null, toState: 'OPEN', action: 'CREATE', description: 'Create modification workspace', requiresReason: true, policyGated: false },
  { fromState: 'OPEN', toState: 'APPLYING_CHANGES', action: 'APPLY', description: 'Apply changes and patches', requiresReason: false, policyGated: false },
  { fromState: 'OPEN', toState: 'DISCARDED', action: 'DISCARD', description: 'Discard workspace', requiresReason: true, policyGated: false },
  { fromState: 'APPLYING_CHANGES', toState: 'ASSESSING_IMPACT', action: 'ASSESS', description: 'Calculate impact assessment of changes', requiresReason: false, policyGated: false },
  { fromState: 'APPLYING_CHANGES', toState: 'OPEN', action: 'PAUSE', description: 'Pause patch application', requiresReason: false, policyGated: false },
  { fromState: 'APPLYING_CHANGES', toState: 'DISCARDED', action: 'DISCARD', description: 'Discard workspace during edit', requiresReason: true, policyGated: false },
  { fromState: 'ASSESSING_IMPACT', toState: 'AWAITING_APPROVAL', action: 'REQUIRE_APPROVAL', description: 'Impact has breaking changes requiring sign-off', requiresReason: true, policyGated: false },
  { fromState: 'ASSESSING_IMPACT', toState: 'COMMITTED', action: 'AUTO_COMMIT', description: 'Non-breaking impact committed directly to new version', requiresReason: true, policyGated: true, gateKey: 'ZERO_CRITICAL_RISKS_GATE' },
  { fromState: 'ASSESSING_IMPACT', toState: 'OPEN', action: 'REVISE', description: 'Return to open state to modify patches', requiresReason: true, policyGated: false },
  { fromState: 'ASSESSING_IMPACT', toState: 'DISCARDED', action: 'DISCARD', description: 'Discard workspace', requiresReason: true, policyGated: false },
  { fromState: 'AWAITING_APPROVAL', toState: 'COMMITTED', action: 'APPROVE_COMMIT', description: 'Approval received, committing workspace', requiresReason: true, policyGated: true, gateKey: 'EXPLICIT_APPROVAL_GATE' },
  { fromState: 'AWAITING_APPROVAL', toState: 'OPEN', action: 'REJECT_REVISE', description: 'Changes rejected, returning for revisions', requiresReason: true, policyGated: false },
  { fromState: 'AWAITING_APPROVAL', toState: 'DISCARDED', action: 'DISCARD', description: 'Discard rejected workspace', requiresReason: true, policyGated: false },
];

// 6. PACKAGE Rules
export const PACKAGE_RULES: TransitionRule[] = [
  { fromState: null, toState: 'PENDING', action: 'INITIALIZE', description: 'Initialize package creation', requiresReason: false, policyGated: false },
  { fromState: 'PENDING', toState: 'GENERATING', action: 'START_GENERATE', description: 'Begin bundling archive and manifest', requiresReason: false, policyGated: false },
  { fromState: 'PENDING', toState: 'REJECTED', action: 'REJECT', description: 'Reject package creation', requiresReason: true, policyGated: false },
  { fromState: 'GENERATING', toState: 'GENERATED', action: 'FINISH_GENERATE', description: 'Archive generated successfully', requiresReason: false, policyGated: false },
  { fromState: 'GENERATING', toState: 'REJECTED', action: 'FAIL_GENERATE', description: 'Package bundling failed', requiresReason: true, policyGated: false },
  { fromState: 'GENERATED', toState: 'VALIDATING', action: 'START_VALIDATE', description: 'Validate package attestations and SBOM integrity', requiresReason: false, policyGated: false },
  { fromState: 'VALIDATING', toState: 'VALIDATED', action: 'VALIDATION_OK', description: 'Attestations and SBOM verified', requiresReason: false, policyGated: true, gateKey: 'POLICY_PASS_GATE' },
  { fromState: 'VALIDATING', toState: 'REJECTED', action: 'VALIDATION_FAILED', description: 'Package attestation verification failed', requiresReason: true, policyGated: false },
  { fromState: 'VALIDATED', toState: 'SIGNING', action: 'START_SIGN', description: 'Apply cryptographic signature to package', requiresReason: false, policyGated: false },
  { fromState: 'VALIDATED', toState: 'REJECTED', action: 'REJECT', description: 'Reject validated package', requiresReason: true, policyGated: false },
  { fromState: 'SIGNING', toState: 'SIGNED', action: 'SIGN_OK', description: 'Cryptographic signature generated and verified', requiresReason: false, policyGated: true, gateKey: 'POLICY_PASS_GATE' },
  { fromState: 'SIGNING', toState: 'REJECTED', action: 'SIGN_FAILED', description: 'Signing failed or key rejected', requiresReason: true, policyGated: false },
  { fromState: 'SIGNED', toState: 'SHIPPED', action: 'DISPATCH', description: 'Dispatch package to shipment target', requiresReason: true, policyGated: true, gateKey: 'ZERO_CRITICAL_RISKS_GATE' },
  { fromState: 'SIGNED', toState: 'DEPRECATED', action: 'DEPRECATE', description: 'Deprecate signed package', requiresReason: true, policyGated: false },
  { fromState: 'SIGNED', toState: 'REVOKED', action: 'REVOKE', description: 'Revoke compromised package', requiresReason: true, policyGated: false },
  { fromState: 'SHIPPED', toState: 'DEPRECATED', action: 'DEPRECATE', description: 'Deprecate shipped package', requiresReason: true, policyGated: false },
  { fromState: 'SHIPPED', toState: 'REVOKED', action: 'REVOKE', description: 'Revoke shipped package in emergency', requiresReason: true, policyGated: false },
];

// 7. SHIPMENT Rules
export const SHIPMENT_RULES: TransitionRule[] = [
  { fromState: null, toState: 'PENDING', action: 'INITIALIZE', description: 'Initialize shipment request', requiresReason: false, policyGated: false },
  { fromState: 'PENDING', toState: 'PREPARING', action: 'START_PREP', description: 'Prepare deployment payload', requiresReason: false, policyGated: false },
  { fromState: 'PENDING', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel pending shipment', requiresReason: true, policyGated: false },
  { fromState: 'PREPARING', toState: 'IN_TRANSIT', action: 'DISPATCH', description: 'Dispatch shipment to destination endpoint', requiresReason: true, policyGated: true, gateKey: 'ZERO_CRITICAL_RISKS_GATE' },
  { fromState: 'PREPARING', toState: 'FAILED', action: 'PREP_FAILED', description: 'Preparation failed', requiresReason: true, policyGated: false },
  { fromState: 'PREPARING', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel shipment during prep', requiresReason: true, policyGated: false },
  { fromState: 'IN_TRANSIT', toState: 'DELIVERED', action: 'DELIVERY_CONFIRMED', description: 'Destination registry confirmed receipt', requiresReason: true, policyGated: false },
  { fromState: 'IN_TRANSIT', toState: 'FAILED', action: 'DELIVERY_FAILED', description: 'Network or transmission failure', requiresReason: true, policyGated: false },
  { fromState: 'IN_TRANSIT', toState: 'REJECTED', action: 'DESTINATION_REJECTED', description: 'Target destination rejected package receipt', requiresReason: true, policyGated: false },
];

// 8. WORKFLOW_RUN Rules
export const WORKFLOW_RUN_RULES: TransitionRule[] = [
  { fromState: null, toState: 'PENDING', action: 'INITIALIZE', description: 'Initialize workflow run', requiresReason: false, policyGated: false },
  { fromState: 'PENDING', toState: 'RUNNING', action: 'START', description: 'Start workflow execution', requiresReason: false, policyGated: false },
  { fromState: 'PENDING', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel workflow run before starting', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'PAUSED', action: 'PAUSE', description: 'Pause workflow execution', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'AWAITING_APPROVAL', action: 'WAIT_APPROVAL', description: 'Workflow halted on approval checkpoint', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'COMPLETED', action: 'COMPLETE', description: 'Workflow completed all steps successfully', requiresReason: false, policyGated: false },
  { fromState: 'RUNNING', toState: 'FAILED', action: 'FAIL', description: 'Workflow failed during step execution', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel running workflow', requiresReason: true, policyGated: false },
  { fromState: 'PAUSED', toState: 'RUNNING', action: 'RESUME', description: 'Resume paused workflow', requiresReason: true, policyGated: false },
  { fromState: 'PAUSED', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel paused workflow', requiresReason: true, policyGated: false },
  { fromState: 'AWAITING_APPROVAL', toState: 'RUNNING', action: 'APPROVED_RESUME', description: 'Approval granted, workflow resumes', requiresReason: true, policyGated: true, gateKey: 'EXPLICIT_APPROVAL_GATE' },
  { fromState: 'AWAITING_APPROVAL', toState: 'FAILED', action: 'REJECTED_FAIL', description: 'Approval denied, workflow terminates as failed', requiresReason: true, policyGated: false },
  { fromState: 'AWAITING_APPROVAL', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel blocked workflow', requiresReason: true, policyGated: false },
];

// 9. JOB Rules
export const JOB_RULES: TransitionRule[] = [
  { fromState: null, toState: 'QUEUED', action: 'ENQUEUE', description: 'Enqueue job in job queue', requiresReason: false, policyGated: false },
  { fromState: 'QUEUED', toState: 'LEASED', action: 'LEASE', description: 'Worker node leases job', requiresReason: false, policyGated: false },
  { fromState: 'QUEUED', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel queued job', requiresReason: true, policyGated: false },
  { fromState: 'LEASED', toState: 'RUNNING', action: 'START', description: 'Worker starts job processing', requiresReason: false, policyGated: false },
  { fromState: 'LEASED', toState: 'QUEUED', action: 'LEASE_EXPIRED', description: 'Worker heartbeat failed; lease released back to queue', requiresReason: true, policyGated: false },
  { fromState: 'LEASED', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel leased job', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'COMPLETED', action: 'COMPLETE', description: 'Job finished successfully', requiresReason: false, policyGated: false },
  { fromState: 'RUNNING', toState: 'RETRYING', action: 'SCHEDULE_RETRY', description: 'Transient failure; schedule retry attempt', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'FAILED', action: 'FAIL', description: 'Job failed and cannot be retried', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'DEAD_LETTER', action: 'DEAD_LETTER', description: 'Job encountered fatal poison payload', requiresReason: true, policyGated: false },
  { fromState: 'RUNNING', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel running job', requiresReason: true, policyGated: false },
  { fromState: 'RETRYING', toState: 'QUEUED', action: 'RE_ENQUEUE', description: 'Backoff timer elapsed, job re-enqueued for next attempt', requiresReason: false, policyGated: false },
  { fromState: 'RETRYING', toState: 'DEAD_LETTER', action: 'EXHAUST_RETRIES', description: 'Max retry attempts exceeded; moved to DLQ', requiresReason: true, policyGated: false },
  { fromState: 'RETRYING', toState: 'CANCELLED', action: 'CANCEL', description: 'Cancel retrying job', requiresReason: true, policyGated: false },
];

export const TRANSITION_RULES_BY_ENTITY: Record<LifecycleEntityKind, TransitionRule[]> = {
  ANALYSIS_RUN: ANALYSIS_RUN_RULES,
  ANALYSIS_STAGE_RUN: ANALYSIS_STAGE_RUN_RULES,
  AGENT_VERSION: AGENT_VERSION_RULES,
  VALIDATION_RUN: VALIDATION_RUN_RULES,
  MODIFICATION_WORKSPACE: MODIFICATION_WORKSPACE_RULES,
  PACKAGE: PACKAGE_RULES,
  SHIPMENT: SHIPMENT_RULES,
  WORKFLOW_RUN: WORKFLOW_RUN_RULES,
  JOB: JOB_RULES,
};

export const TRANSITION_TABLES_BY_ENTITY: Record<LifecycleEntityKind, TransitionRuleTable> = {
  ANALYSIS_RUN: buildRuleTable(ANALYSIS_RUN_RULES),
  ANALYSIS_STAGE_RUN: buildRuleTable(ANALYSIS_STAGE_RUN_RULES),
  AGENT_VERSION: buildRuleTable(AGENT_VERSION_RULES),
  VALIDATION_RUN: buildRuleTable(VALIDATION_RUN_RULES),
  MODIFICATION_WORKSPACE: buildRuleTable(MODIFICATION_WORKSPACE_RULES),
  PACKAGE: buildRuleTable(PACKAGE_RULES),
  SHIPMENT: buildRuleTable(SHIPMENT_RULES),
  WORKFLOW_RUN: buildRuleTable(WORKFLOW_RUN_RULES),
  JOB: buildRuleTable(JOB_RULES),
};

export function getTransitionRules(entityKind: LifecycleEntityKind): TransitionRule[] {
  return TRANSITION_RULES_BY_ENTITY[entityKind] || [];
}

export function findMatchingRule(
  entityKind: LifecycleEntityKind,
  fromState: string | null,
  toState: string,
  action?: string
): TransitionRule | undefined {
  const table = TRANSITION_TABLES_BY_ENTITY[entityKind];
  if (!table) return undefined;
  const key = fromState === null ? '__GENESIS__' : fromState;
  const candidates = table[key] || [];

  return candidates.find(r => {
    if (r.toState !== toState) return false;
    if (action && r.action !== action) return false;
    return true;
  });
}

export function getAllowedTargetStates(entityKind: LifecycleEntityKind, fromState: string | null): string[] {
  const table = TRANSITION_TABLES_BY_ENTITY[entityKind];
  if (!table) return [];
  const key = fromState === null ? '__GENESIS__' : fromState;
  const rules = table[key] || [];
  return Array.from(new Set(rules.map(r => r.toState)));
}
