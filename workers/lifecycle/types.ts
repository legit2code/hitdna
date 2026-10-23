import { z } from 'zod';

/**
 * P25 — Version, Differential, Modification, Impact, Reanalysis & Validation
 * Architecture V2.0.1 (Document 17, 18, 21, 21B)
 */

export const ValidationTypeEnum = z.enum([
  'SOURCE_MODIFICATION',
  'ANALYTICAL_REEVALUATION',
  'POLICY_REEVALUATION',
  'SCENARIO_REEVALUATION',
]);
export type ValidationType = z.infer<typeof ValidationTypeEnum>;

export const ModificationStatusEnum = z.enum([
  'OPEN',
  'APPLYING_CHANGES',
  'ASSESSING_IMPACT',
  'AWAITING_APPROVAL',
  'COMMITTED',
  'DISCARDED',
]);
export type ModificationStatus = z.infer<typeof ModificationStatusEnum>;

export const ChangeAuthorTypeEnum = z.enum([
  'HUMAN',
  'AGENT',
  'AUTOMATED_REMEDIATION',
]);
export type ChangeAuthorType = z.infer<typeof ChangeAuthorTypeEnum>;

export const ChangeTypeEnum = z.enum([
  'CREATE',
  'UPDATE',
  'DELETE',
  'PATCH',
]);
export type ChangeType = z.infer<typeof ChangeTypeEnum>;

export const ImpactSeverityEnum = z.enum([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'NONE',
]);
export type ImpactSeverity = z.infer<typeof ImpactSeverityEnum>;

export const ReanalysisTriggerEnum = z.enum([
  'FULL_REANALYSIS',
  'INCREMENTAL_REANALYSIS',
  'NO_REANALYSIS_NEEDED',
]);
export type ReanalysisTrigger = z.infer<typeof ReanalysisTriggerEnum>;

export const AttributionTypeEnum = z.enum([
  'SOURCE_CHANGE',
  'ANALYZER_CHANGE',
  'BOTH',
  'NO_CHANGE',
]);
export type AttributionType = z.infer<typeof AttributionTypeEnum>;

export interface SourceFileSnapshot {
  path: string;
  content: string;
  hash: string;
  sizeBytes: number;
}

export interface AstNodeSnapshot {
  id: string;
  name: string;
  kind: 'FUNCTION' | 'CLASS' | 'VARIABLE' | 'IMPORT' | 'EXPORT' | 'TOOL_CALL';
  filePath: string;
  startLine: number;
  endLine: number;
  signature?: string;
  bodyHash: string;
}

export interface DependencySnapshot {
  name: string;
  version: string;
  type: 'DIRECT' | 'DEV' | 'PEER' | 'TRANSITIVE';
  vulnerabilities?: Array<{
    cveId: string;
    severity: string;
    description: string;
  }>;
}

export interface CapabilitySnapshot {
  id: string;
  name: string;
  type: 'DECLARED' | 'INFERRED';
  category: 'NETWORK' | 'FILESYSTEM' | 'TOOL_USE' | 'MEMORY' | 'AUTH' | 'GENERAL';
  confidence: number;
  associatedTools: string[];
  isEssential: boolean;
}

export interface PermissionSnapshot {
  scope: string;
  resource: string;
  actions: string[];
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface BehaviorSnapshot {
  scenarioId: string;
  name: string;
  passed: boolean;
  toolCallsCount: number;
  externalRequestsCount: number;
  executionTimeMs: number;
  outputs: Record<string, any>;
}

export interface RiskScoreSnapshot {
  overallScore: number; // 0-100 (higher = safer, or 0-100 risk index)
  riskIndex: number; // 0-100 (higher = riskier)
  structuralRisk: number;
  taintVulnerabilityRisk: number;
  toolMisuseRisk: number;
  sandboxEvasionRisk: number;
  policyViolationsCount: number;
  criticalFindingsCount: number;
  highFindingsCount: number;
}

export interface AnalyzerConfigSnapshot {
  engineVersion: string;
  rulesetVersion: string;
  weightMatrixVersion: string;
  probesCount: number;
}

export interface AgentVersionSnapshot {
  agentVersionId: string;
  agentId: string;
  versionLabel: string; // e.g. "1.0.0", "1.0.1"
  status: string;
  isImmutable: boolean;
  createdAt: string;
  sourceFiles: Record<string, SourceFileSnapshot>;
  astNodes: AstNodeSnapshot[];
  dependencies: Record<string, DependencySnapshot>;
  capabilities: CapabilitySnapshot[];
  permissions: PermissionSnapshot[];
  behaviors: BehaviorSnapshot[];
  riskScore: RiskScoreSnapshot;
  analyzerConfig: AnalyzerConfigSnapshot;
  analysisRunId: string;
}

export interface FileDiffItem {
  path: string;
  changeType: 'ADDED' | 'MODIFIED' | 'REMOVED' | 'UNCHANGED';
  beforeHash?: string;
  afterHash?: string;
  unifiedDiff?: string;
  linesAdded: number;
  linesRemoved: number;
}

export interface AstDiffItem {
  nodeId: string;
  name: string;
  kind: string;
  filePath: string;
  changeType: 'ADDED' | 'MODIFIED' | 'REMOVED' | 'UNCHANGED';
  beforeSignature?: string;
  afterSignature?: string;
  structuralImpact: 'BREAKING' | 'MAJOR' | 'MINOR' | 'INFORMATIONAL';
}

export interface DependencyDiffItem {
  name: string;
  changeType: 'ADDED' | 'MODIFIED' | 'REMOVED' | 'UNCHANGED';
  beforeVersion?: string;
  afterVersion?: string;
  vulnerabilityDelta: {
    fixed: string[];
    introduced: string[];
  };
  isBreaking: boolean;
}

export interface CapabilityDiffItem {
  capabilityId: string;
  name: string;
  category: string;
  changeType: 'GAINED' | 'RETAINED' | 'LOST';
  isEssential: boolean;
  isRegression: boolean;
}

export interface PermissionDiffItem {
  resource: string;
  changeType: 'ADDED' | 'EXPANDED' | 'REDUCED' | 'REMOVED' | 'UNCHANGED';
  beforeActions?: string[];
  afterActions?: string[];
  riskShift: 'ESCALATED' | 'REDUCED' | 'NEUTRAL';
}

export interface BehaviorDiffItem {
  scenarioId: string;
  name: string;
  changeType: 'IMPROVED' | 'REGRESSED' | 'UNCHANGED';
  beforePassed: boolean;
  afterPassed: boolean;
  details: string;
}

export interface FindingAttributionItem {
  findingId: string;
  title: string;
  severity: string;
  attribution: 'NEW_SOURCE_VULNERABILITY' | 'REMEDIED_VULNERABILITY' | 'NEW_DETECTION_RULE' | 'RULE_RELAXATION' | 'COMBINED_EFFECT';
  explanation: string;
}

export interface SourceVsAnalyzerAttribution {
  overallAttribution: AttributionType;
  sourceCodeChanged: boolean;
  analyzerRulesChanged: boolean;
  findingsAttribution: FindingAttributionItem[];
  rationale: string;
}

export interface DiffAnalysisResult {
  versionDiffId: string;
  leftVersionId: string;
  rightVersionId: string;
  fileDiffs: FileDiffItem[];
  astDiffs: AstDiffItem[];
  dependencyDiffs: DependencyDiffItem[];
  capabilityDiffs: CapabilityDiffItem[];
  permissionDiffs: PermissionDiffItem[];
  behaviorDiffs: BehaviorDiffItem[];
  riskScoreDiff: {
    beforeScore: RiskScoreSnapshot;
    afterScore: RiskScoreSnapshot;
    riskIndexDelta: number; // negative is improvement (less risk)
    structuralDelta: number;
    taintDelta: number;
    toolMisuseDelta: number;
    evasionDelta: number;
    criticalFindingsDelta: number;
  };
  attribution: SourceVsAnalyzerAttribution;
  hasBreakingChanges: boolean;
}

export interface ModificationProposal {
  proposalId: string;
  title: string;
  description: string;
  reasoning: string;
  targetFile: string;
  patchContent: string;
  confidenceScore: number;
  isStaged: boolean;
  acceptedAt?: string;
  authorType: 'AGENT' | 'AUTOMATED_REMEDIATION';
}

export interface ModificationChange {
  changeId: string;
  workspaceId: string;
  filePath: string;
  changeType: ChangeType;
  patchLocator: string;
  newContent?: string;
  patchContent?: string;
  authorType: ChangeAuthorType;
  authorRef: string;
  createdAt: string;
}

export interface ImpactItem {
  impactItemId: string;
  targetEntity: string;
  impactType: 'DEPENDENCY_BREAKAGE' | 'CAPABILITY_REGRESSION' | 'RISK_ESCALATION' | 'API_SURFACE_SHIFT' | 'SECURITY_HARDENING';
  severity: ImpactSeverity;
  requiredAction: 'REANALYZE' | 'REGRESSION_TEST' | 'MANUAL_REVIEW' | 'BLOCK' | 'ACCEPT';
  description: string;
}

export interface ImpactAssessment {
  impactAssessmentId: string;
  workspaceId: string;
  highestSeverity: ImpactSeverity;
  affectsEntryPoints: boolean;
  affectsDependencies: boolean;
  affectsPermissions: boolean;
  capabilityRegressionRisk: boolean;
  impactItems: ImpactItem[];
  suggestedReanalysisTrigger: ReanalysisTrigger;
  createdAt: string;
}

export interface ReanalysisStage {
  stageId: string;
  stageName: string;
  scope: 'ALL' | 'TARGETED_FILES' | 'POLICY_ONLY' | 'SCENARIO_ONLY';
  targetPaths?: string[];
  estimatedDurationMs: number;
}

export interface ReanalysisPlan {
  planId: string;
  trigger: ReanalysisTrigger;
  stages: ReanalysisStage[];
  reanalysisReason: string;
  totalEstimatedStages: number;
}

export interface ApprovalRecord {
  approvalId: string;
  targetEntityRefId: string;
  targetType: 'MODIFICATION_WORKSPACE' | 'AGENT_VERSION' | 'VALIDATION_RUN';
  approverId: string;
  approverRole: string; // e.g. 'security_auditor', 'platform_admin'
  decision: 'APPROVED' | 'REJECTED' | 'PENDING' | 'REVOKED';
  rationale: string;
  decidedAt: string;
  signature?: string;
}

export interface ValidationResultItem {
  resultType: 'RISK_DELTA' | 'CAPABILITY_PRESERVATION' | 'BEHAVIORAL_REPLAY' | 'POLICY_EVALUATION';
  status: 'PASSED' | 'FAILED' | 'INCONCLUSIVE' | 'SKIPPED';
  beforeValue?: any;
  afterValue?: any;
  details: string;
}

export interface ValidationRunRecord {
  validation_run_id: string;
  validation_type: ValidationType;
  baseline_agent_version_id: string;
  modified_agent_version_id: string;
  baseline_analysis_run_id: string;
  modified_analysis_run_id: string;
  validation_analysis_run_id: string;
  scenario_pack_id?: string | null;
  validation_plan_version: string;
  policy_ruleset_version?: string | null;
  scope_id: string;
  status: 'PENDING' | 'RUNNING' | 'PASSED' | 'FAILED' | 'ERROR' | 'REQUIRES_REVIEW';
  started_at: string;
  completed_at?: string | null;
  created_at: string;
  results: ValidationResultItem[];
  validationDecision: {
    passed: boolean;
    verdict: 'APPROVED_FOR_RELEASE' | 'REJECTED_REGRESSION' | 'REJECTED_UNAPPROVED_CHANGES' | 'REQUIRES_MANUAL_REVIEW';
    reason: string;
    riskReduced: boolean;
    capabilitiesPreserved: boolean;
    hasCriticalViolations: boolean;
  };
}
