/**
 * CAIM Evaluation, Golden Corpus & Regression Gate Contracts
 * Conforming to P31 specification
 */

export type GoldenCorpusFamily =
  | 'BENIGN_BASELINE'
  | 'KNOWN_VULNERABLE'
  | 'MALICIOUS_TEST_FIXTURE'
  | 'OBFUSCATED'
  | 'MULTI_LANGUAGE'
  | 'FRAMEWORK_SPECIFIC'
  | 'MCP'
  | 'A2A'
  | 'NETWORK_HEAVY'
  | 'FILESYSTEM_HEAVY'
  | 'PROCESS_EXECUTION'
  | 'CREDENTIAL_ACCESS'
  | 'TAINT_SOURCE_TO_SINK'
  | 'SANDBOX_EVASION'
  | 'PROMPT_INJECTION'
  | 'RAG_AUTHORIZATION'
  | 'RAG_GROUNDING'
  | 'POLICY_EDGE_CASE'
  | 'VERSION_DIFF';

export const ALL_GOLDEN_CORPUS_FAMILIES: GoldenCorpusFamily[] = [
  'BENIGN_BASELINE',
  'KNOWN_VULNERABLE',
  'MALICIOUS_TEST_FIXTURE',
  'OBFUSCATED',
  'MULTI_LANGUAGE',
  'FRAMEWORK_SPECIFIC',
  'MCP',
  'A2A',
  'NETWORK_HEAVY',
  'FILESYSTEM_HEAVY',
  'PROCESS_EXECUTION',
  'CREDENTIAL_ACCESS',
  'TAINT_SOURCE_TO_SINK',
  'SANDBOX_EVASION',
  'PROMPT_INJECTION',
  'RAG_AUTHORIZATION',
  'RAG_GROUNDING',
  'POLICY_EDGE_CASE',
  'VERSION_DIFF',
];

export interface GoldenTestFixture {
  fixtureId: string;
  family: GoldenCorpusFamily;
  name: string;
  description: string;
  sourceCodeSnippet?: string;
  sourceLanguage?: 'typescript' | 'python' | 'go' | 'rust' | 'json' | 'yaml';
  isAdversarial: boolean;
  groundTruth: {
    expectedVerdict: 'CLEARED' | 'BLOCKED' | 'FLAGGED_FOR_REVIEW' | 'ABSTAIN';
    expectedVulnerabilityIds: string[];
    expectedTaintFlows: Array<{ source: string; sink: string; isMalicious: boolean }>;
    expectedCapabilities: string[];
    expectedRiskScoreMin: number;
    expectedRiskScoreMax: number;
    expectedRagGroundingPass: boolean;
    expectedRlsAccessAllowed: boolean;
    shouldAbstain: boolean;
    expectedContradictionsCount: number;
    requiredCitationsCount: number;
  };
}

export interface FixtureEvaluationResult {
  fixtureId: string;
  family: GoldenCorpusFamily;
  actualVerdict: 'CLEARED' | 'BLOCKED' | 'FLAGGED_FOR_REVIEW' | 'ABSTAIN';
  isVerdictCorrect: boolean;
  actualVulnerabilities: string[];
  detectedTaintFlows: Array<{ source: string; sink: string }>;
  detectedCapabilities: string[];
  calculatedRiskScore: number;
  ragGroundingScorePct: number;
  rlsAccessGranted: boolean;
  abstained: boolean;
  unsupportedClaimsDetected: number;
  citationsRetrieved: number;
  citationsVerified: number;
  contradictionsDisclosed: number;
  latencyMs: number;
  passedGates: boolean;
  failureReasons?: string[];
}

export interface EvaluationMetricsSummary {
  totalFixturesEvaluated: number;
  // Classification Metrics
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  // Taint & Flow Metrics
  taintPathPrecision: number;
  taintPathRecall: number;
  // Capability Detection Accuracy
  capabilityAccuracy: number;
  // Policy & Risk Regression
  policyRegressionCount: number;
  riskScoreDeltaAvg: number;
  // RAG Information Retrieval Metrics
  recallAtK: number; // e.g. Recall@5
  precisionAtK: number; // e.g. Precision@5
  meanReciprocalRank: number; // MRR
  unsupportedClaimRate: number; // target < 0.05
  citationCompleteness: number; // target > 0.95
  citationCorrectness: number; // target > 0.98
  contradictionDisclosureRate: number; // target 1.0
  abstentionCorrectness: number; // target > 0.99
  rlsAuthorizationNegativePassRate: number; // target 1.0 (Zero-Leak RLS)
}

export interface RegressionThresholds {
  minF1Score: number; // e.g. 0.96
  minPrecision: number; // e.g. 0.98
  minRecall: number; // e.g. 0.95
  minTaintRecall: number; // e.g. 0.97
  minCapabilityAccuracy: number; // e.g. 0.98
  maxAllowedPolicyRegressions: number; // 0 (Zero Tolerance)
  minRecallAtK: number; // e.g. 0.92
  minMRR: number; // e.g. 0.90
  maxUnsupportedClaimRate: number; // e.g. 0.03
  minCitationCompleteness: number; // e.g. 0.95
  minCitationCorrectness: number; // e.g. 0.98
  minContradictionDisclosureRate: number; // e.g. 1.0
  minAbstentionCorrectness: number; // e.g. 0.98
  minRlsNegativePassRate: number; // 1.0 (100% security boundary enforcement)
}

export type ReleaseGateStatus = 'PASSED' | 'REJECTED_REGRESSION' | 'FAILED_THRESHOLD' | 'PENDING_EVALUATION';

export interface EvaluationRun {
  runId: string;
  timestamp: string;
  engineVersion: string;
  baselineEngineVersion: string;
  isConclusionChanging: boolean;
  evaluatedFamilies: GoldenCorpusFamily[];
  metrics: EvaluationMetricsSummary;
  thresholds: RegressionThresholds;
  gateStatus: ReleaseGateStatus;
  regressionViolations: string[];
  results: FixtureEvaluationResult[];
  evaluatorActorId: string;
  signatureSha256: string;
}

export interface ReleaseGateDecision {
  engineVersion: string;
  evaluatedAt: string;
  isConclusionChanging: boolean;
  canDeployToProduction: boolean;
  gateStatus: ReleaseGateStatus;
  summary: string;
  blockingReasons: string[];
  evaluationRunId: string;
}

export const PRODUCTION_REGRESSION_THRESHOLDS: RegressionThresholds = {
  minF1Score: 0.95,
  minPrecision: 0.95,
  minRecall: 0.95,
  minTaintRecall: 0.95,
  minCapabilityAccuracy: 0.95,
  maxAllowedPolicyRegressions: 0,
  minRecallAtK: 0.92,
  minMRR: 0.90,
  maxUnsupportedClaimRate: 0.03,
  minCitationCompleteness: 0.95,
  minCitationCorrectness: 0.98,
  minContradictionDisclosureRate: 1.0,
  minAbstentionCorrectness: 0.98,
  minRlsNegativePassRate: 1.0,
};

export const GOLDEN_CORPUS_FIXTURES: GoldenTestFixture[] = [];
