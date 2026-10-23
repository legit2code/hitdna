import { z } from 'zod';
import { StateRegistryLookupError } from './errors.ts';

export const STATE_MACHINE_VERSION = '2.0.1' as const;

export const LifecycleEntityKindSchema = z.enum([
  'ANALYSIS_RUN',
  'ANALYSIS_STAGE_RUN',
  'AGENT_VERSION',
  'VALIDATION_RUN',
  'MODIFICATION_WORKSPACE',
  'PACKAGE',
  'SHIPMENT',
  'WORKFLOW_RUN',
  'JOB',
]);
export type LifecycleEntityKind = z.infer<typeof LifecycleEntityKindSchema>;

export interface StateDescriptor {
  readonly state: string;
  readonly isInitial: boolean;
  readonly isTerminal: boolean;
  readonly isActive: boolean;
  readonly isReview: boolean;
  readonly isFailure: boolean;
  readonly isCancel: boolean;
  readonly isQuarantine?: boolean;
  readonly description: string;
}

export interface EntityStateCatalog {
  readonly entityKind: LifecycleEntityKind;
  readonly initialState: string;
  readonly states: Record<string, StateDescriptor>;
  readonly terminalStates: Set<string>;
  readonly reviewStates: Set<string>;
  readonly failureStates: Set<string>;
  readonly cancelStates: Set<string>;
}

// 1. ANALYSIS_RUN State Catalog
export const AnalysisRunStates = {
  PENDING: 'PENDING',
  QUEUED: 'QUEUED',
  RUNNING: 'RUNNING',
  STAGE_EXECUTION: 'STAGE_EXECUTION',
  EVALUATING_POLICIES: 'EVALUATING_POLICIES',
  REQUIRES_REVIEW: 'REQUIRES_REVIEW',
  IN_REVIEW: 'IN_REVIEW',
  REANALYZING: 'REANALYZING',
  COMPLETED: 'COMPLETED',
  PARTIAL: 'PARTIAL',
  FAILED: 'FAILED',
  CANCELLED: 'CANCELLED',
} as const;

const ANALYSIS_RUN_CATALOG: EntityStateCatalog = {
  entityKind: 'ANALYSIS_RUN',
  initialState: AnalysisRunStates.PENDING,
  states: {
    [AnalysisRunStates.PENDING]: { state: AnalysisRunStates.PENDING, isInitial: true, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Analysis run initialized, awaiting queueing' },
    [AnalysisRunStates.QUEUED]: { state: AnalysisRunStates.QUEUED, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Analysis run scheduled and queued for orchestrator worker' },
    [AnalysisRunStates.RUNNING]: { state: AnalysisRunStates.RUNNING, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Analysis run execution started' },
    [AnalysisRunStates.STAGE_EXECUTION]: { state: AnalysisRunStates.STAGE_EXECUTION, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Individual analyzer stages executing' },
    [AnalysisRunStates.EVALUATING_POLICIES]: { state: AnalysisRunStates.EVALUATING_POLICIES, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'All stage outputs assembled, evaluating security policies and scoring' },
    [AnalysisRunStates.REQUIRES_REVIEW]: { state: AnalysisRunStates.REQUIRES_REVIEW, isInitial: false, isTerminal: false, isActive: false, isReview: true, isFailure: false, isCancel: false, description: 'Analysis results flagged for human or security reviewer approval' },
    [AnalysisRunStates.IN_REVIEW]: { state: AnalysisRunStates.IN_REVIEW, isInitial: false, isTerminal: false, isActive: true, isReview: true, isFailure: false, isCancel: false, description: 'Active security review in progress by analyst' },
    [AnalysisRunStates.REANALYZING]: { state: AnalysisRunStates.REANALYZING, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Targeted re-evaluation of specific stage artifacts or updated rulesets' },
    [AnalysisRunStates.COMPLETED]: { state: AnalysisRunStates.COMPLETED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Analysis run finished successfully with full verification and all intelligence persisted' },
    [AnalysisRunStates.PARTIAL]: { state: AnalysisRunStates.PARTIAL, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Analysis run completed with partial evidence (e.g. static complete, dynamic unverified)' },
    [AnalysisRunStates.FAILED]: { state: AnalysisRunStates.FAILED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Analysis run terminated with unrecoverable error or stage crash' },
    [AnalysisRunStates.CANCELLED]: { state: AnalysisRunStates.CANCELLED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: true, description: 'Analysis run aborted by user or orchestrator timeout' },
  },
  terminalStates: new Set([AnalysisRunStates.COMPLETED, AnalysisRunStates.PARTIAL, AnalysisRunStates.FAILED, AnalysisRunStates.CANCELLED]),
  reviewStates: new Set([AnalysisRunStates.REQUIRES_REVIEW, AnalysisRunStates.IN_REVIEW]),
  failureStates: new Set([AnalysisRunStates.FAILED]),
  cancelStates: new Set([AnalysisRunStates.CANCELLED]),
};

// 2. ANALYSIS_STAGE_RUN State Catalog
export const AnalysisStageRunStates = {
  PENDING: 'PENDING',
  RUNNING: 'RUNNING',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED',
  SKIPPED: 'SKIPPED',
  TIMED_OUT: 'TIMED_OUT',
  CANCELLED: 'CANCELLED',
} as const;

const ANALYSIS_STAGE_RUN_CATALOG: EntityStateCatalog = {
  entityKind: 'ANALYSIS_STAGE_RUN',
  initialState: AnalysisStageRunStates.PENDING,
  states: {
    [AnalysisStageRunStates.PENDING]: { state: AnalysisStageRunStates.PENDING, isInitial: true, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Stage run initialized, waiting on stage dependencies' },
    [AnalysisStageRunStates.RUNNING]: { state: AnalysisStageRunStates.RUNNING, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Stage engine actively executing' },
    [AnalysisStageRunStates.COMPLETED]: { state: AnalysisStageRunStates.COMPLETED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Stage completed successfully with outputs and envelope recorded' },
    [AnalysisStageRunStates.FAILED]: { state: AnalysisStageRunStates.FAILED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Stage execution failed' },
    [AnalysisStageRunStates.SKIPPED]: { state: AnalysisStageRunStates.SKIPPED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Stage skipped due to input conditions or cache hit' },
    [AnalysisStageRunStates.TIMED_OUT]: { state: AnalysisStageRunStates.TIMED_OUT, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Stage exceeded bounded execution time' },
    [AnalysisStageRunStates.CANCELLED]: { state: AnalysisStageRunStates.CANCELLED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: true, description: 'Stage cancelled due to parent run abort' },
  },
  terminalStates: new Set([AnalysisStageRunStates.COMPLETED, AnalysisStageRunStates.FAILED, AnalysisStageRunStates.SKIPPED, AnalysisStageRunStates.TIMED_OUT, AnalysisStageRunStates.CANCELLED]),
  reviewStates: new Set(),
  failureStates: new Set([AnalysisStageRunStates.FAILED, AnalysisStageRunStates.TIMED_OUT]),
  cancelStates: new Set([AnalysisStageRunStates.CANCELLED]),
};

// 3. AGENT_VERSION State Catalog
export const AgentVersionStates = {
  DRAFT: 'DRAFT',
  DISCOVERED: 'DISCOVERED',
  ANALYZING: 'ANALYZING',
  ANALYZED: 'ANALYZED',
  VALIDATING: 'VALIDATING',
  PENDING_REVIEW: 'PENDING_REVIEW',
  IN_REVIEW: 'IN_REVIEW',
  REVIEW_REJECTED: 'REVIEW_REJECTED',
  QUARANTINED: 'QUARANTINED',
  APPROVED: 'APPROVED',
  PROMOTED: 'PROMOTED',
  RELEASED: 'RELEASED',
  DEPRECATED: 'DEPRECATED',
  SUPERSEDED: 'SUPERSEDED',
  REVOKED: 'REVOKED',
  ARCHIVED: 'ARCHIVED',
} as const;

const AGENT_VERSION_CATALOG: EntityStateCatalog = {
  entityKind: 'AGENT_VERSION',
  initialState: AgentVersionStates.DRAFT,
  states: {
    [AgentVersionStates.DRAFT]: { state: AgentVersionStates.DRAFT, isInitial: true, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Agent version draft created' },
    [AgentVersionStates.DISCOVERED]: { state: AgentVersionStates.DISCOVERED, isInitial: false, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Agent version discovered from source adapter' },
    [AgentVersionStates.ANALYZING]: { state: AgentVersionStates.ANALYZING, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Active multi-engine analysis in progress' },
    [AgentVersionStates.ANALYZED]: { state: AgentVersionStates.ANALYZED, isInitial: false, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Analysis complete with full CAIM and intelligence synthesis' },
    [AgentVersionStates.VALIDATING]: { state: AgentVersionStates.VALIDATING, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Running regression or diff validation against baseline' },
    [AgentVersionStates.PENDING_REVIEW]: { state: AgentVersionStates.PENDING_REVIEW, isInitial: false, isTerminal: false, isActive: false, isReview: true, isFailure: false, isCancel: false, description: 'Policy gates require manual security review' },
    [AgentVersionStates.IN_REVIEW]: { state: AgentVersionStates.IN_REVIEW, isInitial: false, isTerminal: false, isActive: true, isReview: true, isFailure: false, isCancel: false, description: 'Security reviewer actively auditing findings' },
    [AgentVersionStates.REVIEW_REJECTED]: { state: AgentVersionStates.REVIEW_REJECTED, isInitial: false, isTerminal: false, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Reviewer rejected agent version release' },
    [AgentVersionStates.QUARANTINED]: { state: AgentVersionStates.QUARANTINED, isInitial: false, isTerminal: false, isActive: false, isReview: false, isFailure: true, isCancel: false, isQuarantine: true, description: 'Critical security violation or evasion detected; quarantined' },
    [AgentVersionStates.APPROVED]: { state: AgentVersionStates.APPROVED, isInitial: false, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Security policies passed or authorized review approval granted' },
    [AgentVersionStates.PROMOTED]: { state: AgentVersionStates.PROMOTED, isInitial: false, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Promoted to designated release or deployment target' },
    [AgentVersionStates.RELEASED]: { state: AgentVersionStates.RELEASED, isInitial: false, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Published and active in target catalog/marketplace' },
    [AgentVersionStates.DEPRECATED]: { state: AgentVersionStates.DEPRECATED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Deprecated in favor of newer versions' },
    [AgentVersionStates.SUPERSEDED]: { state: AgentVersionStates.SUPERSEDED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Superseded by replacement version' },
    [AgentVersionStates.REVOKED]: { state: AgentVersionStates.REVOKED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Revoked due to security emergency' },
    [AgentVersionStates.ARCHIVED]: { state: AgentVersionStates.ARCHIVED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Archived for compliance retention' },
  },
  terminalStates: new Set([AgentVersionStates.DEPRECATED, AgentVersionStates.SUPERSEDED, AgentVersionStates.REVOKED, AgentVersionStates.ARCHIVED]),
  reviewStates: new Set([AgentVersionStates.PENDING_REVIEW, AgentVersionStates.IN_REVIEW]),
  failureStates: new Set([AgentVersionStates.REVIEW_REJECTED, AgentVersionStates.QUARANTINED, AgentVersionStates.REVOKED]),
  cancelStates: new Set(),
};

// 4. VALIDATION_RUN State Catalog
export const ValidationRunStates = {
  PENDING: 'PENDING',
  RUNNING: 'RUNNING',
  REQUIRES_REVIEW: 'REQUIRES_REVIEW',
  PASSED: 'PASSED',
  FAILED: 'FAILED',
  ERROR: 'ERROR',
  CANCELLED: 'CANCELLED',
} as const;

const VALIDATION_RUN_CATALOG: EntityStateCatalog = {
  entityKind: 'VALIDATION_RUN',
  initialState: ValidationRunStates.PENDING,
  states: {
    [ValidationRunStates.PENDING]: { state: ValidationRunStates.PENDING, isInitial: true, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Validation run initialized' },
    [ValidationRunStates.RUNNING]: { state: ValidationRunStates.RUNNING, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Executing validation comparisons and scenario re-evaluations' },
    [ValidationRunStates.REQUIRES_REVIEW]: { state: ValidationRunStates.REQUIRES_REVIEW, isInitial: false, isTerminal: false, isActive: false, isReview: true, isFailure: false, isCancel: false, description: 'Differences detected requiring human approval' },
    [ValidationRunStates.PASSED]: { state: ValidationRunStates.PASSED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Validation passed all regression/policy criteria' },
    [ValidationRunStates.FAILED]: { state: ValidationRunStates.FAILED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Validation criteria breached' },
    [ValidationRunStates.ERROR]: { state: ValidationRunStates.ERROR, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Execution error occurred during validation' },
    [ValidationRunStates.CANCELLED]: { state: ValidationRunStates.CANCELLED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: true, description: 'Validation run cancelled' },
  },
  terminalStates: new Set([ValidationRunStates.PASSED, ValidationRunStates.FAILED, ValidationRunStates.ERROR, ValidationRunStates.CANCELLED]),
  reviewStates: new Set([ValidationRunStates.REQUIRES_REVIEW]),
  failureStates: new Set([ValidationRunStates.FAILED, ValidationRunStates.ERROR]),
  cancelStates: new Set([ValidationRunStates.CANCELLED]),
};

// 5. MODIFICATION_WORKSPACE State Catalog
export const ModificationWorkspaceStates = {
  OPEN: 'OPEN',
  APPLYING_CHANGES: 'APPLYING_CHANGES',
  ASSESSING_IMPACT: 'ASSESSING_IMPACT',
  AWAITING_APPROVAL: 'AWAITING_APPROVAL',
  COMMITTED: 'COMMITTED',
  DISCARDED: 'DISCARDED',
} as const;

const MODIFICATION_WORKSPACE_CATALOG: EntityStateCatalog = {
  entityKind: 'MODIFICATION_WORKSPACE',
  initialState: ModificationWorkspaceStates.OPEN,
  states: {
    [ModificationWorkspaceStates.OPEN]: { state: ModificationWorkspaceStates.OPEN, isInitial: true, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Workspace created for agent modification' },
    [ModificationWorkspaceStates.APPLYING_CHANGES]: { state: ModificationWorkspaceStates.APPLYING_CHANGES, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Applying patches/changes' },
    [ModificationWorkspaceStates.ASSESSING_IMPACT]: { state: ModificationWorkspaceStates.ASSESSING_IMPACT, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Evaluating change impact on security/capabilities' },
    [ModificationWorkspaceStates.AWAITING_APPROVAL]: { state: ModificationWorkspaceStates.AWAITING_APPROVAL, isInitial: false, isTerminal: false, isActive: false, isReview: true, isFailure: false, isCancel: false, description: 'Changes require reviewer sign-off' },
    [ModificationWorkspaceStates.COMMITTED]: { state: ModificationWorkspaceStates.COMMITTED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Changes committed into a new AgentVersion' },
    [ModificationWorkspaceStates.DISCARDED]: { state: ModificationWorkspaceStates.DISCARDED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: true, description: 'Workspace modifications discarded' },
  },
  terminalStates: new Set([ModificationWorkspaceStates.COMMITTED, ModificationWorkspaceStates.DISCARDED]),
  reviewStates: new Set([ModificationWorkspaceStates.AWAITING_APPROVAL]),
  failureStates: new Set(),
  cancelStates: new Set([ModificationWorkspaceStates.DISCARDED]),
};

// 6. PACKAGE State Catalog
export const PackageStates = {
  PENDING: 'PENDING',
  GENERATING: 'GENERATING',
  GENERATED: 'GENERATED',
  VALIDATING: 'VALIDATING',
  VALIDATED: 'VALIDATED',
  SIGNING: 'SIGNING',
  SIGNED: 'SIGNED',
  SHIPPED: 'SHIPPED',
  REJECTED: 'REJECTED',
  DEPRECATED: 'DEPRECATED',
  REVOKED: 'REVOKED',
} as const;

const PACKAGE_CATALOG: EntityStateCatalog = {
  entityKind: 'PACKAGE',
  initialState: PackageStates.PENDING,
  states: {
    [PackageStates.PENDING]: { state: PackageStates.PENDING, isInitial: true, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Package assembly queued' },
    [PackageStates.GENERATING]: { state: PackageStates.GENERATING, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Packaging archive and manifest generation' },
    [PackageStates.GENERATED]: { state: PackageStates.GENERATED, isInitial: false, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Package archive produced and hashed' },
    [PackageStates.VALIDATING]: { state: PackageStates.VALIDATING, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Verifying package attestations and SBOM integrity' },
    [PackageStates.VALIDATED]: { state: PackageStates.VALIDATED, isInitial: false, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Attestations verified' },
    [PackageStates.SIGNING]: { state: PackageStates.SIGNING, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Applying cryptographic signature' },
    [PackageStates.SIGNED]: { state: PackageStates.SIGNED, isInitial: false, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Package cryptographically sealed and signed' },
    [PackageStates.SHIPPED]: { state: PackageStates.SHIPPED, isInitial: false, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Package dispatched to shipment destination' },
    [PackageStates.REJECTED]: { state: PackageStates.REJECTED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Package validation or signing rejected' },
    [PackageStates.DEPRECATED]: { state: PackageStates.DEPRECATED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Package deprecated' },
    [PackageStates.REVOKED]: { state: PackageStates.REVOKED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Package signature revoked' },
  },
  terminalStates: new Set([PackageStates.REJECTED, PackageStates.DEPRECATED, PackageStates.REVOKED]),
  reviewStates: new Set(),
  failureStates: new Set([PackageStates.REJECTED, PackageStates.REVOKED]),
  cancelStates: new Set(),
};

// 7. SHIPMENT State Catalog
export const ShipmentStates = {
  PENDING: 'PENDING',
  PREPARING: 'PREPARING',
  IN_TRANSIT: 'IN_TRANSIT',
  DELIVERED: 'DELIVERED',
  FAILED: 'FAILED',
  CANCELLED: 'CANCELLED',
  REJECTED: 'REJECTED',
} as const;

const SHIPMENT_CATALOG: EntityStateCatalog = {
  entityKind: 'SHIPMENT',
  initialState: ShipmentStates.PENDING,
  states: {
    [ShipmentStates.PENDING]: { state: ShipmentStates.PENDING, isInitial: true, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Shipment created' },
    [ShipmentStates.PREPARING]: { state: ShipmentStates.PREPARING, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Preparing target deployment payload' },
    [ShipmentStates.IN_TRANSIT]: { state: ShipmentStates.IN_TRANSIT, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Transferring to destination registry' },
    [ShipmentStates.DELIVERED]: { state: ShipmentStates.DELIVERED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Delivery confirmed and receipt recorded' },
    [ShipmentStates.FAILED]: { state: ShipmentStates.FAILED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Shipment transfer failed' },
    [ShipmentStates.CANCELLED]: { state: ShipmentStates.CANCELLED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: true, description: 'Shipment cancelled before dispatch' },
    [ShipmentStates.REJECTED]: { state: ShipmentStates.REJECTED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Destination registry rejected package' },
  },
  terminalStates: new Set([ShipmentStates.DELIVERED, ShipmentStates.FAILED, ShipmentStates.CANCELLED, ShipmentStates.REJECTED]),
  reviewStates: new Set(),
  failureStates: new Set([ShipmentStates.FAILED, ShipmentStates.REJECTED]),
  cancelStates: new Set([ShipmentStates.CANCELLED]),
};

// 8. WORKFLOW_RUN State Catalog
export const WorkflowRunStates = {
  PENDING: 'PENDING',
  RUNNING: 'RUNNING',
  PAUSED: 'PAUSED',
  AWAITING_APPROVAL: 'AWAITING_APPROVAL',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED',
  CANCELLED: 'CANCELLED',
} as const;

const WORKFLOW_RUN_CATALOG: EntityStateCatalog = {
  entityKind: 'WORKFLOW_RUN',
  initialState: WorkflowRunStates.PENDING,
  states: {
    [WorkflowRunStates.PENDING]: { state: WorkflowRunStates.PENDING, isInitial: true, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Workflow run queued' },
    [WorkflowRunStates.RUNNING]: { state: WorkflowRunStates.RUNNING, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Workflow steps executing' },
    [WorkflowRunStates.PAUSED]: { state: WorkflowRunStates.PAUSED, isInitial: false, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Workflow paused by operator' },
    [WorkflowRunStates.AWAITING_APPROVAL]: { state: WorkflowRunStates.AWAITING_APPROVAL, isInitial: false, isTerminal: false, isActive: false, isReview: true, isFailure: false, isCancel: false, description: 'Workflow blocked on manual approval gate' },
    [WorkflowRunStates.COMPLETED]: { state: WorkflowRunStates.COMPLETED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Workflow completed successfully' },
    [WorkflowRunStates.FAILED]: { state: WorkflowRunStates.FAILED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Workflow failed' },
    [WorkflowRunStates.CANCELLED]: { state: WorkflowRunStates.CANCELLED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: true, description: 'Workflow cancelled' },
  },
  terminalStates: new Set([WorkflowRunStates.COMPLETED, WorkflowRunStates.FAILED, WorkflowRunStates.CANCELLED]),
  reviewStates: new Set([WorkflowRunStates.AWAITING_APPROVAL]),
  failureStates: new Set([WorkflowRunStates.FAILED]),
  cancelStates: new Set([WorkflowRunStates.CANCELLED]),
};

// 9. JOB State Catalog
export const JobStates = {
  QUEUED: 'QUEUED',
  LEASED: 'LEASED',
  RUNNING: 'RUNNING',
  RETRYING: 'RETRYING',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED',
  DEAD_LETTER: 'DEAD_LETTER',
  CANCELLED: 'CANCELLED',
} as const;

const JOB_CATALOG: EntityStateCatalog = {
  entityKind: 'JOB',
  initialState: JobStates.QUEUED,
  states: {
    [JobStates.QUEUED]: { state: JobStates.QUEUED, isInitial: true, isTerminal: false, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Job enqueued for worker execution' },
    [JobStates.LEASED]: { state: JobStates.LEASED, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Job leased by worker node' },
    [JobStates.RUNNING]: { state: JobStates.RUNNING, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Job actively processing' },
    [JobStates.RETRYING]: { state: JobStates.RETRYING, isInitial: false, isTerminal: false, isActive: true, isReview: false, isFailure: false, isCancel: false, description: 'Job failed transiently, scheduled for retry attempt' },
    [JobStates.COMPLETED]: { state: JobStates.COMPLETED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: false, description: 'Job finished successfully' },
    [JobStates.FAILED]: { state: JobStates.FAILED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Job failed and exhausted retries' },
    [JobStates.DEAD_LETTER]: { state: JobStates.DEAD_LETTER, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: true, isCancel: false, description: 'Job moved to dead-letter queue' },
    [JobStates.CANCELLED]: { state: JobStates.CANCELLED, isInitial: false, isTerminal: true, isActive: false, isReview: false, isFailure: false, isCancel: true, description: 'Job cancelled' },
  },
  terminalStates: new Set([JobStates.COMPLETED, JobStates.FAILED, JobStates.DEAD_LETTER, JobStates.CANCELLED]),
  reviewStates: new Set(),
  failureStates: new Set([JobStates.FAILED, JobStates.DEAD_LETTER]),
  cancelStates: new Set([JobStates.CANCELLED]),
};

// Global Catalogs Registry
export const STATE_REGISTRY: Record<LifecycleEntityKind, EntityStateCatalog> = {
  ANALYSIS_RUN: ANALYSIS_RUN_CATALOG,
  ANALYSIS_STAGE_RUN: ANALYSIS_STAGE_RUN_CATALOG,
  AGENT_VERSION: AGENT_VERSION_CATALOG,
  VALIDATION_RUN: VALIDATION_RUN_CATALOG,
  MODIFICATION_WORKSPACE: MODIFICATION_WORKSPACE_CATALOG,
  PACKAGE: PACKAGE_CATALOG,
  SHIPMENT: SHIPMENT_CATALOG,
  WORKFLOW_RUN: WORKFLOW_RUN_CATALOG,
  JOB: JOB_CATALOG,
};

export function getEntityCatalog(entityKind: LifecycleEntityKind): EntityStateCatalog {
  const catalog = STATE_REGISTRY[entityKind];
  if (!catalog) {
    throw new StateRegistryLookupError(`Unknown entity kind '${entityKind}' in State Registry`, entityKind);
  }
  return catalog;
}

export function getStateDescriptor(entityKind: LifecycleEntityKind, state: string): StateDescriptor {
  const catalog = getEntityCatalog(entityKind);
  const descriptor = catalog.states[state];
  if (!descriptor) {
    throw new StateRegistryLookupError(`Unknown state '${state}' for entity kind '${entityKind}'`, entityKind);
  }
  return descriptor;
}

export function isTerminalState(entityKind: LifecycleEntityKind, state: string): boolean {
  const catalog = getEntityCatalog(entityKind);
  return catalog.terminalStates.has(state);
}

export function isReviewState(entityKind: LifecycleEntityKind, state: string): boolean {
  const catalog = getEntityCatalog(entityKind);
  return catalog.reviewStates.has(state);
}

export function isFailureState(entityKind: LifecycleEntityKind, state: string): boolean {
  const catalog = getEntityCatalog(entityKind);
  return catalog.failureStates.has(state);
}

export function isCancelState(entityKind: LifecycleEntityKind, state: string): boolean {
  const catalog = getEntityCatalog(entityKind);
  return catalog.cancelStates.has(state);
}
