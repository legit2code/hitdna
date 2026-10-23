import {
  AgentVersionSnapshot,
  DiffAnalysisResult,
  ImpactAssessment,
  ReanalysisPlan,
  ValidationRunRecord,
  ModificationProposal,
  ModificationChange,
  ApprovalRecord,
  ValidationType,
} from './types.ts';
import { DifferentialAnalysisEngine } from './differential/comparator.ts';
import { ModificationWorkspace } from './modification/workspace.ts';
import { ApprovalEngine, CreateApprovalRequest } from './approval/flow.ts';
import { ImpactAnalysisEngine } from './impact/analyzer.ts';
import { ReanalysisPlanner } from './reanalysis/planner.ts';
import { ValidationEngine, ExecuteValidationParams } from './validation/engine.ts';
import { LifecycleStateMachineService } from '@caim/lifecycle';

export class LifecycleImprovementService {
  private workspaces: Map<string, ModificationWorkspace> = new Map();
  private versions: Map<string, AgentVersionSnapshot> = new Map();
  private validationRuns: Map<string, ValidationRunRecord> = new Map();
  private approvals: Map<string, ApprovalRecord[]> = new Map();

  /**
   * Registers a version snapshot in the service repository.
   */
  public registerVersion(version: AgentVersionSnapshot): void {
    this.versions.set(version.agentVersionId, Object.freeze(JSON.parse(JSON.stringify(version))));
  }

  public getVersion(versionId: string): AgentVersionSnapshot | undefined {
    return this.versions.get(versionId);
  }

  /**
   * Creates a new isolated ModificationWorkspace referencing an immutable base version.
   */
  public createWorkspace(params: {
    baseVersionId: string;
    createdBy: string;
    scopeId: string;
  }): ModificationWorkspace {
    const baseVersion = this.versions.get(params.baseVersionId);
    if (!baseVersion) {
      throw new Error(`Baseline AgentVersion '${params.baseVersionId}' not found.`);
    }

    const workspaceId = `ws-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const workspace = new ModificationWorkspace({
      workspaceId,
      baseVersion,
      createdBy: params.createdBy,
      scopeId: params.scopeId,
    });

    this.workspaces.set(workspaceId, workspace);
    return workspace;
  }

  public getWorkspace(workspaceId: string): ModificationWorkspace | undefined {
    return this.workspaces.get(workspaceId);
  }

  /**
   * Stages an AI remediation proposal (proposal only, requires explicit acceptance).
   */
  public stageAiProposal(
    workspaceId: string,
    proposal: Omit<ModificationProposal, 'isStaged'>
  ): ModificationProposal {
    const ws = this.workspaces.get(workspaceId);
    if (!ws) throw new Error(`Workspace '${workspaceId}' not found.`);
    return ws.stageAiProposal(proposal);
  }

  /**
   * Accepts an AI proposal into the active working files.
   */
  public acceptProposal(
    workspaceId: string,
    proposalId: string,
    actorRef: string
  ): ModificationChange {
    const ws = this.workspaces.get(workspaceId);
    if (!ws) throw new Error(`Workspace '${workspaceId}' not found.`);
    return ws.acceptProposal(proposalId, actorRef);
  }

  /**
   * Applies a human manual edit directly to the workspace.
   */
  public applyHumanEdit(
    workspaceId: string,
    editParams: {
      filePath: string;
      newContent?: string;
      patchContent?: string;
      changeType?: 'CREATE' | 'UPDATE' | 'DELETE' | 'PATCH';
      actorRef: string;
    }
  ): ModificationChange {
    const ws = this.workspaces.get(workspaceId);
    if (!ws) throw new Error(`Workspace '${workspaceId}' not found.`);
    return ws.applyHumanEdit(editParams);
  }

  /**
   * Grants and records a formal security approval for a workspace or version.
   */
  public recordApproval(request: CreateApprovalRequest): ApprovalRecord {
    const approval = ApprovalEngine.createApproval(request);
    const existing = this.approvals.get(request.targetEntityRefId) || [];
    existing.push(approval);
    this.approvals.set(request.targetEntityRefId, existing);

    if (request.targetType === 'MODIFICATION_WORKSPACE') {
      const ws = this.workspaces.get(request.targetEntityRefId);
      if (ws) ws.recordApproval(approval);
    }

    return approval;
  }

  public getApprovals(targetEntityRefId: string): ApprovalRecord[] {
    return this.approvals.get(targetEntityRefId) || [];
  }

  /**
   * Computes differential analysis between two version snapshots.
   */
  public compareVersions(
    baselineVersionId: string,
    candidateVersionId: string
  ): DiffAnalysisResult {
    const baseline = this.versions.get(baselineVersionId);
    const candidate = this.versions.get(candidateVersionId);
    if (!baseline || !candidate) {
      throw new Error('Baseline or Candidate version not found for differential comparison.');
    }
    return DifferentialAnalysisEngine.compare(baseline, candidate);
  }

  /**
   * Assesses blast radius and downstream impact of workspace changes.
   */
  public assessWorkspaceImpact(workspaceId: string): {
    impact: ImpactAssessment;
    diff: DiffAnalysisResult;
  } {
    const ws = this.workspaces.get(workspaceId);
    if (!ws) throw new Error(`Workspace '${workspaceId}' not found.`);

    // Build temporary snapshot of workspace working state
    const workingSnapshot: AgentVersionSnapshot = {
      ...ws.baseVersion,
      agentVersionId: `temp-${ws.workspaceId}`,
      sourceFiles: ws.getWorkingFiles(),
    };

    const diff = DifferentialAnalysisEngine.compare(ws.baseVersion, workingSnapshot);
    const impact = ImpactAnalysisEngine.evaluate(diff, ws.baseVersion);

    return { impact, diff };
  }

  /**
   * Generates a reanalysis plan for workspace modifications.
   */
  public planReanalysis(workspaceId: string): ReanalysisPlan {
    const { impact, diff } = this.assessWorkspaceImpact(workspaceId);
    return ReanalysisPlanner.plan(diff, impact);
  }

  /**
   * Commits the workspace into a new immutable candidate version.
   */
  public commitWorkspace(params: {
    workspaceId: string;
    newVersionLabel: string;
    actorRef: string;
    requireApproval?: boolean;
  }): AgentVersionSnapshot {
    const ws = this.workspaces.get(params.workspaceId);
    if (!ws) throw new Error(`Workspace '${params.workspaceId}' not found.`);

    const newVersion = ws.commit({
      newVersionLabel: params.newVersionLabel,
      actorRef: params.actorRef,
      requireExplicitApproval: params.requireApproval,
    });

    this.registerVersion(newVersion);
    return newVersion;
  }

  /**
   * Executes validation between baseline and modified candidate versions.
   */
  public executeValidation(params: {
    validationType: ValidationType;
    baselineVersionId: string;
    modifiedVersionId: string;
    validationAnalysisRunId: string;
    scopeId: string;
    scenarioPackId?: string;
    requireApprovalForSourceMod?: boolean;
  }): ValidationRunRecord {
    const baseline = this.versions.get(params.baselineVersionId);
    const modified = this.versions.get(params.modifiedVersionId);
    if (!baseline || !modified) {
      throw new Error('Baseline or Modified version not found for validation run.');
    }

    const approvals = this.getApprovals(params.modifiedVersionId);

    const validationRun = ValidationEngine.execute({
      validationType: params.validationType,
      baseline,
      modified,
      validationAnalysisRunId: params.validationAnalysisRunId,
      scopeId: params.scopeId,
      scenarioPackId: params.scenarioPackId,
      approvals,
      requireApprovalForSourceMod: params.requireApprovalForSourceMod,
    });

    this.validationRuns.set(validationRun.validation_run_id, validationRun);
    return validationRun;
  }

  public getValidationRun(validationRunId: string): ValidationRunRecord | undefined {
    return this.validationRuns.get(validationRunId);
  }
}
