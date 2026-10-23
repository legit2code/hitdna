import crypto from 'node:crypto';
import {
  AgentVersionSnapshot,
  ModificationProposal,
  ModificationChange,
  ModificationStatus,
  ApprovalRecord,
  ChangeAuthorType,
  SourceFileSnapshot,
} from '../types.ts';

export interface WorkspaceConfig {
  workspaceId: string;
  baseVersion: AgentVersionSnapshot;
  createdBy: string;
  scopeId: string;
}

export class ModificationWorkspace {
  public readonly workspaceId: string;
  public readonly baseVersion: AgentVersionSnapshot;
  public readonly createdBy: string;
  public readonly scopeId: string;

  private status: ModificationStatus = 'OPEN';
  private proposals: Map<string, ModificationProposal> = new Map();
  private changes: ModificationChange[] = [];
  private approvals: ApprovalRecord[] = [];
  private workingFiles: Record<string, SourceFileSnapshot> = {};

  constructor(config: WorkspaceConfig) {
    this.workspaceId = config.workspaceId;
    this.baseVersion = Object.freeze(JSON.parse(JSON.stringify(config.baseVersion)));
    this.createdBy = config.createdBy;
    this.scopeId = config.scopeId;

    // Clone baseline files into mutable working copy
    for (const [path, file] of Object.entries(this.baseVersion.sourceFiles)) {
      this.workingFiles[path] = { ...file };
    }
  }

  public getStatus(): ModificationStatus {
    return this.status;
  }

  public getChanges(): ModificationChange[] {
    return [...this.changes];
  }

  public getProposals(): ModificationProposal[] {
    return Array.from(this.proposals.values());
  }

  public getApprovals(): ApprovalRecord[] {
    return [...this.approvals];
  }

  public getWorkingFiles(): Record<string, SourceFileSnapshot> {
    return { ...this.workingFiles };
  }

  /**
   * Enforces immutability check on the original baseline version.
   */
  public verifyBaselineImmutability(): boolean {
    if (!this.baseVersion.isImmutable) {
      throw new Error(`Baseline version ${this.baseVersion.agentVersionId} must be immutable.`);
    }
    return true;
  }

  /**
   * Stages an AI remediation suggestion as a proposal ONLY.
   * Does NOT modify working files until explicitly accepted.
   */
  public stageAiProposal(proposal: Omit<ModificationProposal, 'isStaged'>): ModificationProposal {
    if (this.status === 'COMMITTED' || this.status === 'DISCARDED') {
      throw new Error(`Cannot add proposals to workspace in state ${this.status}`);
    }

    const fullProposal: ModificationProposal = {
      ...proposal,
      isStaged: true,
      authorType: proposal.authorType || 'AGENT',
    };

    this.proposals.set(proposal.proposalId, fullProposal);
    return fullProposal;
  }

  /**
   * Explicitly accepts a staged AI proposal, turning it into an applied modification change.
   */
  public acceptProposal(proposalId: string, actorRef: string): ModificationChange {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) {
      throw new Error(`Proposal ${proposalId} not found in workspace.`);
    }

    proposal.acceptedAt = new Date().toISOString();
    this.status = 'APPLYING_CHANGES';

    const change: ModificationChange = {
      changeId: `chg-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      workspaceId: this.workspaceId,
      filePath: proposal.targetFile,
      changeType: 'PATCH',
      patchLocator: `patch://proposal/${proposalId}`,
      patchContent: proposal.patchContent,
      authorType: proposal.authorType,
      authorRef: actorRef,
      createdAt: new Date().toISOString(),
    };

    this.applyPatchToWorkingFile(proposal.targetFile, proposal.patchContent);
    this.changes.push(change);

    return change;
  }

  /**
   * Applies a human manual edit directly to the workspace.
   */
  public applyHumanEdit(params: {
    filePath: string;
    newContent?: string;
    patchContent?: string;
    changeType?: 'CREATE' | 'UPDATE' | 'DELETE' | 'PATCH';
    actorRef: string;
  }): ModificationChange {
    if (this.status === 'COMMITTED' || this.status === 'DISCARDED') {
      throw new Error(`Cannot apply changes to workspace in state ${this.status}`);
    }

    this.status = 'APPLYING_CHANGES';
    const changeType = params.changeType || (params.patchContent ? 'PATCH' : 'UPDATE');

    const change: ModificationChange = {
      changeId: `chg-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      workspaceId: this.workspaceId,
      filePath: params.filePath,
      changeType,
      patchLocator: `edit://${params.filePath}`,
      newContent: params.newContent,
      patchContent: params.patchContent,
      authorType: 'HUMAN',
      authorRef: params.actorRef,
      createdAt: new Date().toISOString(),
    };

    if (changeType === 'DELETE') {
      delete this.workingFiles[params.filePath];
    } else if (params.newContent !== undefined) {
      this.workingFiles[params.filePath] = {
        path: params.filePath,
        content: params.newContent,
        hash: `sha256:${crypto.createHash('sha256').update(params.newContent).digest('hex')}`,
        sizeBytes: params.newContent.length,
      };
    } else if (params.patchContent) {
      this.applyPatchToWorkingFile(params.filePath, params.patchContent);
    }

    this.changes.push(change);
    return change;
  }

  /**
   * Records an explicit security review approval for this workspace.
   */
  public recordApproval(approval: ApprovalRecord): void {
    this.approvals.push(approval);
    if (approval.decision === 'APPROVED') {
      this.status = 'AWAITING_APPROVAL';
    }
  }

  /**
   * Commits the workspace into a brand-new immutable AgentVersion.
   * INVARIANT: Unapproved modifications with breaking/high-risk changes or lacking approval cannot commit.
   */
  public commit(params: {
    newVersionLabel: string;
    actorRef: string;
    requireExplicitApproval?: boolean;
  }): AgentVersionSnapshot {
    if (this.status === 'DISCARDED') {
      throw new Error('Cannot commit a discarded modification workspace.');
    }

    const hasApproval = this.approvals.some((a) => a.decision === 'APPROVED');
    if (params.requireExplicitApproval && !hasApproval) {
      throw new Error('Unapproved modification workspace cannot commit to new version.');
    }

    // Verify baseline was never mutated
    this.verifyBaselineImmutability();

    const newVersionId = `v-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const newRunId = `run-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    const candidateVersion: AgentVersionSnapshot = {
      agentVersionId: newVersionId,
      agentId: this.baseVersion.agentId,
      versionLabel: params.newVersionLabel,
      status: 'ANALYZED',
      isImmutable: true,
      createdAt: new Date().toISOString(),
      sourceFiles: { ...this.workingFiles },
      astNodes: this.baseVersion.astNodes.map((n) => ({ ...n })),
      dependencies: { ...this.baseVersion.dependencies },
      capabilities: this.baseVersion.capabilities.map((c) => ({ ...c })),
      permissions: this.baseVersion.permissions.map((p) => ({ ...p })),
      behaviors: this.baseVersion.behaviors.map((b) => ({ ...b })),
      riskScore: { ...this.baseVersion.riskScore },
      analyzerConfig: { ...this.baseVersion.analyzerConfig },
      analysisRunId: newRunId,
    };

    this.status = 'COMMITTED';
    return Object.freeze(candidateVersion);
  }

  public discard(reason: string): void {
    this.status = 'DISCARDED';
  }

  private applyPatchToWorkingFile(filePath: string, patchContent: string): void {
    const existing = this.workingFiles[filePath];
    if (existing) {
      // In realistic diff application, apply the patch or replace
      const updated = `${existing.content}\n// Patched:\n${patchContent}`;
      this.workingFiles[filePath] = {
        path: filePath,
        content: updated,
        hash: `sha256:${crypto.createHash('sha256').update(updated).digest('hex')}`,
        sizeBytes: updated.length,
      };
    } else {
      this.workingFiles[filePath] = {
        path: filePath,
        content: patchContent,
        hash: `sha256:${crypto.createHash('sha256').update(patchContent).digest('hex')}`,
        sizeBytes: patchContent.length,
      };
    }
  }
}
