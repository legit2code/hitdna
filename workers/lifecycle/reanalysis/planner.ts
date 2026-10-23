import {
  DiffAnalysisResult,
  ImpactAssessment,
  ReanalysisPlan,
  ReanalysisStage,
  ReanalysisTrigger,
} from '../types.ts';

export class ReanalysisPlanner {
  /**
   * Plans required reanalysis stages based on differential and impact findings.
   */
  public static plan(
    diff: DiffAnalysisResult,
    impact: ImpactAssessment
  ): ReanalysisPlan {
    const planId = `plan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const trigger: ReanalysisTrigger = impact.suggestedReanalysisTrigger;
    const stages: ReanalysisStage[] = [];

    const modifiedPaths = diff.fileDiffs
      .filter((f) => f.changeType !== 'UNCHANGED')
      .map((f) => f.path);

    if (trigger === 'FULL_REANALYSIS') {
      stages.push(
        {
          stageId: 'stage-syntax-ast',
          stageName: 'Full Syntax & AST Graph Decomposition',
          scope: 'ALL',
          estimatedDurationMs: 850,
        },
        {
          stageId: 'stage-taint-static',
          stageName: 'Global Interprocedural Taint & Security Analysis',
          scope: 'ALL',
          estimatedDurationMs: 1400,
        },
        {
          stageId: 'stage-dynamic-sandbox',
          stageName: 'Isolated Dynamic Sandbox Telemetry & Scenario Replay',
          scope: 'ALL',
          estimatedDurationMs: 2500,
        },
        {
          stageId: 'stage-decision-scoring',
          stageName: 'Multi-Dimensional Risk Scoring & Epistemic Synthesis',
          scope: 'ALL',
          estimatedDurationMs: 600,
        },
        {
          stageId: 'stage-policy-evaluation',
          stageName: 'Security & Compliance Policy Gate Evaluation',
          scope: 'POLICY_ONLY',
          estimatedDurationMs: 300,
        }
      );
    } else if (trigger === 'INCREMENTAL_REANALYSIS') {
      stages.push(
        {
          stageId: 'stage-syntax-targeted',
          stageName: 'Targeted AST Parser for Modified Files',
          scope: 'TARGETED_FILES',
          targetPaths: modifiedPaths,
          estimatedDurationMs: 300,
        },
        {
          stageId: 'stage-taint-targeted',
          stageName: 'Incremental Taint & Flow Analysis',
          scope: 'TARGETED_FILES',
          targetPaths: modifiedPaths,
          estimatedDurationMs: 650,
        },
        {
          stageId: 'stage-decision-incremental',
          stageName: 'Incremental Risk Delta Synthesis',
          scope: 'TARGETED_FILES',
          estimatedDurationMs: 400,
        },
        {
          stageId: 'stage-policy-evaluation',
          stageName: 'Security & Compliance Policy Gate Evaluation',
          scope: 'POLICY_ONLY',
          estimatedDurationMs: 250,
        }
      );
    } else {
      stages.push({
        stageId: 'stage-policy-fastpath',
        stageName: 'Fast-Path Policy Verification',
        scope: 'POLICY_ONLY',
        estimatedDurationMs: 150,
      });
    }

    const reanalysisReason =
      trigger === 'FULL_REANALYSIS'
        ? `Full reanalysis triggered due to high-impact changes (${impact.highestSeverity}): entry points, dependencies, or permissions were modified.`
        : trigger === 'INCREMENTAL_REANALYSIS'
        ? `Incremental reanalysis triggered for ${modifiedPaths.length} modified file(s).`
        : 'No code reanalysis needed; fast-path policy verification only.';

    return {
      planId,
      trigger,
      stages,
      reanalysisReason,
      totalEstimatedStages: stages.length,
    };
  }
}
