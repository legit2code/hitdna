/**
 * E38: Autonomy Goal Analysis Engine
 * Architecture V2.0.1 - Capability Analysis Subsystem
 *
 * Evaluates agent autonomous execution loops, self-directed planning mechanisms,
 * termination conditions, runaway loop defenses, and human-in-the-loop (HITL) checkpoints.
 * Identifies runaway recursion risks, unconstrained autonomous sub-agent spawning,
 * and missing budget/time limit guardrails.
 */

export interface AutonomyExecutionProfile {
  agentId: string;
  hasAutonomousLoop: boolean;
  maxIterationLimit?: number;
  maxExecutionTimeSeconds?: number;
  hasExplicitTerminationCondition: boolean;
  allowsSubagentSpawning: boolean;
  maxSubagentDepth?: number;
  hasHumanInTheLoopApproval: boolean;
  hitlTriggerConditions: string[]; // e.g. ["destructive_action", "budget_exceeded", "financial_transaction"]
  resourceBudgetCapDollars?: number;
  planningAlgorithm: 'REACT' | 'PLAN_AND_SOLVE' | 'AUTOGPT_RECURSIVE' | 'LINEAR_CHAIN' | 'NONE';
}

export type AutonomyRiskType =
  | 'UNCONSTRAINED_RECURSION_LOOP'
  | 'MISSING_ITERATION_CAP'
  | 'UNBOUNDED_SUBAGENT_SPAWNING'
  | 'BYPASS_HUMAN_IN_THE_LOOP'
  | 'MISSING_TERMINATION_CRITERIA'
  | 'UNCONSTRAINED_FINANCIAL_BUDGET';

export interface AutonomyRiskFinding {
  riskType: AutonomyRiskType;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  remediation: string;
}

export interface AutonomySafetyEvaluation {
  analysisRunId: string;
  agentId: string;
  autonomyLevel: 'MANUAL_SUPERVISED' | 'SEMI_AUTONOMOUS' | 'HIGHLY_AUTONOMOUS' | 'FULLY_AUTONOMOUS_UNBOUNDED';
  safetyBoundaryScore: number; // 0.0 to 1.0 (1.0 = strict bounded guardrails)
  findings: AutonomyRiskFinding[];
  isApprovedForAutonomousExecution: boolean;
  requiredSafeguards: string[];
}

export class AutonomyGoalAnalysisEngine {
  public evaluateAutonomySafety(
    analysisRunId: string,
    profile: AutonomyExecutionProfile
  ): AutonomySafetyEvaluation {
    const findings: AutonomyRiskFinding[] = [];
    const requiredSafeguards: string[] = [];

    // 1. Check for unbounded execution loops without iteration cap
    if (profile.hasAutonomousLoop) {
      if (!profile.maxIterationLimit || profile.maxIterationLimit > 50) {
        findings.push({
          riskType: 'MISSING_ITERATION_CAP',
          severity: !profile.maxIterationLimit ? 'CRITICAL' : 'HIGH',
          title: 'Autonomous Loop Lacks Safe Iteration Upper Bound',
          description: `The agent executes an autonomous loop with ${profile.maxIterationLimit ? `excessive iteration cap (${profile.maxIterationLimit})` : 'NO iteration cap'}, risking catastrophic infinite recursion.`,
          remediation: 'Configure a strict maxIterationLimit <= 25 for all autonomous planning loops.',
        });
        requiredSafeguards.push('HARD_ITERATION_CAP_MAX_25');
      }

      // 2. Check for explicit termination criteria
      if (!profile.hasExplicitTerminationCondition) {
        findings.push({
          riskType: 'MISSING_TERMINATION_CRITERIA',
          severity: 'CRITICAL',
          title: 'Missing Deterministic Loop Termination Condition',
          description: 'Autonomous planning loop lacks formal goal completion or failure termination criteria.',
          remediation: 'Implement explicit goal predicate checks and stop token detection in the planning loop.',
        });
        requiredSafeguards.push('GOAL_PREDICATE_TERMINATION');
      }
    }

    // 3. Subagent spawning boundaries
    if (profile.allowsSubagentSpawning) {
      if (!profile.maxSubagentDepth || profile.maxSubagentDepth > 3) {
        findings.push({
          riskType: 'UNBOUNDED_SUBAGENT_SPAWNING',
          severity: 'CRITICAL',
          title: 'Unbounded Sub-Agent Forking Hierarchy',
          description: `Sub-agent spawning depth is ${profile.maxSubagentDepth ?? 'unlimited'}, creating a fork-bomb vulnerability.`,
          remediation: 'Enforce maxSubagentDepth <= 2 and global child process concurrency quotas.',
        });
        requiredSafeguards.push('SUBAGENT_DEPTH_QUOTA_MAX_2');
      }
    }

    // 4. Human in the Loop (HITL) Checkpoints
    if (profile.planningAlgorithm === 'AUTOGPT_RECURSIVE' || profile.hasAutonomousLoop) {
      if (!profile.hasHumanInTheLoopApproval || profile.hitlTriggerConditions.length === 0) {
        findings.push({
          riskType: 'BYPASS_HUMAN_IN_THE_LOOP',
          severity: 'HIGH',
          title: 'Autonomous Action Without Human Confirmation Checkpoints',
          description: 'Autonomous planner can execute high-consequence state modifications without operator approval.',
          remediation: 'Enforce interactive approval gateways for destructive, stateful, or high-cost tool operations.',
        });
        requiredSafeguards.push('MANDATORY_HITL_GATES');
      }
    }

    // 5. Budget constraints
    if (profile.resourceBudgetCapDollars === undefined || profile.resourceBudgetCapDollars <= 0) {
      findings.push({
        riskType: 'UNCONSTRAINED_FINANCIAL_BUDGET',
        severity: 'MEDIUM',
        title: 'Missing Explicit Resource & Token Budget Cap',
        description: 'No dollar-denominated financial or API token quota specified for autonomous execution run.',
        remediation: 'Set hard spending limits per analysis/execution session.',
      });
      requiredSafeguards.push('SESSION_FINANCIAL_CAP');
    }

    // Calculate autonomy level
    let autonomyLevel: AutonomySafetyEvaluation['autonomyLevel'] = 'MANUAL_SUPERVISED';
    if (!profile.hasAutonomousLoop && profile.planningAlgorithm === 'NONE') {
      autonomyLevel = 'MANUAL_SUPERVISED';
    } else if (profile.hasHumanInTheLoopApproval && (profile.maxIterationLimit ?? 0) <= 10) {
      autonomyLevel = 'SEMI_AUTONOMOUS';
    } else if (profile.hasAutonomousLoop && findings.some((f) => f.severity === 'CRITICAL')) {
      autonomyLevel = 'FULLY_AUTONOMOUS_UNBOUNDED';
    } else {
      autonomyLevel = 'HIGHLY_AUTONOMOUS';
    }

    const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
    const highCount = findings.filter((f) => f.severity === 'HIGH').length;

    let score = Math.max(0, 1.0 - (criticalCount * 0.4) - (highCount * 0.15) - (findings.length * 0.05));
    score = Math.round(score * 100) / 100;

    const isApproved = criticalCount === 0 && score >= 0.7;

    return {
      analysisRunId,
      agentId: profile.agentId,
      autonomyLevel,
      safetyBoundaryScore: score,
      findings,
      isApprovedForAutonomousExecution: isApproved,
      requiredSafeguards,
    };
  }
}
