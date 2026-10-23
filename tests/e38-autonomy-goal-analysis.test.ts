import { describe, it, expect } from 'vitest';
import { 
  AutonomyGoalAnalysisEngine, 
  AutonomyExecutionProfile 
} from '../workers/decision/capabilities/autonomy-analysis.ts';

describe('E38: Autonomy Goal Analysis Engine', () => {
  const engine = new AutonomyGoalAnalysisEngine();

  it('rejects unbounded autonomous recursion loops lacking iteration caps and termination predicates', () => {
    const runawayScenario: AutonomyExecutionProfile = {
      agentId: 'agent-runaway-autogpt',
      hasAutonomousLoop: true,
      maxIterationLimit: undefined, // Unbounded
      hasExplicitTerminationCondition: false, // No goal predicate check
      allowsSubagentSpawning: true,
      maxSubagentDepth: 10, // Dangerous depth
      hasHumanInTheLoopApproval: false,
      hitlTriggerConditions: [],
      planningAlgorithm: 'AUTOGPT_RECURSIVE'
    };

    const evaluation = engine.evaluateAutonomySafety('run-e38-001', runawayScenario);

    expect(evaluation.autonomyLevel).toBe('FULLY_AUTONOMOUS_UNBOUNDED');
    expect(evaluation.isApprovedForAutonomousExecution).toBe(false);
    expect(evaluation.findings.some(f => f.riskType === 'MISSING_ITERATION_CAP' && f.severity === 'CRITICAL')).toBe(true);
    expect(evaluation.findings.some(f => f.riskType === 'MISSING_TERMINATION_CRITERIA' && f.severity === 'CRITICAL')).toBe(true);
    expect(evaluation.findings.some(f => f.riskType === 'UNBOUNDED_SUBAGENT_SPAWNING')).toBe(true);
    expect(evaluation.findings.some(f => f.riskType === 'BYPASS_HUMAN_IN_THE_LOOP')).toBe(true);
    expect(evaluation.requiredSafeguards).toContain('HARD_ITERATION_CAP_MAX_25');
    expect(evaluation.requiredSafeguards).toContain('GOAL_PREDICATE_TERMINATION');
    expect(evaluation.safetyBoundaryScore).toBeLessThan(0.4);
  });

  it('validates and approves bounded semi-autonomous agent with strict HITL and iteration caps', () => {
    const safeScenario: AutonomyExecutionProfile = {
      agentId: 'agent-governed-analyst',
      hasAutonomousLoop: true,
      maxIterationLimit: 8,
      maxExecutionTimeSeconds: 300,
      hasExplicitTerminationCondition: true,
      allowsSubagentSpawning: true,
      maxSubagentDepth: 2,
      hasHumanInTheLoopApproval: true,
      hitlTriggerConditions: ['destructive_action', 'budget_exceeded', 'schema_mutation'],
      resourceBudgetCapDollars: 5.0,
      planningAlgorithm: 'REACT'
    };

    const evaluation = engine.evaluateAutonomySafety('run-e38-002', safeScenario);

    expect(evaluation.autonomyLevel).toBe('SEMI_AUTONOMOUS');
    expect(evaluation.isApprovedForAutonomousExecution).toBe(true);
    expect(evaluation.findings.length).toBe(0);
    expect(evaluation.safetyBoundaryScore).toBe(1.0);
  });

  it('detects unconstrained financial spending budget in autonomous executor', () => {
    const unbudgetedScenario: AutonomyExecutionProfile = {
      agentId: 'agent-spending-spree',
      hasAutonomousLoop: true,
      maxIterationLimit: 8,
      hasExplicitTerminationCondition: true,
      allowsSubagentSpawning: false,
      hasHumanInTheLoopApproval: true,
      hitlTriggerConditions: ['destructive_action'],
      resourceBudgetCapDollars: undefined, // Missing financial cap
      planningAlgorithm: 'REACT'
    };

    const evaluation = engine.evaluateAutonomySafety('run-e38-003', unbudgetedScenario);

    expect(evaluation.findings.some(f => f.riskType === 'UNCONSTRAINED_FINANCIAL_BUDGET')).toBe(true);
    expect(evaluation.requiredSafeguards).toContain('SESSION_FINANCIAL_CAP');
  });
});
