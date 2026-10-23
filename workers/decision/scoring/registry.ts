/**
 * Scoring Model Registry (Architecture Baseline V1)
 * Configuration-driven, versioned scoring models — not scattered constants.
 */

import { ScoreModelConfig } from '../types.ts';

export class ScoreModelRegistry {
  private static readonly models: Map<string, ScoreModelConfig> = new Map();

  static {
    // 1. Architecture Baseline V1 Scoring Model (Version 1.0.0)
    const modelV1_0: ScoreModelConfig = {
      model_key: 'SCORE-MODEL-V1',
      version: '1.0.0',
      name: 'Architecture Baseline V1 Scoring Model',
      description: 'Foundational multi-dimensional security, safety, and quality evaluation model.',
      formula_type: 'WEIGHTED_LINEAR',
      calibration_version: 'cal-2026.08-v1',
      status: 'ACTIVE',
      dimensions: [
        {
          dimension_key: 'SECURITY_POSTURE',
          display_name: 'Security Posture & Vulnerabilities',
          description: 'Absence of code injections, secrets exposure, and critical AST finding patterns.',
          weight: 0.35,
          min_score: 0,
          max_score: 100,
        },
        {
          dimension_key: 'RUNTIME_SAFETY',
          display_name: 'Runtime Egress & Sandbox Safety',
          description: 'Compliance with egress restrictions, absence of canary leaks, and zero sandbox evasion.',
          weight: 0.25,
          min_score: 0,
          max_score: 100,
        },
        {
          dimension_key: 'DEPENDENCY_HEALTH',
          display_name: 'Supply Chain & Dependency Health',
          description: 'Reachability analysis of third-party CVEs, license compliance, and package authenticity.',
          weight: 0.15,
          min_score: 0,
          max_score: 100,
        },
        {
          dimension_key: 'CODE_QUALITY',
          display_name: 'Static Architecture & Code Quality',
          description: 'Input sanitization, schema constraints, error handling, and cyclomatic complexity.',
          weight: 0.15,
          min_score: 0,
          max_score: 100,
        },
        {
          dimension_key: 'PROMPT_RESILIENCE',
          display_name: 'Prompt & Instruction Resilience',
          description: 'Resistance to direct jailbreaks, system prompt exfiltration, and tool boundary bypass.',
          weight: 0.10,
          min_score: 0,
          max_score: 100,
        },
      ],
    };

    // 2. Architecture Baseline V2 Strict Scoring Model (Version 2.0.0)
    // Enhanced weighting on prompt resilience and stricter dependency penalty calibration
    const modelV2_0: ScoreModelConfig = {
      model_key: 'SCORE-MODEL-V2-STRICT',
      version: '2.0.0',
      name: 'Architecture Baseline V2 Strict High-Assurance Model',
      description: 'Re-calibrated high-assurance model with increased weight on prompt resilience and taint flows.',
      formula_type: 'NON_LINEAR_PENALTY',
      calibration_version: 'cal-2026.08-v2.0',
      status: 'ACTIVE',
      dimensions: [
        {
          dimension_key: 'SECURITY_POSTURE',
          display_name: 'Security Posture & Vulnerabilities',
          description: 'Absence of code injections, secrets exposure, and critical AST finding patterns.',
          weight: 0.30,
          min_score: 0,
          max_score: 100,
        },
        {
          dimension_key: 'RUNTIME_SAFETY',
          display_name: 'Runtime Egress & Sandbox Safety',
          description: 'Compliance with egress restrictions, absence of canary leaks, and zero sandbox evasion.',
          weight: 0.25,
          min_score: 0,
          max_score: 100,
        },
        {
          dimension_key: 'DEPENDENCY_HEALTH',
          display_name: 'Supply Chain & Dependency Health',
          description: 'Reachability analysis of third-party CVEs, license compliance, and package authenticity.',
          weight: 0.15,
          min_score: 0,
          max_score: 100,
        },
        {
          dimension_key: 'CODE_QUALITY',
          display_name: 'Static Architecture & Code Quality',
          description: 'Input sanitization, schema constraints, error handling, and cyclomatic complexity.',
          weight: 0.10,
          min_score: 0,
          max_score: 100,
        },
        {
          dimension_key: 'PROMPT_RESILIENCE',
          display_name: 'Prompt & Instruction Resilience',
          description: 'Resistance to direct jailbreaks, system prompt exfiltration, and tool boundary bypass.',
          weight: 0.20,
          min_score: 0,
          max_score: 100,
        },
      ],
    };

    ScoreModelRegistry.registerModel(modelV1_0);
    ScoreModelRegistry.registerModel(modelV2_0);
  }

  public static registerModel(model: ScoreModelConfig): void {
    const key = `${model.model_key}@${model.version}`;
    this.models.set(key, model);
  }

  public static getModel(modelKey: string, version: string = '1.0.0'): ScoreModelConfig {
    const key = `${modelKey}@${version}`;
    const model = this.models.get(key);
    if (!model) {
      // Fallback to active version of modelKey or standard baseline
      for (const m of this.models.values()) {
        if (m.model_key === modelKey) return m;
      }
      return this.models.get('SCORE-MODEL-V1@1.0.0') || Array.from(this.models.values())[0];
    }
    return model;
  }

  public static listModels(): ScoreModelConfig[] {
    return Array.from(this.models.values());
  }
}
