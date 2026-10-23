/**
 * Gemini Decision Assistant (Architecture V2.0.1)
 * Provides AI-assisted recommendation and use-case synthesis via @google/genai structured outputs.
 * Strict Mandate: Deterministic validators remain authoritative; LLM output is never trusted without validation.
 */

import { GoogleGenAI } from '@google/genai';
import {
  RecommendationRecord,
  UseCaseEvaluationRecord,
  RiskRecord,
  ScoreResult,
  PolicyDecision,
} from '../types.ts';
import { RecommendationEngine } from '../recommendations/engine.ts';
import { UseCaseEngine, USE_CASE_PROFILE_V1 } from '../use-cases/engine.ts';

let aiClient: GoogleGenAI | null = null;

function getAiClient(): GoogleGenAI | null {
  if (!aiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (apiKey) {
      aiClient = new GoogleGenAI({ apiKey });
    }
  }
  return aiClient;
}

export class GeminiDecisionAssistant {
  /**
   * Generates AI-assisted recommendations backed by structured outputs and validated deterministically.
   */
  public static async synthesizeRecommendations(params: {
    analysisRunId: string;
    entityRefId?: string;
    risks: RiskRecord[];
    evidenceList?: Array<{ evidence_id: string; summary?: string }>;
  }): Promise<RecommendationRecord[]> {
    const ai = getAiClient();
    const deterministicBaseline = RecommendationEngine.generateRecommendations(params);

    if (!ai || params.risks.length === 0) {
      return deterministicBaseline;
    }

    try {
      const prompt = `You are a cybersecurity decision engine auditor. Given the following identified risks:
${JSON.stringify(
  params.risks.map((r) => ({
    risk_id: r.risk_id,
    type: r.risk_type,
    severity: r.severity,
    title: r.title,
    description: r.description,
    evidence_ids: r.evidence_links.map((e) => e.evidence_id),
  })),
  null,
  2
)}

Generate actionable, concrete remediation steps for each risk.
Respond strictly with valid JSON conforming to the following array structure:
[
  {
    "risk_id": string,
    "recommendation_type": "REMEDIATION" | "MITIGATION" | "HARDENING" | "GOVERNANCE",
    "title": string,
    "action_steps": string,
    "priority": "P0" | "P1" | "P2" | "P3",
    "effort_estimate": "LOW" | "MEDIUM" | "HIGH",
    "evidence_ids": string[]
  }
]`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.7-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
        },
      });

      const text = response.text?.trim();
      if (!text) return deterministicBaseline;

      const parsed = JSON.parse(text) as Array<{
        risk_id: string;
        recommendation_type: any;
        title: string;
        action_steps: string;
        priority: any;
        effort_estimate: any;
        evidence_ids: string[];
      }>;

      const aiGeneratedRecs: RecommendationRecord[] = parsed.map((item, idx) => ({
        recommendation_id: `rec-ai-${Date.now()}-${idx}`,
        analysis_run_id: params.analysisRunId,
        entity_ref_id: params.entityRefId,
        risk_id: item.risk_id,
        recommendation_type: item.recommendation_type || 'REMEDIATION',
        title: item.title || `Remediation for Risk ${item.risk_id}`,
        action_steps: item.action_steps || 'Apply defensive schema and policy boundaries.',
        priority: item.priority || 'P1',
        effort_estimate: item.effort_estimate || 'MEDIUM',
        evidence_ids: item.evidence_ids || (params.evidenceList?.[0] ? [params.evidenceList[0].evidence_id] : []),
        created_at: new Date().toISOString(),
      }));

      // Strictly validate AI recommendations
      const validation = RecommendationEngine.validateRecommendations(
        aiGeneratedRecs,
        params.risks,
        params.evidenceList
      );

      if (validation.valid) {
        return aiGeneratedRecs;
      }

      console.warn('AI Recommendations failed deterministic validation, falling back to rule engine:', validation.errors);
      return deterministicBaseline;
    } catch (err) {
      console.warn('Gemini recommendation synthesis error, using deterministic baseline:', err);
      return deterministicBaseline;
    }
  }

  /**
   * Generates AI-assisted use-case evaluations, enforcing exactly 3 positive + 3 negative use cases.
   */
  public static async synthesizeUseCases(params: {
    analysisRunId: string;
    scoreResult: ScoreResult;
    policyDecision: PolicyDecision;
    risks: RiskRecord[];
    evidenceList?: Array<{ evidence_id: string; summary?: string }>;
  }): Promise<UseCaseEvaluationRecord[]> {
    const ai = getAiClient();
    const deterministicBaseline = UseCaseEngine.evaluateUseCases(params);

    if (!ai) {
      return deterministicBaseline;
    }

    try {
      const prompt = `You are an AI Agent enterprise governance engine. Evaluate the agent's suitability across the 6 standard V1 use cases.
Agent overall score: ${params.scoreResult.overall_score}/100 (${params.scoreResult.grade})
Policy outcome: ${params.policyDecision.outcome}
Risks detected: ${params.risks.length}

You must return EXACTLY 3 positive use-case evaluations and EXACTLY 3 negative use-case evaluations matching the V1 profile:
Positive keys: "UC-DEV-ASSIST", "UC-DOC-TRIAGE", "UC-MONITOR-OPS"
Negative keys: "UC-PROD-INFRA", "UC-DB-WRITE", "UC-EXT-DISPATCH"

Respond strictly with valid JSON conforming to the array of 6 items:
[
  {
    "use_case_key": string,
    "title": string,
    "category": "POSITIVE" | "NEGATIVE",
    "suitability": "APPROVED" | "CONDITIONALLY_APPROVED" | "DISAPPROVED",
    "suitability_score": number (0.0 to 1.0),
    "justification": string,
    "evidence_ids": string[]
  }
]`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.7-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
        },
      });

      const text = response.text?.trim();
      if (!text) return deterministicBaseline;

      const parsed = JSON.parse(text) as Array<{
        use_case_key: string;
        title: string;
        category: 'POSITIVE' | 'NEGATIVE';
        suitability: any;
        suitability_score: number;
        justification: string;
        evidence_ids: string[];
      }>;

      const defaultEvidenceId = params.evidenceList?.[0]?.evidence_id || `ev-${params.analysisRunId.substring(0, 8)}`;

      const aiEvaluations: UseCaseEvaluationRecord[] = parsed.map((item, idx) => ({
        evaluation_id: `uceval-ai-${Date.now()}-${idx}`,
        analysis_run_id: params.analysisRunId,
        use_case_key: item.use_case_key,
        title: item.title,
        category: item.category,
        suitability: item.suitability || (item.category === 'POSITIVE' ? 'APPROVED' : 'DISAPPROVED'),
        suitability_score: typeof item.suitability_score === 'number' ? item.suitability_score : (item.category === 'POSITIVE' ? 0.9 : 0.1),
        justification: item.justification || 'Evaluated against security baseline.',
        evidence_ids: item.evidence_ids && item.evidence_ids.length > 0 ? item.evidence_ids : [defaultEvidenceId],
        created_at: new Date().toISOString(),
      }));

      // Strictly validate use cases (mandate exactly 3 positive + 3 negative)
      const validation = UseCaseEngine.validateUseCaseSuite(aiEvaluations, USE_CASE_PROFILE_V1, params.evidenceList);
      if (validation.valid) {
        return aiEvaluations;
      }

      console.warn('AI Use-case evaluations failed validation, falling back to deterministic baseline:', validation.errors);
      return deterministicBaseline;
    } catch (err) {
      console.warn('Gemini use-case synthesis error, using deterministic baseline:', err);
      return deterministicBaseline;
    }
  }
}
