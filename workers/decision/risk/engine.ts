/**
 * Risk Engine (Architecture V2.0.1)
 * Evaluates observations, findings, runtime telemetry, and taint flows into structured RiskRecords
 * with deterministic likelihood, impact, severity, and evidence links.
 */

import { RiskRecord, RiskEvidenceLink, RiskSeverity, DynamicFindingMatch, RiskVerificationStatus } from '../types.ts';
import { RISK_TAXONOMY_V1 } from './rules.ts';

export interface RiskEvaluationInput {
  analysisRunId: string;
  entityRefId?: string;
  findings?: Array<{
    finding_id?: string;
    rule_id?: string;
    finding_type?: string;
    category?: string;
    severity?: string;
    title?: string;
    description?: string;
    confidence?: number;
    evidence_ids?: string[];
  }>;
  staticFindings?: Array<{
    finding_id?: string;
    rule_id?: string;
    finding_type?: string;
    category?: string;
    severity?: string;
    title?: string;
    description?: string;
    confidence?: number;
    evidence_ids?: string[];
  }>;
  dynamicFindings?: DynamicFindingMatch[];
  taintFlows?: Array<{
    flow_id?: string;
    source_type?: string;
    sink_type?: string;
    severity?: string;
    evidence_id?: string;
  }>;
  runtimeEvents?: Array<{
    event_id?: string;
    event_type?: string;
    severity?: string;
    details?: string;
    evidence_id?: string;
  }>;
  dynamicEvents?: Array<{
    event_id?: string;
    event_type?: string;
    severity?: string;
    details?: string;
    evidence_id?: string;
  }>;
  canariesTripped?: Array<{
    canary_id?: string;
    name?: string;
    location?: string;
    tripped_timestamp?: string;
    evidence_id?: string;
  }>;
  reachableCVEs?: Array<{
    package_name?: string;
    cve_id?: string;
    severity?: string;
    evidence_id?: string;
  }>;
  evidenceList?: Array<{
    evidence_id: string;
    evidence_type?: string;
    summary?: string;
  }>;
}

export class RiskEngine {
  /**
   * Evaluates all input artifacts into normalized, evidence-linked RiskRecords.
   */
  public static evaluateRisks(input: RiskEvaluationInput): RiskRecord[] {
    const risks: RiskRecord[] = [];
    const runId = input.analysisRunId;
    const entityRefId = input.entityRefId;

    const allFindings = [...(input.findings || []), ...(input.staticFindings || [])];
    const allRuntimeEvents = [...(input.runtimeEvents || []), ...(input.dynamicEvents || [])];

    // 1. Canaries Tripped (Critical)
    if (input.canariesTripped && input.canariesTripped.length > 0) {
      for (const canary of input.canariesTripped) {
        const rule = RISK_TAXONOMY_V1.CANARY_HONEYTOKEN_LEAK;
        const evidenceLinks: RiskEvidenceLink[] = [];
        if (canary.evidence_id) {
          evidenceLinks.push({ evidence_id: canary.evidence_id, relevance_score: 1.0, notes: 'Direct canary exfiltration telemetry' });
        } else if (input.evidenceList && input.evidenceList.length > 0) {
          evidenceLinks.push({ evidence_id: input.evidenceList[0].evidence_id, relevance_score: 0.9, notes: 'Associated runtime trace' });
        }

        risks.push({
          risk_id: `risk-canary-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          analysis_run_id: runId,
          entity_ref_id: entityRefId,
          risk_type: rule.category,
          title: `${rule.title_template} (${canary.name || canary.location || 'Synthetic Secret'})`,
          description: rule.description_template,
          severity: rule.severity,
          likelihood: rule.base_likelihood,
          impact: rule.base_impact,
          risk_score: parseFloat((rule.base_likelihood * rule.base_impact).toFixed(4)),
          mitigated: false,
          remediation_guidance: rule.remediation_template,
          evidence_links: evidenceLinks,
          created_at: new Date().toISOString(),
        });
      }
    }

    // 2. Taint Flows (Injection Sinks)
    if (input.taintFlows && input.taintFlows.length > 0) {
      for (const flow of input.taintFlows) {
        let rule = RISK_TAXONOMY_V1.CODE_INJECTION_SINK;
        if (flow.sink_type === 'COMMAND_INJECTION' || flow.sink_type === 'EXEC_COMMAND') {
          rule = RISK_TAXONOMY_V1.COMMAND_INJECTION_SINK;
        } else if (flow.sink_type === 'FILE_SYSTEM' || flow.sink_type === 'PATH_TRAVERSAL') {
          rule = RISK_TAXONOMY_V1.PATH_TRAVERSAL;
        }

        const evidenceLinks: RiskEvidenceLink[] = [];
        if (flow.evidence_id) {
          evidenceLinks.push({ evidence_id: flow.evidence_id, relevance_score: 0.95, notes: `Taint path to ${flow.sink_type}` });
        } else if (input.evidenceList && input.evidenceList.length > 0) {
          evidenceLinks.push({ evidence_id: input.evidenceList[0].evidence_id, relevance_score: 0.85, notes: 'Dataflow trace evidence' });
        }

        risks.push({
          risk_id: `risk-taint-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`,
          analysis_run_id: runId,
          entity_ref_id: entityRefId,
          risk_type: rule.category,
          title: `${rule.title_template} [${flow.source_type || 'SOURCE'} -> ${flow.sink_type || 'SINK'}]`,
          description: rule.description_template,
          severity: rule.severity,
          likelihood: rule.base_likelihood,
          impact: rule.base_impact,
          risk_score: parseFloat((rule.base_likelihood * rule.base_impact).toFixed(4)),
          mitigated: false,
          remediation_guidance: rule.remediation_template,
          evidence_links: evidenceLinks,
          created_at: new Date().toISOString(),
        });
      }
    }

    // 3. Runtime Events (Egress violations & Evasion)
    if (allRuntimeEvents.length > 0) {
      for (const event of allRuntimeEvents) {
        if (event.event_type === 'NETWORK_EGRESS_BLOCKED' || event.event_type === 'EGRESS_VIOLATION') {
          const rule = RISK_TAXONOMY_V1.EGRESS_POLICY_VIOLATION;
          const evidenceLinks: RiskEvidenceLink[] = [];
          if (event.evidence_id) {
            evidenceLinks.push({ evidence_id: event.evidence_id, relevance_score: 0.95, notes: 'Egress monitor violation event' });
          }

          risks.push({
            risk_id: `risk-egress-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`,
            analysis_run_id: runId,
            entity_ref_id: entityRefId,
            risk_type: rule.category,
            title: rule.title_template,
            description: event.details || rule.description_template,
            severity: rule.severity,
            likelihood: rule.base_likelihood,
            impact: rule.base_impact,
            risk_score: parseFloat((rule.base_likelihood * rule.base_impact).toFixed(4)),
            mitigated: false,
            remediation_guidance: rule.remediation_template,
            evidence_links: evidenceLinks,
            created_at: new Date().toISOString(),
          });
        } else if (event.event_type === 'EVASION_PROBE' || event.event_type === 'ANTI_ANALYSIS') {
          const rule = RISK_TAXONOMY_V1.SANDBOX_EVASION_BEHAVIOR;
          const evidenceLinks: RiskEvidenceLink[] = [];
          if (event.evidence_id) {
            evidenceLinks.push({ evidence_id: event.evidence_id, relevance_score: 0.9, notes: 'Anti-analysis trigger trace' });
          }

          risks.push({
            risk_id: `risk-evasion-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`,
            analysis_run_id: runId,
            entity_ref_id: entityRefId,
            risk_type: rule.category,
            title: rule.title_template,
            description: event.details || rule.description_template,
            severity: rule.severity,
            likelihood: rule.base_likelihood,
            impact: rule.base_impact,
            risk_score: parseFloat((rule.base_likelihood * rule.base_impact).toFixed(4)),
            mitigated: false,
            remediation_guidance: rule.remediation_template,
            evidence_links: evidenceLinks,
            created_at: new Date().toISOString(),
          });
        }
      }
    }

    // 4. Reachable CVE Dependencies
    if (input.reachableCVEs && input.reachableCVEs.length > 0) {
      for (const cve of input.reachableCVEs) {
        const rule = RISK_TAXONOMY_V1.REACHABLE_CVE_DEPENDENCY;
        const evidenceLinks: RiskEvidenceLink[] = [];
        if (cve.evidence_id) {
          evidenceLinks.push({ evidence_id: cve.evidence_id, relevance_score: 0.9, notes: `Callgraph reachability proof for ${cve.cve_id}` });
        }

        risks.push({
          risk_id: `risk-cve-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`,
          analysis_run_id: runId,
          entity_ref_id: entityRefId,
          risk_type: rule.category,
          title: `${rule.title_template} (${cve.package_name || 'dependency'} / ${cve.cve_id || 'CVE'})`,
          description: rule.description_template,
          severity: (cve.severity as RiskSeverity) || rule.severity,
          likelihood: rule.base_likelihood,
          impact: rule.base_impact,
          risk_score: parseFloat((rule.base_likelihood * rule.base_impact).toFixed(4)),
          mitigated: false,
          remediation_guidance: rule.remediation_template,
          evidence_links: evidenceLinks,
          created_at: new Date().toISOString(),
        });
      }
    }

    // 5. Static AST Findings
    if (allFindings.length > 0) {
      for (const f of allFindings) {
        let rule = RISK_TAXONOMY_V1.MISSING_INPUT_VALIDATION;
        if (f.finding_type === 'HARDCODED_SECRET' || f.category === 'CREDENTIAL_ACCESS' || f.rule_id?.includes('CRED')) {
          rule = RISK_TAXONOMY_V1.HARDCODED_API_KEY;
        } else if (f.finding_type === 'DANGEROUS_EVAL' || f.category === 'PROCESS_EXECUTION' || f.rule_id?.includes('PROC') || f.rule_id?.includes('SQLI')) {
          rule = (f.rule_id?.includes('PROC-001') || f.rule_id?.includes('PROC-002') || f.rule_id?.includes('SQLI')) 
            ? RISK_TAXONOMY_V1.COMMAND_INJECTION_SINK 
            : RISK_TAXONOMY_V1.CODE_INJECTION_SINK;
        } else if (f.category === 'NETWORK' || f.rule_id?.includes('NET')) {
          rule = RISK_TAXONOMY_V1.EGRESS_POLICY_VIOLATION;
        } else if (f.category === 'FILESYSTEM' && (f.severity === 'CRITICAL' || f.rule_id?.includes('FS-001'))) {
          rule = RISK_TAXONOMY_V1.PATH_TRAVERSAL;
        } else if (f.finding_type === 'PROMPT_INJECTION' || f.category === 'PROMPT_INJECTION') {
          rule = RISK_TAXONOMY_V1.PROMPT_INJECTION_VULNERABILITY;
        } else if (f.finding_type === 'AMBIGUOUS_SPEC') {
          rule = RISK_TAXONOMY_V1.AMBIGUOUS_SPECIFICATION;
        }

        const evidenceLinks: RiskEvidenceLink[] = [];
        if (f.evidence_ids && f.evidence_ids.length > 0) {
          for (const eid of f.evidence_ids) {
            evidenceLinks.push({ evidence_id: eid, relevance_score: 0.85, notes: 'Static AST finding evidence' });
          }
        } else if (input.evidenceList && input.evidenceList.length > 0) {
          evidenceLinks.push({ evidence_id: input.evidenceList[0].evidence_id, relevance_score: 0.85, notes: 'Linked static evidence' });
        }

        // Match with dynamicFindings if available
        let verificationStatus: 'STATIC_ONLY' | 'DYNAMIC_CONFIRMED' | 'DYNAMIC_CONTRADICTED' | 'DYNAMIC_UNREPRODUCED' = 'STATIC_ONLY';
        let dynamicCtx: RiskRecord['dynamic_context'] = undefined;
        let finalLikelihood = rule.base_likelihood;
        let finalImpact = rule.base_impact;

        if (input.dynamicFindings && input.dynamicFindings.length > 0) {
          const matchedDyn = input.dynamicFindings.find(
            d => (f.finding_id && d.finding_id === f.finding_id) ||
                 (f.rule_id && d.rule_id === f.rule_id) ||
                 (f.category && d.category === f.category)
          );

          if (matchedDyn) {
            if (matchedDyn.concordance === 'CONFIRMED') {
              verificationStatus = 'DYNAMIC_CONFIRMED';
              finalLikelihood = Math.min(1.0, parseFloat((rule.base_likelihood * 1.25).toFixed(4)));
              finalImpact = Math.min(1.0, parseFloat((rule.base_impact * 1.15).toFixed(4)));
            } else if (matchedDyn.concordance === 'CONTRADICTED') {
              verificationStatus = 'DYNAMIC_CONTRADICTED';
              finalLikelihood = Math.max(0.1, parseFloat((rule.base_likelihood * 0.4).toFixed(4)));
            } else if (matchedDyn.concordance === 'UNREPRODUCED') {
              verificationStatus = 'DYNAMIC_UNREPRODUCED';
              finalLikelihood = Math.max(0.2, parseFloat((rule.base_likelihood * 0.7).toFixed(4)));
            }

            dynamicCtx = {
              concordance: matchedDyn.concordance,
              summary: matchedDyn.dynamic_evidence.summary || matchedDyn.notes || `Dynamic verification: ${matchedDyn.concordance}`,
              syscalls: matchedDyn.dynamic_evidence.syscalls,
              network_egress_attempted: matchedDyn.dynamic_evidence.network_egress_attempted,
              filesystem_access: matchedDyn.dynamic_evidence.filesystem_access,
              exit_code: matchedDyn.dynamic_evidence.exit_code,
            };

            if (matchedDyn.dynamic_evidence.matched_event_ids && matchedDyn.dynamic_evidence.matched_event_ids.length > 0) {
              for (const evId of matchedDyn.dynamic_evidence.matched_event_ids) {
                evidenceLinks.push({
                  evidence_id: evId,
                  relevance_score: 1.0,
                  notes: matchedDyn.notes || `Dynamic sandbox trace (${matchedDyn.concordance})`,
                });
              }
            }
          }
        }

        risks.push({
          risk_id: `risk-finding-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`,
          analysis_run_id: runId,
          entity_ref_id: entityRefId,
          rule_id: f.rule_id,
          risk_type: rule.category,
          title: f.title || rule.title_template,
          description: f.description || rule.description_template,
          severity: (f.severity as RiskSeverity) || rule.severity,
          likelihood: finalLikelihood,
          impact: finalImpact,
          risk_score: parseFloat((finalLikelihood * finalImpact).toFixed(4)),
          mitigated: false,
          verification_status: verificationStatus,
          dynamic_context: dynamicCtx,
          remediation_guidance: rule.remediation_template,
          evidence_links: evidenceLinks,
          created_at: new Date().toISOString(),
        });
      }
    }

    return risks;
  }
}
