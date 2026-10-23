/**
 * Static vs Dynamic Analysis Comparator (P19)
 * Correlates static AST/CFG/Taint findings against live dynamic runtime events,
 * identifying confirmed predictions, dormant code paths, and runtime evasion divergences.
 */

import { DynamicSandboxRunResult, RuntimeEvent } from './types.ts';
import { StaticFinding, StaticAnalysisReport } from '../static-analysis/types.ts';

export interface StaticDynamicFindingMatch {
  finding_id: string;
  rule_id: string;
  category: string;
  severity: string;
  target?: string;
  static_prediction: string;
  dynamic_evidence: {
    matched_event_ids: string[];
    summary: string;
    events: RuntimeEvent[];
  };
  concordance: 'CONFIRMED' | 'CONTRADICTED' | 'PARTIAL' | 'CONDITIONAL';
  differential_status: 'DYNAMIC_CONFIRMED' | 'DYNAMIC_CONTRADICTED';
}

export interface UntriggeredStaticFinding {
  finding_id: string;
  rule_id: string;
  category: string;
  severity: string;
  target?: string;
  predicted_behavior: string;
  reason_not_triggered: 'DORMANT_BRANCH' | 'EVASION_SUPPRESSED' | 'TEST_INPUT_LIMITED' | 'GUARD_PREVENTED';
  differential_status: 'UNTRIGGERED_STATIC';
}

export interface UnpredictedDynamicBehavior {
  category: string;
  severity: string;
  observed_action: string;
  target?: string;
  event_ids: string[];
  description: string;
  possible_cause: 'DYNAMIC_CODE_EVAL' | 'RUNTIME_EVASION' | 'ENVIRONMENT_AWARENESS' | 'CANARY_HARVEST' | 'UNEXPECTED_EGRESS' | 'UNANALYZED_BEHAVIOR';
  differential_status: 'UNPREDICTED_DYNAMIC';
}

export interface EvasionDivergence {
  evasion_type: string;
  detected_at_runtime: boolean;
  static_risk_prediction: string;
  divergence_detail: string;
}

export interface StaticDynamicComparisonReport {
  comparison_id: string;
  artifact_id: string;
  timestamp: string;
  summary: {
    total_static_findings: number;
    total_dynamic_events: number;
    confirmed_matches_count: number;
    contradicted_matches_count: number;
    untriggered_static_count: number;
    unpredicted_dynamic_count: number;
    evasion_divergences_count: number;
    overall_concordance_rate: number; // 0.0 - 1.0
    risk_assessment_delta: 'ELEVATED_BY_DYNAMIC' | 'CONFIRMED_HIGH' | 'CONCORDANT_BENIGN' | 'INDETERMINATE_EVASION' | 'CONTRADICTED_MITIGATED';
  };
  confirmed_matches: StaticDynamicFindingMatch[];
  contradicted_matches: StaticDynamicFindingMatch[];
  untriggered_static_findings: UntriggeredStaticFinding[];
  unpredicted_dynamic_behaviors: UnpredictedDynamicBehavior[];
  evasion_divergences: EvasionDivergence[];
  narrative_report: string;
}

export class StaticDynamicComparator {
  /**
   * Extracts specific target identifier or domain from a static finding if available.
   */
  private static extractFindingTarget(finding: StaticFinding): string | null {
    if ((finding as any).target && typeof (finding as any).target === 'string') {
      return (finding as any).target.toLowerCase();
    }
    if ((finding as any).metadata?.target && typeof (finding as any).metadata.target === 'string') {
      return (finding as any).metadata.target.toLowerCase();
    }

    const textToScan = `${finding.title || ''} ${finding.description || ''} ${finding.rationale || ''}`;
    // Extract domain or host pattern (e.g. evil-c2.com, 192.168.1.1, /etc/passwd)
    const domainMatch = textToScan.match(/\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9-.]+)\b/);
    if (domainMatch && !domainMatch[1].endsWith('.js') && !domainMatch[1].endsWith('.ts') && !domainMatch[1].endsWith('.json')) {
      return domainMatch[1].toLowerCase();
    }
    const pathMatch = textToScan.match(/(?:\/|\\)[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)*/);
    if (pathMatch) {
      return pathMatch[0].toLowerCase();
    }
    return null;
  }

  /**
   * Compares static analysis findings against dynamic sandbox execution telemetry.
   */
  public static compare(
    staticInput: StaticFinding[] | StaticAnalysisReport,
    dynamicResult: DynamicSandboxRunResult
  ): StaticDynamicComparisonReport {
    const comparisonId = `cmp-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const timestamp = new Date().toISOString();
    const artifactId = dynamicResult.artifact_id || 'unknown-artifact';

    // Anti-spoofing invariant: reject attempted mutation from SIMULATED to OBSERVED
    if (
      (dynamicResult.actual_provider === 'SIMULATED' ||
       dynamicResult.provider_type === 'SIMULATED' ||
       dynamicResult.execution_mode === 'SIMULATED') &&
      dynamicResult.truth_state === 'OBSERVED'
    ) {
      throw new Error("Invalid truth state transition: Cannot promote SIMULATED execution to OBSERVED truth state.");
    }

    const staticFindings: StaticFinding[] = Array.isArray(staticInput) 
      ? staticInput 
      : (staticInput.findings || []);

    const dynamicEvents = dynamicResult.runtime_events || [];
    const confirmedMatches: StaticDynamicFindingMatch[] = [];
    const contradictedMatches: StaticDynamicFindingMatch[] = [];
    const untriggeredFindings: UntriggeredStaticFinding[] = [];
    const matchedEventIds = new Set<string>();

    // 1. Match static findings against dynamic events with specific target & category affinity
    for (const finding of staticFindings) {
      let categoryEvents: RuntimeEvent[] = [];

      switch (finding.category) {
        case 'NETWORK': {
          categoryEvents = dynamicEvents.filter(e => 
            e.action !== 'NETWORK_POLICY_ENFORCED' && (
              e.category === 'NETWORK' || 
              e.action.includes('EGRESS') || 
              e.action.includes('HTTP') ||
              e.action.includes('DNS') ||
              e.action.includes('FETCH')
            )
          );
          break;
        }
        case 'FILESYSTEM': {
          categoryEvents = dynamicEvents.filter(e => 
            e.category === 'FILESYSTEM' || 
            e.action.includes('FILE') || 
            e.action.includes('PERSIST') ||
            e.action.includes('WRITE') ||
            e.action.includes('READ')
          );
          break;
        }
        case 'PROCESS_EXECUTION': {
          categoryEvents = dynamicEvents.filter(e => 
            e.category === 'PROCESS' || 
            e.category === 'TOOL' || 
            e.action.includes('PROCESS') ||
            e.action.includes('EXEC') ||
            e.action.includes('SPAWN')
          );
          break;
        }
        case 'CREDENTIAL_ACCESS': {
          categoryEvents = dynamicEvents.filter(e => 
            e.category === 'CANARY' || 
            e.action.includes('CANARY') || 
            e.action.includes('KEY') ||
            e.action.includes('SECRET') ||
            e.action.includes('TOKEN')
          );
          break;
        }
        case 'CONTROL_FLOW_ANOMALY':
        case 'UNSUPPORTED_SYNTAX': {
          categoryEvents = dynamicEvents.filter(e => 
            e.category === 'SECURITY' || 
            e.category === 'ENVIRONMENT' || 
            e.action.includes('EVASION') || 
            e.action.includes('FINGERPRINT') ||
            e.action.includes('DELAY')
          );
          break;
        }
        default: {
          categoryEvents = dynamicEvents.filter(e => 
            e.category === 'SECURITY' || 
            e.status === 'FLAGGED'
          );
          break;
        }
      }

      const findingTarget = this.extractFindingTarget(finding);
      let relevantEvents: RuntimeEvent[] = [];

      if (findingTarget) {
        // Precise target matching: only match events that reference the finding's target or rule
        relevantEvents = categoryEvents.filter(e => {
          const evTarget = (e.target || '').toLowerCase();
          const evMetaTarget = ((e.metadata?.target as string) || '').toLowerCase();
          const evMetaRule = e.metadata?.rule_id;
          return evTarget.includes(findingTarget) || 
                 findingTarget.includes(evTarget) || 
                 evMetaTarget.includes(findingTarget) ||
                 evMetaRule === finding.rule_id;
        });
      } else {
        // If no explicit target specified, match by category/rule affinity
        relevantEvents = categoryEvents.filter(e => {
          if (e.metadata?.rule_id && e.metadata.rule_id === finding.rule_id) {
            return true;
          }
          // If the event has a specific target, but other findings might match it better,
          // check if this finding's category matches
          return true;
        });
      }

      if (relevantEvents.length > 0) {
        for (const ev of relevantEvents) {
          matchedEventIds.add(ev.event_id);
        }

        // Determine if dynamic execution contradicted the static risk prediction
        // e.g. Static predicted unrestricted egress/vulnerability, but dynamic showed BLOCKED / DENIED by policy
        const isContradicted = relevantEvents.some(e => 
          (e.status as string) === 'BLOCKED' || 
          e.action === 'EGRESS_BLOCKED' || 
          e.action === 'DNS_BLOCKED' ||
          e.action.includes('BLOCKED') || 
          e.action.includes('DENIED') || 
          e.metadata?.policy_enforced === true ||
          e.metadata?.blocked === true ||
          e.metadata?.contradiction === true
        );

        if (isContradicted) {
          const matchItem: StaticDynamicFindingMatch = {
            finding_id: finding.finding_id,
            rule_id: finding.rule_id,
            category: finding.category,
            severity: finding.severity,
            target: findingTarget || undefined,
            static_prediction: finding.title || finding.description,
            dynamic_evidence: {
              matched_event_ids: relevantEvents.map(e => e.event_id),
              summary: `Dynamic execution contradicted static risk prediction: action(s) actively BLOCKED or neutralized by runtime security policy.`,
              events: relevantEvents,
            },
            concordance: 'CONTRADICTED',
            differential_status: 'DYNAMIC_CONTRADICTED',
          };
          contradictedMatches.push(matchItem);
          confirmedMatches.push(matchItem);
        } else {
          const matchItem: StaticDynamicFindingMatch = {
            finding_id: finding.finding_id,
            rule_id: finding.rule_id,
            category: finding.category,
            severity: finding.severity,
            target: findingTarget || undefined,
            static_prediction: finding.title || finding.description,
            dynamic_evidence: {
              matched_event_ids: relevantEvents.map(e => e.event_id),
              summary: `Observed ${relevantEvents.length} runtime event(s) in category ${finding.category} confirming static hypothesis.`,
              events: relevantEvents,
            },
            concordance: 'CONFIRMED',
            differential_status: 'DYNAMIC_CONFIRMED',
          };
          confirmedMatches.push(matchItem);
        }
      } else {
        const isEvasionDetected = dynamicResult.anti_analysis_detected || dynamicResult.evasion_risk_score > 0.5;
        untriggeredFindings.push({
          finding_id: finding.finding_id,
          rule_id: finding.rule_id,
          category: finding.category,
          severity: finding.severity,
          target: findingTarget || undefined,
          predicted_behavior: finding.title || finding.description,
          reason_not_triggered: isEvasionDetected ? 'EVASION_SUPPRESSED' : 'DORMANT_BRANCH',
          differential_status: 'UNTRIGGERED_STATIC',
        });
      }
    }

    // 2. Identify unpredicted dynamic behaviors (events not tied to static findings)
    const unpredictedDynamic: UnpredictedDynamicBehavior[] = [];
    const significantUnmatchedEvents = dynamicEvents.filter(e => 
      !matchedEventIds.has(e.event_id) && 
      (e.severity === 'HIGH' || e.severity === 'CRITICAL' || e.status === 'FLAGGED' || e.category === 'CANARY' || e.action.includes('UNEXPECTED') || e.action.includes('EGRESS') || e.action.includes('EXEC'))
    );

    for (const unpredEv of significantUnmatchedEvents) {
      let cause: UnpredictedDynamicBehavior['possible_cause'] = 'RUNTIME_EVASION';
      if (unpredEv.category === 'CANARY') cause = 'CANARY_HARVEST';
      else if (unpredEv.category === 'ENVIRONMENT') cause = 'ENVIRONMENT_AWARENESS';
      else if (unpredEv.action.includes('FUZZ') || unpredEv.action.includes('EVAL')) cause = 'DYNAMIC_CODE_EVAL';
      else if (unpredEv.category === 'NETWORK' || unpredEv.action.includes('EGRESS')) cause = 'UNEXPECTED_EGRESS';
      else cause = 'UNANALYZED_BEHAVIOR';

      unpredictedDynamic.push({
        category: unpredEv.category,
        severity: unpredEv.severity,
        observed_action: unpredEv.action,
        target: unpredEv.target,
        event_ids: [unpredEv.event_id],
        description: `Runtime action '${unpredEv.action}' on target '${unpredEv.target}' was not predicted by static AST analysis.`,
        possible_cause: cause,
        differential_status: 'UNPREDICTED_DYNAMIC',
      });
    }

    // 3. Evaluate evasion divergences
    const evasionDivergences: EvasionDivergence[] = [];
    const hasStaticEvasionWarning = staticFindings.some(f => f.category === 'CONTROL_FLOW_ANOMALY' || f.rule_id.includes('EVASION'));

    for (const indicator of dynamicResult.evasion_indicators || []) {
      if (indicator.detected) {
        evasionDivergences.push({
          evasion_type: indicator.type,
          detected_at_runtime: true,
          static_risk_prediction: hasStaticEvasionWarning ? 'STATIC_FLAGGED' : 'STATIC_MISSED',
          divergence_detail: `Dynamic sandbox observed '${indicator.name}' with confidence ${indicator.confidence.toFixed(2)}. ${indicator.description}`,
        });
      }
    }

    // 4. Compute Concordance & Risk Assessment Delta
    const totalStatic = staticFindings.length;
    const totalDynamic = dynamicEvents.length;
    const confirmedCount = confirmedMatches.filter(m => m.concordance === 'CONFIRMED').length;
    const contradictedCount = contradictedMatches.length;
    const untriggeredCount = untriggeredFindings.length;
    const unpredictedCount = unpredictedDynamic.length;
    const evasionCount = evasionDivergences.length;

    const concordanceRate = totalStatic > 0 
      ? Math.round((confirmedCount / totalStatic) * 100) / 100 
      : (unpredictedCount === 0 ? 1.0 : 0.0);

    let riskAssessmentDelta: StaticDynamicComparisonReport['summary']['risk_assessment_delta'] = 'CONCORDANT_BENIGN';
    if (evasionCount > 0 && dynamicResult.evasion_risk_score >= 0.7) {
      riskAssessmentDelta = 'INDETERMINATE_EVASION';
    } else if (unpredictedCount > 0 || (dynamicResult.canaries_tripped && dynamicResult.canaries_tripped.length > 0)) {
      riskAssessmentDelta = 'ELEVATED_BY_DYNAMIC';
    } else if (confirmedCount > 0 && staticFindings.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')) {
      riskAssessmentDelta = 'CONFIRMED_HIGH';
    } else if (contradictedCount > 0 && confirmedCount === 0 && unpredictedCount === 0) {
      riskAssessmentDelta = 'CONTRADICTED_MITIGATED';
    }

    // 5. Generate human-readable narrative report
    const narrativeLines: string[] = [
      `=== Static vs Dynamic Analysis Correlation Report ===`,
      `Artifact ID: ${artifactId} | Comparison ID: ${comparisonId}`,
      `Execution Mode: ${dynamicResult.provider_type || 'SIMULATED'} (Session: ${dynamicResult.session_id || 'none'})`,
      `Outcome: ${riskAssessmentDelta} (Concordance Rate: ${(concordanceRate * 100).toFixed(1)}%)`,
      ``,
      `[1. Static Predictions vs Dynamic Confirmation]`,
      `  - Total Static Findings: ${totalStatic}`,
      `  - Confirmed at Runtime: ${confirmedCount}`,
      `  - Contradicted at Runtime: ${contradictedCount}`,
      `  - Untriggered/Dormant: ${untriggeredCount}`,
    ];

    if (confirmedMatches.length > 0) {
      narrativeLines.push(`  Findings Analyzed:`);
      for (const m of confirmedMatches) {
        narrativeLines.push(`    * [${m.category}] Rule ${m.rule_id} (${m.severity}) [${m.differential_status}]: "${m.static_prediction}" -> ${m.dynamic_evidence.summary}`);
      }
    }

    if (untriggeredFindings.length > 0) {
      narrativeLines.push(`  Untriggered Static Findings:`);
      for (const u of untriggeredFindings) {
        narrativeLines.push(`    * [${u.category}] Rule ${u.rule_id}: "${u.predicted_behavior}" (Reason: ${u.reason_not_triggered})`);
      }
    }

    narrativeLines.push(``, `[2. Dynamic Anomalies Not Predicted Statically]`);
    if (unpredictedDynamic.length === 0) {
      narrativeLines.push(`  - None. All observed high-severity runtime behaviors were accounted for by static AST findings.`);
    } else {
      for (const u of unpredictedDynamic) {
        narrativeLines.push(`  * [${u.category}] Action: ${u.observed_action} (${u.severity}) -> Cause: ${u.possible_cause}. ${u.description}`);
      }
    }

    narrativeLines.push(``, `[3. Evasion & Anti-Analysis Discrepancies]`);
    if (evasionDivergences.length === 0) {
      narrativeLines.push(`  - No runtime evasion anomalies detected.`);
    } else {
      for (const ed of evasionDivergences) {
        narrativeLines.push(`  * Type: ${ed.evasion_type} (Static Prediction: ${ed.static_risk_prediction}) -> ${ed.divergence_detail}`);
      }
    }

    const narrativeReport = narrativeLines.join('\n');

    return {
      comparison_id: comparisonId,
      artifact_id: artifactId,
      timestamp,
      summary: {
        total_static_findings: totalStatic,
        total_dynamic_events: totalDynamic,
        confirmed_matches_count: confirmedCount,
        contradicted_matches_count: contradictedCount,
        untriggered_static_count: untriggeredCount,
        unpredicted_dynamic_count: unpredictedCount,
        evasion_divergences_count: evasionCount,
        overall_concordance_rate: concordanceRate,
        risk_assessment_delta: riskAssessmentDelta,
      },
      confirmed_matches: confirmedMatches,
      contradicted_matches: contradictedMatches,
      untriggered_static_findings: untriggeredFindings,
      unpredicted_dynamic_behaviors: unpredictedDynamic,
      evasion_divergences: evasionDivergences,
      narrative_report: narrativeReport,
    };
  }
}
