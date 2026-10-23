import crypto from 'crypto';
import { 
  KnowledgeObjectType, 
  KnowledgeProjection 
} from '../types.ts';
import { 
  SecurityClassificationCode, 
  SecurityClassificationRank,
  CLASSIFICATION_CODE_TO_RANK,
} from '@caim/auth/types.ts';

export const CURRENT_PROJECTION_VERSION = 'proj-2026.08.v1';

export interface RawEntityContext {
  agent_id?: string | null;
  agent_version_id?: string | null;
  analysis_run_id?: string | null;
  security_classification?: SecurityClassificationCode;
  projection_version?: string;
}

export function computeSha256(data: any): string {
  const serialized = typeof data === 'string' ? data : JSON.stringify(data, Object.keys(data).sort());
  return crypto.createHash('sha256').update(serialized).digest('hex');
}

/**
 * Universal projection builder interface for all authoritative entity types.
 */
export class ProjectionBuilderRegistry {
  public static buildProjection(
    objectType: KnowledgeObjectType,
    entityRefId: string,
    rawEntity: Record<string, any>,
    context: RawEntityContext = {}
  ): KnowledgeProjection {
    const projectionVersion = context.projection_version || CURRENT_PROJECTION_VERSION;
    const classification = context.security_classification || rawEntity.security_classification || 'INTERNAL';
    const rank = CLASSIFICATION_CODE_TO_RANK[classification] ?? SecurityClassificationRank.INTERNAL;
    const isVault = classification === 'VAULT_RESTRICTED' || rawEntity.is_vault === true;

    let docText = '';
    let summary = '';
    let exactKeywords: Record<string, any> = {
      object_type: objectType,
      entity_ref_id: entityRefId,
      classification,
    };

    switch (objectType) {
      case 'agent': {
        const name = rawEntity.name || rawEntity.agent_name || 'Unnamed Agent';
        const ns = rawEntity.namespace || 'default';
        const desc = rawEntity.description || 'No description provided';
        const vendor = rawEntity.vendor || 'Unknown Vendor';
        const framework = rawEntity.framework || 'Custom';
        const capabilities = Array.isArray(rawEntity.capabilities) ? rawEntity.capabilities.join(', ') : '';

        docText = `[OBJECT: AGENT]
Name: ${name}
Namespace: ${ns}
Vendor: ${vendor}
Framework: ${framework}
Description: ${desc}
Capabilities: ${capabilities}
Architecture: ${rawEntity.architecture_tier || 'Micro-Agent'}`;

        summary = `Agent ${ns}/${name} by ${vendor} (${framework}). Capabilities: ${capabilities || 'None'}.`;
        exactKeywords = {
          ...exactKeywords,
          agent_name: name,
          namespace: ns,
          vendor,
          framework,
          agent_id: rawEntity.agent_id || context.agent_id,
          risk_band: rawEntity.risk_band || rawEntity.risk_level || 'LOW_RISK',
          lifecycle_status: rawEntity.lifecycle_status || rawEntity.status || rawEntity.lifecycle_state || 'APPROVED',
          lifecycle_state: rawEntity.lifecycle_state || rawEntity.lifecycle_status || rawEntity.status || 'APPROVED',
        };
        break;
      }

      case 'version': {
        const verNumber = rawEntity.version_number || rawEntity.semver || '1.0.0';
        const tag = rawEntity.version_tag || 'latest';
        const gitCommit = rawEntity.git_commit_sha || '0000000';
        const status = rawEntity.lifecycle_state || rawEntity.lifecycle_status || rawEntity.status || 'APPROVED';
        const notes = rawEntity.release_notes || 'Initial registration';
        const hash = rawEntity.integrity_hash || computeSha256(rawEntity);

        docText = `[OBJECT: AGENT_VERSION]
Version Number: ${verNumber} (Tag: ${tag})
Lifecycle State: ${status}
Git Commit: ${gitCommit}
Integrity Hash: ${hash}
Release Notes: ${notes}`;

        summary = `Version ${verNumber} (${status}) @ commit ${gitCommit.substring(0, 7)}. Notes: ${notes}`;
        exactKeywords = {
          ...exactKeywords,
          version_number: verNumber,
          version_tag: tag,
          lifecycle_state: status,
          lifecycle_status: status,
          risk_band: rawEntity.risk_band || rawEntity.risk_level || 'LOW_RISK',
          git_commit: gitCommit,
          integrity_hash: hash,
        };
        break;
      }

      case 'run': {
        const runId = rawEntity.analysis_run_id || rawEntity.run_id || entityRefId;
        const runType = rawEntity.run_type || 'STATIC_AND_BEHAVIORAL';
        const status = rawEntity.status || 'COMPLETED';
        const conf = rawEntity.confidence_score !== undefined ? rawEntity.confidence_score : 1.0;
        const duration = rawEntity.duration_ms || rawEntity.execution_time_ms || 0;

        docText = `[OBJECT: ANALYSIS_RUN]
Run ID: ${runId}
Run Type: ${runType}
Status: ${status}
Confidence Score: ${conf}
Duration: ${duration}ms
Trigger: ${rawEntity.trigger_source || 'MANUAL_DISPATCH'}`;

        summary = `Analysis Run ${runId} (${runType}) finished ${status} with confidence ${conf}.`;
        exactKeywords = {
          ...exactKeywords,
          run_id: runId,
          run_type: runType,
          status,
          confidence: conf,
        };
        break;
      }

      case 'finding': {
        const ruleId = rawEntity.rule_id || 'RULE-UNKNOWN';
        const title = rawEntity.title || 'Security/Quality Finding';
        const cat = rawEntity.category || 'VULNERABILITY';
        const sev = rawEntity.severity || 'MEDIUM';
        const file = rawEntity.file_path || rawEntity.location || 'unknown';
        const line = rawEntity.line_number || rawEntity.line || 1;
        const snippet = rawEntity.code_snippet || rawEntity.snippet || '';

        docText = `[OBJECT: FINDING]
Rule ID: ${ruleId}
Title: ${title}
Category: ${cat}
Severity: ${sev}
Location: ${file}:${line}
Code Snippet:
${snippet}
Remediation: ${rawEntity.remediation_advice || rawEntity.recommendation || 'Review code structure'}`;

        summary = `[${sev}] ${title} (${ruleId}) at ${file}:${line}`;
        exactKeywords = {
          ...exactKeywords,
          rule_id: ruleId,
          category: cat,
          severity: sev,
          file_path: file,
          line_number: line,
        };
        break;
      }

      case 'evidence': {
        const evId = rawEntity.evidence_id || entityRefId;
        const evType = rawEntity.evidence_type || 'STATIC_CODE';
        const evClass = rawEntity.evidence_class || 'DIRECT_OBSERVATION';
        const epistemic = rawEntity.epistemic_state || 'OBSERVED_FACT';
        const locator = rawEntity.source_locator || 'repository/ast';
        const conf = rawEntity.confidence !== undefined ? rawEntity.confidence : 1.0;

        docText = `[OBJECT: EVIDENCE]
Evidence ID: ${evId}
Type: ${evType}
Class: ${evClass}
Epistemic State: ${epistemic}
Confidence: ${conf}
Locator: ${locator}
Observation: ${rawEntity.observation || rawEntity.summary || ''}`;

        summary = `Evidence ${evId}: ${epistemic} ${evType} [${evClass}] with confidence ${conf}`;
        exactKeywords = {
          ...exactKeywords,
          evidence_id: evId,
          evidence_type: evType,
          evidence_class: evClass,
          epistemic_state: epistemic,
          source_locator: locator,
        };
        break;
      }

      case 'claim': {
        const claimId = rawEntity.claim_id || entityRefId;
        const claimType = rawEntity.claim_type || 'SECURITY_POSTURE';
        const state = rawEntity.claim_state || 'SUPPORTED';
        const stmt = rawEntity.statement || rawEntity.claim_text || 'No assertion statement';
        const conf = rawEntity.confidence || 0.9;

        docText = `[OBJECT: CLAIM]
Claim ID: ${claimId}
Type: ${claimType}
State: ${state}
Confidence: ${conf}
Statement: ${stmt}
Supporting Evidence Count: ${rawEntity.evidence_links?.length || 0}`;

        summary = `Claim ${claimId} (${claimType} - ${state}): "${stmt}"`;
        exactKeywords = {
          ...exactKeywords,
          claim_id: claimId,
          claim_type: claimType,
          claim_state: state,
        };
        break;
      }

      case 'risk': {
        const riskId = rawEntity.risk_id || entityRefId;
        const riskType = rawEntity.risk_type || 'SECURITY_VULNERABILITY';
        const sev = rawEntity.severity || 'MEDIUM';
        const title = rawEntity.title || 'Risk Finding';
        const score = rawEntity.risk_score || 0.5;
        const desc = rawEntity.description || '';

        docText = `[OBJECT: RISK]
Risk ID: ${riskId}
Type: ${riskType}
Severity: ${sev}
Score: ${score}
Title: ${title}
Description: ${desc}
Mitigated: ${rawEntity.mitigated ? 'YES' : 'NO'}`;

        summary = `Risk [${sev}] ${title} (Score: ${score}): ${desc}`;
        exactKeywords = {
          ...exactKeywords,
          risk_id: riskId,
          risk_type: riskType,
          severity: sev,
          risk_score: score,
        };
        break;
      }

      case 'policy': {
        const policyKey = rawEntity.policy_key || rawEntity.rule_key || 'POL-DEFAULT';
        const outcome = rawEntity.outcome || rawEntity.verdict || 'REQUIRE_REVIEW';
        const reasons = Array.isArray(rawEntity.reasons) ? rawEntity.reasons.join('; ') : (rawEntity.reason || '');
        const override = rawEntity.override_applied ? 'YES' : 'NO';

        docText = `[OBJECT: POLICY_DECISION]
Policy Key: ${policyKey}
Outcome: ${outcome}
Override Applied: ${override}
Decision Reasons:
${reasons}`;

        summary = `Policy ${policyKey} -> ${outcome}. Reasons: ${reasons}`;
        exactKeywords = {
          ...exactKeywords,
          policy_key: policyKey,
          outcome,
          override_applied: rawEntity.override_applied || false,
        };
        break;
      }

      case 'recommendation': {
        const recId = rawEntity.recommendation_id || entityRefId;
        const priority = rawEntity.priority || 'P1';
        const recType = rawEntity.recommendation_type || 'REMEDIATION';
        const title = rawEntity.title || 'Fix recommendation';
        const steps = Array.isArray(rawEntity.action_steps) ? rawEntity.action_steps.join('\n- ') : (rawEntity.description || '');

        docText = `[OBJECT: RECOMMENDATION]
Recommendation ID: ${recId}
Priority: ${priority}
Type: ${recType}
Title: ${title}
Target Risk: ${rawEntity.risk_id || 'N/A'}
Action Steps:
- ${steps}`;

        summary = `[${priority}] ${title} (${recType})`;
        exactKeywords = {
          ...exactKeywords,
          recommendation_id: recId,
          priority,
          recommendation_type: recType,
          risk_id: rawEntity.risk_id,
        };
        break;
      }

      case 'use_case': {
        const ucId = rawEntity.use_case_id || entityRefId;
        const category = rawEntity.category || 'POSITIVE';
        const title = rawEntity.title || 'Use Case Scenario';
        const suitability = rawEntity.suitability || 'APPROVED';
        const rationale = rawEntity.rationale || '';

        docText = `[OBJECT: USE_CASE]
Use Case ID: ${ucId}
Category: ${category}
Suitability: ${suitability}
Title: ${title}
Rationale: ${rationale}
Constraints: ${Array.isArray(rawEntity.constraints) ? rawEntity.constraints.join(', ') : 'None'}`;

        summary = `Use Case [${category}/${suitability}]: ${title}`;
        exactKeywords = {
          ...exactKeywords,
          use_case_id: ucId,
          category,
          suitability,
        };
        break;
      }

      case 'ontology': {
        const concept = rawEntity.concept_name || rawEntity.name || 'Concept';
        const cat = rawEntity.category || 'TAXONOMY';
        const def = rawEntity.definition || rawEntity.description || '';
        const parents = Array.isArray(rawEntity.parent_concepts) ? rawEntity.parent_concepts.join(', ') : '';

        docText = `[OBJECT: ONTOLOGY_CONCEPT]
Concept Name: ${concept}
Category: ${cat}
Parents: ${parents || 'Root'}
Definition: ${def}
Code: ${rawEntity.taxonomy_code || 'CAIM-001'}`;

        summary = `Ontology [${cat}] ${concept}: ${def}`;
        exactKeywords = {
          ...exactKeywords,
          concept_name: concept,
          category: cat,
          taxonomy_code: rawEntity.taxonomy_code,
        };
        break;
      }

      case 'dependency': {
        const pkgName = rawEntity.package_name || rawEntity.name || 'pkg';
        const eco = rawEntity.ecosystem || 'npm';
        const ver = rawEntity.version || '1.0.0';
        const lic = rawEntity.license || 'MIT';
        const reach = rawEntity.reachable_sinks?.length ? 'REACHABLE' : 'UNREACHED';

        docText = `[OBJECT: DEPENDENCY]
Package: ${pkgName}
Ecosystem: ${eco}
Version: ${ver}
License: ${lic}
Reachability Status: ${reach}
Reachable Sinks: ${Array.isArray(rawEntity.reachable_sinks) ? rawEntity.reachable_sinks.join(', ') : 'None'}`;

        summary = `Dependency ${eco}:${pkgName}@${ver} (${lic}, ${reach})`;
        exactKeywords = {
          ...exactKeywords,
          package_name: pkgName,
          ecosystem: eco,
          version: ver,
          license: lic,
          reachability: reach,
        };
        break;
      }

      case 'vulnerability': {
        const cveId = rawEntity.cve_id || rawEntity.advisory_id || entityRefId;
        const pkg = rawEntity.package_name || 'dependency';
        const sev = rawEntity.severity || 'HIGH';
        const cvss = (rawEntity.cvss_score !== undefined && rawEntity.cvss_score !== null)
          ? Number(rawEntity.cvss_score)
          : ((rawEntity.cvss_v3 !== undefined && rawEntity.cvss_v3 !== null) ? Number(rawEntity.cvss_v3) : null);
        const fixed = rawEntity.fixed_version || null;

        const lines: string[] = [
          `[OBJECT: VULNERABILITY]`,
          `Advisory ID: ${cveId}`,
          `Package: ${pkg}`,
          `Severity: ${sev}`,
        ];
        if (cvss !== null) {
          lines.push(`CVSS v3: ${cvss}`);
        }
        if (fixed) {
          lines.push(`Fixed In: ${fixed}`);
        }
        if (rawEntity.summary || rawEntity.description) {
          lines.push(`Summary: ${rawEntity.summary || rawEntity.description}`);
        }
        docText = lines.join('\n');

        summary = `Advisory ${cveId} [${sev}] in ${pkg}${fixed ? `. Fixed in ${fixed}` : ''}${cvss !== null ? ` (CVSS ${cvss})` : ''}`;
        exactKeywords = {
          ...exactKeywords,
          cve_id: cveId,
          package_name: pkg,
          severity: sev,
          ...(cvss !== null ? { cvss_score: cvss } : {}),
          ...(fixed ? { fixed_version: fixed } : {}),
        };
        break;
      }

      case 'package': {
        const name = rawEntity.package_name || rawEntity.name || 'artifact';
        const artType = rawEntity.artifact_type || 'SOURCE_BUNDLE';
        const digest = rawEntity.digest || rawEntity.hash || 'sha256:000';
        const size = rawEntity.size_bytes || 0;
        const entry = rawEntity.entrypoint || 'index.js';

        docText = `[OBJECT: ARTIFACT_PACKAGE]
Package Name: ${name}
Artifact Type: ${artType}
Digest: ${digest}
Size: ${size} bytes
Entrypoint: ${entry}`;

        summary = `Package ${name} (${artType}, ${size} bytes, digest ${digest.substring(0, 12)}...)`;
        exactKeywords = {
          ...exactKeywords,
          package_name: name,
          artifact_type: artType,
          digest,
          entrypoint: entry,
        };
        break;
      }

      default: {
        docText = `[OBJECT: ${String(objectType).toUpperCase()}]\n${JSON.stringify(rawEntity, null, 2)}`;
        summary = `${objectType} object ${entityRefId}`;
      }
    }

    const payload = {
      ...rawEntity,
      _built_summary: summary,
      _built_doc_text: docText,
    };

    const contentHash = computeSha256({
      object_type: objectType,
      entity_ref_id: entityRefId,
      doc_text: docText,
      payload,
      classification,
      projection_version: projectionVersion,
    });

    return {
      knowledge_projection_id: `proj-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      knowledge_object_id: rawEntity.knowledge_object_id || `kobj-${entityRefId}`,
      entity_ref_id: entityRefId,
      object_type: objectType,
      projection_type: `${objectType.toUpperCase()}_PROJECTION_V1`,
      projection_version: projectionVersion,
      agent_id: context.agent_id ?? rawEntity.agent_id ?? null,
      agent_version_id: context.agent_version_id ?? rawEntity.agent_version_id ?? null,
      analysis_run_id: context.analysis_run_id ?? rawEntity.analysis_run_id ?? null,
      security_classification: classification,
      security_classification_rank: rank,
      vault_restricted: isVault,
      document_text: docText,
      summary,
      payload,
      exact_keywords: exactKeywords,
      content_hash: contentHash,
      stale: false,
      indexed_at: null,
      created_at: new Date().toISOString(),
    };
  }
}
