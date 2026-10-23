/**
 * CANE Taxonomic & Structural Inference Engine
 * P14 — Canonicalization
 * 
 * Derives higher-order architectural concepts, compound capabilities, and risk vectors
 * with complete deterministic InferenceProvenance while strictly adhering to the Security Inference Guard.
 */

import { CaneInferredConcept } from './types.ts';
import { STANDARD_CONCEPTS } from '../concepts.ts';
import { recordInferenceProvenance } from '../mappings.ts';
import { SecurityInferenceGuard } from './inference-guard.ts';
import { CaimCapabilityInstance, CaimTool } from '../../../caim/src/index.ts';

export interface InferenceContext {
  agent_version_id: string;
  capabilities: CaimCapabilityInstance[];
  tools: CaimTool[];
  has_network_egress: boolean;
  has_process_exec: boolean;
  has_fs_read: boolean;
  has_fs_write: boolean;
  has_code_eval: boolean;
  has_mcp_tools: boolean;
}

export class CaneInferenceEngine {
  public static readonly ENGINE_KEY = 'caim:cane-taxonomic-inference';
  public static readonly ENGINE_VERSION = '1.0.0';

  /**
   * Evaluates inference rules against the extracted CAIM capabilities and tools
   */
  public static runInference(ctx: InferenceContext): CaneInferredConcept[] {
    const inferences: CaneInferredConcept[] = [];

    // Rule 1: Remote Execution Potential (Process Exec + Network Egress)
    if (ctx.has_process_exec && ctx.has_network_egress) {
      const antecedentCaps = ctx.capabilities.filter(c => 
        c.canonical_key === 'capability.tools.exec' || c.canonical_key === 'capability.network.egress'
      );
      const antecedentIds = antecedentCaps.map(c => c.capability_id);
      const antecedentConceptIds = antecedentCaps.map(c => c.capability_concept_id);

      const targetConcept = STANDARD_CONCEPTS['risk.injection.prompt'] || {
        concept_id: 'r0000000-0001-0000-0000-000000000003',
        canonical_key: 'risk.remote_code_execution',
      };

      const prov = recordInferenceProvenance({
        inference_rule_id: 'INF_RULE_RCE_COMPOUND_CAPABILITY_V1',
        engine_key: this.ENGINE_KEY,
        engine_version: this.ENGINE_VERSION,
        input_entity_ref_ids: antecedentIds.length > 0 ? antecedentIds : [ctx.agent_version_id],
        derived_concept_id: targetConcept.concept_id,
        confidence: 0.88,
      });

      // Pass through security guard
      SecurityInferenceGuard.assertInferenceStateCompliant({
        entity_id: targetConcept.concept_id,
        entity_kind: 'INFERRED_CONCEPT',
        epistemic_state: 'epistemic.derived_assertion',
        has_direct_evidence: false,
        is_inferred: true,
      });

      inferences.push({
        inference_id: `inf_${crypto.randomUUID()}`,
        inference_rule_id: 'INF_RULE_RCE_COMPOUND_CAPABILITY_V1',
        derived_concept_id: targetConcept.concept_id,
        canonical_key: 'risk.remote_code_execution',
        epistemic_state: 'INFERRED_STATIC',
        confidence: 0.88,
        antecedent_concept_ids: antecedentConceptIds,
        antecedent_entity_ids: antecedentIds,
        provenance: prov,
        rationale: 'Inferred compound risk vector from co-occurrence of child process execution and outbound network egress capabilities.',
      });
    }

    // Rule 2: Data Exfiltration Vector (FS Read + Network Egress)
    if (ctx.has_fs_read && ctx.has_network_egress) {
      const antecedentCaps = ctx.capabilities.filter(c => 
        c.canonical_key === 'capability.fs.read' || c.canonical_key === 'capability.network.egress'
      );
      const antecedentIds = antecedentCaps.map(c => c.capability_id);
      const antecedentConceptIds = antecedentCaps.map(c => c.capability_concept_id);

      const targetConcept = STANDARD_CONCEPTS['behavior.data.exfiltration'];

      const prov = recordInferenceProvenance({
        inference_rule_id: 'INF_RULE_DATA_EXFILTRATION_VECTOR_V1',
        engine_key: this.ENGINE_KEY,
        engine_version: this.ENGINE_VERSION,
        input_entity_ref_ids: antecedentIds.length > 0 ? antecedentIds : [ctx.agent_version_id],
        derived_concept_id: targetConcept.concept_id,
        confidence: 0.82,
      });

      // Pass through security guard
      SecurityInferenceGuard.assertInferenceStateCompliant({
        entity_id: targetConcept.concept_id,
        entity_kind: 'INFERRED_CONCEPT',
        epistemic_state: 'epistemic.derived_assertion',
        has_direct_evidence: false,
        is_inferred: true,
      });

      inferences.push({
        inference_id: `inf_${crypto.randomUUID()}`,
        inference_rule_id: 'INF_RULE_DATA_EXFILTRATION_VECTOR_V1',
        derived_concept_id: targetConcept.concept_id,
        canonical_key: targetConcept.canonical_key,
        epistemic_state: 'INFERRED_STATIC',
        confidence: 0.82,
        antecedent_concept_ids: antecedentConceptIds,
        antecedent_entity_ids: antecedentIds,
        provenance: prov,
        rationale: 'Inferred data exfiltration susceptibility from concurrent filesystem read and network egress potential.',
      });
    }

    // Rule 3: Dynamic Code Injection Susceptibility (Code Eval)
    if (ctx.has_code_eval) {
      const evalCaps = ctx.capabilities.filter(c => c.canonical_key === 'capability.code.eval');
      const antecedentIds = evalCaps.map(c => c.capability_id);
      const antecedentConceptIds = evalCaps.map(c => c.capability_concept_id);

      const targetConceptId = 'r0000000-0001-0000-0000-000000000004';
      const prov = recordInferenceProvenance({
        inference_rule_id: 'INF_RULE_DYNAMIC_CODE_INJECTION_V1',
        engine_key: this.ENGINE_KEY,
        engine_version: this.ENGINE_VERSION,
        input_entity_ref_ids: antecedentIds.length > 0 ? antecedentIds : [ctx.agent_version_id],
        derived_concept_id: targetConceptId,
        confidence: 0.90,
      });

      // Pass through security guard
      SecurityInferenceGuard.assertInferenceStateCompliant({
        entity_id: targetConceptId,
        entity_kind: 'INFERRED_CONCEPT',
        epistemic_state: 'epistemic.derived_assertion',
        has_direct_evidence: false,
        is_inferred: true,
      });

      inferences.push({
        inference_id: `inf_${crypto.randomUUID()}`,
        inference_rule_id: 'INF_RULE_DYNAMIC_CODE_INJECTION_V1',
        derived_concept_id: targetConceptId,
        canonical_key: 'risk.code_injection',
        epistemic_state: 'INFERRED_STATIC',
        confidence: 0.90,
        antecedent_concept_ids: antecedentConceptIds,
        antecedent_entity_ids: antecedentIds,
        provenance: prov,
        rationale: 'Inferred arbitrary code execution vulnerability from presence of dynamic eval/Function constructs.',
      });
    }

    return inferences;
  }
}
