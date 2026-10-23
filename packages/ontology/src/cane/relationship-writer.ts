/**
 * CANE Canonical Relationship Writer
 * P14 — Canonicalization
 * 
 * Synthesizes CAIM bindings/dependencies and formal Ontology semantic triples
 * linking agents, tools, protocols, capabilities, permissions, and inferences.
 */

import { 
  CaimManifest, 
  CaimToolBinding, 
  CaimDependencyRelationship 
} from '../../../caim/src/index.ts';
import { 
  OntologyRelationship, 
  OntologyPredicate 
} from '../types.ts';
import { createOntologyRelationship } from '../relationships.ts';
import { CaneInferredConcept } from './types.ts';

export class CaneRelationshipWriter {
  /**
   * Generates ontology triples and CAIM entity bindings
   */
  public static buildRelationships(params: {
    manifest: CaimManifest;
    inferences: CaneInferredConcept[];
  }): {
    ontology_relationships: OntologyRelationship[];
    tool_bindings: CaimToolBinding[];
  } {
    const { manifest, inferences } = params;
    const ontologyRelationships: OntologyRelationship[] = [];
    const toolBindings: CaimToolBinding[] = [];

    const agentVersionId = manifest.version.agent_version_id;

    // 1. AgentVersion EXPOSES Tool
    for (const tool of manifest.tools) {
      // Create ToolBinding if bound to protocol
      if (tool.protocol_instance_id) {
        toolBindings.push({
          _entity_kind: 'TOOL_BINDING',
          binding_id: crypto.randomUUID(),
          tool_id: tool.tool_id,
          target_entity_ref_id: tool.protocol_instance_id,
          binding_type: 'RPC_PROXY',
          confidence: 0.99,
        });

        ontologyRelationships.push(
          createOntologyRelationship({
            subject_concept_id: tool.tool_id,
            predicate: 'BOUND_TO',
            object_concept_id: tool.protocol_instance_id,
            confidence: 0.99,
          })
        );
      }
    }

    // 2. AgentVersion IMPLEMENTS Capability
    for (const cap of manifest.capabilities) {
      ontologyRelationships.push(
        createOntologyRelationship({
          subject_concept_id: agentVersionId,
          predicate: 'IMPLEMENTS',
          object_concept_id: cap.capability_concept_id,
          confidence: cap.confidence,
        })
      );
    }

    // 3. Capability REQUIRES Permission
    for (const perm of manifest.permissions) {
      ontologyRelationships.push(
        createOntologyRelationship({
          subject_concept_id: agentVersionId,
          predicate: 'REQUIRES',
          object_concept_id: perm.permission_concept_id,
          confidence: perm.confidence,
        })
      );
    }

    // 4. Inferred Concept DERIVED_FROM Antecedent Concepts
    for (const inf of inferences) {
      for (const antecedentId of inf.antecedent_concept_ids) {
        ontologyRelationships.push(
          createOntologyRelationship({
            subject_concept_id: inf.derived_concept_id,
            predicate: 'DERIVED_FROM',
            object_concept_id: antecedentId,
            confidence: inf.confidence,
          })
        );
      }
    }

    return {
      ontology_relationships: ontologyRelationships,
      tool_bindings: toolBindings,
    };
  }
}
