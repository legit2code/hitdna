/**
 * CANE Canonicalization & Ontology Mapping Tests
 * P14 Verification Suite
 */

import { describe, it, expect } from 'vitest';
import { 
  CaneCanonicalizer, 
  CaneMappingRegistry, 
  SecurityInferenceGuard, 
  SecurityInferenceGuardViolationError, 
  CaneNormalizers,
  SourceFactsNormalizer,
  STANDARD_CONCEPTS
} from '../index.ts';
import { SyntaxIntelligencePipeline } from '../../../syntax/src/index.ts';

describe('P14 — CANE Canonicalization & Ontology Mapping', () => {
  // Test 1: Cross-Language Equivalence for Process Execution
  it('maps equivalent process-execution constructs in JS/TS, Python, and Go to the same canonical capability with source lineage', () => {
    const jsSnippet = `
      import { exec } from 'child_process';
      export function runScript(cmd) {
        exec(cmd);
      }
    `;

    const pythonSnippet = `
      import subprocess
      def execute_command(cmd):
          subprocess.Popen(cmd, shell=True)
    `;

    const goSnippet = `
      package main
      import "os/exec"
      func runTask(cmd string) {
          exec.Command("sh", "-c", cmd).Run()
      }
    `;

    const parsed = SyntaxIntelligencePipeline.processArtifact('artifact_cross_lang_exec', [
      { path: 'agent_node.ts', content: jsSnippet },
      { path: 'agent_py.py', content: pythonSnippet },
      { path: 'agent_go.go', content: goSnippet },
    ]);

    const result = CaneCanonicalizer.canonicalize(parsed, {
      agent_name: 'MultiLangExecutionAgent',
    });

    // 1. All three languages mapped to capability.tools.exec
    const execCaps = result.caim_manifest.capabilities.filter(
      c => c.canonical_key === 'capability.tools.exec'
    );
    expect(execCaps.length).toBeGreaterThanOrEqual(1);
    expect(execCaps[0].capability_concept_id).toBe(STANDARD_CONCEPTS['capability.tools.exec'].concept_id);

    // 2. Mapping matches preserve specific source lineage for each language
    const execMatches = result.mapping_matches.filter(
      m => m.target_canonical_key === 'capability.tools.exec'
    );
    expect(execMatches.length).toBe(3);

    const matchedFiles = execMatches.map(m => m.file_path);
    expect(matchedFiles).toContain('agent_node.ts');
    expect(matchedFiles).toContain('agent_py.py');
    expect(matchedFiles).toContain('agent_go.go');

    // 3. Spans and provenance are retained
    for (const match of execMatches) {
      expect(match.provenance).toBeDefined();
      expect(match.provenance.transformation_type).toBe('SYNTAX_TRANSFORMATION');
      expect(match.confidence).toBeGreaterThanOrEqual(0.95);
      expect(match.span).toBeDefined();
      expect(match.span?.start_line).toBeGreaterThan(0);
    }
  });

  // Test 2: Unknown Extension Preservation
  it('preserves unknown configuration attributes and extensions without dropping them', () => {
    const customMetadata = {
      x_custom_agent_telemetry: 'datadog://v2',
      x_experimental_sandbox_tier: 'isolated-v8-isolate',
      vendor_specific_tags: ['enterprise', 'financial-compliance'],
    };

    const parsed = SyntaxIntelligencePipeline.processArtifact('artifact_custom_ext', [
      { 
        path: 'package.json', 
        content: JSON.stringify({
          name: 'custom-mcp-agent',
          version: '2.0.0',
          x_mcp_custom_profile: 'streaming-duplex',
          x_vendor_audit_id: 'AUDIT-9921',
        }) 
      },
    ]);

    const result = CaneCanonicalizer.canonicalize(parsed, {
      custom_metadata: customMetadata,
    });

    // Preserves custom_metadata and unrecognized extensions
    expect(result.unmapped_extensions).toBeDefined();
    expect(result.unmapped_extensions.x_custom_agent_telemetry).toBe('datadog://v2');
    expect(result.unmapped_extensions.x_experimental_sandbox_tier).toBe('isolated-v8-isolate');
    expect(result.unmapped_extensions['package.json:x_mcp_custom_profile']).toBe('streaming-duplex');
    expect(result.unmapped_extensions['package.json:x_vendor_audit_id']).toBe('AUDIT-9921');
  });

  // Test 3: Security-Relevant Inference Guard
  it('strictly blocks inference-only concepts from claiming CONFIRMED, OBSERVED, or OBSERVED_RUNTIME states', () => {
    // 1. Directly asserting an inferred entity as OBSERVED_RUNTIME must throw
    expect(() => {
      SecurityInferenceGuard.assertInferenceStateCompliant({
        entity_id: 'cap_inferred_network_probe',
        entity_kind: 'CAPABILITY',
        declaration_state: 'OBSERVED_RUNTIME',
        has_direct_evidence: false,
        is_inferred: true,
      });
    }).toThrow(SecurityInferenceGuardViolationError);

    // 2. Directly asserting an inferred concept as CONFIRMED must throw
    expect(() => {
      SecurityInferenceGuard.assertInferenceStateCompliant({
        entity_id: 'risk.remote_code_execution',
        entity_kind: 'INFERRED_CONCEPT',
        epistemic_state: 'CONFIRMED',
        has_direct_evidence: false,
        is_inferred: true,
      });
    }).toThrow(SecurityInferenceGuardViolationError);

    // 3. Safe enforcement downgrades unsafe states to INFERRED_STATIC
    const safeState = SecurityInferenceGuard.enforceSafeDeclarationState('OBSERVED_RUNTIME', false);
    expect(safeState).toBe('INFERRED_STATIC');

    const explicitSafe = SecurityInferenceGuard.enforceSafeDeclarationState('DECLARED_EXPLICIT', false);
    expect(explicitSafe).toBe('INFERRED_STATIC');
  });

  // Test 4: Compound Taxonomic & Structural Inference with Provenance
  it('correctly executes compound inference (Exec + Network -> RCE Risk) with full derivation provenance', () => {
    const multiCapabilityCode = `
      import { exec } from 'child_process';
      import axios from 'axios';

      export async function downloadAndRun(url, cmd) {
        await axios.get(url);
        exec(cmd);
      }
    `;

    const parsed = SyntaxIntelligencePipeline.processArtifact('artifact_compound_rce', [
      { path: 'danger_agent.ts', content: multiCapabilityCode },
    ]);

    const result = CaneCanonicalizer.canonicalize(parsed);

    // Should detect both exec and network egress
    const capKeys = result.caim_manifest.capabilities.map(c => c.canonical_key);
    expect(capKeys).toContain('capability.tools.exec');
    expect(capKeys).toContain('capability.network.egress');

    // Should derive compound inference
    const rceInference = result.inferences.find(i => i.canonical_key === 'risk.remote_code_execution');
    expect(rceInference).toBeDefined();
    expect(rceInference?.epistemic_state).toBe('INFERRED_STATIC');
    expect(rceInference?.provenance).toBeDefined();
    expect(rceInference?.provenance.engine_key).toBe('caim:cane-taxonomic-inference');
    expect(rceInference?.antecedent_concept_ids.length).toBe(2);

    // Should have DERIVED_FROM ontology relationship
    const derivedRels = result.ontology_relationships.filter(r => r.predicate === 'DERIVED_FROM');
    expect(derivedRels.length).toBeGreaterThanOrEqual(2);
  });
});
