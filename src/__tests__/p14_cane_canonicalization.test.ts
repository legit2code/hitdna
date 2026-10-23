/**
 * P14 — CANE Canonicalization & Ontology Mapping Test Suite
 */

import { describe, it, expect } from 'vitest';
import { 
  CaneCanonicalizer, 
  CaneMappingRegistry, 
  SecurityInferenceGuard, 
  SecurityInferenceGuardViolationError, 
  CaneNormalizers,
  SourceFactsNormalizer,
  STANDARD_CONCEPTS,
  CANE_SPEC_VERSION,
  CANE_MAPPING_REGISTRY_VERSION
} from '@caim/ontology';
import { SyntaxIntelligencePipeline } from '@caim/syntax';

describe('P14 — CANE Canonicalization & Ontology Mapping Architecture', () => {
  it('verifies CANE and Mapping Registry spec versions are defined', () => {
    expect(CANE_SPEC_VERSION).toBe('1.0.0');
    expect(CANE_MAPPING_REGISTRY_VERSION).toBe('1.0.0');
    expect(CaneCanonicalizer.CANONICALIZER_VERSION).toBe('1.0.0');
  });

  it('translates polyglot process-execution source facts across JS, TS, Python, and Go into the identical canonical concept', () => {
    const jsSource = `
      import { exec } from 'child_process';
      export function runCmd(c) { exec(c); }
    `;

    const pySource = `
      import subprocess
      def run_cmd(c):
          subprocess.Popen(c, shell=True)
    `;

    const goSource = `
      package main
      import "os/exec"
      func RunCmd(c string) {
          exec.Command("sh", "-c", c).Run()
      }
    `;

    const parsed = SyntaxIntelligencePipeline.processArtifact('art_polyglot_process', [
      { path: 'services/node_runner.ts', content: jsSource },
      { path: 'services/py_runner.py', content: pySource },
      { path: 'services/go_runner.go', content: goSource },
    ]);

    const result = CaneCanonicalizer.canonicalize(parsed, {
      agent_name: 'PolyglotRunnerAgent',
    });

    // 1. Single unified canonical capability instance for process execution
    const execCaps = result.caim_manifest.capabilities.filter(
      c => c.canonical_key === 'capability.tools.exec'
    );
    expect(execCaps.length).toBe(1);
    expect(execCaps[0].capability_concept_id).toBe(STANDARD_CONCEPTS['capability.tools.exec'].concept_id);
    expect(execCaps[0].declaration_state).toBe('INFERRED_STATIC');

    // 2. Exact source evidence retained for all 3 languages
    const execMatches = result.mapping_matches.filter(
      m => m.target_canonical_key === 'capability.tools.exec'
    );
    expect(execMatches.length).toBe(3);

    const paths = execMatches.map(m => m.file_path);
    expect(paths).toContain('services/node_runner.ts');
    expect(paths).toContain('services/py_runner.py');
    expect(paths).toContain('services/go_runner.go');

    // 3. Provenance and rule identity are preserved
    for (const match of execMatches) {
      expect(match.rule_id).toMatch(/^CANE_MAP_EXEC_/);
      expect(match.confidence).toBeGreaterThanOrEqual(0.95);
      expect(match.provenance.transformation_type).toBe('SYNTAX_TRANSFORMATION');
      expect(match.span?.file_path).toBeDefined();
    }
  });

  it('preserves unknown extensions and vendor metadata without data loss', () => {
    const rawJson = JSON.stringify({
      name: 'enterprise-agent',
      version: '3.1.0',
      x_vendor_compliance_tier: 'SOC2_TYPE2',
      x_custom_sandbox_timeout_ms: 15000,
      custom_extension_block: {
        enclave: 'nitro',
        attestation: true,
      }
    });

    const parsed = SyntaxIntelligencePipeline.processArtifact('art_unknown_ext', [
      { path: 'manifest.json', content: rawJson }
    ]);

    const result = CaneCanonicalizer.canonicalize(parsed, {
      custom_metadata: {
        x_runtime_cluster: 'prod-us-central1',
      }
    });

    expect(result.unmapped_extensions).toBeDefined();
    expect(result.unmapped_extensions.x_runtime_cluster).toBe('prod-us-central1');
    expect(result.unmapped_extensions['manifest.json:x_vendor_compliance_tier']).toBe('SOC2_TYPE2');
    expect(result.unmapped_extensions['manifest.json:x_custom_sandbox_timeout_ms']).toBe(15000);
    expect(result.unmapped_extensions['manifest.json:custom_extension_block']).toEqual({
      enclave: 'nitro',
      attestation: true,
    });
  });

  it('enforces security inference guard preventing inference-only CONFIRMED or OBSERVED states', () => {
    // Assert directly checking violation throws
    expect(() => {
      SecurityInferenceGuard.assertInferenceStateCompliant({
        entity_id: 'cap_inferred_exfiltration',
        entity_kind: 'CAPABILITY',
        declaration_state: 'OBSERVED_RUNTIME',
        has_direct_evidence: false,
        is_inferred: true,
      });
    }).toThrow(SecurityInferenceGuardViolationError);

    expect(() => {
      SecurityInferenceGuard.assertInferenceStateCompliant({
        entity_id: 'risk.remote_code_execution',
        entity_kind: 'INFERRED_CONCEPT',
        epistemic_state: 'CONFIRMED',
        has_direct_evidence: false,
        is_inferred: true,
      });
    }).toThrow(SecurityInferenceGuardViolationError);

    // Enforce safe declaration states
    expect(SecurityInferenceGuard.enforceSafeDeclarationState('OBSERVED_RUNTIME', false)).toBe('INFERRED_STATIC');
    expect(SecurityInferenceGuard.enforceSafeDeclarationState('DECLARED_EXPLICIT', false)).toBe('INFERRED_STATIC');
    expect(SecurityInferenceGuard.enforceSafeDeclarationState('OBSERVED_RUNTIME', true)).toBe('OBSERVED_RUNTIME');
  });

  it('correctly derives compound risk vector (Egress + Exec -> RCE Risk) with ontology semantic triples', () => {
    const code = `
      import { exec } from 'child_process';
      import fetch from 'node-fetch';

      export async function downloadAndExecute(targetUrl: string, cmd: string) {
        await fetch(targetUrl);
        exec(cmd);
      }
    `;

    const parsed = SyntaxIntelligencePipeline.processArtifact('art_compound', [
      { path: 'payload_downloader.ts', content: code }
    ]);

    const result = CaneCanonicalizer.canonicalize(parsed);

    // 1. Verify capability detections
    const capKeys = result.caim_manifest.capabilities.map(c => c.canonical_key);
    expect(capKeys).toContain('capability.tools.exec');
    expect(capKeys).toContain('capability.network.egress');

    // 2. Verify compound inference
    const rce = result.inferences.find(i => i.canonical_key === 'risk.remote_code_execution');
    expect(rce).toBeDefined();
    expect(rce?.epistemic_state).toBe('INFERRED_STATIC');
    expect(rce?.antecedent_concept_ids).toHaveLength(2);

    // 3. Verify ontology triples
    const derivedTriples = result.ontology_relationships.filter(r => r.predicate === 'DERIVED_FROM');
    expect(derivedTriples.length).toBeGreaterThanOrEqual(2);
    expect(derivedTriples.some(t => t.subject_concept_id === rce?.derived_concept_id)).toBe(true);
  });
});
