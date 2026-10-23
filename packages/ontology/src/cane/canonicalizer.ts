/**
 * CANE Canonicalizer Engine — Orchestrator Facade
 * P14 — CAIM & Ontology Canonicalization
 */

import { 
  NormalizedSourceFacts, 
  CanonicalizationResult, 
  CaneMappingMatch, 
  CANE_SPEC_VERSION, 
  CANE_MAPPING_REGISTRY_VERSION 
} from './types.ts';
import { SourceFactsNormalizer } from './source-facts.ts';
import { CaneMappingRegistry } from './mapping-registry.ts';
import { CaneNormalizers } from './normalizers.ts';
import { SecurityInferenceGuard } from './inference-guard.ts';
import { CaneInferenceEngine } from './inference-engine.ts';
import { CaneRelationshipWriter } from './relationship-writer.ts';
import { STANDARD_CONCEPTS, getConceptByCanonicalKey } from '../concepts.ts';
import { createEmptyCaimManifest } from '../../../caim/src/manifest.ts';
import { 
  CaimManifest, 
  CaimCapabilityInstance, 
  CaimTool, 
  CaimComponent, 
  CaimDependencyRelationship, 
  CaimProtocolInstance, 
  CaimEndpoint, 
  CaimConfiguration, 
  CaimPermission, 
  CaimRuntimeEnvironment,
  CaimEntrypoint
} from '../../../caim/src/index.ts';
import { ArtifactParseResult } from '../../../syntax/src/index.ts';
import { ProvenanceRecord } from '../../../contracts/src/index.ts';

export interface CanonicalizeOptions {
  agent_id?: string;
  agent_name?: string;
  agent_version_id?: string;
  content_fingerprint?: string;
  custom_metadata?: Record<string, unknown>;
}

export class CaneCanonicalizer {
  public static readonly CANONICALIZER_VERSION = '1.0.0';

  /**
   * Main entrypoint: Canonicalizes raw syntax facts into source-independent CAIM + Ontology semantics
   */
  public static canonicalize(
    input: NormalizedSourceFacts | ArtifactParseResult,
    options?: CanonicalizeOptions
  ): CanonicalizationResult {
    const startTime = Date.now();

    // 1. Ensure NormalizedSourceFacts
    const normalized: NormalizedSourceFacts = 'facts' in input
      ? input
      : SourceFactsNormalizer.fromArtifactParseResult(input, {
          agent_id: options?.agent_id,
          agent_version_id: options?.agent_version_id,
          custom_metadata: options?.custom_metadata,
        });

    const agentId = options?.agent_id || normalized.agent_id || crypto.randomUUID();
    const agentVersionId = options?.agent_version_id || normalized.agent_version_id || crypto.randomUUID();
    const agentName = options?.agent_name || `Agent-${normalized.artifact_id.slice(0, 8)}`;
    const contentFingerprint = options?.content_fingerprint || crypto.randomUUID();

    // 2. Instantiate base empty manifest
    const manifest: CaimManifest = createEmptyCaimManifest({
      agent_id: agentId,
      canonical_name: agentName,
      agent_version_id: agentVersionId,
      content_fingerprint: contentFingerprint,
    });

    const mappingMatches: CaneMappingMatch[] = [];
    const provenanceRecords: ProvenanceRecord[] = [normalized.provenance];
    const inferredCapabilityIds = new Set<string>();

    const capabilityKeysAdded = new Set<string>();
    const toolsAdded = new Map<string, CaimTool>();
    const componentsAdded = new Map<string, CaimComponent>();
    const protocolsAdded = new Map<string, CaimProtocolInstance>();

    // 3. Process Call Sites against Mapping Registry
    for (const call of normalized.call_sites) {
      const match = CaneMappingRegistry.matchCallSite(
        call,
        (call as any).ecosystem || 'generic',
        call.span?.file_path || 'unknown'
      );

      if (match) {
        mappingMatches.push(match);
        provenanceRecords.push(match.provenance);

        if (match.target_entity_type === 'CAPABILITY') {
          if (!capabilityKeysAdded.has(match.target_canonical_key)) {
            capabilityKeysAdded.add(match.target_canonical_key);
            const capId = crypto.randomUUID();
            const cap: CaimCapabilityInstance = {
              _entity_kind: 'CAPABILITY',
              capability_id: capId,
              agent_version_id: agentVersionId,
              capability_concept_id: match.target_concept_id,
              canonical_key: match.target_canonical_key,
              declaration_state: 'INFERRED_STATIC',
              source_type: 'CODE_AST',
              confidence: match.confidence,
            };
            manifest.capabilities.push(cap);
          }
        }
      }
    }

    // 4. Process Protocols & MCP Tools
    for (const proto of normalized.protocols) {
      const protoId = crypto.randomUUID();
      const protoInstance: CaimProtocolInstance = {
        _entity_kind: 'PROTOCOL_INSTANCE',
        protocol_instance_id: protoId,
        agent_version_id: agentVersionId,
        protocol_name: proto.protocol_kind,
        protocol_version: proto.version || '2024-11-05',
        role: proto.mcp_details?.role === 'CLIENT' ? 'CLIENT' : 'SERVER',
        confidence: proto.confidence || 0.99,
      };
      manifest.protocols.push(protoInstance);
      protocolsAdded.set(proto.protocol_kind, protoInstance);

      // Add MCP capability
      if (proto.protocol_kind === 'MCP' && !capabilityKeysAdded.has('capability.tools.mcp')) {
        capabilityKeysAdded.add('capability.tools.mcp');
        const capId = crypto.randomUUID();
        manifest.capabilities.push({
          _entity_kind: 'CAPABILITY',
          capability_id: capId,
          agent_version_id: agentVersionId,
          capability_concept_id: STANDARD_CONCEPTS['capability.tools.mcp'].concept_id,
          canonical_key: 'capability.tools.mcp',
          declaration_state: 'INFERRED_STATIC',
          source_type: 'CODE_AST',
          confidence: 0.99,
        });
      }

      // Add MCP Tools
      if (proto.mcp_details?.tools) {
        for (const toolFact of proto.mcp_details.tools) {
          if (!toolsAdded.has(toolFact.name)) {
            const toolId = crypto.randomUUID();
            const tool: CaimTool = {
              _entity_kind: 'TOOL',
              tool_id: toolId,
              agent_version_id: agentVersionId,
              canonical_name: toolFact.name,
              tool_type: 'MCP_TOOL',
              interface_type: 'JSON_SCHEMA',
              description: toolFact.description,
              protocol_instance_id: protoId,
              parameters_schema: toolFact.parameters_schema || {},
              confidence: 0.99,
            };
            manifest.tools.push(tool);
            toolsAdded.set(toolFact.name, tool);
          }
        }
      }

      // Match protocol
      const protoMatches = CaneMappingRegistry.matchProtocol(proto, proto.span?.file_path || 'unknown');
      for (const pm of protoMatches) {
        mappingMatches.push(pm);
        provenanceRecords.push(pm.provenance);
      }
    }

    // 5. Process Declared Tools from Syntax configuration
    for (const toolDecl of normalized.tools) {
      if (!toolsAdded.has(toolDecl.name)) {
        const toolId = crypto.randomUUID();
        const tool: CaimTool = {
          _entity_kind: 'TOOL',
          tool_id: toolId,
          agent_version_id: agentVersionId,
          canonical_name: toolDecl.name,
          tool_type: 'FUNCTION',
          interface_type: 'JSON_SCHEMA',
          description: toolDecl.description,
          parameters_schema: toolDecl.parameters || {},
          confidence: 0.95,
        };
        manifest.tools.push(tool);
        toolsAdded.set(toolDecl.name, tool);
      }
    }

    // 6. Process Dependencies -> Components
    for (const dep of normalized.dependencies) {
      const norm = CaneNormalizers.normalizeDependency(dep.name, dep.version, dep.file_path);
      const compKey = `${norm.ecosystem}:${norm.normalized_name}`;
      let comp = componentsAdded.get(compKey);

      if (!comp) {
        comp = {
          _entity_kind: 'COMPONENT',
          component_id: crypto.randomUUID(),
          canonical_name: norm.normalized_name,
          component_type: 'LIBRARY',
          ecosystem: norm.ecosystem,
          version: norm.version,
        };
        manifest.components.push(comp);
        componentsAdded.set(compKey, comp);

        const rel: CaimDependencyRelationship = {
          _entity_kind: 'DEPENDENCY_RELATIONSHIP',
          relationship_id: crypto.randomUUID(),
          agent_version_id: agentVersionId,
          to_component_id: comp.component_id,
          dependency_type: 'DIRECT',
          scope: dep.kind || 'production',
          resolved_version: norm.version,
          is_direct: true,
        };
        manifest.dependencies.push(rel);
      }
    }

    // 7. Process Environment Variables -> Configuration
    if (normalized.env_vars.length > 0) {
      const configId = crypto.randomUUID();
      const entries = normalized.env_vars.map(env => ({
        key_path: env.name,
        value_type: CaneNormalizers.inferConfigValueType(env.default_value),
        normalized_value: env.default_value,
        security_classification: CaneNormalizers.classifySecurityKey(env.name),
      }));

      manifest.configurations.push({
        _entity_kind: 'CONFIGURATION',
        configuration_id: configId,
        agent_version_id: agentVersionId,
        configuration_type: 'ENV_VARS',
        entries,
      });
    }

    // 8. Process Frameworks -> Runtime & Entrypoints
    for (const fw of normalized.frameworks) {
      const runtimeInfo = CaneNormalizers.normalizeRuntime(fw.framework_name);
      manifest.runtimes.push({
        _entity_kind: 'RUNTIME_ENVIRONMENT',
        runtime_id: crypto.randomUUID(),
        agent_version_id: agentVersionId,
        runtime_type: runtimeInfo.runtime_type,
        runtime_name: runtimeInfo.runtime_name,
        execution_mode: runtimeInfo.execution_mode,
      });
    }

    // 9. Run Taxonomic & Structural Inferences
    const hasProcessExec = capabilityKeysAdded.has('capability.tools.exec');
    const hasNetworkEgress = capabilityKeysAdded.has('capability.network.egress');
    const hasFsRead = capabilityKeysAdded.has('capability.fs.read');
    const hasFsWrite = capabilityKeysAdded.has('capability.fs.write');
    const hasCodeEval = capabilityKeysAdded.has('capability.code.eval');
    const hasMcpTools = capabilityKeysAdded.has('capability.tools.mcp');

    const inferences = CaneInferenceEngine.runInference({
      agent_version_id: agentVersionId,
      capabilities: manifest.capabilities,
      tools: manifest.tools,
      has_process_exec: hasProcessExec,
      has_network_egress: hasNetworkEgress,
      has_fs_read: hasFsRead,
      has_fs_write: hasFsWrite,
      has_code_eval: hasCodeEval,
      has_mcp_tools: hasMcpTools,
    });

    // 10. Enforce Security Inference Guard across all entities
    for (const inf of inferences) {
      inferredCapabilityIds.add(inf.derived_concept_id);
    }
    const guardValidation = SecurityInferenceGuard.validateInferenceBoundaries(
      manifest.capabilities,
      inferredCapabilityIds
    );

    // 11. Generate Relationships & Bindings
    const { ontology_relationships, tool_bindings } = CaneRelationshipWriter.buildRelationships({
      manifest,
      inferences,
    });
    manifest.tool_bindings.push(...tool_bindings);

    // 12. Collect all referenced Ontology Concepts
    const ontologyConcepts = Object.values(STANDARD_CONCEPTS);

    const totalTimeMs = Date.now() - startTime;
    const avgConfidence = mappingMatches.length > 0
      ? Number((mappingMatches.reduce((acc, m) => acc + m.confidence, 0) / mappingMatches.length).toFixed(4))
      : 1.0;

    return {
      caim_manifest: manifest,
      ontology_concepts: ontologyConcepts,
      ontology_relationships: ontology_relationships,
      mapping_matches: mappingMatches,
      inferences,
      provenance_records: provenanceRecords,
      unmapped_extensions: normalized.unrecognized_extensions,
      diagnostics: {
        total_source_facts: normalized.facts.length,
        total_mappings_applied: mappingMatches.length,
        total_capabilities: manifest.capabilities.length,
        total_tools: manifest.tools.length,
        total_dependencies: manifest.dependencies.length,
        total_protocols: manifest.protocols.length,
        total_inferences: inferences.length,
        average_mapping_confidence: avgConfidence,
        security_guard_status: guardValidation.valid ? 'PASSED' : 'VIOLATION_BLOCKED',
        processing_time_ms: totalTimeMs,
      },
    };
  }
}
