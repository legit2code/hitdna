/**
 * CANE Normalized Source Fact Representation
 * P14 — Canonicalization
 */

import { 
  NormalizedSourceFacts, 
  NormalizedSourceFactItem 
} from './types.ts';
import { 
  ArtifactParseResult, 
  ParsedSourceFacts, 
  SymbolFact, 
  ImportFact, 
  ExportFact, 
  CallSiteFact, 
  EnvVarRef, 
  ToolDeclaration,
  ModelReference,
  PermissionRef,
  ProtocolFact, 
  FrameworkFingerprint 
} from '../../../syntax/src/index.ts';
import { ProvenanceRecord } from '../../../contracts/src/index.ts';

export class SourceFactsNormalizer {
  /**
   * Translates an ArtifactParseResult from P13 Syntax pipeline into NormalizedSourceFacts for CANE
   */
  public static fromArtifactParseResult(
    artifactResult: ArtifactParseResult,
    options?: { agent_id?: string; agent_version_id?: string; custom_metadata?: Record<string, unknown> }
  ): NormalizedSourceFacts {
    const agentId = options?.agent_id || `agent_${artifactResult.artifact_id.slice(0, 8)}`;
    const agentVersionId = options?.agent_version_id || `ver_${crypto.randomUUID()}`;

    const facts: NormalizedSourceFactItem[] = [];
    const symbols: SymbolFact[] = [];
    const imports: ImportFact[] = [];
    const exports: ExportFact[] = [];
    const callSites: CallSiteFact[] = [];
    const envVars: EnvVarRef[] = [];
    const tools: ToolDeclaration[] = [];
    const models: ModelReference[] = [];
    const permissions: PermissionRef[] = [];
    const dependencies: Array<{ name: string; version: string; kind: string; file_path: string; span?: any }> = [];
    const protocols: ProtocolFact[] = [...artifactResult.aggregate_protocols];
    const frameworks: FrameworkFingerprint[] = [...artifactResult.aggregate_frameworks];
    const filePaths: string[] = [];

    const unrecognizedExtensions: Record<string, unknown> = {
      ...(options?.custom_metadata || {}),
    };

    for (const fileFact of artifactResult.file_facts) {
      filePaths.push(fileFact.file_path);
      const ecosystem = this.detectEcosystem(fileFact.file_path);

      // Collect symbols
      for (const sym of fileFact.symbols) {
        symbols.push(sym);
        facts.push({
          fact_id: `fact_sym_${crypto.randomUUID()}`,
          source_ecosystem: ecosystem,
          file_path: fileFact.file_path,
          fact_category: 'symbol',
          raw_value: sym,
          span: sym.span,
        });
      }

      // Collect imports & infer dependencies
      for (const imp of fileFact.imports) {
        imports.push(imp);
        facts.push({
          fact_id: `fact_imp_${crypto.randomUUID()}`,
          source_ecosystem: ecosystem,
          file_path: fileFact.file_path,
          fact_category: 'import',
          raw_value: imp,
          span: imp.span,
        });

        if (!imp.module_specifier.startsWith('.') && !imp.module_specifier.startsWith('/')) {
          dependencies.push({
            name: imp.module_specifier,
            version: '*',
            kind: 'direct',
            file_path: fileFact.file_path,
            span: imp.span,
          });
        }
      }

      // Collect exports
      for (const exp of fileFact.exports) {
        exports.push(exp);
        facts.push({
          fact_id: `fact_exp_${crypto.randomUUID()}`,
          source_ecosystem: ecosystem,
          file_path: fileFact.file_path,
          fact_category: 'export',
          raw_value: exp,
          span: exp.span,
        });
      }

      // Collect call sites with ecosystem and file path preserved
      for (const call of fileFact.call_sites) {
        const enrichedCall = {
          ...call,
          ecosystem,
          file_path: fileFact.file_path,
        };
        callSites.push(enrichedCall as any);
        facts.push({
          fact_id: `fact_call_${crypto.randomUUID()}`,
          source_ecosystem: ecosystem,
          file_path: fileFact.file_path,
          fact_category: 'call_site',
          raw_value: enrichedCall,
          span: call.span,
        });
      }

      // Collect configuration: env vars, tools, models, permissions
      if (fileFact.configuration) {
        for (const env of fileFact.configuration.env_vars) {
          envVars.push(env);
          facts.push({
            fact_id: `fact_env_${crypto.randomUUID()}`,
            source_ecosystem: ecosystem,
            file_path: fileFact.file_path,
            fact_category: 'env_var',
            raw_value: env,
            span: env.span,
          });
        }

        for (const t of fileFact.configuration.tools) {
          tools.push(t);
          facts.push({
            fact_id: `fact_tool_${crypto.randomUUID()}`,
            source_ecosystem: ecosystem,
            file_path: fileFact.file_path,
            fact_category: 'tool',
            raw_value: t,
            span: t.span,
          });
        }

        for (const m of fileFact.configuration.models) {
          models.push(m);
        }

        for (const p of fileFact.configuration.permissions) {
          permissions.push(p);
        }
      }

      // Check for raw content preview JSON or structured data
      if (fileFact.file_path.toLowerCase().endsWith('.json') && fileFact.raw_content_preview) {
        try {
          const jsonParsed = JSON.parse(fileFact.raw_content_preview);
          const standardKnownKeys = ['name', 'version', 'description', 'main', 'scripts', 'dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies', 'project'];
          for (const [k, v] of Object.entries(jsonParsed)) {
            if (!standardKnownKeys.includes(k)) {
              unrecognizedExtensions[`${fileFact.file_path}:${k}`] = v;
            }
          }
        } catch {
          // ignore
        }
      }
    }

    const provenance: ProvenanceRecord = {
      provenance_id: crypto.randomUUID(),
      source_spans: facts.filter(f => f.span).map(f => ({
        file_path: f.file_path,
        start_line: f.span!.start_line,
        start_col: f.span!.start_col,
        end_line: f.span!.end_line,
        end_col: f.span!.end_col,
        byte_offset_start: f.span!.byte_offset_start,
        byte_offset_end: f.span!.byte_offset_end,
        symbol_hint: f.span!.symbol_hint,
      })).slice(0, 100),
      input_hashes: artifactResult.provenance.input_hashes,
      rule_id: 'CANE_SOURCE_FACTS_NORMALIZATION_V1',
      ruleset_version: '1.0.0',
      transformation_type: 'SYNTAX_TRANSFORMATION',
      confidence: 1.0,
      derived_at: new Date().toISOString(),
      engine_signature: 'caim:cane-source-facts-normalizer:v1.0.0',
    };

    return {
      artifact_id: artifactResult.artifact_id,
      agent_id: agentId,
      agent_version_id: agentVersionId,
      file_paths: filePaths,
      facts,
      symbols,
      imports,
      exports,
      call_sites: callSites,
      env_vars: envVars,
      tools,
      models,
      permissions,
      dependencies,
      protocols,
      frameworks,
      unrecognized_extensions: unrecognizedExtensions,
      provenance,
    };
  }

  public static detectEcosystem(filePath: string): NormalizedSourceFactItem['source_ecosystem'] {
    const lower = filePath.toLowerCase();
    if (lower.endsWith('.ts') || lower.endsWith('.tsx')) return 'typescript';
    if (lower.endsWith('.js') || lower.endsWith('.jsx') || lower.endsWith('.mjs')) return 'javascript';
    if (lower.endsWith('.py')) return 'python';
    if (lower.endsWith('.go')) return 'go';
    if (lower.endsWith('.rs')) return 'rust';
    if (lower.endsWith('.json')) return 'json';
    if (lower.endsWith('.yaml') || lower.endsWith('.yml')) return 'yaml';
    if (lower.endsWith('.toml')) return 'toml';
    if (lower.includes('dockerfile')) return 'dockerfile';
    return 'generic';
  }
}
