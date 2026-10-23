import { 
  ArtifactParseResult, 
  ParsedSourceFacts, 
  FrameworkFingerprint, 
  ProtocolFact, 
  ProvenanceRecord 
} from './types.ts';
import { EncodingDetector } from './encoding-detector.ts';
import { ParserRegistry } from './parser-registry.ts';
import { cryptoHash } from './source-span-util.ts';

export interface ArtifactFileInput {
  path: string;
  content: string | Buffer | Uint8Array;
}

export class SyntaxIntelligencePipeline {
  public static readonly PIPELINE_VERSION = '1.0.0';

  /**
   * Processes quarantined artifact files into structured source facts with exact provenance
   * Strict invariant: Emits only pure structural/semantic facts without risk or policy judgements.
   * Strictly forbids missing files, synthetic/representative substitute code, or empty content.
   */
  public static processArtifact(
    artifactId: string,
    files: ArtifactFileInput[]
  ): ArtifactParseResult {
    const validFiles = files ? files.filter(f => f && f.content !== undefined && f.content !== null && (typeof f.content !== 'string' || f.content.trim().length > 0)) : [];
    if (!files || !Array.isArray(files) || files.length === 0 || validFiles.length === 0) {
      throw new Error(
        'AUTHENTIC_SOURCE_REQUIRED: Syntax intelligence pipeline cannot parse without authentic source files. ' +
        'Analysis without authentic acquired artifacts is strictly prohibited.'
      );
    }

    // Strictly reject synthetic, representative, or substitute files
    for (const f of validFiles) {
      if ((f as any).is_representative || (f as any).is_substitute || (f as any).is_synthetic || (f as any).is_mock) {
        throw new Error(
          'AUTHENTIC_SOURCE_REQUIRED: Synthetic or representative substitute code cannot be parsed or analyzed. ' +
          'Generating representative source is strictly forbidden.'
        );
      }
      if (typeof f.content === 'string') {
        const firstLines = f.content.slice(0, 300);
        if (/^\s*\/\/\s*(Sample entrypoint|Representative substitute|Synthetic substitute|Generated placeholder|Mock substitute)/i.test(firstLines)) {
          throw new Error(
            'AUTHENTIC_SOURCE_REQUIRED: Synthetic or representative substitute code cannot be parsed or analyzed. ' +
            'Generating representative source is strictly forbidden.'
          );
        }
      }
    }

    const fileFacts: ParsedSourceFacts[] = [];
    let totalBytes = 0;
    let parsedBytes = 0;
    let totalSymbols = 0;
    let totalProtocols = 0;
    let totalFrameworks = 0;
    let totalEnvVars = 0;
    let totalTools = 0;
    let totalModels = 0;

    let parsedCount = 0;
    let partialCount = 0;
    let unsupportedCount = 0;
    let failedCount = 0;

    const aggregateFrameworksMap = new Map<string, FrameworkFingerprint>();
    const aggregateProtocols: ProtocolFact[] = [];
    const envVarsCountMap = new Map<string, { count: number; required: boolean }>();
    const modelsCountMap = new Map<string, { provider?: string; count: number }>();
    const toolsMap = new Map<string, string | undefined>();
    const unsupportedArtifacts: Array<{ file_path: string; reason: string }> = [];

    const inputHashes: string[] = [];

    for (const file of files) {
      const contentStr = typeof file.content === 'string'
        ? file.content
        : Buffer.isBuffer(file.content)
          ? file.content.toString('utf-8')
          : Buffer.from(file.content).toString('utf-8');

      const fileType = EncodingDetector.detect(file.path, file.content);
      totalBytes += fileType.byte_size;

      inputHashes.push(cryptoHash(`${file.path}:${fileType.byte_size}:${fileType.encoding}`));

      const facts = ParserRegistry.parseFile(file.path, contentStr, fileType);
      fileFacts.push(facts);

      // Track status
      if (facts.status === 'SUCCESS') {
        parsedCount++;
        parsedBytes += fileType.byte_size;
      } else if (facts.status === 'PARTIAL_SUCCESS') {
        partialCount++;
        parsedBytes += Math.floor(fileType.byte_size * 0.7);
      } else if (facts.status === 'UNSUPPORTED_LANGUAGE' || facts.status === 'BINARY_PRESERVED') {
        unsupportedCount++;
        unsupportedArtifacts.push({
          file_path: file.path,
          reason: facts.partial_coverage_reason || `Unsupported format: ${fileType.language}`,
        });
      } else if (facts.status === 'PARSE_ERROR') {
        failedCount++;
        unsupportedArtifacts.push({
          file_path: file.path,
          reason: facts.error_details?.message || 'Syntax parse failure',
        });
      }

      // Aggregate symbols
      totalSymbols += facts.symbols.length;

      // Aggregate protocols
      totalProtocols += facts.protocols.length;
      for (const p of facts.protocols) {
        aggregateProtocols.push(p);
      }

      // Aggregate frameworks
      totalFrameworks += facts.frameworks.length;
      for (const f of facts.frameworks) {
        if (!aggregateFrameworksMap.has(f.framework_name) || (aggregateFrameworksMap.get(f.framework_name)!.confidence < f.confidence)) {
          aggregateFrameworksMap.set(f.framework_name, f);
        }
      }

      // Aggregate env vars
      totalEnvVars += facts.configuration.env_vars.length;
      for (const ev of facts.configuration.env_vars) {
        const existing = envVarsCountMap.get(ev.name);
        if (existing) {
          existing.count++;
          if (ev.required) existing.required = true;
        } else {
          envVarsCountMap.set(ev.name, { count: 1, required: ev.required });
        }
      }

      // Aggregate tools
      totalTools += facts.configuration.tools.length;
      for (const t of facts.configuration.tools) {
        if (!toolsMap.has(t.name) || (!toolsMap.get(t.name) && t.description)) {
          toolsMap.set(t.name, t.description);
        }
      }

      // Aggregate models
      totalModels += facts.configuration.models.length;
      for (const m of facts.configuration.models) {
        const existing = modelsCountMap.get(m.model_id);
        if (existing) {
          existing.count++;
        } else {
          modelsCountMap.set(m.model_id, { provider: m.provider, count: 1 });
        }
      }
    }

    const byteCoverageRatio = totalBytes > 0 ? Number((parsedBytes / totalBytes).toFixed(4)) : 1.0;

    const pipelineProvenance: ProvenanceRecord = {
      provenance_id: crypto.randomUUID(),
      source_spans: fileFacts.flatMap(f => f.provenance.source_spans).slice(0, 50),
      input_hashes: inputHashes.slice(0, 20),
      rule_id: 'SYNTAX_INTELLIGENCE_PIPELINE_AGGREGATE_V1',
      ruleset_version: this.PIPELINE_VERSION,
      transformation_type: 'SYNTAX_TRANSFORMATION',
      confidence: byteCoverageRatio > 0 ? Math.max(0.7, byteCoverageRatio) : 1.0,
      derived_at: new Date().toISOString(),
      engine_signature: `caim:syntax-intelligence-pipeline:v${this.PIPELINE_VERSION}`,
    };

    return {
      artifact_id: artifactId,
      total_files: files.length,
      parsed_files: parsedCount,
      partial_files: partialCount,
      unsupported_files: unsupportedCount,
      failed_files: failedCount,
      byte_coverage_ratio: byteCoverageRatio,
      total_symbols: totalSymbols,
      total_protocols: totalProtocols,
      total_frameworks: totalFrameworks,
      total_env_vars: totalEnvVars,
      total_tools: totalTools,
      total_models: totalModels,
      file_facts: fileFacts,
      aggregate_frameworks: Array.from(aggregateFrameworksMap.values()),
      aggregate_protocols: aggregateProtocols,
      aggregate_env_vars: Array.from(envVarsCountMap.entries()).map(([name, val]) => ({
        name,
        occurrences: val.count,
        required: val.required,
      })),
      aggregate_models: Array.from(modelsCountMap.entries()).map(([model_id, val]) => ({
        model_id,
        provider: val.provider,
        count: val.count,
      })),
      aggregate_tools: Array.from(toolsMap.entries()).map(([name, description]) => ({
        name,
        description,
      })),
      unsupported_artifacts: unsupportedArtifacts,
      provenance: pipelineProvenance,
    };
  }
}
