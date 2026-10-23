import { 
  FileTypeInfo, 
  ParsedSourceFacts, 
  ParserStatus,
  ProvenanceRecord 
} from './types.ts';
import { JsTsAdapter } from './adapters/js-ts-adapter.ts';
import { PythonAdapter } from './adapters/python-adapter.ts';
import { GoAdapter } from './adapters/go-adapter.ts';
import { StructuredAdapter } from './adapters/structured-adapter.ts';
import { ProtocolDetector } from './protocols/protocol-detector.ts';
import { FrameworkDetector } from './frameworks/framework-detector.ts';
import { ConfigExtractor } from './config/config-extractor.ts';
import { SourceSpanUtil, cryptoHash } from './source-span-util.ts';

export interface ParserHandler {
  id: string;
  version: string;
  canHandle(fileType: FileTypeInfo): boolean;
  parse(filePath: string, sourceText: string, fileType: FileTypeInfo): Partial<ParsedSourceFacts>;
}

export class ParserRegistry {
  private static handlers: ParserHandler[] = [];

  static {
    this.registerBuiltins();
  }

  public static registerBuiltins(): void {
    this.handlers = [
      // 1. JavaScript & TypeScript
      {
        id: JsTsAdapter.ID,
        version: JsTsAdapter.VERSION,
        canHandle: (ft) => ['typescript', 'typescriptreact', 'javascript', 'javascriptreact'].includes(ft.language),
        parse: (filePath, sourceText) => {
          const out = JsTsAdapter.parse(filePath, sourceText);
          return {
            symbols: out.symbols,
            imports: out.imports,
            exports: out.exports,
            call_sites: out.call_sites,
            status: out.has_parse_error ? 'PARTIAL_SUCCESS' : 'SUCCESS',
            confidence: out.has_parse_error ? 0.6 : 1.0,
            partial_coverage_reason: out.has_parse_error ? out.error_message : undefined,
            error_details: out.has_parse_error && out.error_message ? { message: out.error_message } : undefined,
          };
        },
      },
      // 2. Python
      {
        id: PythonAdapter.ID,
        version: PythonAdapter.VERSION,
        canHandle: (ft) => ft.language === 'python',
        parse: (filePath, sourceText) => {
          const out = PythonAdapter.parse(filePath, sourceText);
          return {
            symbols: out.symbols,
            imports: out.imports,
            exports: out.exports,
            call_sites: out.call_sites,
            status: out.has_parse_error ? 'PARTIAL_SUCCESS' : 'SUCCESS',
            confidence: out.has_parse_error ? 0.6 : 1.0,
            partial_coverage_reason: out.has_parse_error ? out.error_message : undefined,
            error_details: out.has_parse_error && out.error_message ? { message: out.error_message } : undefined,
          };
        },
      },
      // 3. Go
      {
        id: GoAdapter.ID,
        version: GoAdapter.VERSION,
        canHandle: (ft) => ft.language === 'go',
        parse: (filePath, sourceText) => {
          const out = GoAdapter.parse(filePath, sourceText);
          return {
            symbols: out.symbols,
            imports: out.imports,
            exports: out.exports,
            call_sites: out.call_sites,
            status: out.has_parse_error ? 'PARTIAL_SUCCESS' : 'SUCCESS',
            confidence: out.has_parse_error ? 0.6 : 1.0,
            partial_coverage_reason: out.has_parse_error ? out.error_message : undefined,
            error_details: out.has_parse_error && out.error_message ? { message: out.error_message } : undefined,
          };
        },
      },
      // 4. Structured Data & Manifests
      {
        id: StructuredAdapter.ID,
        version: StructuredAdapter.VERSION,
        canHandle: (ft) => ft.format_category === 'STRUCTURED_DATA' || ft.format_category === 'CONTAINER_INFRA' || ft.format_category === 'SPECIFICATION_SCHEMA',
        parse: (filePath, sourceText, fileType) => {
          const out = StructuredAdapter.parse(filePath, sourceText, fileType.language);
          return {
            symbols: out.symbols,
            imports: out.imports,
            exports: out.exports,
            call_sites: [],
            status: out.has_parse_error ? 'PARSE_ERROR' : 'SUCCESS',
            confidence: out.has_parse_error ? 0.3 : 1.0,
            partial_coverage_reason: out.has_parse_error ? out.error_message : undefined,
            error_details: out.has_parse_error && out.error_message ? { message: out.error_message } : undefined,
            _data: out.data,
            _dependencies: out.dependencies,
            _env_vars: out.env_vars,
            _deployment: out.deployment,
          } as any;
        },
      },
    ];
  }

  public static register(handler: ParserHandler): void {
    this.handlers.unshift(handler);
  }

  /**
   * Dispatches file parsing to registered adapters with fallback chains and comprehensive fact extraction
   */
  public static parseFile(
    filePath: string,
    sourceText: string,
    fileType: FileTypeInfo
  ): ParsedSourceFacts {
    const inputHash = cryptoHash(`${filePath}:${sourceText}`);
    const lineStarts = SourceSpanUtil.createLineIndex(sourceText);

    // 1. Binary / Compiled preservation
    if (fileType.is_binary || fileType.format_category === 'BINARY_COMPILED') {
      const span = SourceSpanUtil.offsetToSpan(filePath, sourceText, 0, Math.min(100, sourceText.length), lineStarts, 'BINARY_PRESERVED');
      const provenance: ProvenanceRecord = {
        provenance_id: crypto.randomUUID(),
        source_spans: [span],
        input_hashes: [inputHash],
        rule_id: 'BINARY_ARTIFACT_PRESERVATION_V1',
        ruleset_version: '1.0.0',
        transformation_type: 'DIRECT_EXTRACTION',
        confidence: 1.0,
        derived_at: new Date().toISOString(),
        engine_signature: 'caim:syntax:binary-preservation:v1.0.0',
      };

      return {
        file_path: filePath,
        file_type: fileType,
        parser_id: 'binary-preservation-adapter',
        parser_version: '1.0.0',
        status: 'BINARY_PRESERVED',
        confidence: 1.0,
        partial_coverage_reason: 'Binary artifact preserved verbatim without AST decomposition',
        symbols: [],
        imports: [],
        exports: [],
        call_sites: [],
        protocols: [],
        frameworks: [],
        configuration: {
          env_vars: [],
          tools: [],
          models: [],
          permissions: [],
          secrets: [],
        },
        raw_content_preview: `[Binary content size: ${fileType.byte_size} bytes, magic: ${fileType.magic_signature || 'none'}]`,
        provenance,
      };
    }

    // 2. Locate matching handler
    const handler = this.handlers.find(h => h.canHandle(fileType));

    if (!handler) {
      // Unsupported language preservation
      const span = SourceSpanUtil.offsetToSpan(filePath, sourceText, 0, Math.min(100, sourceText.length), lineStarts, 'UNSUPPORTED_LANGUAGE');
      const provenance: ProvenanceRecord = {
        provenance_id: crypto.randomUUID(),
        source_spans: [span],
        input_hashes: [inputHash],
        rule_id: 'UNSUPPORTED_LANGUAGE_PRESERVATION_V1',
        ruleset_version: '1.0.0',
        transformation_type: 'DIRECT_EXTRACTION',
        confidence: 0.8,
        derived_at: new Date().toISOString(),
        engine_signature: 'caim:syntax:unsupported-preservation:v1.0.0',
      };

      return {
        file_path: filePath,
        file_type: fileType,
        parser_id: 'unsupported-adapter',
        parser_version: '1.0.0',
        status: 'UNSUPPORTED_LANGUAGE',
        confidence: 0.5,
        partial_coverage_reason: `No specialized parser registered for language: ${fileType.language} (${fileType.format_category})`,
        symbols: [],
        imports: [],
        exports: [],
        call_sites: [],
        protocols: [],
        frameworks: [],
        configuration: {
          env_vars: [],
          tools: [],
          models: [],
          permissions: [],
          secrets: [],
        },
        raw_content_preview: sourceText.substring(0, 300),
        provenance,
      };
    }

    // 3. Execute handler
    const parsedPartial = handler.parse(filePath, sourceText, fileType);
    const parsedData = (parsedPartial as any)._data;
    const parsedDeps = (parsedPartial as any)._dependencies || [];
    const parsedInitialEnv = (parsedPartial as any)._env_vars || [];
    const parsedDeployment = (parsedPartial as any)._deployment;

    // 4. Run Protocols, Frameworks, and Configuration Intelligence
    const protocols = ProtocolDetector.detect(filePath, sourceText, parsedData);
    const frameworks = FrameworkDetector.detect(filePath, sourceText, parsedDeps);
    const configuration = ConfigExtractor.extract(filePath, sourceText, parsedInitialEnv);
    if (parsedDeployment) {
      configuration.deployment = parsedDeployment;
    }

    const span = SourceSpanUtil.offsetToSpan(filePath, sourceText, 0, sourceText.length, lineStarts, filePath);
    const provenance: ProvenanceRecord = {
      provenance_id: crypto.randomUUID(),
      source_spans: [span],
      input_hashes: [inputHash],
      rule_id: `PARSER_${handler.id.toUpperCase()}_V1`,
      ruleset_version: handler.version,
      transformation_type: 'SYNTAX_TRANSFORMATION',
      confidence: parsedPartial.confidence ?? 1.0,
      derived_at: new Date().toISOString(),
      engine_signature: `caim:${handler.id}:v${handler.version}`,
    };

    return {
      file_path: filePath,
      file_type: fileType,
      parser_id: handler.id,
      parser_version: handler.version,
      status: (parsedPartial.status as ParserStatus) || 'SUCCESS',
      confidence: parsedPartial.confidence ?? 1.0,
      partial_coverage_reason: parsedPartial.partial_coverage_reason,
      error_details: parsedPartial.error_details,
      symbols: parsedPartial.symbols || [],
      imports: parsedPartial.imports || [],
      exports: parsedPartial.exports || [],
      call_sites: parsedPartial.call_sites || [],
      protocols,
      frameworks,
      configuration,
      raw_content_preview: sourceText.length > 500 ? sourceText.substring(0, 497) + '...' : sourceText,
      provenance,
    };
  }
}
