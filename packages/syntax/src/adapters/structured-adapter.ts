import { 
  SymbolFact, 
  ImportFact, 
  ExportFact, 
  SourceSpan,
  EnvVarRef,
  DeploymentCompute
} from '../types.ts';
import { SourceSpanUtil } from '../source-span-util.ts';

export interface StructuredParseOutput {
  format: string;
  data?: any;
  symbols: SymbolFact[];
  imports: ImportFact[];
  exports: ExportFact[];
  env_vars: EnvVarRef[];
  deployment?: DeploymentCompute;
  dependencies: Array<{ name: string; version: string; kind: string }>;
  has_parse_error: boolean;
  error_message?: string;
  error_location?: { line: number; col: number; offset: number };
}

export class StructuredAdapter {
  public static readonly ID = 'syntax-adapter:structured';
  public static readonly VERSION = '1.0.0';

  public static parse(filePath: string, sourceText: string, languageHint: string): StructuredParseOutput {
    const fileName = filePath.split('/').pop() || filePath;
    const lowerName = fileName.toLowerCase();

    if (lowerName === 'dockerfile' || lowerName.startsWith('dockerfile.') || lowerName === 'containerfile') {
      return this.parseDockerfile(filePath, sourceText);
    }
    if (lowerName === 'package.json') {
      return this.parsePackageJson(filePath, sourceText);
    }
    if (lowerName === 'pyproject.toml') {
      return this.parsePyprojectToml(filePath, sourceText);
    }
    if (lowerName === 'requirements.txt' || lowerName.startsWith('requirements-')) {
      return this.parseRequirementsTxt(filePath, sourceText);
    }
    if (lowerName === 'go.mod') {
      return this.parseGoMod(filePath, sourceText);
    }
    if (lowerName === 'cargo.toml') {
      return this.parseCargoToml(filePath, sourceText);
    }
    if (languageHint.includes('json') || lowerName.endsWith('.json')) {
      return this.parseJson(filePath, sourceText);
    }
    if (languageHint.includes('yaml') || lowerName.endsWith('.yaml') || lowerName.endsWith('.yml')) {
      return this.parseYaml(filePath, sourceText);
    }
    if (languageHint.includes('toml') || lowerName.endsWith('.toml')) {
      return this.parseToml(filePath, sourceText);
    }
    if (languageHint.includes('xml') || lowerName.endsWith('.xml')) {
      return this.parseXml(filePath, sourceText);
    }
    if (lowerName === '.env' || lowerName.startsWith('.env.')) {
      return this.parseDotEnv(filePath, sourceText);
    }

    return this.parseGenericStructured(filePath, sourceText);
  }

  private static parseDockerfile(filePath: string, source: string): StructuredParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(source);
    const env_vars: EnvVarRef[] = [];
    const symbols: SymbolFact[] = [];
    const ports: number[] = [];
    let baseImage: string | undefined;
    let workdir: string | undefined;
    const entrypoint: string[] = [];
    const cmd: string[] = [];

    const lines = source.split('\n');
    let offset = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      const lineLen = line.length + 1;

      if (!trimmed || trimmed.startsWith('#')) {
        offset += lineLen;
        continue;
      }

      const upper = trimmed.toUpperCase();

      if (upper.startsWith('FROM ')) {
        const parts = trimmed.substring(5).trim().split(/\s+/);
        baseImage = parts[0];
        const span = SourceSpanUtil.offsetToSpan(filePath, source, offset, offset + line.length, lineStarts, baseImage);
        symbols.push({
          name: baseImage,
          kind: 'MODULE',
          visibility: 'PUBLIC',
          span,
          parameters: [],
          modifiers: ['from_base_image'],
          decorators: [],
        });
      } else if (upper.startsWith('ENV ')) {
        const envContent = trimmed.substring(4).trim();
        const eqIdx = envContent.indexOf('=');
        let varName: string;
        let defaultVal: string | undefined;

        if (eqIdx !== -1) {
          varName = envContent.substring(0, eqIdx).trim();
          defaultVal = envContent.substring(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
        } else {
          const parts = envContent.split(/\s+/);
          varName = parts[0];
          defaultVal = parts.slice(1).join(' ').replace(/^["']|["']$/g, '');
        }

        const span = SourceSpanUtil.offsetToSpan(filePath, source, offset, offset + line.length, lineStarts, varName);
        env_vars.push({
          name: varName,
          required: false,
          default_value: defaultVal,
          reference_kind: 'DOCKERFILE_ENV',
          span,
        });
      } else if (upper.startsWith('EXPOSE ')) {
        const portStrs = trimmed.substring(7).trim().split(/\s+/);
        for (const p of portStrs) {
          const num = parseInt(p, 10);
          if (!isNaN(num)) ports.push(num);
        }
      } else if (upper.startsWith('WORKDIR ')) {
        workdir = trimmed.substring(8).trim();
      } else if (upper.startsWith('ENTRYPOINT ')) {
        entrypoint.push(trimmed.substring(11).trim());
      } else if (upper.startsWith('CMD ')) {
        cmd.push(trimmed.substring(4).trim());
      }

      offset += lineLen;
    }

    const deploymentSpan = SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, 'Dockerfile');

    return {
      format: 'Dockerfile',
      symbols,
      imports: [],
      exports: [],
      env_vars,
      deployment: {
        base_image: baseImage,
        ports,
        entrypoint,
        cmd,
        workdir,
        span: deploymentSpan,
      },
      dependencies: [],
      has_parse_error: false,
    };
  }

  private static parsePackageJson(filePath: string, source: string): StructuredParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(source);
    const imports: ImportFact[] = [];
    const dependencies: Array<{ name: string; version: string; kind: string }> = [];
    const symbols: SymbolFact[] = [];

    try {
      const parsed = JSON.parse(source);
      const span = SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, parsed.name || 'package.json');

      if (parsed.name) {
        symbols.push({
          name: parsed.name,
          kind: 'MODULE',
          visibility: 'PUBLIC',
          span,
          parameters: [],
          modifiers: parsed.version ? [`version:${parsed.version}`] : [],
          decorators: [],
        });
      }

      const depSections: Array<[string, Record<string, string> | undefined]> = [
        ['dependencies', parsed.dependencies],
        ['devDependencies', parsed.devDependencies],
        ['peerDependencies', parsed.peerDependencies],
        ['optionalDependencies', parsed.optionalDependencies],
      ];

      for (const [kind, depObj] of depSections) {
        if (!depObj) continue;
        for (const [pkgName, version] of Object.entries(depObj)) {
          dependencies.push({ name: pkgName, version: String(version), kind });
          imports.push({
            module_specifier: pkgName,
            import_kind: 'STATIC',
            imported_symbols: [{ name: pkgName, is_default: true, is_type_only: false, is_namespace: false }],
            span,
          });
        }
      }

      return {
        format: 'package.json',
        data: parsed,
        symbols,
        imports,
        exports: [],
        env_vars: [],
        dependencies,
        has_parse_error: false,
      };
    } catch (err: any) {
      return {
        format: 'package.json',
        symbols: [],
        imports: [],
        exports: [],
        env_vars: [],
        dependencies: [],
        has_parse_error: true,
        error_message: `JSON Syntax Error: ${err?.message}`,
      };
    }
  }

  private static parsePyprojectToml(filePath: string, source: string): StructuredParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(source);
    const dependencies: Array<{ name: string; version: string; kind: string }> = [];
    const imports: ImportFact[] = [];
    const symbols: SymbolFact[] = [];

    const lines = source.split('\n');
    let currentSection = '';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#')) continue;

      if (line.startsWith('[') && line.endsWith(']')) {
        currentSection = line.replace(/[[\]]/g, '').trim();
        continue;
      }

      if (currentSection === 'project' && line.startsWith('name =')) {
        const nameVal = line.split('=')[1]?.trim().replace(/^["']|["']$/g, '');
        if (nameVal) {
          const span = SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, nameVal);
          symbols.push({
            name: nameVal,
            kind: 'MODULE',
            visibility: 'PUBLIC',
            modifiers: [],
            span,
            parameters: [],
            decorators: [],
          });
        }
      }

      // Dependencies in [project.dependencies] or dependencies = [ ... ]
      if (line.startsWith('"') || line.startsWith("'")) {
        const clean = line.replace(/^["']|["'],?$/g, '').trim();
        const match = /^([a-zA-Z0-9_.-]+)(?:([<>=!~]+)([^,\s]+))?/.exec(clean);
        if (match) {
          const pkg = match[1];
          const ver = match[3] || 'latest';
          dependencies.push({ name: pkg, version: ver, kind: currentSection || 'dependencies' });
          imports.push({
            module_specifier: pkg,
            import_kind: 'STATIC',
            imported_symbols: [{ name: pkg, is_default: true, is_type_only: false, is_namespace: false }],
            span: SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, pkg),
          });
        }
      }
    }

    return {
      format: 'pyproject.toml',
      symbols,
      imports,
      exports: [],
      env_vars: [],
      dependencies,
      has_parse_error: false,
    };
  }

  private static parseRequirementsTxt(filePath: string, source: string): StructuredParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(source);
    const dependencies: Array<{ name: string; version: string; kind: string }> = [];
    const imports: ImportFact[] = [];
    const lines = source.split('\n');
    let offset = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      const lineLen = line.length + 1;

      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) {
        offset += lineLen;
        continue;
      }

      const match = /^([a-zA-Z0-9_.-]+)(?:\s*([<>=!~]+)\s*([^\s;#]+))?/.exec(trimmed);
      if (match) {
        const pkg = match[1];
        const ver = match[3] || '*';
        const span = SourceSpanUtil.offsetToSpan(filePath, source, offset, offset + line.length, lineStarts, pkg);

        dependencies.push({ name: pkg, version: ver, kind: 'requirements' });
        imports.push({
          module_specifier: pkg,
          import_kind: 'STATIC',
          imported_symbols: [{ name: pkg, is_default: true, is_type_only: false, is_namespace: false }],
          span,
        });
      }

      offset += lineLen;
    }

    return {
      format: 'requirements.txt',
      symbols: [],
      imports,
      exports: [],
      env_vars: [],
      dependencies,
      has_parse_error: false,
    };
  }

  private static parseGoMod(filePath: string, source: string): StructuredParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(source);
    const dependencies: Array<{ name: string; version: string; kind: string }> = [];
    const imports: ImportFact[] = [];
    const symbols: SymbolFact[] = [];

    const lines = source.split('\n');
    let inRequireBlock = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('//')) continue;

      if (line.startsWith('module ')) {
        const modName = line.substring(7).trim();
        symbols.push({
          name: modName,
          kind: 'MODULE',
          visibility: 'PUBLIC',
          modifiers: [],
          span: SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, modName),
          parameters: [],
          decorators: [],
        });
      } else if (line.startsWith('require (')) {
        inRequireBlock = true;
      } else if (line === ')' && inRequireBlock) {
        inRequireBlock = false;
      } else if (inRequireBlock || line.startsWith('require ')) {
        const clean = line.replace(/^require\s+/, '').trim();
        const parts = clean.split(/\s+/);
        if (parts.length >= 2) {
          const pkg = parts[0];
          const ver = parts[1];
          dependencies.push({ name: pkg, version: ver, kind: 'go.mod require' });
          imports.push({
            module_specifier: pkg,
            import_kind: 'STATIC',
            imported_symbols: [{ name: pkg, is_default: true, is_type_only: false, is_namespace: false }],
            span: SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, pkg),
          });
        }
      }
    }

    return {
      format: 'go.mod',
      symbols,
      imports,
      exports: [],
      env_vars: [],
      dependencies,
      has_parse_error: false,
    };
  }

  private static parseCargoToml(filePath: string, source: string): StructuredParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(source);
    const dependencies: Array<{ name: string; version: string; kind: string }> = [];
    const imports: ImportFact[] = [];
    const symbols: SymbolFact[] = [];

    const lines = source.split('\n');
    let currentSection = '';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#')) continue;

      if (line.startsWith('[') && line.endsWith(']')) {
        currentSection = line.replace(/[[\]]/g, '').trim();
        continue;
      }

      if (currentSection === 'package' && line.startsWith('name =')) {
        const nameVal = line.split('=')[1]?.trim().replace(/^["']|["']$/g, '');
        if (nameVal) {
          symbols.push({
            name: nameVal,
            kind: 'MODULE',
            visibility: 'PUBLIC',
            modifiers: [],
            span: SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, nameVal),
            parameters: [],
            decorators: [],
          });
        }
      } else if (currentSection.includes('dependencies') && line.includes('=')) {
        const [pkg, rest] = line.split('=');
        const pkgName = pkg.trim();
        const ver = rest.trim().replace(/^["']|["']$/g, '');
        dependencies.push({ name: pkgName, version: ver, kind: currentSection });
        imports.push({
          module_specifier: pkgName,
          import_kind: 'STATIC',
          imported_symbols: [{ name: pkgName, is_default: true, is_type_only: false, is_namespace: false }],
          span: SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, pkgName),
        });
      }
    }

    return {
      format: 'Cargo.toml',
      symbols,
      imports,
      exports: [],
      env_vars: [],
      dependencies,
      has_parse_error: false,
    };
  }

  private static parseJson(filePath: string, source: string): StructuredParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(source);
    try {
      const parsed = JSON.parse(source);
      return {
        format: 'json',
        data: parsed,
        symbols: [],
        imports: [],
        exports: [],
        env_vars: [],
        dependencies: [],
        has_parse_error: false,
      };
    } catch (err: any) {
      return {
        format: 'json',
        symbols: [],
        imports: [],
        exports: [],
        env_vars: [],
        dependencies: [],
        has_parse_error: true,
        error_message: err?.message || 'Invalid JSON syntax',
      };
    }
  }

  private static parseYaml(filePath: string, source: string): StructuredParseOutput {
    const symbols: SymbolFact[] = [];
    const lineStarts = SourceSpanUtil.createLineIndex(source);
    const lines = source.split('\n');

    // Key extraction
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const match = /^([a-zA-Z0-9_.-]+)\s*:\s*(.*)/.exec(line);
      if (match) {
        const key = match[1];
        symbols.push({
          name: key,
          kind: 'PROPERTY',
          visibility: 'PUBLIC',
          modifiers: [],
          span: SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, key),
          parameters: [],
          decorators: [],
        });
      }
    }

    return {
      format: 'yaml',
      symbols,
      imports: [],
      exports: [],
      env_vars: [],
      dependencies: [],
      has_parse_error: false,
    };
  }

  private static parseToml(filePath: string, source: string): StructuredParseOutput {
    return {
      format: 'toml',
      symbols: [],
      imports: [],
      exports: [],
      env_vars: [],
      dependencies: [],
      has_parse_error: false,
    };
  }

  private static parseXml(filePath: string, source: string): StructuredParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(source);
    const symbols: SymbolFact[] = [];
    const tagRegex = /<([a-zA-Z0-9_.-]+)(?:\s+[^>]*)?>/g;
    let match: RegExpExecArray | null;

    while ((match = tagRegex.exec(source)) !== null) {
      const tagName = match[1];
      if (tagName.startsWith('/') || tagName.startsWith('!')) continue;
      symbols.push({
        name: tagName,
        kind: 'STRUCT',
        visibility: 'PUBLIC',
        modifiers: [],
        span: SourceSpanUtil.offsetToSpan(filePath, source, match.index, match.index + match[0].length, lineStarts, tagName),
        parameters: [],
        decorators: [],
      });
    }

    return {
      format: 'xml',
      symbols,
      imports: [],
      exports: [],
      env_vars: [],
      dependencies: [],
      has_parse_error: false,
    };
  }

  private static parseDotEnv(filePath: string, source: string): StructuredParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(source);
    const env_vars: EnvVarRef[] = [];
    const lines = source.split('\n');
    let offset = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      const lineLen = line.length + 1;

      if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
        const [k, v] = trimmed.split('=');
        const varName = k.trim();
        const defaultVal = v?.trim().replace(/^["']|["']$/g, '');
        const span = SourceSpanUtil.offsetToSpan(filePath, source, offset, offset + line.length, lineStarts, varName);

        env_vars.push({
          name: varName,
          required: false,
          default_value: defaultVal,
          reference_kind: 'DOTENV',
          span,
        });
      }

      offset += lineLen;
    }

    return {
      format: 'dotenv',
      symbols: [],
      imports: [],
      exports: [],
      env_vars,
      dependencies: [],
      has_parse_error: false,
    };
  }

  private static parseGenericStructured(filePath: string, source: string): StructuredParseOutput {
    return {
      format: 'generic',
      symbols: [],
      imports: [],
      exports: [],
      env_vars: [],
      dependencies: [],
      has_parse_error: false,
    };
  }
}
