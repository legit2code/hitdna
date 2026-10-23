import { 
  ConfigurationFact, 
  EnvVarRef, 
  ToolDeclaration, 
  ModelReference, 
  PermissionRef, 
  SecretReference, 
  SourceSpan,
  PermissionCapability
} from '../types.ts';
import { SourceSpanUtil } from '../source-span-util.ts';

export class ConfigExtractor {
  /**
   * Extracts environment variables, tool declarations, model references, permissions, and secrets
   */
  public static extract(
    filePath: string,
    sourceText: string,
    initialEnvVars: EnvVarRef[] = []
  ): ConfigurationFact {
    const lineStarts = SourceSpanUtil.createLineIndex(sourceText);

    const envVars = [...initialEnvVars, ...this.extractEnvVars(filePath, sourceText, lineStarts)];
    const tools = this.extractTools(filePath, sourceText, lineStarts);
    const models = this.extractModels(filePath, sourceText, lineStarts);
    const permissions = this.extractPermissions(filePath, sourceText, lineStarts);
    const secrets = this.extractSecrets(filePath, sourceText, lineStarts, envVars);

    return {
      env_vars: this.deduplicateEnvVars(envVars),
      tools,
      models,
      permissions,
      secrets,
    };
  }

  private static extractEnvVars(filePath: string, source: string, lineStarts: number[]): EnvVarRef[] {
    const envVars: EnvVarRef[] = [];

    // 1. JS/TS: process.env.VAR_NAME or process.env['VAR_NAME']
    const jsEnvRegex = /process\.env(?:\.([A-Z0-9_]+)|\[['"]([A-Z0-9_]+)['"]\])/g;
    let match: RegExpExecArray | null;
    while ((match = jsEnvRegex.exec(source)) !== null) {
      const varName = match[1] || match[2];
      const span = SourceSpanUtil.offsetToSpan(filePath, source, match.index, match.index + match[0].length, lineStarts, varName);
      envVars.push({
        name: varName,
        required: source.substring(match.index, match.index + match[0].length + 10).includes('!') || false,
        reference_kind: 'PROCESS_ENV',
        span,
      });
    }

    // 2. Python: os.environ.get("VAR"), os.getenv("VAR"), os.environ["VAR"]
    const pyEnvRegex = /(?:os\.environ\.get|os\.getenv|os\.environ\[)\s*\(?\s*['"]([A-Z0-9_]+)['"](?:\s*,\s*(?:['"]([^'"]*)['"]|([^)]+)))?\)?/g;
    while ((match = pyEnvRegex.exec(source)) !== null) {
      const varName = match[1];
      const defaultVal = match[2] || (match[3] ? match[3].trim() : undefined);
      const span = SourceSpanUtil.offsetToSpan(filePath, source, match.index, match.index + match[0].length, lineStarts, varName);
      envVars.push({
        name: varName,
        required: match[0].includes('os.environ[') && !defaultVal,
        default_value: defaultVal,
        reference_kind: 'OS_ENV',
        span,
      });
    }

    // 3. Go: os.Getenv("VAR") or os.LookupEnv("VAR")
    const goEnvRegex = /os\.(?:Getenv|LookupEnv)\s*\(\s*["']([A-Z0-9_]+)["']\s*\)/g;
    while ((match = goEnvRegex.exec(source)) !== null) {
      const varName = match[1];
      const span = SourceSpanUtil.offsetToSpan(filePath, source, match.index, match.index + match[0].length, lineStarts, varName);
      envVars.push({
        name: varName,
        required: false,
        reference_kind: 'OS_ENV',
        span,
      });
    }

    return envVars;
  }

  private static extractTools(filePath: string, source: string, lineStarts: number[]): ToolDeclaration[] {
    const tools: ToolDeclaration[] = [];

    // 1. Python @tool decorator: @tool\ndef tool_name(...):
    const pyToolRegex = /@(?:tool|mcp\.tool|structured_tool|langchain_core\.tools\.tool)(?:\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+([\w]+)\s*\(([^)]*)\)(?:\s*->\s*[^:]+)?:\s*(?:"""([\s\S]*?)"""|'''([\s\S]*?)''')?/g;
    let match: RegExpExecArray | null;

    while ((match = pyToolRegex.exec(source)) !== null) {
      const toolName = match[1];
      const docstring = match[3] || match[4];
      const span = SourceSpanUtil.offsetToSpan(filePath, source, match.index, match.index + match[0].length, lineStarts, toolName);

      tools.push({
        name: toolName,
        description: docstring ? docstring.trim() : `Tool function ${toolName}`,
        declaration_kind: 'DECORATOR',
        span,
      });
    }

    // 2. JS/TS tool helper: tool(async (input) => ..., { name: 'tool_name', description: '...' })
    const jsToolRegex = /tool\s*\(\s*(?:async\s*)?\([^)]*\)\s*=>[\s\S]*?,\s*\{\s*name:\s*['"]([^'"]+)['"](?:\s*,\s*description:\s*['"]([^'"]*)['"])?/g;
    while ((match = jsToolRegex.exec(source)) !== null) {
      const toolName = match[1];
      const desc = match[2];
      const span = SourceSpanUtil.offsetToSpan(filePath, source, match.index, match.index + match[0].length, lineStarts, toolName);

      tools.push({
        name: toolName,
        description: desc || undefined,
        declaration_kind: 'FUNCTION_CALL',
        span,
      });
    }

    // 3. CrewAI Tool classes: class MyCustomTool(BaseTool):
    const crewToolRegex = /class\s+([\w]+)\s*\(\s*(?:BaseTool|Tool)\s*\):[\s\S]*?name\s*(?::\s*str\s*)?=\s*["']([^"']+)["'](?:\s*description\s*(?::\s*str\s*)?=\s*["']([^"']*)["'])?/g;
    while ((match = crewToolRegex.exec(source)) !== null) {
      const className = match[1];
      const toolName = match[2] || className;
      const desc = match[3];
      const span = SourceSpanUtil.offsetToSpan(filePath, source, match.index, match.index + match[0].length, lineStarts, toolName);

      tools.push({
        name: toolName,
        description: desc || `Custom tool class ${className}`,
        declaration_kind: 'CLASS_METHOD',
        span,
      });
    }

    return tools;
  }

  private static extractModels(filePath: string, source: string, lineStarts: number[]): ModelReference[] {
    const models: ModelReference[] = [];
    const knownModels = [
      { pattern: /(?:gpt-4o(?:-mini)?|gpt-4-turbo|gpt-4|gpt-3\.5-turbo)/gi, provider: 'openai' },
      { pattern: /(?:gemini-1\.5-pro|gemini-1\.5-flash|gemini-2\.0-flash|gemini-pro)/gi, provider: 'google' },
      { pattern: /(?:claude-3-5-sonnet|claude-3-opus|claude-3-haiku|claude-2\.1)/gi, provider: 'anthropic' },
      { pattern: /(?:llama-3\.1-(?:8b|70b|405b)|llama-3-(?:8b|70b)|llama-2)/gi, provider: 'meta' },
      { pattern: /(?:deepseek-(?:r1|v3|chat|coder))/gi, provider: 'deepseek' },
      { pattern: /(?:mistral-(?:large|medium|small)|mixtral-8x7b)/gi, provider: 'mistral' },
      { pattern: /(?:qwen-2\.5|qwen-2)/gi, provider: 'alibaba' },
    ];

    for (const km of knownModels) {
      const regex = new RegExp(km.pattern.source, 'gi');
      let match: RegExpExecArray | null;

      while ((match = regex.exec(source)) !== null) {
        const modelId = match[0].toLowerCase();
        const span = SourceSpanUtil.offsetToSpan(filePath, source, match.index, match.index + match[0].length, lineStarts, modelId);

        // Check if temperature or max_tokens is configured nearby
        const surroundingSlice = source.substring(Math.max(0, match.index - 50), Math.min(source.length, match.index + 150));
        const tempMatch = /temperature\s*(?::|=)\s*([0-9.]+)/i.exec(surroundingSlice);
        const tokensMatch = /(?:max_tokens|maxTokens)\s*(?::|=)\s*([0-9]+)/i.exec(surroundingSlice);

        models.push({
          model_id: modelId,
          provider: km.provider,
          temperature: tempMatch ? parseFloat(tempMatch[1]) : undefined,
          max_tokens: tokensMatch ? parseInt(tokensMatch[1], 10) : undefined,
          span,
        });
      }
    }

    return models;
  }

  private static extractPermissions(filePath: string, source: string, lineStarts: number[]): PermissionRef[] {
    const permissions: PermissionRef[] = [];

    const capabilityMatchers: Array<{
      capability: PermissionCapability;
      pattern: RegExp;
      description: string;
    }> = [
      {
        capability: 'FILESYSTEM',
        pattern: /(?:fs\.readFile|fs\.writeFile|open\(|os\.remove|os\.mkdir|pathlib\.Path|ioutil\.ReadFile|os\.Create)/,
        description: 'Direct local filesystem read/write operations',
      },
      {
        capability: 'NETWORK',
        pattern: /(?:fetch\(|axios\.|requests\.|http\.Get|aiohttp\.ClientSession|urllib\.request|net\.Dial)/,
        description: 'Outbound network HTTP/socket communication',
      },
      {
        capability: 'SUBPROCESS_EXEC',
        pattern: /(?:child_process|subprocess\.run|subprocess\.Popen|os\.system|exec\.Command)/,
        description: 'Operating system subprocess execution',
      },
      {
        capability: 'DATABASE',
        pattern: /(?:createTestDb|pg\.Client|sqlite3|mongoose\.connect|prisma\.|drizzle\(|psycopg2|gorm\.Open)/,
        description: 'Database client connection and query execution',
      },
      {
        capability: 'BROWSER_AUTOMATION',
        pattern: /(?:playwright|puppeteer|selenium|webdriver|chromium\.launch)/,
        description: 'Headless browser automation and DOM interaction',
      },
      {
        capability: 'AUDIO_MEDIA',
        pattern: /(?:navigator\.mediaDevices|AudioContext|whisper|pyaudio|sounddevice)/,
        description: 'Audio recording, playback, or transcription processing',
      },
      {
        capability: 'ENVIRONMENT_ACCESS',
        pattern: /(?:process\.env|os\.environ|os\.getenv|os\.Getenv)/,
        description: 'Access to host environment variables',
      },
    ];

    for (const cm of capabilityMatchers) {
      const match = cm.pattern.exec(source);
      if (match) {
        const span = SourceSpanUtil.offsetToSpan(filePath, source, match.index, match.index + match[0].length, lineStarts, cm.capability);
        permissions.push({
          capability: cm.capability,
          description: cm.description,
          span,
        });
      }
    }

    return permissions;
  }

  private static extractSecrets(
    filePath: string,
    source: string,
    lineStarts: number[],
    envVars: EnvVarRef[]
  ): SecretReference[] {
    const secrets: SecretReference[] = [];

    // 1. Env-based secret names
    for (const ev of envVars) {
      const upper = ev.name.toUpperCase();
      let category: 'API_KEY' | 'BEARER_TOKEN' | 'PASSWORD' | 'PRIVATE_KEY' | 'VAULT_SECRET' | null = null;

      if (upper.includes('API_KEY') || upper.includes('APIKEY')) category = 'API_KEY';
      else if (upper.includes('TOKEN') || upper.includes('JWT') || upper.includes('AUTH')) category = 'BEARER_TOKEN';
      else if (upper.includes('PASSWORD') || upper.includes('PASS') || upper.includes('SECRET')) category = 'PASSWORD';
      else if (upper.includes('PRIVATE_KEY') || upper.includes('RSA') || upper.includes('CERT')) category = 'PRIVATE_KEY';
      else if (upper.includes('VAULT') || upper.includes('CREDENTIAL')) category = 'VAULT_SECRET';

      if (category) {
        secrets.push({
          secret_name: ev.name,
          category,
          detection_kind: 'ENV_PATTERN',
          is_masked: true,
          span: ev.span,
        });
      }
    }

    // 2. Secret Vault clients
    const vaultClients = [
      { pattern: /SecretsManagerClient|aws-sdk\/client-secrets-manager/, name: 'AWS_SECRETS_MANAGER', category: 'VAULT_SECRET' as const },
      { pattern: /SecretManagerServiceClient|@google-cloud\/secret-manager/, name: 'GCP_SECRET_MANAGER', category: 'VAULT_SECRET' as const },
      { pattern: /SecretClient|@azure\/keyvault-secrets/, name: 'AZURE_KEY_VAULT', category: 'VAULT_SECRET' as const },
      { pattern: /node-vault|hvac\.Client/, name: 'HASHICORP_VAULT', category: 'VAULT_SECRET' as const },
    ];

    for (const vc of vaultClients) {
      const match = vc.pattern.exec(source);
      if (match) {
        const span = SourceSpanUtil.offsetToSpan(filePath, source, match.index, match.index + match[0].length, lineStarts, vc.name);
        secrets.push({
          secret_name: vc.name,
          category: vc.category,
          detection_kind: 'VAULT_CLIENT',
          is_masked: true,
          span,
        });
      }
    }

    return secrets;
  }

  private static deduplicateEnvVars(vars: EnvVarRef[]): EnvVarRef[] {
    const seen = new Set<string>();
    const result: EnvVarRef[] = [];
    for (const v of vars) {
      if (!seen.has(v.name)) {
        seen.add(v.name);
        result.push(v);
      }
    }
    return result;
  }
}
