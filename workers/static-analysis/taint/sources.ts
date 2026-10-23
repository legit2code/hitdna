/**
 * Versioned Taint Source Registry
 * P16 — Dataflow / Taint Intelligence
 */

import { TaintSourceDefinition, TAINT_SOURCE_REGISTRY_VERSION } from './types.ts';

export class TaintSourceRegistry {
  public static readonly REGISTRY_VERSION = TAINT_SOURCE_REGISTRY_VERSION;

  public static readonly SOURCES: TaintSourceDefinition[] = [
    // 1. Hardcoded Credentials & Secret Literals
    {
      source_id: 'SRC-CRED-001',
      category: 'CREDENTIAL_SECRET',
      name: 'Hardcoded Secret / API Token Literal',
      description: 'Hardcoded API key, private key header, bearer token, or password string literal in source.',
      pattern_type: 'LITERAL_REGEX',
      match_patterns: [
        /sk-[a-zA-Z0-9_\-]{20,}/i,
        /ghp_[a-zA-Z0-9]{30,}/i,
        /glpat-[a-zA-Z0-9\-]{20,}/i,
        /eyJ[a-zA-Z0-9_\-]{15,}\.eyJ[a-zA-Z0-9_\-]{15,}/i, // JWT
        /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/,
        /(?:password|passwd|secret|api_key|apiKey|auth_token)\s*[:=]\s*["'][^"']{8,}["']/i
      ],
      base_confidence: 0.98,
      sensitivity_level: 'CRITICAL',
    },

    // 2. Sensitive Environment Variables
    {
      source_id: 'SRC-ENV-001',
      category: 'ENVIRONMENT_SECRET',
      name: 'Sensitive Environment Variable Access',
      description: 'Source code reads known sensitive environment variable (API_KEY, SECRET, TOKEN, PRIVATE_KEY).',
      pattern_type: 'MEMBER_ACCESS',
      match_member_roots: ['process.env', 'os.environ', 'os.Getenv', 'process.env.'],
      match_identifiers: [
        'API_KEY', 'SECRET_KEY', 'DATABASE_URL', 'AUTH_TOKEN', 'AWS_SECRET_ACCESS_KEY',
        'STRIPE_KEY', 'OPENAI_API_KEY', 'GEMINI_API_KEY', 'GITHUB_TOKEN', 'PRIVATE_KEY',
        'DB_PASSWORD', 'PASSWORD', 'SECRET'
      ],
      base_confidence: 0.95,
      sensitivity_level: 'HIGH',
    },

    // 3. Filesystem Reads
    {
      source_id: 'SRC-FS-001',
      category: 'FILESYSTEM_READ',
      name: 'Local Filesystem Ingestion',
      description: 'Result of local file read operation (fs.readFileSync, open(), ioutil.ReadFile, fs.readFile).',
      pattern_type: 'FUNCTION_CALL',
      match_functions: [
        'fs.readFileSync', 'fs.readFile', 'fs.promises.readFile',
        'open', 'os.ReadFile', 'ioutil.ReadFile', 'f.read', 'readline'
      ],
      base_confidence: 0.94,
      sensitivity_level: 'MEDIUM',
    },

    // 4. Sensitive OS Paths Read
    {
      source_id: 'SRC-FS-002',
      category: 'FILESYSTEM_READ',
      name: 'Sensitive System Path Read',
      description: 'Filesystem read specifically targeting sensitive system files (/etc/passwd, ~/.ssh, /etc/shadow).',
      pattern_type: 'LITERAL_REGEX',
      match_patterns: [
        /\/etc\/passwd/,
        /\/etc\/shadow/,
        /\.ssh\/id_rsa/,
        /\/proc\/self\/environ/,
        /C:\\Windows\\System32\\config/
      ],
      base_confidence: 0.99,
      sensitivity_level: 'CRITICAL',
    },

    // 5. Ingress User / Tool Inputs
    {
      source_id: 'SRC-INPUT-001',
      category: 'USER_INPUT',
      name: 'External Request / User Parameter',
      description: 'Direct user input or webhook payload parameter (req.body, req.query, req.params, sys.argv).',
      pattern_type: 'MEMBER_ACCESS',
      match_member_roots: ['req.body', 'req.query', 'req.params', 'request.json', 'sys.argv', 'args'],
      base_confidence: 0.90,
      sensitivity_level: 'MEDIUM',
    },

    // 6. Tool / MCP Argument Ingestion
    {
      source_id: 'SRC-TOOL-001',
      category: 'TOOL_ARGUMENT',
      name: 'Model / Tool Invocation Argument',
      description: 'Input arguments supplied to an LLM tool or MCP action execution handler.',
      pattern_type: 'IDENTIFIER',
      match_identifiers: ['toolArgs', 'params', 'arguments', 'toolInput', 'inputSchema', 'input'],
      base_confidence: 0.88,
      sensitivity_level: 'MEDIUM',
    },

    // 7. Network Response Body Ingestion
    {
      source_id: 'SRC-NET-001',
      category: 'NETWORK_RESPONSE',
      name: 'Remote HTTP Response Body',
      description: 'Data received from external network response body (res.json(), response.data, response.text).',
      pattern_type: 'FUNCTION_CALL',
      match_functions: ['res.json', 'response.json', 'res.text', 'response.text', 'response.read'],
      base_confidence: 0.85,
      sensitivity_level: 'MEDIUM',
    }
  ];

  public static getSourceById(id: string): TaintSourceDefinition | undefined {
    return this.SOURCES.find(s => s.source_id === id);
  }

  public static getAllSources(): TaintSourceDefinition[] {
    return [...this.SOURCES];
  }
}
