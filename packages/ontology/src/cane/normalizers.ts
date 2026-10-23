/**
 * CANE Field & Value Normalizers with Unknown Extension Preservation
 * P14 — Canonicalization
 */

import { 
  ConfigValueType, 
  SecurityClassification, 
  EndpointDirection, 
  EndpointType, 
  RuntimeType, 
  ExecutionMode 
} from '../../../caim/src/index.ts';

export class CaneNormalizers {
  /**
   * Identifies security classification based on key names and context
   */
  public static classifySecurityKey(key: string): SecurityClassification {
    const upper = key.toUpperCase();
    if (
      upper.includes('SECRET') || 
      upper.includes('PRIVATE_KEY') || 
      upper.includes('PASSWORD') || 
      upper.includes('PASSWD') || 
      upper.includes('VAULT') ||
      upper.includes('CREDENTIAL')
    ) {
      return 'VAULT_RESTRICTED';
    }
    if (
      upper.includes('API_KEY') || 
      upper.includes('TOKEN') || 
      upper.includes('AUTH') || 
      upper.includes('BEARER') || 
      upper.includes('SESSION') ||
      upper.includes('SIGNING_KEY')
    ) {
      return 'SENSITIVE';
    }
    if (
      upper.includes('INTERNAL') || 
      upper.includes('BACKEND') || 
      upper.includes('HOST') || 
      upper.includes('PORT') || 
      upper.includes('DATABASE') || 
      upper.includes('DB_URI')
    ) {
      return 'INTERNAL';
    }
    return 'PUBLIC_METADATA';
  }

  /**
   * Normalizes an environment variable value type
   */
  public static inferConfigValueType(value?: string): ConfigValueType {
    if (!value) return 'STRING';
    const trimmed = value.trim();
    if (trimmed === 'true' || trimmed === 'false') return 'BOOLEAN';
    if (!isNaN(Number(trimmed)) && trimmed !== '') return 'NUMBER';
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
      try {
        JSON.parse(trimmed);
        return 'JSON';
      } catch {
        return 'STRING';
      }
    }
    if (trimmed.startsWith('vault://') || trimmed.startsWith('secret://') || trimmed.startsWith('env:')) {
      return 'SECRET_REF';
    }
    return 'STRING';
  }

  /**
   * Normalizes endpoint path and method
   */
  public static normalizeEndpoint(rawPath?: string, rawMethod?: string): {
    path: string;
    method: string;
    direction: EndpointDirection;
    endpoint_type: EndpointType;
  } {
    let path = (rawPath || '/').trim();
    // Clean double slashes
    path = path.replace(/\/+/g, '/');
    if (!path.startsWith('/')) path = `/${path}`;
    if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);

    const method = (rawMethod || 'GET').toUpperCase();
    const isWebhook = path.includes('webhook') || path.includes('/hook');
    const isSocket = path.includes('/ws') || path.includes('/socket');

    let endpoint_type: EndpointType = 'INGRESS';
    if (isWebhook) endpoint_type = 'WEBHOOK';
    else if (isSocket) endpoint_type = 'SOCKET';

    return {
      path,
      method,
      direction: 'INBOUND',
      endpoint_type,
    };
  }

  /**
   * Normalizes dependency ecosystem and version
   */
  public static normalizeDependency(name: string, rawVersion?: string, filename?: string): {
    normalized_name: string;
    ecosystem: string;
    version: string;
    is_direct: boolean;
  } {
    let ecosystem = 'generic';
    if (filename) {
      const lower = filename.toLowerCase();
      if (lower.includes('package.json') || lower.endsWith('.ts') || lower.endsWith('.js')) ecosystem = 'npm';
      else if (lower.includes('requirements.txt') || lower.includes('pyproject.toml') || lower.endsWith('.py')) ecosystem = 'pypi';
      else if (lower.includes('go.mod') || lower.endsWith('.go')) ecosystem = 'go';
      else if (lower.includes('cargo.toml') || lower.endsWith('.rs')) ecosystem = 'cargo';
    }

    const version = (rawVersion || '*').replace(/^[~^>=< ]+/, '').trim() || 'latest';
    return {
      normalized_name: name.trim(),
      ecosystem,
      version,
      is_direct: true,
    };
  }

  /**
   * Normalizes runtime information
   */
  public static normalizeRuntime(frameworkOrExt: string): {
    runtime_type: RuntimeType;
    runtime_name: string;
    execution_mode: ExecutionMode;
  } {
    const lower = frameworkOrExt.toLowerCase();
    if (lower.includes('python') || lower.endsWith('.py') || lower.includes('fastapi') || lower.includes('flask')) {
      return { runtime_type: 'PYTHON', runtime_name: 'CPython 3.11+', execution_mode: 'SANDBOXED' };
    }
    if (lower.includes('node') || lower.endsWith('.ts') || lower.endsWith('.js') || lower.includes('express')) {
      return { runtime_type: 'NODEJS', runtime_name: 'Node.js 20+ / V8', execution_mode: 'SANDBOXED' };
    }
    if (lower.includes('go') || lower.endsWith('.go') || lower.includes('gin')) {
      return { runtime_type: 'NATIVE_BINARY', runtime_name: 'Go Runtime (gc)', execution_mode: 'SANDBOXED' };
    }
    if (lower.includes('docker') || lower.includes('container')) {
      return { runtime_type: 'DOCKER', runtime_name: 'OCI Container', execution_mode: 'CONTAINERIZED' };
    }
    if (lower.includes('wasm')) {
      return { runtime_type: 'WASM', runtime_name: 'Wasmtime / WasmEdge', execution_mode: 'SANDBOXED' };
    }
    return { runtime_type: 'NODEJS', runtime_name: 'Standard POSIX / Node', execution_mode: 'SANDBOXED' };
  }

  /**
   * Preserves unknown / unrecognized extension attributes without dropping them
   */
  public static preserveUnknownExtensions(
    sourceObject: Record<string, unknown>,
    knownStandardKeys: string[]
  ): Record<string, unknown> {
    const extensions: Record<string, unknown> = {};
    const knownSet = new Set(knownStandardKeys);

    for (const [key, value] of Object.entries(sourceObject)) {
      if (!knownSet.has(key) && value !== undefined) {
        extensions[key] = value;
      }
    }

    return extensions;
  }
}
