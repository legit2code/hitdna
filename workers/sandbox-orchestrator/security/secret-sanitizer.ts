/**
 * Strict Threat-Model Secret Sanitizer
 * Ensures the sandbox NEVER receives Supabase secret key, Gemini key, discovery tokens,
 * signing keys, or real user credentials.
 */

export interface SanitizationReport {
  isClean: boolean;
  blockedKeys: string[];
  sanitizedCount: number;
}

export class SecretSanitizer {
  // Regex patterns and exact names of forbidden platform secrets
  private static readonly FORBIDDEN_PATTERNS: RegExp[] = [
    /supabase.*key/i,
    /gemini.*key/i,
    /ai_studio/i,
    /jwt.*secret/i,
    /signing.*key/i,
    /vault.*key/i,
    /discovery.*token/i,
    /session.*token/i,
    /user.*password/i,
    /db.*password/i,
    /postgres.*pwd/i,
    /e2b_api_key/i,
    /aws_.*(key|secret)/i,
    /gcp_.*key/i,
    /kms_.*key/i,
    /oci_.*(token|key)/i,
    /github_.*token/i,
    /private.*key/i,
    /bearer.*token/i,
    /auth.*token/i,
  ];

  private static readonly FORBIDDEN_EXACT_KEYS: Set<string> = new Set([
    'GEMINI_API_KEY',
    'SUPABASE_SERVICE_ROLE_KEY',
    'SUPABASE_ANON_KEY',
    'SUPABASE_URL',
    'DATABASE_URL',
    'DIRECT_URL',
    'SESSION_SECRET',
    'JWT_SECRET',
    'VAULT_MASTER_KEY',
    'DISCOVERY_API_TOKEN',
    'E2B_API_KEY',
    'ADMIN_AUTH_TOKEN',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN',
    'GCP_KMS_KEY_NAME',
    'OCI_AUTH_TOKEN',
    'GITHUB_TOKEN',
    'RELEASE_SIGNING_PRIVATE_KEY_PEM',
  ]);

  /**
   * Sanitizes environment variables intended for sandbox container injection.
   * Strips all forbidden secrets and returns a sanitized clone.
   */
  public static sanitizeEnvVars(env: Record<string, string>): { sanitized: Record<string, string>; report: SanitizationReport } {
    const sanitized: Record<string, string> = {};
    const blockedKeys: string[] = [];

    for (const [key, value] of Object.entries(env)) {
      if (this.isForbiddenKey(key, value)) {
        blockedKeys.push(key);
      } else {
        sanitized[key] = value;
      }
    }

    return {
      sanitized,
      report: {
        isClean: blockedKeys.length === 0,
        blockedKeys,
        sanitizedCount: blockedKeys.length,
      }
    };
  }

  /**
   * Scans text files or payload contents for accidental real credentials before transfer.
   */
  public static sanitizeFilePayload(files: Record<string, string>): { sanitized: Record<string, string>; report: SanitizationReport } {
    const sanitized: Record<string, string> = {};
    const blockedKeys: string[] = [];

    for (const [filePath, content] of Object.entries(files)) {
      let cleanContent = content;
      
      // Look for real key patterns like AIzaSy..., eyJhbGciOi..., etc.
      if (content.includes('AIzaSy') || content.includes('sbp_') || content.includes('eyJhbGciOi')) {
        blockedKeys.push(filePath);
        cleanContent = cleanContent
          .replace(/AIzaSy[A-Za-z0-9_-]+/g, '[REDACTED_API_KEY]')
          .replace(/sbp_[a-f0-9]{40}/g, '[REDACTED_SUPABASE_KEY]')
          .replace(/eyJhbGciOi[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[REDACTED_JWT_TOKEN]');
      }

      sanitized[filePath] = cleanContent;
    }

    return {
      sanitized,
      report: {
        isClean: blockedKeys.length === 0,
        blockedKeys,
        sanitizedCount: blockedKeys.length,
      }
    };
  }

  public static isForbiddenKey(keyName: string, value?: string): boolean {
    const upperKey = keyName.toUpperCase();
    if (this.FORBIDDEN_EXACT_KEYS.has(upperKey)) {
      return true;
    }

    for (const pattern of this.FORBIDDEN_PATTERNS) {
      if (pattern.test(keyName)) {
        return true;
      }
    }

    // Check if value matches live credentials pattern
    if (value) {
      if (/^AIzaSy[A-Za-z0-9_-]{33}$/.test(value)) return true;
      if (/^sbp_[a-f0-9]{40}$/.test(value)) return true;
      if (/^AKIA[0-9A-Z]{16}$/.test(value)) return true;
      if (/^ghp_[A-Za-z0-9]{36}$/.test(value)) return true;
      if (value.includes('-----BEGIN') && value.includes('PRIVATE KEY-----')) return true;
    }

    return false;
  }
}
