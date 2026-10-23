/**
 * Composer Target Validator
 * Refuses real-world targets (domains, public IPs, external live services)
 * Strictly enforces synthetic, abstract, and sandbox targets across:
 * 1. User Prompt Input
 * 2. Generated Code & Tooling Output
 */

export interface TargetValidationResult {
  allowed: boolean;
  refusal_reason?: string;
  detected_targets?: string[];
  validation_pass?: 'PROMPT' | 'GENERATED_CODE';
}

export class ComposerTargetValidator {
  // Allowed synthetic and sandbox domains/patterns
  public static readonly ALLOWED_SYNTHETIC_PATTERNS = [
    /synthetic-target\.local/i,
    /\.synthetic-sandbox\.internal/i,
    /sandbox\.caim\.internal/i,
    /localhost/i,
    /127\.0\.0\.1/i,
    /0\.0\.0\.0/i,
    /mock:\/\//i,
    /test:\/\//i,
    /sandbox:\/\//i,
    /dummy/i,
    /mock-api/i,
    /synthetic/i,
  ];

  // Regex patterns detecting real-world internet targets
  private static readonly REAL_WORLD_DOMAIN_REGEX = /\b(?:https?:\/\/)?([a-zA-Z0-9-]+\.(?:com|org|net|io|co|ai|dev|app|cloud|internal-corp|corp|gov|edu|uk|de|cn|ru|info|biz|me))\b/gi;
  private static readonly PUBLIC_IP_REGEX = /\b(?!(?:127|10|172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)\.)(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;

  // Patterns detecting unconstrained runtime target parameters / CLI flags in generated code
  private static readonly UNCONSTRAINED_CLI_FLAGS = [
    /(?:--target(?:-url|-host)?|--host|--url|--endpoint|--dest(?:ination)?|--remote-(?:host|url|endpoint)|--target-ip)\b/i,
    /process\.argv\s*(?:\[\s*\d+\s*\]|\.slice|\.includes\(\s*['"`](?:--target|-t|--host|-h|--url|--endpoint)\))/i,
    /(?:yargs|commander|minimist|parseArgs)\b[\s\S]*?(?:['"`](?:target|host|url|endpoint|dest)['"`])/i,
  ];

  private static readonly UNCONSTRAINED_ENV_VARS = [
    /process\.env\.(?:TARGET_HOST|TARGET_URL|TARGET_IP|REMOTE_HOST|REMOTE_URL|TARGET|DESTINATION_HOST|DEST_URL|TARGET_ENDPOINT)(?!\s*\|\|\s*['"`]http:\/\/synthetic-target)/i,
  ];

  private static readonly UNCONSTRAINED_CODE_PARAMS = [
    /(?:constructor|function\s+\w+|\w+\s*=\s*(?:async\s*)?\([^)]*)\(\s*(?:[^)]*,\s*)?(?:(?:private|protected|public|readonly)\s+)?(?:target|targetHost|targetUrl|target_host|target_url|targetIp|target_ip|remoteHost|remoteUrl|remote_host|remote_url|destinationHost|destination_host|externalHost|external_host)\s*:\s*string\s*(?!=)(?:\s*,|\s*\))/i,
    /(?:interface|type)\s+\w+[\s\S]*?(?:target_host|target_url|targetHost|targetUrl|remoteHost|remoteUrl|targetIp|target_ip)\s*:\s*string\s*;/i,
  ];

  /**
   * Evaluates prompt text for real-world target references
   */
  public static validatePrompt(promptText: string): TargetValidationResult {
    if (!promptText || promptText.trim().length === 0) {
      return { allowed: true, validation_pass: 'PROMPT' };
    }

    const detectedRealWorldTargets: string[] = [];

    // 1. Check for real-world domain names
    let domainMatch: RegExpExecArray | null;
    const domainRegex = new RegExp(ComposerTargetValidator.REAL_WORLD_DOMAIN_REGEX);
    while ((domainMatch = domainRegex.exec(promptText)) !== null) {
      const matchStr = domainMatch[1] || domainMatch[0];
      const isSynthetic = ComposerTargetValidator.ALLOWED_SYNTHETIC_PATTERNS.some(p => p.test(matchStr));
      if (!isSynthetic) {
        detectedRealWorldTargets.push(matchStr);
      }
    }

    // 2. Check for public IP addresses
    let ipMatch: RegExpExecArray | null;
    const ipRegex = new RegExp(ComposerTargetValidator.PUBLIC_IP_REGEX);
    while ((ipMatch = ipRegex.exec(promptText)) !== null) {
      const matchStr = ipMatch[0];
      const isSynthetic = ComposerTargetValidator.ALLOWED_SYNTHETIC_PATTERNS.some(p => p.test(matchStr));
      if (!isSynthetic) {
        detectedRealWorldTargets.push(matchStr);
      }
    }

    if (detectedRealWorldTargets.length > 0) {
      return {
        allowed: false,
        validation_pass: 'PROMPT',
        refusal_reason: `Refusal: Real-world target infrastructure detected (${detectedRealWorldTargets.join(', ')}). Composer strictly mandates synthetic, abstract, or sandbox targets (e.g. 'http://synthetic-target.local').`,
        detected_targets: detectedRealWorldTargets,
      };
    }

    return { allowed: true, validation_pass: 'PROMPT' };
  }

  /**
   * Primary validate method (alias to validatePrompt for backward compatibility)
   */
  public static validate(promptText: string): TargetValidationResult {
    return this.validatePrompt(promptText);
  }

  /**
   * Validates generated source code files to ensure no real-world hostnames,
   * unconstrained CLI target flags, or open runtime parameters are introduced.
   */
  public static validateGeneratedCode(codeOrFiles: string | Record<string, string>): TargetValidationResult {
    const filesToInspect: Record<string, string> = typeof codeOrFiles === 'string'
      ? { 'index.ts': codeOrFiles }
      : codeOrFiles;

    const detectedTargets: string[] = [];
    const detectedUnconstrainedParams: string[] = [];

    for (const [filePath, fileContent] of Object.entries(filesToInspect)) {
      // 1. Scan for hardcoded real-world domains
      let domainMatch: RegExpExecArray | null;
      const domainRegex = new RegExp(ComposerTargetValidator.REAL_WORLD_DOMAIN_REGEX);
      while ((domainMatch = domainRegex.exec(fileContent)) !== null) {
        const matchStr = domainMatch[1] || domainMatch[0];
        const isSynthetic = ComposerTargetValidator.ALLOWED_SYNTHETIC_PATTERNS.some(p => p.test(matchStr));
        if (!isSynthetic && !detectedTargets.includes(matchStr)) {
          detectedTargets.push(matchStr);
        }
      }

      // 2. Scan for hardcoded public IP addresses
      let ipMatch: RegExpExecArray | null;
      const ipRegex = new RegExp(ComposerTargetValidator.PUBLIC_IP_REGEX);
      while ((ipMatch = ipRegex.exec(fileContent)) !== null) {
        const matchStr = ipMatch[0];
        const isSynthetic = ComposerTargetValidator.ALLOWED_SYNTHETIC_PATTERNS.some(p => p.test(matchStr));
        if (!isSynthetic && !detectedTargets.includes(matchStr)) {
          detectedTargets.push(matchStr);
        }
      }

      // 3. Scan for unconstrained CLI target flags / argv parsing
      for (const pattern of ComposerTargetValidator.UNCONSTRAINED_CLI_FLAGS) {
        if (pattern.test(fileContent)) {
          const match = fileContent.match(pattern);
          const flagDesc = match ? match[0] : 'CLI target parameter';
          detectedUnconstrainedParams.push(`CLI argument/flag: "${flagDesc}" in ${filePath}`);
        }
      }

      // 4. Scan for unconstrained runtime environment variables
      for (const pattern of ComposerTargetValidator.UNCONSTRAINED_ENV_VARS) {
        if (pattern.test(fileContent)) {
          const match = fileContent.match(pattern);
          const envDesc = match ? match[0] : 'Environment variable target';
          detectedUnconstrainedParams.push(`Runtime env var: "${envDesc}" in ${filePath}`);
        }
      }

      // 5. Scan for unconstrained function/constructor target parameters or interface fields
      for (const pattern of ComposerTargetValidator.UNCONSTRAINED_CODE_PARAMS) {
        if (pattern.test(fileContent)) {
          const match = fileContent.match(pattern);
          const paramDesc = match ? match[0].trim() : 'Unconstrained target parameter';
          detectedUnconstrainedParams.push(`Unconstrained target parameter: "${paramDesc}" in ${filePath}`);
        }
      }
    }

    if (detectedTargets.length > 0) {
      return {
        allowed: false,
        validation_pass: 'GENERATED_CODE',
        refusal_reason: `Refusal: Generated code contains real-world target infrastructure (${detectedTargets.join(', ')}). Generated tooling is strictly prohibited from referencing real-world external hosts or public IPs.`,
        detected_targets: detectedTargets,
      };
    }

    if (detectedUnconstrainedParams.length > 0) {
      return {
        allowed: false,
        validation_pass: 'GENERATED_CODE',
        refusal_reason: `Refusal: Generated code contains unconstrained target parameter, CLI flag, or runtime environment variable (${detectedUnconstrainedParams.join('; ')}). Generated tooling must be strictly bound to the platform's synthetic-target service and cannot accept arbitrary runtime target hosts.`,
        detected_targets: detectedUnconstrainedParams,
      };
    }

    return { allowed: true, validation_pass: 'GENERATED_CODE' };
  }
}

