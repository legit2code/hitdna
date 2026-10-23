export class SafeRepositoryAcquisition {
  // Sensitive environment variable prefixes or names to strip
  private static readonly SENSITIVE_ENV_PATTERNS = [
    /TOKEN/i,
    /SECRET/i,
    /KEY/i,
    /PASSWORD/i,
    /AUTH/i,
    /CREDENTIAL/i,
    /^GIT_/i,
    /^SSH_/i,
    /^AWS_/i,
    /^GCP_/i,
    /^GOOGLE_/i,
    /^AZURE_/i,
  ];

  /**
   * Generates a sanitized environment object for any external git operation,
   * completely stripped of developer, production, or CI credentials, and
   * hardens git against interactive prompts or hook execution.
   */
  static getSanitizedGitEnvironment(baseEnv: Record<string, string | undefined> = process.env): Record<string, string> {
    const cleanEnv: Record<string, string> = {};

    for (const [key, value] of Object.entries(baseEnv)) {
      if (value === undefined) continue;

      // Filter out any key matching sensitive patterns
      const isSensitive = this.SENSITIVE_ENV_PATTERNS.some((pattern) => pattern.test(key));
      if (!isSensitive) {
        cleanEnv[key] = value;
      }
    }

    // Set mandatory git safety variables
    cleanEnv['GIT_TERMINAL_PROMPT'] = '0';
    cleanEnv['GIT_ASKPASS'] = '/bin/false';
    cleanEnv['GIT_SSH_COMMAND'] = 'ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new';
    cleanEnv['GIT_CONFIG_NOSYSTEM'] = '1';
    cleanEnv['GIT_OPTIONAL_LOCKS'] = '0';

    return cleanEnv;
  }

  /**
   * Builds hardened command line flags for Git clone operations:
   * - No git hook execution (core.hooksPath=/dev/null)
   * - No submodule initialization (--no-recurse-submodules)
   * - Shallow clone (--depth 1)
   */
  static getGitCloneArguments(
    repoUrl: string,
    targetDirectory: string,
    options: { branchOrRef?: string; depth?: number } = {}
  ): string[] {
    const args = [
      'clone',
      '-c',
      'core.hooksPath=/dev/null', // Disable git hooks
      '--no-recurse-submodules',   // Disable automatic submodule recursion
      '--depth',
      String(options.depth ?? 1),
    ];

    if (options.branchOrRef) {
      args.push('--branch', options.branchOrRef);
    }

    args.push(repoUrl, targetDirectory);
    return args;
  }

  /**
   * Strips authentication and credential headers when a request redirects or crosses domains.
   */
  static sanitizeHeadersForRedirect(
    headers: Record<string, string>,
    originalUrl: string,
    redirectTargetUrl: string
  ): Record<string, string> {
    const original = new URL(originalUrl);
    const target = new URL(redirectTargetUrl);

    // If host or protocol changed, strip credential headers
    if (original.hostname !== target.hostname || original.protocol !== target.protocol) {
      const sanitized: Record<string, string> = {};
      const strippedHeaders = ['authorization', 'cookie', 'token', 'private-token', 'x-api-key', 'proxy-authorization'];

      for (const [key, val] of Object.entries(headers)) {
        if (!strippedHeaders.includes(key.toLowerCase())) {
          sanitized[key] = val;
        }
      }
      return sanitized;
    }

    return { ...headers };
  }

  /**
   * Recommends provider-native archive/tarball API URL over git clone.
   */
  static getPreferredArchiveDownloadUrl(
    sourceType: string,
    locator: string,
    ref: string = 'main'
  ): { preferredMethod: 'ARCHIVE_API' | 'GIT_CLONE'; downloadUrl?: string } {
    const cleanLocator = locator.replace(/^[a-z]+:\/\//, '');

    switch (sourceType.toLowerCase()) {
      case 'github': {
        const parts = cleanLocator.split('/');
        if (parts.length >= 2) {
          return {
            preferredMethod: 'ARCHIVE_API',
            downloadUrl: `https://api.github.com/repos/${parts[0]}/${parts[1]}/tarball/${encodeURIComponent(ref)}`,
          };
        }
        break;
      }
      case 'gitlab': {
        const encodedProject = encodeURIComponent(cleanLocator);
        return {
          preferredMethod: 'ARCHIVE_API',
          downloadUrl: `https://gitlab.com/api/v4/projects/${encodedProject}/repository/archive.tar.gz?sha=${encodeURIComponent(ref)}`,
        };
      }
      case 'codeberg': {
        const parts = cleanLocator.split('/');
        if (parts.length >= 2) {
          return {
            preferredMethod: 'ARCHIVE_API',
            downloadUrl: `https://codeberg.org/api/v1/repos/${parts[0]}/${parts[1]}/archive/${encodeURIComponent(ref)}.tar.gz`,
          };
        }
        break;
      }
      case 'npm': {
        return {
          preferredMethod: 'ARCHIVE_API',
          downloadUrl: `https://registry.npmjs.org/${cleanLocator}/-/${cleanLocator}-latest.tgz`,
        };
      }
      case 'pypi': {
        return {
          preferredMethod: 'ARCHIVE_API',
          downloadUrl: `https://pypi.org/pypi/${cleanLocator}/json`,
        };
      }
    }

    return { preferredMethod: 'ARCHIVE_API' };
  }
}
