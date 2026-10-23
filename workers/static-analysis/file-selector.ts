/**
 * File Selector for Static Analysis
 * P15 — Static Analysis & Control Flow
 */

import { FileSelectionResult, SelectedFile, ExcludedFile } from './types.ts';

export class StaticFileSelector {
  private static readonly EXCLUDE_PATTERNS = [
    /node_modules\//i,
    /\.git\//i,
    /dist\//i,
    /build\//i,
    /\.next\//i,
    /\.turbo\//i,
    /coverage\//i,
    /package-lock\.json$/i,
    /yarn\.lock$/i,
    /pnpm-lock\.yaml$/i,
    /Cargo\.lock$/i,
    /go\.sum$/i,
    /\.(png|jpg|jpeg|gif|svg|ico|webp|woff|woff2|ttf|eot|mp3|mp4|zip|tar|gz)$/i,
  ];

  private static readonly ENTRYPOINT_NAMES = [
    /^index\.(ts|tsx|js|jsx|mjs)$/i,
    /^main\.(ts|tsx|js|jsx|py|go|rs)$/i,
    /^app\.(ts|tsx|js|jsx|py)$/i,
    /^server\.(ts|tsx|js|jsx)$/i,
    /^cli\.(ts|js|py|go)$/i,
    /^agent\.(ts|js|py)$/i,
    /^mcp_server\.(ts|js|py)$/i,
  ];

  /**
   * Evaluates input files and categorizes them into included and excluded files
   */
  public static selectFiles(
    files: Array<{ path: string; content: string }>,
    explicitEntrypoints?: string[]
  ): FileSelectionResult {
    const included: SelectedFile[] = [];
    const excluded: ExcludedFile[] = [];
    const entrypointsSet = new Set<string>(explicitEntrypoints || []);
    let totalBytes = 0;

    for (const file of files) {
      const normalizedPath = file.path.replace(/\\/g, '/').replace(/^\.\//, '');
      const sizeBytes = new TextEncoder().encode(file.content).length;

      // Check exclusions
      const excludeMatch = this.EXCLUDE_PATTERNS.find(pattern => pattern.test(normalizedPath));
      if (excludeMatch) {
        excluded.push({
          path: normalizedPath,
          reason: `Matched exclusion pattern: ${excludeMatch.toString()}`,
        });
        continue;
      }

      const role = this.determineFileRole(normalizedPath);
      const language = this.detectLanguage(normalizedPath);

      // Check if entrypoint
      const fileName = normalizedPath.split('/').pop() || normalizedPath;
      const isExplicitEntry = entrypointsSet.has(normalizedPath) || entrypointsSet.has(fileName);
      const isHeuristicEntry = this.ENTRYPOINT_NAMES.some(pattern => pattern.test(fileName)) ||
        file.content.includes('McpServer') || 
        file.content.includes('createMcpServer') ||
        file.content.includes('express()') ||
        file.content.includes('FastAPI()') ||
        file.content.includes('func main()');

      const isEntrypoint = isExplicitEntry || (role === 'SOURCE' && isHeuristicEntry);

      if (isEntrypoint) {
        entrypointsSet.add(normalizedPath);
      }

      totalBytes += sizeBytes;
      included.push({
        path: normalizedPath,
        language,
        size_bytes: sizeBytes,
        is_entrypoint: isEntrypoint,
        role,
      });
    }

    return {
      included_files: included,
      excluded_files: excluded,
      entrypoint_files: Array.from(entrypointsSet),
      total_files_evaluated: files.length,
      total_source_bytes: totalBytes,
    };
  }

  public static determineFileRole(filePath: string): SelectedFile['role'] {
    const lower = filePath.toLowerCase();
    if (
      lower.includes('.test.') || 
      lower.includes('.spec.') || 
      lower.includes('__tests__/') || 
      lower.includes('tests/') || 
      lower.includes('test/')
    ) {
      return 'TEST';
    }

    if (
      lower.endsWith('.json') || 
      lower.endsWith('.yaml') || 
      lower.endsWith('.yml') || 
      lower.endsWith('.toml') || 
      lower.endsWith('.env') || 
      lower.includes('config')
    ) {
      return 'CONFIG';
    }

    if (
      lower.endsWith('.ts') || 
      lower.endsWith('.tsx') || 
      lower.endsWith('.js') || 
      lower.endsWith('.jsx') || 
      lower.endsWith('.mjs') || 
      lower.endsWith('.py') || 
      lower.endsWith('.go') || 
      lower.endsWith('.rs')
    ) {
      return 'SOURCE';
    }

    return 'RESOURCE';
  }

  public static detectLanguage(filePath: string): string {
    const lower = filePath.toLowerCase();
    if (lower.endsWith('.ts') || lower.endsWith('.tsx')) return 'TypeScript';
    if (lower.endsWith('.js') || lower.endsWith('.jsx') || lower.endsWith('.mjs')) return 'JavaScript';
    if (lower.endsWith('.py')) return 'Python';
    if (lower.endsWith('.go')) return 'Go';
    if (lower.endsWith('.rs')) return 'Rust';
    if (lower.endsWith('.json')) return 'JSON';
    if (lower.endsWith('.yaml') || lower.endsWith('.yml')) return 'YAML';
    if (lower.endsWith('.toml')) return 'TOML';
    if (lower.endsWith('.dockerfile') || lower.includes('dockerfile')) return 'Dockerfile';
    return 'PlainText';
  }
}
