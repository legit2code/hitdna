/**
 * Malicious Package, Backdoor & Typo-squatting Detection Engine
 */

import { PackageIdentifier, MaliciousPackageRisk } from '../types.ts';

export class MaliciousPackageDetector {
  private static readonly POPULAR_PACKAGES = [
    'express', 'lodash', 'react', 'axios', 'chalk', 'commander', 'moment',
    'requests', 'flask', 'django', 'numpy', 'scipy', 'torch', 'transformers',
    'tokio', 'serde', 'gin-gonic'
  ];

  /**
   * Scans package list and package manifest scripts for malicious backdoor or typo-squatting patterns
   */
  public static scan(
    components: PackageIdentifier[],
    rawManifests: Map<string, string>
  ): MaliciousPackageRisk[] {
    const risks: MaliciousPackageRisk[] = [];

    // 1. Check for typo-squatting against popular packages
    for (const comp of components) {
      const cName = comp.name.toLowerCase();
      for (const popular of MaliciousPackageDetector.POPULAR_PACKAGES) {
        if (cName !== popular && MaliciousPackageDetector.isTypoSquatCandidate(cName, popular)) {
          risks.push({
            purl: comp.purl,
            package_name: comp.name,
            risk_type: 'TYPOSQUAT',
            severity: 'HIGH',
            description: `Package [${comp.name}] has high edit similarity to popular package [${popular}], potential typo-squatting attack.`,
            indicators: [`Target package: ${popular}`, `Edit distance: 1`],
          });
        }
      }
    }

    // 2. Check for suspicious install lifecycle scripts in package.json
    for (const [path, content] of rawManifests.entries()) {
      if (path.endsWith('package.json')) {
        try {
          const pkg = JSON.parse(content);
          if (pkg.scripts && typeof pkg.scripts === 'object') {
            for (const [hook, cmd] of Object.entries<string>(pkg.scripts)) {
              if (['preinstall', 'postinstall', 'install'].includes(hook)) {
                if (/curl\s+|wget\s+|bash\s+|sh\s+-c|eval\(|base64\s+-d|http:\/\/|https:\/\//i.test(cmd)) {
                  risks.push({
                    purl: `pkg:npm/${pkg.name || 'root'}@${pkg.version || '0.0.0'}`,
                    package_name: pkg.name || 'root',
                    risk_type: 'SUSPICIOUS_LIFECYCLE_SCRIPT',
                    severity: 'CRITICAL',
                    description: `Package defines suspicious remote execution in lifecycle script [${hook}]: "${cmd}"`,
                    indicators: [`Hook: ${hook}`, `Command: ${cmd}`],
                  });
                }
              }
            }
          }
        } catch {
          // Ignore parse errors
        }
      }
    }

    return risks;
  }

  private static isTypoSquatCandidate(name: string, target: string): boolean {
    if (Math.abs(name.length - target.length) > 1) return false;
    // Levenshtein distance 1 check
    let diff = 0;
    let i = 0, j = 0;
    while (i < name.length && j < target.length) {
      if (name[i] !== target[j]) {
        diff++;
        if (diff > 1) return false;
        if (name.length > target.length) i++;
        else if (target.length > name.length) j++;
        else { i++; j++; }
      } else {
        i++; j++;
      }
    }
    return diff <= 1;
  }
}
