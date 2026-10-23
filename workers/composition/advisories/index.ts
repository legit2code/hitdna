/**
 * Vulnerability Advisory Correlation Engine
 */

import { VulnerabilityAdvisory, DependencyGraph, PackageIdentifier } from '../types.ts';
import { OSVAdapter } from './osv.ts';
import { NVDAdapter } from './nvd.ts';
import { CANONICAL_ADVISORY_FIXTURES } from './catalog.ts';

export class VulnerabilityCorrelationEngine {
  /**
   * Correlates dependency components with known security advisories
   */
  public static async correlate(
    graph: DependencyGraph,
    options: { nvdApiKey?: string } = {}
  ): Promise<Map<string, VulnerabilityAdvisory[]>> {
    const componentVulnMap: Map<string, VulnerabilityAdvisory[]> = new Map();

    for (const comp of graph.all_components) {
      const matchedVulns: VulnerabilityAdvisory[] = [];
      const lowName = comp.name.toLowerCase();

      // 1. Check local catalog
      let knownInLocalCatalog = false;
      for (const fixture of CANONICAL_ADVISORY_FIXTURES) {
        if (fixture.package_name.toLowerCase() === lowName) {
          knownInLocalCatalog = true;
          if (VulnerabilityCorrelationEngine.isVersionVulnerable(comp.resolved_version || comp.version, fixture.affected_version_ranges)) {
            matchedVulns.push(fixture);
          }
        }
      }

      // 2. Query OSV Adapter if not in local catalog
      if (!knownInLocalCatalog && matchedVulns.length === 0) {
        const osvResults = await OSVAdapter.queryPackage(comp.ecosystem, comp.name, comp.resolved_version || comp.version);
        for (const osv of osvResults) {
          if (VulnerabilityCorrelationEngine.isVersionVulnerable(comp.resolved_version || comp.version, osv.affected_version_ranges)) {
            if (!matchedVulns.some(v => v.vuln_id === osv.vuln_id)) {
              matchedVulns.push(osv);
            }
          }
        }
      }

      if (matchedVulns.length > 0) {
        componentVulnMap.set(comp.purl, matchedVulns);
      }
    }

    return componentVulnMap;
  }

  /**
   * Simple semver range checker
   */
  public static isVersionVulnerable(version: string, affectedRanges: string[]): boolean {
    if (!affectedRanges || affectedRanges.length === 0) return true;
    const cleanVer = version.replace(/^[v^~>=<]+/, '').trim();
    if (!cleanVer) return true;

    // Check against patterns like '<4.17.21', '<=2.14.1', '>=2.0-beta9'
    for (const range of affectedRanges) {
      const match = range.match(/^([<>=!~]+)\s*(.+)$/);
      if (match) {
        const op = match[1];
        const target = match[2];
        const cmp = VulnerabilityCorrelationEngine.compareSemver(cleanVer, target);
        if (op === '<' && cmp >= 0) return false;
        if (op === '<=' && cmp > 0) return false;
        if (op === '>' && cmp <= 0) return false;
        if (op === '>=' && cmp < 0) return false;
      }
    }
    return true;
  }

  /**
   * Semver comparison helper
   */
  public static compareSemver(v1: string, v2: string): number {
    const p1 = v1.split(/[\.-]/).map(n => parseInt(n, 10) || 0);
    const p2 = v2.split(/[\.-]/).map(n => parseInt(n, 10) || 0);
    const len = Math.max(p1.length, p2.length);

    for (let i = 0; i < len; i++) {
      const a = p1[i] || 0;
      const b = p2[i] || 0;
      if (a > b) return 1;
      if (a < b) return -1;
    }
    return 0;
  }
}
