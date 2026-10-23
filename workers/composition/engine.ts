/**
 * CAIM Composition, SBOM/AI-BOM, Vulnerability Correlation & Reachability Engine
 * Logical Engines: E29, E30, E31, E32, E33, E34, E35
 * Standard: Architecture V2.0.1 Specification
 */

import { 
  CompositionAnalysisResult, 
  DependencyGraph, 
  CycloneDXSbom, 
  AIBOMReport, 
  ReachabilityTrace, 
  LicenseComplianceResult, 
  MaliciousPackageRisk,
  VulnerabilityAdvisory 
} from './types.ts';
import { ManifestParserRegistry } from './manifests/index.ts';
import { CycloneDXGenerator } from './cyclonedx/index.ts';
import { AIBOMExtractor } from './aibom/index.ts';
import { VulnerabilityCorrelationEngine } from './advisories/index.ts';
import { ReachabilityEngine, ReachabilityContext } from './reachability/index.ts';
import { LicenseComplianceEngine } from './compliance/license.ts';
import { MaliciousPackageDetector } from './compliance/malicious.ts';
import { StaticAnalysisReport } from '../static-analysis/types.ts';

export interface RunCompositionOptions {
  artifactId?: string;
  files: Map<string, string>;
  staticAnalysis?: StaticAnalysisReport;
  runtimeEvents?: Array<{ event_type: string; payload?: any }>;
  nvdApiKey?: string;
  fixedTimestamp?: string;
}

export class CompositionEngine {
  /**
   * Runs the complete composition intelligence pipeline
   */
  public static async run(options: RunCompositionOptions): Promise<CompositionAnalysisResult> {
    const artifactId = options.artifactId || 'art-composition-default';
    const timestamp = options.fixedTimestamp || new Date().toISOString();

    // 1. E29: Dependency Resolution Engine (Manifest & Lockfile parsing)
    const depGraph: DependencyGraph = ManifestParserRegistry.parseAll(options.files);

    // 2. E30: Deterministic SBOM Extraction Engine (CycloneDX 1.5)
    const sbom: CycloneDXSbom = CycloneDXGenerator.generate(depGraph, timestamp);
    const sbomJsonCanonical = CycloneDXGenerator.toCanonicalJson(sbom);

    // 3. E31: AI-BOM Model Card, Framework & Prompt Extraction Engine
    const aibom: AIBOMReport = AIBOMExtractor.extract(options.files, depGraph);

    // 4. E32: Vulnerability Correlation Advisory Engine (OSV + NVD)
    const componentVulnMap = await VulnerabilityCorrelationEngine.correlate(depGraph, {
      nvdApiKey: options.nvdApiKey,
    });

    const allAdvisories: VulnerabilityAdvisory[] = [];
    for (const advs of componentVulnMap.values()) {
      for (const adv of advs) {
        if (!allAdvisories.some(a => a.vuln_id === adv.vuln_id)) {
          allAdvisories.push(adv);
        }
      }
    }

    // 5. E33: Reachability & Exploitability Engine (Separates PRESENT vs REACHABLE)
    const reachabilityContext: ReachabilityContext = {
      files: options.files,
      symbolGraph: options.staticAnalysis?.symbol_graph,
      callGraph: options.staticAnalysis?.call_graph,
      runtimeEvents: options.runtimeEvents,
    };

    const reachabilityResults: ReachabilityTrace[] = ReachabilityEngine.evaluate(
      componentVulnMap,
      depGraph.all_components,
      reachabilityContext
    );

    // 6. E34: License & Legal Compliance Engine
    const licenseCompliance: LicenseComplianceResult[] = LicenseComplianceEngine.evaluate(depGraph.all_components);

    // 7. E35: Malicious Package & Backdoor Detection Engine
    const maliciousRisks: MaliciousPackageRisk[] = MaliciousPackageDetector.scan(depGraph.all_components, options.files);

    // Compute Metrics
    const vulnerabilitiesPresent = reachabilityResults.filter(r => r.status === 'VULNERABLE_PRESENT' || r.status === 'PRESENT_UNREACHED').length;
    const vulnerabilitiesReachable = reachabilityResults.filter(r => r.status === 'VULNERABILITY_REACHABLE' || r.status === 'DYNAMICALLY_CONFIRMED_REACHABLE').length;
    const highCriticalRisks = allAdvisories.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH').length +
      maliciousRisks.filter(m => m.severity === 'CRITICAL' || m.severity === 'HIGH').length;

    return {
      analysis_id: `comp-run-${Date.now()}`,
      timestamp,
      artifact_id: artifactId,
      primary_ecosystem: depGraph.ecosystem,
      dependency_graph: depGraph,
      sbom,
      sbom_json_canonical: sbomJsonCanonical,
      aibom,
      advisories: allAdvisories,
      reachability_results: reachabilityResults,
      license_compliance: licenseCompliance,
      malicious_package_risks: maliciousRisks,
      metrics: {
        total_dependencies: depGraph.all_components.length,
        direct_dependencies_count: depGraph.total_direct_count,
        transitive_dependencies_count: depGraph.total_transitive_count,
        vulnerabilities_present_count: vulnerabilitiesPresent,
        vulnerabilities_reachable_count: vulnerabilitiesReachable,
        ai_models_count: aibom.total_models,
        ai_frameworks_count: aibom.total_frameworks,
        high_critical_risk_count: highCriticalRisks,
      },
    };
  }
}
