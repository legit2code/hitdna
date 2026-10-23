/**
 * Composition, SBOM, AI-BOM, Vulnerability, and Reachability Types
 * Standard: CAIM V2.0.1 / CycloneDX 1.5 Specification
 */

import { SourceSpan } from '@caim/syntax/types.ts';
import { CallGraph } from '../static-analysis/types.ts';

export type PackageEcosystem = 'npm' | 'pypi' | 'golang' | 'cargo' | 'maven' | 'nuget' | 'generic';

export type DependencyScope = 'RUNTIME' | 'DEV' | 'OPTIONAL' | 'PEER' | 'TRANSITIVE';

export interface PackageIdentifier {
  ecosystem: PackageEcosystem;
  name: string;
  version: string;
  purl: string;
  scope?: DependencyScope;
  is_direct: boolean;
  depth: number;
  resolved_version?: string;
  license?: string;
  checksum_sha256?: string;
  description?: string;
  homepage?: string;
  repository_url?: string;
}

export interface DependencyEdge {
  from_purl: string;
  to_purl: string;
  requirement_spec?: string;
  scope: DependencyScope;
}

export interface DependencyGraph {
  root_name: string;
  root_version: string;
  ecosystem: PackageEcosystem;
  direct_dependencies: PackageIdentifier[];
  transitive_dependencies: PackageIdentifier[];
  all_components: PackageIdentifier[];
  edges: DependencyEdge[];
  adjacency_list: Record<string, string[]>;
  circular_dependencies: string[][];
  total_direct_count: number;
  total_transitive_count: number;
}

export interface AIModelDescriptor {
  model_id: string;
  name: string;
  provider: 'openai' | 'anthropic' | 'google' | 'meta' | 'huggingface' | 'ollama' | 'mistral' | 'cohere' | 'local' | 'unknown';
  architecture?: string;
  family?: string;
  parameters_estimate?: string;
  source_file: string;
  span?: SourceSpan;
  is_local_weight: boolean;
  format?: 'gguf' | 'safetensors' | 'onnx' | 'pt' | 'bin' | 'api_endpoint';
  task_type?: 'chat' | 'completion' | 'embedding' | 'image' | 'audio' | 'rerank' | 'multimodal';
}

export interface AIDatasetDescriptor {
  dataset_id: string;
  name: string;
  source: string;
  source_file: string;
  span?: SourceSpan;
  split?: 'train' | 'validation' | 'test' | 'eval';
  license?: string;
}

export interface AIFrameworkDescriptor {
  framework_id: string;
  name: 'langchain' | 'llamaindex' | 'transformers' | 'pytorch' | 'tensorflow' | 'vllm' | 'ollama' | 'litellm' | 'guidance' | 'outlines' | 'dspy' | 'autogen' | 'crewai' | 'other';
  version?: string;
  source_file: string;
  purl?: string;
  modules_used: string[];
}

export interface AIPromptTemplateDescriptor {
  template_id: string;
  name: string;
  role: 'system' | 'user' | 'assistant' | 'tool';
  source_file: string;
  span?: SourceSpan;
  variables: string[];
  snippet: string;
}

export interface AIBOMReport {
  models: AIModelDescriptor[];
  datasets: AIDatasetDescriptor[];
  frameworks: AIFrameworkDescriptor[];
  prompt_templates: AIPromptTemplateDescriptor[];
  total_models: number;
  total_frameworks: number;
  total_datasets: number;
  has_local_weights: boolean;
  ai_bill_of_materials_version: string;
}

export type VulnerabilitySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL' | 'UNKNOWN';

export interface VulnerabilityAdvisory {
  vuln_id: string; // CVE-*, GHSA-*, OSV-*
  aliases: string[];
  title: string;
  summary: string;
  details?: string;
  ecosystem: PackageEcosystem;
  package_name: string;
  affected_version_ranges: string[];
  fixed_versions: string[];
  cvss_v3_score?: number;
  cvss_v3_vector?: string;
  cvss_v4_score?: number;
  severity: VulnerabilitySeverity;
  cwe_ids: string[];
  references: string[];
  published_at?: string;
  withdrawn_at?: string;
  vulnerable_symbols?: string[]; // Specific function/method names affected
}

export type ReachabilityStatus = 
  | 'VULNERABLE_PRESENT'            // Present in dependencies, but not confirmed reachable in code
  | 'PRESENT_UNREACHED'             // Analyzed in AST/CallGraph: never imported or never invoked
  | 'VULNERABILITY_REACHABLE'       // Statically confirmed reachable via import + call graph trace
  | 'DYNAMICALLY_CONFIRMED_REACHABLE' // Dynamic runtime event proved execution/exploit reachability
  | 'SAFE_FIXED';                   // Installed version is patched / outside vulnerable range

export type ReachabilityConfidence = 'HIGH' | 'MEDIUM' | 'LOW' | 'HEURISTIC';

export interface ReachabilityTrace {
  vulnerability_id: string;
  package_name: string;
  package_purl: string;
  installed_version: string;
  status: ReachabilityStatus;
  is_direct_dependency: boolean;
  imported_in_files: string[];
  imported_symbols: string[];
  target_vulnerable_symbols: string[];
  reachability_path: string[]; // ['main.ts:handleReq', 'util.ts:parse', 'pkg:vulnerableFn']
  confidence: number;
  confidence_level: ReachabilityConfidence;
  evidence_description: string;
  static_call_depth: number;
  runtime_confirmed: boolean;
}

export interface LicenseComplianceResult {
  purl: string;
  package_name: string;
  declared_license: string;
  normalized_spdx: string;
  classification: 'PERMISSIVE' | 'WEAK_COPYLEFT' | 'STRONG_COPYLEFT' | 'COMMERCIAL_RESTRICTIVE' | 'UNKNOWN';
  compliance_risk: 'LOW' | 'MEDIUM' | 'HIGH';
  notes?: string;
}

export interface MaliciousPackageRisk {
  purl: string;
  package_name: string;
  risk_type: 'TYPOSQUAT' | 'SUSPICIOUS_LIFECYCLE_SCRIPT' | 'KNOWN_MALICIOUS_HASH' | 'OBFUSCATED_INSTALL';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description: string;
  indicators: string[];
}

export interface CycloneDXMetadata {
  timestamp: string;
  tools: Array<{ vendor: string; name: string; version: string }>;
  component: {
    name: string;
    version: string;
    type: string;
    purl?: string;
  };
}

export interface CycloneDXComponent {
  'bom-ref': string;
  type: string;
  name: string;
  version: string;
  purl: string;
  scope?: string;
  licenses?: Array<{ license: { id?: string; name?: string } }>;
  hashes?: Array<{ alg: string; content: string }>;
  properties?: Array<{ name: string; value: string }>;
}

export interface CycloneDXDependency {
  ref: string;
  dependsOn: string[];
}

export interface CycloneDXSbom {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: number;
  metadata: CycloneDXMetadata;
  components: CycloneDXComponent[];
  dependencies: CycloneDXDependency[];
  vulnerabilities?: any[];
}

export interface CompositionAnalysisResult {
  analysis_id: string;
  timestamp: string;
  artifact_id: string;
  primary_ecosystem: PackageEcosystem;
  dependency_graph: DependencyGraph;
  sbom: CycloneDXSbom;
  sbom_json_canonical: string;
  aibom: AIBOMReport;
  advisories: VulnerabilityAdvisory[];
  reachability_results: ReachabilityTrace[];
  license_compliance: LicenseComplianceResult[];
  malicious_package_risks: MaliciousPackageRisk[];
  metrics: {
    total_dependencies: number;
    direct_dependencies_count: number;
    transitive_dependencies_count: number;
    vulnerabilities_present_count: number;
    vulnerabilities_reachable_count: number;
    ai_models_count: number;
    ai_frameworks_count: number;
    high_critical_risk_count: number;
  };
}
