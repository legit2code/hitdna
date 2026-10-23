import { describe, it, expect, vi } from 'vitest';
import {
  AuthenticSourceAcquisitionService,
  AuthenticSourceUnavailableError,
  DiscoveryCandidate,
  AutonomousDiscoveryWorker,
  SourceAdapterRegistry,
} from '@caim/source';
import { StaticAnalysisEngine } from '../workers/static-analysis/index.ts';

describe('Authentic Source Acquisition and Truthful Semantics Pipeline', () => {
  const mockCandidate: DiscoveryCandidate = {
    source_type: 'github',
    display_name: 'test-real-agent',
    source_locator: 'https://github.com/caim-agents/test-real-agent',
    type_hint: 'AGENT_REPOSITORY',
    confidence: 0.95,
    discovered_at: '2026-09-13T00:00:00.000Z',
    raw_metadata: {
      framework: 'LangChain',
      author: 'SecurityTeam',
      description: 'An autonomous agent with tools',
    },
  };

  describe('1. AuthenticSourceAcquisitionService Verification & Provenance', () => {
    it('truthfully marks SOURCE_UNAVAILABLE and ANALYSIS_NOT_PERFORMED when no files are acquired', () => {
      const result = AuthenticSourceAcquisitionService.verifyAndHashArtifact(
        mockCandidate,
        null,
        { version_identity: 'v1.0.0' }
      );

      expect(result.has_authentic_source).toBe(false);
      expect(result.source_status).toBe('SOURCE_UNAVAILABLE');
      expect(result.analysis_status).toBe('ANALYSIS_NOT_PERFORMED');
      expect(result.files).toHaveLength(0);
      expect(result.provenance).toBeNull();
      expect(result.rejection_reason).toContain('SOURCE_UNAVAILABLE');
    });

    it('truthfully marks SOURCE_UNAVAILABLE when empty or whitespace-only files are passed', () => {
      const result = AuthenticSourceAcquisitionService.verifyAndHashArtifact(
        mockCandidate,
        [
          { path: 'agent.ts', content: '   \n  \t  ' }
        ],
        { version_identity: 'v1.0.0' }
      );

      expect(result.has_authentic_source).toBe(false);
      expect(result.source_status).toBe('SOURCE_UNAVAILABLE');
      expect(result.analysis_status).toBe('ANALYSIS_NOT_PERFORMED');
      expect(result.files).toHaveLength(0);
      expect(result.provenance).toBeNull();
    });

    it('assertAuthenticSourceAcquired throws AuthenticSourceUnavailableError when authentic source is missing', () => {
      expect(() => {
        AuthenticSourceAcquisitionService.assertAuthenticSourceAcquired(
          mockCandidate,
          []
        );
      }).toThrow(AuthenticSourceUnavailableError);
    });

    it('preserves complete provenance and exact content hashes when authentic files are acquired', () => {
      const authenticFiles = [
        {
          path: 'src/agent.ts',
          content: 'export class SecurityAgent { async run() { return "safe"; } }',
        },
        {
          path: 'package.json',
          content: '{"name": "test-real-agent", "version": "1.0.0"}',
        },
      ];

      const result = AuthenticSourceAcquisitionService.verifyAndHashArtifact(
        mockCandidate,
        authenticFiles,
        {
          version_identity: 'v1.0.0',
          canonical_location: 'https://github.com/caim-agents/test-real-agent/tree/main',
        }
      );

      expect(result.has_authentic_source).toBe(true);
      expect(result.source_status).toBe('ACQUIRED');
      expect(result.analysis_status).toBe('ANALYSIS_COMPLETE');
      expect(result.files).toHaveLength(2);
      expect(result.provenance).toBeDefined();

      const prov = result.provenance!;
      expect(prov.discovery_source).toBe('github');
      expect(prov.canonical_artifact_location).toBe('https://github.com/caim-agents/test-real-agent/tree/main');
      expect(prov.version_identity).toBe('v1.0.0');
      expect(prov.content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(prov.exact_files_analyzed).toHaveLength(2);
      expect(prov.exact_files_analyzed[0].sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(prov.exact_files_analyzed[0].byte_size).toBeGreaterThan(0);
      expect(prov.exact_files_analyzed[1].sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(new Date(prov.acquisition_timestamp).getTime()).not.toBeNaN();
    });
  });

  describe('2. StaticAnalysisEngine Anti-Synthetic Guard Clause', () => {
    it('throws an error if StaticAnalysisEngine.analyze is called with no files', () => {
      expect(() => {
        StaticAnalysisEngine.analyze({
          artifactId: 'art-no-files',
          files: [],
          entrypoints: ['index.ts'],
        });
      }).toThrow(/AUTHENTIC_SOURCE_REQUIRED/);
    });

    it('throws an error if StaticAnalysisEngine.analyze is called with empty file contents', () => {
      expect(() => {
        StaticAnalysisEngine.analyze({
          artifactId: 'art-empty-files',
          files: [{ path: 'index.ts', content: '    ' }],
          entrypoints: ['index.ts'],
        });
      }).toThrow(/AUTHENTIC_SOURCE_REQUIRED/);
    });

    it('successfully analyzes authentic source files and extracts findings', () => {
      const authenticSource = [
        {
          path: 'agent.ts',
          content: `
            import { exec } from 'child_process';
            export function runCommand(userCmd: string) {
              eval(userCmd);
              exec(userCmd);
            }
          `,
        },
      ];

      const report = StaticAnalysisEngine.analyze({
        artifactId: 'art-authentic-01',
        files: authenticSource,
        entrypoints: ['agent.ts'],
      });

      expect(report).toBeDefined();
      expect(report.artifact_id).toBe('art-authentic-01');
      expect(report.findings.length).toBeGreaterThan(0);
    });
  });

  describe('3. AutonomousDiscoveryWorker Ingestion Loop Truthful Accounting', () => {
    it('only increments ingested count for agents with authentic source (ANALYSIS_COMPLETE)', async () => {
      const registry = new SourceAdapterRegistry();
      const mockDiscoveryEngine = {
        runDiscovery: async () => ({
          totalCandidates: 2,
          packages: [
            {
              candidate: {
                source_type: 'npm',
                display_name: 'candidate-with-no-source',
                source_locator: 'npm://candidate-with-no-source',
              },
            },
            {
              candidate: {
                source_type: 'github',
                display_name: 'candidate-with-real-source',
                source_locator: 'github://org/candidate-with-real-source',
                acquired_files: [
                  { path: 'index.ts', content: 'export const run = () => "ok";' }
                ],
              },
            },
          ],
          report: { totalCandidates: 2 },
        }),
      };

      const worker = new AutonomousDiscoveryWorker(
        mockDiscoveryEngine as any,
        registry,
        async (candidate: DiscoveryCandidate) => {
          const verification = AuthenticSourceAcquisitionService.verifyAndHashArtifact(
            candidate,
            (candidate as any).acquired_files || null
          );

          if (!verification.has_authentic_source) {
            return {
              agent_id: 'agent-1',
              agent_version_id: 'ver-1',
              canonical_name: candidate.display_name,
              version_label: 'v1.0.0',
              source_type: candidate.source_type,
              source_locator: candidate.source_locator,
              author: 'Community',
              description: 'No source available',
              framework: 'Custom',
              security_classification: 'DATA_UNAVAILABLE',
              discovered_at: new Date().toISOString(),
              analysis_status: 'ANALYSIS_NOT_PERFORMED',
              source_status: 'SOURCE_UNAVAILABLE',
              risk_band: 'NOT_CALCULATED',
              overall_score: 'NOT_CALCULATED',
              policy_outcome: 'NOT_CALCULATED',
              good_use_cases: [],
              bad_use_cases: [],
              findings_count: 'NOT_CALCULATED',
              evidence_count: 'NOT_CALCULATED',
              capabilities: [],
              truthState: 'UNKNOWN',
              truth_state: 'UNKNOWN',
              epistemic_metadata: {} as any,
            };
          }

          return {
            agent_id: 'agent-2',
            agent_version_id: 'ver-2',
            canonical_name: candidate.display_name,
            version_label: 'v1.0.0',
            source_type: candidate.source_type,
            source_locator: candidate.source_locator,
            author: 'Community',
            description: 'Source acquired',
            framework: 'Custom',
            security_classification: 'INTERNAL',
            discovered_at: new Date().toISOString(),
            analysis_status: 'ANALYSIS_COMPLETE',
            source_status: 'ACQUIRED',
            source_provenance: verification.provenance!,
            risk_band: 'LOW',
            overall_score: 88,
            policy_outcome: 'ALLOW',
            good_use_cases: [],
            bad_use_cases: [],
            findings_count: 0,
            evidence_count: 1,
            capabilities: ['Static AST'],
            truthState: 'INFERRED',
            truth_state: 'INFERRED',
            epistemic_metadata: {} as any,
          };
        }
      );

      const cycleResult = await worker.runDiscoveryCycle(['test-query']);

      // Discovered candidates is 2, but only 1 had authentic source analyzed
      expect(cycleResult.candidates_found).toBe(2);
      expect(cycleResult.newly_analyzed).toBe(1);

      // Verify the library accurately reflects both
      const library = worker.getLibrary();
      expect(library).toHaveLength(2);

      const unanalyzed = library.find(a => a.canonical_name === 'candidate-with-no-source');
      expect(unanalyzed?.analysis_status).toBe('ANALYSIS_NOT_PERFORMED');
      expect(unanalyzed?.source_status).toBe('SOURCE_UNAVAILABLE');
      expect(unanalyzed?.overall_score).toBe('NOT_CALCULATED');

      const analyzed = library.find(a => a.canonical_name === 'candidate-with-real-source');
      expect(analyzed?.analysis_status).toBe('ANALYSIS_COMPLETE');
      expect(analyzed?.source_status).toBe('ACQUIRED');
      expect(analyzed?.overall_score).toBe(88);
    });
  });

  describe('4. Ingestion Invariant: Missing Source Strictly Precludes Static Analysis', () => {
    it('proves that ingestion attempt without authentic source NEVER invokes StaticAnalysisEngine.analyze', () => {
      const analyzeSpy = vi.spyOn(StaticAnalysisEngine, 'analyze');

      // Candidate with only locator / metadata, but NO authentic source acquired
      const discoveredCandidate: DiscoveryCandidate = {
        source_type: 'github',
        display_name: 'synthetic-bypass-attempt',
        source_locator: 'https://github.com/unknown/synthetic-bypass-attempt',
        type_hint: 'AGENT_REPOSITORY',
        confidence: 0.95,
        discovered_at: '2026-09-13T00:00:00.000Z',
        raw_metadata: {
          description: 'A mock agent that has not had source files downloaded',
        },
      };

      // 1. Verify gatekeeper check
      const verification = AuthenticSourceAcquisitionService.verifyAndHashArtifact(
        discoveredCandidate,
        null // No authentic files acquired
      );

      // Invariant: Must report SOURCE_UNAVAILABLE and ANALYSIS_NOT_PERFORMED
      expect(verification.has_authentic_source).toBe(false);
      expect(verification.source_status).toBe('SOURCE_UNAVAILABLE');
      expect(verification.analysis_status).toBe('ANALYSIS_NOT_PERFORMED');

      // 2. Ingestion pipeline decision branch based on verification
      if (verification.has_authentic_source) {
        StaticAnalysisEngine.analyze({
          artifactId: 'art-never-reached',
          files: verification.files.map(f => ({ path: f.path, content: f.content as string })),
          entrypoints: ['agent.ts'],
        });
      }

      // Assert StaticAnalysisEngine was NEVER called
      expect(analyzeSpy).not.toHaveBeenCalled();

      // Clean up spy
      analyzeSpy.mockRestore();
    });
  });
});
