import { describe, it, expect, vi } from 'vitest';
import {
  AuthenticSourceAcquisitionService,
  AuthenticSourceUnavailableError,
  DiscoveryCandidate,
  AuthenticSourceFile,
} from '@caim/source';
import { StaticAnalysisEngine, runStaticAnalysisJob } from '../workers/static-analysis/index.ts';

describe('Prompt 3: Authentic Source Acquisition Invariant & Anti-Synthetic Enforcement', () => {
  const candidateFixture: DiscoveryCandidate = {
    source_type: 'github',
    display_name: 'acme/prod-agent',
    source_locator: 'https://github.com/acme/prod-agent',
    type_hint: 'AGENT_REPOSITORY',
    confidence: 0.98,
    discovered_at: '2026-09-15T12:00:00.000Z',
    raw_metadata: {
      framework: 'CrewAI',
      version: 'v2.4.1',
      author: 'AcmeCorp',
    },
  };

  describe('1. Missing Source Acquisition Can NEVER Result in ANALYSIS_COMPLETE', () => {
    it('pipeline retains discovered candidate and records DISCOVERED / SOURCE_UNAVAILABLE / ANALYSIS_NOT_PERFORMED when acquisition yields null', async () => {
      const analyzeSpy = vi.spyOn(StaticAnalysisEngine, 'analyze');

      // Attempt pipeline with source fetcher returning null (artifact source not acquired)
      const pipelineResult = await AuthenticSourceAcquisitionService.executePipeline(
        candidateFixture,
        async () => null
      );

      // Invariant: Candidate must be retained, not discarded
      expect(pipelineResult.candidate).toBeDefined();
      expect(pipelineResult.candidate.display_name).toBe('acme/prod-agent');

      // Truthful failure semantics
      expect(pipelineResult.candidate_status).toBe('DISCOVERED');
      expect(pipelineResult.source_status).toBe('SOURCE_UNAVAILABLE');
      expect(pipelineResult.analysis_status).toBe('ANALYSIS_NOT_PERFORMED');
      expect(pipelineResult.analysis_status).not.toBe('ANALYSIS_COMPLETE');
      expect(pipelineResult.provenance).toBeNull();
      expect(pipelineResult.files_analyzed_count).toBe(0);

      // Verify stages: ACQUIRE failed, subsequent analysis stages skipped
      const stageNames = pipelineResult.pipeline_stages.map(s => s.stage);
      expect(stageNames).toEqual([
        'DISCOVER',
        'IDENTIFY',
        'ACQUIRE_ACTUAL_ARTIFACT',
        'VERIFY_ARTIFACT',
        'HASH_PROVENANCE',
        'PARSE',
        'STATIC_ANALYSIS',
        'TAINT_SECURITY_ANALYSIS',
      ]);

      const acquireStage = pipelineResult.pipeline_stages.find(s => s.stage === 'ACQUIRE_ACTUAL_ARTIFACT');
      expect(acquireStage?.status).toBe('FAILED');

      const skippedStages = pipelineResult.pipeline_stages.filter(s => s.status === 'SKIPPED');
      expect(skippedStages.map(s => s.stage)).toEqual([
        'VERIFY_ARTIFACT',
        'HASH_PROVENANCE',
        'PARSE',
        'STATIC_ANALYSIS',
        'TAINT_SECURITY_ANALYSIS',
      ]);

      // Static analysis engine must NEVER be called
      expect(analyzeSpy).not.toHaveBeenCalled();
      analyzeSpy.mockRestore();
    });

    it('pipeline retains candidate when acquisition throws network/auth error and marks ANALYSIS_NOT_PERFORMED', async () => {
      const pipelineResult = await AuthenticSourceAcquisitionService.executePipeline(
        candidateFixture,
        async () => {
          throw new Error('404 Not Found: Repository source archive unavailable');
        }
      );

      expect(pipelineResult.candidate_status).toBe('DISCOVERED');
      expect(pipelineResult.source_status).toBe('SOURCE_UNAVAILABLE');
      expect(pipelineResult.analysis_status).toBe('ANALYSIS_NOT_PERFORMED');
      expect(pipelineResult.analysis_status).not.toBe('ANALYSIS_COMPLETE');
      expect(pipelineResult.provenance).toBeNull();
    });

    it('assertAuthenticSourceAcquired throws AuthenticSourceUnavailableError on missing source', () => {
      expect(() => {
        AuthenticSourceAcquisitionService.assertAuthenticSourceAcquired(candidateFixture, null);
      }).toThrow(AuthenticSourceUnavailableError);

      try {
        AuthenticSourceAcquisitionService.assertAuthenticSourceAcquired(candidateFixture, null);
      } catch (err: any) {
        expect(err.code).toBe('SOURCE_UNAVAILABLE');
        expect(err.analysis_status).toBe('ANALYSIS_NOT_PERFORMED');
      }
    });
  });

  describe('2. Representative or Substitute Source Code is Strictly Prohibited & Never Analyzed', () => {
    it('rejects files explicitly flagged as synthetic or representative', async () => {
      const substituteFiles = [
        {
          path: 'agent.ts',
          content: 'export class FakeAgent {}',
          is_representative: true,
        },
      ];

      const verification = AuthenticSourceAcquisitionService.verifyAndHashArtifact(
        candidateFixture,
        substituteFiles as any
      );

      expect(verification.has_authentic_source).toBe(false);
      expect(verification.candidate_status).toBe('DISCOVERED');
      expect(verification.source_status).toBe('SOURCE_UNAVAILABLE');
      expect(verification.analysis_status).toBe('ANALYSIS_NOT_PERFORMED');
      expect(verification.provenance).toBeNull();
      expect(verification.rejection_reason).toContain('Synthetic, representative, or substitute code is strictly prohibited');
    });

    it('rejects files containing representative substitute comment headers', async () => {
      const placeholderFiles = [
        {
          path: 'entrypoint.ts',
          content: '// Sample entrypoint\nexport function main() { return true; }',
        },
      ];

      const verification = AuthenticSourceAcquisitionService.verifyAndHashArtifact(
        candidateFixture,
        placeholderFiles
      );

      expect(verification.has_authentic_source).toBe(false);
      expect(verification.source_status).toBe('SOURCE_UNAVAILABLE');
      expect(verification.analysis_status).toBe('ANALYSIS_NOT_PERFORMED');
      expect(verification.rejection_reason).toContain('Synthetic or representative substitute code cannot be analyzed');
    });

    it('StaticAnalysisEngine.analyze rejects representative or substitute files', () => {
      expect(() => {
        StaticAnalysisEngine.analyze({
          artifactId: 'substitute-bypass-test',
          files: [
            {
              path: 'agent.ts',
              content: 'export const x = 1;',
              is_representative: true,
            } as any,
          ],
        });
      }).toThrow(/AUTHENTIC_SOURCE_REQUIRED: Synthetic or representative substitute code cannot be analyzed/);

      expect(() => {
        StaticAnalysisEngine.analyze({
          artifactId: 'substitute-header-test',
          files: [
            {
              path: 'agent.ts',
              content: '// Sample entrypoint\nexport const x = 1;',
            },
          ],
        });
      }).toThrow(/AUTHENTIC_SOURCE_REQUIRED: Synthetic or representative substitute code cannot be analyzed/);
    });

    it('runStaticAnalysisJob throws error rather than synthesizing a sample entrypoint when files are omitted', async () => {
      await expect(
        runStaticAnalysisJob({
          artifactId: 'no-files-job',
          // files omitted intentionally
        } as any)
      ).rejects.toThrow(/AUTHENTIC_SOURCE_REQUIRED/);
    });

    it('SyntaxIntelligencePipeline strictly rejects missing or substitute source files without analysis', async () => {
      const { SyntaxIntelligencePipeline } = await import('@caim/syntax/intelligence-pipeline.ts');

      // 1. Missing files
      expect(() => {
        SyntaxIntelligencePipeline.processArtifact('syntax-missing-files', []);
      }).toThrow(/AUTHENTIC_SOURCE_REQUIRED/);

      // 2. Explicit representative or substitute flag
      expect(() => {
        SyntaxIntelligencePipeline.processArtifact('syntax-substitute-file', [
          {
            path: 'agent.ts',
            content: 'export class RepresentativeAgent {}',
            is_representative: true,
          } as any,
        ]);
      }).toThrow(/AUTHENTIC_SOURCE_REQUIRED: Synthetic or representative substitute code cannot be parsed or analyzed/);

      // 3. Substitute comment header
      expect(() => {
        SyntaxIntelligencePipeline.processArtifact('syntax-substitute-header', [
          {
            path: 'agent.ts',
            content: '// Sample entrypoint\nexport const x = 1;',
          },
        ]);
      }).toThrow(/AUTHENTIC_SOURCE_REQUIRED: Synthetic or representative substitute code cannot be parsed or analyzed/);
    });

    it('DataflowTaintEngine strictly rejects missing or substitute source without analysis', async () => {
      const { DataflowTaintEngine } = await import('../workers/static-analysis/taint/engine.ts');

      // 1. Empty map
      expect(() => {
        DataflowTaintEngine.traceTaint(
          'taint-empty',
          {} as any,
          new Map(),
          {} as any,
          {} as any,
          []
        );
      }).toThrow(/AUTHENTIC_SOURCE_REQUIRED: Taint analysis cannot execute without authentic source files/);

      // 2. Substitute header in content map
      const map = new Map<string, string>();
      map.set('agent.ts', '// Representative substitute\nexport const x = 1;');
      expect(() => {
        DataflowTaintEngine.traceTaint(
          'taint-substitute',
          {} as any,
          map,
          {} as any,
          {} as any,
          []
        );
      }).toThrow(/AUTHENTIC_SOURCE_REQUIRED: Synthetic or representative substitute code cannot be analyzed in taint engine/);
    });
  });

  describe('3. Enforced Pipeline Sequence with Provenance Preservation', () => {
    it('executes the full 8-step pipeline on authentic acquired artifacts', async () => {
      const authenticSourceFiles: AuthenticSourceFile[] = [
        {
          path: 'src/main.ts',
          content: `
            import { Tool } from 'langchain/tools';
            export class WebSearchTool extends Tool {
              name = "web_search";
              description = "Searches the live web";
              async _call(query: string) {
                return fetch("https://api.search.internal?q=" + query);
              }
            }
          `,
          hash: '',
          byte_size: 0,
        },
        {
          path: 'package.json',
          content: '{"name": "acme-prod-agent", "version": "2.4.1"}',
          hash: '',
          byte_size: 0,
        },
      ];

      const pipelineResult = await AuthenticSourceAcquisitionService.executePipeline(
        candidateFixture,
        async () => authenticSourceFiles,
        {
          parseAndAnalyze: async (files, prov) => {
            return StaticAnalysisEngine.analyze({
              artifactId: 'art-pipeline-test-01',
              files: files.map(f => ({ path: f.path, content: f.content as string })),
            });
          },
        },
        {
          canonical_location: 'https://github.com/acme/prod-agent/releases/tag/v2.4.1',
          version_identity: 'v2.4.1',
          discovery_provider: 'github-enterprise',
        }
      );

      // Provenance must be preserved before analysis
      expect(pipelineResult.provenance).not.toBeNull();
      const prov = pipelineResult.provenance!;
      expect(prov.discovery_source).toBe('github');
      expect(prov.discovery_provider).toBe('github-enterprise');
      expect(prov.canonical_artifact_location).toBe('https://github.com/acme/prod-agent/releases/tag/v2.4.1');
      expect(prov.version_identity).toBe('v2.4.1');
      expect(prov.acquisition_timestamp).toBeDefined();
      expect(prov.content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(prov.exact_files_analyzed).toHaveLength(2);
      expect(prov.exact_files_analyzed[0].sha256).toBeDefined();
      expect(prov.exact_files_analyzed[0].byte_size).toBeGreaterThan(0);

      // Pipeline execution success
      expect(pipelineResult.candidate_status).toBe('DISCOVERED');
      expect(pipelineResult.source_status).toBe('ACQUIRED');
      expect(pipelineResult.analysis_status).toBe('ANALYSIS_COMPLETE');
      expect(pipelineResult.files_analyzed_count).toBe(2);

      // Verify all 8 stages completed in sequence
      const stages = pipelineResult.pipeline_stages;
      expect(stages).toHaveLength(8);
      expect(stages.every(s => s.status === 'COMPLETED')).toBe(true);
      expect(stages.map(s => s.stage)).toEqual([
        'DISCOVER',
        'IDENTIFY',
        'ACQUIRE_ACTUAL_ARTIFACT',
        'VERIFY_ARTIFACT',
        'HASH_PROVENANCE',
        'PARSE',
        'STATIC_ANALYSIS',
        'TAINT_SECURITY_ANALYSIS',
      ]);
    });
  });
});
