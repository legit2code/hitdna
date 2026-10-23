/**
 * Composition, SBOM/AI-BOM, Vulnerability & Reachability Intelligence Worker
 * Logical Engines: E29, E30, E31, E32, E33, E34, E35
 */

export * from './types.ts';
export * from './purl/index.ts';
export * from './manifests/index.ts';
export * from './manifests/npm.ts';
export * from './manifests/pypi.ts';
export * from './manifests/golang.ts';
export * from './cyclonedx/index.ts';
export * from './aibom/index.ts';
export * from './advisories/index.ts';
export * from './advisories/osv.ts';
export * from './advisories/nvd.ts';
export * from './advisories/catalog.ts';
export * from './reachability/index.ts';
export * from './compliance/license.ts';
export * from './compliance/malicious.ts';
export * from './engine.ts';
export * from './fixtures.ts';

export interface CompositionJob {
  artifactId: string;
  files?: Record<string, string>;
  options?: any;
}

export async function runCompositionJob(job: CompositionJob) {
  const fileMap = new Map<string, string>();
  if (job.files) {
    for (const [k, v] of Object.entries(job.files)) {
      fileMap.set(k, v);
    }
  }

  const { CompositionEngine } = await import('./engine.ts');
  const result = await CompositionEngine.run({
    artifactId: job.artifactId,
    files: fileMap,
    ...(job.options || {}),
  });

  return {
    status: 'COMPOSITION_COMPLETED',
    result,
  };
}
