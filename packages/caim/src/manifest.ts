import { CaimManifest, CAIM_SPEC_VERSION } from './types.ts';
import { CaimManifestSchema } from './schemas.ts';

export function createEmptyCaimManifest(params: {
  agent_id: string;
  canonical_name: string;
  agent_version_id: string;
  content_fingerprint: string;
  version_label?: string;
}): CaimManifest {
  return {
    caim_version: CAIM_SPEC_VERSION,
    agent: {
      _entity_kind: 'CANONICAL_AGENT',
      agent_id: params.agent_id,
      canonical_name: params.canonical_name,
      status: 'ACTIVE',
      identity_confidence: 1.0,
    },
    version: {
      _entity_kind: 'AGENT_VERSION',
      agent_version_id: params.agent_version_id,
      agent_id: params.agent_id,
      version_label: params.version_label,
      content_fingerprint: params.content_fingerprint,
    },
    distributions: [],
    components: [],
    dependencies: [],
    tools: [],
    tool_bindings: [],
    protocols: [],
    protocol_capabilities: [],
    capabilities: [],
    permissions: [],
    entrypoints: [],
    runtimes: [],
    endpoints: [],
    models: [],
    datasets: [],
    prompts: [],
    configurations: [],
    credentials: [],
    data_access_requirements: [],
  };
}

export function validateCaimManifest(manifest: unknown): CaimManifest {
  return CaimManifestSchema.parse(manifest) as CaimManifest;
}
