import { BaseSourceAdapter } from '../base-adapter.ts';
import {
  DiscoveryCriteria,
  DiscoveryResult,
  CursorState,
  SourceMetadataResult,
  ResolvedArtifactLocatorsResult,
  DiscoveryRelationshipsResult,
  ChangeTokenResult,
  SourcePolicy,
  AdapterHealth,
  DiscoveryCandidate,
  HttpFetcher,
  CandidateRelationship,
  ArtifactLocatorEntry,
  ImmutableResolutionResult,
} from '../types.ts';
import { ImmutableVersionResolver } from '../immutable-resolver.ts';
import { FetchGateway } from '../fetch-gateway/index.ts';

export interface MCPServerData {
  $schema?: string;
  name: string;
  title?: string;
  description?: string;
  version?: string;
  websiteUrl?: string;
  repository?: {
    url: string;
    source?: string;
  };
  packages?: Array<{
    registryType: string;
    identifier: string;
    version?: string;
    transport?: {
      type: string;
    };
  }>;
  remotes?: Array<{
    type: string;
    url: string;
    headers?: Array<{
      name: string;
      isRequired?: boolean;
      isSecret?: boolean;
      description?: string;
    }>;
  }>;
  icons?: Array<{
    src: string;
    mimeType?: string;
    sizes?: string[];
  }>;
  _meta?: Record<string, unknown>;
}

export interface MCPRegistryEnvelope {
  server: MCPServerData;
  _meta?: {
    'io.modelcontextprotocol.registry/official'?: {
      status?: string;
      publishedAt?: string;
      updatedAt?: string;
      isLatest?: boolean;
    };
    [key: string]: unknown;
  };
}

export interface MCPRegistryListResponse {
  servers?: MCPRegistryEnvelope[];
  metadata?: {
    nextCursor?: string;
    count?: number;
  };
}

export interface MCPAdapterOptions {
  baseUrl?: string;
  fetcher?: HttpFetcher;
  gateway?: FetchGateway;
}

export class MCPSourceAdapter extends BaseSourceAdapter {
  readonly sourceType = 'mcp';
  readonly sourceName = 'Official MCP Registry';
  readonly adapterVersion = '1.0.0';

  private readonly baseUrl: string;

  constructor(options: MCPAdapterOptions = {}) {
    super({
      fetcher: options.fetcher,
      gateway: options.gateway,
      initialRateLimit: {
        limit: 100,
        remaining: 100,
        window_seconds: 60,
        is_exhausted: false,
      },
    });
    this.baseUrl = (options.baseUrl || 'https://registry.modelcontextprotocol.io').replace(/\/$/, '');
  }

  private parseServerName(locator: string): string {
    let clean = locator.replace(/^mcp:\/\//, '').replace(/^https?:\/\/registry\.modelcontextprotocol\.io\/v0\/servers\/?/, '');
    clean = clean.replace(/\/$/, '');
    if (!clean) {
      throw new Error(`Invalid MCP server locator: '${locator}'`);
    }
    return clean;
  }

  async discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult> {
    const url = new URL(`${this.baseUrl}/v0/servers`);
    if (criteria.query) {
      url.searchParams.set('search', criteria.query);
    }
    if (criteria.limit) {
      url.searchParams.set('limit', String(Math.min(criteria.limit, 100)));
    }
    if (cursor?.token) {
      url.searchParams.set('cursor', cursor.token);
    }

    const res = await this.request<MCPRegistryListResponse>(url.toString(), {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'caim-source-adapter/1.0.0',
      },
    });

    const items = res.data?.servers || [];
    const nextCursor = res.data?.metadata?.nextCursor || null;

    // MCP servers are tool/context providers, not automatic agents!
    // They must be classified through the downstream pipeline.
    const candidates: DiscoveryCandidate[] = items.map((item) => {
      const server = item.server;
      const officialMeta = item._meta?.['io.modelcontextprotocol.registry/official'];
      return {
        source_locator: `mcp://${server.name}`,
        display_name: server.title ? `${server.title} (${server.name})` : server.name,
        source_type: this.sourceType,
        type_hint: 'TOOL_SPECIFICATION',
        confidence: 0.85,
        summary: server.description || undefined,
        raw_metadata: item as unknown as Record<string, unknown>,
        created_at: officialMeta?.publishedAt,
        updated_at: officialMeta?.updatedAt,
        discovered_at: new Date().toISOString(),
      };
    });

    return {
      candidates,
      next_cursor: nextCursor ? { token: nextCursor } : null,
      has_more: !!nextCursor,
      rate_limit: this.get_rate_limit_state(),
      provenance: this.generate_provenance('DISCOVER', [this.hashPayload(items)]),
    };
  }

  async fetch_metadata(locator: string): Promise<SourceMetadataResult> {
    const serverName = this.parseServerName(locator);
    const url = new URL(`${this.baseUrl}/v0/servers`);
    url.searchParams.set('search', serverName);
    url.searchParams.set('limit', '10');

    const res = await this.request<MCPRegistryListResponse>(url.toString(), {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'caim-source-adapter/1.0.0',
      },
      locator: `mcp://${serverName}`,
    });

    const servers = res.data?.servers || [];
    const matched = servers.find((s) => s.server.name === serverName) || servers[0];

    if (!matched) {
      throw new Error(`[SOURCE_UNAVAILABLE] MCP server '${serverName}' not found in registry`);
    }

    const contentHash = this.hashPayload(matched);

    return {
      source_locator: `mcp://${serverName}`,
      raw_metadata: matched as unknown as Record<string, unknown>,
      content_hash: contentHash,
      observed_at: new Date().toISOString(),
      etag: res.headers['etag'],
      provenance: this.generate_provenance('FETCH_METADATA', [contentHash]),
    };
  }

  async resolve_canonical_pivot(candidate: DiscoveryCandidate | string): Promise<ImmutableResolutionResult> {
    const locator = this.extractLocator(candidate);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};
    return ImmutableVersionResolver.resolveDiscoveryOnlyPivot('mcp', locator, raw);
  }

  async resolve_immutable_identity(candidate: DiscoveryCandidate | string): Promise<ImmutableResolutionResult> {
    return this.resolve_canonical_pivot(candidate);
  }

  async resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult> {
    const locator = this.extractLocator(candidate);
    const meta = await this.fetch_metadata(locator);
    const envelope = meta.raw_metadata as unknown as MCPRegistryEnvelope;
    const server = envelope?.server;

    const locators: ArtifactLocatorEntry[] = [
      {
        locator,
        artifact_type: 'SPECIFICATION',
        mime_type: 'application/json',
        is_primary: true,
      },
    ];

    if (server?.repository?.url) {
      locators.push({
        locator: server.repository.url,
        artifact_type: 'GIT_REPOSITORY',
        mime_type: 'application/x-git',
        is_primary: false,
      });
    }

    if (server?.websiteUrl) {
      locators.push({
        locator: server.websiteUrl,
        artifact_type: 'DOCUMENTATION',
        mime_type: 'text/html',
        is_primary: false,
      });
    }

    if (Array.isArray(server?.packages)) {
      for (const pkg of server.packages) {
        if (pkg.registryType === 'npm') {
          locators.push({
            locator: `npm://${pkg.identifier}`,
            artifact_type: 'NPM_TARBALL',
            mime_type: 'application/gzip',
            is_primary: false,
          });
        } else if (pkg.registryType === 'pypi') {
          locators.push({
            locator: `pypi://${pkg.identifier}`,
            artifact_type: 'PACKAGE_DISTRIBUTION',
            mime_type: 'application/gzip',
            is_primary: false,
          });
        }
      }
    }

    return {
      source_locator: locator,
      primary_locator: locator,
      artifacts: locators,
      provenance: this.generate_provenance('RESOLVE_ARTIFACTS', [this.hashPayload(locators)]),
    };
  }

  async enumerate_relationships(candidate: DiscoveryCandidate | string): Promise<DiscoveryRelationshipsResult> {
    const locator = this.extractLocator(candidate);
    const meta = await this.fetch_metadata(locator);
    const envelope = meta.raw_metadata as unknown as MCPRegistryEnvelope;
    const server = envelope?.server;

    const relationships: CandidateRelationship[] = [];

    if (server?.repository?.url) {
      relationships.push({
        from_locator: locator,
        target_locator: server.repository.url,
        relationship_type: 'UPSTREAM_SOURCE',
        target_type_hint: 'AGENT_REPOSITORY',
        depth: 1,
        metadata: {
          role: 'source_repository',
          source: server.repository.source || 'github',
        },
      });
    }

    if (Array.isArray(server?.packages)) {
      for (const pkg of server.packages) {
        relationships.push({
          from_locator: locator,
          target_locator: `${pkg.registryType}://${pkg.identifier}`,
          relationship_type: 'RELATED_PACKAGE',
          target_type_hint: 'PACKAGE_DISTRIBUTION',
          depth: 1,
          metadata: {
            registry: pkg.registryType,
            transport: pkg.transport?.type,
          },
        });
      }
    }

    if (server?.websiteUrl) {
      relationships.push({
        from_locator: locator,
        target_locator: server.websiteUrl,
        relationship_type: 'HOMEPAGE',
        depth: 1,
      });
    }

    return {
      source_locator: locator,
      relationships,
      provenance: this.generate_provenance('ENUMERATE_RELATIONSHIPS', [this.hashPayload(relationships)]),
    };
  }

  async get_change_token(candidate: DiscoveryCandidate | string): Promise<ChangeTokenResult> {
    const locator = this.extractLocator(candidate);
    const meta = await this.fetch_metadata(locator);
    const envelope = meta.raw_metadata as unknown as MCPRegistryEnvelope;
    const version = envelope?.server?.version || '0.0.0';
    const updatedAt = envelope?._meta?.['io.modelcontextprotocol.registry/official']?.updatedAt || meta.observed_at;
    const token = `${version}:${updatedAt}`;

    return {
      source_locator: locator,
      change_token: token,
      token_type: 'VERSION',
      last_modified: updatedAt,
    };
  }

  get_source_policy(): SourcePolicy {
    return {
      source_type: this.sourceType,
      source_name: this.sourceName,
      auth_mode: 'ANONYMOUS',
      max_page_size: 100,
      rate_limit_per_minute: 60,
      retry_policy: {
        max_retries: 3,
        backoff_factor: 2.0,
        initial_delay_ms: 1000,
      },
      supported_query_families: ['keyword', 'namespace', 'package', 'transport'],
      capabilities: {
        can_stream: false,
        can_search: true,
        provides_dependencies: true,
        provides_artifacts: true,
        requires_auth: false,
      },
    };
  }

  async health_check(): Promise<AdapterHealth> {
    const start = Date.now();
    try {
      const res = await this.request<MCPRegistryListResponse>(`${this.baseUrl}/v0/servers?limit=1`, {
        timeoutMs: 8000,
      });
      const latency = Date.now() - start;
      const count = res.data?.servers?.length || 0;
      return {
        status: res.status === 200 ? 'HEALTHY' : 'DEGRADED',
        auth_status: 'ANONYMOUS',
        message: res.status === 200
          ? `[ACTIVE] Official MCP Registry reachable (${count} sample servers available)`
          : `[TEMPORARILY_DEGRADED] Unexpected status: ${res.status}`,
        latency_ms: latency,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        status: 'UNHEALTHY',
        auth_status: 'ANONYMOUS',
        message: `[SOURCE_UNAVAILABLE] Failed to reach Official MCP Registry: ${err.message}`,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }
}
