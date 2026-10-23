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

export interface DockerHubAdapterOptions {
  token?: string;
  baseUrl?: string;
  fetcher?: HttpFetcher;
}

export class DockerHubSourceAdapter extends BaseSourceAdapter {
  readonly sourceType = 'dockerhub';
  readonly sourceName = 'Docker Hub';
  readonly adapterVersion = '1.0.0';

  private readonly token?: string;
  private readonly baseUrl: string;

  constructor(options: DockerHubAdapterOptions = {}) {
    super({
      fetcher: options.fetcher,
      initialRateLimit: {
        limit: options.token ? 5000 : 200,
        remaining: options.token ? 5000 : 200,
        window_seconds: 3600 * 6, // Docker anonymous pull rate limit window (6 hours)
        is_exhausted: false,
      },
    });
    this.token = options.token || (typeof process !== 'undefined' ? process.env.DOCKERHUB_TOKEN : undefined);
    this.baseUrl = options.baseUrl || 'https://hub.docker.com/v2';
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'User-Agent': 'caim-source-adapter/1.0.0',
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  private parseImageLocator(locator: string): { namespace: string; repository: string } {
    let clean = locator.replace(/^docker:\/\//, '').replace(/^https?:\/\/hub\.docker\.com\/r\//, '');
    clean = clean.replace(/\/$/, '');
    const parts = clean.split('/');
    if (parts.length === 1) {
      return { namespace: 'library', repository: parts[0] };
    }
    if (parts.length >= 2) {
      return { namespace: parts[0], repository: parts[1].split(':')[0] };
    }
    throw new Error(`Invalid Docker locator: '${locator}'`);
  }

  async discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult> {
    const page = cursor?.page ?? 1;
    const pageSize = Math.min(criteria.limit ?? 25, 100);

    const searchUrl = new URL(`${this.baseUrl}/search/repositories/`);
    searchUrl.searchParams.set('query', criteria.query || 'agent');
    searchUrl.searchParams.set('page', String(page));
    searchUrl.searchParams.set('page_size', String(pageSize));

    const res = await this.request<{ results: any[]; count: number }>(searchUrl.toString(), {
      headers: this.getHeaders(),
    });

    const results = res.data?.results || [];
    const count = res.data?.count || 0;
    const hasMore = page * pageSize < count;

    const candidates: DiscoveryCandidate[] = results.map((item) => {
      const repoName = item.repo_name || `${item.namespace || 'library'}/${item.name}`;
      return {
        source_locator: `docker://${repoName}`,
        display_name: repoName,
        source_type: this.sourceType,
        type_hint: 'CONTAINER_IMAGE',
        confidence: 1.0,
        summary: item.short_description || item.description || undefined,
        raw_metadata: item,
        created_at: item.created_at,
        updated_at: item.last_updated,
        discovered_at: new Date().toISOString(),
      };
    });

    return {
      candidates,
      next_cursor: hasMore ? { page: page + 1 } : null,
      has_more: hasMore,
      rate_limit: this.get_rate_limit_state(),
      provenance: this.generate_provenance('DISCOVER', [this.hashPayload(results)]),
    };
  }

  async fetch_metadata(locator: string): Promise<SourceMetadataResult> {
    const { namespace, repository } = this.parseImageLocator(locator);
    const url = `${this.baseUrl}/repositories/${namespace}/${repository}/`;

    const res = await this.request<Record<string, unknown>>(url, {
      headers: this.getHeaders(),
      locator: `docker://${namespace}/${repository}`,
    });

    const rawData = res.data || {};
    const contentHash = this.hashPayload(rawData);

    return {
      source_locator: `docker://${namespace}/${repository}`,
      raw_metadata: rawData,
      content_hash: contentHash,
      observed_at: new Date().toISOString(),
      etag: res.headers['etag'],
      provenance: this.generate_provenance('FETCH_METADATA', [contentHash]),
    };
  }

  async resolve_immutable_identity(candidate: DiscoveryCandidate | string, tag: string = 'latest'): Promise<ImmutableResolutionResult> {
    const locator = this.extractLocator(candidate);
    return ImmutableVersionResolver.resolveDockerHub(locator, tag, this.fetcher);
  }

  async resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult> {
    const locator = this.extractLocator(candidate);
    const { namespace, repository } = this.parseImageLocator(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    let digest: string | undefined = (raw.digest as string) || (raw.manifest_digest as string);
    if (!digest && Array.isArray(raw.images) && raw.images.length > 0) {
      digest = raw.images[0].digest;
    }

    if (!digest || !ImmutableVersionResolver.isManifestDigest(digest)) {
      try {
        const resolved = await ImmutableVersionResolver.resolveDockerHub(locator, 'latest', this.fetcher);
        digest = resolved.manifest_digest;
      } catch {
        // Fallback
      }
    }

    const imageRef = `${namespace === 'library' ? '' : namespace + '/'}${repository}`;
    const canonicalLocator = digest
      ? `docker.io/${namespace}/${repository}@${digest}`
      : `docker.io/${namespace}/${repository}:latest`;

    const artifacts: ArtifactLocatorEntry[] = [
      {
        artifact_type: 'CONTAINER_MANIFEST',
        locator: canonicalLocator,
        filename: digest ? `${repository}@${digest.replace('sha256:', '')}` : `${repository}-latest`,
        mime_type: 'application/vnd.docker.distribution.manifest.v2+json',
        is_primary: true,
        metadata: {
          image_tag: 'latest',
          manifest_digest: digest,
          is_container_artifact: true,
          is_source_code: false,
          pull_cmd: digest ? `docker pull ${imageRef}@${digest}` : `docker pull ${imageRef}:latest`,
          star_count: raw.star_count,
          pull_count: raw.pull_count,
        },
      },
    ];

    return {
      source_locator: canonicalLocator,
      primary_locator: canonicalLocator,
      artifacts,
      provenance: this.generate_provenance('RESOLVE_ARTIFACTS', [this.hashPayload(artifacts)]),
    };
  }

  async enumerate_relationships(candidate: DiscoveryCandidate | string): Promise<DiscoveryRelationshipsResult> {
    const locator = this.extractLocator(candidate);
    const { namespace, repository } = this.parseImageLocator(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    const relationships: CandidateRelationship[] = [];

    // Namespace / Org
    if (namespace && namespace !== 'library') {
      relationships.push({
        from_locator: `docker://${namespace}/${repository}`,
        target_locator: `docker://orgs/${namespace}`,
        relationship_type: 'MAINTAINED_BY',
        depth: 1,
      });
    }

    // Base Image if identified in descriptions/metadata
    if (raw.base_image) {
      relationships.push({
        from_locator: `docker://${namespace}/${repository}`,
        target_locator: `docker://${raw.base_image}`,
        relationship_type: 'BASE_IMAGE',
        target_type_hint: 'CONTAINER_IMAGE',
        depth: 1,
      });
    }

    return {
      source_locator: `docker://${namespace}/${repository}`,
      relationships,
      provenance: this.generate_provenance('ENUMERATE_RELATIONSHIPS', [this.hashPayload(relationships)]),
    };
  }

  async get_change_token(candidate: DiscoveryCandidate | string): Promise<ChangeTokenResult> {
    const locator = this.extractLocator(candidate);
    const { namespace, repository } = this.parseImageLocator(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    const token = (raw.last_updated as string) || (raw.digest as string) || 'unknown-docker-token';
    return {
      source_locator: `docker://${namespace}/${repository}`,
      change_token: token,
      token_type: raw.digest ? 'DIGEST' : 'TIMESTAMP',
      last_modified: raw.last_updated as string,
    };
  }

  get_source_policy(): SourcePolicy {
    return {
      source_type: this.sourceType,
      source_name: this.sourceName,
      auth_mode: this.token ? 'AUTHENTICATED' : 'DEGRADED',
      max_page_size: 100,
      rate_limit_per_minute: this.token ? 300 : 50,
      retry_policy: {
        max_retries: 3,
        backoff_factor: 2.0,
        initial_delay_ms: 1000,
      },
      supported_query_families: ['query', 'is_official', 'is_automated', 'stars'],
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
      const url = `${this.baseUrl}/search/repositories/?query=alpine&page_size=1`;
      await this.request(url, { headers: this.getHeaders() });
      const latency = Date.now() - start;

      return {
        status: this.token ? 'HEALTHY' : 'DEGRADED',
        auth_status: this.token ? 'AUTHENTICATED' : 'ANONYMOUS',
        message: this.token 
          ? 'Docker Hub authenticated session active' 
          : 'Docker Hub public anonymous search operating (subject to anonymous pull rate limits)',
        latency_ms: latency,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        status: 'UNHEALTHY',
        auth_status: this.token ? 'INVALID_CREDENTIALS' : 'ANONYMOUS',
        message: `Docker Hub health check failed: ${err.message}`,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }
}
