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
import { ImmutableVersionResolver, ProviderIntegrityVerifier } from '../immutable-resolver.ts';

export interface NpmAdapterOptions {
  baseUrl?: string;
  fetcher?: HttpFetcher;
}

export class NpmSourceAdapter extends BaseSourceAdapter {
  readonly sourceType = 'npm';
  readonly sourceName = 'npm';
  readonly adapterVersion = '1.0.0';

  private readonly baseUrl: string;

  constructor(options: NpmAdapterOptions = {}) {
    super({
      fetcher: options.fetcher,
      initialRateLimit: {
        limit: 1000,
        remaining: 1000,
        window_seconds: 60,
        is_exhausted: false,
      },
    });
    this.baseUrl = options.baseUrl || 'https://registry.npmjs.org';
  }

  private parsePackageName(locator: string): string {
    let clean = locator.replace(/^npm:\/\//, '').replace(/^https?:\/\/(www\.)?npmjs\.com\/package\//, '');
    clean = clean.replace(/\/$/, '');
    if (!clean) {
      throw new Error(`Invalid npm locator: '${locator}'`);
    }
    return clean;
  }

  private encodePackageName(name: string): string {
    // Scoped packages like @org/pkg must encode the slash as %2f
    if (name.startsWith('@')) {
      const [scope, pkg] = name.split('/');
      return `${encodeURIComponent(scope)}%2f${encodeURIComponent(pkg)}`;
    }
    return encodeURIComponent(name);
  }

  async discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult> {
    const from = cursor?.offset ?? (cursor?.page ? (cursor.page - 1) * (criteria.limit ?? 20) : 0);
    const size = Math.min(criteria.limit ?? 20, 100);

    const searchUrl = new URL(`${this.baseUrl}/-/v1/search`);
    searchUrl.searchParams.set('text', criteria.query || 'agent');
    searchUrl.searchParams.set('size', String(size));
    searchUrl.searchParams.set('from', String(from));

    const res = await this.request<{ objects: any[]; total: number }>(searchUrl.toString(), {
      headers: { 'Accept': 'application/json', 'User-Agent': 'caim-source-adapter/1.0.0' },
    });

    const objects = res.data?.objects || [];
    const total = res.data?.total || 0;
    const hasMore = from + size < total;

    const candidates: DiscoveryCandidate[] = objects.map((item) => {
      const pkg = item.package || {};
      return {
        source_locator: `npm://${pkg.name}`,
        display_name: `${pkg.name} (${pkg.version || 'latest'})`,
        source_type: this.sourceType,
        type_hint: 'PACKAGE_DISTRIBUTION',
        confidence: 1.0,
        summary: pkg.description || undefined,
        raw_metadata: item,
        created_at: pkg.date,
        updated_at: pkg.date,
        discovered_at: new Date().toISOString(),
      };
    });

    return {
      candidates,
      next_cursor: hasMore ? { offset: from + size, page: Math.floor((from + size) / size) + 1 } : null,
      has_more: hasMore,
      rate_limit: this.get_rate_limit_state(),
      provenance: this.generate_provenance('DISCOVER', [this.hashPayload(objects)]),
    };
  }

  async fetch_metadata(locator: string): Promise<SourceMetadataResult> {
    const pkgName = this.parsePackageName(locator);
    const encoded = this.encodePackageName(pkgName);
    const url = `${this.baseUrl}/${encoded}`;

    const res = await this.request<Record<string, unknown>>(url, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'caim-source-adapter/1.0.0' },
      locator: `npm://${pkgName}`,
    });

    const rawData = res.data || {};
    const contentHash = this.hashPayload(rawData);

    return {
      source_locator: `npm://${pkgName}`,
      raw_metadata: rawData,
      content_hash: contentHash,
      observed_at: new Date().toISOString(),
      etag: res.headers['etag'],
      provenance: this.generate_provenance('FETCH_METADATA', [contentHash]),
    };
  }

  async resolve_immutable_identity(candidate: DiscoveryCandidate | string, versionOrTag: string = 'latest'): Promise<ImmutableResolutionResult> {
    const locator = this.extractLocator(candidate);
    const pkgName = this.parsePackageName(locator);
    return ImmutableVersionResolver.resolveNpm(pkgName, versionOrTag, this.fetcher);
  }

  async resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult> {
    const locator = this.extractLocator(candidate);
    const pkgName = this.parsePackageName(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    let latestVersionData: any = null;
    let exactVersion = 'latest';
    if (raw.package) {
      // From search result
      latestVersionData = raw.package;
      exactVersion = latestVersionData.version || 'latest';
    } else if (raw.versions && typeof raw.versions === 'object') {
      const latestTag = (raw['dist-tags'] as any)?.latest;
      exactVersion = latestTag || Object.keys(raw.versions)[0] || 'latest';
      latestVersionData = latestTag ? (raw.versions as any)[latestTag] : Object.values(raw.versions)[0];
    }

    const dist = latestVersionData?.dist || {};
    const tarballUrl = dist.tarball || `${this.baseUrl}/${pkgName}/-/${pkgName.split('/').pop()}-${exactVersion}.tgz`;

    // Parse SRI without calling SHA-1 or SHA-512 SHA-256
    const sriMeta = dist.integrity ? ProviderIntegrityVerifier.parseNpmSri(dist.integrity) : null;
    const sha1Meta = dist.shasum ? ProviderIntegrityVerifier.parseNpmShasum(dist.shasum) : null;

    // Only set checksum_sha256 if the algorithm is strictly sha256
    const sha256Checksum = sriMeta?.algorithm === 'sha256' ? sriMeta.expected_value : undefined;

    const artifacts: ArtifactLocatorEntry[] = [
      {
        artifact_type: 'NPM_TARBALL',
        locator: tarballUrl,
        filename: tarballUrl.split('/').pop() || `${pkgName}-${exactVersion}.tgz`,
        checksum_sha256: sha256Checksum,
        download_url: tarballUrl,
        is_primary: true,
        metadata: {
          exact_version: exactVersion,
          shasum_sha1: dist.shasum,
          integrity_sri: dist.integrity,
          integrity_algorithm: sriMeta?.algorithm || (sha1Meta ? 'sha1' : undefined),
          unpackedSize: dist.unpackedSize,
        },
      },
    ];

    return {
      source_locator: `npm://${pkgName}@${exactVersion}`,
      primary_locator: tarballUrl,
      artifacts,
      provenance: this.generate_provenance('RESOLVE_ARTIFACTS', [this.hashPayload(artifacts)]),
    };
  }

  async enumerate_relationships(candidate: DiscoveryCandidate | string): Promise<DiscoveryRelationshipsResult> {
    const locator = this.extractLocator(candidate);
    const pkgName = this.parsePackageName(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    let versionData: any = null;
    if (raw.package) {
      versionData = raw.package;
    } else if (raw.versions && typeof raw.versions === 'object') {
      const latestTag = (raw['dist-tags'] as any)?.latest;
      versionData = latestTag ? (raw.versions as any)[latestTag] : Object.values(raw.versions)[0];
    } else {
      versionData = raw;
    }

    const relationships: CandidateRelationship[] = [];

    // Runtime Dependencies
    const deps = versionData?.dependencies || {};
    for (const [dep, spec] of Object.entries(deps)) {
      relationships.push({
        from_locator: `npm://${pkgName}`,
        target_locator: `npm://${dep}`,
        relationship_type: 'DEPENDENCY',
        target_type_hint: 'PACKAGE_DISTRIBUTION',
        depth: 1,
        metadata: { specifier: spec },
      });
    }

    // Dev Dependencies
    const devDeps = versionData?.devDependencies || {};
    for (const [dep, spec] of Object.entries(devDeps)) {
      relationships.push({
        from_locator: `npm://${pkgName}`,
        target_locator: `npm://${dep}`,
        relationship_type: 'DEV_DEPENDENCY',
        target_type_hint: 'PACKAGE_DISTRIBUTION',
        depth: 1,
        metadata: { specifier: spec },
      });
    }

    // Upstream Repository (e.g. GitHub)
    const repo = versionData?.repository || raw.repository;
    const repoUrl = typeof repo === 'string' ? repo : repo?.url;
    if (repoUrl && typeof repoUrl === 'string') {
      if (repoUrl.includes('github.com')) {
        const match = repoUrl.match(/github\.com[/:]([^\/]+\/[^\/\#\?]+)/);
        if (match && match[1]) {
          relationships.push({
            from_locator: `npm://${pkgName}`,
            target_locator: `github://${match[1].replace(/\.git$/, '')}`,
            relationship_type: 'UPSTREAM_SOURCE',
            target_type_hint: 'AGENT_REPOSITORY',
            depth: 1,
          });
        }
      }
    }

    // Maintainers / Author
    const author = versionData?.author || raw.author;
    if (author) {
      const authorName = typeof author === 'string' ? author : author.name;
      if (authorName) {
        relationships.push({
          from_locator: `npm://${pkgName}`,
          target_locator: `npm://authors/${encodeURIComponent(authorName)}`,
          relationship_type: 'MAINTAINED_BY',
          depth: 1,
        });
      }
    }

    return {
      source_locator: `npm://${pkgName}`,
      relationships,
      provenance: this.generate_provenance('ENUMERATE_RELATIONSHIPS', [this.hashPayload(relationships)]),
    };
  }

  async get_change_token(candidate: DiscoveryCandidate | string): Promise<ChangeTokenResult> {
    const locator = this.extractLocator(candidate);
    const pkgName = this.parsePackageName(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    const latest = (raw['dist-tags'] as any)?.latest || (raw.package as any)?.version || '0.0.0';
    return {
      source_locator: `npm://${pkgName}`,
      change_token: latest,
      token_type: 'VERSION',
      last_modified: (raw.time as any)?.modified,
    };
  }

  get_source_policy(): SourcePolicy {
    return {
      source_type: this.sourceType,
      source_name: this.sourceName,
      auth_mode: 'ANONYMOUS',
      max_page_size: 100,
      rate_limit_per_minute: 1000,
      retry_policy: {
        max_retries: 3,
        backoff_factor: 2.0,
        initial_delay_ms: 500,
      },
      supported_query_families: ['search', 'package_name', 'scope', 'keywords'],
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
      await this.request(`${this.baseUrl}/-/ping`, {
        headers: { 'Accept': 'application/json' },
      });
      const latency = Date.now() - start;

      return {
        status: 'HEALTHY',
        auth_status: 'ANONYMOUS',
        message: 'npm public registry healthy and operational',
        latency_ms: latency,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        status: 'UNHEALTHY',
        auth_status: 'ANONYMOUS',
        message: `npm health check failed: ${err.message}`,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }
}
