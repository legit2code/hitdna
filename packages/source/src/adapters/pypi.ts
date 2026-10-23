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

export interface PyPIAdapterOptions {
  baseUrl?: string;
  fetcher?: HttpFetcher;
}

export class PyPISourceAdapter extends BaseSourceAdapter {
  readonly sourceType = 'pypi';
  readonly sourceName = 'PyPI';
  readonly adapterVersion = '1.0.0';

  private readonly baseUrl: string;

  constructor(options: PyPIAdapterOptions = {}) {
    super({
      fetcher: options.fetcher,
      initialRateLimit: {
        limit: 1000,
        remaining: 1000,
        window_seconds: 60,
        is_exhausted: false,
      },
    });
    this.baseUrl = options.baseUrl || 'https://pypi.org';
  }

  private parsePackageName(locator: string): string {
    let clean = locator.replace(/^pypi:\/\//, '').replace(/^https?:\/\/pypi\.org\/project\//, '');
    clean = clean.replace(/\/$/, '').split('/')[0];
    if (!clean) {
      throw new Error(`Invalid PyPI locator: '${locator}'`);
    }
    return clean.toLowerCase();
  }

  async discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult> {
    const pkgName = criteria.query ? this.parsePackageName(criteria.query) : 'pip';
    
    // PyPI warehouse JSON for individual package
    const meta = await this.fetch_metadata(`pypi://${pkgName}`);
    const raw = meta.raw_metadata;
    const info = (raw.info as any) || {};

    const candidate: DiscoveryCandidate = {
      source_locator: `pypi://${info.name || pkgName}`,
      display_name: `${info.name || pkgName} (${info.version || 'unknown'})`,
      source_type: this.sourceType,
      type_hint: 'PACKAGE_DISTRIBUTION',
      confidence: 1.0,
      summary: info.summary || undefined,
      raw_metadata: raw,
      created_at: undefined,
      updated_at: undefined,
      discovered_at: new Date().toISOString(),
    };

    return {
      candidates: [candidate],
      next_cursor: null,
      has_more: false,
      rate_limit: this.get_rate_limit_state(),
      provenance: this.generate_provenance('DISCOVER', [meta.content_hash]),
    };
  }

  async fetch_metadata(locator: string): Promise<SourceMetadataResult> {
    const pkgName = this.parsePackageName(locator);
    const url = `${this.baseUrl}/pypi/${encodeURIComponent(pkgName)}/json`;

    const res = await this.request<Record<string, unknown>>(url, {
      locator: `pypi://${pkgName}`,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'caim-source-adapter/1.0.0',
      },
    });

    const rawData = res.data || {};
    const contentHash = this.hashPayload(rawData);

    return {
      source_locator: `pypi://${pkgName}`,
      raw_metadata: rawData,
      content_hash: contentHash,
      observed_at: new Date().toISOString(),
      etag: res.headers['etag'],
      provenance: this.generate_provenance('FETCH_METADATA', [contentHash]),
    };
  }

  async resolve_immutable_identity(candidate: DiscoveryCandidate | string, requestedVersion?: string): Promise<ImmutableResolutionResult> {
    const locator = this.extractLocator(candidate);
    const pkgName = this.parsePackageName(locator);
    return ImmutableVersionResolver.resolvePyPi(pkgName, requestedVersion, this.fetcher);
  }

  async resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult> {
    const locator = this.extractLocator(candidate);
    const pkgName = this.parsePackageName(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};
    const info = (raw.info as any) || {};
    const exactVersion = info.version || (raw.version as string) || 'latest';
    const urls = Array.isArray(raw.urls) ? raw.urls : [];

    const artifacts: ArtifactLocatorEntry[] = urls.map((u: any, idx: number) => {
      const isWheel = u.packagetype === 'bdist_wheel' || (u.filename && u.filename.endsWith('.whl'));
      const isSdist = u.packagetype === 'sdist' || (u.filename && (u.filename.endsWith('.tar.gz') || u.filename.endsWith('.zip')));
      
      const sha256Clean = u.digests?.sha256 ? u.digests.sha256.toLowerCase() : undefined;

      return {
        artifact_type: isWheel ? 'WHEEL' : isSdist ? 'SDIST' : 'PACKAGE_DISTRIBUTION',
        locator: u.url || `${this.baseUrl}/packages/${u.filename}`,
        filename: u.filename,
        size_bytes: u.size,
        checksum_sha256: sha256Clean,
        download_url: u.url,
        is_primary: idx === 0 || isWheel,
        metadata: {
          exact_version: exactVersion,
          distribution_filename: u.filename,
          python_version: u.python_version,
          sha256: sha256Clean,
          upload_time: u.upload_time_iso_8601 || u.upload_time,
          yanked: u.yanked,
        },
      };
    });

    if (artifacts.length === 0) {
      artifacts.push({
        artifact_type: 'PACKAGE_DISTRIBUTION',
        locator: `${this.baseUrl}/project/${pkgName}/`,
        is_primary: true,
      });
    }

    const primaryArtifact = artifacts.find(a => a.is_primary) || artifacts[0];
    const primaryLocator = primaryArtifact.locator;
    const primaryFilename = primaryArtifact.filename;

    const immutableLocator = primaryFilename
      ? `pypi://${pkgName}@${exactVersion}#${primaryFilename}`
      : `pypi://${pkgName}@${exactVersion}`;

    return {
      source_locator: immutableLocator,
      primary_locator: primaryLocator,
      artifacts,
      provenance: this.generate_provenance('RESOLVE_ARTIFACTS', [this.hashPayload(artifacts)]),
    };
  }

  async enumerate_relationships(candidate: DiscoveryCandidate | string): Promise<DiscoveryRelationshipsResult> {
    const locator = this.extractLocator(candidate);
    const pkgName = this.parsePackageName(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};
    const info = (raw.info as any) || {};

    const relationships: CandidateRelationship[] = [];

    // Dependencies from requires_dist
    const requiresDist = Array.isArray(info.requires_dist) ? info.requires_dist : [];
    for (const req of requiresDist) {
      // Parse dependency name before specifier/semver, e.g. "requests (>=2.28.0) ; extra == 'all'"
      const match = req.match(/^([a-zA-Z0-9_\-\.]+)/);
      if (match && match[1]) {
        const depName = match[1].toLowerCase();
        relationships.push({
          from_locator: `pypi://${pkgName}`,
          target_locator: `pypi://${depName}`,
          relationship_type: 'DEPENDENCY',
          target_type_hint: 'PACKAGE_DISTRIBUTION',
          depth: 1,
          metadata: { specifier: req },
        });
      }
    }

    // Upstream Source or Repository
    const projectUrls = info.project_urls || {};
    const repoUrl = projectUrls.Source || projectUrls.Repository || projectUrls['Source Code'] || projectUrls.Code || info.home_page;
    if (repoUrl && typeof repoUrl === 'string') {
      if (repoUrl.includes('github.com')) {
        const match = repoUrl.match(/github\.com\/([^\/]+\/[^\/\#\?]+)/);
        if (match && match[1]) {
          relationships.push({
            from_locator: `pypi://${pkgName}`,
            target_locator: `github://${match[1].replace(/\.git$/, '')}`,
            relationship_type: 'UPSTREAM_SOURCE',
            target_type_hint: 'AGENT_REPOSITORY',
            depth: 1,
          });
        }
      } else if (repoUrl.startsWith('http')) {
        relationships.push({
          from_locator: `pypi://${pkgName}`,
          target_locator: repoUrl,
          relationship_type: 'HOMEPAGE',
          depth: 1,
        });
      }
    }

    // Author / Maintainer
    if (info.author || info.maintainer) {
      relationships.push({
        from_locator: `pypi://${pkgName}`,
        target_locator: `pypi://authors/${encodeURIComponent(info.author || info.maintainer)}`,
        relationship_type: 'MAINTAINED_BY',
        depth: 1,
        metadata: { author_email: info.author_email },
      });
    }

    return {
      source_locator: `pypi://${pkgName}`,
      relationships,
      provenance: this.generate_provenance('ENUMERATE_RELATIONSHIPS', [this.hashPayload(relationships)]),
    };
  }

  async get_change_token(candidate: DiscoveryCandidate | string): Promise<ChangeTokenResult> {
    const locator = this.extractLocator(candidate);
    const pkgName = this.parsePackageName(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};
    const info = (raw.info as any) || {};

    const version = info.version || '0.0.0';
    return {
      source_locator: `pypi://${pkgName}`,
      change_token: version,
      token_type: 'VERSION',
      last_modified: undefined,
    };
  }

  get_source_policy(): SourcePolicy {
    return {
      source_type: this.sourceType,
      source_name: this.sourceName,
      auth_mode: 'ANONYMOUS',
      max_page_size: 50,
      rate_limit_per_minute: 1000,
      retry_policy: {
        max_retries: 3,
        backoff_factor: 2.0,
        initial_delay_ms: 500,
      },
      supported_query_families: ['package_name', 'classifier', 'simple'],
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
      // Check PyPI warehouse availability with standard package
      await this.fetch_metadata('pypi://pip');
      const latency = Date.now() - start;

      return {
        status: 'HEALTHY',
        auth_status: 'ANONYMOUS',
        message: 'PyPI public JSON registry reachable and responsive',
        latency_ms: latency,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        status: 'UNHEALTHY',
        auth_status: 'ANONYMOUS',
        message: `PyPI health check failed: ${err.message}`,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }
}
