import crypto from 'node:crypto';
import {
  HttpFetcher,
  DiscoveryCandidate,
  ArtifactLocatorEntry,
  HashAlgorithm,
  ProviderIntegrityMetadata,
  ImmutableResolutionResult,
  IntegrityCheckResult,
} from './types.ts';

// ---------------------------------------------------------------------------
// 2. Provider Integrity Verifier (Enforces Correct SRI & Cryptographic Types)
// ---------------------------------------------------------------------------

export class ProviderIntegrityVerifier {
  /**
   * Parses npm Subresource Integrity (SRI) string: e.g. "sha512-42b...==" or "sha1-42b...=="
   * Strictly distinguishes algorithms: SHA-512 is never called SHA-256; SHA-1 is never called SHA-256.
   */
  public static parseNpmSri(sriString: string): ProviderIntegrityMetadata | null {
    if (!sriString || typeof sriString !== 'string') return null;

    const trimmed = sriString.trim();
    if (trimmed.startsWith('sha512-')) {
      return {
        algorithm: 'sha512',
        expected_value: trimmed.slice(7),
        sri_string: trimmed,
        encoding: 'base64',
      };
    }

    if (trimmed.startsWith('sha384-')) {
      return {
        algorithm: 'sha512', // standard high-bit fallback
        expected_value: trimmed.slice(7),
        sri_string: trimmed,
        encoding: 'base64',
      };
    }

    if (trimmed.startsWith('sha256-')) {
      return {
        algorithm: 'sha256',
        expected_value: trimmed.slice(7),
        sri_string: trimmed,
        encoding: 'base64',
      };
    }

    if (trimmed.startsWith('sha1-')) {
      return {
        algorithm: 'sha1',
        expected_value: trimmed.slice(5),
        sri_string: trimmed,
        encoding: 'base64',
      };
    }

    return null;
  }

  /**
   * Parses npm legacy shasum (40 hex characters SHA-1).
   * Strictly preserves algorithm as 'sha1' and does NOT label it 'sha256'.
   */
  public static parseNpmShasum(shasumHex: string): ProviderIntegrityMetadata | null {
    if (!shasumHex || typeof shasumHex !== 'string') return null;
    const clean = shasumHex.trim().toLowerCase();
    if (/^[0-9a-f]{40}$/.test(clean)) {
      return {
        algorithm: 'sha1',
        expected_value: clean,
        encoding: 'hex',
      };
    }
    return null;
  }

  /**
   * Parses PyPI provider SHA-256 (64 hex characters).
   */
  public static parsePyPiSha256(sha256Hex: string): ProviderIntegrityMetadata | null {
    if (!sha256Hex || typeof sha256Hex !== 'string') return null;
    const clean = sha256Hex.trim().toLowerCase();
    if (/^[0-9a-f]{64}$/.test(clean)) {
      return {
        algorithm: 'sha256',
        expected_value: clean,
        encoding: 'hex',
      };
    }
    return null;
  }

  /**
   * Verifies byte payload against provider-supplied integrity metadata.
   * Throws Error with code 'INTEGRITY_MISMATCH' if checksums do not match.
   */
  public static verifyBytes(
    payload: Buffer | Uint8Array | string,
    integrity: ProviderIntegrityMetadata
  ): IntegrityCheckResult {
    const buffer = Buffer.isBuffer(payload)
      ? payload
      : typeof payload === 'string'
      ? Buffer.from(payload, 'utf8')
      : Buffer.from(payload);

    let actualDigest: string;
    if (integrity.algorithm === 'sha512') {
      const hash = crypto.createHash('sha512').update(buffer);
      actualDigest = integrity.encoding === 'base64' ? hash.digest('base64') : hash.digest('hex');
    } else if (integrity.algorithm === 'sha1') {
      const hash = crypto.createHash('sha1').update(buffer);
      actualDigest = integrity.encoding === 'base64' ? hash.digest('base64') : hash.digest('hex').toLowerCase();
    } else {
      // sha256
      const hash = crypto.createHash('sha256').update(buffer);
      actualDigest = integrity.encoding === 'base64' ? hash.digest('base64') : hash.digest('hex').toLowerCase();
    }

    const expectedNormalized = integrity.encoding === 'hex'
      ? integrity.expected_value.toLowerCase()
      : integrity.expected_value;

    const matched = actualDigest === expectedNormalized;

    if (!matched) {
      const err = new Error(
        `INTEGRITY_MISMATCH: Computed ${integrity.algorithm.toUpperCase()} (${actualDigest}) does not match provider-supplied integrity (${expectedNormalized})`
      );
      (err as any).code = 'INTEGRITY_MISMATCH';
      (err as any).expected = expectedNormalized;
      (err as any).actual = actualDigest;
      (err as any).algorithm = integrity.algorithm;
      throw err;
    }

    return {
      verified: true,
      algorithm: integrity.algorithm,
      expected: expectedNormalized,
      actual: actualDigest,
      matched: true,
    };
  }
}

// ---------------------------------------------------------------------------
// 3. Immutable Version Resolver (Resolves Mutable Discovery Locators)
// ---------------------------------------------------------------------------

export class ImmutableVersionResolver {
  /**
   * Validates if a commit string is a strict 40-character hexadecimal Git commit SHA.
   */
  public static isCommitSha(val: string): boolean {
    return typeof val === 'string' && /^[0-9a-f]{40}$/i.test(val.trim());
  }

  /**
   * Validates if a digest is an OCI / Docker manifest digest (sha256:64hex).
   */
  public static isManifestDigest(val: string): boolean {
    return typeof val === 'string' && /^sha256:[0-9a-f]{64}$/i.test(val.trim());
  }

  /**
   * Validates if a tag or ref is mutable (e.g. 'main', 'master', 'HEAD', 'latest', 'v1.x').
   */
  public static isMutableReference(ref: string): boolean {
    if (!ref || typeof ref !== 'string') return true;
    const lower = ref.trim().toLowerCase();
    return (
      lower === 'main' ||
      lower === 'master' ||
      lower === 'head' ||
      lower === 'latest' ||
      lower === 'trunk' ||
      lower === 'develop' ||
      lower === 'dev' ||
      lower.startsWith('refs/heads/')
    );
  }

  /**
   * GITHUB:
   * 1. Resolves default branch HEAD or ref to an exact 40-character commit SHA.
   * 2. Never treats 'main', 'master', 'HEAD', or a branch name as the immutable final identity.
   * 3. Constructs exact commit archive URL: https://github.com/{owner}/{repo}/archive/{commitSha}.tar.gz
   */
  public static async resolveGitHub(
    locator: string,
    refOrBranch?: string,
    fetcher?: HttpFetcher
  ): Promise<ImmutableResolutionResult> {
    let clean = locator.replace(/^github:\/\//, '').replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '');
    const parts = clean.split('/');
    if (parts.length < 2) {
      throw new Error(`Invalid GitHub repository locator: '${locator}'`);
    }
    const [owner, repo] = [parts[0], parts[1]];

    // If an exact 40-char SHA is already supplied as ref, we still verify format
    if (refOrBranch && this.isCommitSha(refOrBranch)) {
      const commitSha = refOrBranch.trim().toLowerCase();
      return {
        source_type: 'github',
        mutable_locator: `github://${owner}/${repo}`,
        immutable_locator: `github://${owner}/${repo}#${commitSha}`,
        resolved_version: commitSha,
        commit_sha: commitSha,
        distribution_filename: `${repo}-${commitSha}.tar.gz`,
        is_immutable: true,
        metadata: { owner, repo, commitSha, target: `archive/${commitSha}.tar.gz` },
        is_container_artifact: false,
        is_source_code: true,
        acquisition_supported: true,
        resolved_at: new Date().toISOString(),
      };
    }

    if (!fetcher) {
      throw new Error('HttpFetcher is required to query GitHub API for default branch commit SHA resolution');
    }

    // Query repository metadata first to discover default_branch if not provided
    const repoRes = await fetcher(`https://api.github.com/repos/${owner}/${repo}`);
    if (repoRes.status !== 200 || !repoRes.data) {
      throw new Error(`GitHub API repository lookup failed with HTTP ${repoRes.status} for ${owner}/${repo}`);
    }
    const repoData = repoRes.data;
    const defaultBranch = refOrBranch || repoData.default_branch || 'main';

    // Query exact commit for this branch/ref
    const commitRes = await fetcher(`https://api.github.com/repos/${owner}/${repo}/commits/${defaultBranch}`);
    if (commitRes.status !== 200 || !commitRes.data) {
      throw new Error(`GitHub commit lookup failed with HTTP ${commitRes.status} for ${owner}/${repo}@${defaultBranch}`);
    }

    const commitSha = commitRes.data.sha;
    if (!this.isCommitSha(commitSha)) {
      throw new Error(
        `[PROVIDER_INTEGRITY_ERROR] GitHub API returned invalid non-40-character commit SHA: '${commitSha}' for ${owner}/${repo}`
      );
    }

    return {
      source_type: 'github',
      mutable_locator: `github://${owner}/${repo}@${defaultBranch}`,
      immutable_locator: `github://${owner}/${repo}#${commitSha}`,
      resolved_version: commitSha,
      commit_sha: commitSha,
      distribution_filename: `${repo}-${commitSha}.tar.gz`,
      is_immutable: true,
      metadata: {
        repository_id: repoData.id,
        owner,
        repo,
        default_branch: repoData.default_branch,
        commit_sha: commitSha,
        commit_author: commitRes.data.commit?.author?.name,
        commit_date: commitRes.data.commit?.author?.date,
        archive_url: `https://github.com/${owner}/${repo}/archive/${commitSha}.tar.gz`,
      },
      is_container_artifact: false,
      is_source_code: true,
      acquisition_supported: true,
      resolved_at: new Date().toISOString(),
    };
  }

  /**
   * GITLAB:
   * Resolves project repository and branch to exact 40-character commit SHA.
   */
  public static async resolveGitLab(
    locator: string,
    refOrBranch?: string,
    fetcher?: HttpFetcher
  ): Promise<ImmutableResolutionResult> {
    let clean = locator.replace(/^gitlab:\/\//, '').replace(/^https?:\/\/gitlab\.com\//, '').replace(/\.git$/, '');
    const encodedPath = encodeURIComponent(clean);

    if (refOrBranch && this.isCommitSha(refOrBranch)) {
      const commitSha = refOrBranch.trim().toLowerCase();
      return {
        source_type: 'gitlab',
        mutable_locator: `gitlab://${clean}`,
        immutable_locator: `gitlab://${clean}#${commitSha}`,
        resolved_version: commitSha,
        commit_sha: commitSha,
        distribution_filename: `archive-${commitSha}.tar.gz`,
        is_immutable: true,
        metadata: { pathWithNamespace: clean, commitSha },
        is_container_artifact: false,
        is_source_code: true,
        acquisition_supported: true,
        resolved_at: new Date().toISOString(),
      };
    }

    if (!fetcher) {
      throw new Error('HttpFetcher is required to query GitLab API for commit SHA resolution');
    }

    const projRes = await fetcher(`https://gitlab.com/api/v4/projects/${encodedPath}`);
    if (projRes.status !== 200 || !projRes.data) {
      throw new Error(`GitLab project lookup failed with HTTP ${projRes.status} for ${clean}`);
    }
    const defaultBranch = refOrBranch || projRes.data.default_branch || 'main';

    const commitRes = await fetcher(`https://gitlab.com/api/v4/projects/${encodedPath}/repository/commits/${defaultBranch}`);
    if (commitRes.status !== 200 || !commitRes.data) {
      throw new Error(`GitLab commit lookup failed with HTTP ${commitRes.status} for ${clean}@${defaultBranch}`);
    }

    const commitSha = commitRes.data.id || commitRes.data.sha;
    if (!this.isCommitSha(commitSha)) {
      throw new Error(`GitLab API returned invalid commit SHA '${commitSha}' for ${clean}`);
    }

    return {
      source_type: 'gitlab',
      mutable_locator: `gitlab://${clean}@${defaultBranch}`,
      immutable_locator: `gitlab://${clean}#${commitSha}`,
      resolved_version: commitSha,
      commit_sha: commitSha,
      distribution_filename: `archive-${commitSha}.tar.gz`,
      is_immutable: true,
      metadata: {
        project_id: projRes.data.id,
        path_with_namespace: clean,
        default_branch: projRes.data.default_branch,
        commit_sha: commitSha,
        archive_url: `https://gitlab.com/api/v4/projects/${encodedPath}/repository/archive.tar.gz?sha=${commitSha}`,
      },
      is_container_artifact: false,
      is_source_code: true,
      acquisition_supported: true,
      resolved_at: new Date().toISOString(),
    };
  }

  /**
   * CODEBERG:
   * Resolves repository to exact 40-character commit SHA.
   */
  public static async resolveCodeberg(
    locator: string,
    refOrBranch?: string,
    fetcher?: HttpFetcher
  ): Promise<ImmutableResolutionResult> {
    let clean = locator.replace(/^codeberg:\/\//, '').replace(/^https?:\/\/codeberg\.org\//, '').replace(/\.git$/, '');
    const [owner, repo] = clean.split('/');

    if (refOrBranch && this.isCommitSha(refOrBranch)) {
      const commitSha = refOrBranch.trim().toLowerCase();
      return {
        source_type: 'codeberg',
        mutable_locator: `codeberg://${owner}/${repo}`,
        immutable_locator: `codeberg://${owner}/${repo}#${commitSha}`,
        resolved_version: commitSha,
        commit_sha: commitSha,
        distribution_filename: `${repo}-${commitSha}.tar.gz`,
        is_immutable: true,
        metadata: { owner, repo, commitSha },
        is_container_artifact: false,
        is_source_code: true,
        acquisition_supported: true,
        resolved_at: new Date().toISOString(),
      };
    }

    if (!fetcher) {
      throw new Error('HttpFetcher is required to query Codeberg API for commit SHA resolution');
    }

    const repoRes = await fetcher(`https://codeberg.org/api/v1/repos/${owner}/${repo}`);
    if (repoRes.status !== 200 || !repoRes.data) {
      throw new Error(`Codeberg repository lookup failed with HTTP ${repoRes.status} for ${owner}/${repo}`);
    }
    const defaultBranch = refOrBranch || repoRes.data.default_branch || 'main';

    const commitRes = await fetcher(`https://codeberg.org/api/v1/repos/${owner}/${repo}/commits/${defaultBranch}`);
    if (commitRes.status !== 200 || !commitRes.data) {
      throw new Error(`Codeberg commit lookup failed with HTTP ${commitRes.status} for ${owner}/${repo}@${defaultBranch}`);
    }

    const commitSha = commitRes.data.sha;
    if (!this.isCommitSha(commitSha)) {
      throw new Error(`Codeberg API returned invalid commit SHA '${commitSha}' for ${owner}/${repo}`);
    }

    return {
      source_type: 'codeberg',
      mutable_locator: `codeberg://${owner}/${repo}@${defaultBranch}`,
      immutable_locator: `codeberg://${owner}/${repo}#${commitSha}`,
      resolved_version: commitSha,
      commit_sha: commitSha,
      distribution_filename: `${repo}-${commitSha}.tar.gz`,
      is_immutable: true,
      metadata: {
        repo_id: repoRes.data.id,
        owner,
        repo,
        default_branch: defaultBranch,
        commit_sha: commitSha,
        archive_url: `https://codeberg.org/${owner}/${repo}/archive/${commitSha}.tar.gz`,
      },
      is_container_artifact: false,
      is_source_code: true,
      acquisition_supported: true,
      resolved_at: new Date().toISOString(),
    };
  }

  /**
   * NPM:
   * 1. Resolves exact semver from tag/range.
   * 2. Parses SRI correctly (e.g. sha512- base64).
   * 3. Supports SHA-1 shasum where provided.
   * 4. Does NOT call SHA-1 or SHA-512 values SHA-256.
   * 5. Encapsulates provider integrity metadata.
   */
  public static async resolveNpm(
    pkgName: string,
    versionOrTag: string = 'latest',
    fetcher?: HttpFetcher
  ): Promise<ImmutableResolutionResult> {
    const cleanPkg = pkgName.replace(/^npm:\/\//, '');

    if (!fetcher) {
      throw new Error('HttpFetcher is required to query npm registry packument');
    }

    const res = await fetcher(`https://registry.npmjs.org/${encodeURIComponent(cleanPkg)}`);
    if (res.status !== 200 || !res.data) {
      throw new Error(`npm registry lookup failed with HTTP ${res.status} for ${cleanPkg}`);
    }

    const packument = res.data;
    const distTags = packument['dist-tags'] || {};
    const exactVersion = distTags[versionOrTag] || versionOrTag;

    const versionData = packument.versions?.[exactVersion];
    if (!versionData) {
      throw new Error(`npm version '${exactVersion}' not found in registry for package '${cleanPkg}'`);
    }

    const dist = versionData.dist || {};
    const tarball = dist.tarball;
    const filename = tarball ? tarball.split('/').pop() : `${cleanPkg}-${exactVersion}.tgz`;

    // Parse integrity: prioritize SRI (sha512), fallback to shasum (sha1)
    let integrityMeta: ProviderIntegrityMetadata | undefined;
    if (dist.integrity) {
      const parsedSri = ProviderIntegrityVerifier.parseNpmSri(dist.integrity);
      if (parsedSri) {
        integrityMeta = parsedSri;
      }
    }
    if (!integrityMeta && dist.shasum) {
      const parsedShasum = ProviderIntegrityVerifier.parseNpmShasum(dist.shasum);
      if (parsedShasum) {
        integrityMeta = parsedShasum;
      }
    }

    return {
      source_type: 'npm',
      mutable_locator: `npm://${cleanPkg}@${versionOrTag}`,
      immutable_locator: `npm://${cleanPkg}@${exactVersion}`,
      resolved_version: exactVersion,
      distribution_filename: filename,
      integrity_metadata: integrityMeta,
      is_immutable: true,
      metadata: {
        package: cleanPkg,
        version: exactVersion,
        tarball_url: tarball,
        unpacked_size: dist.unpackedSize,
        file_count: dist.fileCount,
        has_sri: Boolean(dist.integrity),
        has_shasum: Boolean(dist.shasum),
      },
      is_container_artifact: false,
      is_source_code: true,
      acquisition_supported: true,
      resolved_at: new Date().toISOString(),
    };
  }

  /**
   * PYPI:
   * 1. Resolves exact version and distribution filename.
   * 2. Validates provider-supplied SHA-256.
   * 3. Persists exact distribution identity.
   */
  public static async resolvePyPi(
    pkgName: string,
    requestedVersion?: string,
    fetcher?: HttpFetcher
  ): Promise<ImmutableResolutionResult> {
    const cleanPkg = pkgName.replace(/^pypi:\/\//, '');

    if (!fetcher) {
      throw new Error('HttpFetcher is required to query PyPI JSON API');
    }

    const url = requestedVersion
      ? `https://pypi.org/pypi/${cleanPkg}/${requestedVersion}/json`
      : `https://pypi.org/pypi/${cleanPkg}/json`;

    const res = await fetcher(url);
    if (res.status !== 200 || !res.data) {
      throw new Error(`PyPI lookup failed with HTTP ${res.status} for ${cleanPkg}`);
    }

    const info = res.data.info || {};
    const exactVersion = info.version;
    const urls: any[] = res.data.urls || [];

    // Select primary distribution: wheel first, then sdist
    const selectedDist = urls.find((u: any) => u.packagetype === 'bdist_wheel') || urls[0];
    if (!selectedDist) {
      throw new Error(`No distributions available on PyPI for ${cleanPkg}@${exactVersion}`);
    }

    const filename = selectedDist.filename;
    const sha256Hex = selectedDist.digests?.sha256;
    const integrityMeta = ProviderIntegrityVerifier.parsePyPiSha256(sha256Hex);

    return {
      source_type: 'pypi',
      mutable_locator: `pypi://${cleanPkg}`,
      immutable_locator: `pypi://${cleanPkg}@${exactVersion}#${filename}`,
      resolved_version: exactVersion,
      distribution_filename: filename,
      integrity_metadata: integrityMeta || undefined,
      is_immutable: true,
      metadata: {
        package: cleanPkg,
        version: exactVersion,
        filename,
        download_url: selectedDist.url,
        packagetype: selectedDist.packagetype,
        python_version: selectedDist.python_version,
        sha256: sha256Hex,
      },
      is_container_artifact: false,
      is_source_code: true,
      acquisition_supported: true,
      resolved_at: new Date().toISOString(),
    };
  }

  /**
   * HUGGING FACE / SPACES:
   * Resolves immutable revision commit SHA and repository snapshot files.
   */
  public static async resolveHuggingFace(
    modelOrSpaceId: string,
    refOrRevision: string = 'main',
    isSpace: boolean = false,
    fetcher?: HttpFetcher
  ): Promise<ImmutableResolutionResult> {
    const cleanId = modelOrSpaceId.replace(/^hf:\/\/(models|spaces)\//, '');

    if (!fetcher) {
      throw new Error('HttpFetcher is required to query Hugging Face API');
    }

    const endpoint = isSpace
      ? `https://huggingface.co/api/spaces/${cleanId}`
      : `https://huggingface.co/api/models/${cleanId}`;

    const res = await fetcher(endpoint);
    if (res.status !== 200 || !res.data) {
      throw new Error(`Hugging Face lookup failed with HTTP ${res.status} for ${cleanId}`);
    }

    const commitSha = res.data.sha;
    if (!this.isCommitSha(commitSha)) {
      throw new Error(`Hugging Face API returned invalid revision SHA: '${commitSha}' for ${cleanId}`);
    }

    const prefix = isSpace ? 'hf://spaces' : 'hf://models';

    return {
      source_type: isSpace ? 'hf-spaces' : 'huggingface',
      mutable_locator: `${prefix}/${cleanId}@${refOrRevision}`,
      immutable_locator: `${prefix}/${cleanId}#${commitSha}`,
      resolved_version: commitSha,
      commit_sha: commitSha,
      distribution_filename: `${cleanId.replace(/\//g, '_')}-${commitSha}.tar.gz`,
      is_immutable: true,
      metadata: {
        modelId: cleanId,
        commitSha,
        is_space: isSpace,
        snapshot_clone_url: `https://huggingface.co/${cleanId}.git`,
        raw_metadata: res.data,
      },
      is_container_artifact: false,
      is_source_code: true,
      acquisition_supported: true,
      resolved_at: new Date().toISOString(),
    };
  }

  /**
   * DOCKER HUB / OCI:
   * 1. Resolves mutable image tag (e.g. ':latest') to immutable manifest digest (sha256:64hex).
   * 2. Treats image digest as identity.
   * 3. Strictly marks is_container_artifact: true, is_source_code: false.
   */
  public static async resolveDockerHub(
    imageLocator: string,
    tag: string = 'latest',
    fetcher?: HttpFetcher
  ): Promise<ImmutableResolutionResult> {
    let clean = imageLocator.replace(/^docker:\/\//, '').replace(/^docker\.io\//, '');
    let imageTag = tag;
    if (clean.includes(':')) {
      const [img, t] = clean.split(':');
      clean = img;
      imageTag = t;
    }
    const [namespace, repository] = clean.includes('/') ? clean.split('/') : ['library', clean];

    if (!fetcher) {
      throw new Error('HttpFetcher is required to query Docker Hub tag digest API');
    }

    const res = await fetcher(`https://hub.docker.com/v2/repositories/${namespace}/${repository}/tags/${imageTag}`);
    if (res.status !== 200 || !res.data) {
      throw new Error(`Docker Hub lookup failed with HTTP ${res.status} for ${namespace}/${repository}:${imageTag}`);
    }

    // Extract manifest digest from tag response or images
    let digest: string | undefined = res.data.digest;
    if (!digest && Array.isArray(res.data.images) && res.data.images.length > 0) {
      digest = res.data.images[0].digest;
    }

    if (!digest || !this.isManifestDigest(digest)) {
      throw new Error(
        `[PROVIDER_INTEGRITY_ERROR] Docker Hub tag '${imageTag}' did not yield a valid OCI sha256 manifest digest for ${namespace}/${repository}`
      );
    }

    const immutableLocator = `docker.io/${namespace}/${repository}@${digest}`;

    return {
      source_type: 'dockerhub',
      mutable_locator: `docker.io/${namespace}/${repository}:${imageTag}`,
      immutable_locator: immutableLocator,
      resolved_version: digest,
      manifest_digest: digest,
      is_immutable: true,
      metadata: {
        namespace,
        repository,
        tag: imageTag,
        digest,
        architecture: res.data.images?.[0]?.architecture,
        os: res.data.images?.[0]?.os,
      },
      is_container_artifact: true,
      is_source_code: false,
      acquisition_supported: true,
      resolved_at: new Date().toISOString(),
    };
  }

  /**
   * REPLICATE:
   * Model version / weights / source resolution.
   * If source code is not exposed by provider, returns SOURCE_ACQUISITION_UNSUPPORTED rather than fabricating source.
   */
  public static async resolveReplicate(
    locator: string,
    fetcher?: HttpFetcher
  ): Promise<ImmutableResolutionResult> {
    const clean = locator.replace(/^replicate:\/\//, '');
    const [owner, name] = clean.split('/');

    if (!fetcher) {
      throw new Error('HttpFetcher is required to query Replicate API');
    }

    const res = await fetcher(`https://api.replicate.com/v1/models/${owner}/${name}`);
    if (res.status !== 200 || !res.data) {
      throw new Error(`Replicate model lookup failed with HTTP ${res.status} for ${owner}/${name}`);
    }

    const model = res.data;
    const latestVersion = model.latest_version?.id;

    // Check if open source repository exists in model metadata
    const githubUrl = model.github_url;
    const hasVerifiableSource = Boolean(githubUrl && githubUrl.includes('github.com'));

    const canonicalPivots = githubUrl ? [{ provider: 'github', locator: githubUrl }] : [];

    return {
      source_type: 'replicate',
      mutable_locator: `replicate://${owner}/${name}`,
      immutable_locator: latestVersion ? `replicate://${owner}/${name}:${latestVersion}` : `replicate://${owner}/${name}`,
      resolved_version: latestVersion || 'LATEST_UNVERSIONED',
      is_immutable: Boolean(latestVersion),
      metadata: {
        owner,
        name,
        latest_version_id: latestVersion,
        github_url: githubUrl,
      },
      is_container_artifact: false,
      is_source_code: false,
      acquisition_supported: hasVerifiableSource,
      unsupported_reason: hasVerifiableSource
        ? undefined
        : 'SOURCE_ACQUISITION_UNSUPPORTED: Replicate hosts closed-weight API inference endpoints and does not distribute raw source code bytes. Pivot to linked repository if available.',
      pivot_required: hasVerifiableSource,
      canonical_pivots: canonicalPivots,
      resolved_at: new Date().toISOString(),
    };
  }

  /**
   * KAGGLE:
   * Notebook / dataset resolution. Returns SOURCE_ACQUISITION_UNSUPPORTED if source bytes are not downloadable.
   */
  public static async resolveKaggle(
    locator: string,
    fetcher?: HttpFetcher
  ): Promise<ImmutableResolutionResult> {
    const clean = locator.replace(/^kaggle:\/\//, '');
    const [author, slug] = clean.split('/');

    if (!fetcher) {
      throw new Error('HttpFetcher is required to query Kaggle kernel API');
    }

    const res = await fetcher(`https://www.kaggle.com/api/v1/kernels/list?search=${encodeURIComponent(slug)}`);
    const kernels: any[] = Array.isArray(res.data) ? res.data : [];
    const matched = kernels.find((k: any) => k.ref === clean || (k.author === author && k.slug === slug)) || kernels[0];

    const versionNum = matched?.lastUpdateTime || 'v1';

    return {
      source_type: 'kaggle',
      mutable_locator: `kaggle://${clean}`,
      immutable_locator: `kaggle://${clean}#${versionNum}`,
      resolved_version: String(versionNum),
      is_immutable: false,
      metadata: { author, slug, raw: matched },
      is_container_artifact: false,
      is_source_code: false,
      acquisition_supported: false,
      unsupported_reason: 'SOURCE_ACQUISITION_UNSUPPORTED: Kaggle kernels API does not provide signed downloadable source code archives in anonymous mode. Never fabricate notebook content.',
      resolved_at: new Date().toISOString(),
    };
  }

  /**
   * DISCOVERY-ONLY PROVIDERS (MCP, Hacker News, arXiv):
   * Pivots to canonical source / package references.
   * Does NOT establish source authenticity directly because they do not host verifiable source bytes.
   */
  public static resolveDiscoveryOnlyPivot(
    provider: 'mcp' | 'hackernews' | 'arxiv',
    locator: string,
    rawMetadata: Record<string, unknown> = {}
  ): ImmutableResolutionResult {
    const canonicalPivots: Array<{ provider: string; locator: string }> = [];

    if (provider === 'mcp') {
      const server = (rawMetadata as any)?.server;
      if (server?.repository?.url) {
        canonicalPivots.push({ provider: 'github', locator: server.repository.url });
      }
      if (Array.isArray(server?.packages)) {
        for (const pkg of server.packages) {
          if (pkg.registryType === 'npm') {
            canonicalPivots.push({ provider: 'npm', locator: `npm://${pkg.identifier}` });
          } else if (pkg.registryType === 'pypi') {
            canonicalPivots.push({ provider: 'pypi', locator: `pypi://${pkg.identifier}` });
          }
        }
      }
    } else if (provider === 'hackernews') {
      const url = (rawMetadata as any)?.url;
      if (url && typeof url === 'string') {
        if (url.includes('github.com')) canonicalPivots.push({ provider: 'github', locator: url });
        if (url.includes('huggingface.co')) canonicalPivots.push({ provider: 'huggingface', locator: url });
      }
    } else if (provider === 'arxiv') {
      const links = (rawMetadata as any)?.code_links;
      if (Array.isArray(links)) {
        for (const link of links) {
          if (typeof link === 'string' && link.includes('github.com')) {
            canonicalPivots.push({ provider: 'github', locator: link });
          }
        }
      }
    }

    return {
      source_type: provider,
      mutable_locator: locator,
      immutable_locator: locator,
      resolved_version: 'DISCOVERY_ONLY_INDEX',
      is_immutable: false,
      metadata: rawMetadata,
      is_container_artifact: false,
      is_source_code: false,
      acquisition_supported: false,
      unsupported_reason: `SOURCE_ACQUISITION_UNSUPPORTED: '${provider}' is a discovery-only index that does not host verifiable source bytes. Must pivot to canonical source/package repository.`,
      pivot_required: canonicalPivots.length > 0,
      canonical_pivots: canonicalPivots,
      resolved_at: new Date().toISOString(),
    };
  }
}
