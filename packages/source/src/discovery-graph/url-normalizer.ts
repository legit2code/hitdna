/**
 * Architecture V2.0.1 — Discovery URL & Locator Normalizer
 * Enforces strict, canonical normalization across all supported ecosystems.
 */

export interface NormalizedUrlResult {
  raw_url: string;
  normalized_url: string;
  canonical_url: string;
  domain: string;
  candidate_type: string;
  source_adapter: string;
}

export class UrlNormalizer {
  public static normalize(rawInput: string): NormalizedUrlResult {
    const trimmed = rawInput.trim();

    // 1. NPM Packages
    if (trimmed.startsWith('npm://')) {
      const pkg = trimmed.replace(/^npm:\/\//, '').replace(/\/$/, '').toLowerCase();
      return {
        raw_url: trimmed,
        normalized_url: `npm://${pkg}`,
        canonical_url: `https://www.npmjs.com/package/${pkg}`,
        domain: 'npmjs.com',
        candidate_type: 'PACKAGE',
        source_adapter: 'npm',
      };
    }
    if (trimmed.includes('npmjs.com/package/')) {
      const match = trimmed.match(/npmjs\.com\/package\/((?:@[^/?#]+\/)?[^/?#]+)/i);
      const pkg = match ? match[1].toLowerCase() : trimmed;
      return {
        raw_url: trimmed,
        normalized_url: `npm://${pkg}`,
        canonical_url: `https://www.npmjs.com/package/${pkg}`,
        domain: 'npmjs.com',
        candidate_type: 'PACKAGE',
        source_adapter: 'npm',
      };
    }

    // 2. PyPI Packages
    if (trimmed.startsWith('pypi://')) {
      const pkg = trimmed.replace(/^pypi:\/\//, '').replace(/\/$/, '').toLowerCase();
      return {
        raw_url: trimmed,
        normalized_url: `pypi://${pkg}`,
        canonical_url: `https://pypi.org/project/${pkg}/`,
        domain: 'pypi.org',
        candidate_type: 'PACKAGE',
        source_adapter: 'pypi',
      };
    }
    if (trimmed.includes('pypi.org/project/')) {
      const match = trimmed.match(/pypi\.org\/project\/([^/?#]+)/i);
      const pkg = match ? match[1].toLowerCase() : trimmed;
      return {
        raw_url: trimmed,
        normalized_url: `pypi://${pkg}`,
        canonical_url: `https://pypi.org/project/${pkg}/`,
        domain: 'pypi.org',
        candidate_type: 'PACKAGE',
        source_adapter: 'pypi',
      };
    }

    // 3. GitHub Repositories
    if (trimmed.startsWith('github://')) {
      const path = trimmed.replace(/^github:\/\//, '').replace(/\.git$/, '').replace(/\/$/, '').toLowerCase();
      return {
        raw_url: trimmed,
        normalized_url: `github://${path}`,
        canonical_url: `https://github.com/${path}`,
        domain: 'github.com',
        candidate_type: path.includes('/') ? 'REPOSITORY' : 'ORGANIZATION',
        source_adapter: 'github',
      };
    }
    if (trimmed.includes('github.com/')) {
      const match = trimmed.match(/github\.com\/([^/?#]+\/[^/?#]+)/i);
      if (match) {
        const repoPath = match[1].replace(/\.git$/, '').toLowerCase();
        return {
          raw_url: trimmed,
          normalized_url: `github://${repoPath}`,
          canonical_url: `https://github.com/${repoPath}`,
          domain: 'github.com',
          candidate_type: 'REPOSITORY',
          source_adapter: 'github',
        };
      }
    }

    // 4. GitLab Repositories
    if (trimmed.startsWith('gitlab://')) {
      const path = trimmed.replace(/^gitlab:\/\//, '').replace(/\.git$/, '').replace(/\/$/, '').toLowerCase();
      return {
        raw_url: trimmed,
        normalized_url: `gitlab://${path}`,
        canonical_url: `https://gitlab.com/${path}`,
        domain: 'gitlab.com',
        candidate_type: 'REPOSITORY',
        source_adapter: 'gitlab',
      };
    }
    if (trimmed.includes('gitlab.com/')) {
      const match = trimmed.match(/gitlab\.com\/([^/?#]+\/[^/?#]+)/i);
      if (match) {
        const repoPath = match[1].replace(/\.git$/, '').toLowerCase();
        return {
          raw_url: trimmed,
          normalized_url: `gitlab://${repoPath}`,
          canonical_url: `https://gitlab.com/${repoPath}`,
          domain: 'gitlab.com',
          candidate_type: 'REPOSITORY',
          source_adapter: 'gitlab',
        };
      }
    }

    // 5. Hugging Face Models
    if (trimmed.startsWith('hf://') || trimmed.startsWith('huggingface://')) {
      const model = trimmed.replace(/^(?:hf|huggingface):\/\//, '').replace(/\/$/, '').toLowerCase();
      return {
        raw_url: trimmed,
        normalized_url: `huggingface://${model}`,
        canonical_url: `https://huggingface.co/${model}`,
        domain: 'huggingface.co',
        candidate_type: 'MODEL',
        source_adapter: 'huggingface',
      };
    }
    if (trimmed.includes('huggingface.co/')) {
      const match = trimmed.match(/huggingface\.co\/([^/?#]+\/[^/?#]+)/i);
      if (match) {
        const model = match[1].toLowerCase();
        return {
          raw_url: trimmed,
          normalized_url: `huggingface://${model}`,
          canonical_url: `https://huggingface.co/${model}`,
          domain: 'huggingface.co',
          candidate_type: 'MODEL',
          source_adapter: 'huggingface',
        };
      }
    }

    // 6. Docker Hub Images
    if (trimmed.startsWith('docker://')) {
      const img = trimmed.replace(/^docker:\/\//, '').replace(/\/$/, '').toLowerCase();
      return {
        raw_url: trimmed,
        normalized_url: `docker://${img}`,
        canonical_url: `https://hub.docker.com/r/${img}`,
        domain: 'hub.docker.com',
        candidate_type: 'CONTAINER_IMAGE',
        source_adapter: 'dockerhub',
      };
    }
    if (trimmed.includes('hub.docker.com/r/')) {
      const match = trimmed.match(/hub\.docker\.com\/r\/([^/?#]+\/[^/?#]+)/i);
      if (match) {
        const img = match[1].toLowerCase();
        return {
          raw_url: trimmed,
          normalized_url: `docker://${img}`,
          canonical_url: `https://hub.docker.com/r/${img}`,
          domain: 'hub.docker.com',
          candidate_type: 'CONTAINER_IMAGE',
          source_adapter: 'dockerhub',
        };
      }
    }

    // 7. Codeberg Repositories
    if (trimmed.startsWith('codeberg://')) {
      const path = trimmed.replace(/^codeberg:\/\//, '').replace(/\.git$/, '').replace(/\/$/, '').toLowerCase();
      return {
        raw_url: trimmed,
        normalized_url: `codeberg://${path}`,
        canonical_url: `https://codeberg.org/${path}`,
        domain: 'codeberg.org',
        candidate_type: 'REPOSITORY',
        source_adapter: 'codeberg',
      };
    }
    if (trimmed.includes('codeberg.org/')) {
      const match = trimmed.match(/codeberg\.org\/([^/?#]+\/[^/?#]+)/i);
      if (match) {
        const repoPath = match[1].replace(/\.git$/, '').toLowerCase();
        return {
          raw_url: trimmed,
          normalized_url: `codeberg://${repoPath}`,
          canonical_url: `https://codeberg.org/${repoPath}`,
          domain: 'codeberg.org',
          candidate_type: 'REPOSITORY',
          source_adapter: 'codeberg',
        };
      }
    }

    // Generic URL fallback
    try {
      const parsed = new URL(trimmed);
      const domain = parsed.hostname.toLowerCase();
      // Remove query tracking params (utm_*, ref, etc.)
      const searchParams = new URLSearchParams(parsed.search);
      for (const key of Array.from(searchParams.keys())) {
        if (key.startsWith('utm_') || key === 'ref' || key === 'source') {
          searchParams.delete(key);
        }
      }
      parsed.search = searchParams.toString();
      const normalized = parsed.toString().replace(/\/$/, '');

      return {
        raw_url: trimmed,
        normalized_url: normalized,
        canonical_url: normalized,
        domain: domain,
        candidate_type: 'WEB_PAGE',
        source_adapter: 'generic',
      };
    } catch {
      // Return locator as-is
      return {
        raw_url: trimmed,
        normalized_url: trimmed.toLowerCase(),
        canonical_url: trimmed,
        domain: 'unknown',
        candidate_type: 'UNKNOWN',
        source_adapter: 'unknown',
      };
    }
  }
}
