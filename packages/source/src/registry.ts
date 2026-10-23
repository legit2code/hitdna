import { SourceAdapter } from './types.ts';
import { SourceNotFoundError } from './errors.ts';
import { GitHubSourceAdapter, GitHubAdapterOptions } from './adapters/github.ts';
import { GitLabSourceAdapter, GitLabAdapterOptions } from './adapters/gitlab.ts';
import { PyPISourceAdapter, PyPIAdapterOptions } from './adapters/pypi.ts';
import { NpmSourceAdapter, NpmAdapterOptions } from './adapters/npm.ts';
import { HuggingFaceSourceAdapter, HuggingFaceAdapterOptions } from './adapters/huggingface.ts';
import { DockerHubSourceAdapter, DockerHubAdapterOptions } from './adapters/dockerhub.ts';
import { CodebergSourceAdapter, CodebergAdapterOptions } from './adapters/codeberg.ts';
import { MCPSourceAdapter, MCPAdapterOptions } from './adapters/mcp.ts';
import { HuggingFaceSpacesSourceAdapter, HFSpacesAdapterOptions } from './adapters/hf-spaces.ts';
import { ReplicateSourceAdapter, ReplicateAdapterOptions } from './adapters/replicate.ts';
import { KaggleSourceAdapter, KaggleAdapterOptions } from './adapters/kaggle.ts';
import { HackerNewsSourceAdapter, HackerNewsAdapterOptions } from './adapters/hackernews.ts';
import { ArxivSourceAdapter, ArxivAdapterOptions } from './adapters/arxiv.ts';

export interface DefaultRegistryOptions {
  github?: GitHubAdapterOptions;
  gitlab?: GitLabAdapterOptions;
  pypi?: PyPIAdapterOptions;
  npm?: NpmAdapterOptions;
  huggingface?: HuggingFaceAdapterOptions;
  dockerhub?: DockerHubAdapterOptions;
  codeberg?: CodebergAdapterOptions;
  mcp?: MCPAdapterOptions;
  hfSpaces?: HFSpacesAdapterOptions;
  replicate?: ReplicateAdapterOptions;
  kaggle?: KaggleAdapterOptions;
  hackernews?: HackerNewsAdapterOptions;
  arxiv?: ArxivAdapterOptions;
}

export class SourceAdapterRegistry {
  private adapters = new Map<string, SourceAdapter>();

  register(adapter: SourceAdapter): this {
    this.adapters.set(adapter.sourceType.toLowerCase(), adapter);
    return this;
  }

  unregister(sourceType: string): boolean {
    return this.adapters.delete(sourceType.toLowerCase());
  }

  get(sourceType: string): SourceAdapter | undefined {
    return this.adapters.get(sourceType.toLowerCase());
  }

  mustGet(sourceType: string): SourceAdapter {
    const adapter = this.get(sourceType);
    if (!adapter) {
      throw new SourceNotFoundError(`No source adapter registered for type: '${sourceType}'`, {
        sourceType,
        locator: `source://${sourceType}`,
      });
    }
    return adapter;
  }

  getAll(): SourceAdapter[] {
    return Array.from(this.adapters.values());
  }

  /**
   * Automatically resolves which adapter handles a given locator string based on protocol or domain.
   */
  resolveForLocator(locator: string): SourceAdapter {
    const clean = locator.toLowerCase();

    if (clean.startsWith('github://') || clean.includes('github.com')) {
      return this.mustGet('github');
    }
    if (clean.startsWith('gitlab://') || clean.includes('gitlab.com')) {
      return this.mustGet('gitlab');
    }
    if (clean.startsWith('pypi://') || clean.includes('pypi.org')) {
      return this.mustGet('pypi');
    }
    if (clean.startsWith('npm://') || clean.includes('npmjs.com') || clean.includes('registry.npmjs.org')) {
      return this.mustGet('npm');
    }
    if (clean.startsWith('hf_spaces://') || clean.startsWith('hf-space://') || clean.includes('huggingface.co/spaces')) {
      return this.mustGet('hf_spaces');
    }
    if (clean.startsWith('hf://') || clean.includes('huggingface.co')) {
      return this.mustGet('huggingface');
    }
    if (clean.startsWith('docker://') || clean.includes('docker.io') || clean.includes('hub.docker.com')) {
      return this.mustGet('dockerhub');
    }
    if (clean.startsWith('codeberg://') || clean.includes('codeberg.org')) {
      return this.mustGet('codeberg');
    }
    if (clean.startsWith('mcp://') || clean.includes('registry.modelcontextprotocol.io')) {
      return this.mustGet('mcp');
    }
    if (clean.startsWith('replicate://') || clean.includes('replicate.com')) {
      return this.mustGet('replicate');
    }
    if (clean.startsWith('kaggle://') || clean.includes('kaggle.com')) {
      return this.mustGet('kaggle');
    }
    if (clean.startsWith('hn://') || clean.includes('news.ycombinator.com') || clean.startsWith('hackernews://')) {
      return this.mustGet('hackernews');
    }
    if (clean.startsWith('arxiv://') || clean.includes('arxiv.org')) {
      return this.mustGet('arxiv');
    }

    // Try matching any registered adapter by prefix
    for (const adapter of this.adapters.values()) {
      if (clean.startsWith(`${adapter.sourceType}://`)) {
        return adapter;
      }
    }

    throw new SourceNotFoundError(`Unable to infer source adapter for locator: '${locator}'`, {
      sourceType: 'unknown',
      locator,
    });
  }

  /**
   * Creates a registry pre-populated with standard adapters (all 7 core adapters + 6 Tier 1 adapters).
   */
  static createDefault(options: DefaultRegistryOptions = {}): SourceAdapterRegistry {
    const registry = new SourceAdapterRegistry();
    registry.register(new GitHubSourceAdapter(options.github));
    registry.register(new GitLabSourceAdapter(options.gitlab));
    registry.register(new PyPISourceAdapter(options.pypi));
    registry.register(new NpmSourceAdapter(options.npm));
    registry.register(new HuggingFaceSourceAdapter(options.huggingface));
    registry.register(new DockerHubSourceAdapter(options.dockerhub));
    registry.register(new CodebergSourceAdapter(options.codeberg));
    registry.register(new MCPSourceAdapter(options.mcp));
    registry.register(new HuggingFaceSpacesSourceAdapter(options.hfSpaces));
    registry.register(new ReplicateSourceAdapter(options.replicate));
    registry.register(new KaggleSourceAdapter(options.kaggle));
    registry.register(new HackerNewsSourceAdapter(options.hackernews));
    registry.register(new ArxivSourceAdapter(options.arxiv));
    return registry;
  }
}

