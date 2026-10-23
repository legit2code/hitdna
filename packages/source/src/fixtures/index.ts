import { HttpFetcher, HttpResponse } from '../types.ts';

// ---------------------------------------------------------------------------
// 1. Synthetic Provider Fixtures
// ---------------------------------------------------------------------------

export const GITHUB_FIXTURES = {
  search: {
    total_count: 1,
    incomplete_results: false,
    items: [
      {
        id: 12345678,
        node_id: 'MDEwOlJlcG9zaXRvcnkxMjM0NTY3OA==',
        name: 'autonomous-caim-agent',
        full_name: 'caim-org/autonomous-caim-agent',
        private: false,
        owner: {
          login: 'caim-org',
          id: 99999,
          type: 'Organization',
          site_admin: false,
        },
        html_url: 'https://github.com/caim-org/autonomous-caim-agent',
        description: 'Reference Autonomous CAIM Agent with ontological contracts and policy engine',
        fork: false,
        created_at: '2026-01-15T08:00:00Z',
        updated_at: '2026-08-20T14:30:00Z',
        pushed_at: '2026-08-22T19:45:00Z',
        homepage: 'https://caim.dev/agents/autonomous',
        size: 4096,
        stargazers_count: 350,
        watchers_count: 350,
        language: 'TypeScript',
        default_branch: 'main',
      },
    ],
  },
  repo: {
    id: 12345678,
    name: 'autonomous-caim-agent',
    full_name: 'caim-org/autonomous-caim-agent',
    private: false,
    owner: {
      login: 'caim-org',
      id: 99999,
      type: 'Organization',
    },
    html_url: 'https://github.com/caim-org/autonomous-caim-agent',
    description: 'Reference Autonomous CAIM Agent with ontological contracts and policy engine',
    fork: false,
    default_branch: 'main',
    pushed_at: '2026-08-22T19:45:00Z',
    created_at: '2026-01-15T08:00:00Z',
    updated_at: '2026-08-20T14:30:00Z',
  },
  rateLimit: {
    resources: {
      core: {
        limit: 5000,
        remaining: 4995,
        reset: Math.floor(Date.now() / 1000) + 3600,
        used: 5,
      },
      search: {
        limit: 30,
        remaining: 29,
        reset: Math.floor(Date.now() / 1000) + 60,
        used: 1,
      },
    },
  },
};

export const GITLAB_FIXTURES = {
  projects: [
    {
      id: 98765,
      name: 'caim-pipeline-runner',
      name_with_namespace: 'Security Research / caim-pipeline-runner',
      path: 'caim-pipeline-runner',
      path_with_namespace: 'security-research/caim-pipeline-runner',
      created_at: '2026-02-10T10:00:00Z',
      default_branch: 'main',
      description: 'GitLab Autonomous Pipeline Runner for CAIM validation',
      http_url_to_repo: 'https://gitlab.com/security-research/caim-pipeline-runner.git',
      last_activity_at: '2026-08-21T11:20:00Z',
      namespace: {
        id: 4321,
        name: 'Security Research',
        path: 'security-research',
        full_path: 'security-research',
      },
      forked_from_project: null,
      star_count: 42,
    },
  ],
  project: {
    id: 98765,
    name: 'caim-pipeline-runner',
    name_with_namespace: 'Security Research / caim-pipeline-runner',
    path: 'caim-pipeline-runner',
    path_with_namespace: 'security-research/caim-pipeline-runner',
    created_at: '2026-02-10T10:00:00Z',
    default_branch: 'main',
    description: 'GitLab Autonomous Pipeline Runner for CAIM validation',
    http_url_to_repo: 'https://gitlab.com/security-research/caim-pipeline-runner.git',
    last_activity_at: '2026-08-21T11:20:00Z',
    namespace: {
      id: 4321,
      name: 'Security Research',
      path: 'security-research',
    },
  },
  version: {
    version: '17.3.0-ee',
    revision: 'abcdef12345',
  },
};

export const PYPI_FIXTURES = {
  package: {
    info: {
      author: 'CAIM Core Engineering',
      author_email: 'engineers@caim.dev',
      name: 'caim-agent-sdk',
      version: '2.1.0',
      summary: 'Python SDK for CAIM Agent specification, ontology, and runtime verification',
      home_page: 'https://caim.dev/python',
      license: 'Apache-2.0',
      requires_dist: [
        'pydantic (>=2.5.0)',
        'httpx (>=0.27.0)',
        'cryptography (>=42.0.0)',
      ],
      project_urls: {
        Homepage: 'https://caim.dev/python',
        Repository: 'https://github.com/caim-org/caim-agent-sdk-python',
        Documentation: 'https://docs.caim.dev/sdk/python',
      },
    },
    releases: {
      '2.1.0': [
        {
          filename: 'caim_agent_sdk-2.1.0-py3-none-any.whl',
          packagetype: 'bdist_wheel',
          python_version: 'py3',
          size: 45678,
          url: 'https://files.pythonhosted.org/packages/caim_agent_sdk-2.1.0-py3-none-any.whl',
          upload_time_iso_8601: '2026-08-18T16:00:00Z',
          digests: {
            sha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
          },
        },
        {
          filename: 'caim-agent-sdk-2.1.0.tar.gz',
          packagetype: 'sdist',
          python_version: 'source',
          size: 38900,
          url: 'https://files.pythonhosted.org/packages/caim-agent-sdk-2.1.0.tar.gz',
          upload_time_iso_8601: '2026-08-18T15:55:00Z',
          digests: {
            sha256: 'f0e1d2c3b4a59687786950413223140596877869504132231405968778695041',
          },
        },
      ],
    },
    urls: [
      {
        filename: 'caim_agent_sdk-2.1.0-py3-none-any.whl',
        packagetype: 'bdist_wheel',
        python_version: 'py3',
        size: 45678,
        url: 'https://files.pythonhosted.org/packages/caim_agent_sdk-2.1.0-py3-none-any.whl',
        upload_time_iso_8601: '2026-08-18T16:00:00Z',
        digests: {
          sha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
        },
      },
    ],
  },
};

export const NPM_FIXTURES = {
  search: {
    total: 1,
    objects: [
      {
        package: {
          name: '@caim/contracts',
          version: '2.0.1',
          description: 'Official TypeScript Ontological and Architectural Contracts for CAIM',
          date: '2026-08-19T20:00:00.000Z',
          publisher: {
            username: 'caim-admin',
            email: 'admin@caim.dev',
          },
          links: {
            npm: 'https://www.npmjs.com/package/%40caim%2Fcontracts',
            homepage: 'https://caim.dev',
            repository: 'https://github.com/caim-org/caim-contracts-ts',
          },
        },
        score: {
          final: 0.95,
        },
      },
    ],
  },
  package: {
    name: '@caim/contracts',
    'dist-tags': {
      latest: '2.0.1',
    },
    versions: {
      '2.0.1': {
        name: '@caim/contracts',
        version: '2.0.1',
        description: 'Official TypeScript Ontological and Architectural Contracts for CAIM',
        author: {
          name: 'CAIM Specification Working Group',
        },
        repository: {
          type: 'git',
          url: 'git+https://github.com/caim-org/caim-contracts-ts.git',
        },
        dependencies: {
          zod: '^4.4.3',
        },
        devDependencies: {
          typescript: '~5.8.2',
          vitest: '^4.1.11',
        },
        dist: {
          integrity: 'sha512-syntheticHashIntegrityValue123456789==',
          shasum: 'abcdef1234567890abcdef1234567890abcdef12',
          tarball: 'https://registry.npmjs.org/@caim/contracts/-/@caim/contracts-2.0.1.tgz',
          unpackedSize: 154200,
        },
      },
    },
    time: {
      modified: '2026-08-19T20:00:00.000Z',
      '2.0.1': '2026-08-19T20:00:00.000Z',
    },
  },
};

export const HUGGINGFACE_FIXTURES = {
  models: [
    {
      id: 'caim-ai/caim-reasoner-7b',
      modelId: 'caim-ai/caim-reasoner-7b',
      description: 'Fine-tuned reasoning agent model with ontology graph grounding',
      pipeline_tag: 'text-generation',
      tags: ['caim', 'reasoning', 'safetensors', 'base_model:meta-llama/Llama-3-8B'],
      createdAt: '2026-06-01T09:00:00.000Z',
      lastModified: '2026-08-20T18:15:00.000Z',
      sha: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
      downloads: 12500,
      likes: 420,
      cardData: {
        base_model: 'meta-llama/Llama-3-8B',
        datasets: ['caim-ai/reasoning-evaluation-corpus-v1'],
        language: ['en'],
      },
      siblings: [
        { rfilename: 'config.json' },
        { rfilename: 'model.safetensors' },
        { rfilename: 'tokenizer.json' },
        { rfilename: 'README.md' },
      ],
    },
  ],
  model: {
    id: 'caim-ai/caim-reasoner-7b',
    modelId: 'caim-ai/caim-reasoner-7b',
    description: 'Fine-tuned reasoning agent model with ontology graph grounding',
    pipeline_tag: 'text-generation',
    createdAt: '2026-06-01T09:00:00.000Z',
    lastModified: '2026-08-20T18:15:00.000Z',
    sha: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
    cardData: {
      base_model: 'meta-llama/Llama-3-8B',
      datasets: ['caim-ai/reasoning-evaluation-corpus-v1'],
    },
    siblings: [
      { rfilename: 'config.json' },
      { rfilename: 'model.safetensors' },
      { rfilename: 'README.md' },
    ],
  },
};

export const DOCKERHUB_FIXTURES = {
  search: {
    count: 1,
    results: [
      {
        name: 'caim-sandbox-runner',
        namespace: 'caimorg',
        repo_name: 'caimorg/caim-sandbox-runner',
        short_description: 'Hardened OCI Container Sandbox for Untrusted Agent Execution',
        star_count: 88,
        pull_count: '50K+',
        last_updated: '2026-08-21T07:45:00Z',
        created_at: '2026-03-01T12:00:00Z',
      },
    ],
  },
  repo: {
    user: 'caimorg',
    name: 'caim-sandbox-runner',
    namespace: 'caimorg',
    repository_type: 'image',
    status: 1,
    description: 'Hardened OCI Container Sandbox for Untrusted Agent Execution',
    is_private: false,
    star_count: 88,
    pull_count: 52000,
    last_updated: '2026-08-21T07:45:00Z',
    created_at: '2026-03-01T12:00:00Z',
  },
};

export const CODEBERG_FIXTURES = {
  search: {
    ok: true,
    data: [
      {
        id: 554433,
        name: 'caim-libre-agent',
        full_name: 'libre-ai/caim-libre-agent',
        description: 'Community-driven FOSS Autonomous Agent under European AI Act Compliance',
        owner: {
          username: 'libre-ai',
          full_name: 'Libre AI Collective',
        },
        clone_url: 'https://codeberg.org/libre-ai/caim-libre-agent.git',
        html_url: 'https://codeberg.org/libre-ai/caim-libre-agent',
        website: 'https://libre-ai.org',
        default_branch: 'main',
        fork: false,
        created_at: '2026-04-10T14:00:00Z',
        updated_at: '2026-08-22T08:30:00Z',
        stars_count: 140,
      },
    ],
  },
  repo: {
    id: 554433,
    name: 'caim-libre-agent',
    full_name: 'libre-ai/caim-libre-agent',
    description: 'Community-driven FOSS Autonomous Agent under European AI Act Compliance',
    owner: {
      username: 'libre-ai',
    },
    clone_url: 'https://codeberg.org/libre-ai/caim-libre-agent.git',
    default_branch: 'main',
    created_at: '2026-04-10T14:00:00Z',
    updated_at: '2026-08-22T08:30:00Z',
  },
  version: {
    version: 'Forgejo 8.0.0',
  },
};

export const BRAVE_SEARCH_FIXTURES = {
  search: {
    query: {
      original: 'autonomous caim agent',
      show_strict_warning: false,
      is_navigational: false,
    },
    mixed: {
      type: 'mixed',
      main: [],
      top: [],
      side: [],
    },
    web: {
      type: 'search',
      total: 3,
      results: [
        {
          title: 'CAIM: Autonomous Agent Specification & Reference Architecture',
          url: 'https://caim.dev/agents/autonomous',
          description: 'Official ontological specification and reference implementation for verifiable autonomous agents.',
          page_age: '2026-08-20T10:00:00Z',
          language: 'en',
          family_friendly: true,
        },
        {
          title: 'GitHub - caim-org/autonomous-caim-agent: Reference Autonomous CAIM Agent',
          url: 'https://github.com/caim-org/autonomous-caim-agent',
          description: 'Reference Autonomous CAIM Agent with ontological contracts and policy engine.',
          page_age: '2026-08-22T19:45:00Z',
          language: 'en',
          family_friendly: true,
        },
        {
          title: 'PyPI - autonomous-caim-agent: Python client distribution',
          url: 'https://pypi.org/project/autonomous-caim-agent/',
          description: 'PyPI distribution package for CAIM autonomous agent framework and tools.',
          page_age: '2026-08-21T16:00:00Z',
          language: 'en',
          family_friendly: true,
        },
      ],
    },
  },
};

// ---------------------------------------------------------------------------
// 2. Mock HTTP Transport Factory
// ---------------------------------------------------------------------------

export function createMockHttpFetcher(): HttpFetcher {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('[FATAL PRODUCTION ERROR] createMockHttpFetcher is strictly prohibited in production mode.');
  }
  return async (url: string, options = {}): Promise<HttpResponse> => {
    const urlStr = url.toString();
    const cleanUrl = urlStr.split('?')[0];

    // Standard headers returned by mock transport
    const defaultHeaders = {
      'content-type': 'application/json',
      'x-ratelimit-limit': '1000',
      'x-ratelimit-remaining': '995',
      'x-ratelimit-reset': String(Math.floor(Date.now() / 1000) + 3600),
      'etag': 'W/"synth-etag-12345"',
    };

    // GitHub routes
    if (urlStr.includes('api.github.com/search/repositories')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: GITHUB_FIXTURES.search };
    }
    if (urlStr.includes('api.github.com/repos/')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: GITHUB_FIXTURES.repo };
    }
    if (urlStr.includes('api.github.com/rate_limit')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: GITHUB_FIXTURES.rateLimit };
    }

    // GitLab routes
    if (urlStr.includes('gitlab.com/api/v4/projects?') || urlStr.endsWith('gitlab.com/api/v4/projects')) {
      return { status: 200, statusText: 'OK', headers: { ...defaultHeaders, 'x-next-page': '' }, data: GITLAB_FIXTURES.projects };
    }
    if (urlStr.includes('gitlab.com/api/v4/projects/')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: GITLAB_FIXTURES.project };
    }
    if (urlStr.includes('gitlab.com/api/v4/version')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: GITLAB_FIXTURES.version };
    }

    // PyPI routes
    if (urlStr.includes('pypi.org/pypi/')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: PYPI_FIXTURES.package };
    }

    // npm routes
    if (urlStr.includes('registry.npmjs.org/-/v1/search')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: NPM_FIXTURES.search };
    }
    if (urlStr.includes('registry.npmjs.org/-/ping')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: { ok: true } };
    }
    if (urlStr.includes('registry.npmjs.org/')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: NPM_FIXTURES.package };
    }

    // Hugging Face routes
    if (cleanUrl.endsWith('huggingface.co/api/models') || urlStr.includes('huggingface.co/api/models?')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: HUGGINGFACE_FIXTURES.models };
    }
    if (urlStr.includes('huggingface.co/api/models/')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: HUGGINGFACE_FIXTURES.model };
    }

    // Docker Hub routes
    if (urlStr.includes('hub.docker.com/v2/search/repositories')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: DOCKERHUB_FIXTURES.search };
    }
    if (urlStr.includes('hub.docker.com/v2/repositories/')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: DOCKERHUB_FIXTURES.repo };
    }

    // Codeberg routes
    if (urlStr.includes('codeberg.org/api/v1/repos/search')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: CODEBERG_FIXTURES.search };
    }
    if (urlStr.includes('codeberg.org/api/v1/repos/')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: CODEBERG_FIXTURES.repo };
    }
    if (urlStr.includes('codeberg.org/api/v1/version')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: CODEBERG_FIXTURES.version };
    }

    // Brave Search routes
    if (urlStr.includes('api.search.brave.com/res/v1/web/search')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: BRAVE_SEARCH_FIXTURES.search };
    }

    // MCP routes
    if (urlStr.includes('modelcontextprotocol.io')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: { servers: [] } };
    }

    // Hugging Face Spaces routes
    if (urlStr.includes('huggingface.co/api/spaces')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: [] };
    }

    // HackerNews routes
    if (urlStr.includes('hacker-news.firebaseio.com')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: 12345 };
    }

    // arXiv routes
    if (urlStr.includes('export.arxiv.org')) {
      return {
        status: 200,
        statusText: 'OK',
        headers: { ...defaultHeaders, 'content-type': 'application/atom+xml' },
        data: '<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><id>http://arxiv.org/abs/2304.11817v1</id><title>Test Paper</title><updated>2023-04-24T00:00:00Z</updated><published>2023-04-24T00:00:00Z</published><summary>Test summary</summary></entry></feed>',
      };
    }

    // Replicate routes
    if (urlStr.includes('api.replicate.com')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: { results: [] } };
    }

    // Kaggle routes
    if (urlStr.includes('kaggle.com')) {
      return { status: 200, statusText: 'OK', headers: defaultHeaders, data: [] };
    }

    return {
      status: 404,
      statusText: 'Not Found',
      headers: defaultHeaders,
      data: { message: `Synthetic mock route not found for: ${url}` },
    };
  };
}
