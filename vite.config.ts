import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig, Plugin } from 'vite';

function isolateWorkersPlugin(): Plugin {
  return {
    name: 'isolate-workers-boundary',
    resolveId(source, importer) {
      if (source.includes('workers/') || source.startsWith('@workers')) {
        throw new Error(
          `[Architecture Invariant Violation] Client bundle must not import worker packages directly (${source}). Workers run out-of-process.`
        );
      }
      if (source.includes('packages/packaging') || source.startsWith('@caim/packaging')) {
        throw new Error(
          `[Architecture Invariant Violation F-19] Client bundle must not import packaging packages directly (${source}). Packaging runs server-side.`
        );
      }
      if (source.includes('packages/syntax') || source.startsWith('@caim/syntax')) {
        throw new Error(
          `[Architecture Invariant Violation] Client bundle must not import syntax parser packages directly (${source}). Syntax analysis runs server-side.`
        );
      }
      if (source === 'node:crypto' || source === 'crypto') {
        throw new Error(
          `[Architecture Invariant Violation] Client bundle must not import crypto directly (${source}) from ${importer}.`
        );
      }
      return null;
    },
  };
}

export default defineConfig(() => {
  return {
    plugins: [isolateWorkersPlugin(), react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
        '@caim/api': path.resolve(__dirname, 'packages/api/src'),
        '@caim/auth': path.resolve(__dirname, 'packages/auth/src'),
        '@caim/config': path.resolve(__dirname, 'packages/config/src'),
        '@caim/contracts': path.resolve(__dirname, 'packages/contracts/src'),
        '@caim/crypto': path.resolve(__dirname, 'packages/crypto/src'),
        '@caim/db': path.resolve(__dirname, 'packages/db/src'),
        '@caim/events': path.resolve(__dirname, 'packages/events/src'),
        '@caim/lifecycle': path.resolve(__dirname, 'packages/lifecycle/src'),
        '@caim/ontology': path.resolve(__dirname, 'packages/ontology/src'),
        '@caim/packaging': path.resolve(__dirname, 'packages/packaging/src'),
        '@caim/source': path.resolve(__dirname, 'packages/source/src'),
        '@caim/syntax': path.resolve(__dirname, 'packages/syntax/src'),
        '@caim/testing': path.resolve(__dirname, 'packages/testing/src'),
        '@caim/workflow': path.resolve(__dirname, 'packages/workflow/src'),
      },
    },
    server: {
      // HMR is disabled in AI Studio environment
      hmr: false,
      watch: null,
    },
    build: {
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes('node_modules')) {
              if (id.includes('lucide-react')) {
                return 'vendor-lucide';
              }
              if (id.includes('motion')) {
                return 'vendor-motion';
              }
              return 'vendor-core';
            }
          },
        },
      },
    },
  };
});
