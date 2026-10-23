import { build } from 'esbuild';

async function buildServer() {
  const allowSourcemaps = process.env.ALLOW_SOURCEMAPS === '1';

  await build({
    entryPoints: ['server.ts'],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    packages: 'external',
    sourcemap: allowSourcemaps,
    outfile: 'dist/server.cjs',
  });
}

buildServer().catch((err) => {
  console.error('Failed to build server:', err);
  process.exit(1);
});
