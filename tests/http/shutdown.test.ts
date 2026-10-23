import { describe, it, expect } from 'vitest';
import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close((err) => {
        if (err) reject(err);
        else resolve(port);
      });
    });
  });
}

describe('Graceful Shutdown (R03 Task 6)', () => {
  it('drains in-flight requests upon receiving SIGTERM and exits with code 0', async () => {
    const port = await getFreePort();

    const tsxCli = path.resolve(process.cwd(), 'node_modules/tsx/dist/cli.mjs');
    const child = spawn(
      process.execPath,
      [tsxCli, 'apps/server/main.ts'],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          PORT: port.toString(),
          TEST_PORT: port.toString(),
          HOST: '127.0.0.1',
          NODE_ENV: 'test',
          SKIP_VITE: 'true',
          SHUTDOWN_TIMEOUT_MS: '5000',
        },
        stdio: 'pipe',
      }
    );

    // Collect child stderr/stdout for diagnostics if needed
    let output = '';
    child.stdout?.on('data', (d) => { output += d.toString(); });
    child.stderr?.on('data', (d) => { output += d.toString(); });

    // Poll until server is healthy
    const baseUrl = `http://127.0.0.1:${port}`;
    let isUp = false;
    for (let i = 0; i < 100; i++) {
      if (child.exitCode !== null) {
        console.error('Child process exited early with code:', child.exitCode, output);
        break;
      }
      try {
        const res = await fetch(`${baseUrl}/healthz`);
        if (res.status === 200) {
          isUp = true;
          break;
        }
      } catch {
        // Retry
      }
      await new Promise((r) => setTimeout(r, 200));
    }

    expect(isUp).toBe(true);

    // Start a slow in-flight request (400 ms delay)
    const slowRequestPromise = fetch(`${baseUrl}/api/test-slow?delay=400`);

    // Wait 100 ms to guarantee the request is in-flight on the server
    await new Promise((r) => setTimeout(r, 100));

    // Send SIGTERM to initiate graceful shutdown while request is processing
    child.kill('SIGTERM');

    // Wait for the in-flight request to complete
    const response = await slowRequestPromise;
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; delay: number };
    expect(body.ok).toBe(true);
    expect(body.delay).toBe(400);

    // Wait for the process to exit and verify exit code 0
    const exitCode = await new Promise<number | null>((resolve) => {
      child.on('exit', (code) => resolve(code));
    });

    expect(exitCode).toBe(0);
  }, 30000);
});
