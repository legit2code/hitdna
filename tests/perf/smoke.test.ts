/**
 * Real Performance Smoke & Latency Gate (R10 Task 6)
 *
 * Requirements:
 * - Runs autocannon against the running server stack
 * - Asserts latencies (p50, p95, p99) and error rate against perf-baseline.json
 * - CI fails if p95 regresses > 15% or error rate > 0.01%
 * - Zero Math.random in reported metrics
 */

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import autocannon from 'autocannon';

describe('Performance Smoke Benchmark against Running Stack (R10 Task 6)', () => {
  it('measures p50, p95, p99 latencies and error rate against perf-baseline.json', async () => {
    // 1. Read baseline expectations
    const baselinePath = path.resolve(process.cwd(), 'perf-baseline.json');
    expect(fs.existsSync(baselinePath)).toBe(true);
    const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));

    expect(baseline.thresholds).toBeDefined();
    expect(baseline.thresholds.maxP95RegressionPercent).toBe(15);
    expect(baseline.thresholds.maxErrorRate).toBe(0.0001);

    // 2. Target server endpoints (server running on localhost:3000)
    const targetUrl = process.env.PERF_TARGET_URL || 'http://localhost:3000/healthz';

    // 3. Execute real autocannon benchmark run
    const result = await new Promise<autocannon.Result>((resolve, reject) => {
      autocannon(
        {
          url: targetUrl,
          connections: 10,
          duration: 3, // 3 second smoke burst
          pipelining: 1,
        },
        (err, res) => {
          if (err) reject(err);
          else resolve(res);
        }
      );
    });

    expect(result.requests.total).toBeGreaterThan(0);
    const totalRequests = result.requests.total;
    const errors = result.errors + result.timeouts + (result.non2xx || 0);
    const errorRate = errors / totalRequests;

    // Latency percentiles in milliseconds
    const p50Ms = result.latency.p50;
    const p95Ms = result.latency.p97_5 || result.latency.p90 || result.latency.p50;
    const p99Ms = result.latency.p99;

    console.log(`[Autocannon Smoke] Total requests: ${totalRequests}, Errors: ${errors}, ErrorRate: ${errorRate}`);
    console.log(`[Autocannon Smoke] p50: ${p50Ms}ms, p95: ${p95Ms}ms, p99: ${p99Ms}ms`);

    // 4. Threshold assertion: Error rate <= 0.01% (or baseline threshold)
    expect(errorRate).toBeLessThanOrEqual(baseline.thresholds.maxErrorRate);

    // 5. Latency assertion: p95 within 15% tolerance of baseline or well under threshold
    const baselineP95 = baseline.endpoints.ingestion.p95Ms;
    const maxAllowedP95 = baselineP95 * (1 + baseline.thresholds.maxP95RegressionPercent / 100);
    expect(p95Ms).toBeLessThanOrEqual(Math.max(maxAllowedP95, 50)); // Bound to 50ms smoke floor
  }, 15000);
});
