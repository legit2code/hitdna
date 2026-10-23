/**
 * P33 — Dedicated Performance Smoke & Graceful Degradation Test Suite
 *
 * Validates:
 * 1. Core Analysis Pipeline (Static Analysis AST/CFG + Decision Scoring) baseline latency and throughput
 *    under synthetic load with explicit pass/fail thresholds.
 * 2. Resource-Exhaustion Guarding & Graceful Degradation (concurrency limits, bounded queues, backpressure load shedding).
 * 3. Regression Detection comparing current benchmarks against stored performance baselines.
 */

import { describe, it, expect } from 'vitest';
import {
  PerformanceSmokeRunner,
  PerformanceBaseline,
  CorePipelineBenchmarkResult,
  CapacityDegradationResult,
  RegressionComparisonResult,
} from '@caim/workflow/performance-smoke.ts';
import { StaticAnalysisEngine } from '../../workers/static-analysis/engine.ts';
import { DecisionOrchestrationEngine } from '../../workers/decision/engine.ts';

describe('P33: Performance Smoke & Capacity Degradation Suite', () => {
  /**
   * 1. Baseline Latency & Throughput for Core Analysis Pipeline (Static Analysis + Decision Suite)
   *
   * Thresholds Chosen & Rationale:
   * - Max P95 Latency: <= 15.0 ms.
   *   Rationale: In-memory AST parsing, CFG construction, taint detection, and multi-factor decision scoring
   *   for typical agent units (~50-100 LOC) should execute in < 2-5ms in modern V8. 15.0ms provides an upper
   *   bound accounting for JIT warm-up and garbage collection spikes while guaranteeing batch processing of 100
   *   packages completes in < 1.5 seconds.
   * - Min Throughput: >= 100.0 operations/second.
   *   Rationale: Core queue workers must sustain at least 100 complete analysis cycles per second per process
   *   to handle peak CI/CD webhook bursts without unbounded queue buildup.
   */
  describe('1. Core Analysis Pipeline Baseline Latency & Throughput Benchmark', () => {
    it('executes static analysis + decision scoring pipeline under synthetic load and meets latency & throughput thresholds', async () => {
      const benchmarkResult: CorePipelineBenchmarkResult = await PerformanceSmokeRunner.runCoreAnalysisPipeline({
        iterations: 30,
        maxP95Ms: 15.0,
        minThroughputOpsSec: 100.0,
      });

      // Output benchmark metrics for observability
      console.log('--- Core Pipeline Benchmark Results ---');
      console.log(`Iterations: ${benchmarkResult.iterations}`);
      console.log(`Total Duration: ${benchmarkResult.durationMs}ms`);
      console.log(`Throughput: ${benchmarkResult.throughputOpsSec} ops/sec (Threshold: >= ${benchmarkResult.thresholds.minThroughputOpsSec} ops/sec)`);
      console.log(`Latency P50: ${benchmarkResult.latency.p50Ms}ms, P95: ${benchmarkResult.latency.p95Ms}ms, P99: ${benchmarkResult.latency.p99Ms}ms (P95 Threshold: <= ${benchmarkResult.thresholds.maxP95Ms}ms)`);
      console.log(`Findings Detected: ${benchmarkResult.findingsCount}, Policy Decision Outcome: ${benchmarkResult.policyOutcome}`);

      expect(benchmarkResult.status).toBe('PASSED');
      expect(benchmarkResult.latency.p95Ms).toBeLessThanOrEqual(15.0);
      expect(benchmarkResult.throughputOpsSec).toBeGreaterThanOrEqual(100.0);
      expect(benchmarkResult.findingsCount).toBeGreaterThan(0);
      expect(benchmarkResult.policyOutcome).toBeDefined();
    });

    it('executes live StaticAnalysisEngine + DecisionOrchestrationEngine worker pipeline end-to-end under synthetic load', async () => {
      const livePipelineResult = await PerformanceSmokeRunner.runCoreAnalysisPipeline({
        iterations: 25,
        maxP95Ms: 35.0,
        minThroughputOpsSec: 80.0,
        pipelineExecutor: async ({ iteration, files }) => {
          const runId = `live-perf-${iteration}`;
          const saReport = StaticAnalysisEngine.analyze({
            pipelineRunId: runId,
            artifactId: `art-perf-${iteration}`,
            files,
            entrypoints: ['src/agent.ts'],
          });

          const decisionResult = await DecisionOrchestrationEngine.runDecisionSuite({
            analysisRunId: runId,
            entityRefId: `art-perf-${iteration}`,
            findings: saReport.findings,
            taintFlows: saReport.taint_report ? [
              { source_type: 'HTTP_PARAM', sink_type: 'COMMAND_INJECTION', severity: 'HIGH' }
            ] : [],
          });

          return {
            findingsCount: saReport.findings.length,
            policyOutcome: decisionResult.policy_decision?.outcome || 'ALLOW',
            scoreResult: {
              overallScore: decisionResult.score_result?.overall_score || 0,
              riskBand: decisionResult.score_result?.risk_band || 'UNKNOWN',
            },
          };
        },
      });

      console.log('--- Live Static + Decision Worker Pipeline Benchmark ---');
      console.log(`Iterations: ${livePipelineResult.iterations}`);
      console.log(`Throughput: ${livePipelineResult.throughputOpsSec} ops/sec`);
      console.log(`Latency P50: ${livePipelineResult.latency.p50Ms}ms, P95: ${livePipelineResult.latency.p95Ms}ms`);

      expect(livePipelineResult.status).toBe('PASSED');
      expect(livePipelineResult.latency.p95Ms).toBeLessThanOrEqual(35.0);
      expect(livePipelineResult.throughputOpsSec).toBeGreaterThanOrEqual(80.0);
      expect(livePipelineResult.policyOutcome).toBeDefined();
    });

    it('runs the full 6-component system smoke suite and verifies all sub-step distributions', async () => {
      const fullReport = await PerformanceSmokeRunner.runSuite();

      expect(fullReport.overallStatus).toBe('PASSED');
      expect(fullReport.steps.length).toBe(6);

      const stepNames = fullReport.steps.map(s => s.stepName);
      expect(stepNames).toContain('Catalog & Agent Version API Reads');
      expect(stepNames).toContain('Queue Job Enqueue & Lease Acquisition');
      expect(stepNames).toContain('Representative Static AST & Control-Flow Parsing');
      expect(stepNames).toContain('RAG Grounding & Vector Similarity Search');
      expect(stepNames).toContain('8-Hop Epistemic Lineage Resolution');
      expect(stepNames).toContain('Package Bundle Build & Cryptographic Signing');

      for (const step of fullReport.steps) {
        expect(step.status).toBe('PASSED');
        expect(step.latency.p95Ms).toBeGreaterThanOrEqual(0);
        expect(step.throughputPerSecond).toBeGreaterThan(0);
      }
    });
  });

  /**
   * 2. Resource-Exhaustion Guard & Graceful Degradation Test
   *
   * Verifies that when synthetic traffic surges past worker capacity (concurrency: 5, queue depth: 20, spike: 60 jobs):
   * - The system does NOT crash, throw unhandled exceptions, or corrupt internal state.
   * - Jobs within capacity are accepted, queued, and processed.
   * - Excess jobs beyond the bounded queue depth are shed gracefully with backpressure (429 Too Many Requests / Backoff).
   * - 0 unhandled promise rejections or fatal process failures occur.
   */
  describe('2. Resource-Exhaustion Guard & Graceful Degradation', () => {
    it('gracefully sheds load via backpressure and processes queued jobs without crashing under 3x overload spike', async () => {
      const degradationResult: CapacityDegradationResult = await PerformanceSmokeRunner.evaluateCapacityDegradation({
        concurrencyLimit: 5,
        queueCapacity: 20,
        spikeVolume: 60, // 3x queue capacity, 12x active concurrency
        simulatedJobWorkloadMs: 4,
      });

      console.log('--- Capacity Degradation & Guard Results ---');
      console.log(`Total Submitted: ${degradationResult.metrics.totalSubmitted}`);
      console.log(`Accepted & Completed: ${degradationResult.metrics.acceptedAndCompleted}`);
      console.log(`Gracefully Shed / Backpressure Rejected: ${degradationResult.metrics.backpressureRejected}`);
      console.log(`Crashes / Unhandled Errors: ${degradationResult.metrics.crashedCount}`);
      console.log(`Degradation Status: ${degradationResult.degradationStatus}`);

      // Confirm 0 crashes occurred
      expect(degradationResult.metrics.crashedCount).toBe(0);
      expect(degradationResult.degradationStatus).toBe('GRACEFUL_DEGRADATION');
      expect(degradationResult.passed).toBe(true);

      // Confirm all submitted jobs were accounted for (completed or backpressure shed)
      expect(
        degradationResult.metrics.acceptedAndCompleted + degradationResult.metrics.backpressureRejected
      ).toBe(degradationResult.metrics.totalSubmitted);

      // Confirm backpressure shed load when queue depth was exceeded
      expect(degradationResult.metrics.backpressureRejected).toBeGreaterThan(0);
      expect(degradationResult.metrics.acceptedAndCompleted).toBeGreaterThanOrEqual(5);
    });
  });

  /**
   * 3. Performance Regression Engine (Stored Baseline Comparison)
   *
   * Verifies that current benchmark telemetry is compared against a certified historical baseline:
   * - Passes when current performance is within allowed tolerance (+30% latency, -25% throughput).
   * - Detects meaningful regressions and fails when latency spikes or throughput collapses past tolerance.
   */
  describe('3. Regression Comparison against Stored Historical Baseline', () => {
    it('confirms current core pipeline and multi-step suite meet stored certified baseline tolerances', async () => {
      const baseline: PerformanceBaseline = PerformanceSmokeRunner.getStoredBaseline();
      expect(baseline.baselineId).toBeDefined();
      expect(baseline.architectureVersion).toBe('2.0.1');

      // Run current benchmark
      const currentReport = await PerformanceSmokeRunner.runSuite();
      const comparison: RegressionComparisonResult = PerformanceSmokeRunner.compareWithBaseline(
        currentReport,
        baseline,
        {
          maxLatencyRegressionPercent: 30.0, // Fail if latency degrades by > 30%
          maxThroughputDropPercent: 25.0,    // Fail if throughput drops by > 25%
        }
      );

      console.log('--- Baseline Regression Comparison ---');
      console.log(`Baseline ID: ${comparison.baselineId}`);
      console.log(`Verdict: ${comparison.verdict}`);
      console.log(`Evaluated Components: ${comparison.evaluatedComponentsCount}`);
      console.log(`Violations Count: ${comparison.violations.length}`);

      expect(comparison.verdict).toBe('PASSED');
      expect(comparison.hasRegression).toBe(false);
      expect(comparison.violations).toHaveLength(0);
    });

    it('correctly detects and flags a synthetic latency regression exceeding the tolerance threshold', async () => {
      const baseline: PerformanceBaseline = PerformanceSmokeRunner.getStoredBaseline();

      // Create an artificially regressed report to verify regression detection logic
      const regressedReport = await PerformanceSmokeRunner.runSuite();
      // Artificially inflate the latency of the first step by 300%
      regressedReport.steps[0].latency.p95Ms = baseline.stepBaselines[regressedReport.steps[0].stepName].p95Ms * 4;

      const comparison: RegressionComparisonResult = PerformanceSmokeRunner.compareWithBaseline(
        regressedReport,
        baseline,
        {
          maxLatencyRegressionPercent: 30.0,
          maxThroughputDropPercent: 25.0,
        }
      );

      expect(comparison.verdict).toBe('REGRESSION_DETECTED');
      expect(comparison.hasRegression).toBe(true);
      expect(comparison.violations.length).toBeGreaterThan(0);
      expect(comparison.violations[0].metric).toBe('P95_LATENCY');
      expect(comparison.violations[0].violationMessage).toContain('regressed by');
    });

    it('correctly detects and flags a synthetic throughput drop exceeding the tolerance threshold', async () => {
      const baseline: PerformanceBaseline = PerformanceSmokeRunner.getStoredBaseline();

      const regressedReport = await PerformanceSmokeRunner.runSuite();
      // Artificially collapse throughput to 10% of baseline
      regressedReport.steps[0].throughputPerSecond = baseline.stepBaselines[regressedReport.steps[0].stepName].throughputOpsSec * 0.1;

      const comparison: RegressionComparisonResult = PerformanceSmokeRunner.compareWithBaseline(
        regressedReport,
        baseline,
        {
          maxLatencyRegressionPercent: 30.0,
          maxThroughputDropPercent: 25.0,
        }
      );

      expect(comparison.verdict).toBe('REGRESSION_DETECTED');
      expect(comparison.hasRegression).toBe(true);
      const throughputViolation = comparison.violations.find(v => v.metric === 'THROUGHPUT');
      expect(throughputViolation).toBeDefined();
      expect(throughputViolation?.violationMessage).toContain('Throughput dropped');
    });
  });
});
