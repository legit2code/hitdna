import {
  FreshnessEvaluation,
  FreshnessStatus,
  FreshnessMetrics,
  ChangeTokenType,
} from './types.ts';

export interface FreshnessRecord {
  source_locator: string;
  source_type: string;
  strategy_id?: string;
  last_observed_at: string;
  change_token?: string;
  token_type?: ChangeTokenType;
  ttl_seconds: number;
}

export class FreshnessScheduler {
  private records = new Map<string, FreshnessRecord>();

  private readonly defaultTtlBySource: Record<string, number> = {
    github: 3600,       // 1 hour
    gitlab: 3600,       // 1 hour
    pypi: 86400,        // 24 hours
    npm: 86400,         // 24 hours
    huggingface: 14400, // 4 hours
    dockerhub: 14400,   // 4 hours
    codeberg: 7200,     // 2 hours
    brave_search: 43200,// 12 hours
    web: 43200,         // 12 hours
  };

  /**
   * Records or updates observation telemetry for a given source locator.
   */
  recordObservation(entry: {
    source_locator: string;
    source_type: string;
    strategy_id?: string;
    change_token?: string;
    token_type?: ChangeTokenType;
    observed_at?: string;
    ttl_seconds?: number;
  }): FreshnessEvaluation {
    const observedAt = entry.observed_at || new Date().toISOString();
    const ttl = entry.ttl_seconds || this.defaultTtlBySource[entry.source_type.toLowerCase()] || 3600;

    const record: FreshnessRecord = {
      source_locator: entry.source_locator,
      source_type: entry.source_type.toLowerCase(),
      strategy_id: entry.strategy_id,
      last_observed_at: observedAt,
      change_token: entry.change_token,
      token_type: entry.token_type,
      ttl_seconds: ttl,
    };

    this.records.set(entry.source_locator, record);
    return this.evaluateLocator(entry.source_locator);
  }

  /**
   * Evaluates freshness status for a given locator based on elapsed time and TTL.
   */
  evaluateLocator(locator: string, nowMs: number = Date.now()): FreshnessEvaluation {
    const record = this.records.get(locator);
    if (!record) {
      return {
        source_locator: locator,
        source_type: 'unknown',
        status: 'UNKNOWN',
        last_observed_at: new Date(0).toISOString(),
        age_seconds: Number.MAX_SAFE_INTEGER,
        ttl_seconds: 3600,
        recommended_next_check: new Date().toISOString(),
      };
    }

    const observedMs = new Date(record.last_observed_at).getTime();
    const ageSeconds = Math.max(0, Math.floor((nowMs - observedMs) / 1000));
    const ttl = record.ttl_seconds;

    let status: FreshnessStatus = 'FRESH';
    if (ageSeconds >= ttl * 2) {
      status = 'EXPIRED';
    } else if (ageSeconds >= ttl) {
      status = 'STALE';
    }

    const nextCheckMs = observedMs + ttl * 1000;

    return {
      source_locator: record.source_locator,
      source_type: record.source_type,
      status,
      last_observed_at: record.last_observed_at,
      age_seconds: ageSeconds,
      ttl_seconds: ttl,
      change_token: record.change_token,
      token_type: record.token_type,
      recommended_next_check: new Date(nextCheckMs).toISOString(),
    };
  }

  /**
   * Retrieves all locators currently evaluated as STALE or EXPIRED for re-check scheduling.
   */
  getStaleLocators(nowMs: number = Date.now()): FreshnessEvaluation[] {
    const staleList: FreshnessEvaluation[] = [];
    for (const locator of this.records.keys()) {
      const evaluation = this.evaluateLocator(locator, nowMs);
      if (evaluation.status === 'STALE' || evaluation.status === 'EXPIRED') {
        staleList.push(evaluation);
      }
    }
    return staleList;
  }

  /**
   * Computes coverage and freshness metrics aggregated across time windows and sources.
   * Explicitly avoids claiming complete Internet coverage.
   */
  computeMetrics(window: '1h' | '24h' | '7d' | '30d' = '24h', nowMs: number = Date.now()): FreshnessMetrics {
    const windowSecondsMap = {
      '1h': 3600,
      '24h': 86400,
      '7d': 604800,
      '30d': 2592000,
    };
    const maxAgeSeconds = windowSecondsMap[window];

    let freshCount = 0;
    let staleCount = 0;
    let expiredCount = 0;
    let totalInWindow = 0;

    const bySource: Record<string, { total: number; fresh: number; stale: number; freshness_ratio: number }> = {};
    const byStrategy: Record<string, { total: number; fresh: number; stale: number }> = {};

    for (const record of this.records.values()) {
      const evalResult = this.evaluateLocator(record.source_locator, nowMs);
      if (evalResult.age_seconds > maxAgeSeconds) {
        continue;
      }

      totalInWindow++;
      if (evalResult.status === 'FRESH') freshCount++;
      else if (evalResult.status === 'STALE') staleCount++;
      else if (evalResult.status === 'EXPIRED') expiredCount++;

      // Source breakdown
      if (!bySource[record.source_type]) {
        bySource[record.source_type] = { total: 0, fresh: 0, stale: 0, freshness_ratio: 0 };
      }
      bySource[record.source_type].total++;
      if (evalResult.status === 'FRESH') bySource[record.source_type].fresh++;
      else bySource[record.source_type].stale++;

      // Strategy breakdown
      const stratKey = record.strategy_id || 'unassigned';
      if (!byStrategy[stratKey]) {
        byStrategy[stratKey] = { total: 0, fresh: 0, stale: 0 };
      }
      byStrategy[stratKey].total++;
      if (evalResult.status === 'FRESH') byStrategy[stratKey].fresh++;
      else byStrategy[stratKey].stale++;
    }

    // Compute ratios
    for (const s of Object.keys(bySource)) {
      const src = bySource[s];
      src.freshness_ratio = src.total > 0 ? Number((src.fresh / src.total).toFixed(3)) : 0;
    }

    const overallRatio = totalInWindow > 0 ? Number((freshCount / totalInWindow).toFixed(3)) : 1.0;

    return {
      window,
      total_observed: totalInWindow,
      fresh_count: freshCount,
      stale_count: staleCount,
      expired_count: expiredCount,
      freshness_ratio: overallRatio,
      by_source: bySource,
      by_strategy: byStrategy,
      sample_coverage_note: 'Bounded Public Discovery Sample — Never claim complete Internet coverage',
    };
  }
}
