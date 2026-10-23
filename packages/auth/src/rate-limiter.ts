/**
 * Real Multi-Tier Principal-Scoped Rate Limiter with Shared Distributed Backing Store
 * 
 * Provides distributed rate limiting for all /api/* routes, scoped per authenticated principal
 * (fallback to client IP if unauthenticated). Enforces strict limits on expensive compute/API routes
 * across multiple server processes sharing a backing store (PostgreSQL or Redis or SharedStore).
 */

import { Request, Response, NextFunction } from 'express';
import { PrincipalContext } from './types.ts';
import type { DatabaseClient } from '@caim/db';

export interface RateLimitConfig {
  windowMs: number; // Duration of window in milliseconds (e.g. 60,000 for 1 minute)
  maxRequests: number; // Maximum requests allowed within window
  tierName?: string; // Descriptive tier identifier
}

export interface RouteRateLimitRule {
  pathPattern: RegExp | string;
  methods?: string[]; // Optional method filter (e.g. ['POST'])
  config: RateLimitConfig;
  description: string;
}

export interface RateLimitBucket {
  count: number;
  resetAt: number; // Epoch ms when bucket resets
}

export interface RateLimitCheckResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number; // Unix timestamp in seconds
  retryAfterSeconds: number;
  tierName: string;
  description: string;
  callerKey: string;
}

export const RATE_LIMIT_TIERS = {
  // Expensive compute, external search, LLM RAG, and microVM sandbox routes
  COMPOSER_GENERATE: { windowMs: 60_000, maxRequests: 5, tierName: 'COMPOSER_GENERATE' },      // 5 req / min
  COMPOSER_EXECUTE: { windowMs: 60_000, maxRequests: 10, tierName: 'COMPOSER_EXECUTE' },       // 10 req / min
  ANALYSIS_TRIGGER: { windowMs: 60_000, maxRequests: 10, tierName: 'ANALYSIS_TRIGGER' },       // 10 req / min
  DISCOVERY_TRIGGER: { windowMs: 60_000, maxRequests: 10, tierName: 'DISCOVERY_TRIGGER' },     // 10 req / min
  RAG_CHAT: { windowMs: 60_000, maxRequests: 20, tierName: 'RAG_CHAT' },                       // 20 req / min

  // General standard API routes
  DEFAULT_API: { windowMs: 60_000, maxRequests: 120, tierName: 'DEFAULT_API' },                // 120 req / min
  AUTH_ENDPOINTS: { windowMs: 60_000, maxRequests: 30, tierName: 'AUTH_ENDPOINTS' },           // 30 req / min
} as const;

/**
 * Interface for pluggable distributed rate limiting stores.
 */
export interface IRateLimitStore {
  /**
   * Atomically increments the hit count for a key and returns the updated bucket.
   * If the window has expired or the key doesn't exist, a new window is initialized.
   */
  incrementAndGet(key: string, windowMs: number): Promise<RateLimitBucket>;

  /**
   * Retrieves the current bucket state without incrementing.
   */
  get(key: string): Promise<RateLimitBucket | null>;

  /**
   * Resets a specific key or all keys in the store.
   */
  reset(key?: string): Promise<void>;

  /**
   * Cleans up expired entries.
   */
  cleanupExpired?(): Promise<void>;

  /**
   * Returns statistics about stored buckets.
   */
  getStats?(): Promise<{ totalBuckets: number; activeTiers: Record<string, number> }>;
}

/**
 * Shared in-memory backing store for multi-instance simulation and testing.
 */
export class SharedInMemoryRateLimitStore implements IRateLimitStore {
  private buckets: Map<string, RateLimitBucket> = new Map();

  async incrementAndGet(key: string, windowMs: number): Promise<RateLimitBucket> {
    const now = Date.now();
    let bucket = this.buckets.get(key);

    if (!bucket || now >= bucket.resetAt) {
      bucket = {
        count: 1,
        resetAt: now + windowMs,
      };
      this.buckets.set(key, bucket);
      return { ...bucket };
    }

    bucket.count += 1;
    return { ...bucket };
  }

  async get(key: string): Promise<RateLimitBucket | null> {
    const bucket = this.buckets.get(key);
    if (!bucket) return null;
    return { ...bucket };
  }

  async reset(key?: string): Promise<void> {
    if (key) {
      this.buckets.delete(key);
    } else {
      this.buckets.clear();
    }
  }

  async cleanupExpired(): Promise<void> {
    const now = Date.now();
    for (const [k, v] of this.buckets.entries()) {
      if (now >= v.resetAt) {
        this.buckets.delete(k);
      }
    }
  }

  async getStats(): Promise<{ totalBuckets: number; activeTiers: Record<string, number> }> {
    const activeTiers: Record<string, number> = {};
    for (const key of this.buckets.keys()) {
      const parts = key.split(':');
      const tier = parts[parts.length - 1] || 'default';
      activeTiers[tier] = (activeTiers[tier] || 0) + 1;
    }
    return {
      totalBuckets: this.buckets.size,
      activeTiers,
    };
  }
}

/**
 * PostgreSQL Distributed Backing Store.
 * Uses atomic UPSERT with atomic window reset and conditional increment.
 * Guarantees cross-instance concurrency safety without external locks.
 */
export class PostgresRateLimitStore implements IRateLimitStore {
  private dbClient: DatabaseClient;
  private tableInitialized: boolean = false;

  constructor(dbClient: DatabaseClient) {
    this.dbClient = dbClient;
  }

  public async ensureSchema(): Promise<void> {
    if (this.tableInitialized) return;
    try {
      await this.dbClient.query(`
        CREATE TABLE IF NOT EXISTS security.rate_limit_buckets (
          bucket_key text PRIMARY KEY,
          count integer NOT NULL DEFAULT 1,
          reset_at bigint NOT NULL,
          updated_at timestamptz NOT NULL DEFAULT now()
        );
      `);
      this.tableInitialized = true;
    } catch {
      // If table already exists or schema is managed by migrations
      this.tableInitialized = true;
    }
  }

  async incrementAndGet(key: string, windowMs: number): Promise<RateLimitBucket> {
    await this.ensureSchema();
    const now = Date.now();
    const newResetAt = now + windowMs;

    const res = await this.dbClient.query(`
      INSERT INTO security.rate_limit_buckets (bucket_key, count, reset_at, updated_at)
      VALUES ($1, 1, $2, NOW())
      ON CONFLICT (bucket_key) DO UPDATE
      SET 
        count = CASE 
          WHEN security.rate_limit_buckets.reset_at <= $3 THEN 1 
          ELSE security.rate_limit_buckets.count + 1 
        END,
        reset_at = CASE 
          WHEN security.rate_limit_buckets.reset_at <= $3 THEN $2 
          ELSE security.rate_limit_buckets.reset_at 
        END,
        updated_at = NOW()
      RETURNING count, reset_at;
    `, [key, newResetAt, now]);

    const row = res.rows[0];
    return {
      count: parseInt(String(row.count ?? '0'), 10),
      resetAt: Number(row.reset_at ?? 0),
    };
  }

  async get(key: string): Promise<RateLimitBucket | null> {
    await this.ensureSchema();
    const res = await this.dbClient.query(`
      SELECT count, reset_at FROM security.rate_limit_buckets WHERE bucket_key = $1;
    `, [key]);

    if (!res.rows || res.rows.length === 0) return null;
    return {
      count: parseInt(String(res.rows[0].count ?? '0'), 10),
      resetAt: Number(res.rows[0].reset_at ?? 0),
    };
  }

  async reset(key?: string): Promise<void> {
    await this.ensureSchema();
    if (key) {
      await this.dbClient.query(`DELETE FROM security.rate_limit_buckets WHERE bucket_key = $1;`, [key]);
    } else {
      await this.dbClient.query(`DELETE FROM security.rate_limit_buckets;`);
    }
  }

  async cleanupExpired(): Promise<void> {
    await this.ensureSchema();
    const now = Date.now();
    await this.dbClient.query(`DELETE FROM security.rate_limit_buckets WHERE reset_at <= $1;`, [now]);
  }

  async getStats(): Promise<{ totalBuckets: number; activeTiers: Record<string, number> }> {
    await this.ensureSchema();
    const res = await this.dbClient.query(`SELECT bucket_key FROM security.rate_limit_buckets;`);
    const activeTiers: Record<string, number> = {};
    for (const row of res.rows || []) {
      const bucketKeyStr = typeof row.bucket_key === 'string' ? row.bucket_key : '';
      const parts = bucketKeyStr.split(':');
      const tier = parts[parts.length - 1] || 'default';
      activeTiers[tier] = (activeTiers[tier] || 0) + 1;
    }
    return {
      totalBuckets: (res.rows || []).length,
      activeTiers,
    };
  }
}

// Global default shared store fallback for standard server processes
const globalSharedStore = new SharedInMemoryRateLimitStore();

export interface RateLimiterOptions {
  store?: IRateLimitStore;
  dbClient?: DatabaseClient;
  rules?: RouteRateLimitRule[];
  defaultConfig?: RateLimitConfig;
}

export class RateLimiterEngine {
  private store: IRateLimitStore;
  private rules: RouteRateLimitRule[] = [];
  private defaultConfig: RateLimitConfig = RATE_LIMIT_TIERS.DEFAULT_API;

  constructor(
    rulesOrOptions?: RouteRateLimitRule[] | RateLimiterOptions,
    defaultConfig?: RateLimitConfig,
    explicitStore?: IRateLimitStore
  ) {
    if (Array.isArray(rulesOrOptions)) {
      this.rules = rulesOrOptions;
      if (defaultConfig) this.defaultConfig = defaultConfig;
      this.store = explicitStore || globalSharedStore;
    } else if (rulesOrOptions && typeof rulesOrOptions === 'object') {
      const opts = rulesOrOptions as RateLimiterOptions;
      if (opts.rules) this.rules = opts.rules;
      else this.initDefaultRules();
      if (opts.defaultConfig) this.defaultConfig = opts.defaultConfig;
      
      if (opts.store) {
        this.store = opts.store;
      } else if (opts.dbClient) {
        this.store = new PostgresRateLimitStore(opts.dbClient);
      } else {
        this.store = globalSharedStore;
      }
    } else {
      this.initDefaultRules();
      if (defaultConfig) this.defaultConfig = defaultConfig;
      this.store = explicitStore || globalSharedStore;
    }

    // Periodic cleanup of expired buckets every 5 minutes
    if (typeof setInterval !== 'undefined') {
      setInterval(() => {
        this.cleanupExpiredBuckets().catch(() => {});
      }, 5 * 60 * 1000).unref?.();
    }
  }

  private initDefaultRules() {
    this.rules = [
      {
        pathPattern: /^\/api\/composer\/generate/,
        methods: ['POST'],
        config: RATE_LIMIT_TIERS.COMPOSER_GENERATE,
        description: 'Composer Code Generation (LLM Synthesis & AST Verification)',
      },
      {
        pathPattern: /^\/api\/composer\/execute/,
        methods: ['POST'],
        config: RATE_LIMIT_TIERS.COMPOSER_EXECUTE,
        description: 'Composer MicroVM Isolated Execution & Canary Verification',
      },
      {
        pathPattern: /^\/api\/(analysis\/trigger|analysis\/runs|dev\/analysis\/trigger)/,
        methods: ['POST'],
        config: RATE_LIMIT_TIERS.ANALYSIS_TRIGGER,
        description: 'Analysis Trigger (Full AST, Taint Graph & Dynamic E2B Sandbox Verification)',
      },
      {
        pathPattern: /^\/api\/(discovery\/pipeline\/trigger|discovery\/run|dev\/discovery\/run)/,
        methods: ['POST'],
        config: RATE_LIMIT_TIERS.DISCOVERY_TRIGGER,
        description: 'Discovery Pipeline Scan (Web Crawling & Multi-Source Polymorphic Resolution)',
      },
      {
        pathPattern: /^\/api\/rag\/chat/,
        methods: ['POST'],
        config: RATE_LIMIT_TIERS.RAG_CHAT,
        description: 'Grounded RAG Chat Synthesis (Hybrid Fusion & Vector Retrieval)',
      },
      {
        pathPattern: /^\/api\/auth\/(login|register|refresh)/,
        methods: ['POST'],
        config: RATE_LIMIT_TIERS.AUTH_ENDPOINTS,
        description: 'Authentication & Credential Exchange',
      },
    ];
  }

  /**
   * Resolves the rate-limiting key for a given request.
   * Priority: Authenticated principal_id > Fallback Client IP
   */
  public resolveCallerKey(req: Request): { key: string; isPrincipal: boolean; principalId: string } {
    const reqWithPrincipal = req as Request & { principal?: PrincipalContext };
    const principal = reqWithPrincipal.principal;
    if (principal && principal.is_authenticated && principal.principal_id && principal.principal_id !== 'anonymous') {
      return {
        key: `principal:${principal.principal_id}`,
        isPrincipal: true,
        principalId: principal.principal_id,
      };
    }

    const ip = req.ip || req.socket?.remoteAddress || req.headers?.['x-forwarded-for'] || '127.0.0.1';
    const cleanIp = Array.isArray(ip) ? ip[0] : (typeof ip === 'string' ? ip.split(',')[0].trim() : '127.0.0.1');
    return {
      key: `ip:${cleanIp}`,
      isPrincipal: false,
      principalId: `anonymous-${cleanIp}`,
    };
  }

  /**
   * Finds matching route config rule or falls back to default.
   */
  public matchRule(path: string, method: string): { config: RateLimitConfig; description: string } {
    for (const rule of this.rules) {
      if (rule.methods && !rule.methods.includes(method.toUpperCase())) {
        continue;
      }
      if (typeof rule.pathPattern === 'string') {
        if (path.startsWith(rule.pathPattern)) {
          return { config: rule.config, description: rule.description };
        }
      } else if (rule.pathPattern.test(path)) {
        return { config: rule.config, description: rule.description };
      }
    }
    return { config: this.defaultConfig, description: 'Standard API Endpoint' };
  }

  /**
   * Evaluates request against rate limit using the shared backing store.
   */
  public async checkLimit(req: Request): Promise<RateLimitCheckResult> {
    const path = req.path || req.originalUrl || '/';
    const method = req.method || 'GET';
    const { key, principalId } = this.resolveCallerKey(req);
    const { config, description } = this.matchRule(path, method);

    const bucketKey = `${key}:${config.tierName || 'default'}`;
    const now = Date.now();

    const bucket = await this.store.incrementAndGet(bucketKey, config.windowMs);

    const allowed = bucket.count <= config.maxRequests;
    const remaining = Math.max(0, config.maxRequests - bucket.count);
    const resetAtSeconds = Math.ceil(bucket.resetAt / 1000);
    const retryAfterSeconds = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));

    return {
      allowed,
      limit: config.maxRequests,
      remaining,
      resetAt: resetAtSeconds,
      retryAfterSeconds,
      tierName: config.tierName || 'DEFAULT_API',
      description,
      callerKey: key,
    };
  }

  /**
   * Resets all buckets in the shared store.
   */
  public async resetAll(): Promise<void> {
    await this.store.reset();
  }

  /**
   * Cleans up expired buckets.
   */
  public async cleanupExpiredBuckets(): Promise<void> {
    if (this.store.cleanupExpired) {
      await this.store.cleanupExpired();
    }
  }

  /**
   * Returns current active bucket statistics.
   */
  public async getStats(): Promise<{ totalBuckets: number; activeTiers: Record<string, number> }> {
    if (this.store.getStats) {
      return await this.store.getStats();
    }
    return { totalBuckets: 0, activeTiers: {} };
  }

  /**
   * Exposes backing store reference for diagnostic inspection.
   */
  public getStore(): IRateLimitStore {
    return this.store;
  }
}

/**
 * Creates Express middleware enforcing rate limits on all /api/* routes via shared store.
 */
export function createRateLimiterMiddleware(engine: RateLimiterEngine) {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Only apply rate limiting to /api/* routes
    if (!req.path.startsWith('/api') && !req.originalUrl.startsWith('/api')) {
      return next();
    }

    // Health check and root diagnostic bypass to ensure container readiness probes never fail
    if (req.path === '/api/health' || req.path === '/api/config/public') {
      return next();
    }

    try {
      const check = await engine.checkLimit(req);

      // Set standard RFC rate-limiting headers
      res.setHeader('X-RateLimit-Limit', check.limit.toString());
      res.setHeader('X-RateLimit-Remaining', check.remaining.toString());
      res.setHeader('X-RateLimit-Reset', check.resetAt.toString());
      res.setHeader('X-RateLimit-Tier', check.tierName);

      if (!check.allowed) {
        res.setHeader('Retry-After', check.retryAfterSeconds.toString());
        return res.status(429).json({
          error: `Too Many Requests: Rate limit of ${check.limit} requests per minute exceeded for ${check.callerKey} on ${check.description}.`,
          code: 'RATE_LIMIT_EXCEEDED',
          tier: check.tierName,
          limit: check.limit,
          window_seconds: 60,
          retry_after_seconds: check.retryAfterSeconds,
        });
      }

      next();
    } catch (err: unknown) {
      // In fail-open resilience mode, log and proceed if store throws
      console.error('[RATE_LIMITER_ERROR] Failed to check rate limit:', err);
      next();
    }
  };
}
