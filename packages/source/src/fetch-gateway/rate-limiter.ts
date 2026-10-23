import { DomainRateLimitConfig } from './types.ts';
import { FetchGatewayError } from './errors.ts';

interface QueuedRequest {
  resolve: () => void;
  reject: (err: any) => void;
  timer: NodeJS.Timeout;
}

interface DomainBucket {
  tokens: number;
  capacity: number;
  tokensPerSecond: number;
  lastRefill: number;
  maxConcurrency: number;
  activeConcurrency: number;
  retryAfterUntil: number;
  backoffMultiplier: number;
  queue: QueuedRequest[];
}

export class DomainRateLimiter {
  private buckets = new Map<string, DomainBucket>();

  constructor(
    private readonly defaultConfig: DomainRateLimitConfig = {
      tokensPerSecond: 5,
      burstCapacity: 5,
      maxConcurrency: 2,
    },
    private readonly customConfigs: Record<string, Partial<DomainRateLimitConfig>> = {}
  ) {}

  /**
   * Acquires execution slot and token for a domain.
   * Suspends and queues if token bucket is empty or concurrency limit is reached.
   */
  async acquire(domain: string, waitTimeoutMs: number = 30000): Promise<void> {
    const bucket = this.getOrCreateBucket(domain);

    return new Promise<void>((resolve, reject) => {
      let isSettled = false;

      const timer = setTimeout(() => {
        if (!isSettled) {
          isSettled = true;
          // Remove from queue
          bucket.queue = bucket.queue.filter((q) => q.timer !== timer);
          reject(
            new FetchGatewayError(
              `Rate limiter acquisition timeout (${waitTimeoutMs}ms) exceeded for domain '${domain}'.`,
              'RATE_LIMIT_ACQUIRE_TIMEOUT',
              { domain, waitTimeoutMs }
            )
          );
        }
      }, waitTimeoutMs);

      const queued: QueuedRequest = {
        resolve: () => {
          if (!isSettled) {
            isSettled = true;
            clearTimeout(timer);
            resolve();
          }
        },
        reject: (err) => {
          if (!isSettled) {
            isSettled = true;
            clearTimeout(timer);
            reject(err);
          }
        },
        timer,
      };

      bucket.queue.push(queued);
      this.processQueue(bucket, domain);
    });
  }

  /**
   * Releases concurrency slot for the domain and schedules the next queued request.
   */
  release(domain: string): void {
    const bucket = this.buckets.get(domain);
    if (!bucket) return;

    bucket.activeConcurrency = Math.max(0, bucket.activeConcurrency - 1);
    this.processQueue(bucket, domain);
  }

  /**
   * Updates Retry-After penalty for a domain (e.g. upon receiving HTTP 429).
   */
  recordRetryAfter(domain: string, retryAfterVal: number | string): void {
    const bucket = this.getOrCreateBucket(domain);
    let delayMs = 60 * 1000; // default 60s

    if (typeof retryAfterVal === 'number') {
      delayMs = Math.max(1, retryAfterVal) * 1000;
    } else if (typeof retryAfterVal === 'string') {
      const parsedNum = parseInt(retryAfterVal, 10);
      if (!isNaN(parsedNum)) {
        delayMs = Math.max(1, parsedNum) * 1000;
      } else {
        const parsedDate = Date.parse(retryAfterVal);
        if (!isNaN(parsedDate)) {
          delayMs = Math.max(1000, parsedDate - Date.now());
        }
      }
    }

    const now = Date.now();
    bucket.retryAfterUntil = Math.max(bucket.retryAfterUntil, now + delayMs);
    bucket.tokens = 0; // Drain tokens
  }

  /**
   * Records consecutive failures to apply exponential backoff.
   */
  recordFailure(domain: string): void {
    const bucket = this.getOrCreateBucket(domain);
    bucket.backoffMultiplier = Math.min(16, bucket.backoffMultiplier * 2);
  }

  /**
   * Resets exponential backoff multiplier on success.
   */
  recordSuccess(domain: string): void {
    const bucket = this.getOrCreateBucket(domain);
    bucket.backoffMultiplier = 1;
  }

  /**
   * Inspects current status of a domain bucket.
   */
  getStatus(domain: string): {
    tokens: number;
    activeConcurrency: number;
    queueLength: number;
    retryAfterRemainingMs: number;
  } {
    const bucket = this.getOrCreateBucket(domain);
    this.refill(bucket);
    const now = Date.now();
    return {
      tokens: bucket.tokens,
      activeConcurrency: bucket.activeConcurrency,
      queueLength: bucket.queue.length,
      retryAfterRemainingMs: Math.max(0, bucket.retryAfterUntil - now),
    };
  }

  private processQueue(bucket: DomainBucket, domain: string): void {
    if (bucket.queue.length === 0) return;

    const now = Date.now();

    // Check if domain is in Retry-After blackout
    if (now < bucket.retryAfterUntil) {
      const waitMs = bucket.retryAfterUntil - now;
      setTimeout(() => this.processQueue(bucket, domain), waitMs);
      return;
    }

    // Check concurrency limit
    if (bucket.activeConcurrency >= bucket.maxConcurrency) {
      return;
    }

    // Refill tokens
    this.refill(bucket);

    // Check if a token is available
    if (bucket.tokens < 1) {
      // Calculate time until next token is available
      const needed = 1 - bucket.tokens;
      const waitMs = Math.ceil((needed / bucket.tokensPerSecond) * 1000);
      setTimeout(() => this.processQueue(bucket, domain), waitMs);
      return;
    }

    // Allocate token and concurrency slot
    bucket.tokens -= 1;
    bucket.activeConcurrency += 1;

    const next = bucket.queue.shift();
    if (next) {
      next.resolve();
    }
  }

  private refill(bucket: DomainBucket): void {
    const now = Date.now();
    const elapsedSeconds = (now - bucket.lastRefill) / 1000;
    if (elapsedSeconds > 0) {
      bucket.tokens = Math.min(bucket.capacity, bucket.tokens + elapsedSeconds * bucket.tokensPerSecond);
      bucket.lastRefill = now;
    }
  }

  private getOrCreateBucket(domain: string): DomainBucket {
    let bucket = this.buckets.get(domain);
    if (!bucket) {
      const custom = this.customConfigs[domain] || {};
      const capacity = custom.burstCapacity ?? this.defaultConfig.burstCapacity;
      const tokensPerSecond = custom.tokensPerSecond ?? this.defaultConfig.tokensPerSecond;
      const maxConcurrency = custom.maxConcurrency ?? this.defaultConfig.maxConcurrency;

      bucket = {
        tokens: capacity,
        capacity,
        tokensPerSecond,
        lastRefill: Date.now(),
        maxConcurrency,
        activeConcurrency: 0,
        retryAfterUntil: 0,
        backoffMultiplier: 1,
        queue: [],
      };
      this.buckets.set(domain, bucket);
    }
    return bucket;
  }
}
