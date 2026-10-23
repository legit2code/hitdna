import { ConflictError } from './errors.ts';

export interface IdempotencyRecord {
  key: string;
  scope?: string;
  status: 'IN_FLIGHT' | 'COMPLETED' | 'FAILED';
  statusCode: number;
  responseBody: unknown;
  createdAt: number;
  completedAt?: number;
  expiresAt: number;
}

export class IdempotencyManager {
  private static instance: IdempotencyManager;
  private readonly store = new Map<string, IdempotencyRecord>();
  private readonly defaultTtlMs: number;

  constructor(defaultTtlMs: number = 24 * 60 * 60 * 1000) {
    this.defaultTtlMs = defaultTtlMs;
  }

  public static getInstance(): IdempotencyManager {
    if (!IdempotencyManager.instance) {
      IdempotencyManager.instance = new IdempotencyManager();
    }
    return IdempotencyManager.instance;
  }

  private formatKey(key: string, scope?: string): string {
    return scope ? `${scope}:${key}` : key;
  }

  /**
   * Acquire an idempotency key.
   * If in flight -> throws ConflictError (409)
   * If already completed -> returns cached record for replay
   * If not exists -> registers as IN_FLIGHT and returns null (proceed with execution)
   */
  public acquire(key: string, scope?: string, ttlMs?: number): IdempotencyRecord | null {
    this.cleanupExpired();
    const compoundKey = this.formatKey(key, scope);
    const existing = this.store.get(compoundKey);

    if (existing) {
      if (existing.status === 'IN_FLIGHT') {
        throw new ConflictError(`Concurrent operation in progress for Idempotency-Key '${key}'`, {
          idempotency_key: key,
          scope,
          retryable_after_ms: 1000,
        });
      }
      if (existing.status === 'COMPLETED') {
        return existing;
      }
    }

    const now = Date.now();
    const record: IdempotencyRecord = {
      key,
      scope,
      status: 'IN_FLIGHT',
      statusCode: 200,
      responseBody: null,
      createdAt: now,
      expiresAt: now + (ttlMs || this.defaultTtlMs),
    };
    this.store.set(compoundKey, record);
    return null;
  }

  /**
   * Complete the idempotency key with status code and response payload
   */
  public complete(key: string, statusCode: number, responseBody: unknown, scope?: string): void {
    const compoundKey = this.formatKey(key, scope);
    const existing = this.store.get(compoundKey);
    if (existing) {
      existing.status = 'COMPLETED';
      existing.statusCode = statusCode;
      existing.responseBody = responseBody;
      existing.completedAt = Date.now();
    }
  }

  /**
   * Release or fail the key if execution failed unexpectedly so it can be retried
   */
  public fail(key: string, scope?: string): void {
    const compoundKey = this.formatKey(key, scope);
    this.store.delete(compoundKey);
  }

  /**
   * Clear all records (useful for testing)
   */
  public clear(): void {
    this.store.clear();
  }

  public getRecord(key: string, scope?: string): IdempotencyRecord | undefined {
    return this.store.get(this.formatKey(key, scope));
  }

  private cleanupExpired(): void {
    const now = Date.now();
    for (const [k, v] of this.store.entries()) {
      if (v.expiresAt <= now) {
        this.store.delete(k);
      }
    }
  }
}
