import { RetryPolicy } from './types.ts';
import { classifyError } from './errors.ts';

export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 5,
  initialDelayMs: 1000,
  maxDelayMs: 60000,
  multiplier: 2,
  enableJitter: true,
  retryableErrorClasses: ['TransientJobError', 'RateLimitedJobError', 'TransientError', 'RateLimitError'],
  nonRetryableErrorCodes: [
    'ERR_POISON_PILL_PAYLOAD',
    'ERR_POISON_PAYLOAD_UNRECOVERABLE',
    'ERR_JOB_CANCELLED',
    'ERR_WORKFLOW_CANCELLED',
    'ERR_LEASE_EXPIRED',
    'ERR_LEASE_LOST',
    'ERR_IDEMPOTENCY_CONFLICT',
    'ERR_NOT_IMPLEMENTED',
  ],
};

export function calculateBackoffMs(
  attemptNo: number,
  policyOverrides?: Partial<RetryPolicy>
): number {
  const policy = { ...DEFAULT_RETRY_POLICY, ...policyOverrides };
  const effectiveAttempt = Math.max(1, attemptNo);

  // Exponential backoff: initialDelay * multiplier^(attempt - 1)
  const baseDelay = policy.initialDelayMs * Math.pow(policy.multiplier, effectiveAttempt - 1);
  const cappedDelay = Math.min(baseDelay, policy.maxDelayMs);

  if (!policy.enableJitter) {
    return Math.round(cappedDelay);
  }

  // Full jitter: uniformly random between 0.5 * delay and 1.5 * delay
  const jitterMin = 0.5 * cappedDelay;
  const jitterMax = 1.5 * cappedDelay;
  const jittered = jitterMin + Math.random() * (jitterMax - jitterMin);

  return Math.round(Math.min(jittered, policy.maxDelayMs));
}

export function shouldRetry(
  attemptNo: number,
  error: unknown,
  policyOverrides?: Partial<RetryPolicy>
): { retry: boolean; delayMs: number; reason: string } {
  const policy = { ...DEFAULT_RETRY_POLICY, ...policyOverrides };

  if (attemptNo >= policy.maxAttempts) {
    return {
      retry: false,
      delayMs: 0,
      reason: `Exhausted maximum retry attempts (${attemptNo}/${policy.maxAttempts})`,
    };
  }

  const classified = classifyError(error);

  if (policy.nonRetryableErrorCodes?.includes(classified.failureCode)) {
    return {
      retry: false,
      delayMs: 0,
      reason: `Error code '${classified.failureCode}' is explicitly non-retryable`,
    };
  }

  if (classified.classification === 'POISON_PILL' || classified.classification === 'CANCELLED' || classified.classification === 'PERMANENT') {
    return {
      retry: false,
      delayMs: 0,
      reason: `Error classification '${classified.classification}' is non-retryable`,
    };
  }

  if (classified.retryable || classified.classification === 'TRANSIENT' || classified.classification === 'RATE_LIMITED') {
    const delayMs = calculateBackoffMs(attemptNo, policy);
    return {
      retry: true,
      delayMs,
      reason: `Transient failure; retry attempt ${attemptNo + 1} scheduled with ${delayMs}ms backoff`,
    };
  }

  return {
    retry: false,
    delayMs: 0,
    reason: `Unclassified non-transient failure: ${classified.message}`,
  };
}

export function computeNextAttemptDate(
  attemptNo: number,
  policyOverrides?: Partial<RetryPolicy>
): Date {
  const delayMs = calculateBackoffMs(attemptNo, policyOverrides);
  return new Date(Date.now() + delayMs);
}
