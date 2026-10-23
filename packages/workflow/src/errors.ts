import { ErrorClassification } from './types.ts';

export class JobExecutionError extends Error {
  readonly code: string;
  readonly classification: ErrorClassification;
  readonly retryable: boolean;
  readonly details?: unknown;

  constructor(
    message: string,
    options: {
      code?: string;
      classification?: ErrorClassification;
      retryable?: boolean;
      details?: unknown;
    } = {}
  ) {
    super(message);
    this.name = 'JobExecutionError';
    this.code = options.code || 'ERR_JOB_EXECUTION_FAILED';
    this.classification = options.classification || 'TRANSIENT';
    this.retryable = options.retryable ?? (this.classification === 'TRANSIENT' || this.classification === 'RATE_LIMITED');
    this.details = options.details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class TransientJobError extends JobExecutionError {
  constructor(message: string, code = 'ERR_TRANSIENT_FAILURE', details?: unknown) {
    super(message, { code, classification: 'TRANSIENT', retryable: true, details });
    this.name = 'TransientJobError';
  }
}

export class PermanentJobError extends JobExecutionError {
  constructor(message: string, code = 'ERR_PERMANENT_FAILURE', details?: unknown) {
    super(message, { code, classification: 'PERMANENT', retryable: false, details });
    this.name = 'PermanentJobError';
  }
}

export class PoisonPillJobError extends JobExecutionError {
  constructor(message: string, code = 'ERR_POISON_PILL_PAYLOAD', details?: unknown) {
    super(message, { code, classification: 'POISON_PILL', retryable: false, details });
    this.name = 'PoisonPillJobError';
  }
}

export class RateLimitedJobError extends JobExecutionError {
  readonly retryAfterMs?: number;

  constructor(message: string, retryAfterMs?: number, code = 'ERR_RATE_LIMITED', details?: unknown) {
    super(message, { code, classification: 'RATE_LIMITED', retryable: true, details });
    this.name = 'RateLimitedJobError';
    this.retryAfterMs = retryAfterMs;
  }
}

export class LeaseExpiredError extends JobExecutionError {
  constructor(message = 'Worker lease expired or was preempted by another node', details?: unknown) {
    super(message, { code: 'ERR_LEASE_EXPIRED', classification: 'PERMANENT', retryable: false, details });
    this.name = 'LeaseExpiredError';
  }
}

export class LeaseLostError extends JobExecutionError {
  constructor(message = 'Worker lost ownership of lease to competing worker', details?: unknown) {
    super(message, { code: 'ERR_LEASE_LOST', classification: 'PERMANENT', retryable: false, details });
    this.name = 'LeaseLostError';
  }
}

export class NotImplementedError extends JobExecutionError {
  constructor(workerOrFeatureName: string, details?: unknown) {
    super(`NOT_IMPLEMENTED: ${workerOrFeatureName} is not yet implemented (STUB).`, {
      code: 'ERR_NOT_IMPLEMENTED',
      classification: 'PERMANENT',
      retryable: false,
      details,
    });
    this.name = 'NotImplementedError';
  }
}

export class JobCancelledError extends JobExecutionError {
  constructor(message = 'Job execution was cancelled', details?: unknown) {
    super(message, { code: 'ERR_JOB_CANCELLED', classification: 'CANCELLED', retryable: false, details });
    this.name = 'JobCancelledError';
  }
}

export class WorkflowCancelledError extends JobExecutionError {
  constructor(message = 'Workflow execution was cancelled', details?: unknown) {
    super(message, { code: 'ERR_WORKFLOW_CANCELLED', classification: 'CANCELLED', retryable: false, details });
    this.name = 'WorkflowCancelledError';
  }
}

export class DependencyFailedError extends JobExecutionError {
  readonly failedDependencyStepKey: string;

  constructor(stepKey: string, message?: string) {
    super(message || `Upstream dependency step '${stepKey}' failed`, {
      code: 'ERR_DEPENDENCY_FAILED',
      classification: 'PERMANENT',
      retryable: false,
    });
    this.name = 'DependencyFailedError';
    this.failedDependencyStepKey = stepKey;
  }
}

export class IdempotencyConflictError extends JobExecutionError {
  constructor(message = 'Idempotency key conflict: identical key submitted with conflicting payload', details?: unknown) {
    super(message, { code: 'ERR_IDEMPOTENCY_CONFLICT', classification: 'PERMANENT', retryable: false, details });
    this.name = 'IdempotencyConflictError';
  }
}

export interface ClassifiedError {
  classification: ErrorClassification;
  failureCode: string;
  failureClass: string;
  retryable: boolean;
  message: string;
  details?: unknown;
}

export function classifyError(err: unknown): ClassifiedError {
  if (err instanceof JobExecutionError) {
    return {
      classification: err.classification,
      failureCode: err.code,
      failureClass: err.name,
      retryable: err.retryable,
      message: err.message,
      details: err.details,
    };
  }

  if (err instanceof Error) {
    const msg = err.message.toLowerCase();
    const name = err.name.toLowerCase();

    // Check for rate limits
    if (msg.includes('rate limit') || msg.includes('429') || msg.includes('too many requests')) {
      return {
        classification: 'RATE_LIMITED',
        failureCode: 'ERR_HTTP_429_RATE_LIMIT',
        failureClass: 'RateLimitError',
        retryable: true,
        message: err.message,
      };
    }

    // Check for poison pill / malformed schemas
    if (
      msg.includes('malformed') ||
      msg.includes('invalid json') ||
      msg.includes('zod error') ||
      msg.includes('schema violation') ||
      msg.includes('corrupted') ||
      msg.includes('poison')
    ) {
      return {
        classification: 'POISON_PILL',
        failureCode: 'ERR_POISON_PAYLOAD_UNRECOVERABLE',
        failureClass: 'PoisonPillError',
        retryable: false,
        message: err.message,
      };
    }

    // Check for transient network/DB errors
    if (
      msg.includes('econnrefused') ||
      msg.includes('econnreset') ||
      msg.includes('etimedout') ||
      msg.includes('socket hang up') ||
      msg.includes('deadlock detected') ||
      msg.includes('connection timeout') ||
      msg.includes('502') ||
      msg.includes('503') ||
      msg.includes('504') ||
      name.includes('timeout')
    ) {
      return {
        classification: 'TRANSIENT',
        failureCode: 'ERR_TRANSIENT_NETWORK_OR_DB',
        failureClass: 'TransientError',
        retryable: true,
        message: err.message,
      };
    }

    // Default Error is permanent
    return {
      classification: 'PERMANENT',
      failureCode: 'ERR_UNCLASSIFIED_RUNTIME_ERROR',
      failureClass: err.name || 'Error',
      retryable: false,
      message: err.message,
    };
  }

  return {
    classification: 'PERMANENT',
    failureCode: 'ERR_UNKNOWN_THROWN_VALUE',
    failureClass: 'UnknownError',
    retryable: false,
    message: String(err),
  };
}
