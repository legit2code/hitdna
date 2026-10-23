export class FetchGatewayError extends Error {
  constructor(message: string, public readonly code: string, public readonly details?: Record<string, any>) {
    super(message);
    this.name = this.constructor.name;
  }
}

export class SsrfBlockedError extends FetchGatewayError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'SSRF_BLOCKED', details);
  }
}

export class RobotsDisallowedError extends FetchGatewayError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'ROBOTS_DISALLOWED', details);
  }
}

export class CircuitBreakerOpenError extends FetchGatewayError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'CIRCUIT_BREAKER_OPEN', details);
  }
}

export class ResponseSizeExceededError extends FetchGatewayError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'RESPONSE_SIZE_EXCEEDED', details);
  }
}

export class ContentTypeBlockedError extends FetchGatewayError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'CONTENT_TYPE_BLOCKED', details);
  }
}

export class RedirectLimitExceededError extends FetchGatewayError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'REDIRECT_LIMIT_EXCEEDED', details);
  }
}

export class ArchiveSafetyError extends FetchGatewayError {
  constructor(message: string, code: string = 'ARCHIVE_SAFETY_VIOLATION', details?: Record<string, any>) {
    super(message, code, details);
  }
}

export class ArchiveBombError extends ArchiveSafetyError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'ARCHIVE_BOMB_DETECTED', details);
  }
}

export class ArchiveTraversalError extends ArchiveSafetyError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'ARCHIVE_PATH_TRAVERSAL', details);
  }
}

export class ArchiveSymlinkEscapeError extends ArchiveSafetyError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'ARCHIVE_SYMLINK_ESCAPE', details);
  }
}
