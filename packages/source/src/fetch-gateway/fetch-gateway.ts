import crypto from 'crypto';
import { Agent, fetch as undiciFetch } from 'undici';
import { HttpFetcher, HttpResponse } from '../types.ts';
import {
  AuditLogEntry,
  FetchGatewayConfig,
  GatewayRequestOptions,
} from './types.ts';
import {
  FetchGatewayError,
  RedirectLimitExceededError,
  ResponseSizeExceededError,
  SsrfBlockedError,
  RobotsDisallowedError,
} from './errors.ts';
import { ResolvedTarget, SsrfFilter } from './ssrf-filter.ts';
import { RobotsPolicyEnforcer } from './robots-checker.ts';
import { DomainRateLimiter } from './rate-limiter.ts';
import { SourceCircuitBreaker } from './circuit-breaker.ts';
import { ContentSafetyValidator } from './content-safety.ts';
import { SafeRepositoryAcquisition } from './safe-repository.ts';

export class FetchGateway {
  private static instance?: FetchGateway;

  private readonly config: FetchGatewayConfig;
  private readonly ssrfFilter: SsrfFilter;
  private readonly robotsEnforcer: RobotsPolicyEnforcer;
  private readonly rateLimiter: DomainRateLimiter;
  private readonly circuitBreaker: SourceCircuitBreaker;
  private readonly contentSafety: ContentSafetyValidator;
  private readonly auditLogs: AuditLogEntry[] = [];
  private readonly customTransport?: HttpFetcher;

  constructor(options: {
    config?: Partial<FetchGatewayConfig>;
    ssrfFilter?: SsrfFilter;
    robotsEnforcer?: RobotsPolicyEnforcer;
    rateLimiter?: DomainRateLimiter;
    circuitBreaker?: SourceCircuitBreaker;
    transport?: HttpFetcher;
  } = {}) {
    this.config = {
      maxRedirects: options.config?.maxRedirects ?? 5,
      defaultTimeoutMs: options.config?.defaultTimeoutMs ?? 20000,
      maxResponseBytes: options.config?.maxResponseBytes ?? 10 * 1024 * 1024,
      allowedProtocols: options.config?.allowedProtocols ?? ['http:', 'https:'],
      safetyLimits: {
        maxResponseBytes: 10 * 1024 * 1024,
        maxArchiveBytes: 50 * 1024 * 1024,
        maxExpandedBytes: 100 * 1024 * 1024,
        maxDecompressionRatio: 100,
        maxFileCount: 5000,
        maxNestedArchiveDepth: 2,
        timeoutMs: 30000,
        ...options.config?.safetyLimits,
      },
      circuitBreaker: {
        failureThreshold: 5,
        cooldownMs: 30000,
        halfOpenMaxProbes: 1,
        ...options.config?.circuitBreaker,
      },
      defaultRateLimit: {
        tokensPerSecond: 5,
        burstCapacity: 5,
        maxConcurrency: 2,
        ...options.config?.defaultRateLimit,
      },
      domainRateLimits: options.config?.domainRateLimits ?? {},
    };

    this.ssrfFilter = options.ssrfFilter ?? new SsrfFilter();
    this.robotsEnforcer = options.robotsEnforcer ?? new RobotsPolicyEnforcer('caim-bot', async (robotsUrl: string) => {
      try {
        const resolvedRobots = await this.ssrfFilter.validate(robotsUrl);
        const res = await this.executeTransport(
          robotsUrl,
          {
            method: 'GET',
            headers: { 'User-Agent': 'caim-bot' },
            timeoutMs: 5000,
          },
          resolvedRobots
        );
        return typeof res.data === 'string' ? res.data : null;
      } catch {
        return null;
      }
    });
    this.rateLimiter = options.rateLimiter ?? new DomainRateLimiter(this.config.defaultRateLimit, this.config.domainRateLimits);
    this.circuitBreaker = options.circuitBreaker ?? new SourceCircuitBreaker(this.config.circuitBreaker);
    this.contentSafety = new ContentSafetyValidator(this.config.maxResponseBytes);
    this.customTransport = options.transport;
  }

  /**
   * Singleton accessor for centralized gateway.
   */
  static getInstance(): FetchGateway {
    if (!FetchGateway.instance) {
      FetchGateway.instance = new FetchGateway();
    }
    return FetchGateway.instance;
  }

  static setInstance(gateway: FetchGateway): void {
    FetchGateway.instance = gateway;
  }

  /**
   * Primary entrypoint: fetches a URL while enforcing all security controls:
   * 1. SSRF prevention on initial URL and DNS resolution
   * 2. Source circuit breaker check
   * 3. Robots.txt policy evaluation
   * 4. Per-domain token bucket rate limiting and concurrency throttling
   * 5. Network transport execution with timeout
   * 6. Hop-by-hop redirect following with full SSRF re-validation and credential stripping
   * 7. Response size & content-type validation
   * 8. Retry-After & backoff handling
   * 9. Audit logging
   */
  async request(url: string, options: GatewayRequestOptions = {}): Promise<HttpResponse> {
    const startTime = Date.now();
    const method = options.method?.toUpperCase() || 'GET';
    let currentUrl = url;
    let redirectCount = 0;
    let headers = { ...(options.headers || {}) };
    let finalTarget: ResolvedTarget | null = null;
    let lastStatus: number | undefined;
    let bytesReceived = 0;

    // Helper to log audit
    const recordLog = (
      outcome: AuditLogEntry['outcome'],
      status?: number,
      details?: string
    ) => {
      this.auditLogs.push({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        method,
        url,
        domain: finalTarget?.parsedUrl.hostname || new URL(url).hostname,
        resolvedIp: finalTarget?.resolvedIps[0],
        statusCode: status,
        durationMs: Date.now() - startTime,
        bytesReceived,
        outcome,
        details,
      });
    };

    try {
      while (true) {
        // --- STEP 1: SSRF Validation on Current URL ---
        let resolvedTarget: ResolvedTarget;
        try {
          resolvedTarget = await this.ssrfFilter.validate(currentUrl);
          finalTarget = resolvedTarget;
        } catch (ssrfErr: any) {
          recordLog('SSRF_BLOCKED', undefined, ssrfErr.message);
          throw ssrfErr;
        }

        const domain = resolvedTarget.hostname;
        const sourceKey = options.sourceType || domain;

        // --- STEP 2: Circuit Breaker Check ---
        try {
          this.circuitBreaker.checkState(sourceKey);
        } catch (cbErr: any) {
          recordLog('CIRCUIT_OPEN', undefined, cbErr.message);
          throw cbErr;
        }

        // --- STEP 3: Robots.txt Policy Enforcement ---
        if (!options.skipRobots) {
          try {
            await this.robotsEnforcer.checkAllowed(currentUrl);
          } catch (robotsErr: any) {
            recordLog('ROBOTS_DISALLOWED', undefined, robotsErr.message);
            throw robotsErr;
          }
        }

        // --- STEP 4: Centralized Rate Limiter & Domain Concurrency Acquisition ---
        if (!options.bypassRateLimit) {
          try {
            await this.rateLimiter.acquire(domain, options.timeoutMs || this.config.defaultTimeoutMs);
          } catch (rateErr: any) {
            recordLog('RATE_LIMITED', undefined, rateErr.message);
            throw rateErr;
          }
        }

        // --- STEP 5: Safe Network Fetch Execution ---
        let response: HttpResponse;
        try {
          response = await this.executeTransport(
            currentUrl,
            {
              ...options,
              method,
              headers,
            },
            resolvedTarget
          );
        } catch (transportErr: any) {
          this.rateLimiter.recordFailure(domain);
          this.circuitBreaker.recordFailure(sourceKey, true);
          if (transportErr instanceof ResponseSizeExceededError) {
            recordLog('SIZE_EXCEEDED', undefined, transportErr.message);
          } else {
            recordLog('ERROR', undefined, transportErr.message);
          }
          throw transportErr;
        } finally {
          if (!options.bypassRateLimit) {
            this.rateLimiter.release(domain);
          }
        }

        lastStatus = response.status;

        // --- STEP 6: Handle Redirects with Hop-by-Hop Re-validation ---
        if ([301, 302, 303, 307, 308].includes(response.status)) {
          const locationHeader = response.headers['location'] || response.headers['Location'];
          if (!locationHeader) {
            // No location header; return as-is
            break;
          }

          redirectCount += 1;
          if (redirectCount > this.config.maxRedirects) {
            const err = new RedirectLimitExceededError(
              `Exceeded maximum allowed redirect hops (${this.config.maxRedirects}) while fetching '${url}'.`,
              { url, redirectCount, maxRedirects: this.config.maxRedirects }
            );
            recordLog('REDIRECT_BLOCKED', response.status, err.message);
            throw err;
          }

          // Resolve relative redirect URL
          const nextUrl = new URL(locationHeader, currentUrl).toString();

          // Strip credentials on cross-domain redirect (Part D requirement)
          headers = SafeRepositoryAcquisition.sanitizeHeadersForRedirect(headers, currentUrl, nextUrl);

          // Loop will re-validate SSRF, robots, and rate limits on the next hop!
          currentUrl = nextUrl;
          continue;
        }

        // --- STEP 7: Content & Response Size Safety Validation ---
        this.contentSafety.validateHeaders(response.headers, options.maxResponseBytes);

        if (typeof response.data === 'string') {
          bytesReceived = Buffer.byteLength(response.data, 'utf8');
        } else if (Buffer.isBuffer(response.data)) {
          bytesReceived = response.data.length;
        } else if (response.data && typeof response.data === 'object') {
          bytesReceived = Buffer.byteLength(JSON.stringify(response.data), 'utf8');
        }

        this.contentSafety.validateReceivedBytes(bytesReceived, options.maxResponseBytes);

        // --- STEP 8: Upstream Status & Retry-After Recording ---
        if (response.status === 429) {
          const retryAfter = response.headers['retry-after'] || response.headers['Retry-After'];
          this.rateLimiter.recordRetryAfter(domain, retryAfter || 60);
          this.circuitBreaker.recordFailure(sourceKey, true);
        } else if (response.status >= 500) {
          this.rateLimiter.recordFailure(domain);
          this.circuitBreaker.recordFailure(sourceKey, true);
        } else {
          this.rateLimiter.recordSuccess(domain);
          this.circuitBreaker.recordSuccess(sourceKey);
        }

        recordLog('SUCCESS', response.status);
        return response;
      }

      throw new FetchGatewayError(`Unexpected loop termination for '${url}'`, 'UNEXPECTED_ERROR');
    } catch (err: any) {
      if (!(err instanceof FetchGatewayError)) {
        recordLog('ERROR', lastStatus, err.message);
      }
      throw err;
    }
  }

  /**
   * Adapts the FetchGateway into the standard HttpFetcher signature required by BaseSourceAdapter.
   */
  createFetcher(): HttpFetcher {
    return (url: string, options?: {
      method?: string;
      headers?: Record<string, string>;
      body?: string;
      timeoutMs?: number;
      sourceType?: string;
    }): Promise<HttpResponse> => {
      return this.request(url, options);
    };
  }

  getAuditLogs(): AuditLogEntry[] {
    return [...this.auditLogs];
  }

  clearAuditLogs(): void {
    this.auditLogs.length = 0;
  }

  getSsrfFilter(): SsrfFilter {
    return this.ssrfFilter;
  }

  getRobotsEnforcer(): RobotsPolicyEnforcer {
    return this.robotsEnforcer;
  }

  getRateLimiter(): DomainRateLimiter {
    return this.rateLimiter;
  }

  getCircuitBreaker(): SourceCircuitBreaker {
    return this.circuitBreaker;
  }

  /**
   * Dispatches the underlying HTTP request using custom transport if supplied,
   * or undici fetch with pinned Agent connect.lookup and streaming body size limits.
   */
  private async executeTransport(
    targetUrl: string,
    options: GatewayRequestOptions,
    resolvedTarget?: ResolvedTarget | null
  ): Promise<HttpResponse> {
    if (this.customTransport) {
      return this.customTransport(targetUrl, {
        ...options,
        pinnedTarget: resolvedTarget ?? options.pinnedTarget,
      });
    }

    const controller = new AbortController();
    const timeoutMs = options.timeoutMs ?? this.config.defaultTimeoutMs;
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let dispatcher: Agent | undefined;
    if (resolvedTarget && resolvedTarget.resolvedIps && resolvedTarget.resolvedIps.length > 0) {
      const targetIps = resolvedTarget.resolvedIps;
      dispatcher = new Agent({
        connect: {
          lookup: (hostname, lookupOpts, cb) => {
            const records = targetIps.map((ip) => ({
              address: ip,
              family: ip.includes(':') ? (6 as const) : (4 as const),
            }));
            if (lookupOpts && (lookupOpts as any).all) {
              cb(null, records as any);
            } else {
              const first = records[0];
              cb(null, first.address, first.family);
            }
          },
        },
      });
    }

    try {
      const maxBytes = options.maxResponseBytes ?? this.config.maxResponseBytes;

      const res = await undiciFetch(targetUrl, {
        method: options.method || 'GET',
        headers: options.headers,
        body: options.body,
        signal: controller.signal,
        redirect: 'manual', // Strictly manual to intercept every hop
        dispatcher,
      });

      const responseHeaders: Record<string, string> = {};
      res.headers.forEach((value, key) => {
        responseHeaders[key.toLowerCase()] = value;
      });

      // Upfront Content-Length verification before consuming body
      const contentLengthHeader = responseHeaders['content-length'];
      if (contentLengthHeader) {
        const length = parseInt(contentLengthHeader, 10);
        if (!isNaN(length) && length > maxBytes) {
          controller.abort();
          throw new ResponseSizeExceededError(
            `Response Content-Length (${length} bytes) exceeds maximum permitted limit (${maxBytes} bytes).`,
            { declaredBytes: length, limitBytes: maxBytes }
          );
        }
      }

      // If redirect, do not consume body
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        return {
          status: res.status,
          statusText: res.statusText,
          headers: responseHeaders,
          data: null,
        };
      }

      // Stream the body with a running byte counter
      const chunks: Uint8Array[] = [];
      let bytesRead = 0;
      if (res.body) {
        const reader = res.body.getReader();
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value) {
              bytesRead += value.byteLength;
              if (bytesRead > maxBytes) {
                controller.abort();
                throw new ResponseSizeExceededError(
                  `Response body size (${bytesRead} bytes) exceeded maximum permitted limit (${maxBytes} bytes).`,
                  { bytesRead, limitBytes: maxBytes }
                );
              }
              chunks.push(value);
            }
          }
        } catch (err: any) {
          if (err instanceof ResponseSizeExceededError) {
            throw err;
          }
          if (controller.signal.aborted) {
            throw new FetchGatewayError(`Request timed out after ${timeoutMs}ms while reading response body`, 'TIMEOUT', { timeoutMs });
          }
          throw err;
        }
      }

      const bodyBuffer = Buffer.concat(chunks);
      const contentType = responseHeaders['content-type'] || '';
      let data: any;

      if (contentType.includes('application/json')) {
        const text = bodyBuffer.toString('utf8');
        try {
          data = JSON.parse(text);
        } catch {
          data = text;
        }
      } else {
        data = bodyBuffer.toString('utf8');
      }

      return {
        status: res.status,
        statusText: res.statusText,
        headers: responseHeaders,
        data,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * Convenient module-level function to retrieve the default shared gateway.
 */
export function getDefaultFetchGateway(): FetchGateway {
  return FetchGateway.getInstance();
}
