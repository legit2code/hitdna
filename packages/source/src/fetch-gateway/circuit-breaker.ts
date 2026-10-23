import { CircuitBreakerConfig, CircuitBreakerState } from './types.ts';
import { CircuitBreakerOpenError } from './errors.ts';

interface CircuitState {
  state: CircuitBreakerState;
  consecutiveFailures: number;
  lastFailureTime: number;
  openedAt: number;
  halfOpenProbeCount: number;
}

export class SourceCircuitBreaker {
  private circuits = new Map<string, CircuitState>();

  constructor(
    private readonly config: CircuitBreakerConfig = {
      failureThreshold: 5,
      cooldownMs: 30000,
      halfOpenMaxProbes: 1,
    }
  ) {}

  /**
   * Asserts whether a source/domain is available to accept requests.
   * Throws CircuitBreakerOpenError if the breaker is OPEN.
   */
  checkState(sourceKey: string): void {
    const circuit = this.getOrCreateCircuit(sourceKey);
    const now = Date.now();

    if (circuit.state === 'OPEN') {
      // Check if cooldown has elapsed
      if (now - circuit.openedAt >= this.config.cooldownMs) {
        circuit.state = 'HALF_OPEN';
        circuit.halfOpenProbeCount = 0;
      } else {
        const remainingSec = Math.ceil((circuit.openedAt + this.config.cooldownMs - now) / 1000);
        throw new CircuitBreakerOpenError(
          `Circuit breaker for source '${sourceKey}' is OPEN (cooling down for ${remainingSec}s).`,
          {
            sourceKey,
            state: 'OPEN',
            cooldownRemainingMs: circuit.openedAt + this.config.cooldownMs - now,
          }
        );
      }
    }

    if (circuit.state === 'HALF_OPEN') {
      if (circuit.halfOpenProbeCount >= this.config.halfOpenMaxProbes) {
        throw new CircuitBreakerOpenError(
          `Circuit breaker for source '${sourceKey}' is in HALF_OPEN state; probe request already in flight.`,
          { sourceKey, state: 'HALF_OPEN' }
        );
      }
      circuit.halfOpenProbeCount += 1;
    }
  }

  /**
   * Records successful response to reset failure count or close half-open circuit.
   */
  recordSuccess(sourceKey: string): void {
    const circuit = this.getOrCreateCircuit(sourceKey);
    circuit.consecutiveFailures = 0;
    circuit.state = 'CLOSED';
    circuit.halfOpenProbeCount = 0;
  }

  /**
   * Records failure to potentially trip breaker.
   */
  recordFailure(sourceKey: string, isRateLimitedOrServerDown: boolean = true): void {
    const circuit = this.getOrCreateCircuit(sourceKey);
    const now = Date.now();

    circuit.lastFailureTime = now;
    circuit.consecutiveFailures += 1;

    if (circuit.state === 'HALF_OPEN') {
      // Probe failed: trip back to OPEN immediately
      circuit.state = 'OPEN';
      circuit.openedAt = now;
    } else if (circuit.consecutiveFailures >= this.config.failureThreshold || isRateLimitedOrServerDown) {
      if (circuit.consecutiveFailures >= this.config.failureThreshold) {
        circuit.state = 'OPEN';
        circuit.openedAt = now;
      }
    }
  }

  /**
   * Manually trips breaker (e.g. on severe upstream outage or rate-limit exhaustion).
   */
  trip(sourceKey: string, cooldownMs?: number): void {
    const circuit = this.getOrCreateCircuit(sourceKey);
    circuit.state = 'OPEN';
    circuit.openedAt = Date.now();
    if (cooldownMs) {
      // Temporarily override openedAt if custom cooldown requested
      circuit.openedAt = Date.now() + cooldownMs - this.config.cooldownMs;
    }
  }

  getState(sourceKey: string): CircuitBreakerState {
    const circuit = this.getOrCreateCircuit(sourceKey);
    const now = Date.now();
    if (circuit.state === 'OPEN' && now - circuit.openedAt >= this.config.cooldownMs) {
      return 'HALF_OPEN';
    }
    return circuit.state;
  }

  private getOrCreateCircuit(sourceKey: string): CircuitState {
    let circuit = this.circuits.get(sourceKey);
    if (!circuit) {
      circuit = {
        state: 'CLOSED',
        consecutiveFailures: 0,
        lastFailureTime: 0,
        openedAt: 0,
        halfOpenProbeCount: 0,
      };
      this.circuits.set(sourceKey, circuit);
    }
    return circuit;
  }
}
