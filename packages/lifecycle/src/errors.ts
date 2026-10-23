/**
 * Architecture V2.0.1 - Lifecycle State Engine Error Taxonomy
 */

export class LifecycleStateError extends Error {
  public readonly code: string;
  public readonly entityKind?: string;
  public readonly entityRefId?: string;

  constructor(message: string, code: string = 'ERR_LIFECYCLE_STATE', entityKind?: string, entityRefId?: string) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.entityKind = entityKind;
    this.entityRefId = entityRefId;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when attempting an illegal transition between states (e.g. jumping over required intermediate states).
 */
export class InvalidStateTransitionError extends LifecycleStateError {
  public readonly fromState: string | null;
  public readonly toState: string;
  public readonly allowedTransitions: string[];

  constructor(params: {
    entityKind: string;
    entityRefId: string;
    fromState: string | null;
    toState: string;
    allowedTransitions: string[];
    message?: string;
  }) {
    const allowed = params.allowedTransitions.length > 0
      ? params.allowedTransitions.join(', ')
      : 'NONE (Terminal state or uninitialized)';
    const msg = params.message || 
      `Invalid state transition for ${params.entityKind} [${params.entityRefId}]: cannot transition from '${params.fromState}' to '${params.toState}'. Legal target states from '${params.fromState}': [${allowed}].`;
    
    super(msg, 'ERR_INVALID_STATE_TRANSITION', params.entityKind, params.entityRefId);
    this.fromState = params.fromState;
    this.toState = params.toState;
    this.allowedTransitions = params.allowedTransitions;
  }
}

/**
 * Thrown when attempting to transition out of an immutable terminal state.
 */
export class TerminalStateError extends LifecycleStateError {
  public readonly terminalState: string;

  constructor(params: {
    entityKind: string;
    entityRefId: string;
    terminalState: string;
    attemptedToState: string;
  }) {
    const msg = `Terminal state violation for ${params.entityKind} [${params.entityRefId}]: entity is in terminal state '${params.terminalState}' and cannot transition to '${params.attemptedToState}'. Terminal states are immutable.`;
    super(msg, 'ERR_TERMINAL_STATE_IMMUTABLE', params.entityKind, params.entityRefId);
    this.terminalState = params.terminalState;
  }
}

/**
 * Thrown when a transition is blocked by a policy gate (e.g. unresolved critical risks, missing approvals).
 */
export class PolicyGateFailedError extends LifecycleStateError {
  public readonly gateKey: string;
  public readonly violations: string[];

  constructor(params: {
    entityKind: string;
    entityRefId: string;
    fromState: string | null;
    toState: string;
    gateKey: string;
    violations: string[];
    reason?: string;
  }) {
    const reasonText = params.reason ? `: ${params.reason}` : '';
    const violationsText = params.violations.length > 0 ? ` (Violations: ${params.violations.join('; ')})` : '';
    const msg = `Policy gate '${params.gateKey}' failed for ${params.entityKind} [${params.entityRefId}] transitioning '${params.fromState}' -> '${params.toState}'${reasonText}${violationsText}`;
    super(msg, 'ERR_POLICY_GATE_REJECTED', params.entityKind, params.entityRefId);
    this.gateKey = params.gateKey;
    this.violations = params.violations;
  }
}

/**
 * Thrown when a transition is attempted without providing a mandatory explanation/reason.
 */
export class MissingTransitionReasonError extends LifecycleStateError {
  constructor(params: {
    entityKind: string;
    entityRefId: string;
    fromState: string | null;
    toState: string;
  }) {
    const msg = `Missing transition reason for ${params.entityKind} [${params.entityRefId}]: transition '${params.fromState}' -> '${params.toState}' strictly requires a non-empty transition reason.`;
    super(msg, 'ERR_MISSING_TRANSITION_REASON', params.entityKind, params.entityRefId);
  }
}

/**
 * Thrown when projecting state history detects forking, non-linear sequences, or broken state continuity.
 */
export class StateProjectionIntegrityError extends LifecycleStateError {
  public readonly sequenceError: string;

  constructor(params: {
    entityKind: string;
    entityRefId: string;
    sequenceError: string;
    details?: Record<string, unknown>;
  }) {
    const msg = `State projection integrity violation for ${params.entityKind} [${params.entityRefId}]: ${params.sequenceError}`;
    super(msg, 'ERR_STATE_PROJECTION_CORRUPT', params.entityKind, params.entityRefId);
    this.sequenceError = params.sequenceError;
  }
}

/**
 * Thrown when an actor does not possess the authority/role to trigger a restricted lifecycle transition.
 */
export class UnauthorizedTransitionActorError extends LifecycleStateError {
  public readonly actorRef: string;
  public readonly requiredRoles: string[];

  constructor(params: {
    entityKind: string;
    entityRefId: string;
    actorRef: string;
    fromState: string | null;
    toState: string;
    requiredRoles: string[];
  }) {
    const msg = `Unauthorized transition actor '${params.actorRef}' for ${params.entityKind} [${params.entityRefId}]: transitioning '${params.fromState}' -> '${params.toState}' requires one of roles [${params.requiredRoles.join(', ')}].`;
    super(msg, 'ERR_UNAUTHORIZED_TRANSITION_ACTOR', params.entityKind, params.entityRefId);
    this.actorRef = params.actorRef;
    this.requiredRoles = params.requiredRoles;
  }
}

/**
 * Thrown when optimistic locking detects the current state in database does not match the expected fromState.
 */
export class StateTransitionConflictError extends LifecycleStateError {
  public readonly expectedFromState: string | null;
  public readonly actualCurrentState: string | null;

  constructor(params: {
    entityKind: string;
    entityRefId: string;
    expectedFromState: string | null;
    actualCurrentState: string | null;
  }) {
    const msg = `State transition conflict for ${params.entityKind} [${params.entityRefId}]: expected state '${params.expectedFromState}', but current state in database is '${params.actualCurrentState}'.`;
    super(msg, 'ERR_STATE_CONCURRENCY_CONFLICT', params.entityKind, params.entityRefId);
    this.expectedFromState = params.expectedFromState;
    this.actualCurrentState = params.actualCurrentState;
  }
}

/**
 * Thrown when an unknown entity kind or state name is passed to the registry.
 */
export class StateRegistryLookupError extends LifecycleStateError {
  constructor(message: string, entityKind?: string) {
    super(message, 'ERR_STATE_REGISTRY_LOOKUP', entityKind);
  }
}
