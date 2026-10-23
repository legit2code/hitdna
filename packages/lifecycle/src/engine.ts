import {
  LifecycleEntityKind,
  STATE_MACHINE_VERSION,
  getEntityCatalog,
  getStateDescriptor,
  isTerminalState,
} from './registry.ts';
import {
  TransitionRule,
  findMatchingRule,
  getAllowedTargetStates,
  getTransitionRules,
} from './rules.ts';
import {
  PolicyGateContext,
  PolicyGateRegistry,
  GateCheckResult,
} from './gates.ts';
import {
  InvalidStateTransitionError,
  TerminalStateError,
  PolicyGateFailedError,
  MissingTransitionReasonError,
  UnauthorizedTransitionActorError,
} from './errors.ts';

export interface TransitionRequest {
  readonly entityRefId: string;
  readonly entityKind: LifecycleEntityKind;
  readonly fromState: string | null;
  readonly toState: string;
  readonly action?: string;
  readonly transitionReason?: string;
  readonly actorRef: string;
  readonly correlationId: string;
  readonly causationId?: string;
  readonly actorRoles?: string[];
  readonly gateContext?: Partial<PolicyGateContext>;
}

export interface TransitionValidationSuccess {
  readonly valid: true;
  readonly rule: TransitionRule;
  readonly stateMachineVersion: string;
  readonly gateResult?: GateCheckResult;
}

export interface TransitionValidationFailure {
  readonly valid: false;
  readonly error: Error;
}

export type TransitionValidationResult = TransitionValidationSuccess | TransitionValidationFailure;

export class LifecycleStateEngine {
  public static readonly VERSION = STATE_MACHINE_VERSION;

  /**
   * Validates whether a state transition is legally permissible without throwing errors.
   */
  public static async validate(request: TransitionRequest): Promise<TransitionValidationResult> {
    try {
      const result = await this.assertLegalTransition(request);
      return {
        valid: true,
        rule: result.rule,
        stateMachineVersion: STATE_MACHINE_VERSION,
        gateResult: result.gateResult,
      };
    } catch (err) {
      return {
        valid: false,
        error: err instanceof Error ? err : new Error(String(err)),
      };
    }
  }

  /**
   * Asserts that a state transition is legal, policy-compliant, and authorized.
   * Throws typed domain errors on any violation.
   */
  public static async assertLegalTransition(request: TransitionRequest): Promise<{
    rule: TransitionRule;
    gateResult?: GateCheckResult;
  }> {
    const { entityRefId, entityKind, fromState, toState, action, transitionReason, actorRef, correlationId, actorRoles } = request;

    // 1. Verify Entity Kind Catalog
    const catalog = getEntityCatalog(entityKind);

    // 2. Verify Target State exists
    getStateDescriptor(entityKind, toState);

    // 3. Verify From State exists (if not genesis)
    if (fromState !== null) {
      getStateDescriptor(entityKind, fromState);

      // Check if fromState is an immutable terminal state
      if (catalog.terminalStates.has(fromState)) {
        throw new TerminalStateError({
          entityKind,
          entityRefId,
          terminalState: fromState,
          attemptedToState: toState,
        });
      }
    }

    // 4. Find Matching Rule in Transition Graph
    const rule = findMatchingRule(entityKind, fromState, toState, action);
    if (!rule) {
      const allowedTransitions = getAllowedTargetStates(entityKind, fromState);
      throw new InvalidStateTransitionError({
        entityKind,
        entityRefId,
        fromState,
        toState,
        allowedTransitions,
      });
    }

    // 5. Verify Transition Reason Requirement
    if (rule.requiresReason && (!transitionReason || transitionReason.trim().length === 0)) {
      throw new MissingTransitionReasonError({
        entityKind,
        entityRefId,
        fromState,
        toState,
      });
    }

    // 6. Verify Actor Roles if rule specifies restriction
    if (rule.allowedRoles && rule.allowedRoles.length > 0) {
      const roles = actorRoles || [];
      const hasRole = rule.allowedRoles.some(r => roles.includes(r));
      if (!hasRole) {
        throw new UnauthorizedTransitionActorError({
          entityKind,
          entityRefId,
          actorRef,
          fromState,
          toState,
          requiredRoles: rule.allowedRoles,
        });
      }
    }

    // 7. Evaluate Policy Gate if required
    let gateResult: GateCheckResult | undefined;
    if (rule.policyGated && rule.gateKey) {
      const fullGateContext: PolicyGateContext = {
        entityRefId,
        entityKind,
        fromState,
        toState,
        actorRef,
        correlationId,
        actorRoles,
        ...request.gateContext,
      };

      gateResult = await PolicyGateRegistry.evaluateGate(rule.gateKey, fullGateContext);
      if (!gateResult.allowed) {
        throw new PolicyGateFailedError({
          entityKind,
          entityRefId,
          fromState,
          toState,
          gateKey: rule.gateKey,
          violations: gateResult.violations,
          reason: gateResult.reason,
        });
      }
    }

    return { rule, gateResult };
  }

  /**
   * Retrieves all legal target states reachable from the given state.
   */
  public static getLegalNextStates(entityKind: LifecycleEntityKind, currentState: string | null): string[] {
    return getAllowedTargetStates(entityKind, currentState);
  }

  /**
   * Retrieves all transition rules for a given entity kind.
   */
  public static getRulesForEntity(entityKind: LifecycleEntityKind): TransitionRule[] {
    return getTransitionRules(entityKind);
  }

  /**
   * Checks whether a given state is terminal.
   */
  public static isTerminal(entityKind: LifecycleEntityKind, state: string): boolean {
    return isTerminalState(entityKind, state);
  }
}
