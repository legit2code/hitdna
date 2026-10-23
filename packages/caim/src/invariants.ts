import { 
  CaimAgentVersion, 
  CaimPermission, 
  CaimCapabilityInstance, 
  CaimBehaviorObserved 
} from './types.ts';

export class SemanticInvariantViolationError extends Error {
  constructor(message: string) {
    super(`Semantic Invariant Violation: ${message}`);
    this.name = 'SemanticInvariantViolationError';
  }
}

/**
 * Invariant: AgentVersion represents static content identity, NEVER an analysis execution.
 */
export function assertAgentVersionIsNotAnalysisRun(obj: unknown): void {
  if (!obj || typeof obj !== 'object') return;
  
  const record = obj as Record<string, unknown>;
  if ('analysis_run_id' in record && '_entity_kind' in record && record._entity_kind === 'AGENT_VERSION') {
    throw new SemanticInvariantViolationError(
      'AgentVersion cannot contain analysis_run_id; AgentVersion is static content identity, not an AnalysisRun'
    );
  }

  if ('pipeline_version' in record && '_entity_kind' in record && record._entity_kind === 'AGENT_VERSION') {
    throw new SemanticInvariantViolationError(
      'AgentVersion cannot contain pipeline_version; execution metadata belongs strictly to AnalysisRun'
    );
  }
}

/**
 * Invariant: Permission != Capability != BehaviorObserved
 * These three concepts are fundamentally distinct:
 * - Permission: security/access authorization grant or request
 * - Capability: functional feature/potential of the agent
 * - BehaviorObserved: empirical execution event
 */
export function assertPermissionNotCapabilityNotBehavior(obj: unknown): void {
  if (!obj || typeof obj !== 'object') return;
  
  const record = obj as Record<string, unknown>;
  const kind = record._entity_kind;

  if (kind === 'PERMISSION') {
    if ('observed_action' in record || 'runtime_event_id' in record) {
      throw new SemanticInvariantViolationError(
        'Permission entity cannot contain empirical runtime execution fields (BehaviorObserved)'
      );
    }
    if ('declaration_state' in record && typeof record.declaration_state === 'string' && record.declaration_state.startsWith('INFERRED_')) {
      throw new SemanticInvariantViolationError(
        'Permission declared_state cannot be mixed with Capability declaration_state'
      );
    }
  }

  if (kind === 'CAPABILITY') {
    if ('declared_state' in record && ['REQUESTED', 'GRANTED', 'REQUIRED', 'ASSUMED'].includes(record.declared_state as string)) {
      throw new SemanticInvariantViolationError(
        'Capability entity cannot possess Permission declared_state'
      );
    }
    if ('observed_action' in record || 'runtime_event_id' in record) {
      throw new SemanticInvariantViolationError(
        'Capability represents functional potential, not raw empirical BehaviorObserved'
      );
    }
  }

  if (kind === 'BEHAVIOR_OBSERVED') {
    if (!('runtime_event_id' in record) || !('occurred_at' in record)) {
      throw new SemanticInvariantViolationError(
        'BehaviorObserved must be bound to a concrete runtime_event_id and occurred_at timestamp'
      );
    }
  }
}

export function isCaimPermission(obj: unknown): obj is CaimPermission {
  return typeof obj === 'object' && obj !== null && (obj as Record<string, unknown>)._entity_kind === 'PERMISSION';
}

export function isCaimCapability(obj: unknown): obj is CaimCapabilityInstance {
  return typeof obj === 'object' && obj !== null && (obj as Record<string, unknown>)._entity_kind === 'CAPABILITY';
}

export function isCaimBehaviorObserved(obj: unknown): obj is CaimBehaviorObserved {
  return typeof obj === 'object' && obj !== null && (obj as Record<string, unknown>)._entity_kind === 'BEHAVIOR_OBSERVED';
}

export function isCaimAgentVersion(obj: unknown): obj is CaimAgentVersion {
  return typeof obj === 'object' && obj !== null && (obj as Record<string, unknown>)._entity_kind === 'AGENT_VERSION';
}
