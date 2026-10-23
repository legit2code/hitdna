import {
  LifecycleEntityKind,
  LifecycleStateMachineService,
  LifecycleStateEngine,
  TransitionRequest,
  TransitionExecutionResult,
  StateProjectionResult,
  StateProjector,
  LifecycleTransitionRecord,
} from '@caim/lifecycle';

export * from './types.ts';
export * from './differential/comparator.ts';
export * from './modification/workspace.ts';
export * from './approval/flow.ts';
export * from './impact/analyzer.ts';
export * from './reanalysis/planner.ts';
export * from './validation/engine.ts';
export * from './service.ts';
export * from './audit-verifier-worker.ts';

export interface LifecycleJob {
  entityRefId: string;
  entityKind: LifecycleEntityKind;
  fromState: string | null;
  toState: string;
  action?: string;
  transitionReason: string;
  actorRef: string;
  correlationId: string;
  actorRoles?: string[];
  gateContext?: any;
}

export interface LifecycleJobResult {
  status: 'SUCCESS' | 'FAILED' | 'REJECTED_BY_POLICY';
  transitionValid: boolean;
  transitionRecord?: LifecycleTransitionRecord;
  projection?: StateProjectionResult;
  error?: string;
}

export async function runLifecycleJob(
  job: LifecycleJob,
  dbClient?: any
): Promise<LifecycleJobResult> {
  try {
    const request: TransitionRequest = {
      entityRefId: job.entityRefId,
      entityKind: job.entityKind,
      fromState: job.fromState,
      toState: job.toState,
      action: job.action,
      transitionReason: job.transitionReason,
      actorRef: job.actorRef,
      correlationId: job.correlationId,
      actorRoles: job.actorRoles,
      gateContext: job.gateContext,
    };

    const result: TransitionExecutionResult = await LifecycleStateMachineService.transitionState(request, {
      dbClient,
    });

    return {
      status: 'SUCCESS',
      transitionValid: true,
      transitionRecord: result.transitionRecord,
      projection: result.projection,
    };
  } catch (err: any) {
    const isPolicyGate = err.code === 'ERR_POLICY_GATE_REJECTED';
    return {
      status: isPolicyGate ? 'REJECTED_BY_POLICY' : 'FAILED',
      transitionValid: false,
      error: err.message || String(err),
    };
  }
}

export {
  LifecycleStateMachineService,
  LifecycleStateEngine,
  StateProjector,
};
