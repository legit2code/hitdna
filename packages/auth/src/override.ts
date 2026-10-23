import { 
  PrincipalContext, 
  AuditedOverrideRequest, 
  SecurityClassificationRank, 
  UnauthorizedAccessError 
} from './types.ts';

export interface AuditEventSink {
  logAuditEvent(event: {
    principal_or_service_id: string;
    action: string;
    target_entity_ref_id?: string | null;
    outcome: 'SUCCESS' | 'DENIED' | 'ERROR';
    correlation_id: string;
    metadata: Record<string, any>;
  }): Promise<any> | any;
}

export interface MfaSecurityStatus {
  mfa_supported: false;
  mfa_enforced: false;
  mfa_status: 'NOT_IMPLEMENTED_BY_PLATFORM';
  strongest_control_enforced: 'AUTHENTICATED_PRIVILEGED_ROLE_AND_AUDITED_JUSTIFICATION';
  details: string;
}

export function getMfaSecurityStatus(): MfaSecurityStatus {
  return {
    mfa_supported: false,
    mfa_enforced: false,
    mfa_status: 'NOT_IMPLEMENTED_BY_PLATFORM',
    strongest_control_enforced: 'AUTHENTICATED_PRIVILEGED_ROLE_AND_AUDITED_JUSTIFICATION',
    details: 'Multi-factor authentication (MFA) step-up is not supported by the platform identity provider. Enforcing authenticated cryptographic principal verification, privileged role/capability checks, and mandatory audit justification.',
  };
}

/**
 * Executes a privileged / break-glass operation with mandatory audit logging and justification.
 * (Architecture V2.0.1 Document 13)
 */
export async function executeWithAuditedOverride<T>(
  context: PrincipalContext,
  request: AuditedOverrideRequest,
  auditSink: AuditEventSink,
  operation: (elevatedContext: PrincipalContext) => Promise<T> | T
): Promise<T> {
  // 1. Authenticated principal validation (Anonymous principals must fail)
  if (
    !context || 
    !context.is_authenticated || 
    context.roles?.includes('anonymous') || 
    context.principal_id === 'anonymous' || 
    context.principalType === 'anonymous'
  ) {
    throw new UnauthorizedAccessError('Break-glass override rejected: Principal must be authenticated (anonymous rejected).');
  }

  // 2. Specific privileged capability/role requirement (ordinary users must fail)
  const privilegedRoles = ['admin', 'operator', 'security_officer', 'system_admin'];
  const privilegedCapabilities = ['break_glass', 'security.break_glass', 'override.execute', 'vault.override', 'security.override'];

  const hasPrivilegedRole = context.roles?.some((r) => privilegedRoles.includes(r as string));
  const hasPrivilegedCap =
    (context.capabilities || []).some((c) => privilegedCapabilities.includes(c)) ||
    (context.grants || []).some((g) => privilegedCapabilities.includes(g));

  if (!hasPrivilegedRole && !hasPrivilegedCap) {
    throw new UnauthorizedAccessError(
      `Break-glass override rejected: Principal '${context.principal_id}' lacks privileged break-glass authorization (operator or admin required).`
    );
  }

  // 3. Mandatory audit reason / justification (min 10 chars)
  if (!request.justification || request.justification.trim().length < 10) {
    throw new UnauthorizedAccessError('Break-glass override rejected: A valid justification (min 10 chars) is required.');
  }

  // 4. Report MFA status explicitly (Do not create fake MFA)
  const mfaStatus = getMfaSecurityStatus();

  const elevatedContext: PrincipalContext = {
    ...context,
    is_override_active: true,
    override_justification: request.justification,
    correlation_id: request.correlation_id,
    max_classification_rank: SecurityClassificationRank.VAULT_RESTRICTED,
  };

  try {
    const result = await operation(elevatedContext);

    // Record immutable audit event
    await auditSink.logAuditEvent({
      principal_or_service_id: context.principal_id,
      action: `AUDITED_OVERRIDE:${request.action}`,
      target_entity_ref_id: request.target_resource_id,
      outcome: 'SUCCESS',
      correlation_id: request.correlation_id,
      metadata: {
        actor_id: request.actor_id,
        justification: request.justification,
        target_resource_type: request.target_resource_type,
        target_resource_id: request.target_resource_id,
        mfa_status: mfaStatus.mfa_status,
        mfa_supported: mfaStatus.mfa_supported,
        security_control: mfaStatus.strongest_control_enforced,
        timestamp: new Date().toISOString(),
        ...request.metadata,
      },
    });

    return result;
  } catch (error: unknown) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    await auditSink.logAuditEvent({
      principal_or_service_id: context.principal_id,
      action: `AUDITED_OVERRIDE:${request.action}`,
      target_entity_ref_id: request.target_resource_id,
      outcome: 'ERROR',
      correlation_id: request.correlation_id,
      metadata: {
        actor_id: request.actor_id,
        justification: request.justification,
        error: errorMsg,
        mfa_status: mfaStatus.mfa_status,
        timestamp: new Date().toISOString(),
      },
    });
    throw error;
  }
}
