import { z } from 'zod';

export type Brand<K, T> = K & { readonly __brand: T };

export type AgentId = Brand<string, 'AgentId'>;
export type AgentVersionId = Brand<string, 'AgentVersionId'>;
export type AnalysisRunId = Brand<string, 'AnalysisRunId'>;
export type StageRunId = Brand<string, 'StageRunId'>;
export type ScopeId = Brand<string, 'ScopeId'>;
export type TenantId = Brand<string, 'TenantId'>;
export type EntityRefId = Brand<string, 'EntityRefId'>;
export type EvidenceId = Brand<string, 'EvidenceId'>;
export type AssertionId = Brand<string, 'AssertionId'>;
export type ClaimId = Brand<string, 'ClaimId'>;
export type RiskId = Brand<string, 'RiskId'>;
export type FindingId = Brand<string, 'FindingId'>;
export type ArtifactId = Brand<string, 'ArtifactId'>;
export type SecurityClassificationId = Brand<string, 'SecurityClassificationId'>;

const UUID_REGEX = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export function isValidUuid(value: string): boolean {
  return UUID_REGEX.test(value);
}

export const UuidSchema = z.string().regex(UUID_REGEX, 'Must be a valid UUID');

export function asAgentId(id: string): AgentId {
  UuidSchema.parse(id);
  return id as AgentId;
}

export function asAgentVersionId(id: string): AgentVersionId {
  UuidSchema.parse(id);
  return id as AgentVersionId;
}

export function asAnalysisRunId(id: string): AnalysisRunId {
  UuidSchema.parse(id);
  return id as AnalysisRunId;
}

export function asStageRunId(id: string): StageRunId {
  UuidSchema.parse(id);
  return id as StageRunId;
}

export function asScopeId(id: string): ScopeId {
  UuidSchema.parse(id);
  return id as ScopeId;
}

export function asTenantId(id: string): TenantId {
  UuidSchema.parse(id);
  return id as TenantId;
}

export function asEntityRefId(id: string): EntityRefId {
  UuidSchema.parse(id);
  return id as EntityRefId;
}

export function asEvidenceId(id: string): EvidenceId {
  UuidSchema.parse(id);
  return id as EvidenceId;
}

export function asAssertionId(id: string): AssertionId {
  UuidSchema.parse(id);
  return id as AssertionId;
}

export function asClaimId(id: string): ClaimId {
  UuidSchema.parse(id);
  return id as ClaimId;
}

export function asFindingId(id: string): FindingId {
  UuidSchema.parse(id);
  return id as FindingId;
}

export function asArtifactId(id: string): ArtifactId {
  UuidSchema.parse(id);
  return id as ArtifactId;
}
