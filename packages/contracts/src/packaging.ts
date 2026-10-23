import { z } from 'zod';
import { PolicyOutcomeEnum, FindingSeverityEnum, ScoreRiskBandEnum } from './enums.ts';

/**
 * P26 — Browser-Safe Packaging, Attestation, Signing & Shipping Contracts
 * Architecture V2.0.1
 */

export const PackageStatusEnum = z.enum([
  'GENERATED',
  'VALIDATED',
  'SIGNED',
  'SHIPPED',
  'DEPRECATED',
]);
export type PackageStatus = z.infer<typeof PackageStatusEnum>;

export const ShippingTargetTypeEnum = z.enum([
  'OCI_REGISTRY',
  'S3_STORAGE',
  'WEBHOOK_DEPLOYMENT',
  'LOCAL_STAGING',
]);
export type ShippingTargetType = z.infer<typeof ShippingTargetTypeEnum>;

export const DetailedDeliveryStateEnum = z.enum([
  'NOT_CONFIGURED',
  'PENDING',
  'UPLOADING',
  'UPLOADED_UNVERIFIED',
  'VERIFYING',
  'DELIVERED_VERIFIED',
  'SIMULATED_DELIVERY',
  'FAILED',
  'INTEGRITY_MISMATCH',
  'AUTHORIZATION_DENIED',
  'PROVIDER_UNAVAILABLE',
  'UNKNOWN_REMOTE_STATE',
  'PARTIALLY_DELIVERED_UNPERSISTED',
  'PERSISTENCE_FAILED',
]);
export type DetailedDeliveryState = z.infer<typeof DetailedDeliveryStateEnum>;

export const ShipmentStatusEnum = z.enum([
  'DELIVERED',
  'DELIVERED_VERIFIED',
  'FAILED',
  'NOT_CONFIGURED',
  'PROVIDER_UNAVAILABLE',
  'SIMULATED_DELIVERY',
  'PENDING',
  'IN_TRANSIT',
  'UPLOADING',
  'UPLOADED_UNVERIFIED',
  'VERIFYING',
  'INTEGRITY_MISMATCH',
  'AUTHORIZATION_DENIED',
  'UNKNOWN_REMOTE_STATE',
  'PARTIALLY_DELIVERED_UNPERSISTED',
  'PERSISTENCE_FAILED',
]);
export type ShipmentStatus = z.infer<typeof ShipmentStatusEnum>;

export interface ImmutableArtifactRecord {
  artifactId: string;
  immutableVersion: string;
  sha256Digest: string;
  sizeBytes: number;
  format: string;
  mediaType: string;
  sourceIdentity: string;
  provenanceHash: string;
  releaseId: string;
  commitSha: string;
  tenantId: string;
  authorizedDestination: string;
  attestationRef?: string;
  destinationProvider: ShippingTargetType;
  canonicalRemoteLocator: string;
  deliveryState: DetailedDeliveryState;
  remoteVersionId?: string;
  integrityVerified: boolean;
  verifiedAt?: string;
}

export interface PackageFileEntry {
  path: string;
  content: string | Uint8Array;
  sha256: string;
  sizeBytes: number;
  contentType: string;
  description: string;
}

export const ValidationReferenceSchema = z.object({
  validation_run_id: z.string(),
  validation_plan_version: z.string(),
  status: z.string(),
  verdict: z.string(),
  risk_reduced: z.boolean(),
  capabilities_preserved: z.boolean(),
  completed_at: z.string(),
});
export type ValidationReference = z.infer<typeof ValidationReferenceSchema>;

export const PolicyReferenceSchema = z.object({
  policy_ruleset_version: z.string(),
  policy_outcome: PolicyOutcomeEnum,
  risk_score: z.number(),
  risk_band: ScoreRiskBandEnum,
  policy_allowed: z.boolean(),
  evaluated_at: z.string(),
  override_id: z.string().optional(),
});
export type PolicyReference = z.infer<typeof PolicyReferenceSchema>;

export const ApprovalReferenceSchema = z.object({
  approval_id: z.string(),
  approver_id: z.string(),
  approver_role: z.string(),
  decision: z.enum(['APPROVED', 'REJECTED', 'PENDING', 'REVOKED']),
  decided_at: z.string(),
  rationale: z.string(),
  signature: z.string().optional(),
});
export type ApprovalReference = z.infer<typeof ApprovalReferenceSchema>;

export const ProvenanceReferenceSchema = z.object({
  engine_version: z.string(),
  ruleset_version: z.string(),
  analysis_run_id: z.string(),
  input_hashes: z.array(z.string()),
  generated_at: z.string(),
});
export type ProvenanceReference = z.infer<typeof ProvenanceReferenceSchema>;

export const PackageManifestContentEntrySchema = z.object({
  path: z.string(),
  sha256: z.string(),
  size_bytes: z.number(),
  content_type: z.string(),
  description: z.string(),
});
export type PackageManifestContentEntry = z.infer<typeof PackageManifestContentEntrySchema>;

export const PackageManifestSchema = z.object({
  schema_version: z.string().default('https://caim.security/schema/package-manifest/v1'),
  package_id: z.string(),
  agent_id: z.string(),
  agent_version_id: z.string(),
  version_label: z.string(),
  created_at: z.string(),
  manifest_hash: z.string(),
  contents: z.array(PackageManifestContentEntrySchema),
  metadata: z.object({
    author: z.string(),
    license: z.string(),
    security_classification: z.string(),
    framework: z.string(),
    description: z.string(),
  }),
  validation_reference: ValidationReferenceSchema,
  policy_reference: PolicyReferenceSchema,
  approval_references: z.array(ApprovalReferenceSchema),
  provenance_reference: ProvenanceReferenceSchema,
});
export type PackageManifest = z.infer<typeof PackageManifestSchema>;

export const InTotoSubjectSchema = z.object({
  name: z.string(),
  digest: z.record(z.string(), z.string()),
});
export type InTotoSubject = z.infer<typeof InTotoSubjectSchema>;

export const AttestationStatementSchema = z.object({
  _type: z.literal('https://in-toto.io/Statement/v1'),
  subject: z.array(InTotoSubjectSchema),
  predicateType: z.string(),
  predicate: z.object({
    builder: z.object({
      id: z.string(),
      version: z.string(),
    }),
    buildType: z.string(),
    invocation: z.object({
      configSource: z.object({
        uri: z.string(),
        digest: z.record(z.string(), z.string()),
      }),
      parameters: z.record(z.string(), z.any()),
    }),
    materials: z.array(z.object({
      uri: z.string(),
      digest: z.record(z.string(), z.string()),
    })),
    metadata: z.object({
      buildInvocationId: z.string(),
      buildStartedOn: z.string(),
      buildFinishedOn: z.string(),
      completeness: z.object({
        parameters: z.boolean(),
        environment: z.boolean(),
        materials: z.boolean(),
      }),
      reproducible: z.boolean(),
    }),
    validation_summary: z.record(z.string(), z.any()),
    policy_decision: z.record(z.string(), z.any()),
    approvals: z.array(z.record(z.string(), z.any())),
  }),
});
export type AttestationStatement = z.infer<typeof AttestationStatementSchema>;

export const SignatureEnvelopeSchema = z.object({
  signature_id: z.string(),
  target_id: z.string(),
  signature_scheme: z.literal('ed25519'),
  key_id: z.string(),
  key_version: z.string(),
  public_key_pem: z.string(),
  signature_base64: z.string(),
  signed_at: z.string(),
  algorithm: z.literal('Ed25519'),
});
export type SignatureEnvelope = z.infer<typeof SignatureEnvelopeSchema>;

export interface SignedPackageBundle {
  package_id: string;
  manifest: PackageManifest;
  manifest_hash: string;
  files: Map<string, PackageFileEntry>;
  attestation: AttestationStatement;
  signature: SignatureEnvelope;
}

export interface VerificationResult {
  valid: boolean;
  tampered: boolean;
  keyId: string;
  keyVersion: string;
  algorithm: string;
  manifestHashMatched: boolean;
  contentHashesMatched: boolean;
  signatureVerified: boolean;
  errors: string[];
}

export const DeliveryReceiptSchema = z.object({
  shipment_id: z.string(),
  package_id: z.string(),
  target_type: z.string(),
  target_locator: z.string(),
  manifest_hash: z.string(),
  signature_id: z.string(),
  shipped_at: z.string().nullable().optional(),
  status: ShipmentStatusEnum,
  receipt_locator: z.string().nullable().optional(),
  transfer_size_bytes: z.number(),
  receipt_signature: z.string().nullable().optional(),
  audit_trail_id: z.string(),
  truthState: z.string().optional(),
  truth_state: z.string().optional(),
  detailed_state: DetailedDeliveryStateEnum.optional(),
  artifact_digest: z.string().optional(),
  remote_digest: z.string().optional(),
  version_id: z.string().nullable().optional(),
  provider_request_id: z.string().nullable().optional(),
  integrity_verified: z.boolean().optional(),
  verified_at: z.string().nullable().optional(),
  provider_delivery_verified: z.boolean().optional(),
  durable_persistence_verified: z.boolean().optional(),
  persistence_error: z.string().nullable().optional(),
  idempotency_key: z.string().nullable().optional(),
  reconciliation_id: z.string().nullable().optional(),
  byte_level_readback_verified: z.boolean().optional(),
  error: z.string().nullable().optional(),
  metadata: z.record(z.string(), z.any()).optional(),
});
export type DeliveryReceipt = z.infer<typeof DeliveryReceiptSchema>;

export interface PolicyGateResult {
  allowed: boolean;
  gate_name: string;
  reasons: string[];
  blockers: string[];
  evaluated_at: string;
}

export interface ShippingGateResult {
  allowed: boolean;
  target_type: ShippingTargetType;
  reasons: string[];
  blockers: string[];
  signature_valid: boolean;
  evaluated_at: string;
}

/**
 * RP-00 Release Verification Receipt Schema
 * Cryptographic and provenance audit binding for root platform gate.
 */
export const PreGitHistoryStatusEnum = z.enum([
  'NOT_APPLICABLE_NO_PRIOR_GIT_REPOSITORY',
  'SCANNED_FULL_GIT_HISTORY',
  'HISTORICAL_SCAN_PENDING_EXTERNAL_GIT',
]);
export type PreGitHistoryStatus = z.infer<typeof PreGitHistoryStatusEnum>;

export const Rp00VerificationReceiptSchema = z.object({
  schemaVersion: z.literal('https://caim.security/schema/rp00-receipt/v1').default('https://caim.security/schema/rp00-receipt/v1'),
  phase: z.literal('RP-00'),
  phaseStatus: z.enum(['VERIFIED', 'BLOCKED', 'PHASE_BLOCKED']),
  timestamp: z.string(),
  preGitHistoryStatus: PreGitHistoryStatusEnum,
  sourceSnapshotSha256: z.string().nullable().optional(),
  gitCommitSha: z.string().nullable().optional(),
  releaseArtifactSha256: z.string().nullable().optional(),
  ciRunId: z.string().nullable().optional(),
  packageManagerVersion: z.string(),
  historySecretScan: z.object({
    status: z.enum(['PASSED', 'FAILED', 'NOT_APPLICABLE', 'PENDING_EXTERNAL_CI']),
    findingsCount: z.number(),
    summary: z.string(),
  }),
  bundleSecretScan: z.object({
    status: z.enum(['PASSED', 'FAILED', 'PENDING_BUILD']),
    findingsCount: z.number(),
    clientBundleClean: z.boolean(),
    serverBundleClean: z.boolean(),
    summary: z.string(),
  }),
  releaseFreezeActive: z.boolean(),
  auditNotes: z.string(),
});
export type Rp00VerificationReceipt = z.infer<typeof Rp00VerificationReceiptSchema>;
