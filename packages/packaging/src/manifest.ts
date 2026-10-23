import { 
  PackageManifest, 
  PackageManifestSchema, 
  PackageManifestContentEntry,
  ValidationReference,
  PolicyReference,
  ApprovalReference,
  ProvenanceReference
} from './types.ts';
import { computeManifestRootHash, deterministicPrettyJson } from './hashing.ts';

/**
 * Package Manifest Builder & Validator
 */

export interface BuildManifestInput {
  packageId: string;
  agentId: string;
  agentVersionId: string;
  versionLabel: string;
  createdAt: string;
  contents: PackageManifestContentEntry[];
  metadata: {
    author: string;
    license: string;
    securityClassification: string;
    framework: string;
    description: string;
  };
  validationReference: ValidationReference;
  policyReference: PolicyReference;
  approvalReferences: ApprovalReference[];
  provenanceReference: ProvenanceReference;
}

export class PackageManifestBuilder {
  /**
   * Builds and validates a deterministic PackageManifest.
   */
  static build(input: BuildManifestInput): PackageManifest {
    // Sort contents deterministically by path
    const sortedContents = [...input.contents].sort((a, b) => a.path.localeCompare(b.path));

    // Compute manifest root hash across all content files
    const manifestHash = computeManifestRootHash(
      sortedContents.map((c) => ({ path: c.path, sha256: c.sha256 }))
    );

    // Sort approval references deterministically by approval_id
    const sortedApprovals = [...input.approvalReferences].sort((a, b) =>
      a.approval_id.localeCompare(b.approval_id)
    );

    const rawManifest: PackageManifest = {
      schema_version: 'https://caim.security/schema/package-manifest/v1',
      package_id: input.packageId,
      agent_id: input.agentId,
      agent_version_id: input.agentVersionId,
      version_label: input.versionLabel,
      created_at: input.createdAt,
      manifest_hash: manifestHash,
      contents: sortedContents,
      metadata: {
        author: input.metadata.author,
        license: input.metadata.license,
        security_classification: input.metadata.securityClassification,
        framework: input.metadata.framework,
        description: input.metadata.description,
      },
      validation_reference: input.validationReference,
      policy_reference: input.policyReference,
      approval_references: sortedApprovals,
      provenance_reference: input.provenanceReference,
    };

    // Strict schema validation
    return PackageManifestSchema.parse(rawManifest);
  }

  /**
   * Serializes manifest to deterministic formatted JSON.
   */
  static toDeterministicJson(manifest: PackageManifest): string {
    return deterministicPrettyJson(manifest);
  }
}
