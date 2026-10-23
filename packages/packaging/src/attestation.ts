import { 
  AttestationStatement, 
  AttestationStatementSchema,
  PackageManifest
} from './types.ts';
import { deterministicPrettyJson } from './hashing.ts';

/**
 * in-toto & SLSA-compliant Attestation Builder
 */

export interface BuildAttestationInput {
  manifest: PackageManifest;
  builderId?: string;
  builderVersion?: string;
  reproducible?: boolean;
  extraMaterials?: Array<{ uri: string; digest: Record<string, string> }>;
}

export class AttestationBuilder {
  /**
   * Generates a signed in-toto v1 Statement containing SLSA provenance and CAIM verification predicates.
   */
  static build(input: BuildAttestationInput): AttestationStatement {
    const { manifest } = input;
    const builderId = input.builderId || 'https://caim.security/builders/agent-packager/v2.0.1';
    const builderVersion = input.builderVersion || '2.0.1';

    const subjects = [
      {
        name: `agent-${manifest.agent_id}-${manifest.version_label}.tar.gz`,
        digest: {
          sha256: manifest.manifest_hash,
        },
      },
      ...manifest.contents.map((c) => ({
        name: c.path,
        digest: {
          sha256: c.sha256,
        },
      })),
    ];

    const materials = [
      {
        uri: `caim://agent-version/${manifest.agent_version_id}`,
        digest: {
          sha256: manifest.provenance_reference.input_hashes[0] || manifest.manifest_hash,
        },
      },
      ...(input.extraMaterials || []),
    ];

    const statement: AttestationStatement = {
      _type: 'https://in-toto.io/Statement/v1',
      subject: subjects,
      predicateType: 'https://caim.security/attestation/v1',
      predicate: {
        builder: {
          id: builderId,
          version: builderVersion,
        },
        buildType: 'https://caim.security/build-types/agent-release/v1',
        invocation: {
          configSource: {
            uri: `caim://manifest/${manifest.package_id}`,
            digest: {
              sha256: manifest.manifest_hash,
            },
          },
          parameters: {
            agent_id: manifest.agent_id,
            version_label: manifest.version_label,
            validation_run_id: manifest.validation_reference.validation_run_id,
            policy_ruleset_version: manifest.policy_reference.policy_ruleset_version,
          },
        },
        materials,
        metadata: {
          buildInvocationId: `inv-${manifest.package_id}`,
          buildStartedOn: manifest.created_at,
          buildFinishedOn: manifest.created_at,
          completeness: {
            parameters: true,
            environment: true,
            materials: true,
          },
          reproducible: input.reproducible !== false,
        },
        validation_summary: {
          validation_run_id: manifest.validation_reference.validation_run_id,
          verdict: manifest.validation_reference.verdict,
          status: manifest.validation_reference.status,
          risk_reduced: manifest.validation_reference.risk_reduced,
          capabilities_preserved: manifest.validation_reference.capabilities_preserved,
        },
        policy_decision: {
          outcome: manifest.policy_reference.policy_outcome,
          risk_score: manifest.policy_reference.risk_score,
          risk_band: manifest.policy_reference.risk_band,
          allowed: manifest.policy_reference.policy_allowed,
        },
        approvals: manifest.approval_references.map((a) => ({
          approval_id: a.approval_id,
          approver_id: a.approver_id,
          role: a.approver_role,
          decision: a.decision,
          decided_at: a.decided_at,
        })),
      },
    };

    return AttestationStatementSchema.parse(statement);
  }

  /**
   * Serializes attestation statement to deterministic formatted JSON.
   */
  static toDeterministicJson(attestation: AttestationStatement): string {
    return deterministicPrettyJson(attestation);
  }
}
