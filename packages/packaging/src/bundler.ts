import { 
  SignedPackageBundle, 
  PackageFileEntry, 
  PackageManifest,
  PackageManifestContentEntry,
  ValidationReference,
  PolicyReference,
  ApprovalReference,
  ProvenanceReference
} from './types.ts';
import { sha256, canonicalJson, deterministicPrettyJson, normalizeLineEndings } from './hashing.ts';
import { CycloneDxGenerator, SbomComponent, CycloneDxMetadata } from './sbom.ts';
import { SummaryCsvGenerator, SummaryRow } from './summary.ts';
import { PackageManifestBuilder } from './manifest.ts';
import { AttestationBuilder } from './attestation.ts';
import { KmsSignerBoundary } from './crypto/kms-boundary.ts';
import { PackagingPolicyGate } from './gates.ts';

export interface PackageBuildInput {
  packageId?: string;
  agentId: string;
  agentVersionId: string;
  versionLabel: string;
  createdAt?: string;
  sourceFiles: Record<string, string>;
  analysisReport: Record<string, any>;
  sbomComponents: SbomComponent[];
  validationReference: ValidationReference;
  policyReference: PolicyReference;
  approvalReferences: ApprovalReference[];
  provenanceReference: ProvenanceReference;
  metadata: {
    author: string;
    license: string;
    securityClassification: string;
    framework: string;
    description: string;
  };
  requireTwoPersonApproval?: boolean;
}

export class DeterministicPackageBundler {
  /**
   * Builds, packages, generates all required deterministic deliverables, and cryptographically signs the release bundle.
   */
  static async buildAndSign(
    input: PackageBuildInput,
    kmsBoundary: KmsSignerBoundary
  ): Promise<SignedPackageBundle> {
    const packageId = input.packageId || `pkg-${input.agentId}-${input.versionLabel}`;
    const createdAt = input.createdAt || '2026-08-26T12:00:00Z'; // deterministic default

    const filesMap = new Map<string, PackageFileEntry>();

    // 1. Process Approved Source Files (sort keys deterministically)
    const sortedSourcePaths = Object.keys(input.sourceFiles).sort();
    for (const filePath of sortedSourcePaths) {
      const rawContent = input.sourceFiles[filePath];
      const normalized = normalizeLineEndings(rawContent);
      const fileHash = sha256(normalized);
      const sizeBytes = Buffer.byteLength(normalized, 'utf-8');

      filesMap.set(filePath, {
        path: filePath,
        content: normalized,
        sha256: fileHash,
        sizeBytes,
        contentType: getContentType(filePath),
        description: `Approved Source Payload: ${filePath}`,
      });
    }

    // 2. Generate CycloneDX SBOM (bom.json)
    const sbomMetadata: CycloneDxMetadata = {
      componentName: `agent-${input.agentId}`,
      version: input.versionLabel,
      author: input.metadata.author,
      licenses: [input.metadata.license],
      timestamp: createdAt,
    };
    const sbomJson = CycloneDxGenerator.generateSbom(sbomMetadata, input.sbomComponents);
    const sbomString = deterministicPrettyJson(sbomJson);
    const sbomHash = sha256(sbomString);

    filesMap.set('bom.json', {
      path: 'bom.json',
      content: sbomString,
      sha256: sbomHash,
      sizeBytes: Buffer.byteLength(sbomString, 'utf-8'),
      contentType: 'application/vnd.cyclonedx+json',
      description: 'CycloneDX v1.5 Software Bill of Materials (SBOM)',
    });

    // 3. Generate Summary CSV (summary.csv)
    const summaryRows: SummaryRow[] = [
      {
        itemType: 'VALIDATION',
        identifier: input.validationReference.validation_run_id,
        severity: 'INFORMATIONAL',
        category: 'VALIDATION_DECISION',
        status: input.validationReference.status,
        details: `Verdict: ${input.validationReference.verdict}, Plan: ${input.validationReference.validation_plan_version}`,
      },
      {
        itemType: 'POLICY',
        identifier: `policy-${input.policyReference.policy_ruleset_version}`,
        severity: input.policyReference.risk_band,
        category: 'POLICY_GATE',
        status: input.policyReference.policy_outcome,
        details: `Risk Score: ${input.policyReference.risk_score}, Allowed: ${input.policyReference.policy_allowed}`,
      },
      ...input.approvalReferences.map((a) => ({
        itemType: 'APPROVAL' as const,
        identifier: a.approval_id,
        severity: 'INFORMATIONAL',
        category: a.approver_role,
        status: a.decision,
        details: `Approver: ${a.approver_id}, DecidedAt: ${a.decided_at}`,
      })),
      ...input.sbomComponents.map((c) => ({
        itemType: 'DEPENDENCY' as const,
        identifier: `${c.name}@${c.version}`,
        severity: c.vulnerabilities && c.vulnerabilities.length > 0 ? 'HIGH' : 'LOW',
        category: c.type,
        status: 'INSPECTED',
        details: `Licenses: ${(c.licenses || []).join(', ') || 'N/A'}, CVEs: ${(c.vulnerabilities || []).length}`,
      })),
    ];

    const summaryCsvString = SummaryCsvGenerator.generateCsv(summaryRows);
    const summaryCsvHash = sha256(summaryCsvString);

    filesMap.set('summary.csv', {
      path: 'summary.csv',
      content: summaryCsvString,
      sha256: summaryCsvHash,
      sizeBytes: Buffer.byteLength(summaryCsvString, 'utf-8'),
      contentType: 'text/csv',
      description: 'Tabular Compliance & Risk Audit Summary CSV',
    });

    // 4. Generate Analysis Report JSON (report.json)
    const reportString = deterministicPrettyJson(input.analysisReport);
    const reportHash = sha256(reportString);

    filesMap.set('report.json', {
      path: 'report.json',
      content: reportString,
      sha256: reportHash,
      sizeBytes: Buffer.byteLength(reportString, 'utf-8'),
      contentType: 'application/json',
      description: 'Comprehensive Structured Analysis Report',
    });

    // 5. Generate Provenance JSON (provenance.json)
    const provenanceString = deterministicPrettyJson(input.provenanceReference);
    const provenanceHash = sha256(provenanceString);

    filesMap.set('provenance.json', {
      path: 'provenance.json',
      content: provenanceString,
      sha256: provenanceHash,
      sizeBytes: Buffer.byteLength(provenanceString, 'utf-8'),
      contentType: 'application/json',
      description: 'Analysis-Version & Engine Provenance Manifest',
    });

    // 6. Build Manifest Content Entries (deterministic sort)
    const manifestEntries: PackageManifestContentEntry[] = Array.from(filesMap.values())
      .map((f) => ({
        path: f.path,
        sha256: f.sha256,
        size_bytes: f.sizeBytes,
        content_type: f.contentType,
        description: f.description,
      }))
      .sort((a, b) => a.path.localeCompare(b.path));

    // 7. Build Manifest
    const manifest = PackageManifestBuilder.build({
      packageId,
      agentId: input.agentId,
      agentVersionId: input.agentVersionId,
      versionLabel: input.versionLabel,
      createdAt,
      contents: manifestEntries,
      metadata: {
        author: input.metadata.author,
        license: input.metadata.license,
        securityClassification: input.metadata.securityClassification,
        framework: input.metadata.framework,
        description: input.metadata.description,
      },
      validationReference: input.validationReference,
      policyReference: input.policyReference,
      approvalReferences: input.approvalReferences,
      provenanceReference: input.provenanceReference,
    });

    const manifestJsonString = PackageManifestBuilder.toDeterministicJson(manifest);
    const manifestFileHash = sha256(manifestJsonString);

    filesMap.set('manifest.json', {
      path: 'manifest.json',
      content: manifestJsonString,
      sha256: manifestFileHash,
      sizeBytes: Buffer.byteLength(manifestJsonString, 'utf-8'),
      contentType: 'application/json',
      description: 'Cryptographic Root Package Manifest',
    });

    // 8. Generate in-toto Attestation Statement (attestation.json)
    const attestation = AttestationBuilder.build({ manifest });
    const attestationString = AttestationBuilder.toDeterministicJson(attestation);
    const attestationHash = sha256(attestationString);

    filesMap.set('attestation.json', {
      path: 'attestation.json',
      content: attestationString,
      sha256: attestationHash,
      sizeBytes: Buffer.byteLength(attestationString, 'utf-8'),
      contentType: 'application/vnd.in-toto+json',
      description: 'in-toto v1 SLSA-Compliant Attestation Statement',
    });

    // 9. Evaluate Pre-Signing Policy Gate
    const gateResult = PackagingPolicyGate.evaluatePreSigningGate({
      validationReference: input.validationReference,
      policyReference: input.policyReference,
      approvalReferences: input.approvalReferences,
      requireTwoPersonApproval: input.requireTwoPersonApproval,
    });

    // 10. Request KMS Signer Boundary to Sign
    const signature = await kmsBoundary.signManifest(manifest, gateResult);

    return {
      package_id: packageId,
      manifest,
      manifest_hash: manifest.manifest_hash,
      files: filesMap,
      attestation,
      signature,
    };
  }
}

function getContentType(filePath: string): string {
  if (filePath.endsWith('.ts')) return 'text/typescript';
  if (filePath.endsWith('.js')) return 'text/javascript';
  if (filePath.endsWith('.py')) return 'text/x-python';
  if (filePath.endsWith('.json')) return 'application/json';
  if (filePath.endsWith('.csv')) return 'text/csv';
  if (filePath.endsWith('.md')) return 'text/markdown';
  if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) return 'text/yaml';
  return 'text/plain';
}
