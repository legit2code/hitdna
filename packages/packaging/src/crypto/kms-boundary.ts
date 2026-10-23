import { ISigner, Ed25519Signer } from './signer.ts';
import type { PackageManifest, SignatureEnvelope, PolicyGateResult } from '../types.ts';
import { KeyRegistry } from './key-registry.ts';
import { SignatureVerifier } from './verifier.ts';
import { 
  ICloudKmsProvider, 
  CloudKmsSignerAdapter, 
  ProductionKeyCustodyViolationError 
} from './cloud-kms-provider.ts';
import { 
  CanonicalReleasePayload, 
  computeCanonicalPayloadDigest, 
  validateCanonicalReleasePayload 
} from './canonical-payload.ts';

/**
 * KMS & Isolated Signing Boundary (Threat Model Compliance)
 * 
 * INVARIANT: Private signing keys are strictly confined within this boundary.
 * Neither web requests, general queue workers, nor sandbox environments
 * have access to raw private keys or key material.
 * In production, in-process ephemeral key fallbacks are strictly prohibited.
 */

export class SigningPolicyViolationError extends Error {
  constructor(message: string, public blockers: string[]) {
    super(`Signing blocked by policy gate: ${message} (Blockers: ${blockers.join(', ')})`);
    this.name = 'SigningPolicyViolationError';
  }
}

export class KmsSignerBoundary {
  private signer: ISigner;
  private keyRegistry: KeyRegistry;

  constructor(signer: ISigner, keyRegistry?: KeyRegistry) {
    this.signer = signer;
    this.keyRegistry = keyRegistry || new KeyRegistry();

    // Register signer's public key in registry
    this.keyRegistry.registerKey({
      keyId: signer.getKeyId(),
      keyVersion: signer.getKeyVersion(),
      publicKeyPem: signer.getPublicKeyPem(),
      algorithm: signer.getAlgorithm(),
      status: 'ACTIVE',
      validFrom: new Date().toISOString(),
      description: 'Primary Release Signing Key (KMS Enclave Isolated)',
    }, true);
  }

  /**
   * Factory method to create an isolated boundary with test or environment signing material.
   * INVARIANT: Ephemeral local keys are strictly forbidden in production.
   */
  static createDefault(keyId: string = 'caim-release-key-01', keyVersion: string = 'v1'): KmsSignerBoundary {
    const isProd = process.env.NODE_ENV === 'production' || process.env.CAIM_REQUIRE_CLOUD_KMS === 'true';
    if (isProd) {
      throw new ProductionKeyCustodyViolationError(
        'Production Key Custody Violation: In-process ephemeral signing keys are strictly prohibited in production. Authentic Cloud KMS (GCP Cloud KMS or AWS KMS) must be used.'
      );
    }
    const { signer } = Ed25519Signer.generateKeyPair(keyId, keyVersion);
    return new KmsSignerBoundary(signer);
  }

  /**
   * Factory method for environment key material.
   * INVARIANT: Raw private-key PEM ingestion is strictly prohibited in production.
   */
  static fromPrivateKeyPem(keyId: string, keyVersion: string, privateKeyPem: string): KmsSignerBoundary {
    const isProd = process.env.NODE_ENV === 'production' || process.env.CAIM_REQUIRE_CLOUD_KMS === 'true';
    if (isProd) {
      throw new ProductionKeyCustodyViolationError(
        'Production Key Custody Violation: Direct private-key PEM ingestion is strictly prohibited in production. Keys must remain isolated within Cloud KMS.'
      );
    }
    const signer = new Ed25519Signer({
      keyId,
      keyVersion,
      privateKeyPem,
    });
    return new KmsSignerBoundary(signer);
  }

  /**
   * Factory method for authentic Cloud KMS provider (GCP or AWS).
   */
  static async fromCloudKms(provider: ICloudKmsProvider, keyRegistry?: KeyRegistry): Promise<KmsSignerBoundary> {
    const adapter = await CloudKmsSignerAdapter.create(provider);
    return new KmsSignerBoundary(adapter, keyRegistry);
  }

  getKeyRegistry(): KeyRegistry {
    return this.keyRegistry;
  }

  getPublicKeyPem(): string {
    return this.signer.getPublicKeyPem();
  }

  getKeyId(): string {
    return this.signer.getKeyId();
  }

  getKeyVersion(): string {
    return this.signer.getKeyVersion();
  }

  isConfigured(): boolean {
    return Boolean(this.signer);
  }

  /**
   * Verifies cryptographic provider capability by performing an internal test sign and verification.
   */
  async verifyCapability(): Promise<{ healthy: boolean; keyId: string; error?: string }> {
    try {
      if (!this.signer) {
        return { healthy: false, keyId: 'none', error: 'No signer initialized in KMS boundary' };
      }
      const testData = 'caim-kms-capability-probe-' + Date.now();
      const envelope = await this.signer.sign(testData, 'kms-probe');
      const isValid = SignatureVerifier.verifySignature(testData, envelope, this.signer.getPublicKeyPem());
      if (!isValid) {
        return { healthy: false, keyId: this.signer.getKeyId(), error: 'Cryptographic signature verification failed' };
      }
      return { healthy: true, keyId: this.signer.getKeyId() };
    } catch (err: any) {
      return { healthy: false, keyId: this.signer?.getKeyId() || 'unknown', error: err?.message || String(err) };
    }
  }

  /**
   * Signs a PackageManifest ONLY IF the pre-signing policy gate passes.
   * If the gate is rejected (e.g. DENY_SHIPPING, unapproved, regression), throws SigningPolicyViolationError.
   */
  async signManifest(
    manifest: PackageManifest,
    gateResult: PolicyGateResult
  ): Promise<SignatureEnvelope> {
    if (!gateResult.allowed) {
      throw new SigningPolicyViolationError(
        gateResult.gate_name,
        gateResult.blockers
      );
    }

    // Sign the root manifest_hash
    const signatureEnvelope = await this.signer.sign(
      manifest.manifest_hash,
      manifest.package_id
    );

    return signatureEnvelope;
  }

  /**
   * Signs a CanonicalReleasePayload ONLY IF the pre-signing policy gate passes.
   * Strictly binds signature to canonical release fields (RFC 8785).
   */
  async signCanonicalPayload(
    payload: CanonicalReleasePayload,
    gateResult: PolicyGateResult
  ): Promise<SignatureEnvelope> {
    if (!gateResult.allowed) {
      throw new SigningPolicyViolationError(
        gateResult.gate_name,
        gateResult.blockers
      );
    }

    validateCanonicalReleasePayload(payload);
    const digest = computeCanonicalPayloadDigest(payload);

    return this.signer.sign(digest, payload.releaseId);
  }
}
