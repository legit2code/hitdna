import crypto from 'node:crypto';
import { SignatureEnvelope, SignedPackageBundle, PackageManifest, VerificationResult } from '../types.ts';
import { sha256, computeManifestRootHash } from '../hashing.ts';

export type { VerificationResult };

export class SignatureVerifier {
  /**
   * Verifies an Ed25519 signature directly over a data payload.
   */
  static verifySignature(
    data: string | Uint8Array,
    signatureEnvelope: SignatureEnvelope,
    expectedPublicKeyPem?: string
  ): boolean {
    try {
      if (!signatureEnvelope || !signatureEnvelope.signature_base64 || signatureEnvelope.signature_base64 === 'auto-signed') {
        return false;
      }
      const publicKeyToUse = expectedPublicKeyPem || signatureEnvelope.public_key_pem;
      if (!publicKeyToUse) {
        return false;
      }

      const pubKeyObj = crypto.createPublicKey(publicKeyToUse);
      const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(data);
      const sigBuffer = Buffer.from(signatureEnvelope.signature_base64, 'base64');

      const algoUpper = (signatureEnvelope.algorithm || signatureEnvelope.signature_scheme || '').toUpperCase();
      const keyType = pubKeyObj.asymmetricKeyType;

      // 1. Ed25519 (only supported for true ed25519 keys)
      if (keyType === 'ed25519' || algoUpper === 'ED25519') {
        if (keyType !== 'ed25519') {
          return false; // Mismatched key type for Ed25519
        }
        return crypto.verify(null, dataBuffer, pubKeyObj, sigBuffer);
      }

      // 2. RSA-PSS (requires RSA_PKCS1_PSS_PADDING and salt length)
      if (algoUpper.includes('PSS') || keyType === 'rsa-pss') {
        const hash = algoUpper.includes('512') ? 'sha512' : (algoUpper.includes('384') ? 'sha384' : 'sha256');
        return crypto.verify(
          hash,
          dataBuffer,
          {
            key: pubKeyObj,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
          },
          sigBuffer
        );
      }

      // 3. RSA PKCS#1 v1.5
      if (keyType === 'rsa' || algoUpper.includes('RSA') || algoUpper.includes('PKCS1')) {
        const hash = algoUpper.includes('512') ? 'sha512' : (algoUpper.includes('384') ? 'sha384' : 'sha256');
        return crypto.verify(
          hash,
          dataBuffer,
          {
            key: pubKeyObj,
            padding: crypto.constants.RSA_PKCS1_PADDING,
          },
          sigBuffer
        );
      }

      // 4. ECDSA (NIST P-256, P-384, P-521)
      if (keyType === 'ec' || algoUpper.includes('ECDSA') || algoUpper.includes('EC_SIGN')) {
        const hash = algoUpper.includes('384') ? 'sha384' : (algoUpper.includes('512') ? 'sha512' : 'sha256');
        return crypto.verify(hash, dataBuffer, pubKeyObj, sigBuffer);
      }

      // Default fallback
      return crypto.verify('SHA256', dataBuffer, pubKeyObj, sigBuffer);
    } catch {
      return false;
    }
  }

  /**
   * Thoroughly verifies an entire SignedPackageBundle:
   * 1. Verifies each individual content file matches its manifest sha256.
   * 2. Recomputes manifest_hash from content files and verifies it matches manifest.manifest_hash.
   * 3. Verifies cryptographic signature over the manifest_hash or target.
   * 4. Verifies in-toto attestation digest references the manifest_hash.
   */
  static verifyBundle(
    bundle: SignedPackageBundle,
    trustedPublicKeyPem?: string
  ): VerificationResult {
    const errors: string[] = [];
    let manifestHashMatched = true;
    let contentHashesMatched = true;
    let tampered = false;

    if (!bundle) {
      return {
        valid: false,
        tampered: true,
        keyId: 'unknown',
        keyVersion: 'unknown',
        algorithm: 'unknown',
        manifestHashMatched: false,
        contentHashesMatched: false,
        signatureVerified: false,
        errors: ['Package bundle is null or undefined'],
      };
    }

    const { manifest, files, signature, attestation } = bundle;

    if (!manifest) {
      errors.push('Missing package manifest in bundle');
      manifestHashMatched = false;
      tampered = true;
    }

    if (!files) {
      errors.push('Missing content files in bundle');
      contentHashesMatched = false;
      tampered = true;
    }

    if (!signature) {
      errors.push('Missing cryptographic signature in bundle');
      tampered = true;
    }

    if (!attestation) {
      errors.push('Missing release attestation statement in bundle');
      tampered = true;
    }

    const fileEntries: Array<{ path: string; sha256: string }> = [];

    // 1. Check all content files if manifest and files exist
    if (manifest && files) {
      if (Array.isArray(manifest.contents)) {
        for (const manifestEntry of manifest.contents) {
          const actualFile = files instanceof Map ? files.get(manifestEntry.path) : (files as any)[manifestEntry.path];
          if (!actualFile) {
            errors.push(`Missing content file in package bundle: ${manifestEntry.path}`);
            contentHashesMatched = false;
            tampered = true;
            continue;
          }

          const actualHash = sha256(actualFile.content);
          if (actualHash !== manifestEntry.sha256) {
            errors.push(
              `Content hash mismatch for ${manifestEntry.path}. Manifest: ${manifestEntry.sha256}, Actual: ${actualHash}`
            );
            contentHashesMatched = false;
            tampered = true;
          }

          fileEntries.push({ path: manifestEntry.path, sha256: actualHash });
        }

        // Check if extra files exist in bundle that are not in manifest
        const allowedEnvelopeFiles = new Set(['manifest.json', 'attestation.json']);
        const entriesIterator = files instanceof Map ? files.entries() : Object.entries(files);
        for (const [filePath] of entriesIterator) {
          if (allowedEnvelopeFiles.has(filePath)) continue;
          const inManifest = manifest.contents.some((c) => c.path === filePath);
          if (!inManifest) {
            errors.push(`Unregistered file present in package bundle: ${filePath}`);
            tampered = true;
          }
        }
      } else {
        errors.push('Manifest contents is not an array');
        manifestHashMatched = false;
        tampered = true;
      }
    }

    // 2. Recompute manifest root hash
    if (manifest) {
      const recomputedRootHash = computeManifestRootHash(fileEntries);
      if (recomputedRootHash !== manifest.manifest_hash) {
        errors.push(
          `Manifest root hash mismatch. Declared: ${manifest.manifest_hash}, Recomputed: ${recomputedRootHash}`
        );
        manifestHashMatched = false;
        tampered = true;
      }
    }

    // 3. Verify Signature over manifest.manifest_hash
    let signatureVerified = false;
    if (manifest && signature) {
      signatureVerified = this.verifySignature(
        manifest.manifest_hash,
        signature,
        trustedPublicKeyPem
      );

      if (!signatureVerified) {
        errors.push(`Cryptographic Ed25519 signature verification failed for key ID: ${signature.key_id}`);
        tampered = true;
      }
    } else {
      tampered = true;
    }

    // 4. Verify Attestation subject
    if (manifest && attestation && Array.isArray(attestation.subject)) {
      const tarSubject = attestation.subject.find((s) => s.name?.endsWith('.tar.gz'));
      if (tarSubject && tarSubject.digest?.sha256 !== manifest.manifest_hash) {
        errors.push(
          `Attestation subject digest does not match manifest hash: ${tarSubject.digest?.sha256} vs ${manifest.manifest_hash}`
        );
        tampered = true;
      }
    } else if (attestation && !Array.isArray(attestation.subject)) {
      errors.push('Attestation subject is not a valid array');
      tampered = true;
    }

    const valid = errors.length === 0 && signatureVerified && contentHashesMatched && manifestHashMatched;

    return {
      valid,
      tampered,
      keyId: signature?.key_id || 'unknown',
      keyVersion: signature?.key_version || 'unknown',
      algorithm: signature?.algorithm || 'unknown',
      manifestHashMatched,
      contentHashesMatched,
      signatureVerified,
      errors,
    };
  }
}
