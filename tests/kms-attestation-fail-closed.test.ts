/**
 * CAIM Cloud KMS Attestation & Cryptographic Fail-Closed Negative Regression Suite
 * Architecture P105 — Hardware Key Custody, Attestation Binding & Adversarial Verification
 *
 * MANDATORY TEST COVERAGE:
 * 1. Missing credentials -> fail closed / EXTERNAL INFRA REQUIRED
 * 2. Invalid key ID / resource name -> throws KmsInvalidKeyError
 * 3. Unsupported / incorrect signing algorithm -> throws KmsUnsupportedAlgorithmError
 * 4. Tampered artifact digest rejection -> verification returns false
 * 5. Altered release manifest rejection -> verification returns false
 * 6. Forged provider response rejection -> signature fails verification
 * 7. Unauthorized key access rejection -> throws KmsAuthenticationError
 * 8. Remote timeout / network error handling -> throws KmsNetworkTimeoutError
 * 9. Disabled or revoked key rejection -> throws KmsKeyDisabledError
 * 10. Signature replay prevention across releases (different releaseId / commitSha)
 * 11. Cross-environment receipt reuse rejection (evaluator rejects receipt)
 * 12. Attempted local fallback in production -> throws ProductionKeyCustodyViolationError
 * 13. Missing or malformed signature -> verification returns false
 * 14. Partial signing failure -> fails closed, no valid signature envelope returned
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { 
  GcpCloudKmsProvider, 
  AwsKmsProvider, 
  KmsAuthenticationError, 
  KmsInvalidKeyError, 
  KmsKeyDisabledError, 
  KmsUnsupportedAlgorithmError, 
  KmsNetworkTimeoutError, 
  ProductionKeyCustodyViolationError,
  ICloudKmsProvider,
  KmsSignatureResult
} from '../packages/packaging/src/crypto/cloud-kms-provider.ts';
import { 
  KmsSignerBoundary, 
  SigningPolicyViolationError 
} from '../packages/packaging/src/crypto/kms-boundary.ts';
import { Ed25519Signer } from '../packages/packaging/src/crypto/signer.ts';
import { 
  CanonicalReleasePayload, 
  canonicalizeReleasePayload, 
  canonicalizeRfc8785,
  computeCanonicalPayloadDigest, 
  validateCanonicalReleasePayload, 
  verifyCanonicalPayloadIntegrity,
  InvalidCanonicalPayloadError 
} from '../packages/packaging/src/crypto/canonical-payload.ts';
import { SignatureVerifier } from '../packages/packaging/src/crypto/verifier.ts';
import { certifyRealKms, redactKeyIdentifier } from '../scripts/certify-real-kms.ts';
import { evaluateAllReleaseGates } from '../scripts/evaluate-release-gates.ts';
import { createAndSaveRunnerReceipt } from '../src/certification/receipt-generator.ts';

describe('P105 — CAIM Real Cloud KMS Attestation & Cryptographic Certification Suite', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    delete process.env.GCP_KMS_KEY_NAME;
    delete process.env.AWS_KMS_KEY_ID;
    delete process.env.CLOUD_KMS_ACCESS_TOKEN;
    delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
    delete process.env.AWS_ACCESS_KEY_ID;
    delete process.env.AWS_SECRET_ACCESS_KEY;
    delete process.env.CAIM_REQUIRE_CLOUD_KMS;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  // ---------------------------------------------------------------------------
  // Scenario 1: Missing Credentials
  // ---------------------------------------------------------------------------
  describe('Scenario 1 — Missing Credentials Fail-Closed Behavior', () => {
    it('certifyRealKms reports EXTERNAL INFRA REQUIRED when KMS environment variables are missing', async () => {
      const tempReceiptPath = path.resolve(process.cwd(), 'dist/test-kms-missing-receipt.json');
      const tempLogPath = path.resolve(process.cwd(), 'dist/test-kms-missing.log');

      const receipt = await certifyRealKms({
        receiptOutputPath: tempReceiptPath,
        logOutputPath: tempLogPath,
      });

      expect(receipt.status).toBe('EXTERNAL INFRA REQUIRED');
      expect(receipt.providerType).toBe('NONE');
      expect(receipt.testCounts.total).toBe(0);
      expect(receipt.testCounts.passed).toBe(0);
      expect(receipt.blockers.some(b => b.includes('missing GCP_KMS_KEY_NAME or AWS_KMS_KEY_ID'))).toBe(true);

      // Verify receipt file written
      expect(fs.existsSync(tempReceiptPath)).toBe(true);
      const onDisk = JSON.parse(fs.readFileSync(tempReceiptPath, 'utf-8'));
      expect(onDisk.status).toBe('EXTERNAL INFRA REQUIRED');

      // Cleanup
      if (fs.existsSync(tempReceiptPath)) fs.unlinkSync(tempReceiptPath);
      if (fs.existsSync(tempLogPath)) fs.unlinkSync(tempLogPath);
    });

    it('GcpCloudKmsProvider throws KmsAuthenticationError when credentials are missing', async () => {
      const provider = new GcpCloudKmsProvider({
        keyName: 'projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
      });

      const digest = crypto.createHash('sha256').update('test').digest();
      await expect(provider.signDigest(digest)).rejects.toThrow(KmsAuthenticationError);
    });

    it('AwsKmsProvider throws KmsAuthenticationError when AWS credentials are missing', async () => {
      const provider = new AwsKmsProvider({
        keyId: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
      });

      const digest = crypto.createHash('sha256').update('test').digest();
      await expect(provider.signDigest(digest)).rejects.toThrow(KmsAuthenticationError);
    });
  });

  // ---------------------------------------------------------------------------
  // Scenario 2: Invalid Key ID / Resource Name
  // ---------------------------------------------------------------------------
  describe('Scenario 2 — Invalid Key Identifier Format Rejection', () => {
    it('GcpCloudKmsProvider rejects empty or malformed key name', () => {
      expect(() => new GcpCloudKmsProvider({ keyName: '' })).toThrow(KmsInvalidKeyError);
      expect(() => new GcpCloudKmsProvider({ keyName: 'invalid-simple-name' })).toThrow(KmsInvalidKeyError);
      expect(() => new GcpCloudKmsProvider({ keyName: 'projects/123' })).toThrow(KmsInvalidKeyError);
    });

    it('AwsKmsProvider rejects empty or malformed key identifier', () => {
      expect(() => new AwsKmsProvider({ keyId: '' })).toThrow(KmsInvalidKeyError);
      expect(() => new AwsKmsProvider({ keyId: 'invalid-arn-format' })).toThrow(KmsInvalidKeyError);
    });
  });

  // ---------------------------------------------------------------------------
  // Scenario 3: Unsupported / Incorrect Signing Algorithm
  // ---------------------------------------------------------------------------
  describe('Scenario 3 — Unsupported Cryptographic Algorithm Rejection', () => {
    it('GcpCloudKmsProvider rejects unsupported algorithms', () => {
      expect(() => new GcpCloudKmsProvider({
        keyName: 'projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
        algorithm: 'MD5_RSA' as any,
      })).toThrow(KmsUnsupportedAlgorithmError);
    });
  });

  // ---------------------------------------------------------------------------
  // Scenario 4: Tampered Artifact Digest Rejection
  // ---------------------------------------------------------------------------
  describe('Scenario 4 — Tampered Artifact Digest Rejection', () => {
    it('canonical payload integrity verification rejects modified artifact digest', () => {
      const payload: CanonicalReleasePayload = {
        artifactDigest: crypto.createHash('sha256').update('artifact-data').digest('hex'),
        commitSha: 'a'.repeat(40),
        releaseId: 'rc-caim-2.0.1-test',
        environment: 'production',
        gateSummaryDigest: crypto.createHash('sha256').update('gate-summary').digest('hex'),
        keyId: 'projects/caim/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1',
        keyVersion: 'v1',
        attestationSchemaVersion: '2.0.0',
      };

      const originalDigest = computeCanonicalPayloadDigest(payload);

      // Verify authentic integrity
      expect(verifyCanonicalPayloadIntegrity(payload, originalDigest)).toBe(true);

      // Invert one byte of artifactDigest
      const tamperedPayload = {
        ...payload,
        artifactDigest: 'b' + payload.artifactDigest.slice(1),
      };

      expect(verifyCanonicalPayloadIntegrity(tamperedPayload, originalDigest)).toBe(false);
    });

    it('SignatureVerifier rejects signature when data payload is tampered', async () => {
      const { signer, publicKeyPem } = Ed25519Signer.generateKeyPair('test-key', 'v1');
      const originalData = 'caim-attestation-v2-digest-data';
      const envelope = await signer.sign(originalData);

      // Authentic matches
      expect(SignatureVerifier.verifySignature(originalData, envelope, publicKeyPem)).toBe(true);

      // Tampered data rejected
      const tamperedData = 'caim-attestation-v2-digest-data-tampered';
      expect(SignatureVerifier.verifySignature(tamperedData, envelope, publicKeyPem)).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Scenario 5: Altered Release Manifest Rejection
  // ---------------------------------------------------------------------------
  describe('Scenario 5 — Altered Release Manifest Rejection', () => {
    it('SignatureVerifier.verifyBundle rejects bundle with modified manifest_hash', () => {
      const testKey = Ed25519Signer.generateKeyPair('test-key', 'v1');
      const sampleManifest: any = {
        package_id: 'pkg-1',
        manifest_hash: '1111111111111111111111111111111111111111111111111111111111111111',
        contents: [{ path: 'test.txt', sha256: crypto.createHash('sha256').update('hello').digest('hex') }],
      };

      const testEnvelope = {
        signature_id: 'sig-1',
        target_id: 'pkg-1',
        signature_scheme: 'ed25519' as const,
        key_id: 'test-key',
        key_version: 'v1',
        public_key_pem: testKey.publicKeyPem,
        signature_base64: 'invalid-tampered-signature',
        signed_at: new Date().toISOString(),
        algorithm: 'Ed25519' as const,
      };

      const bundle: any = {
        package_id: 'pkg-1',
        manifest: sampleManifest,
        files: new Map([['test.txt', { content: 'hello' }]]),
        signature: testEnvelope,
        attestation: { subject: [{ name: 'test.tar.gz', digest: { sha256: sampleManifest.manifest_hash } }] },
      };

      const res = SignatureVerifier.verifyBundle(bundle, testKey.publicKeyPem);
      expect(res.valid).toBe(false);
      expect(res.tampered).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Scenario 6: Forged Provider Response Rejection
  // ---------------------------------------------------------------------------
  describe('Scenario 6 — Forged Provider Response Rejection', () => {
    it('SignatureVerifier rejects arbitrary or forged base64 signature strings', () => {
      const fakeEnvelope: any = {
        signature_id: 'sig-forged',
        target_id: 'pkg-target',
        signature_scheme: 'ed25519',
        key_id: 'fake-key',
        key_version: 'v1',
        public_key_pem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAZg==\n-----END PUBLIC KEY-----',
        signature_base64: Buffer.from('attacker-forged-payload').toString('base64'),
        signed_at: new Date().toISOString(),
        algorithm: 'Ed25519',
      };

      const isValid = SignatureVerifier.verifySignature('caim-data', fakeEnvelope);
      expect(isValid).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Scenario 7: Unauthorized Key Access Rejection
  // ---------------------------------------------------------------------------
  describe('Scenario 7 — Unauthorized Key Access (401/403) Rejection', () => {
    it('GcpCloudKmsProvider maps HTTP 403 response to KmsAuthenticationError', async () => {
      process.env.CLOUD_KMS_ACCESS_TOKEN = 'test-token-123';

      const mockTransport = async () => {
        return new Response('Permission denied on resource', { status: 403, statusText: 'Forbidden' });
      };

      const provider = new GcpCloudKmsProvider({
        keyName: 'projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
        transport: mockTransport as any,
      });

      const digest = crypto.createHash('sha256').update('test-payload').digest();
      await expect(provider.signDigest(digest)).rejects.toThrow(KmsAuthenticationError);
    });
  });

  // ---------------------------------------------------------------------------
  // Scenario 8: Remote Timeout / Network Error Handling
  // ---------------------------------------------------------------------------
  describe('Scenario 8 — Remote Network Timeout Handling', () => {
    it('GcpCloudKmsProvider aborts and throws KmsNetworkTimeoutError on timeout', async () => {
      process.env.CLOUD_KMS_ACCESS_TOKEN = 'test-token-123';

      const mockHangingTransport = async (_url: string, init: RequestInit) => {
        return new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => {
            const err = new Error('The operation was aborted');
            err.name = 'AbortError';
            reject(err);
          });
        });
      };

      const provider = new GcpCloudKmsProvider({
        keyName: 'projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
        timeoutMs: 50, // fast timeout for test
        transport: mockHangingTransport as any,
      });

      const digest = crypto.createHash('sha256').update('test-payload').digest();
      await expect(provider.signDigest(digest)).rejects.toThrow(KmsNetworkTimeoutError);
    });
  });

  // ---------------------------------------------------------------------------
  // Scenario 9: Disabled or Revoked Key Rejection
  // ---------------------------------------------------------------------------
  describe('Scenario 9 — Disabled or Revoked Key Rejection', () => {
    it('GcpCloudKmsProvider detects DISABLED or DESTROYED key version', async () => {
      process.env.CLOUD_KMS_ACCESS_TOKEN = 'test-token-123';

      const mockTransport = async () => {
        return new Response('Key version is DISABLED in Cloud KMS', { status: 400 });
      };

      const provider = new GcpCloudKmsProvider({
        keyName: 'projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
        transport: mockTransport as any,
      });

      const digest = crypto.createHash('sha256').update('test-payload').digest();
      await expect(provider.signDigest(digest)).rejects.toThrow(KmsKeyDisabledError);
    });
  });

  // ---------------------------------------------------------------------------
  // Scenario 10: Signature Replay Prevention Across Releases
  // ---------------------------------------------------------------------------
  describe('Scenario 10 — Signature Replay Prevention Across Releases', () => {
    it('different releaseId or commitSha produces different canonical digest preventing signature reuse', () => {
      const payloadV1: CanonicalReleasePayload = {
        artifactDigest: crypto.createHash('sha256').update('shared-artifact').digest('hex'),
        commitSha: '1'.repeat(40),
        releaseId: 'rc-caim-2.0.1-rc1',
        environment: 'production',
        gateSummaryDigest: crypto.createHash('sha256').update('gates').digest('hex'),
        keyId: 'projects/caim/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1',
        keyVersion: 'v1',
        attestationSchemaVersion: '2.0.0',
      };

      const payloadV2: CanonicalReleasePayload = {
        ...payloadV1,
        releaseId: 'rc-caim-2.0.1-rc2', // different release ID
      };

      const digestV1 = computeCanonicalPayloadDigest(payloadV1);
      const digestV2 = computeCanonicalPayloadDigest(payloadV2);

      expect(digestV1).not.toBe(digestV2);
      expect(verifyCanonicalPayloadIntegrity(payloadV2, digestV1)).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Scenario 11: Cross-Environment Receipt Reuse Rejection
  // ---------------------------------------------------------------------------
  describe('Scenario 11 — Cross-Environment Receipt Reuse Rejection', () => {
    it('evaluateAllReleaseGates rejects receipt when environment does not match expectedEnvironment', () => {
      const tempDir = path.resolve(process.cwd(), 'dist/test-receipts-env-mismatch');
      fs.mkdirSync(tempDir, { recursive: true });

      // Generate receipt for 'development'
      createAndSaveRunnerReceipt({
        gateId: 'GATE_L07_KMS_ATTESTATION',
        environment: 'development',
        providerType: 'REAL',
        command: 'pnpm exec tsx scripts/certify-real-kms.ts',
        exitCode: 0,
        durationMs: 10,
        stdout: 'passed',
        logPointer: '/logs/kms.log',
        testCounts: { total: 3, passed: 3, failed: 0, skipped: 0 },
        status: 'EXECUTED — PASS',
        providerReceipt: {
          isRealKms: true,
          challengeResponseVerified: true,
          tamperDetectionVerified: true,
        },
        outputPath: path.join(tempDir, 'kms-receipt.json'),
      });

      // Evaluate expecting 'production' environment
      const manifest = evaluateAllReleaseGates({
        receiptsDir: tempDir,
        expectedEnvironment: 'production',
        releaseFreeze: true,
      });

      const kmsGate = manifest.gates.find(g => g.gateId === 'GATE_L07_KMS_ATTESTATION');
      expect(kmsGate?.status).toBe('EXECUTED — FAIL');
      expect(kmsGate?.blockers.some(b => b.includes('ENVIRONMENT_MISMATCH'))).toBe(true);

      // Cleanup
      fs.rmSync(tempDir, { recursive: true, force: true });
    });
  });

  // ---------------------------------------------------------------------------
  // Scenario 12: Attempted Local Fallback in Production
  // ---------------------------------------------------------------------------
  describe('Scenario 12 — Production Key Custody Violation on Local Fallback', () => {
    it('KmsSignerBoundary.createDefault throws ProductionKeyCustodyViolationError in production', () => {
      process.env.NODE_ENV = 'production';
      expect(() => KmsSignerBoundary.createDefault()).toThrow(ProductionKeyCustodyViolationError);
    });

    it('KmsSignerBoundary.fromPrivateKeyPem throws ProductionKeyCustodyViolationError in production', () => {
      process.env.NODE_ENV = 'production';
      const fakePrivPem = '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIF...\n-----END PRIVATE KEY-----';
      expect(() => KmsSignerBoundary.fromPrivateKeyPem('k1', 'v1', fakePrivPem)).toThrow(
        ProductionKeyCustodyViolationError
      );
    });

    it('KmsSignerBoundary.createDefault throws when CAIM_REQUIRE_CLOUD_KMS is true', () => {
      process.env.CAIM_REQUIRE_CLOUD_KMS = 'true';
      expect(() => KmsSignerBoundary.createDefault()).toThrow(ProductionKeyCustodyViolationError);
    });
  });

  // ---------------------------------------------------------------------------
  // Scenario 13: Missing or Malformed Signature
  // ---------------------------------------------------------------------------
  describe('Scenario 13 — Missing or Malformed Signature Rejection', () => {
    it('SignatureVerifier.verifySignature returns false for missing or auto-signed signature', () => {
      expect(SignatureVerifier.verifySignature('data', null as any)).toBe(false);
      expect(SignatureVerifier.verifySignature('data', { signature_base64: '' } as any)).toBe(false);
      expect(SignatureVerifier.verifySignature('data', { signature_base64: 'auto-signed' } as any)).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Scenario 14: Partial Signing Failure
  // ---------------------------------------------------------------------------
  describe('Scenario 14 — Partial Signing Failure Rejection', () => {
    it('KmsSignerBoundary.signCanonicalPayload throws SigningPolicyViolationError when gateResult.allowed is false', async () => {
      const boundary = KmsSignerBoundary.createDefault('test-k', 'v1');
      const payload: CanonicalReleasePayload = {
        artifactDigest: crypto.randomBytes(32).toString('hex'),
        commitSha: '0'.repeat(40),
        releaseId: 'rel-1',
        environment: 'test',
        gateSummaryDigest: crypto.randomBytes(32).toString('hex'),
        keyId: 'k1',
        keyVersion: 'v1',
        attestationSchemaVersion: '2.0.0',
      };

      const rejectedGateResult = {
        allowed: false,
        gate_name: 'GATE_PRE_SIGN_POLICY',
        blockers: ['UNAUTHORIZED_PACKAGE_RELEASE'],
      };

      await expect(
        boundary.signCanonicalPayload(payload, rejectedGateResult as any)
      ).rejects.toThrow(SigningPolicyViolationError);
    });
  });

  // ===========================================================================
  // P105A — TASK 1: RFC 8785 INTEROPERABILITY & CONFORMANCE
  // ===========================================================================
  describe('P105A — Task 1: RFC 8785 Interoperability & Conformance', () => {
    it('1.1: Recursive object-property ordering by UTF-16 code units', () => {
      const input = {
        z: { b: 2, a: 1 },
        a: { d: 4, c: 3 },
      };
      const canonical = canonicalizeRfc8785(input);
      expect(canonical).toBe('{"a":{"c":3,"d":4},"z":{"a":1,"b":2}}');
    });

    it('1.2: UTF-16 property-name ordering with Unicode characters', () => {
      // RFC 8785 Section 3.2.3: comparison is based on UTF-16 code units
      const input = {
        '\u20ac': 'euro',     // U+20AC (8364)
        '\u00e9': 'e-acute',  // U+00E9 (233)
        'a': 'latin-a',       // U+0061 (97)
        'A': 'latin-A',       // U+0041 (65)
        'aa': 'latin-aa',     // 'A' < 'a' < 'aa' < '\u00e9' < '\u20ac'
      };
      const canonical = canonicalizeRfc8785(input);
      const keys = Object.keys(JSON.parse(canonical));
      expect(keys).toEqual(['A', 'a', 'aa', '\u00e9', '\u20ac']);
    });

    it('1.3: Unicode escaping: printable characters preserved without extra \\u escapes', () => {
      const input = {
        text: 'Hello world! Café ☕ €',
        controls: 'Line1\nLine2\tTab\rReturn',
      };
      const canonical = canonicalizeRfc8785(input);
      // Raw UTF-8 printable preserved, control characters escaped
      expect(canonical).toContain('Café ☕ €');
      expect(canonical).toContain('\\nLine2\\tTab\\rReturn');
    });

    it('1.4: ECMAScript-compatible number serialization: -0 normalized to 0, decimals and exponents', () => {
      expect(canonicalizeRfc8785({ val: -0 })).toBe('{"val":0}');
      expect(canonicalizeRfc8785({ val: 0 })).toBe('{"val":0}');
      expect(canonicalizeRfc8785({ val: 123.456 })).toBe('{"val":123.456}');
      expect(canonicalizeRfc8785({ val: 1e20 })).toBe('{"val":100000000000000000000}');
      expect(canonicalizeRfc8785({ val: 1e21 })).toBe('{"val":1e+21}');
    });

    it('1.5: Nested arrays and objects formatted strictly with zero extraneous whitespace', () => {
      const input = [
        { b: 2, a: 1 },
        [3, { d: 4, c: 5 }],
      ];
      expect(canonicalizeRfc8785(input)).toBe('[{"a":1,"b":2},[3,{"c":5,"d":4}]]');
    });

    it('1.6: Determinism: different property insertion orders yield identical serialized string and SHA-256 digest', () => {
      const obj1 = { z: 1, m: 2, a: 3, k: { y: 10, b: 20 } };
      const obj2 = { a: 3, k: { b: 20, y: 10 }, z: 1, m: 2 };

      const canon1 = canonicalizeRfc8785(obj1);
      const canon2 = canonicalizeRfc8785(obj2);

      expect(canon1).toBe(canon2);
      const digest1 = crypto.createHash('sha256').update(canon1).digest('hex');
      const digest2 = crypto.createHash('sha256').update(canon2).digest('hex');
      expect(digest1).toBe(digest2);
    });

    it('1.7: Rejection of unsupported values: NaN, Infinity, BigInt, and circular references', () => {
      expect(() => canonicalizeRfc8785({ val: NaN })).toThrow(/RFC 8785 rejection/);
      expect(() => canonicalizeRfc8785({ val: Infinity })).toThrow(/RFC 8785 rejection/);
      expect(() => canonicalizeRfc8785({ val: BigInt(123) })).toThrow(/RFC 8785 rejection/);

      const circular: any = { a: 1 };
      circular.self = circular;
      expect(() => canonicalizeRfc8785(circular)).toThrow(/circular reference/);
    });

    it('1.8: Payload mutation changes the canonical signed digest', () => {
      const payload: CanonicalReleasePayload = {
        artifactDigest: crypto.randomBytes(32).toString('hex'),
        commitSha: 'a'.repeat(40),
        releaseId: 'rc-1',
        environment: 'production',
        gateSummaryDigest: crypto.randomBytes(32).toString('hex'),
        keyId: 'k1',
        keyVersion: 'v1',
        attestationSchemaVersion: '2.0.0',
      };

      const digest1 = computeCanonicalPayloadDigest(payload);

      // Mutate environment
      const mutatedEnv = { ...payload, environment: 'staging' as const };
      const digest2 = computeCanonicalPayloadDigest(mutatedEnv);
      expect(digest1).not.toBe(digest2);

      // Mutate keyId
      const mutatedKey = { ...payload, keyId: 'k2' };
      const digest3 = computeCanonicalPayloadDigest(mutatedKey);
      expect(digest1).not.toBe(digest3);
    });
  });

  // ===========================================================================
  // P105A — TASK 2: CLOUD SIGNATURE COMPATIBILITY & ALGORITHM MATRIX
  // ===========================================================================
  describe('P105A — Task 2: Cloud Signature Compatibility & Algorithm Matrix', () => {
    it('2.1 [OFFLINE]: RSA PKCS#1 v1.5 verification with RSA 2048 keypair', () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });
      const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
      const data = 'caim-release-manifest-hash-data';

      // Sign with RSA-SHA256 PKCS#1 v1.5
      const sign = crypto.createSign('SHA256');
      sign.update(data);
      const signature = sign.sign(privateKey);

      const envelope: any = {
        signature_id: 'sig-rsa-pkcs1',
        target_id: 'target-1',
        signature_scheme: 'rsa_pkcs1_sha256',
        key_id: 'projects/p/locations/l/keyRings/r/cryptoKeys/rsa-key/cryptoKeyVersions/1',
        key_version: 'v1',
        public_key_pem: pubPem,
        signature_base64: signature.toString('base64'),
        signed_at: new Date().toISOString(),
        algorithm: 'RSA_SIGN_PKCS1_2048_SHA256',
      };

      const valid = SignatureVerifier.verifySignature(data, envelope, pubPem);
      expect(valid).toBe(true);

      // Mutated data fails
      expect(SignatureVerifier.verifySignature(data + '-mutated', envelope, pubPem)).toBe(false);
    });

    it('2.2 [OFFLINE]: RSA-PSS verification with RSA 2048 keypair, PSS padding and salt length', () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });
      const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
      const data = 'caim-release-manifest-hash-pss-data';

      // Sign with RSA-PSS padding
      const sign = crypto.createSign('SHA256');
      sign.update(data);
      const signature = sign.sign({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      });

      const envelope: any = {
        signature_id: 'sig-rsa-pss',
        target_id: 'target-1',
        signature_scheme: 'rsa_pss_sha256',
        key_id: 'projects/p/locations/l/keyRings/r/cryptoKeys/pss-key/cryptoKeyVersions/1',
        key_version: 'v1',
        public_key_pem: pubPem,
        signature_base64: signature.toString('base64'),
        signed_at: new Date().toISOString(),
        algorithm: 'RSA_SIGN_PSS_2048_SHA256',
      };

      const valid = SignatureVerifier.verifySignature(data, envelope, pubPem);
      expect(valid).toBe(true);

      // Mutated data fails
      expect(SignatureVerifier.verifySignature(data + '-mutated', envelope, pubPem)).toBe(false);
    });

    it('2.3 [OFFLINE]: ECDSA P-256 (NIST P-256 with SHA-256 and DER ASN.1 signature)', () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1', // NIST P-256
      });
      const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
      const data = 'caim-release-manifest-hash-p256';

      const sign = crypto.createSign('SHA256');
      sign.update(data);
      const signature = sign.sign(privateKey); // DER format

      const envelope: any = {
        signature_id: 'sig-ecdsa-p256',
        target_id: 'target-1',
        signature_scheme: 'ecdsa_sha256',
        key_id: 'projects/p/locations/l/keyRings/r/cryptoKeys/ec-key/cryptoKeyVersions/1',
        key_version: 'v1',
        public_key_pem: pubPem,
        signature_base64: signature.toString('base64'),
        signed_at: new Date().toISOString(),
        algorithm: 'EC_SIGN_P256_SHA256',
      };

      const valid = SignatureVerifier.verifySignature(data, envelope, pubPem);
      expect(valid).toBe(true);
      expect(SignatureVerifier.verifySignature(data + '-mutated', envelope, pubPem)).toBe(false);
    });

    it('2.4 [OFFLINE]: ECDSA P-384 (NIST P-384 with SHA-384 and DER ASN.1 signature)', () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp384r1', // NIST P-384
      });
      const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
      const data = 'caim-release-manifest-hash-p384';

      const sign = crypto.createSign('SHA384');
      sign.update(data);
      const signature = sign.sign(privateKey); // DER format

      const envelope: any = {
        signature_id: 'sig-ecdsa-p384',
        target_id: 'target-1',
        signature_scheme: 'ecdsa_sha384',
        key_id: 'projects/p/locations/l/keyRings/r/cryptoKeys/ec384-key/cryptoKeyVersions/1',
        key_version: 'v1',
        public_key_pem: pubPem,
        signature_base64: signature.toString('base64'),
        signed_at: new Date().toISOString(),
        algorithm: 'EC_SIGN_P384_SHA384',
      };

      const valid = SignatureVerifier.verifySignature(data, envelope, pubPem);
      expect(valid).toBe(true);
      expect(SignatureVerifier.verifySignature(data + '-mutated', envelope, pubPem)).toBe(false);
    });

    it('2.5 [OFFLINE]: Ed25519 verification succeeds only when key type is true ed25519', () => {
      const { signer, publicKeyPem } = Ed25519Signer.generateKeyPair('k-ed', 'v1');
      const data = 'caim-release-ed25519-data';

      return signer.sign(data).then((envelope) => {
        expect(SignatureVerifier.verifySignature(data, envelope, publicKeyPem)).toBe(true);
        expect(SignatureVerifier.verifySignature(data + '-mutated', envelope, publicKeyPem)).toBe(false);
      });
    });

    it('2.6 [OFFLINE]: Provider constraint: AwsKmsProvider rejects Ed25519 with KmsUnsupportedAlgorithmError', () => {
      expect(() => new AwsKmsProvider({
        keyId: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
        algorithm: 'Ed25519' as any,
      })).toThrow(KmsUnsupportedAlgorithmError);
    });

    it('2.7 [OFFLINE]: Incorrect algorithm rejection: verifying RSA-PSS signature with RSA PKCS#1 padding fails', () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });
      const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
      const data = 'test-algorithm-mismatch';

      // Sign with PSS
      const sign = crypto.createSign('SHA256');
      sign.update(data);
      const pssSig = sign.sign({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      });

      // Claim envelope is PKCS#1 v1.5
      const mismatchedEnvelope: any = {
        signature_id: 'sig-mismatch',
        target_id: 'target-1',
        signature_scheme: 'rsa_pkcs1',
        key_id: 'k1',
        key_version: 'v1',
        public_key_pem: pubPem,
        signature_base64: pssSig.toString('base64'),
        signed_at: new Date().toISOString(),
        algorithm: 'RSA_SIGN_PKCS1_2048_SHA256', // Mismatched algorithm
      };

      // Fails verification because padding does not match
      expect(SignatureVerifier.verifySignature(data, mismatchedEnvelope, pubPem)).toBe(false);
    });

    it('2.8 [OFFLINE]: Wrong-key verification failure: signature fails under alternate public key', () => {
      const keyPair1 = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const keyPair2 = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

      const data = 'test-wrong-key';
      const sign = crypto.createSign('SHA256');
      sign.update(data);
      const signature = sign.sign(keyPair1.privateKey);

      const envelope: any = {
        signature_id: 'sig-1',
        target_id: 'target-1',
        signature_scheme: 'rsa_pkcs1',
        key_id: 'k1',
        key_version: 'v1',
        public_key_pem: keyPair1.publicKey.export({ type: 'spki', format: 'pem' }) as string,
        signature_base64: signature.toString('base64'),
        signed_at: new Date().toISOString(),
        algorithm: 'RSA_SIGN_PKCS1_2048_SHA256',
      };

      const alternatePubPem = keyPair2.publicKey.export({ type: 'spki', format: 'pem' }) as string;
      expect(SignatureVerifier.verifySignature(data, envelope, alternatePubPem)).toBe(false);
    });
  });

  // ===========================================================================
  // P105A — TASK 3 & 4: LIVE CERTIFICATION HARNESS & CUSTODY REDACTION
  // ===========================================================================
  describe('P105A — Tasks 3 & 4: Key Custody Redaction & Live Harness Refusal', () => {
    it('3.1: redactKeyIdentifier redacts GCP project, locations, ring and AWS account numbers', () => {
      const gcpKey = 'projects/prod-project-123/locations/us-central1/keyRings/prod-ring/cryptoKeys/prod-key/cryptoKeyVersions/1';
      const redactedGcp = redactKeyIdentifier(gcpKey);
      expect(redactedGcp).not.toContain('prod-project-123');
      expect(redactedGcp).not.toContain('prod-ring');
      expect(redactedGcp).toContain('projects/***/locations/***/keyRings/***');

      const awsKey = 'arn:aws:kms:us-east-1:123456789012:key/99999999-8888-7777-6666-555555555555';
      const redactedAws = redactKeyIdentifier(awsKey);
      expect(redactedAws).not.toContain('123456789012');
      expect(redactedAws).toContain('arn:aws:kms:us-east-1:***:key/');
    });

    it('3.2: With dummy GCP_KMS_KEY_NAME without credentials, harness reports EXTERNAL INFRA REQUIRED (never PASS)', async () => {
      process.env.GCP_KMS_KEY_NAME = 'dummy';

      const tempReceiptPath = path.resolve(process.cwd(), 'dist/test-dummy-gcp-receipt.json');
      const tempLogPath = path.resolve(process.cwd(), 'dist/test-dummy-gcp.log');

      const receipt = await certifyRealKms({
        receiptOutputPath: tempReceiptPath,
        logOutputPath: tempLogPath,
      });

      expect(receipt.status).toBe('EXTERNAL INFRA REQUIRED');
      expect(receipt.providerType).toBe('NONE');
      expect(receipt.blockers.some(b => b.includes('valid credentials'))).toBe(true);

      if (fs.existsSync(tempReceiptPath)) fs.unlinkSync(tempReceiptPath);
      if (fs.existsSync(tempLogPath)) fs.unlinkSync(tempLogPath);
    });

    it('3.3: With dummy GCP_KMS_KEY_NAME and token, harness rejects invalid key name format with EXECUTED — FAIL', async () => {
      process.env.GCP_KMS_KEY_NAME = 'dummy';
      process.env.CLOUD_KMS_ACCESS_TOKEN = 'fake-bearer-token';

      const tempReceiptPath = path.resolve(process.cwd(), 'dist/test-dummy-fail-receipt.json');
      const tempLogPath = path.resolve(process.cwd(), 'dist/test-dummy-fail.log');

      const receipt = await certifyRealKms({
        receiptOutputPath: tempReceiptPath,
        logOutputPath: tempLogPath,
      });

      expect(receipt.status).toBe('EXECUTED — FAIL');
      expect(receipt.blockers.some(b => b.includes('Invalid GCP KMS key resource name format'))).toBe(true);

      if (fs.existsSync(tempReceiptPath)) fs.unlinkSync(tempReceiptPath);
      if (fs.existsSync(tempLogPath)) fs.unlinkSync(tempLogPath);
    });
  });
});


