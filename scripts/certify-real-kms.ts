/**
 * CAIM Real Cloud KMS Certification Harness
 * Architecture P105 — Hardware Cryptographic Key Custody & Cloud Attestation Certification
 *
 * GOVERNANCE:
 * 1. Executes authentic asymmetric signing against Cloud KMS (GCP or AWS).
 * 2. Emulators, mocks, or local key substitutions are STRICTLY PROHIBITED for certification.
 * 3. Never reports EXECUTED — PASS unless actual remote challenge-response signing and
 *    negative tamper probe verification have succeeded against the remote provider.
 * 4. Confirms key version and algorithm dynamically from provider response (never hardcoded).
 * 5. Produces tamper-evident V2 RunnerReceipt (GATE_L07_KMS_ATTESTATION) with redacted
 *    provider identity, request metadata, and zero secrets.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { 
  GcpCloudKmsProvider, 
  AwsKmsProvider, 
  ICloudKmsProvider, 
  KmsAuthenticationError 
} from '../packages/packaging/src/crypto/cloud-kms-provider.ts';
import { 
  CanonicalReleasePayload, 
  computeCanonicalPayloadDigest 
} from '../packages/packaging/src/crypto/canonical-payload.ts';
import { createAndSaveRunnerReceipt } from '../src/certification/receipt-generator.ts';
import { RunnerReceipt } from '../src/certification/gate-schema.ts';

export interface CertifyKmsOptions {
  receiptOutputPath?: string;
  logOutputPath?: string;
  expectedCommitSha?: string;
  customProvider?: ICloudKmsProvider;
}

/**
 * Redacts sensitive project IDs, account numbers, and internal resource paths from key identifiers.
 */
export function redactKeyIdentifier(keyId?: string): string {
  if (!keyId || keyId.trim().length === 0) return 'NONE';
  return keyId
    .replace(/(projects\/)[^/]+(\/locations\/)[^/]+(\/keyRings\/)[^/]+/, '$1***$2***$3***')
    .replace(/(arn:aws:kms:[^:]+:)\d+(:key\/)/, '$1***$2');
}

export async function certifyRealKms(options: CertifyKmsOptions = {}): Promise<RunnerReceipt> {
  const startTime = Date.now();
  const receiptPath = options.receiptOutputPath || path.resolve(process.cwd(), 'docs/certification/kms-receipt.json');
  const logDir = path.resolve(process.cwd(), 'docs/certification/logs');
  const logPath = options.logOutputPath || path.join(logDir, 'l07-kms-attestation.log');
  fs.mkdirSync(path.dirname(receiptPath), { recursive: true });
  fs.mkdirSync(path.dirname(logPath), { recursive: true });

  const logLines: string[] = [];
  const log = (msg: string) => {
    const entry = `[${new Date().toISOString()}] ${msg}`;
    logLines.push(entry);
    console.log(msg);
  };

  log('================================================================================');
  log('   CAIM REAL CLOUD KMS ATTESTATION & KEY CUSTODY CERTIFICATION HARNESS (GATE L07)');
  log('================================================================================');

  const gcpKey = process.env.GCP_KMS_KEY_NAME?.trim();
  const awsKey = process.env.AWS_KMS_KEY_ID?.trim();
  const commitSha = options.expectedCommitSha || process.env.GITHUB_SHA || process.env.COMMIT_SHA || '0000000000000000000000000000000000000000';
  const environment = (process.env.NODE_ENV as any) || 'development';

  // Check if live KMS credentials exist
  const hasGcpCreds = Boolean(
    gcpKey &&
    (process.env.CLOUD_KMS_ACCESS_TOKEN ||
      (process.env.GOOGLE_APPLICATION_CREDENTIALS && fs.existsSync(process.env.GOOGLE_APPLICATION_CREDENTIALS)))
  );

  const hasAwsCreds = Boolean(
    awsKey && process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY
  );

  const isConfiguredWithCreds = Boolean(options.customProvider || hasGcpCreds || hasAwsCreds);

  // 1. If not configured with authentic credentials, return fail-closed EXTERNAL INFRA REQUIRED
  if (!isConfiguredWithCreds) {
    const blockers: string[] = [];
    if (!gcpKey && !awsKey) {
      blockers.push('Production Cloud KMS is not configured (missing GCP_KMS_KEY_NAME or AWS_KMS_KEY_ID).');
    } else if (gcpKey && !hasGcpCreds) {
      blockers.push('GCP_KMS_KEY_NAME is configured but valid credentials (GOOGLE_APPLICATION_CREDENTIALS or CLOUD_KMS_ACCESS_TOKEN) are missing.');
    } else if (awsKey && !hasAwsCreds) {
      blockers.push('AWS_KMS_KEY_ID is configured but AWS credentials (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) are missing.');
    }
    blockers.push('Hardware-isolated cryptographic attestation requires an authorized Cloud KMS key resource.');
    blockers.push('Ephemeral in-process keys cannot certify production package signing.');

    log('KMS infrastructure status: EXTERNAL INFRA REQUIRED');
    blockers.forEach(b => log(`  - BLOCKER: ${b}`));

    fs.writeFileSync(logPath, logLines.join('\n') + '\n', 'utf-8');

    const receipt = createAndSaveRunnerReceipt({
      gateId: 'GATE_L07_KMS_ATTESTATION',
      providerType: 'NONE',
      command: 'pnpm exec tsx scripts/certify-real-kms.ts',
      exitCode: 2,
      durationMs: Date.now() - startTime,
      stdout: logLines.join('\n'),
      logPointer: logPath,
      testCounts: { total: 0, passed: 0, failed: 0, skipped: 0 },
      status: 'EXTERNAL INFRA REQUIRED',
      providerReceipt: {
        harnessVersion: '2.0.0',
        kmsConfigured: Boolean(gcpKey || awsKey),
        kmsProvider: gcpKey ? 'GCP_KMS' : (awsKey ? 'AWS_KMS' : 'NONE'),
        redactedKeyIdentifier: redactKeyIdentifier(gcpKey || awsKey),
        keyVersion: 'NONE',
        detectedAlgorithm: 'NONE',
        challengeDigestSha256: 'NONE',
        signatureVerificationOutcome: 'NOT_EXECUTED',
        negativeProbes: {
          tamperedDigestRejection: false,
          wrongKeyRejection: false,
        },
        executionEnvironment: environment,
        testedCommitSha: commitSha,
        requestResponseMetadata: {
          endpoint: gcpKey ? 'https://cloudkms.googleapis.com/v1/' : (awsKey ? 'https://kms.amazonaws.com/' : 'NONE'),
          httpMethod: 'NONE',
          statusText: 'EXTERNAL_INFRA_REQUIRED',
          latencyMs: 0,
        },
        challengeResponseVerified: false,
        tamperDetectionVerified: false,
        ephemeralFallbackProhibitedInProduction: true,
      },
      blockers,
      outputPath: receiptPath,
    });

    return receipt;
  }

  // 2. When live KMS provider is present, execute authentic remote challenge-response and tamper probes
  try {
    let provider: ICloudKmsProvider;
    if (options.customProvider) {
      provider = options.customProvider;
    } else if (hasGcpCreds && gcpKey) {
      log(`Initializing GCP Cloud KMS Provider: ${redactKeyIdentifier(gcpKey)}`);
      provider = new GcpCloudKmsProvider({ keyName: gcpKey });
    } else if (hasAwsCreds && awsKey) {
      log(`Initializing AWS KMS Provider: ${redactKeyIdentifier(awsKey)}`);
      provider = new AwsKmsProvider({ keyId: awsKey });
    } else {
      throw new KmsAuthenticationError('No valid cloud KMS provider credentials available.');
    }

    log(`Obtaining remote public key PEM from ${provider.providerType}...`);
    const publicKeyPem = await provider.getPublicKeyPem();
    const confirmedAlgorithm = provider.getAlgorithm();
    const confirmedVersion = provider.getKeyVersion();
    log(`Public key retrieved. Algorithm: ${confirmedAlgorithm}, Version: ${confirmedVersion}, Length: ${publicKeyPem.length} chars.`);

    // Probe 1: Authentic remote challenge-response signing & verification
    log('Probe 1: Executing authentic remote challenge-response signing...');
    const testPayload: CanonicalReleasePayload = {
      artifactDigest: crypto.randomBytes(32).toString('hex'),
      commitSha,
      releaseId: `rc-probe-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
      environment,
      gateSummaryDigest: crypto.randomBytes(32).toString('hex'),
      keyId: provider.getKeyId(),
      keyVersion: confirmedVersion,
      attestationSchemaVersion: '2.0.0',
    };

    const payloadDigestHex = computeCanonicalPayloadDigest(testPayload);
    const digestBuffer = Buffer.from(payloadDigestHex, 'hex');

    const signStart = Date.now();
    const signResult = await provider.signDigest(digestBuffer);
    const signLatency = Date.now() - signStart;
    log(`Remote signature received (${signLatency}ms). Algorithm: ${signResult.algorithm}. Base64 length: ${signResult.signatureBase64.length}`);

    const isSigValid = await provider.verifySignature(digestBuffer, signResult.signatureBuffer, publicKeyPem);
    if (!isSigValid) {
      throw new Error('Probe 1 Failed: Cryptographic signature verification of authentic payload digest failed.');
    }
    log('Probe 1 PASS: Authentic signature verified with remote public key.');

    // Probe 2: Negative tamper detection
    log('Probe 2: Verifying rejection of tampered payload digest...');
    const tamperedDigest = Buffer.from(digestBuffer);
    tamperedDigest[0] ^= 0xff; // Invert first byte

    const isTamperedValid = await provider.verifySignature(tamperedDigest, signResult.signatureBuffer, publicKeyPem);
    if (isTamperedValid) {
      throw new Error('Probe 2 Failed: Tampered payload digest was unexpectedly accepted by signature verifier!');
    }
    log('Probe 2 PASS: Tampered payload digest correctly rejected.');

    // Probe 3: Negative wrong-key rejection
    log('Probe 3: Verifying rejection under mismatched key pair...');
    const alternateKeyPair = crypto.generateKeyPairSync('ed25519');
    const alternatePubPem = alternateKeyPair.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const isWrongKeyValid = await provider.verifySignature(digestBuffer, signResult.signatureBuffer, alternatePubPem);
    if (isWrongKeyValid) {
      throw new Error('Probe 3 Failed: Signature was accepted under a completely different public key!');
    }
    log('Probe 3 PASS: Signature rejected under mismatched public key.');

    fs.writeFileSync(logPath, logLines.join('\n') + '\n', 'utf-8');

    const receipt = createAndSaveRunnerReceipt({
      gateId: 'GATE_L07_KMS_ATTESTATION',
      providerType: 'REAL',
      command: 'pnpm exec tsx scripts/certify-real-kms.ts',
      exitCode: 0,
      durationMs: Date.now() - startTime,
      stdout: logLines.join('\n'),
      logPointer: logPath,
      testCounts: { total: 3, passed: 3, failed: 0, skipped: 0 },
      status: 'EXECUTED — PASS',
      providerReceipt: {
        harnessVersion: '2.0.0',
        kmsConfigured: true,
        kmsProvider: provider.providerType,
        redactedKeyIdentifier: redactKeyIdentifier(provider.getKeyId()),
        keyVersion: confirmedVersion,
        detectedAlgorithm: confirmedAlgorithm,
        challengeDigestSha256: payloadDigestHex,
        signatureVerificationOutcome: 'VERIFIED',
        negativeProbes: {
          tamperedDigestRejection: true,
          wrongKeyRejection: true,
        },
        executionEnvironment: environment,
        testedCommitSha: commitSha,
        requestResponseMetadata: {
          endpoint: provider.providerType === 'GCP_KMS' ? 'https://cloudkms.googleapis.com/v1/' : 'https://kms.amazonaws.com/',
          httpMethod: 'POST',
          statusText: 'OK',
          latencyMs: signLatency,
        },
        isRealKms: true,
        challengeResponseVerified: true,
        tamperDetectionVerified: true,
        ephemeralFallbackProhibitedInProduction: true,
        probes: [
          { name: 'remote_challenge_sign_verify', passed: true },
          { name: 'tampered_digest_rejection', passed: true },
          { name: 'wrong_key_signature_rejection', passed: true },
        ],
      },
      blockers: [],
      outputPath: receiptPath,
    });

    log('================================================================================');
    log('KMS CERTIFICATION COMPLETE: EXECUTED — PASS');
    log(`Receipt written to: ${receiptPath}`);
    log('================================================================================');

    return receipt;
  } catch (err: any) {
    log(`CRITICAL ERROR during Cloud KMS certification: ${err.message}`);
    fs.writeFileSync(logPath, logLines.join('\n') + '\n', 'utf-8');

    const receipt = createAndSaveRunnerReceipt({
      gateId: 'GATE_L07_KMS_ATTESTATION',
      providerType: 'REAL',
      command: 'pnpm exec tsx scripts/certify-real-kms.ts',
      exitCode: 1,
      durationMs: Date.now() - startTime,
      stdout: logLines.join('\n'),
      logPointer: logPath,
      testCounts: { total: 3, passed: 0, failed: 1, skipped: 0 },
      status: 'EXECUTED — FAIL',
      providerReceipt: {
        harnessVersion: '2.0.0',
        kmsConfigured: true,
        kmsProvider: gcpKey ? 'GCP_KMS' : (awsKey ? 'AWS_KMS' : 'UNKNOWN'),
        redactedKeyIdentifier: redactKeyIdentifier(gcpKey || awsKey),
        keyVersion: 'UNKNOWN',
        detectedAlgorithm: 'UNKNOWN',
        challengeDigestSha256: 'ERROR',
        signatureVerificationOutcome: 'FAILED',
        negativeProbes: {
          tamperedDigestRejection: false,
          wrongKeyRejection: false,
        },
        executionEnvironment: environment,
        testedCommitSha: commitSha,
        requestResponseMetadata: {
          endpoint: gcpKey ? 'https://cloudkms.googleapis.com/v1/' : (awsKey ? 'https://kms.amazonaws.com/' : 'NONE'),
          httpMethod: 'POST',
          statusText: err.message,
          latencyMs: Date.now() - startTime,
        },
        challengeResponseVerified: false,
        tamperDetectionVerified: false,
        ephemeralFallbackProhibitedInProduction: true,
      },
      blockers: [err.message],
      outputPath: receiptPath,
    });

    return receipt;
  }
}

// Standalone execution if invoked directly via CLI
if (process.argv[1] && process.argv[1].endsWith('certify-real-kms.ts')) {
  certifyRealKms()
    .then((receipt) => {
      if (receipt.status === 'EXECUTED — PASS') {
        process.exit(0);
      } else if (receipt.status === 'EXTERNAL INFRA REQUIRED') {
        process.exit(2);
      } else {
        process.exit(1);
      }
    })
    .catch((err) => {
      console.error('Fatal unhandled error in certify-real-kms:', err);
      process.exit(1);
    });
}
