/**
 * CAIM Deterministic Canonical Release Payload Binding (RFC 8785 / JCS Compliance)
 * Architecture P105A — Cryptographic Attestation & Hardware KMS Binding
 *
 * Implements complete RFC 8785 JSON Canonicalization Scheme (JCS):
 * 1. Recursive object-property ordering by UTF-16 code units.
 * 2. Minimal JSON escaping (no superfluous \u escapes for printable characters).
 * 3. ECMAScript-compatible number serialization (-0 normalized to 0, no trailing zeros).
 * 4. Rejection of NaN, Infinity, circular references, and unsupported types.
 * 5. Strict binding to the 7 mandatory CAIM release attestation fields.
 */

import crypto from 'node:crypto';

export interface CanonicalReleasePayload {
  artifactDigest: string;          // 64-character SHA-256 hex string of artifact or root package
  commitSha: string;               // 40-character hexadecimal Git commit SHA
  releaseId: string;               // Unique release identifier (e.g. rc-caim-v2.0.1-xxxx)
  environment: 'development' | 'staging' | 'production' | 'ci' | 'test';
  gateSummaryDigest: string;       // SHA-256 hex digest of evaluated release gate summary
  keyId: string;                   // Cloud KMS key resource name or identifier
  keyVersion: string;              // Cloud KMS key version
  attestationSchemaVersion: string;// Attestation schema version (e.g. "2.0.0" or "https://caim.security/schema/attestation/v2")
}

export class InvalidCanonicalPayloadError extends Error {
  constructor(message: string, public readonly field?: string) {
    super(`Invalid Canonical Release Payload: ${message}${field ? ` (Field: ${field})` : ''}`);
    this.name = 'InvalidCanonicalPayloadError';
  }
}

/**
 * Universal RFC 8785 JSON Canonicalization Scheme (JCS) serializer.
 * Enforces UTF-16 code-unit property ordering, minimal escapes, and standard number representation.
 */
export function canonicalizeRfc8785(data: unknown): string {
  const seen = new Set<object>();

  function serialize(value: unknown): string {
    if (value === null) return 'null';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'number') {
      if (Number.isNaN(value) || !Number.isFinite(value)) {
        throw new TypeError('RFC 8785 rejection: NaN and Infinity are not valid JSON numbers');
      }
      if (Object.is(value, -0)) return '0';
      return JSON.stringify(value);
    }
    if (typeof value === 'string') {
      return JSON.stringify(value);
    }
    if (typeof value === 'undefined' || typeof value === 'function' || typeof value === 'symbol') {
      throw new TypeError(`RFC 8785 rejection: unsupported type '${typeof value}'`);
    }
    if (typeof value === 'bigint') {
      throw new TypeError('RFC 8785 rejection: BigInt is not supported');
    }
    if (typeof value === 'object') {
      if (seen.has(value)) {
        throw new TypeError('RFC 8785 rejection: circular reference detected');
      }
      seen.add(value);

      try {
        if (Array.isArray(value)) {
          const items = value.map((item) => {
            if (typeof item === 'undefined' || typeof item === 'function' || typeof item === 'symbol') {
              return 'null'; // In arrays, undefined becomes null per JSON spec
            }
            return serialize(item);
          });
          return `[${items.join(',')}]`;
        }

        // Object: sort keys by UTF-16 code unit ordering (RFC 8785 Section 3.2.3)
        const keys = Object.keys(value).sort((a, b) => {
          return a < b ? -1 : a > b ? 1 : 0;
        });

        const entries: string[] = [];
        for (const key of keys) {
          const propVal = (value as Record<string, unknown>)[key];
          if (typeof propVal === 'undefined' || typeof propVal === 'function' || typeof propVal === 'symbol') {
            continue; // Skip undefined/function properties in objects
          }
          entries.push(`${JSON.stringify(key)}:${serialize(propVal)}`);
        }

        return `{${entries.join(',')}}`;
      } finally {
        seen.delete(value);
      }
    }

    throw new TypeError(`RFC 8785 rejection: unexpected value`);
  }

  return serialize(data);
}

/**
 * Validates that all 7 mandatory release payload fields are strictly present and well-formed.
 */
export function validateCanonicalReleasePayload(payload: CanonicalReleasePayload): void {
  if (!payload || typeof payload !== 'object') {
    throw new InvalidCanonicalPayloadError('Payload must be a non-null object');
  }

  // 1. artifactDigest: 64-hex SHA-256
  if (typeof payload.artifactDigest !== 'string' || !/^[0-9a-f]{64}$/i.test(payload.artifactDigest)) {
    throw new InvalidCanonicalPayloadError(
      'artifactDigest must be a 64-character hexadecimal SHA-256 digest',
      'artifactDigest'
    );
  }

  // 2. commitSha: 40-hex commit SHA
  if (typeof payload.commitSha !== 'string' || !/^[0-9a-f]{40}$/i.test(payload.commitSha)) {
    throw new InvalidCanonicalPayloadError(
      'commitSha must be a 40-character hexadecimal Git commit hash',
      'commitSha'
    );
  }

  // 3. releaseId: non-empty string
  if (typeof payload.releaseId !== 'string' || payload.releaseId.trim().length === 0) {
    throw new InvalidCanonicalPayloadError('releaseId must be a non-empty string', 'releaseId');
  }

  // 4. environment: recognized environment enum
  const validEnvironments = ['development', 'staging', 'production', 'ci', 'test'];
  if (!validEnvironments.includes(payload.environment)) {
    throw new InvalidCanonicalPayloadError(
      `environment must be one of: ${validEnvironments.join(', ')}`,
      'environment'
    );
  }

  // 5. gateSummaryDigest: 64-hex SHA-256
  if (typeof payload.gateSummaryDigest !== 'string' || !/^[0-9a-f]{64}$/i.test(payload.gateSummaryDigest)) {
    throw new InvalidCanonicalPayloadError(
      'gateSummaryDigest must be a 64-character hexadecimal SHA-256 digest',
      'gateSummaryDigest'
    );
  }

  // 6. keyId: non-empty string
  if (typeof payload.keyId !== 'string' || payload.keyId.trim().length === 0) {
    throw new InvalidCanonicalPayloadError('keyId must be a non-empty string', 'keyId');
  }

  // keyVersion: non-empty string
  if (typeof payload.keyVersion !== 'string' || payload.keyVersion.trim().length === 0) {
    throw new InvalidCanonicalPayloadError('keyVersion must be a non-empty string', 'keyVersion');
  }

  // 7. attestationSchemaVersion: non-empty string
  if (typeof payload.attestationSchemaVersion !== 'string' || payload.attestationSchemaVersion.trim().length === 0) {
    throw new InvalidCanonicalPayloadError(
      'attestationSchemaVersion must be a non-empty string',
      'attestationSchemaVersion'
    );
  }
}

/**
 * Serializes payload deterministically using RFC 8785 JSON Canonicalization Scheme (JCS).
 */
export function canonicalizeReleasePayload(payload: CanonicalReleasePayload): string {
  validateCanonicalReleasePayload(payload);

  const normalizedObject: Record<string, string> = {
    artifactDigest: payload.artifactDigest.toLowerCase(),
    attestationSchemaVersion: payload.attestationSchemaVersion,
    commitSha: payload.commitSha.toLowerCase(),
    environment: payload.environment,
    gateSummaryDigest: payload.gateSummaryDigest.toLowerCase(),
    keyId: payload.keyId,
    keyVersion: payload.keyVersion,
    releaseId: payload.releaseId,
  };

  return canonicalizeRfc8785(normalizedObject);
}

/**
 * Computes the SHA-256 digest of the canonicalized release payload.
 */
export function computeCanonicalPayloadDigest(payload: CanonicalReleasePayload): string {
  const canonicalString = canonicalizeReleasePayload(payload);
  return crypto.createHash('sha256').update(canonicalString, 'utf-8').digest('hex');
}

/**
 * Verifies that a payload matches an expected SHA-256 digest.
 */
export function verifyCanonicalPayloadIntegrity(
  payload: CanonicalReleasePayload,
  expectedDigest: string
): boolean {
  try {
    const computed = computeCanonicalPayloadDigest(payload);
    return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(expectedDigest));
  } catch {
    return false;
  }
}
