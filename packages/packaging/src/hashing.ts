import crypto from 'node:crypto';

/**
 * Deterministic Content Hashing & Canonical JSON Serialization
 * Architecture V2.0.1 (Document 17, 18, 21, 21B)
 */

/**
 * Computes SHA-256 hex digest for a string or Uint8Array.
 */
export function sha256(data: string | Uint8Array): string {
  const hash = crypto.createHash('sha256');
  if (typeof data === 'string') {
    hash.update(Buffer.from(data, 'utf-8'));
  } else {
    hash.update(data);
  }
  return hash.digest('hex');
}

/**
 * Deterministically serializes a JavaScript object into canonical JSON with sorted keys.
 * Ensures identical objects produce identical byte-for-byte strings and hashes.
 */
export function canonicalJson(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    const serializedItems = obj.map((item) => canonicalJson(item));
    return `[${serializedItems.join(',')}]`;
  }

  const keys = Object.keys(obj).sort();
  const serializedPairs = keys.map((key) => {
    const val = obj[key];
    if (val === undefined) {
      return null;
    }
    return `${JSON.stringify(key)}:${canonicalJson(val)}`;
  }).filter((p) => p !== null);

  return `{${serializedPairs.join(',')}}`;
}

/**
 * Formats canonical JSON with standard 2-space indentation for human-readable yet deterministic output.
 */
export function deterministicPrettyJson(obj: any): string {
  const parseCanonical = JSON.parse(canonicalJson(obj));
  return JSON.stringify(parseCanonical, null, 2);
}

/**
 * Computes root manifest hash from a list of files with their relative paths and sha256 digests.
 * The files are sorted by path alphabetically to ensure determinism.
 */
export function computeManifestRootHash(
  files: Array<{ path: string; sha256: string }>
): string {
  const sorted = [...files].sort((a, b) => a.path.localeCompare(b.path));
  const combined = sorted.map((f) => `${f.path}:${f.sha256}`).join('\n');
  return sha256(combined);
}

/**
 * Normalizes text content by normalizing line endings to Unix LF (\n).
 */
export function normalizeLineEndings(content: string): string {
  return content.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}
