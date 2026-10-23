const SENSITIVE_KEY_PATTERNS = [
  /key/i,
  /secret/i,
  /token/i,
  /password/i,
  /credential/i,
  /private/i,
  /auth/i,
  /signature/i,
];

/**
 * Redacts a sensitive string value preserving type.
 */
export function redactSecret(value: string | undefined | null): string {
  if (!value) return '[EMPTY]';
  if (value.length <= 6) return '***[REDACTED]***';
  return `${value.substring(0, 3)}...[REDACTED]...${value.substring(value.length - 2)}`;
}

/**
 * Deeply redacts sensitive keys in an object tree.
 */
export function redactObject<T extends Record<string, any>>(obj: T): Record<string, any> {
  if (!obj || typeof obj !== 'object') return obj;

  const result: Record<string, any> = Array.isArray(obj) ? [] : {};

  for (const [key, val] of Object.entries(obj)) {
    const isSensitive = SENSITIVE_KEY_PATTERNS.some((pattern) => pattern.test(key));

    if (isSensitive && typeof val === 'string') {
      result[key] = redactSecret(val);
    } else if (val && typeof val === 'object') {
      result[key] = redactObject(val);
    } else {
      result[key] = val;
    }
  }

  return result;
}
