/**
 * Versioned Taint Sanitizer & Transform Registry
 * P16 — Dataflow / Taint Intelligence
 */

import { TaintSanitizerDefinition, TAINT_SANITIZER_REGISTRY_VERSION } from './types.ts';

export class TaintSanitizerRegistry {
  public static readonly REGISTRY_VERSION = TAINT_SANITIZER_REGISTRY_VERSION;

  public static readonly SANITIZERS: TaintSanitizerDefinition[] = [
    // 1. Cryptographic Hashing
    {
      sanitizer_id: 'SAN-CRYPTO-001',
      category: 'CRYPTOGRAPHIC_HASH',
      name: 'Irreversible One-Way Hash',
      description: 'Transforms cleartext data into cryptographic digest (sha256, md5, bcrypt, crypto.createHash).',
      pattern_type: 'FUNCTION_CALL',
      match_functions: [
        'crypto.createHash', 'createHash', 'sha256', 'sha512', 'bcrypt.hash',
        'hashlib.sha256', 'md5', 'argon2.hash'
      ],
      neutralization_power: 1.0,
    },

    // 2. Encryption / Symmetric / Asymmetric
    {
      sanitizer_id: 'SAN-CRYPTO-002',
      category: 'ENCRYPTION',
      name: 'Payload Encryption / Ciphering',
      description: 'Encrypts cleartext payload into ciphertext (crypto.createCipheriv, encrypt, aes.encrypt).',
      pattern_type: 'FUNCTION_CALL',
      match_functions: [
        'crypto.createCipheriv', 'encrypt', 'aes.encrypt', 'rsa.encrypt', 'seal'
      ],
      neutralization_power: 0.95,
    },

    // 3. Secret Redaction & Masking
    {
      sanitizer_id: 'SAN-MASK-001',
      category: 'REDACTION_MASK',
      name: 'Secret Redaction / Masking Transform',
      description: 'Replaces sensitive characters with mask strings (redact, maskSecret, scrub, sanitizeKey).',
      pattern_type: 'FUNCTION_CALL',
      match_functions: [
        'redact', 'maskSecret', 'scrub', 'sanitizeKey', 'mask', 'redactApiKey', 'stripCredentials'
      ],
      match_patterns: [
        /\.replace\(\s*\/[^\/]+\/\s*,\s*["']\*\*\*["']\)/
      ],
      neutralization_power: 0.98,
    },

    // 4. URL / HTML Encoding
    {
      sanitizer_id: 'SAN-ENCODE-001',
      category: 'URL_ENCODING',
      name: 'URL / HTML Entity Encoding',
      description: 'Encodes dangerous characters for safe transport (encodeURIComponent, escapeHtml, sanitizeUrl).',
      pattern_type: 'FUNCTION_CALL',
      match_functions: [
        'encodeURIComponent', 'encodeURI', 'escapeHtml', 'sanitizeUrl', 'DOMPurify.sanitize'
      ],
      neutralization_power: 0.70, // Prevents injection, though cleartext remains
    },

    // 5. Numeric / Primitive Type Cast
    {
      sanitizer_id: 'SAN-CAST-001',
      category: 'NUMERIC_PARSE',
      name: 'Numeric Parsing / Primitive Type Casting',
      description: 'Converts arbitrary input into strict numeric or primitive representation (parseInt, Number, parseFloat).',
      pattern_type: 'FUNCTION_CALL',
      match_functions: [
        'parseInt', 'parseFloat', 'Number', 'Math.floor', 'Math.round', 'int', 'float'
      ],
      neutralization_power: 0.99,
    },

    // 6. Boolean Predicate / Type Guard
    {
      sanitizer_id: 'SAN-GUARD-001',
      category: 'TYPE_CAST_BOOLEAN',
      name: 'Boolean Conversion / Existence Check',
      description: 'Reduces sensitive data to a boolean flag (Boolean(), !!x, Array.isArray()).',
      pattern_type: 'TYPE_GUARD',
      match_functions: ['Boolean', 'Array.isArray', 'isNaN'],
      neutralization_power: 1.0,
    },

    // 7. Schema Validation & Stripping
    {
      sanitizer_id: 'SAN-VALIDATE-001',
      category: 'VALIDATION_CHECK',
      name: 'Strict Schema Parse / Validation',
      description: 'Validates and filters inputs against strict schema (zod.parse, schema.validate, validator.escape).',
      pattern_type: 'MEMBER_METHOD',
      match_methods: ['parse', 'safeParse', 'validate', 'escape'],
      neutralization_power: 0.85,
    }
  ];

  public static getSanitizerById(id: string): TaintSanitizerDefinition | undefined {
    return this.SANITIZERS.find(s => s.sanitizer_id === id);
  }

  public static getAllSanitizers(): TaintSanitizerDefinition[] {
    return [...this.SANITIZERS];
  }
}
