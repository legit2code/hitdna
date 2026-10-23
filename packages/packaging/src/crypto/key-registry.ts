export interface KeyMetadata {
  keyId: string;
  keyVersion: string;
  publicKeyPem: string;
  algorithm: string;
  status: 'ACTIVE' | 'ROTATED' | 'REVOKED';
  validFrom: string;
  validUntil?: string;
  description?: string;
}

export class KeyRegistry {
  private keys: Map<string, KeyMetadata> = new Map();
  private activeKeyId: string | null = null;

  constructor() {}

  /**
   * Registers a public key metadata entry.
   */
  registerKey(metadata: KeyMetadata, makeActive: boolean = false): void {
    const compositeKey = `${metadata.keyId}@${metadata.keyVersion}`;
    this.keys.set(compositeKey, metadata);
    this.keys.set(metadata.keyId, metadata); // fallback latest lookup

    if (makeActive || !this.activeKeyId) {
      this.activeKeyId = metadata.keyId;
    }
  }

  /**
   * Retrieves a public key by key ID and optional key version.
   */
  getKey(keyId: string, keyVersion?: string): KeyMetadata | undefined {
    if (keyVersion) {
      return this.keys.get(`${keyId}@${keyVersion}`);
    }
    return this.keys.get(keyId);
  }

  getActiveKeyId(): string | null {
    return this.activeKeyId;
  }

  listKeys(): KeyMetadata[] {
    const unique = new Map<string, KeyMetadata>();
    for (const [, meta] of this.keys) {
      unique.set(`${meta.keyId}@${meta.keyVersion}`, meta);
    }
    return Array.from(unique.values());
  }
}
