import crypto from 'node:crypto';
import type { SignatureEnvelope } from '../types.ts';

/**
 * Ed25519 Signer Interface & Cryptographic Implementation
 * Enforces pure Ed25519 signatures with SPKI/PKCS8 standard encoding.
 */

export interface ISigner {
  sign(data: string | Uint8Array, targetId?: string): Promise<SignatureEnvelope>;
  getPublicKeyPem(): string;
  getKeyId(): string;
  getKeyVersion(): string;
  getAlgorithm(): string;
}

export class Ed25519Signer implements ISigner {
  private keyId: string;
  private keyVersion: string;
  private privateKeyPem: string;
  private publicKeyPem: string;

  constructor(options: {
    keyId: string;
    keyVersion: string;
    privateKeyPem: string;
    publicKeyPem?: string;
  }) {
    this.keyId = options.keyId;
    this.keyVersion = options.keyVersion;
    this.privateKeyPem = options.privateKeyPem;

    if (options.publicKeyPem) {
      this.publicKeyPem = options.publicKeyPem;
    } else {
      // Derive public key from private key if not supplied
      const privKeyObj = crypto.createPrivateKey(options.privateKeyPem);
      const pubKeyObj = crypto.createPublicKey(privKeyObj);
      this.publicKeyPem = pubKeyObj.export({ type: 'spki', format: 'pem' }) as string;
    }
  }

  /**
   * Generates a new ephemeral or persistent Ed25519 keypair.
   */
  static generateKeyPair(keyId: string, keyVersion: string = 'v1'): {
    signer: Ed25519Signer;
    publicKeyPem: string;
    privateKeyPem: string;
  } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;

    const signer = new Ed25519Signer({
      keyId,
      keyVersion,
      privateKeyPem: privPem,
      publicKeyPem: pubPem,
    });

    return {
      signer,
      publicKeyPem: pubPem,
      privateKeyPem: privPem,
    };
  }

  getKeyId(): string {
    return this.keyId;
  }

  getKeyVersion(): string {
    return this.keyVersion;
  }

  getPublicKeyPem(): string {
    return this.publicKeyPem;
  }

  getAlgorithm(): string {
    return 'Ed25519';
  }

  /**
   * Signs input data buffer/string and produces a typed SignatureEnvelope.
   */
  async sign(data: string | Uint8Array, targetId?: string): Promise<SignatureEnvelope> {
    const buffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(data);
    const privKeyObj = crypto.createPrivateKey(this.privateKeyPem);

    // Ed25519 signing with Node crypto
    const signatureBuffer = crypto.sign(null, buffer, privKeyObj);
    const signatureBase64 = signatureBuffer.toString('base64');
    const signedAt = new Date().toISOString();
    const sigId = `sig-${this.keyId}-${Date.now()}`;

    return {
      signature_id: sigId,
      target_id: targetId || `target-${Date.now()}`,
      signature_scheme: 'ed25519',
      key_id: this.keyId,
      key_version: this.keyVersion,
      public_key_pem: this.publicKeyPem,
      signature_base64: signatureBase64,
      signed_at: signedAt,
      algorithm: 'Ed25519',
    };
  }
}
