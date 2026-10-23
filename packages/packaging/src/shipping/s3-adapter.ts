import crypto from 'node:crypto';
import { IShippingTargetAdapter, ShippingOptions } from './adapter.ts';
import { SignedPackageBundle, DeliveryReceipt, ShippingTargetType } from '../types.ts';
import { sha256 } from '../hashing.ts';
import {
  validateS3Destination,
  serializePackageBundleToBytes,
  generateAwsSigV4Headers,
} from './shipping-utils.ts';

export interface S3StorageAdapterOptions {
  bucketName?: string;
  region?: string;
  allowedBuckets?: string[];
  timeoutMs?: number;
  maxSizeBytes?: number;
  simulate?: boolean;
  transport?: (url: string, init: RequestInit) => Promise<Response>;
}

export class S3StorageAdapter implements IShippingTargetAdapter {
  readonly targetType: ShippingTargetType = 'S3_STORAGE';
  private bucketName?: string;
  private region: string;
  private allowedBuckets?: string[];
  private timeoutMs: number;
  private maxSizeBytes: number;
  private simulate?: boolean;
  private transport?: (url: string, init: RequestInit) => Promise<Response>;

  constructor(options: S3StorageAdapterOptions = {}) {
    this.bucketName = options.bucketName || process.env.S3_BUCKET_NAME;
    this.region = options.region || process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1';
    this.allowedBuckets = options.allowedBuckets;
    this.timeoutMs = options.timeoutMs || 10000;
    this.maxSizeBytes = options.maxSizeBytes || 50 * 1024 * 1024; // 50MB default
    this.simulate = options.simulate;
    this.transport = options.transport;
  }

  isConfigured(): boolean {
    const hasBucket = Boolean(this.bucketName || process.env.S3_BUCKET_NAME);
    const hasCreds = Boolean(
      (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) ||
      this.transport // Custom transport counts as configured in test harnesses
    );
    return hasBucket && hasCreds;
  }

  private resolveCredentials(): { accessKeyId: string; secretAccessKey: string; sessionToken?: string } | null {
    const accessKeyId = process.env.AWS_ACCESS_KEY_ID?.trim();
    const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY?.trim();
    const sessionToken = process.env.AWS_SESSION_TOKEN?.trim();

    if (!accessKeyId || !secretAccessKey) {
      if (this.transport) {
        return { accessKeyId: 'TESTKEYID', secretAccessKey: 'TESTSECRETKEY' };
      }
      return null;
    }
    return { accessKeyId, secretAccessKey, sessionToken };
  }

  async ship(
    bundle: SignedPackageBundle,
    options: ShippingOptions
  ): Promise<DeliveryReceipt> {
    const shipmentId = `ship-s3-${Date.now()}-${sha256(bundle.manifest_hash || 'hash').slice(0, 8)}`;
    const shippedAt = new Date().toISOString();
    const auditId = `audit-${shipmentId}`;

    const effectiveBucket = this.bucketName || process.env.S3_BUCKET_NAME;

    // Parse targetLocator or default to canonical tenant/release prefix
    let bucket = effectiveBucket;
    let key = '';

    if (options.targetLocator && options.targetLocator.startsWith('s3://')) {
      const withoutScheme = options.targetLocator.slice(5);
      const slashIdx = withoutScheme.indexOf('/');
      if (slashIdx !== -1) {
        bucket = withoutScheme.slice(0, slashIdx);
        key = withoutScheme.slice(slashIdx + 1);
      } else {
        bucket = withoutScheme;
      }
    }

    if (!key) {
      const tenantPrefix = options.tenantId ? `releases/${options.tenantId}` : `releases/${bundle.manifest?.agent_id || 'default'}`;
      key = `${tenantPrefix}/${bundle.manifest?.version_label || 'v1.0.0'}/bundle.tar.gz`;
    }

    const canonicalLocator = `s3://${bucket}/${key}`;

    // 1. Destination Safety & Tenancy Validation
    const destValidation = validateS3Destination(bucket || '', key, {
      allowedBuckets: this.allowedBuckets,
      expectedTenantId: options.tenantId,
    });

    if (!destValidation.valid) {
      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: canonicalLocator,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature?.signature_id || 'none',
        shipped_at: shippedAt,
        status: 'AUTHORIZATION_DENIED',
        detailed_state: 'AUTHORIZATION_DENIED',
        receipt_locator: null,
        transfer_size_bytes: 0,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'FAILED',
        truth_state: 'FAILED',
        error: destValidation.error,
        metadata: { authorization_denied: true, reason: destValidation.error },
      };
    }

    // 2. Check Configuration & Dev Simulation Invariants
    const isConfigured = this.isConfigured();
    const isDevSim =
      process.env.NODE_ENV !== 'production' &&
      (options.simulate || this.simulate || !isConfigured);

    if (process.env.NODE_ENV === 'production') {
      if (!isConfigured || options.simulate || this.simulate) {
        return {
          shipment_id: shipmentId,
          package_id: bundle.package_id,
          target_type: this.targetType,
          target_locator: canonicalLocator,
          manifest_hash: bundle.manifest_hash,
          signature_id: bundle.signature?.signature_id || 'none',
          shipped_at: shippedAt,
          status: 'NOT_CONFIGURED',
          detailed_state: 'NOT_CONFIGURED',
          receipt_locator: null,
          transfer_size_bytes: 0,
          receipt_signature: null,
          audit_trail_id: auditId,
          truthState: 'NOT_CONFIGURED',
          truth_state: 'NOT_CONFIGURED',
          error: (options.simulate || this.simulate)
            ? 'SIMULATED_DELIVERY is strictly forbidden in production environments'
            : 'S3 storage is not configured (missing credentials or S3_BUCKET_NAME in production)',
          metadata: { configured: isConfigured, simulated: false },
        };
      }
    }

    if (isDevSim) {
      let totalBytes = 0;
      for (const [, f] of bundle.files || []) totalBytes += f.sizeBytes;
      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: canonicalLocator,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature?.signature_id || 'none',
        shipped_at: shippedAt,
        status: 'SIMULATED_DELIVERY',
        detailed_state: 'SIMULATED_DELIVERY',
        receipt_locator: canonicalLocator,
        transfer_size_bytes: totalBytes,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'SIMULATED',
        truth_state: 'SIMULATED',
        metadata: {
          bucket,
          region: this.region,
          simulated: true,
          simulation_notice: 'No active S3 connection configured. Delivery simulated in development mode.',
        },
      };
    }

    // 3. Serialize Bundle & Check Size
    const { bytes, sha256Digest, sizeBytes } = serializePackageBundleToBytes(bundle);
    if (sizeBytes > this.maxSizeBytes) {
      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: canonicalLocator,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature?.signature_id || 'none',
        shipped_at: shippedAt,
        status: 'FAILED',
        detailed_state: 'FAILED',
        receipt_locator: null,
        transfer_size_bytes: 0,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'FAILED',
        truth_state: 'FAILED',
        error: `Payload size (${sizeBytes} bytes) exceeds maximum limit (${this.maxSizeBytes} bytes)`,
      };
    }

    // 4. Resolve Credentials
    const creds = this.resolveCredentials();
    if (!creds) {
      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: canonicalLocator,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature?.signature_id || 'none',
        shipped_at: shippedAt,
        status: 'NOT_CONFIGURED',
        detailed_state: 'NOT_CONFIGURED',
        receipt_locator: null,
        transfer_size_bytes: 0,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'NOT_CONFIGURED',
        truth_state: 'NOT_CONFIGURED',
        error: 'Missing AWS credentials for authentic S3 shipping',
      };
    }

    // 5. Execute Remote PUT Object Request with Bounded Retries
    const s3Url = new URL(`https://${bucket}.s3.${this.region}.amazonaws.com/${key}`);
    const fetchFn = this.transport || fetch;

    let uploadResponse: Response | null = null;
    let attempts = 0;
    const maxAttempts = 3;
    let lastError = '';

    while (attempts < maxAttempts) {
      attempts++;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const headers = generateAwsSigV4Headers({
          method: 'PUT',
          url: s3Url,
          headers: {
            'content-type': 'application/gzip',
            'x-amz-meta-manifest-hash': bundle.manifest_hash,
            'x-amz-meta-package-id': bundle.package_id,
          },
          payloadBytes: bytes,
          region: this.region,
          service: 's3',
          accessKeyId: creds.accessKeyId,
          secretAccessKey: creds.secretAccessKey,
          sessionToken: creds.sessionToken,
        });

        uploadResponse = await fetchFn(s3Url.toString(), {
          method: 'PUT',
          headers,
          body: bytes,
          signal: controller.signal,
        });

        clearTimeout(timer);

        if (uploadResponse.ok) {
          break;
        }

        // Handle throttling or transient server errors
        if (uploadResponse.status === 429 || uploadResponse.status >= 500) {
          lastError = `HTTP ${uploadResponse.status} from S3`;
          if (attempts < maxAttempts) {
            await new Promise((r) => setTimeout(r, 100 * attempts));
            continue;
          }
        } else {
          // Non-retryable error (e.g. 401, 403, 404)
          lastError = `HTTP ${uploadResponse.status} from S3`;
          break;
        }
      } catch (err: any) {
        clearTimeout(timer);
        if (err.name === 'AbortError' || err.message?.includes('aborted')) {
          lastError = `S3 PUT timed out after ${this.timeoutMs}ms`;
        } else {
          lastError = err.message || 'Network error connecting to S3';
        }
        if (attempts >= maxAttempts) break;
      }
    }

    if (!uploadResponse || !uploadResponse.ok) {
      const isAuth = uploadResponse?.status === 401 || uploadResponse?.status === 403;
      const isThrottledOrUnavailable = uploadResponse?.status === 429 || uploadResponse?.status === 503 || lastError.includes('timed out');

      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: canonicalLocator,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature?.signature_id || 'none',
        shipped_at: shippedAt,
        status: isAuth ? 'AUTHORIZATION_DENIED' : isThrottledOrUnavailable ? 'PROVIDER_UNAVAILABLE' : 'FAILED',
        detailed_state: isAuth ? 'AUTHORIZATION_DENIED' : isThrottledOrUnavailable ? 'PROVIDER_UNAVAILABLE' : 'FAILED',
        receipt_locator: null,
        transfer_size_bytes: 0,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'FAILED',
        truth_state: 'FAILED',
        error: `S3 upload failed: ${lastError}`,
      };
    }

    // Capture version ID and request ID
    const versionId = uploadResponse.headers.get('x-amz-version-id');
    const providerRequestId = uploadResponse.headers.get('x-amz-request-id') || uploadResponse.headers.get('x-amz-id-2');

    // 6. Independent Remote Readback Verification (Task 3 items 13-16)
    // Read back the object bytes from S3 and verify the cryptographic digest
    let readbackResponse: Response | null = null;
    try {
      const getHeaders = generateAwsSigV4Headers({
        method: 'GET',
        url: s3Url,
        headers: {},
        payloadBytes: Buffer.alloc(0),
        region: this.region,
        service: 's3',
        accessKeyId: creds.accessKeyId,
        secretAccessKey: creds.secretAccessKey,
        sessionToken: creds.sessionToken,
      });

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      readbackResponse = await fetchFn(s3Url.toString(), {
        method: 'GET',
        headers: getHeaders,
        signal: controller.signal,
      });
      clearTimeout(timer);
    } catch (err: any) {
      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: canonicalLocator,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature?.signature_id || 'none',
        shipped_at: shippedAt,
        status: 'UNKNOWN_REMOTE_STATE',
        detailed_state: 'UNKNOWN_REMOTE_STATE',
        receipt_locator: canonicalLocator,
        transfer_size_bytes: sizeBytes,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'FAILED',
        truth_state: 'FAILED',
        error: `Upload succeeded but readback verification failed: ${err.message}`,
        version_id: versionId,
        provider_request_id: providerRequestId,
      };
    }

    if (!readbackResponse || !readbackResponse.ok) {
      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: canonicalLocator,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature?.signature_id || 'none',
        shipped_at: shippedAt,
        status: 'UNKNOWN_REMOTE_STATE',
        detailed_state: 'UNKNOWN_REMOTE_STATE',
        receipt_locator: canonicalLocator,
        transfer_size_bytes: sizeBytes,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'FAILED',
        truth_state: 'FAILED',
        error: `Remote object readback returned HTTP ${readbackResponse?.status}`,
        version_id: versionId,
        provider_request_id: providerRequestId,
      };
    }

    const readbackArrayBuf = await readbackResponse.arrayBuffer();
    const readbackBuf = Buffer.from(readbackArrayBuf);
    const remoteDigest = crypto.createHash('sha256').update(readbackBuf).digest('hex');

    // 7. Cryptographic Digest Comparison
    if (remoteDigest !== sha256Digest) {
      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: canonicalLocator,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature?.signature_id || 'none',
        shipped_at: shippedAt,
        status: 'INTEGRITY_MISMATCH',
        detailed_state: 'INTEGRITY_MISMATCH',
        receipt_locator: canonicalLocator,
        transfer_size_bytes: sizeBytes,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'FAILED',
        truth_state: 'FAILED',
        artifact_digest: sha256Digest,
        remote_digest: remoteDigest,
        integrity_verified: false,
        error: `Integrity Mismatch: Local digest ${sha256Digest} did not match readback digest ${remoteDigest}`,
        version_id: versionId,
        provider_request_id: providerRequestId,
      };
    }

    // 8. Confirmed Verified Delivery
    return {
      shipment_id: shipmentId,
      package_id: bundle.package_id,
      target_type: this.targetType,
      target_locator: canonicalLocator,
      manifest_hash: bundle.manifest_hash,
      signature_id: bundle.signature?.signature_id || 'none',
      shipped_at: shippedAt,
      status: 'DELIVERED',
      detailed_state: 'DELIVERED_VERIFIED',
      receipt_locator: canonicalLocator,
      transfer_size_bytes: sizeBytes,
      receipt_signature: null,
      audit_trail_id: auditId,
      truthState: 'OBSERVED',
      truth_state: 'OBSERVED',
      artifact_digest: sha256Digest,
      remote_digest: remoteDigest,
      version_id: versionId,
      provider_request_id: providerRequestId,
      integrity_verified: true,
      verified_at: new Date().toISOString(),
      metadata: {
        bucket,
        region: this.region,
        key,
        version_id: versionId,
        provider_request_id: providerRequestId,
        real_delivery: true,
      },
    };
  }

  async verifyRemoteDelivery(
    receipt: DeliveryReceipt
  ): Promise<{ verified: boolean; remoteDigest?: string; error?: string }> {
    if (!receipt.receipt_locator || !receipt.receipt_locator.startsWith('s3://')) {
      return { verified: false, error: 'Invalid S3 receipt locator' };
    }

    const withoutScheme = receipt.receipt_locator.slice(5);
    const slashIdx = withoutScheme.indexOf('/');
    const bucket = slashIdx !== -1 ? withoutScheme.slice(0, slashIdx) : withoutScheme;
    const key = slashIdx !== -1 ? withoutScheme.slice(slashIdx + 1) : '';

    const creds = this.resolveCredentials();
    if (!creds) {
      return { verified: false, error: 'Missing AWS credentials for verification' };
    }

    const s3Url = new URL(`https://${bucket}.s3.${this.region}.amazonaws.com/${key}`);
    const fetchFn = this.transport || fetch;

    try {
      const headers = generateAwsSigV4Headers({
        method: 'GET',
        url: s3Url,
        headers: {},
        payloadBytes: Buffer.alloc(0),
        region: this.region,
        service: 's3',
        accessKeyId: creds.accessKeyId,
        secretAccessKey: creds.secretAccessKey,
        sessionToken: creds.sessionToken,
      });

      const res = await fetchFn(s3Url.toString(), { method: 'GET', headers });
      if (!res.ok) {
        return { verified: false, error: `Remote GET returned HTTP ${res.status}` };
      }

      const buf = Buffer.from(await res.arrayBuffer());
      const digest = crypto.createHash('sha256').update(buf).digest('hex');
      const matches = !receipt.artifact_digest || receipt.artifact_digest === digest;

      return {
        verified: matches,
        remoteDigest: digest,
        error: matches ? undefined : `Digest mismatch: expected ${receipt.artifact_digest}, got ${digest}`,
      };
    } catch (err: any) {
      return { verified: false, error: err.message };
    }
  }

  async healthCheck(): Promise<{ healthy: boolean; details: string }> {
    if (!this.isConfigured()) {
      return {
        healthy: false,
        details: 'S3 cloud storage is not configured (missing bucket or AWS credentials)',
      };
    }
    return {
      healthy: true,
      details: `S3 storage configured for bucket ${this.bucketName || process.env.S3_BUCKET_NAME} in region ${this.region}`,
    };
  }
}
