import crypto from 'node:crypto';
import { IShippingTargetAdapter, ShippingOptions } from './adapter.ts';
import { SignedPackageBundle, DeliveryReceipt, ShippingTargetType } from '../types.ts';
import { sha256 } from '../hashing.ts';
import {
  validateRegistryHost,
  validateAndResolveRegistryHost,
  validateRedirectUrl,
  serializePackageBundleToBytes,
} from './shipping-utils.ts';

export interface OciRegistryAdapterOptions {
  registryHost?: string;
  allowedHosts?: string[];
  insecure?: boolean;
  timeoutMs?: number;
  maxSizeBytes?: number;
  simulate?: boolean;
  transport?: (url: string, init: RequestInit) => Promise<Response>;
  dnsResolver?: (hostname: string) => Promise<{ address: string; family: number }[]>;
}

export class OciRegistryAdapter implements IShippingTargetAdapter {
  readonly targetType: ShippingTargetType = 'OCI_REGISTRY';
  private registryHost?: string;
  private allowedHosts?: string[];
  private insecure: boolean;
  private timeoutMs: number;
  private maxSizeBytes: number;
  private simulate?: boolean;
  private transport?: (url: string, init: RequestInit) => Promise<Response>;
  private dnsResolver?: (hostname: string) => Promise<{ address: string; family: number }[]>;

  constructor(options: OciRegistryAdapterOptions = {}) {
    this.registryHost = options.registryHost || process.env.OCI_REGISTRY_HOST;
    this.allowedHosts = options.allowedHosts;
    this.insecure = options.insecure ?? false;
    this.timeoutMs = options.timeoutMs || 10000;
    this.maxSizeBytes = options.maxSizeBytes || 50 * 1024 * 1024;
    this.simulate = options.simulate;
    this.transport = options.transport;
    this.dnsResolver = options.dnsResolver;
  }

  isConfigured(): boolean {
    const hasHost = Boolean(this.registryHost || process.env.OCI_REGISTRY_HOST);
    const hasToken = Boolean(process.env.OCI_AUTH_TOKEN || this.transport);
    return hasHost && hasToken;
  }

  private resolveAuthHeader(): string | null {
    const token = process.env.OCI_AUTH_TOKEN?.trim();
    if (token) {
      if (token.startsWith('Basic ') || token.startsWith('Bearer ')) {
        return token;
      }
      return `Bearer ${token}`;
    }
    if (this.transport) {
      return 'Bearer TEST_OCI_TOKEN';
    }
    return null;
  }

  async ship(
    bundle: SignedPackageBundle,
    options: ShippingOptions
  ): Promise<DeliveryReceipt> {
    const shipmentId = `ship-oci-${Date.now()}-${sha256(bundle.manifest_hash || 'hash').slice(0, 8)}`;
    const shippedAt = new Date().toISOString();
    const auditId = `audit-${shipmentId}`;

    const effectiveHost = this.registryHost || process.env.OCI_REGISTRY_HOST || '';

    // Parse targetLocator or default to canonical repository
    let host = effectiveHost;
    let repository = '';
    let tag = '';

    if (options.targetLocator) {
      let raw = options.targetLocator;
      if (raw.startsWith('oci://') || raw.startsWith('docker://')) {
        raw = raw.replace(/^(oci|docker):\/\//, '');
      }

      const tagIdx = raw.indexOf(':');
      if (tagIdx !== -1) {
        tag = raw.slice(tagIdx + 1);
        raw = raw.slice(0, tagIdx);
      }

      const slashIdx = raw.indexOf('/');
      if (slashIdx !== -1) {
        host = raw.slice(0, slashIdx);
        repository = raw.slice(slashIdx + 1);
      } else {
        host = raw;
      }
    }

    if (!repository) {
      const tenantPrefix = options.tenantId ? `agents/${options.tenantId}` : `agents/${bundle.manifest?.agent_id || 'default'}`;
      repository = `${tenantPrefix}/${bundle.manifest?.version_label || 'v1.0.0'}`;
    }

    if (!tag) {
      tag = `sha256-${(bundle.manifest_hash || 'hash').slice(0, 16)}`;
    }

    const canonicalLocator = `${host}/${repository}:${tag}`;

    // 1. Validate Registry Host & SSRF Protection (including DNS resolution)
    const hostValidation = await validateAndResolveRegistryHost(host, this.allowedHosts, this.dnsResolver);
    if (!hostValidation.valid) {
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
        error: hostValidation.error,
        metadata: { ssrf_blocked: true, reason: hostValidation.error, resolved_ips: hostValidation.resolvedIps },
      };
    }

    // Validate repository name (OCI Distribution Spec)
    const repoRegex = /^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*)*$/;
    if (!repoRegex.test(repository) || repository.includes('..') || repository.startsWith('/')) {
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
        error: `Invalid repository name or path traversal in '${repository}'`,
      };
    }

    // Tenant isolation: if expectedTenantId is provided, repository must contain tenant scope
    if (options.tenantId) {
      const tenantPrefix1 = `agents/${options.tenantId}/`;
      const tenantPrefix2 = `${options.tenantId}/`;
      if (!repository.startsWith(tenantPrefix1) && !repository.startsWith(tenantPrefix2)) {
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
          error: `Cross-tenant path violation: Repository '${repository}' does not belong to tenant '${options.tenantId}'`,
        };
      }
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
            : 'OCI registry endpoint is not configured (missing OCI_REGISTRY_HOST or OCI_AUTH_TOKEN in production)',
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
          oci_media_type: 'application/vnd.caim.package.v1+tar',
          layer_digest: `sha256:${bundle.manifest_hash}`,
          attestation_tag: `${tag}.att`,
          registry_host: host,
          simulated: true,
          simulation_notice: 'No active OCI registry connection configured. Delivery simulated in development mode.',
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
        error: `Package bundle size (${sizeBytes} bytes) exceeds maximum limit (${this.maxSizeBytes} bytes)`,
      };
    }

    // 4. Resolve Auth
    const authHeader = this.resolveAuthHeader();
    if (!authHeader) {
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
        error: 'Missing OCI authorization token (OCI_AUTH_TOKEN)',
      };
    }

    const protocol = this.insecure ? 'http' : 'https';
    const baseUrl = `${protocol}://${host}`;
    const fetchFn = this.transport || fetch;

    // 5. OCI Distribution Spec: Step 1 - Initiate Blob Upload (POST /v2/<name>/blobs/uploads/)
    const uploadInitUrl = `${baseUrl}/v2/${repository}/blobs/uploads/`;
    let uploadLocation = '';

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      const initRes = await fetchFn(uploadInitUrl, {
        method: 'POST',
        headers: {
          Authorization: authHeader,
          'Content-Length': '0',
        },
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (initRes.status === 401 || initRes.status === 403) {
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
          error: `OCI Registry rejected authorization credentials (HTTP ${initRes.status})`,
        };
      }

      if (initRes.status === 429 || initRes.status >= 500) {
        return {
          shipment_id: shipmentId,
          package_id: bundle.package_id,
          target_type: this.targetType,
          target_locator: canonicalLocator,
          manifest_hash: bundle.manifest_hash,
          signature_id: bundle.signature?.signature_id || 'none',
          shipped_at: shippedAt,
          status: 'PROVIDER_UNAVAILABLE',
          detailed_state: 'PROVIDER_UNAVAILABLE',
          receipt_locator: null,
          transfer_size_bytes: 0,
          receipt_signature: null,
          audit_trail_id: auditId,
          truthState: 'FAILED',
          truth_state: 'FAILED',
          error: `OCI Registry unavailable (HTTP ${initRes.status})`,
        };
      }

      const locationHeader = initRes.headers.get('location');
      if (!locationHeader) {
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
          error: 'OCI Registry did not return Location header for blob upload',
        };
      }

      // Check for SSRF in location redirect
      if (locationHeader.startsWith('http://') || locationHeader.startsWith('https://')) {
        const redirectCheck = validateRedirectUrl(locationHeader, this.allowedHosts, this.insecure);
        if (!redirectCheck.valid || !redirectCheck.url) {
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
            error: `SSRF Blocked: OCI Registry upload Location header rejected: ${redirectCheck.error}`,
          };
        }
        uploadLocation = redirectCheck.url.toString();
      } else {
        uploadLocation = `${baseUrl}${locationHeader.startsWith('/') ? '' : '/'}${locationHeader}`;
      }
    } catch (err: any) {
      const isTimeout = err.name === 'AbortError' || err.message?.includes('aborted');
      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: canonicalLocator,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature?.signature_id || 'none',
        shipped_at: shippedAt,
        status: isTimeout ? 'PROVIDER_UNAVAILABLE' : 'FAILED',
        detailed_state: isTimeout ? 'PROVIDER_UNAVAILABLE' : 'FAILED',
        receipt_locator: null,
        transfer_size_bytes: 0,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'FAILED',
        truth_state: 'FAILED',
        error: `Failed to initiate blob upload: ${err.message}`,
      };
    }

    // 6. OCI Distribution Spec: Step 2 - Upload Blob with digest query (PUT <location>?digest=sha256:<digest>)
    const sep = uploadLocation.includes('?') ? '&' : '?';
    const blobPutUrl = `${uploadLocation}${sep}digest=sha256:${sha256Digest}`;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      const blobRes = await fetchFn(blobPutUrl, {
        method: 'PUT',
        headers: {
          Authorization: authHeader,
          'Content-Type': 'application/vnd.caim.package.v1+tar',
          'Content-Length': String(sizeBytes),
        },
        body: bytes,
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (!blobRes.ok && blobRes.status !== 201 && blobRes.status !== 202) {
        return {
          shipment_id: shipmentId,
          package_id: bundle.package_id,
          target_type: this.targetType,
          target_locator: canonicalLocator,
          manifest_hash: bundle.manifest_hash,
          signature_id: bundle.signature?.signature_id || 'none',
          shipped_at: shippedAt,
          status: blobRes.status === 429 || blobRes.status >= 500 ? 'PROVIDER_UNAVAILABLE' : 'FAILED',
          detailed_state: blobRes.status === 429 || blobRes.status >= 500 ? 'PROVIDER_UNAVAILABLE' : 'FAILED',
          receipt_locator: null,
          transfer_size_bytes: 0,
          receipt_signature: null,
          audit_trail_id: auditId,
          truthState: 'FAILED',
          truth_state: 'FAILED',
          error: `OCI Registry blob upload failed with HTTP ${blobRes.status}`,
        };
      }
    } catch (err: any) {
      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: canonicalLocator,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature?.signature_id || 'none',
        shipped_at: shippedAt,
        status: 'PROVIDER_UNAVAILABLE',
        detailed_state: 'PROVIDER_UNAVAILABLE',
        receipt_locator: null,
        transfer_size_bytes: 0,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'FAILED',
        truth_state: 'FAILED',
        error: `Network error during OCI blob upload: ${err.message}`,
      };
    }

    // 7. OCI Distribution Spec: Step 3 - Upload Artifact Manifest (PUT /v2/<name>/manifests/<tag>)
    const configPayload = JSON.stringify({
      mediaType: 'application/vnd.caim.package.config.v1+json',
      packageId: bundle.package_id,
      manifestHash: bundle.manifest_hash,
      signatureId: bundle.signature?.signature_id,
    });
    const configDigest = crypto.createHash('sha256').update(configPayload).digest('hex');

    const ociManifest = {
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      config: {
        mediaType: 'application/vnd.caim.package.config.v1+json',
        digest: `sha256:${configDigest}`,
        size: Buffer.byteLength(configPayload),
      },
      layers: [
        {
          mediaType: 'application/vnd.caim.package.v1+tar',
          digest: `sha256:${sha256Digest}`,
          size: sizeBytes,
          annotations: {
            'org.opencontainers.image.title': `${bundle.package_id}.tar.gz`,
          },
        },
      ],
      annotations: {
        'org.opencontainers.image.created': shippedAt,
        'caim.security/manifest-hash': bundle.manifest_hash,
        'caim.security/signature-id': bundle.signature?.signature_id || 'none',
        'caim.security/package-id': bundle.package_id,
      },
    };

    const manifestBytes = Buffer.from(JSON.stringify(ociManifest), 'utf-8');
    const computedManifestDigest = crypto.createHash('sha256').update(manifestBytes).digest('hex');

    const manifestUrl = `${baseUrl}/v2/${repository}/manifests/${tag}`;
    let manifestRes: Response;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      manifestRes = await fetchFn(manifestUrl, {
        method: 'PUT',
        headers: {
          Authorization: authHeader,
          'Content-Type': 'application/vnd.oci.image.manifest.v1+json',
          'Content-Length': String(manifestBytes.length),
        },
        body: manifestBytes,
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (!manifestRes.ok && manifestRes.status !== 201) {
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
          transfer_size_bytes: sizeBytes,
          receipt_signature: null,
          audit_trail_id: auditId,
          truthState: 'FAILED',
          truth_state: 'FAILED',
          error: `OCI Registry manifest put failed with HTTP ${manifestRes.status}`,
        };
      }
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
        error: `Network error putting OCI manifest: ${err.message}`,
      };
    }

    // 8. Independent Remote Integrity Readback & Verification
    // Retrieve manifest by digest and verify returned layer digests
    const manifestDigestUrl = `${baseUrl}/v2/${repository}/manifests/sha256:${computedManifestDigest}`;
    let readbackManifestRes: Response;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      readbackManifestRes = await fetchFn(manifestDigestUrl, {
        method: 'GET',
        headers: {
          Authorization: authHeader,
          Accept: 'application/vnd.oci.image.manifest.v1+json',
        },
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
        error: `Remote manifest readback failed: ${err.message}`,
      };
    }

    if (!readbackManifestRes.ok) {
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
        error: `Remote manifest readback returned HTTP ${readbackManifestRes.status}`,
      };
    }

    const readbackManifestJson: any = await readbackManifestRes.json();
    const readbackLayer = readbackManifestJson?.layers?.[0];
    const readbackConfig = readbackManifestJson?.config;

    // Verify manifest schema version and descriptors
    if (readbackManifestJson?.schemaVersion !== 2) {
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
        integrity_verified: false,
        error: `OCI Manifest schema version mismatch: expected 2, got ${readbackManifestJson?.schemaVersion}`,
      };
    }

    if (readbackConfig && readbackConfig.digest && readbackConfig.digest !== `sha256:${configDigest}`) {
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
        integrity_verified: false,
        error: `OCI Manifest config descriptor digest mismatch. Expected sha256:${configDigest}, got ${readbackConfig?.digest}`,
      };
    }

    if (!readbackLayer || readbackLayer.digest !== `sha256:${sha256Digest}`) {
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
        remote_digest: readbackLayer?.digest?.replace('sha256:', '') || 'unknown',
        integrity_verified: false,
        error: `OCI Manifest layer digest mismatch. Expected sha256:${sha256Digest}, got ${readbackLayer?.digest}`,
      };
    }

    if (typeof readbackLayer.size === 'number' && readbackLayer.size !== sizeBytes) {
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
        remote_digest: 'SIZE_MISMATCH',
        integrity_verified: false,
        error: `OCI Manifest layer size descriptor mismatch. Expected ${sizeBytes} bytes, got ${readbackLayer.size}`,
      };
    }

    // 9. Actual Byte-Level Readback & Independent Hashing (GET /v2/<name>/blobs/sha256:<digest>)
    const getBlobUrl = `${baseUrl}/v2/${repository}/blobs/sha256:${sha256Digest}`;
    let readbackBlobBytes: Buffer;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      const blobRes = await fetchFn(getBlobUrl, {
        method: 'GET',
        headers: {
          Authorization: authHeader,
          Accept: 'application/octet-stream, application/vnd.caim.package.v1+tar',
        },
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (!blobRes.ok) {
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
          error: `Remote blob byte readback failed: GET returned HTTP ${blobRes.status} (Remote blob verification failed)`,
          integrity_verified: false,
        };
      }

      const arrayBuf = await blobRes.arrayBuffer();
      readbackBlobBytes = Buffer.from(arrayBuf);
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
        error: `Network error during remote blob byte readback: ${err.message}`,
      };
    }

    // Byte size verification
    if (readbackBlobBytes.length !== sizeBytes) {
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
        remote_digest: 'TRUNCATED_OR_OVERSIZED',
        integrity_verified: false,
        error: `OCI Blob byte-length mismatch: expected ${sizeBytes} bytes, readback returned ${readbackBlobBytes.length} bytes (corrupted or truncated content)`,
      };
    }

    // Independent cryptographic hash of readback bytes
    const computedReadbackDigest = crypto.createHash('sha256').update(readbackBlobBytes).digest('hex');
    if (computedReadbackDigest !== sha256Digest) {
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
        remote_digest: computedReadbackDigest,
        integrity_verified: false,
        error: `OCI Blob byte-level content hash mismatch: expected sha256:${sha256Digest}, computed from readback bytes sha256:${computedReadbackDigest}`,
      };
    }

    const immutableDigestLocator = `${host}/${repository}@sha256:${computedManifestDigest}`;

    // 10. Verified Remote Delivery
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
      receipt_locator: immutableDigestLocator,
      transfer_size_bytes: sizeBytes,
      receipt_signature: null,
      audit_trail_id: auditId,
      truthState: 'OBSERVED',
      truth_state: 'OBSERVED',
      artifact_digest: sha256Digest,
      remote_digest: computedManifestDigest,
      integrity_verified: true,
      verified_at: new Date().toISOString(),
      byte_level_readback_verified: true,
      provider_delivery_verified: true,
      metadata: {
        oci_media_type: 'application/vnd.oci.image.manifest.v1+json',
        layer_digest: `sha256:${sha256Digest}`,
        manifest_digest: `sha256:${computedManifestDigest}`,
        tag,
        registry_host: host,
        repository,
        immutable_locator: immutableDigestLocator,
        real_delivery: true,
        byte_level_readback_verified: true,
        verified_bytes_length: sizeBytes,
        readback_sha256: computedReadbackDigest,
      },
    };
  }

  async healthCheck(): Promise<{ healthy: boolean; details: string }> {
    if (!this.isConfigured()) {
      return {
        healthy: false,
        details: 'OCI registry endpoint is not configured (missing host or auth token)',
      };
    }
    return {
      healthy: true,
      details: `OCI registry configured for ${this.registryHost || process.env.OCI_REGISTRY_HOST}`,
    };
  }
}
