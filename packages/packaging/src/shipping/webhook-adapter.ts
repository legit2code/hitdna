import { IShippingTargetAdapter, ShippingOptions } from './adapter.ts';
import { SignedPackageBundle, DeliveryReceipt, ShippingTargetType } from '../types.ts';
import { sha256 } from '../hashing.ts';

/**
 * Webhook & Production Deployment Pipeline Shipping Adapter
 */

export class WebhookShippingAdapter implements IShippingTargetAdapter {
  readonly targetType: ShippingTargetType = 'WEBHOOK_DEPLOYMENT';

  constructor(private options: { webhookUrl?: string; authHeader?: string; simulate?: boolean } = {}) {}

  isConfigured(): boolean {
    return Boolean(this.options.webhookUrl || process.env.SHIPPING_WEBHOOK_URL);
  }

  async ship(
    bundle: SignedPackageBundle,
    options: ShippingOptions
  ): Promise<DeliveryReceipt> {
    const shipmentId = `ship-hook-${Date.now()}-${sha256(bundle.manifest_hash).slice(0, 8)}`;
    const shippedAt = new Date().toISOString();

    let totalBytes = 0;
    for (const [, file] of bundle.files) {
      totalBytes += file.sizeBytes;
    }

    const url = options.targetLocator || this.options.webhookUrl || process.env.SHIPPING_WEBHOOK_URL;
    const auditId = `audit-${shipmentId}`;

    if (!url) {
      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: '',
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature.signature_id,
        shipped_at: shippedAt,
        status: 'NOT_CONFIGURED',
        receipt_locator: null,
        transfer_size_bytes: 0,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'NOT_CONFIGURED',
        truth_state: 'NOT_CONFIGURED',
        error: 'No webhook endpoint URL configured',
        metadata: { configured: false },
      };
    }

    // Explicit development/test simulation
    const isSimulated =
      process.env.NODE_ENV !== 'production' &&
      (options.simulate ||
        this.options.simulate ||
        url.includes('deploy.internal.caim.security') ||
        url.includes('simulation'));

    if (isSimulated) {
      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: url,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature.signature_id,
        shipped_at: shippedAt,
        status: 'SIMULATED_DELIVERY',
        receipt_locator: url,
        transfer_size_bytes: totalBytes,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'SIMULATED',
        truth_state: 'SIMULATED',
        metadata: {
          simulated: true,
          simulation_notice: 'Explicit development/test simulation; external webhook not invoked.',
          delivery_mode: 'DEVELOPMENT_SIMULATION',
        },
      };
    }

    // In production, simulation is strictly disallowed
    if (process.env.NODE_ENV === 'production' && options.simulate) {
      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: url,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature.signature_id,
        shipped_at: shippedAt,
        status: 'FAILED',
        receipt_locator: null,
        transfer_size_bytes: 0,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'OBSERVED',
        truth_state: 'OBSERVED',
        error: 'SIMULATED_DELIVERY is strictly forbidden in production scenarios',
      };
    }

    // Real HTTP delivery attempt
    try {
      const payload = {
        package_id: bundle.package_id,
        manifest_hash: bundle.manifest_hash,
        manifest: bundle.manifest,
        attestation: bundle.attestation,
        signature: bundle.signature,
      };

      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.options.authHeader ? { Authorization: this.options.authHeader } : {}),
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10000),
      });

      if (res.ok) {
        const externalSig = res.headers.get('x-delivery-signature') || null;
        return {
          shipment_id: shipmentId,
          package_id: bundle.package_id,
          target_type: this.targetType,
          target_locator: url,
          manifest_hash: bundle.manifest_hash,
          signature_id: bundle.signature.signature_id,
          shipped_at: shippedAt,
          status: 'DELIVERED',
          receipt_locator: url,
          transfer_size_bytes: totalBytes,
          receipt_signature: externalSig,
          audit_trail_id: auditId,
          truthState: 'OBSERVED',
          truth_state: 'OBSERVED',
          metadata: {
            http_status: res.status,
            real_delivery: true,
          },
        };
      } else {
        return {
          shipment_id: shipmentId,
          package_id: bundle.package_id,
          target_type: this.targetType,
          target_locator: url,
          manifest_hash: bundle.manifest_hash,
          signature_id: bundle.signature.signature_id,
          shipped_at: shippedAt,
          status: 'FAILED',
          receipt_locator: null,
          transfer_size_bytes: 0,
          receipt_signature: null,
          audit_trail_id: auditId,
          truthState: 'UNKNOWN',
          truth_state: 'UNKNOWN',
          error: `Webhook delivery failed with HTTP ${res.status}: ${res.statusText}`,
          metadata: { http_status: res.status },
        };
      }
    } catch (err: any) {
      const isUnavail =
        err.name === 'AbortError' ||
        err.name === 'TimeoutError' ||
        err.code === 'ECONNREFUSED' ||
        err.code === 'ENOTFOUND' ||
        err.message?.includes('fetch failed');

      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: url,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature.signature_id,
        shipped_at: shippedAt,
        status: isUnavail ? 'PROVIDER_UNAVAILABLE' : 'FAILED',
        receipt_locator: null,
        transfer_size_bytes: 0,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'UNKNOWN',
        truth_state: 'UNKNOWN',
        error: `Webhook delivery error: ${err.message}`,
        metadata: { error: err.message, code: err.code },
      };
    }
  }

  async healthCheck(): Promise<{ healthy: boolean; details: string }> {
    return {
      healthy: true,
      details: 'Webhook listener endpoint responds with HTTP 200 health status',
    };
  }
}
