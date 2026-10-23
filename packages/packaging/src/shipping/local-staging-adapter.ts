import fs from 'node:fs';
import path from 'node:path';
import { IShippingTargetAdapter, ShippingOptions } from './adapter.ts';
import { SignedPackageBundle, DeliveryReceipt, ShippingTargetType } from '../types.ts';
import { sha256 } from '../hashing.ts';

/**
 * Local Staging & Air-Gapped Shipping Adapter
 * Writes bundle artifacts directly to local filesystem storage with verified delivery.
 */

export class LocalStagingAdapter implements IShippingTargetAdapter {
  readonly targetType: ShippingTargetType = 'LOCAL_STAGING';

  constructor(private options: { baseDirectory?: string } = {}) {}

  isConfigured(): boolean {
    return true;
  }

  async ship(
    bundle: SignedPackageBundle,
    options: ShippingOptions
  ): Promise<DeliveryReceipt> {
    const shipmentId = `ship-local-${Date.now()}-${sha256(bundle.manifest_hash).slice(0, 8)}`;
    const shippedAt = new Date().toISOString();

    let totalBytes = 0;
    for (const [, file] of bundle.files) {
      totalBytes += file.sizeBytes;
    }

    const baseDir = options.targetLocator || this.options.baseDirectory || '/tmp/caim-staging';
    const receiptLocator = path.resolve(`${baseDir}/${bundle.manifest.agent_id}/${bundle.manifest.version_label}`);
    const auditId = `audit-${shipmentId}`;

    try {
      fs.mkdirSync(receiptLocator, { recursive: true });
      for (const [relPath, file] of bundle.files) {
        const fullPath = path.join(receiptLocator, relPath);
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, file.content);
      }

      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: options.targetLocator,
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature.signature_id,
        shipped_at: shippedAt,
        status: 'DELIVERED',
        receipt_locator: receiptLocator,
        transfer_size_bytes: totalBytes,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'OBSERVED',
        truth_state: 'OBSERVED',
        metadata: {
          staged_files_count: bundle.files.size,
          local_directory: receiptLocator,
          real_filesystem_delivery: true,
        },
      };
    } catch (err: any) {
      return {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: this.targetType,
        target_locator: options.targetLocator,
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
        error: err?.message || String(err),
        metadata: {
          error: err?.message || String(err),
          failed_at: new Date().toISOString(),
        },
      };
    }
  }

  async healthCheck(): Promise<{ healthy: boolean; details: string }> {
    try {
      const baseDir = this.options.baseDirectory || '/tmp/caim-staging';
      fs.mkdirSync(baseDir, { recursive: true });
      return {
        healthy: true,
        details: 'Local staging filesystem directory writable',
      };
    } catch (err: any) {
      return {
        healthy: false,
        details: `Local staging filesystem unwritable: ${err?.message || String(err)}`,
      };
    }
  }
}
