import { IShippingTargetAdapter, ShippingOptions } from './adapter.ts';
import { OciRegistryAdapter } from './oci-adapter.ts';
import { S3StorageAdapter } from './s3-adapter.ts';
import { WebhookShippingAdapter } from './webhook-adapter.ts';
import { LocalStagingAdapter } from './local-staging-adapter.ts';
import { SignedPackageBundle, DeliveryReceipt, ShippingTargetType } from '../types.ts';
import { PackagingPolicyGate } from '../gates.ts';

export class ShippingPolicyViolationError extends Error {
  constructor(message: string, public blockers: string[]) {
    super(`Shipping blocked by policy gate: ${message} (Blockers: ${blockers.join(', ')})`);
    this.name = 'ShippingPolicyViolationError';
  }
}

export interface UnresolvedShipmentRecord {
  reconciliation_id: string;
  shipment_id: string;
  package_id: string;
  target_type: string;
  target_locator: string;
  provider_receipt: DeliveryReceipt;
  provider_delivery_verified: boolean;
  durable_persistence_verified: boolean;
  failure_stage: 'DATABASE_INSERT' | 'TRANSACTION_COMMIT' | 'RECONCILIATION';
  error_message: string;
  occurred_at: string;
  reconciled: boolean;
  reconciled_at?: string;
}

export class ShippingService {
  private adapters: Map<ShippingTargetType | string, IShippingTargetAdapter> = new Map();
  private deliveryAuditLog: DeliveryReceipt[] = [];
  private unresolvedShipments: Map<string, UnresolvedShipmentRecord> = new Map();
  private idempotencyRegistry: Map<string, DeliveryReceipt> = new Map();

  constructor(customAdapters?: IShippingTargetAdapter[]) {
    if (customAdapters && customAdapters.length > 0) {
      for (const adapter of customAdapters) {
        this.adapters.set(adapter.targetType, adapter);
      }
    } else {
      // Register default suite of shipping target adapters
      this.registerAdapter(new OciRegistryAdapter());
      this.registerAdapter(new S3StorageAdapter());
      this.registerAdapter(new WebhookShippingAdapter());
      this.registerAdapter(new LocalStagingAdapter());
    }
  }

  registerAdapter(adapter: IShippingTargetAdapter): void {
    this.adapters.set(adapter.targetType, adapter);
  }

  getAdapter(targetType: ShippingTargetType | string): IShippingTargetAdapter | undefined {
    return this.adapters.get(targetType);
  }

  /**
   * Ships a signed package bundle to the destination after verifying the pre-shipping policy gate.
   */
  async shipBundle(
    bundle: SignedPackageBundle,
    targetType: ShippingTargetType | string,
    options: ShippingOptions,
    trustedPublicKeyPem?: string
  ): Promise<DeliveryReceipt> {
    const shipmentId = `ship-${Date.now()}-${(bundle?.manifest_hash || 'hash').slice(0, 8)}`;
    const auditId = `audit-${shipmentId}`;

    // 0. Idempotency check: prevent duplicate remote uploads for already verified packages
    const idempotencyKey = options?.idempotencyKey || `${bundle.package_id}:${options?.targetLocator || targetType}`;
    const existingShipment = this.idempotencyRegistry.get(idempotencyKey);
    if (existingShipment && existingShipment.status === 'DELIVERED' && existingShipment.integrity_verified) {
      return {
        ...existingShipment,
        idempotency_key: idempotencyKey,
        metadata: {
          ...existingShipment.metadata,
          idempotent_replay: true,
        },
      };
    }

    const adapter = this.getAdapter(targetType);
    if (!adapter) {
      const receipt: DeliveryReceipt = {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: targetType,
        target_locator: options?.targetLocator || '',
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature?.signature_id || 'none',
        shipped_at: null,
        status: 'NOT_CONFIGURED',
        receipt_locator: null,
        transfer_size_bytes: 0,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'NOT_CONFIGURED',
        truth_state: 'NOT_CONFIGURED',
        error: `No shipping provider configured for target: ${targetType}`,
        metadata: {
          configured: false,
          missing_provider: true,
          target_type: targetType,
        },
      };
      this.deliveryAuditLog.push(receipt);
      return receipt;
    }

    // 1. Evaluate Pre-Shipping Policy Gate & Signature Verification
    const gateResult = PackagingPolicyGate.evaluatePreShippingGate(
      bundle,
      targetType as ShippingTargetType,
      trustedPublicKeyPem
    );

    if (!gateResult.allowed) {
      throw new ShippingPolicyViolationError(
        `Pre-shipping checks failed for target ${targetType}`,
        gateResult.blockers
      );
    }

    // 2. Deliver package via adapter with comprehensive error capture
    try {
      const receipt = await adapter.ship(bundle, options);

      // 3. Enforce CAIM Truth Invariants
      if (receipt.status === 'DELIVERED') {
        receipt.truthState = 'OBSERVED';
        receipt.truth_state = 'OBSERVED';
        receipt.detailed_state = receipt.detailed_state || 'DELIVERED_VERIFIED';
      } else if (receipt.status === 'SIMULATED_DELIVERY') {
        receipt.truthState = 'SIMULATED';
        receipt.truth_state = 'SIMULATED';
        receipt.detailed_state = receipt.detailed_state || 'SIMULATED_DELIVERY';
        receipt.receipt_signature = null;
      } else if (receipt.status === 'NOT_CONFIGURED') {
        receipt.truthState = 'NOT_CONFIGURED';
        receipt.truth_state = 'NOT_CONFIGURED';
        receipt.detailed_state = receipt.detailed_state || 'NOT_CONFIGURED';
        receipt.receipt_signature = null;
      } else if (receipt.status === 'INTEGRITY_MISMATCH') {
        receipt.truthState = 'FAILED';
        receipt.truth_state = 'FAILED';
        receipt.detailed_state = 'INTEGRITY_MISMATCH';
        receipt.receipt_signature = null;
      } else if (receipt.status === 'AUTHORIZATION_DENIED') {
        receipt.truthState = 'FAILED';
        receipt.truth_state = 'FAILED';
        receipt.detailed_state = 'AUTHORIZATION_DENIED';
        receipt.receipt_signature = null;
      } else {
        receipt.receipt_signature = null;
      }

      // Prohibit SIMULATED_DELIVERY in production
      if (process.env.NODE_ENV === 'production' && receipt.status === 'SIMULATED_DELIVERY') {
        receipt.status = 'NOT_CONFIGURED';
        receipt.receipt_locator = null;
        receipt.receipt_signature = null;
        receipt.truthState = 'NOT_CONFIGURED';
        receipt.truth_state = 'NOT_CONFIGURED';
        receipt.detailed_state = 'NOT_CONFIGURED';
        receipt.error = 'SIMULATED_DELIVERY is strictly forbidden in production environments';
      }

      // 4. Record in immutable delivery audit log & idempotency registry
      if (receipt.status === 'DELIVERED' && receipt.integrity_verified) {
        this.idempotencyRegistry.set(idempotencyKey, receipt);
      }
      this.deliveryAuditLog.push(receipt);
      return receipt;
    } catch (err: any) {
      const isUnavail =
        err.name === 'AbortError' ||
        err.name === 'TimeoutError' ||
        err.code === 'ECONNREFUSED' ||
        err.code === 'ENOTFOUND' ||
        err.message?.toLowerCase().includes('unavailable') ||
        err.message?.toLowerCase().includes('timeout') ||
        err.message?.toLowerCase().includes('fetch failed');

      const receipt: DeliveryReceipt = {
        shipment_id: shipmentId,
        package_id: bundle.package_id,
        target_type: targetType,
        target_locator: options?.targetLocator || '',
        manifest_hash: bundle.manifest_hash,
        signature_id: bundle.signature?.signature_id || 'none',
        shipped_at: null,
        status: isUnavail ? 'PROVIDER_UNAVAILABLE' : 'FAILED',
        receipt_locator: null,
        transfer_size_bytes: 0,
        receipt_signature: null,
        audit_trail_id: auditId,
        truthState: 'UNKNOWN',
        truth_state: 'UNKNOWN',
        error: err.message,
        metadata: {
          error: err.message,
          stack: err.stack,
        },
      };
      this.deliveryAuditLog.push(receipt);
      return receipt;
    }
  }

  getAuditLog(): DeliveryReceipt[] {
    return [...this.deliveryAuditLog];
  }

  getShipmentByPackageId(packageId: string): DeliveryReceipt | undefined {
    return this.deliveryAuditLog.find((r) => r.package_id === packageId);
  }

  recordUnresolvedShipment(record: UnresolvedShipmentRecord): void {
    this.unresolvedShipments.set(record.shipment_id, record);
    if (record.reconciliation_id) {
      this.unresolvedShipments.set(record.reconciliation_id, record);
    }
  }

  getUnresolvedShipments(): UnresolvedShipmentRecord[] {
    const unique = new Map<string, UnresolvedShipmentRecord>();
    for (const rec of this.unresolvedShipments.values()) {
      unique.set(rec.shipment_id, rec);
    }
    return Array.from(unique.values());
  }

  getUnresolvedShipment(id: string): UnresolvedShipmentRecord | undefined {
    return this.unresolvedShipments.get(id);
  }

  markShipmentReconciled(id: string): boolean {
    const rec = this.unresolvedShipments.get(id);
    if (rec) {
      rec.reconciled = true;
      rec.reconciled_at = new Date().toISOString();
      return true;
    }
    return false;
  }
}
