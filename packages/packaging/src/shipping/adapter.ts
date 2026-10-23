import { SignedPackageBundle, DeliveryReceipt, ShippingTargetType } from '../types.ts';

/**
 * Shipping Target Adapter Interface (Architecture V2.0.1)
 */

export interface ShippingOptions {
  targetLocator: string;
  metadata?: Record<string, any>;
  dryRun?: boolean;
  simulate?: boolean;
  tenantId?: string;
  releaseId?: string;
  commitSha?: string;
  environment?: string;
  maxSizeBytes?: number;
}

export interface IShippingTargetAdapter {
  readonly targetType: ShippingTargetType | string;
  
  isConfigured?(): boolean;

  ship(
    bundle: SignedPackageBundle,
    options: ShippingOptions
  ): Promise<DeliveryReceipt>;

  healthCheck(): Promise<{ healthy: boolean; details: string }>;
}
