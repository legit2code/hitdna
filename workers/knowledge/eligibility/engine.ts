import { 
  KnowledgeObjectType, 
  IndexingEligibilityResult 
} from '../types.ts';
import { SecurityClassificationCode } from '@caim/auth/types.ts';

export class IndexingEligibilityEngine {
  /**
   * Evaluates if a raw entity is eligible for projection and vector indexing.
   */
  public static evaluateEligibility(
    objectType: KnowledgeObjectType,
    rawEntity: Record<string, any>,
    classification?: SecurityClassificationCode
  ): IndexingEligibilityResult {
    // 1. Check for deletion/tombstone
    if (rawEntity.deleted === true || rawEntity.is_deleted === true || rawEntity.status === 'DELETED' || rawEntity.status === 'PURGED') {
      return {
        eligible: false,
        reason: 'Entity is marked as deleted or purged',
        vault_restricted: false,
        target_index: 'NONE',
      };
    }

    // 2. Check for ephemeral or uncommitted run states
    if (objectType === 'run' && (rawEntity.status === 'IN_PROGRESS' || rawEntity.status === 'PENDING' || rawEntity.status === 'CANCELLED')) {
      return {
        eligible: false,
        reason: `Analysis run is in non-terminal/ephemeral state: ${rawEntity.status}`,
        vault_restricted: false,
        target_index: 'NONE',
      };
    }

    // 3. Check security classification & vault boundaries
    const effectiveClassification = classification || rawEntity.security_classification || 'INTERNAL';
    const isVaultRestricted = effectiveClassification === 'VAULT_RESTRICTED' || rawEntity.is_vault === true || rawEntity.vault_restricted === true;

    if (isVaultRestricted) {
      // In Architecture V2.0.1 Document 13 & 18:
      // Never put vault-restricted content into a general-access index.
      return {
        eligible: true,
        reason: 'Vault-restricted entity eligible only for dedicated vault index',
        vault_restricted: true,
        target_index: 'VAULT_RESTRICTED_INDEX',
      };
    }

    // 4. Validate presence of basic content
    if (!rawEntity || Object.keys(rawEntity).length === 0) {
      return {
        eligible: false,
        reason: 'Entity has empty content payload',
        vault_restricted: false,
        target_index: 'NONE',
      };
    }

    return {
      eligible: true,
      reason: 'Entity satisfies all indexing eligibility criteria for general vector corpus',
      vault_restricted: false,
      target_index: 'GENERAL_VECTOR_INDEX',
    };
  }
}
