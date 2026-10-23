import { 
  PrincipalContext, 
  SecurityClassificationRank, 
  UnauthorizedVaultAccessError 
} from './types.ts';

export interface VaultRestrictedPayload<T = unknown> {
  id: string;
  data: T;
  security_classification_rank: SecurityClassificationRank;
  credential_refs?: string[];
  taint_paths?: unknown[];
  raw_traces?: unknown[];
}

/**
 * Validates caller clearance for reading VAULT_RESTRICTED entities.
 * Returns true if authorized, or throws UnauthorizedVaultAccessError (or returns false in soft check).
 */
export function isAuthorizedForVault(context: PrincipalContext): boolean {
  if (context.is_override_active) {
    return true;
  }
  return context.max_classification_rank >= SecurityClassificationRank.VAULT_RESTRICTED ||
    context.roles.includes('admin') ||
    context.roles.includes('vault_reader') ||
    context.grants.includes('vault_reader');
}

/**
 * Filter an array of items enforcing strict vault boundary:
 * Unauthorized callers receive 0 vault-restricted records.
 */
export function filterVaultRecords<T extends { security_classification_rank?: SecurityClassificationRank }>(
  context: PrincipalContext,
  items: T[]
): T[] {
  const canReadVault = isAuthorizedForVault(context);
  return items.filter(item => {
    const rank = item.security_classification_rank ?? SecurityClassificationRank.PUBLIC_METADATA;
    if (rank >= SecurityClassificationRank.VAULT_RESTRICTED) {
      return canReadVault;
    }
    return rank <= context.max_classification_rank;
  });
}

/**
 * Guard for reading a single vault-restricted item. Throws error if unauthorized.
 */
export function readVaultItem<T>(
  context: PrincipalContext,
  item: VaultRestrictedPayload<T>
): VaultRestrictedPayload<T> {
  if (!isAuthorizedForVault(context)) {
    throw new UnauthorizedVaultAccessError(
      `Access denied: Principal '${context.principal_id}' lacks VAULT_READER or ADMIN clearance required to access vault item '${item.id}'.`
    );
  }
  return item;
}
