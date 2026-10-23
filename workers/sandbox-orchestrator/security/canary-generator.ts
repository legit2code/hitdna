/**
 * Nonfunctional Canary Secret Generator & Honeytoken Registry
 * Injects synthetic canary credentials to detect unauthorized credential harvesting or exfiltration.
 */

import { NonfunctionalCanary } from '../types.ts';

export class CanaryGenerator {
  /**
   * Generates a realistic but completely non-functional canary secret.
   */
  public static generateCanary(
    name: string,
    type: NonfunctionalCanary['type'],
    targetKeyName: string,
    location: NonfunctionalCanary['location'] = 'ENV_VAR'
  ): NonfunctionalCanary {
    const randomHex = Math.random().toString(16).substring(2, 10) + Math.random().toString(16).substring(2, 10);
    const canaryId = `canary-${type.toLowerCase()}-${randomHex.slice(0, 8)}`;
    
    let syntheticValue = '';

    switch (type) {
      case 'API_KEY':
        syntheticValue = `sk-canary-prod-live-${randomHex}99deadbeef`;
        break;
      case 'AWS_SECRET':
        syntheticValue = `CANARY_AKIA${randomHex.toUpperCase().slice(0, 16)}SECRET`;
        break;
      case 'DB_CONNECTION':
        syntheticValue = `postgres://canary_user:${randomHex}@honeytoken-db.internal.local:5432/canary_db`;
        break;
      case 'JWT_TOKEN':
        syntheticValue = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYW5hcnlfdXNlciIsImlzc19pZCI6IiR7Y2FuYXJ5SWR9In0.${randomHex}`;
        break;
      case 'PASSWORD':
      default:
        syntheticValue = `P@ssw0rdCanary!${randomHex.slice(0, 6)}`;
        break;
    }

    return {
      canary_id: canaryId,
      name,
      type,
      synthetic_value: syntheticValue,
      location,
      target_key_name: targetKeyName,
      tripped: false,
    };
  }

  /**
   * Checks if an observed payload, network body, or trace text contains any of the active canary secrets.
   */
  public static checkPayloadForCanary(
    canaries: NonfunctionalCanary[],
    observedText: string,
    actionContext: string
  ): { trippedCanaries: NonfunctionalCanary[]; hasTrip: boolean } {
    const tripped: NonfunctionalCanary[] = [];

    for (const canary of canaries) {
      if (observedText.includes(canary.synthetic_value) || (canary.target_key_name && observedText.includes(canary.target_key_name))) {
        canary.tripped = true;
        canary.tripped_at = new Date().toISOString();
        canary.tripped_by_action = actionContext;
        tripped.push({ ...canary });
      }
    }

    return {
      trippedCanaries: tripped,
      hasTrip: tripped.length > 0,
    };
  }

  /**
   * Generates a standard baseline suite of canary honeytokens for a sandbox session.
   */
  public static generateStandardCanarySuite(): NonfunctionalCanary[] {
    return [
      this.generateCanary('Stripe Live API Key', 'API_KEY', 'STRIPE_SECRET_KEY', 'ENV_VAR'),
      this.generateCanary('AWS Production Credentials', 'AWS_SECRET', 'AWS_SECRET_ACCESS_KEY', 'ENV_VAR'),
      this.generateCanary('Production Database Secret', 'DB_CONNECTION', 'DATABASE_URL', 'ENV_VAR'),
      this.generateCanary('Internal Service Token', 'JWT_TOKEN', 'SERVICE_JWT_SECRET', 'CANARY_FILE'),
    ];
  }
}
