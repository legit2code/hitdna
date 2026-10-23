/**
 * Password Hashing & Verification Service
 * Uses Argon2id as primary modern KDF (tuned to ~250 ms target on platform hardware)
 * with automatic rehash-on-login from legacy bcrypt hashes.
 */

import argon2 from 'argon2';
import bcrypt from 'bcryptjs';

/**
 * Authoritative Argon2id Parameters:
 * - type: argon2.argon2id (RFC 9106 recommended hybrid mode resistant to side-channel and GPU attacks)
 * - memoryCost: 65536 KiB (64 MiB memory hardness)
 * - timeCost: 2 iterations (tuned to ~250 ms target on platform production hardware)
 * - parallelism: 1 thread
 */
export const ARGON2_CONFIG: Parameters<typeof argon2.hash>[1] = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 2,
  parallelism: 1,
};

export const MAX_PASSWORD_LENGTH = 128;

export function normalizePassword(plaintext: string): string {
  if (!plaintext || typeof plaintext !== 'string') {
    throw new Error('Password must be a non-empty string.');
  }
  if (plaintext.length > MAX_PASSWORD_LENGTH) {
    throw new Error(`Password exceeds maximum allowed length of ${MAX_PASSWORD_LENGTH} characters.`);
  }
  return plaintext.normalize('NFKC');
}

export interface IBreachedPasswordChecker {
  isBreached(password: string): Promise<boolean>;
}

export class NoopBreachedPasswordChecker implements IBreachedPasswordChecker {
  async isBreached(_password: string): Promise<boolean> {
    return false;
  }
}

let breachedPasswordChecker: IBreachedPasswordChecker = new NoopBreachedPasswordChecker();

export function setBreachedPasswordChecker(checker: IBreachedPasswordChecker): void {
  breachedPasswordChecker = checker;
}

export function getBreachedPasswordChecker(): IBreachedPasswordChecker {
  return breachedPasswordChecker;
}

/**
 * Hashes a plaintext password using Argon2id with unicode NFKC normalization.
 */
export async function hashPassword(plaintext: string): Promise<string> {
  const normalized = normalizePassword(plaintext);
  return (await argon2.hash(normalized, ARGON2_CONFIG)) as string;
}

export function hashPasswordSync(plaintext: string): string {
  const normalized = normalizePassword(plaintext);
  return bcrypt.hashSync(normalized, 10);
}

/**
 * Verifies password with support for both modern Argon2id and legacy bcrypt hashes.
 * Detects whether hash needs upgrading to Argon2id upon successful authentication.
 */
export async function verifyPasswordWithRehashCheck(
  plaintext: string,
  hash: string
): Promise<{ valid: boolean; needsRehash: boolean }> {
  if (!plaintext || !hash) {
    return { valid: false, needsRehash: false };
  }

  let normalized: string;
  try {
    normalized = normalizePassword(plaintext);
  } catch {
    return { valid: false, needsRehash: false };
  }

  // Legacy bcrypt check ($2a$, $2b$, $2y$)
  if (hash.startsWith('$2a$') || hash.startsWith('$2b$') || hash.startsWith('$2y$')) {
    try {
      const match = await bcrypt.compare(normalized, hash);
      return { valid: match, needsRehash: match };
    } catch {
      return { valid: false, needsRehash: false };
    }
  }

  // Argon2id check
  if (hash.startsWith('$argon2')) {
    try {
      const match = await argon2.verify(hash, normalized);
      return { valid: match, needsRehash: false };
    } catch {
      return { valid: false, needsRehash: false };
    }
  }

  return { valid: false, needsRehash: false };
}

/**
 * Standard password verification helper returning a simple boolean.
 */
export async function verifyPassword(plaintext: string, hash: string): Promise<boolean> {
  const result = await verifyPasswordWithRehashCheck(plaintext, hash);
  return result.valid;
}

/**
 * In-memory Tracker for per-account and per-IP login backoff
 */
export class PasswordBackoffTracker {
  private attemptsByAccount = new Map<string, { count: number; lockedUntil: number }>();
  private attemptsByIp = new Map<string, { count: number; lockedUntil: number }>();

  public checkBackoff(account: string, ip?: string): { allowed: boolean; retryAfterMs: number } {
    const now = Date.now();
    const accState = this.attemptsByAccount.get(account.toLowerCase().trim());
    if (accState && accState.lockedUntil > now) {
      return { allowed: false, retryAfterMs: accState.lockedUntil - now };
    }
    if (ip) {
      const ipState = this.attemptsByIp.get(ip.trim());
      if (ipState && ipState.lockedUntil > now) {
        return { allowed: false, retryAfterMs: ipState.lockedUntil - now };
      }
    }
    return { allowed: true, retryAfterMs: 0 };
  }

  public recordFailedAttempt(account: string, ip?: string): void {
    const now = Date.now();
    const update = (state?: { count: number; lockedUntil: number }) => {
      const count = (state?.count || 0) + 1;
      let lockedUntil = 0;
      if (count >= 5) {
        // Exponential backoff starting at 1s up to max 15 minutes
        const delayMs = Math.min(1000 * Math.pow(2, count - 5), 15 * 60 * 1000);
        lockedUntil = now + delayMs;
      }
      return { count, lockedUntil };
    };

    const normAccount = account.toLowerCase().trim();
    this.attemptsByAccount.set(normAccount, update(this.attemptsByAccount.get(normAccount)));
    if (ip) {
      const normIp = ip.trim();
      this.attemptsByIp.set(normIp, update(this.attemptsByIp.get(normIp)));
    }
  }

  public resetFailedAttempts(account: string, ip?: string): void {
    this.attemptsByAccount.delete(account.toLowerCase().trim());
    if (ip) {
      this.attemptsByIp.delete(ip.trim());
    }
  }

  public clear(): void {
    this.attemptsByAccount.clear();
    this.attemptsByIp.clear();
  }
}

export const passwordBackoffTracker = new PasswordBackoffTracker();
