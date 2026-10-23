/**
 * Enterprise Client-side Authentication & Token Management Service
 * Manages JWT Access Tokens strictly in memory (not persisted in localStorage/sessionStorage),
 * relies on server-managed httpOnly, Secure, SameSite cookies for refresh tokens,
 * and provides automatic silent refresh and authenticatedFetch wrapper.
 */

export interface AuthenticatedUser {
  principal_id: string;
  email: string;
  roles: string[];
  tenant_id?: string | null;
}

export interface LoginResponse {
  access_token: string;
  refresh_token?: string;
  token_type: 'Bearer';
  expires_in: number;
  principal: AuthenticatedUser;
}

// Legacy storage keys to clean up and purge from unencrypted localStorage
const LEGACY_ACCESS_TOKEN_KEY = 'caim_access_token';
const LEGACY_REFRESH_TOKEN_KEY = 'caim_refresh_token';
const LEGACY_USER_KEY = 'caim_user_profile';
const LEGACY_TOKEN_EXPIRY_KEY = 'caim_access_token_expires_at';

class AuthClient {
  private inMemoryAccessToken: string | null = null;
  private inMemoryTokenExpiresAt: number | null = null;
  private inMemoryUser: AuthenticatedUser | null = null;
  private refreshPromise: Promise<string | null> | null = null;
  private authStateListeners: Array<(user: AuthenticatedUser | null) => void> = [];

  constructor() {
    // Purge any tokens from localStorage to ensure no credentials exist in unencrypted browser storage
    this.purgeLegacyStorage();
  }

  private purgeLegacyStorage(): void {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        localStorage.removeItem(LEGACY_ACCESS_TOKEN_KEY);
        localStorage.removeItem(LEGACY_REFRESH_TOKEN_KEY);
        localStorage.removeItem(LEGACY_USER_KEY);
        localStorage.removeItem(LEGACY_TOKEN_EXPIRY_KEY);
      }
    } catch {
      // Ignore in environments without window/localStorage
    }
  }

  /**
   * Returns the short-lived access token held strictly in memory.
   */
  public getAccessToken(): string | null {
    return this.inMemoryAccessToken;
  }

  /**
   * Returns null as refresh tokens are moved to httpOnly, Secure, SameSite cookies
   * and are inaccessible to client-side JavaScript.
   */
  public getRefreshToken(): string | null {
    return null;
  }

  public getUser(): AuthenticatedUser | null {
    return this.inMemoryUser;
  }

  public isAuthenticated(): boolean {
    return Boolean(this.inMemoryAccessToken && this.inMemoryUser);
  }

  public subscribe(listener: (user: AuthenticatedUser | null) => void): () => void {
    this.authStateListeners.push(listener);
    return () => {
      this.authStateListeners = this.authStateListeners.filter(l => l !== listener);
    };
  }

  private notify(user: AuthenticatedUser | null) {
    for (const listener of this.authStateListeners) {
      try {
        listener(user);
      } catch (err) {
        console.error('[AuthClient] Listener error:', err);
      }
    }
  }

  /**
   * Stores the short-lived access token and authenticated principal in memory only.
   * No credentials or tokens are persisted to localStorage or sessionStorage.
   */
  public saveSession(response: LoginResponse): void {
    this.inMemoryAccessToken = response.access_token;
    this.inMemoryTokenExpiresAt = Date.now() + (response.expires_in || 900) * 1000;
    this.inMemoryUser = response.principal;

    // Ensure no residual credentials remain in localStorage
    this.purgeLegacyStorage();

    this.notify(response.principal);
  }

  /**
   * Clears the in-memory access token, user session, and any legacy storage keys.
   */
  public clearSession(): void {
    this.inMemoryAccessToken = null;
    this.inMemoryTokenExpiresAt = null;
    this.inMemoryUser = null;
    this.purgeLegacyStorage();
    this.notify(null);
  }

  public isTokenExpiringSoon(): boolean {
    if (!this.inMemoryTokenExpiresAt) return true;
    // If less than 60 seconds remaining
    return Date.now() >= this.inMemoryTokenExpiresAt - 60000;
  }

  /**
   * Performs real login with email & password against POST /api/auth/login.
   * Server responds with the short-lived access token and sets an httpOnly, Secure,
   * SameSite refresh token cookie.
   */
  public async login(email: string, password: string): Promise<LoginResponse> {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'same-origin',
      body: JSON.stringify({ email: email.trim(), password }),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `Authentication failed with HTTP ${res.status}`);
    }

    const data: LoginResponse = await res.json();
    this.saveSession(data);
    return data;
  }

  /**
   * Performs silent refresh via POST /api/auth/refresh.
   * The browser automatically sends the httpOnly, Secure, SameSite refresh token cookie.
   */
  public async refreshAccessToken(): Promise<string | null> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = (async () => {
      try {
        const res = await fetch('/api/auth/refresh', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'same-origin',
          body: JSON.stringify({}),
        });

        if (!res.ok) {
          this.clearSession();
          return null;
        }

        const data: LoginResponse = await res.json();
        this.saveSession(data);
        return data.access_token;
      } catch (err) {
        console.warn('[AuthClient] Silent refresh failed:', err);
        this.clearSession();
        return null;
      } finally {
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  /**
   * Performs logout by asking the server to revoke the session and clear the httpOnly cookie,
   * while clearing all in-memory credentials.
   */
  public async logout(): Promise<void> {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({}),
      });
    } catch {
      // Ignore network errors during logout
    }
    this.clearSession();
  }

  /**
   * Universal authenticated fetch wrapper that attaches Authorization: Bearer <token>
   * from in-memory state and automatically refreshes tokens if expired or on 401 response.
   */
  public async fetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
    let token = this.getAccessToken();

    // Check if token is near expiration and refresh proactively
    if (token && this.isTokenExpiringSoon()) {
      const refreshedToken = await this.refreshAccessToken();
      if (refreshedToken) {
        token = refreshedToken;
      }
    }

    const headers = new Headers(init.headers || {});
    // Ensure x-bypass-auth is never sent
    headers.delete('x-bypass-auth');
    headers.delete('X-Bypass-Auth');

    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    const modifiedInit: RequestInit = {
      ...init,
      headers,
      credentials: init.credentials || 'same-origin',
    };

    let response = await fetch(input, modifiedInit);

    // If 401 Unauthorized, attempt one silent refresh using the httpOnly cookie and retry
    if (response.status === 401) {
      const newToken = await this.refreshAccessToken();
      if (newToken) {
        headers.set('Authorization', `Bearer ${newToken}`);
        response = await fetch(input, {
          ...init,
          headers,
          credentials: init.credentials || 'same-origin',
        });
      }
    }

    return response;
  }

  /**
   * Performs authenticated password rotation via POST /api/auth/change-password.
   */
  public async changePassword(currentPassword: string, newPassword: string): Promise<{ success: boolean; message: string }> {
    const res = await this.fetch('/api/auth/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `Password change failed with HTTP ${res.status}`);
    }

    return data;
  }
}

export const authClient = new AuthClient();
export const authenticatedFetch = authClient.fetch.bind(authClient);
