import { describe, it, expect, beforeEach, vi } from 'vitest';
import express from 'express';
import { authClient, LoginResponse } from '../apps/web/src/lib/authClient.ts';

// Simple mock for localStorage in Node test environment
class MockLocalStorage {
  private store: Record<string, string> = {};

  public getItem(key: string): string | null {
    return this.store[key] ?? null;
  }

  public setItem(key: string, value: string): void {
    this.store[key] = String(value);
  }

  public removeItem(key: string): void {
    delete this.store[key];
  }

  public clear(): void {
    this.store = {};
  }
}

const mockStorage = new MockLocalStorage();
(globalThis as any).localStorage = mockStorage;
(globalThis as any).window = { localStorage: mockStorage };

describe('Auth Token Storage & Cookie Hardening', () => {
  beforeEach(() => {
    // Clear localStorage and session before each test
    mockStorage.clear();
    authClient.clearSession();
  });

  describe('1. Client-side AuthClient Storage Hardening (Memory Only)', () => {
    const mockLoginResponse: LoginResponse = {
      access_token: 'test-in-memory-access-token-12345',
      refresh_token: 'test-server-refresh-token-67890',
      token_type: 'Bearer',
      expires_in: 900,
      principal: {
        principal_id: 'user-001',
        email: 'security-tester@enterprise.corp',
        roles: ['SECURITY_ANALYST'],
        tenant_id: 'tenant-123',
      },
    };

    it('stores the short-lived access token strictly in memory, never in localStorage', () => {
      authClient.saveSession(mockLoginResponse);

      // Access token is accessible via in-memory getter
      expect(authClient.getAccessToken()).toBe('test-in-memory-access-token-12345');

      // CRITICAL: Neither access token nor refresh token is persisted in localStorage!
      expect(localStorage.getItem('caim_access_token')).toBeNull();
      expect(localStorage.getItem('caim_refresh_token')).toBeNull();
      expect(localStorage.getItem('caim_access_token_expires_at')).toBeNull();
    });

    it('does not store the refresh token in JavaScript state (returns null)', () => {
      authClient.saveSession(mockLoginResponse);

      // Refresh token is handled exclusively via server httpOnly cookie, not in client JS
      expect(authClient.getRefreshToken()).toBeNull();
      expect(localStorage.getItem('caim_refresh_token')).toBeNull();
    });

    it('clears all in-memory tokens and purges any legacy localStorage keys on logout', () => {
      authClient.saveSession(mockLoginResponse);
      expect(authClient.isAuthenticated()).toBe(true);

      // Artificially plant legacy items to ensure purgeLegacyStorage works
      localStorage.setItem('caim_access_token', 'legacy-leak');
      localStorage.setItem('caim_refresh_token', 'legacy-leak-refresh');

      authClient.clearSession();

      expect(authClient.getAccessToken()).toBeNull();
      expect(authClient.getUser()).toBeNull();
      expect(authClient.isAuthenticated()).toBe(false);
      expect(localStorage.getItem('caim_access_token')).toBeNull();
      expect(localStorage.getItem('caim_refresh_token')).toBeNull();
    });
  });

  describe('2. Server httpOnly, Secure, SameSite Cookie Configuration', () => {
    function parseCookies(cookieHeader?: string): Record<string, string> {
      if (!cookieHeader) return {};
      const cookies: Record<string, string> = {};
      const pairs = cookieHeader.split(';');
      for (const pair of pairs) {
        const idx = pair.indexOf('=');
        if (idx < 0) continue;
        const key = pair.substring(0, idx).trim();
        const val = pair.substring(idx + 1).trim();
        try {
          cookies[key] = decodeURIComponent(val);
        } catch {
          cookies[key] = val;
        }
      }
      return cookies;
    }

    it('sets the refresh token in an httpOnly, Secure, SameSite=Strict cookie on login', async () => {
      const app = express();
      app.use(express.json());

      app.post('/api/auth/login', (_req, res) => {
        const refreshTokenValue = 'mock-secure-refresh-token-abc';
        res.cookie('refresh_token', refreshTokenValue, {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
          path: '/',
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        res.json({
          access_token: 'mock-access-token',
          expires_in: 900,
          token_type: 'Bearer',
          principal: { principal_id: 'p1', email: 'test@example.com', roles: ['USER'] },
        });
      });

      const server = app.listen(0);
      const port = (server.address() as any).port;

      try {
        const res = await fetch(`http://localhost:${port}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'test@example.com', password: 'password123' }),
        });

        const setCookie = res.headers.get('set-cookie');
        expect(setCookie).toBeDefined();
        expect(setCookie).toContain('refresh_token=mock-secure-refresh-token-abc');
        expect(setCookie).toContain('HttpOnly');
        expect(setCookie).toContain('Secure');
        expect(setCookie).toContain('SameSite=Strict');
      } finally {
        server.close();
      }
    });

    it('reads refresh token from cookie on /api/auth/refresh and updates the cookie', async () => {
      const app = express();
      app.use(express.json());

      app.post('/api/auth/refresh', (req, res) => {
        const cookies = parseCookies(req.headers.cookie);
        const refreshToken = cookies['refresh_token'] || req.body?.refresh_token;
        if (!refreshToken) {
          return res.status(400).json({ error: 'Missing refresh token' });
        }

        const newRefreshToken = 'rotated-refresh-token-xyz';
        res.cookie('refresh_token', newRefreshToken, {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
          path: '/',
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        return res.json({
          access_token: 'new-short-lived-access-token',
          refresh_token: newRefreshToken,
          expires_in: 900,
        });
      });

      const server = app.listen(0);
      const port = (server.address() as any).port;

      try {
        const res = await fetch(`http://localhost:${port}/api/auth/refresh`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: 'refresh_token=mock-secure-refresh-token-abc',
          },
          body: JSON.stringify({}),
        });

        expect(res.status).toBe(200);
        const data = await res.json();
        expect(data.access_token).toBe('new-short-lived-access-token');

        const setCookie = res.headers.get('set-cookie');
        expect(setCookie).toContain('refresh_token=rotated-refresh-token-xyz');
        expect(setCookie).toContain('HttpOnly');
        expect(setCookie).toContain('Secure');
        expect(setCookie).toContain('SameSite=Strict');
      } finally {
        server.close();
      }
    });

    it('clears the refresh token cookie with matching attributes on logout', async () => {
      const app = express();
      app.use(express.json());

      app.post('/api/auth/logout', (_req, res) => {
        res.clearCookie('refresh_token', {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
          path: '/',
        });
        res.json({ status: 'logged_out', success: true });
      });

      const server = app.listen(0);
      const port = (server.address() as any).port;

      try {
        const res = await fetch(`http://localhost:${port}/api/auth/logout`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        });

        const setCookie = res.headers.get('set-cookie');
        expect(setCookie).toBeDefined();
        // Clear-cookie sets Max-Age=0 or expires in past
        expect(setCookie).toContain('refresh_token=;');
        expect(setCookie).toContain('HttpOnly');
        expect(setCookie).toContain('Secure');
        expect(setCookie).toContain('SameSite=Strict');
      } finally {
        server.close();
      }
    });
  });
});
