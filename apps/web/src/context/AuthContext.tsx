import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authClient, AuthenticatedUser, LoginResponse } from '../lib/authClient.ts';

interface AuthContextType {
  user: AuthenticatedUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, pass: string) => Promise<LoginResponse>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<string | null>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthenticatedUser | null>(() => authClient.getUser());
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    // Initial session validation or silent refresh via httpOnly cookie
    async function initAuth() {
      const storedToken = authClient.getAccessToken();

      if (storedToken && authClient.getUser()) {
        if (authClient.isTokenExpiringSoon()) {
          await authClient.refreshAccessToken();
        }
        setUser(authClient.getUser());
      } else {
        // Attempt silent refresh using the server-set httpOnly refresh cookie
        try {
          const newToken = await authClient.refreshAccessToken();
          if (newToken) {
            setUser(authClient.getUser());
          } else {
            setUser(null);
          }
        } catch {
          setUser(null);
        }
      }
      setIsLoading(false);
    }

    initAuth();

    // Subscribe to auth state changes across tabs/windows
    const unsubscribe = authClient.subscribe((updatedUser) => {
      setUser(updatedUser);
    });

    return unsubscribe;
  }, []);

  const login = useCallback(async (email: string, pass: string) => {
    const res = await authClient.login(email, pass);
    setUser(res.principal);
    return res;
  }, []);

  const logout = useCallback(async () => {
    await authClient.logout();
    setUser(null);
  }, []);

  const refreshToken = useCallback(async () => {
    return authClient.refreshAccessToken();
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: Boolean(user),
        isLoading,
        login,
        logout,
        refreshToken,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
