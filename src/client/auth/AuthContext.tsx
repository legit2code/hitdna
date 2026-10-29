/**
 * React Auth Context & State Provider
 * Engine: PF-05 (Authentication, Roles & Authorization Engine)
 * Architecture Version: 5.0.0 | Phase: P06
 */

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { AuthUser, UserRole } from '../../contracts/auth.js';
import { signInWithGoogle, signOut, subscribeToAuthState } from './authService.js';

export interface AuthContextValue {
  user: AuthUser | null;
  role: UserRole;
  loading: boolean;
  isAuthenticated: boolean;
  isAdmin: boolean;
  isResearcher: boolean;
  signIn: () => Promise<void>;
  logOut: () => Promise<void>;
  setUserForDevTesting?: (user: AuthUser | null) => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    try {
      const unsubscribe = subscribeToAuthState((authUser) => {
        setUser(authUser);
        setLoading(false);
      });
      return () => unsubscribe();
    } catch {
      // In SSR or testing contexts where Firebase Auth is mocked/offline
      setLoading(false);
    }
  }, []);

  const handleSignIn = async () => {
    setLoading(true);
    try {
      const authUser = await signInWithGoogle();
      setUser(authUser);
    } finally {
      setLoading(false);
    }
  };

  const handleSignOut = async () => {
    setLoading(true);
    try {
      await signOut();
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const role: UserRole = user?.role || 'USER';
  const isAuthenticated = !!user;
  const isAdmin = role === 'ADMIN';
  const isResearcher = role === 'RESEARCHER' || role === 'ADMIN';

  const value: AuthContextValue = {
    user,
    role,
    loading,
    isAuthenticated,
    isAdmin,
    isResearcher,
    signIn: handleSignIn,
    logOut: handleSignOut,
    setUserForDevTesting: setUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
