/**
 * Client Firebase Authentication Service
 * Engine: PF-05 (Authentication, Roles & Authorization Engine)
 * Architecture Version: 5.0.0 | Phase: P06
 *
 * Provides Google Sign-In with Firebase Auth, session lifecycle management,
 * and role-based client token exchange. Zero secret exposure to client bundle.
 */

import { initializeApp, getApps, getApp, FirebaseApp } from 'firebase/app';
import {
  getAuth,
  signInWithPopup,
  GoogleAuthProvider,
  signOut as firebaseSignOut,
  onAuthStateChanged,
  User as FirebaseUser,
  Auth,
} from 'firebase/auth';
import { AuthUser, UserRole } from '../../contracts/auth.js';

export interface FirebaseClientConfig {
  apiKey: string;
  authDomain: string;
  projectId: string;
  storageBucket: string;
  messagingSenderId: string;
  appId: string;
}

// Client configuration safe for browser DevTools (public credentials only)
const DEFAULT_CLIENT_CONFIG: FirebaseClientConfig = {
  apiKey: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_FIREBASE_API_KEY) || 'AIzaSy-HITDNA-PUBLIC-CLIENT-KEY',
  authDomain: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_FIREBASE_AUTH_DOMAIN) || 'hit-dna-intelligence.firebaseapp.com',
  projectId: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_FIREBASE_PROJECT_ID) || 'hit-dna-intelligence',
  storageBucket: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_FIREBASE_STORAGE_BUCKET) || 'hit-dna-intelligence.appspot.com',
  messagingSenderId: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_FIREBASE_MESSAGING_SENDER_ID) || '1234567890',
  appId: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_FIREBASE_APP_ID) || '1:1234567890:web:abcdef123456',
};

let appInstance: FirebaseApp | null = null;
let authInstance: Auth | null = null;

export function getFirebaseApp(config?: Partial<FirebaseClientConfig>): FirebaseApp {
  if (!appInstance) {
    const existing = getApps();
    if (existing.length > 0) {
      appInstance = getApp();
    } else {
      appInstance = initializeApp({ ...DEFAULT_CLIENT_CONFIG, ...config });
    }
  }
  return appInstance;
}

export function getClientAuth(): Auth {
  if (!authInstance) {
    const app = getFirebaseApp();
    authInstance = getAuth(app);
  }
  return authInstance;
}

/**
 * Maps a Firebase user to the canonical AuthUser contract.
 * Extracts custom claims or default USER role.
 */
export async function mapFirebaseUser(user: FirebaseUser): Promise<AuthUser> {
  const tokenResult = await user.getIdTokenResult();
  const role: UserRole = (tokenResult.claims['role'] as UserRole) || 'USER';

  return {
    uid: user.uid,
    email: user.email,
    displayName: user.displayName,
    photoURL: user.photoURL,
    role,
    customClaims: tokenResult.claims as Record<string, unknown>,
    isAnonymous: user.isAnonymous,
    createdAt: user.metadata.creationTime || new Date().toISOString(),
  };
}

/**
 * Initiates Google Sign-In with Firebase Authentication.
 */
export async function signInWithGoogle(): Promise<AuthUser> {
  const auth = getClientAuth();
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });

  const result = await signInWithPopup(auth, provider);
  return mapFirebaseUser(result.user);
}

/**
 * Signs out current user.
 */
export async function signOut(): Promise<void> {
  const auth = getClientAuth();
  await firebaseSignOut(auth);
}

/**
 * Subscribes to auth state changes.
 */
export function subscribeToAuthState(callback: (user: AuthUser | null) => void): () => void {
  const auth = getClientAuth();
  return onAuthStateChanged(auth, async (firebaseUser) => {
    if (firebaseUser) {
      try {
        const authUser = await mapFirebaseUser(firebaseUser);
        callback(authUser);
      } catch (err) {
        console.error('Failed to map authenticated Firebase user', err);
        callback(null);
      }
    } else {
      callback(null);
    }
  });
}
