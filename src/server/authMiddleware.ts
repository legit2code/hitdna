/**
 * Server Authentication & Route Authorization Middleware
 * Engine: PF-05 (Authentication, Roles & Authorization Engine)
 * Architecture Version: 5.0.0 | Phase: P06
 */

import { Request, Response, NextFunction } from 'express';
import { AuthUser, UserRole, UserPermission, AuthorizationError } from '../contracts/auth.js';
import { defaultAuthGuard } from '../domain/authorizationGuard.js';

// Extend Express Request interface to carry authenticated user
declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

/**
 * Resolves authenticated user from standard Authorization Bearer header
 * or explicit development/test headers (x-test-user-id, x-test-user-role).
 */
export function authenticateToken(req: Request, _res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization'];
  const testUserId = req.headers['x-test-user-id'] as string | undefined;
  const testUserRole = (req.headers['x-test-user-role'] as UserRole | undefined) || 'USER';

  if (testUserId) {
    req.user = {
      uid: testUserId,
      email: `${testUserId}@hitdna.internal`,
      displayName: `User ${testUserId}`,
      photoURL: null,
      role: testUserRole,
      createdAt: new Date().toISOString(),
    };
    return next();
  }

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    try {
      // In production or test mock, decode bearer token payload
      const parsed = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
      if (parsed.uid && parsed.role) {
        req.user = {
          uid: parsed.uid,
          email: parsed.email || null,
          displayName: parsed.displayName || null,
          photoURL: parsed.photoURL || null,
          role: parsed.role,
          customClaims: parsed.customClaims,
          createdAt: parsed.createdAt || new Date().toISOString(),
        };
      }
    } catch {
      // Invalid token, leave req.user undefined
    }
  }

  next();
}

/**
 * Guard middleware ensuring request is authenticated.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({
      error: 'UNAUTHENTICATED',
      message: 'Authentication required to access this endpoint',
      timestamp: new Date().toISOString(),
    });
    return;
  }
  next();
}

/**
 * Guard middleware requiring one of the specified roles.
 */
export function requireRole(...roles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'UNAUTHENTICATED',
        message: 'Authentication required for role verification',
        timestamp: new Date().toISOString(),
      });
      return;
    }

    try {
      defaultAuthGuard.assertRole(req.user, roles, req.path);
      next();
    } catch (err: any) {
      if (err instanceof AuthorizationError) {
        res.status(403).json({
          error: err.code,
          message: err.message,
          requiredRoles: roles,
          userRole: req.user.role,
          timestamp: new Date().toISOString(),
        });
        return;
      }
      res.status(403).json({ error: 'FORBIDDEN', message: 'Access denied' });
    }
  };
}

/**
 * Guard middleware requiring a specific permission.
 */
export function requirePermission(permission: UserPermission) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'UNAUTHENTICATED',
        message: 'Authentication required for permission check',
        timestamp: new Date().toISOString(),
      });
      return;
    }

    try {
      defaultAuthGuard.assertPermission(req.user, permission, req.path);
      next();
    } catch (err: any) {
      if (err instanceof AuthorizationError) {
        res.status(403).json({
          error: err.code,
          message: err.message,
          requiredPermission: permission,
          userRole: req.user.role,
          timestamp: new Date().toISOString(),
        });
        return;
      }
      res.status(403).json({ error: 'FORBIDDEN', message: 'Access denied' });
    }
  };
}
