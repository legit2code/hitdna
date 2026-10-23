import React from 'react';
import { ShieldAlert, ShieldCheck, UserCheck, AlertOctagon } from 'lucide-react';

interface DiagnosticRoleGuardProps {
  currentRole: string;
  onRoleChange: (newRole: string) => void;
  authorized: boolean;
  error?: string | null;
}

export const DiagnosticRoleGuard: React.FC<DiagnosticRoleGuardProps> = ({
  currentRole,
  onRoleChange,
  authorized,
  error,
}) => {
  const testRoles = [
    { role: 'operator', label: 'Operator (Authorized)', allowed: true },
    { role: 'admin', label: 'Admin (Authorized)', allowed: true },
    { role: 'auditor', label: 'Auditor (Authorized)', allowed: true },
    { role: 'system_engineer', label: 'System Engineer (Authorized)', allowed: true },
    { role: 'analyst', label: 'Analyst (Denied)', allowed: false },
    { role: 'user', label: 'Standard User (Denied)', allowed: false },
    { role: 'anonymous', label: 'Anonymous (Denied)', allowed: false },
  ];

  return (
    <div className="bg-slate-900/90 border-b border-slate-800 px-4 py-2.5">
      <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center space-x-2">
          {authorized ? (
            <div className="flex items-center space-x-1.5 text-emerald-400 font-mono">
              <ShieldCheck className="w-4 h-4" />
              <span>RBAC Policy: Protected Diagnostic Access Granted</span>
            </div>
          ) : (
            <div className="flex items-center space-x-1.5 text-rose-400 font-mono">
              <ShieldAlert className="w-4 h-4" />
              <span>RBAC Policy: Diagnostic Role Guard Active (403 Forbidden)</span>
            </div>
          )}
        </div>

        <div className="flex items-center space-x-2 font-mono">
          <span className="text-slate-400 text-[11px] flex items-center">
            <UserCheck className="w-3.5 h-3.5 mr-1 text-cyan-400" />
            Simulate Role:
          </span>
          <select
            value={currentRole}
            onChange={(e) => onRoleChange(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded px-2.5 py-1 font-mono focus:outline-none focus:border-cyan-500"
          >
            {testRoles.map((r) => (
              <option key={r.role} value={r.role}>
                {r.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {!authorized && error && (
        <div className="max-w-7xl mx-auto mt-2 p-3 bg-rose-950/30 border border-rose-500/40 rounded-lg text-xs font-mono text-rose-300 flex items-start space-x-2">
          <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold text-rose-200">Unauthorized Diagnostic Access</div>
            <p className="text-rose-300/80 text-[11px] mt-0.5">{error}</p>
            <p className="text-slate-400 text-[11px] mt-1">
              Select an authorized diagnostic role (e.g. <code>operator</code> or <code>admin</code>) from the role selector above to view live control plane telemetry.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
