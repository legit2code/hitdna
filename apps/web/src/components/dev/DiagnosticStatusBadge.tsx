import React from 'react';
import { CheckCircle2, Clock, AlertTriangle, XCircle, RefreshCw, Slash, PlayCircle } from 'lucide-react';

interface DiagnosticStatusBadgeProps {
  status: string;
  size?: 'sm' | 'md';
  pulse?: boolean;
}

export const DiagnosticStatusBadge: React.FC<DiagnosticStatusBadgeProps> = ({ 
  status, 
  size = 'md',
  pulse = false 
}) => {
  const normalized = (status || 'UNKNOWN').toUpperCase();

  const getStyle = () => {
    switch (normalized) {
      case 'COMPLETED':
      case 'RESOLVED':
      case 'ACTIVE':
      case 'HEALTHY':
        return {
          bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
          dotBg: 'bg-emerald-400',
          icon: <CheckCircle2 className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />,
        };
      case 'RUNNING':
      case 'LEASED':
        return {
          bg: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/20',
          dotBg: 'bg-cyan-400',
          icon: <PlayCircle className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />,
        };
      case 'QUEUED':
      case 'PENDING':
      case 'UNRESOLVED':
        return {
          bg: 'bg-amber-500/10 text-amber-300 border-amber-500/20',
          dotBg: 'bg-amber-400',
          icon: <Clock className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />,
        };
      case 'RETRYING':
        return {
          bg: 'bg-indigo-500/10 text-indigo-300 border-indigo-500/20',
          dotBg: 'bg-indigo-400',
          icon: <RefreshCw className={`${size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} animate-spin`} />,
        };
      case 'DEAD_LETTER':
      case 'FAILED':
      case 'UNHEALTHY':
      case 'DEGRADED':
        return {
          bg: 'bg-rose-500/10 text-rose-300 border-rose-500/20',
          dotBg: 'bg-rose-400',
          icon: <XCircle className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />,
        };
      case 'CANCELLED':
      case 'DISCARDED':
        return {
          bg: 'bg-slate-700/30 text-slate-400 border-slate-700',
          dotBg: 'bg-slate-500',
          icon: <Slash className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />,
        };
      default:
        return {
          bg: 'bg-slate-800 text-slate-300 border-slate-700',
          dotBg: 'bg-slate-400',
          icon: <AlertTriangle className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />,
        };
    }
  };

  const style = getStyle();
  const paddingClass = size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center space-x-1.5 font-mono font-medium rounded-md border ${style.bg} ${paddingClass}`}
    >
      {pulse && (
        <span className="relative flex h-1.5 w-1.5">
          <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${style.dotBg} opacity-75`}></span>
          <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${style.dotBg}`}></span>
        </span>
      )}
      {style.icon}
      <span>{normalized}</span>
    </span>
  );
};
