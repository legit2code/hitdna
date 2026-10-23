import React, { ReactNode } from 'react';

interface DiagnosticMetricsCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: ReactNode;
  badge?: string;
  badgeVariant?: 'emerald' | 'cyan' | 'amber' | 'rose' | 'slate';
}

export const DiagnosticMetricsCard: React.FC<DiagnosticMetricsCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  badge,
  badgeVariant = 'cyan',
}) => {
  const getBadgeClass = () => {
    switch (badgeVariant) {
      case 'emerald':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      case 'amber':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'rose':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      case 'slate':
        return 'bg-slate-800 text-slate-400 border-slate-700';
      case 'cyan':
      default:
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20';
    }
  };

  return (
    <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-4 flex flex-col justify-between">
      <div className="flex items-start justify-between">
        <div className="flex items-center space-x-2 text-slate-400 text-xs font-mono">
          <div className="text-cyan-400">{icon}</div>
          <span>{title}</span>
        </div>
        {badge && (
          <span className={`text-[10px] font-mono font-medium px-2 py-0.5 rounded border ${getBadgeClass()}`}>
            {badge}
          </span>
        )}
      </div>
      <div className="mt-3">
        <div className="text-xl font-bold font-mono text-slate-100 tracking-tight">{value}</div>
        {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
      </div>
    </div>
  );
};
