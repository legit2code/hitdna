import React, { useState } from 'react';
import { 
  Info, 
  HelpCircle, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  HelpCircle as UncertainIcon,
  RefreshCw,
  FolderOpen,
  Search,
  Lock,
  Layers
} from 'lucide-react';

// ============================================================================
// 1. HELP TOOLTIP DEFINITIONS & COMPONENT
// ============================================================================

export const FIELD_HELP_DEFINITIONS: Record<string, { title: string; description: string; details?: string[] }> = {
  security_classification: {
    title: 'Security Classification',
    description: 'Mandatory data classification rank governing who can access, project, or execute against this asset.',
    details: [
      'PUBLIC_METADATA (Rank 0): Unrestricted public metadata.',
      'INTERNAL (Rank 1): Internal organization-wide access.',
      'CONFIDENTIAL (Rank 2): Sensitive internal business logic & telemetry.',
      'SECRET (Rank 3): Cryptographic keys, credentials, & proprietary IP.',
      'VAULT_RESTRICTED (Rank 4): Enclave-guarded assets requiring break-glass override.'
    ]
  },
  risk_score: {
    title: 'Multi-Dimensional Risk Score',
    description: 'Composite 0–100 security index evaluated across 6 dimensions: Autonomy, Privileges, Input Exposure, Supply Chain, Code Exec, and Egress.',
    details: [
      'LOW (80–100): Production-certified; zero unmitigated taint sinks.',
      'MODERATE (60–79): Conditional clearance; requires human signoff.',
      'HIGH (40–59): High attack surface or risky sandbox egress.',
      'CRITICAL (0–39): Severe CVE, arbitrary exec, or hard block; deployment blocked.'
    ]
  },
  epistemic_status: {
    title: 'Epistemic Status (Evidence Grounding)',
    description: 'Formal epistemological validity score indicating the certainty and provenance of analysis claims.',
    details: [
      'CONFIRMED: Empirically verified via AST, CFG taint trace, or dynamic sandbox.',
      'REFUTED: Disproven by direct contradiction or signature mismatch.',
      'UNCERTAIN: Heuristic estimate requiring further runtime probing.',
      'CONTRADICTED: Disagreement detected between policy claims and observed AST behaviors.'
    ]
  },
  autonomy_tier: {
    title: 'Autonomy & Execution Scope',
    description: 'Categorization of agent independence and potential side-effect radius during autonomous execution.',
    details: [
      'TIER 1 (Assisted): Read-only suggestions; human executes every tool.',
      'TIER 2 (Supervised): Bounded tool calls with human confirmation on mutation.',
      'TIER 3 (Autonomous): Self-directed loops with strict budget & timeout constraints.',
      'TIER 4 (Multi-Agent Swarm): Spawns dynamic subagents with delegated sub-scopes.'
    ]
  },
  taint_path: {
    title: 'Inter-Procedural Taint Path',
    description: 'Dataflow trajectory tracking unvalidated inputs (sources) traversing call graphs to privileged execution points (sinks) without sanitization.'
  },
  kms_attestation: {
    title: 'Cryptographic KMS Attestation',
    description: 'Ed25519 digital signature over the deterministic package manifest, signed inside a hardware security enclave.'
  }
};

export interface FieldHelpTooltipProps {
  fieldKey?: keyof typeof FIELD_HELP_DEFINITIONS | string;
  customTitle?: string;
  customDescription?: string;
  className?: string;
}

export const FieldHelpTooltip: React.FC<FieldHelpTooltipProps> = ({
  fieldKey,
  customTitle,
  customDescription,
  className = ''
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const def = fieldKey ? FIELD_HELP_DEFINITIONS[fieldKey] : null;
  const title = customTitle || def?.title || 'Field Information';
  const description = customDescription || def?.description || '';
  const details = def?.details || [];

  return (
    <div className={`relative inline-flex items-center ${className}`}>
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); setIsOpen(!isOpen); }}
        onMouseEnter={() => setIsOpen(true)}
        onMouseLeave={() => setIsOpen(false)}
        className="text-slate-400 hover:text-cyan-400 transition-colors p-0.5 rounded focus:outline-none focus:ring-1 focus:ring-cyan-500"
        aria-label={`Help: ${title}`}
      >
        <HelpCircle className="w-3.5 h-3.5" />
      </button>

      {isOpen && (
        <div 
          className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2 w-72 p-3 bg-slate-900 border border-slate-700 rounded-lg shadow-xl text-left text-xs font-sans pointer-events-none transition-opacity"
          style={{ filter: 'drop-shadow(0 10px 15px rgba(0,0,0,0.5))' }}
        >
          <div className="font-semibold text-slate-100 mb-1 flex items-center justify-between">
            <span>{title}</span>
            <span className="text-[10px] font-mono text-cyan-400 uppercase">Guide</span>
          </div>
          <p className="text-slate-300 text-[11px] leading-relaxed mb-2">
            {description}
          </p>
          {details.length > 0 && (
            <div className="border-t border-slate-800 pt-1.5 space-y-1">
              {details.map((d, i) => (
                <div key={i} className="text-[10px] text-slate-400 leading-tight">
                  • {d}
                </div>
              ))}
            </div>
          )}
          {/* Arrow */}
          <div className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-slate-900"></div>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 2. SECURITY CLASSIFICATION BADGE WITH TOOLTIP
// ============================================================================

export interface SecurityClassificationBadgeProps {
  classification?: string;
  showTooltip?: boolean;
}

export const SecurityClassificationBadge: React.FC<SecurityClassificationBadgeProps> = ({ 
  classification = 'INTERNAL',
  showTooltip = true
}) => {
  const norm = classification.toUpperCase();
  let colorStyle = 'bg-slate-800 text-slate-400 border-slate-700';

  if (norm.includes('DATA_UNAVAILABLE') || norm.includes('UNKNOWN')) {
    colorStyle = 'bg-slate-800/80 text-slate-400 border-slate-700/60';
  } else if (norm.includes('PUBLIC')) {
    colorStyle = 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20';
  } else if (norm.includes('INTERNAL')) {
    colorStyle = 'bg-cyan-500/10 text-cyan-300 border-cyan-500/20';
  } else if (norm.includes('CONFIDENTIAL')) {
    colorStyle = 'bg-amber-500/10 text-amber-300 border-amber-500/20';
  } else if (norm.includes('SECRET')) {
    colorStyle = 'bg-purple-500/10 text-purple-300 border-purple-500/20';
  } else if (norm.includes('VAULT')) {
    colorStyle = 'bg-rose-500/10 text-rose-300 border-rose-500/30';
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium border ${colorStyle}`}>
      <Lock className="w-2.5 h-2.5" />
      <span>{norm}</span>
      {showTooltip && <FieldHelpTooltip fieldKey="security_classification" />}
    </span>
  );
};

// ============================================================================
// 3. RISK SCORE BADGE WITH METER & TOOLTIP
// ============================================================================

export interface RiskScoreBadgeProps {
  score: number | string;
  riskBand?: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' | 'NOT_CALCULATED' | string;
  truthState?: string;
  showTooltip?: boolean;
}

export const RiskScoreBadge: React.FC<RiskScoreBadgeProps> = ({
  score,
  riskBand,
  truthState,
  showTooltip = true
}) => {
  const isNotCalculated = score === 'NOT_CALCULATED' || typeof score !== 'number' && isNaN(Number(score));
  const numericScore = isNotCalculated ? null : Number(score);

  const band = riskBand || (numericScore !== null 
    ? (numericScore >= 80 ? 'LOW' : numericScore >= 60 ? 'MODERATE' : numericScore >= 40 ? 'HIGH' : 'CRITICAL')
    : 'NOT_CALCULATED');

  let colorStyle = 'bg-slate-800/80 text-slate-400 border-slate-700'; // NOT_CALCULATED default
  
  if (!isNotCalculated) {
    if (band === 'LOW') {
      colorStyle = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    } else if (band === 'MODERATE') {
      colorStyle = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    } else if (band === 'HIGH') {
      colorStyle = 'bg-orange-500/10 text-orange-400 border-orange-500/30';
    } else if (band === 'CRITICAL') {
      colorStyle = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
    }
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium border ${colorStyle}`}>
      <ShieldCheck className="w-3 h-3" />
      <span>{isNotCalculated ? 'Score: NOT_CALCULATED' : `Score ${numericScore}/100`}</span>
      <span className="opacity-75">[{band}]</span>
      {truthState && <TruthStateBadge truthState={truthState} />}
      {showTooltip && <FieldHelpTooltip fieldKey="risk_score" />}
    </span>
  );
};

// ============================================================================
// 3b. TRUTH STATE BADGE
// ============================================================================

export interface TruthStateBadgeProps {
  truthState?: 'OBSERVED' | 'STATICALLY_DERIVED' | 'INFERRED' | 'SIMULATED' | 'EXTERNAL' | 'USER_DECLARED' | 'FIXTURE' | 'UNKNOWN' | string;
  showTooltip?: boolean;
  className?: string;
}

export const TruthStateBadge: React.FC<TruthStateBadgeProps> = ({
  truthState = 'UNKNOWN',
  showTooltip = false,
  className = ''
}) => {
  const norm = (truthState || 'UNKNOWN').toUpperCase();
  let colorStyle = 'bg-slate-800/90 text-slate-400 border-slate-700/80'; // UNKNOWN
  
  if (norm === 'OBSERVED' || norm === 'CONFIRMED') {
    colorStyle = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
  } else if (norm === 'STATICALLY_DERIVED') {
    colorStyle = 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
  } else if (norm === 'INFERRED') {
    colorStyle = 'bg-indigo-500/10 text-indigo-300 border-indigo-500/30';
  } else if (norm === 'SIMULATED') {
    colorStyle = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
  } else if (norm === 'EXTERNAL') {
    colorStyle = 'bg-sky-500/10 text-sky-400 border-sky-500/30';
  } else if (norm === 'USER_DECLARED') {
    colorStyle = 'bg-blue-500/10 text-blue-300 border-blue-500/30';
  } else if (norm === 'FIXTURE') {
    colorStyle = 'bg-purple-500/10 text-purple-300 border-purple-500/30';
  }

  return (
    <span 
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-medium border ${colorStyle} ${className}`}
      title={`Truth State: ${norm}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80" />
      <span>{norm}</span>
      {showTooltip && <FieldHelpTooltip fieldKey="epistemic_status" />}
    </span>
  );
};

// ============================================================================
// 4. EPISTEMIC STATUS BADGE WITH TOOLTIP
// ============================================================================

export interface EpistemicStatusBadgeProps {
  status: 'CONFIRMED' | 'REFUTED' | 'UNCERTAIN' | 'CONTRADICTED' | string;
  showTooltip?: boolean;
}

export const EpistemicStatusBadge: React.FC<EpistemicStatusBadgeProps> = ({
  status,
  showTooltip = true
}) => {
  const norm = status.toUpperCase();
  let colorStyle = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
  let Icon = CheckCircle2;

  if (norm === 'REFUTED') {
    colorStyle = 'bg-rose-500/10 text-rose-400 border-rose-500/20';
    Icon = XCircle;
  } else if (norm === 'UNCERTAIN') {
    colorStyle = 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    Icon = UncertainIcon;
  } else if (norm === 'CONTRADICTED') {
    colorStyle = 'bg-purple-500/10 text-purple-400 border-purple-500/20';
    Icon = AlertTriangle;
  }

  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium border ${colorStyle}`}>
      <Icon className="w-3 h-3" />
      <span>{norm}</span>
      {showTooltip && <FieldHelpTooltip fieldKey="epistemic_status" />}
    </span>
  );
};

// ============================================================================
// 5. EMPTY STATE COMPONENT
// ============================================================================

export interface EmptyStateProps {
  title: string;
  description: string;
  icon?: React.ReactNode;
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  icon,
  actionLabel,
  onAction,
  className = ''
}) => {
  return (
    <div className={`flex flex-col items-center justify-center p-8 text-center bg-slate-900/50 border border-slate-800 rounded-xl ${className}`}>
      <div className="h-12 w-12 rounded-xl bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-slate-400 mb-3.5">
        {icon || <FolderOpen className="w-6 h-6 text-slate-400" />}
      </div>
      <h3 className="text-sm font-semibold text-slate-200 mb-1">{title}</h3>
      <p className="text-xs text-slate-400 max-w-sm mb-4 leading-relaxed">{description}</p>
      {actionLabel && onAction && (
        <button
          onClick={onAction}
          className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
};

// ============================================================================
// 6. LOADING STATE COMPONENT
// ============================================================================

export interface LoadingStateProps {
  title?: string;
  message?: string;
  className?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  title = 'Loading Data',
  message = 'Fetching records from the CAIM intelligence plane...',
  className = ''
}) => {
  return (
    <div className={`flex flex-col items-center justify-center p-12 text-center bg-slate-900/30 border border-slate-800/80 rounded-xl ${className}`}>
      <RefreshCw className="w-7 h-7 text-cyan-400 animate-spin mb-3.5" />
      <h3 className="text-sm font-medium text-slate-200 mb-1">{title}</h3>
      <p className="text-xs text-slate-400 font-mono">{message}</p>
    </div>
  );
};

// ============================================================================
// 7. FIRST VISIT WALKTHROUGH MODAL
// ============================================================================

export { FirstVisitWalkthroughModal } from './FirstVisitWalkthroughModal.tsx';
export type { FirstVisitWalkthroughModalProps } from './FirstVisitWalkthroughModal.tsx';


