import React, { useState } from 'react';
import { 
  Sparkles, 
  Bot, 
  ShieldCheck, 
  GitPullRequest, 
  Package, 
  Cpu, 
  ArrowRight, 
  X, 
  CheckCircle2, 
  FileCode,
  Lock,
  Layers
} from 'lucide-react';

export interface FirstVisitWalkthroughModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateToWorkflow?: (workflow: string) => void;
}

export const FirstVisitWalkthroughModal: React.FC<FirstVisitWalkthroughModalProps> = ({
  isOpen,
  onClose,
  onNavigateToWorkflow,
}) => {
  const [step, setStep] = useState(0);

  if (!isOpen) return null;

  const steps = [
    {
      title: 'Welcome to CAIM Agent Assurance Platform',
      badge: 'Zero-Knowledge Onboarding',
      icon: Sparkles,
      description: 'CAIM continuously discovers, statically analyzes, taint-tracks, and scores autonomous AI agents across 7 public and private registries.',
      highlight: 'Every agent in the catalog is pre-analyzed with a 3-good / 3-bad use case matrix, AST taint traces, and cryptographically signed packaging gates.',
      action: 'Start Tour',
      features: [
        'Deterministic AST Parser with zero ungrounded claims',
        '7 Source Adapters (GitHub, GitLab, PyPI, npm, Hugging Face, Docker Hub, Codeberg)',
        'Epistemic Grounding & Vector RAG with direct source citations',
      ]
    },
    {
      title: 'Autonomous Discovery & Pre-Analyzed Library',
      badge: 'Continuous Pipeline',
      icon: Bot,
      description: 'Our background worker polls source registries autonomously. Discovered agents are automatically ingested into the Assurance Library.',
      highlight: 'Click "Ask RAG" on any agent card to ask natural-language questions scoped to its verified findings, AST privileges, and evidence graph.',
      action: 'Next: Security & Risk Gates',
      features: [
        'Automatic 3-Good / 3-Bad Use-Case evaluation matrix',
        'Multi-dimensional composite risk scoring (0-100 scale)',
        'Zero-mock real static AST & taint flow extraction',
      ]
    },
    {
      title: 'Multi-Hop Taint & Cryptographic Attestation',
      badge: 'Deterministic Verification',
      icon: ShieldCheck,
      description: 'Explore inter-procedural AST taint paths, query the vector knowledge base, inspect policy rule gates, and generate Ed25519 KMS-signed deployment bundles.',
      highlight: 'Switch between RBAC roles (Security Auditor, Release Manager, Diagnostic Admin) to inspect role-scoped policies and audit logs.',
      action: 'Enter Platform',
      features: [
        'KMS Ed25519 and SLSA Provenance Attestation Level 3',
        'Automated AST code remediation and diff patch proposals',
        'Full Definition-of-Done (DoD) verification matrix',
      ]
    },
  ];

  const current = steps[step];
  const Icon = current.icon;

  const handleFinish = () => {
    localStorage.setItem('caim_walkthrough_seen', 'true');
    onClose();
    if (onNavigateToWorkflow) {
      onNavigateToWorkflow('library');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5 relative">
        
        {/* Close Button */}
        <button
          onClick={handleFinish}
          className="absolute top-5 right-5 text-slate-400 hover:text-slate-200 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Icon className="w-4 h-4" />
            </div>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              {current.badge}
            </span>
          </div>
          <span className="text-xs text-slate-400 font-mono pr-6">Step {step + 1} of {steps.length}</span>
        </div>

        <div className="space-y-2">
          <h3 className="text-lg font-bold text-slate-100">{current.title}</h3>
          <p className="text-xs text-slate-300 leading-relaxed">{current.description}</p>
        </div>

        {/* Feature list */}
        <div className="space-y-1.5 py-1">
          {current.features.map((feat, i) => (
            <div key={i} className="flex items-center space-x-2 text-xs text-slate-300">
              <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span>{feat}</span>
            </div>
          ))}
        </div>

        <div className="p-3.5 bg-slate-950/80 border border-slate-800 rounded-xl">
          <p className="text-xs text-cyan-300/90 font-mono leading-relaxed">
            💡 {current.highlight}
          </p>
        </div>

        <div className="flex items-center justify-between pt-2 border-t border-slate-800">
          <button
            onClick={handleFinish}
            className="text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            Skip walkthrough
          </button>

          <div className="flex items-center space-x-2">
            {step > 0 && (
              <button
                onClick={() => setStep(s => s - 1)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors"
              >
                Back
              </button>
            )}
            <button
              onClick={() => {
                if (step < steps.length - 1) {
                  setStep(s => s + 1);
                } else {
                  handleFinish();
                }
              }}
              className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors flex items-center space-x-1.5"
            >
              <span>{current.action}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
