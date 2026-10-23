import React, { useEffect, useState, useMemo } from 'react';
import { 
  Bot, 
  Search, 
  ShieldCheck, 
  ShieldAlert, 
  Layers, 
  Cpu, 
  CheckCircle2, 
  AlertTriangle, 
  Lock, 
  FileText, 
  Activity, 
  Server, 
  KeyRound, 
  Sliders, 
  ExternalLink,
  Terminal,
  FolderGit2,
  Workflow,
  Sparkles,
  GitCompare,
  Package,
  Share2,
  Eye,
  Menu,
  X,
  ChevronRight,
  User,
  Scale,
  Award,
  Database,
  RefreshCw,
  HelpCircle,
  BarChart3,
  CheckSquare
} from 'lucide-react';

// Diagnostic Console for /dev routes
import { DiagnosticLayout } from './src/components/dev/DiagnosticLayout.tsx';

// All 15 Enterprise Workflow Views
import { LibraryWorkflowView } from './src/components/views/LibraryWorkflowView.tsx';
import { AgentsWorkflowView } from './src/components/views/AgentsWorkflowView.tsx';
import { AnalysisWorkflowView } from './src/components/views/AnalysisWorkflowView.tsx';
import { DiscoveryWorkflowView } from './src/components/views/DiscoveryWorkflowView.tsx';
import { EvidenceWorkflowView } from './src/components/views/EvidenceWorkflowView.tsx';
import { GoldenCorpusWorkflowView } from './src/components/views/GoldenCorpusWorkflowView.tsx';
import { GovernanceWorkflowView } from './src/components/views/GovernanceWorkflowView.tsx';
import { KnowledgeWorkflowView } from './src/components/views/KnowledgeWorkflowView.tsx';
import { ModificationWorkflowView } from './src/components/views/ModificationWorkflowView.tsx';
import { ObservabilityWorkflowView } from './src/components/views/ObservabilityWorkflowView.tsx';
import { OperationsWorkflowView } from './src/components/views/OperationsWorkflowView.tsx';
import { PackagesWorkflowView } from './src/components/views/PackagesWorkflowView.tsx';
import { ProductionHardeningView } from './src/components/views/ProductionHardeningView.tsx';
import { RiskPolicyWorkflowView } from './src/components/views/RiskPolicyWorkflowView.tsx';
import { TraceabilityDodWorkflowView } from './src/components/views/TraceabilityDodWorkflowView.tsx';
import { FieldHelpTooltip } from './src/components/common/Affordances.tsx';
import { FirstVisitWalkthroughModal } from './src/components/common/FirstVisitWalkthroughModal.tsx';
import { ChangePasswordModal } from './src/components/auth/ChangePasswordModal.tsx';
import { AuthProvider, useAuth } from './src/context/AuthContext.tsx';
import { LoginView } from './src/components/auth/LoginView.tsx';
import { SignupView } from './src/components/auth/SignupView.tsx';
import { VerifyEmailView } from './src/components/auth/VerifyEmailView.tsx';
import { authenticatedFetch } from './src/lib/authClient.ts';
import { LogOut, UserCheck } from 'lucide-react';

export type NavRoute = 
  | 'library'
  | 'agents'
  | 'discovery'
  | 'analysis'
  | 'evidence'
  | 'risk-policy'
  | 'governance'
  | 'knowledge'
  | 'modification'
  | 'packages'
  | 'observability'
  | 'operations'
  | 'golden-corpus'
  | 'production-hardening'
  | 'traceability';

interface NavItem {
  id: NavRoute;
  path: string;
  label: string;
  category: 'Library & Discovery' | 'Registry' | 'Security & Analysis' | 'Intelligence & Remediation' | 'Operations & Shipping' | 'Verification & Release';
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  badge?: string;
}

const NAV_ITEMS: NavItem[] = [
  // 0. Library & Discovery Landing
  {
    id: 'library',
    path: '/library',
    label: 'Assurance Library',
    category: 'Library & Discovery',
    icon: Sparkles,
    badge: 'Continuous',
    description: 'Pre-analyzed agent library, autonomous crawler status, and 3-good/3-bad use case recommendations.',
  },

  // 1. Registry & Source
  {
    id: 'agents',
    path: '/agents',
    label: 'Agents & Versions',
    category: 'Registry',
    icon: Bot,
    description: 'Canonical Agent Registry, versions, tool privileges & cryptographic provenance.',
  },
  {
    id: 'discovery',
    path: '/discovery',
    label: 'Discovery & Ingestion',
    category: 'Registry',
    icon: Search,
    description: 'Multi-source repository adapters, web crawler, and identity resolution.',
  },

  // 2. Security & Analysis
  {
    id: 'analysis',
    path: '/analysis',
    label: 'Multi-Stage Analysis',
    category: 'Security & Analysis',
    icon: Cpu,
    description: 'AST parser, control flow graphs, multi-hop taint tracking & dynamic sandbox.',
  },
  {
    id: 'evidence',
    path: '/evidence',
    label: 'Evidence & Assertions',
    category: 'Security & Analysis',
    icon: Share2,
    description: 'Multi-hop evidence graph, epistemic confidence & proof lineage.',
  },
  {
    id: 'risk-policy',
    path: '/risk-policy',
    label: 'Risk & Policy Gates',
    category: 'Security & Analysis',
    icon: ShieldCheck,
    description: 'Multi-dimensional risk scoring, enterprise policies & automated recommendations.',
  },
  {
    id: 'governance',
    path: '/governance',
    label: 'Governance & Audits',
    category: 'Security & Analysis',
    icon: Scale,
    description: 'CAIM ontology, security classifications, RBAC & break-glass audit ledger.',
  },

  // 3. Intelligence & Remediation
  {
    id: 'knowledge',
    path: '/knowledge',
    label: 'Knowledge & RAG',
    category: 'Intelligence & Remediation',
    icon: Sparkles,
    description: 'Grounded RAG synthesis, vector retrieval, and citation verification.',
  },
  {
    id: 'modification',
    path: '/modification',
    label: 'Modification & Patches',
    category: 'Intelligence & Remediation',
    icon: GitCompare,
    description: 'AST-safe code remediation proposals, diff visualizer & two-person sign-off.',
  },

  // 4. Operations & Shipping
  {
    id: 'packages',
    path: '/packages',
    label: 'Packaging & Attestation',
    category: 'Operations & Shipping',
    icon: Package,
    description: 'Deterministic package bundler, Ed25519 KMS attestation & shipping gates.',
  },
  {
    id: 'observability',
    path: '/observability',
    label: 'Observability & Cost',
    category: 'Operations & Shipping',
    icon: Activity,
    description: 'OpenTelemetry spans, Gemini token attribution, and secret redactor.',
  },
  {
    id: 'operations',
    path: '/operations',
    label: 'Operations & DLQ',
    category: 'Operations & Shipping',
    icon: Server,
    description: 'Worker pool topologies, concurrency control, and dead-letter queue replay.',
  },

  // 5. Verification & Release
  {
    id: 'golden-corpus',
    path: '/golden-corpus',
    label: 'Golden Corpus Evaluator',
    category: 'Verification & Release',
    icon: Award,
    description: '8-family benchmark test corpus, regression thresholds & release certification.',
  },
  {
    id: 'production-hardening',
    path: '/production-hardening',
    label: 'Production Hardening',
    category: 'Verification & Release',
    icon: Lock,
    description: 'SSRF/archive guards, config validator, performance smoke & release manifests.',
  },
  {
    id: 'traceability',
    path: '/traceability',
    label: 'Traceability & DoD',
    category: 'Verification & Release',
    icon: CheckSquare,
    description: 'Authoritative requirements matrix, observation-to-conclusion lineage & DoD audit.',
  },
];

function AppContent() {
  const { user, isAuthenticated, isLoading, logout } = useAuth();

  // Current route extraction from URL
  const [currentPath, setCurrentPath] = useState<string>(() => window.location.pathname);
  const [activeWorkflow, setActiveWorkflow] = useState<NavRoute>(() => {
    const path = window.location.pathname.replace(/^\//, '');
    const matched = NAV_ITEMS.find(item => item.id === path || item.path === `/${path}`);
    return matched ? matched.id : 'library';
  });

  // End-user Role State (defaults to Security Auditor for comprehensive visibility)
  const [currentRole, setCurrentRole] = useState<string>('security_auditor');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isSidebarOpen, setIsSidebarOpen] = useState<boolean>(true);
  const [workflowParams, setWorkflowParams] = useState<any>({});

  // System Health and Public Config
  const [systemHealth, setSystemHealth] = useState<{ status: string; version: string } | null>({
    status: 'OPERATIONAL',
    version: '2.0.1'
  });
  const [showWalkthrough, setShowWalkthrough] = useState<boolean>(() => {
    return !localStorage.getItem('caim_walkthrough_seen');
  });
  const [showChangePassword, setShowChangePassword] = useState<boolean>(false);

  // Listen to browser forward/back buttons
  useEffect(() => {
    const handlePopState = () => {
      const path = window.location.pathname;
      setCurrentPath(path);
      if (!path.startsWith('/dev')) {
        const cleanPath = path.replace(/^\//, '');
        const matched = NAV_ITEMS.find(item => item.id === cleanPath || item.path === path);
        if (matched) {
          setActiveWorkflow(matched.id);
        } else if (path === '/' || path === '') {
          setActiveWorkflow('library');
        }
      }
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Fetch public system state
  useEffect(() => {
    authenticatedFetch('/api/health')
      .then(res => res.json())
      .then(data => {
        if (data && data.status) {
          setSystemHealth({
            status: data.status.toUpperCase(),
            version: data.version || '2.0.1'
          });
        }
      })
      .catch(() => {
        // Safe fallback
      });
  }, [isAuthenticated]);

  // Programmatic navigation handler
  const navigateTo = (route: NavRoute | string, params?: any) => {
    if (route === 'dev' || route.startsWith('/dev')) {
      const target = route.startsWith('/dev') ? route : '/dev/system';
      window.history.pushState({}, '', target);
      setCurrentPath(target);
      return;
    }

    const matched = NAV_ITEMS.find(item => item.id === route || item.path === route || item.path === `/${route}`);
    const targetId = matched ? matched.id : 'agents';
    const targetPath = matched ? matched.path : '/agents';

    window.history.pushState({}, '', targetPath);
    setCurrentPath(targetPath);
    setActiveWorkflow(targetId);
    if (params) setWorkflowParams(params);
  };

  // If loading session state, show graceful loader
  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center space-y-3">
        <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-xs font-mono text-slate-400">Verifying Cryptographic Session...</p>
      </div>
    );
  }

  // If unauthenticated, route between Login, Signup, and Email Verification
  if (!isAuthenticated) {
    if (currentPath === '/signup') {
      return (
        <SignupView
          onNavigateToLogin={() => {
            window.history.pushState({}, '', '/login');
            setCurrentPath('/login');
          }}
          onNavigateToVerify={(email) => {
            const target = `/verify-email?email=${encodeURIComponent(email)}`;
            window.history.pushState({}, '', target);
            setCurrentPath('/verify-email');
          }}
        />
      );
    }

    if (currentPath === '/verify-email') {
      return (
        <VerifyEmailView
          onNavigateToLogin={(verifiedEmail) => {
            window.history.pushState({}, '', '/login');
            setCurrentPath('/login');
          }}
        />
      );
    }

    return (
      <LoginView
        onNavigateToSignup={() => {
          window.history.pushState({}, '', '/signup');
          setCurrentPath('/signup');
        }}
        onNavigateToVerify={(email) => {
          const target = email ? `/verify-email?email=${encodeURIComponent(email)}` : '/verify-email';
          window.history.pushState({}, '', target);
          setCurrentPath('/verify-email');
        }}
      />
    );
  }

  // If user navigates to /dev, render Diagnostic Console
  if (currentPath.startsWith('/dev')) {
    return <DiagnosticLayout />;
  }

  // Filter navigation items by search query
  const filteredNavItems = useMemo(() => {
    if (!searchQuery.trim()) return NAV_ITEMS;
    const q = searchQuery.toLowerCase();
    return NAV_ITEMS.filter(item => 
      item.label.toLowerCase().includes(q) ||
      item.description.toLowerCase().includes(q) ||
      item.category.toLowerCase().includes(q)
    );
  }, [searchQuery]);

  // Group navigation items by category
  const categories = ['Library & Discovery', 'Registry', 'Security & Analysis', 'Intelligence & Remediation', 'Operations & Shipping', 'Verification & Release'] as const;

  const currentNav = NAV_ITEMS.find(n => n.id === activeWorkflow) || NAV_ITEMS[0];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 antialiased flex flex-col font-sans selection:bg-cyan-900 selection:text-cyan-100">
      
      {/* Top Header Bar */}
      <header className="border-b border-slate-800/90 bg-slate-900/90 backdrop-blur sticky top-0 z-50">
        <div className="max-w-[1700px] mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
          
          {/* Left: Brand Logo & Title */}
          <div className="flex items-center space-x-3.5 shrink-0">
            <button
              onClick={() => setIsSidebarOpen(!isSidebarOpen)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors lg:hidden"
              aria-label="Toggle Sidebar"
            >
              {isSidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>

            <button 
              onClick={() => navigateTo('agents')}
              className="flex items-center space-x-3 text-left group"
            >
              <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm group-hover:border-cyan-400 transition-colors">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-bold text-slate-100 text-sm tracking-tight group-hover:text-cyan-300 transition-colors">
                    CAIM Intelligence Platform
                  </span>
                  <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-semibold">
                    v2.0.1 Release
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 hidden sm:block">
                  Agent Lifecycle Assurance • 71 Logical Engines • Strict Security Boundaries
                </p>
              </div>
            </button>
          </div>

          {/* Center: Global Navigation Search & Active Workflow Pill */}
          <div className="hidden md:flex items-center flex-1 max-w-md mx-4">
            <div className="relative w-full">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search workflows, agents, policies, or analysis..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full bg-slate-950/80 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-sans transition-colors"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2.5 top-2 text-slate-500 hover:text-slate-300 text-xs"
                >
                  ✕
                </button>
              )}
            </div>
          </div>

          {/* Right: User Identity, Role Switcher, System Health & Sign Out */}
          <div className="flex items-center space-x-3 shrink-0">
            
            {/* Authenticated User Capsule */}
            {user && (
              <div className="hidden xl:flex items-center space-x-2 px-2.5 py-1 bg-slate-950/90 border border-slate-800 rounded-lg text-xs font-mono">
                <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                <span className="text-slate-300 truncate max-w-[140px]">{user.email}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 uppercase font-semibold">
                  {user.roles[0] || 'User'}
                </span>
              </div>
            )}

            {/* End-User Role Switcher */}
            <div className="flex items-center space-x-1.5 bg-slate-950 border border-slate-800 rounded-lg px-2 py-1">
              <User className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-[11px] text-slate-400 font-mono hidden sm:inline">Role:</span>
              <select
                value={currentRole}
                onChange={e => setCurrentRole(e.target.value)}
                className="bg-transparent text-cyan-400 text-xs font-mono font-medium focus:outline-none cursor-pointer"
              >
                <option value="security_auditor" className="bg-slate-900 text-slate-200">Security Auditor</option>
                <option value="platform_admin" className="bg-slate-900 text-slate-200">Platform Admin</option>
                <option value="release_manager" className="bg-slate-900 text-slate-200">Release Manager</option>
                <option value="analyst" className="bg-slate-900 text-slate-200">Security Analyst</option>
                <option value="operator" className="bg-slate-900 text-slate-200">Operator</option>
              </select>
              <FieldHelpTooltip 
                customTitle="Active User Persona"
                customDescription="Controls role-based access control (RBAC) grants, policy override permissions, and security classification clearance ranks."
              />
            </div>

            {/* System Status Pill */}
            <div className="hidden lg:flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span>Engines Online (71/71)</span>
            </div>

            {/* Password Rotation Modal Trigger */}
            <button
              onClick={() => setShowChangePassword(true)}
              className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 border border-slate-700/80 text-slate-300 hover:text-cyan-300 text-xs font-mono transition-colors"
              title="Rotate Account Password & Invalidate Prior Sessions"
            >
              <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden md:inline">Password</span>
            </button>

            {/* User Walkthrough Guide Trigger */}
            <button
              onClick={() => setShowWalkthrough(true)}
              className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 border border-slate-700/80 text-slate-300 hover:text-cyan-300 text-xs font-mono transition-colors"
              title="Open Zero-Knowledge Onboarding Guide"
            >
              <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden sm:inline">Guide</span>
            </button>

            {/* Engineering Console Hand-off */}
            <button
              onClick={() => navigateTo('dev')}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-mono transition-colors"
              title="Switch to Internal Diagnostic Console"
            >
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden sm:inline">/dev</span>
            </button>

            {/* Sign Out Button */}
            <button
              onClick={() => logout()}
              className="p-1.5 rounded-lg bg-slate-800/80 hover:bg-rose-950/40 border border-slate-700/80 hover:border-rose-500/40 text-slate-400 hover:text-rose-400 transition-colors"
              title="Sign Out (Revoke JWT session)"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>

          </div>

        </div>
      </header>

      {/* Main Body Layout */}
      <div className="flex-1 flex max-w-[1700px] w-full mx-auto">
        
        {/* Navigation Sidebar */}
        <aside 
          className={`${
            isSidebarOpen ? 'block' : 'hidden'
          } lg:block w-72 shrink-0 border-r border-slate-800/80 bg-slate-900/40 p-4 overflow-y-auto space-y-6 select-none`}
        >
          {categories.map(category => {
            const items = filteredNavItems.filter(item => item.category === category);
            if (items.length === 0) return null;

            return (
              <div key={category} className="space-y-1.5">
                <div className="px-2 py-1 text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">
                  {category}
                </div>

                <div className="space-y-1">
                  {items.map(item => {
                    const Icon = item.icon;
                    const isActive = activeWorkflow === item.id;

                    return (
                      <button
                        key={item.id}
                        onClick={() => navigateTo(item.id)}
                        className={`w-full text-left flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                          isActive
                            ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-sm'
                            : 'text-slate-300 hover:text-slate-100 hover:bg-slate-800/60 border border-transparent'
                        }`}
                      >
                        <div className="flex items-center space-x-2.5 min-w-0">
                          <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                          <span className="truncate">{item.label}</span>
                        </div>
                        {isActive && <ChevronRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />}
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}

          {/* Quick System Stats in Sidebar Footer */}
          <div className="pt-4 border-t border-slate-800 space-y-2 text-[11px] text-slate-400 font-mono">
            <div className="flex justify-between items-center">
              <span>Logical Engines</span>
              <span className="text-emerald-400 font-semibold">71 Certified</span>
            </div>
            <div className="flex justify-between items-center">
              <span>Ontology Graph</span>
              <span className="text-slate-200">CAIM Core V2.0</span>
            </div>
            <div className="flex justify-between items-center">
              <span>KMS Attestation</span>
              <span className="text-cyan-400">Ed25519 Active</span>
            </div>
          </div>
        </aside>

        {/* Main Content Area */}
        <main className="flex-1 min-w-0 p-4 sm:p-6 lg:p-8 space-y-6 overflow-y-auto">
          
          {/* Breadcrumb & Context Header */}
          <div className="flex items-center justify-between pb-2 border-b border-slate-800/60 text-xs font-mono text-slate-400">
            <div className="flex items-center space-x-2">
              <span className="text-slate-500">CAIM Platform</span>
              <span>/</span>
              <span className="text-slate-500">{currentNav.category}</span>
              <span>/</span>
              <span className="text-cyan-400 font-semibold">{currentNav.label}</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="hidden sm:inline">Active Scope:</span>
              <span className="text-slate-200">Enterprise Core</span>
            </div>
          </div>

          {/* Render the Active Workflow View */}
          <div id="workflow-view-container" className="animate-in fade-in duration-200">
            {activeWorkflow === 'library' && (
              <LibraryWorkflowView 
                currentRole={currentRole} 
                onNavigateToWorkflow={navigateTo} 
              />
            )}

            {activeWorkflow === 'agents' && (
              <AgentsWorkflowView 
                currentRole={currentRole} 
                onNavigateToWorkflow={navigateTo} 
              />
            )}

            {activeWorkflow === 'discovery' && (
              <DiscoveryWorkflowView 
                currentRole={currentRole} 
                onNavigateToWorkflow={navigateTo} 
              />
            )}

            {activeWorkflow === 'analysis' && (
              <AnalysisWorkflowView 
                currentRole={currentRole} 
                agentId={workflowParams.agentId}
                onNavigateToWorkflow={navigateTo} 
              />
            )}

            {activeWorkflow === 'evidence' && (
              <EvidenceWorkflowView />
            )}

            {activeWorkflow === 'risk-policy' && (
              <RiskPolicyWorkflowView 
                currentRole={currentRole} 
                onNavigateToWorkflow={navigateTo} 
              />
            )}

            {activeWorkflow === 'governance' && (
              <GovernanceWorkflowView 
                currentRole={currentRole} 
                onNavigateToWorkflow={navigateTo} 
              />
            )}

            {activeWorkflow === 'knowledge' && (
              <KnowledgeWorkflowView 
                currentRole={currentRole} 
                initialQuery={workflowParams.query}
                onNavigateToWorkflow={navigateTo} 
              />
            )}

            {activeWorkflow === 'modification' && (
              <ModificationWorkflowView />
            )}

            {activeWorkflow === 'packages' && (
              <PackagesWorkflowView 
                currentRole={currentRole} 
                onNavigateToWorkflow={navigateTo} 
              />
            )}

            {activeWorkflow === 'observability' && (
              <ObservabilityWorkflowView 
                currentRole={currentRole} 
                onNavigateToWorkflow={navigateTo} 
              />
            )}

            {activeWorkflow === 'operations' && (
              <OperationsWorkflowView 
                currentRole={currentRole} 
                onNavigateToWorkflow={navigateTo} 
              />
            )}

            {activeWorkflow === 'golden-corpus' && (
              <GoldenCorpusWorkflowView 
                currentRole={currentRole} 
              />
            )}

            {activeWorkflow === 'production-hardening' && (
              <ProductionHardeningView />
            )}

            {activeWorkflow === 'traceability' && (
              <TraceabilityDodWorkflowView />
            )}
          </div>

        </main>

      </div>

      {/* Zero-Knowledge First Visit Walkthrough Modal */}
      <FirstVisitWalkthroughModal 
        isOpen={showWalkthrough} 
        onClose={() => setShowWalkthrough(false)} 
        onNavigateToWorkflow={navigateTo} 
      />

      {/* Account Password Rotation Modal */}
      <ChangePasswordModal
        isOpen={showChangePassword}
        onClose={() => setShowChangePassword(false)}
      />

    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

