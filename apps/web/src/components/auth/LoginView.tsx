import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  Lock, 
  Mail, 
  Key, 
  AlertCircle, 
  Loader2, 
  CheckCircle2, 
  UserCheck, 
  Fingerprint,
  Sparkles
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext.tsx';

interface DevSeedAccount {
  email: string;
  role: string;
  label: string;
  description?: string;
}

interface LoginViewProps {
  onSuccess?: () => void;
  onNavigateToSignup?: () => void;
  onNavigateToVerify?: (email?: string) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ 
  onSuccess, 
  onNavigateToSignup, 
  onNavigateToVerify 
}) => {
  const { login } = useAuth();
  const [email, setEmail] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<boolean>(false);
  const [devAccounts, setDevAccounts] = useState<DevSeedAccount[]>([]);

  // Dynamically query server-side dev seed accounts (runtime check: process.env.NODE_ENV !== 'production')
  useEffect(() => {
    let isMounted = true;
    fetch('/api/auth/dev-seed-accounts')
      .then(async (res) => {
        if (!res.ok) return { accounts: [] };
        return res.json();
      })
      .then((data) => {
        if (isMounted && data?.accounts && Array.isArray(data.accounts)) {
          setDevAccounts(data.accounts);
        }
      })
      .catch(() => {
        // Ignored in production or when unreachable
      });
    return () => {
      isMounted = false;
    };
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setError('Please enter both email and password.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await login(email, password);
      setSuccess(true);
      if (onSuccess) {
        setTimeout(() => onSuccess(), 400);
      }
    } catch (err: any) {
      setError(err.message || 'Invalid email or password.');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectAccount = (selectedEmail: string) => {
    setEmail(selectedEmail);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center items-center px-4 py-12 relative overflow-hidden font-sans selection:bg-cyan-500 selection:text-white">
      {/* Background ambient lighting */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md relative z-10 space-y-6">
        
        {/* Header Branding */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 mb-2 shadow-lg shadow-cyan-950/40">
            <ShieldCheck className="w-7 h-7" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center justify-center gap-2">
            <span>CAIM Platform</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
              v2.0.1
            </span>
          </h1>
          <p className="text-xs text-slate-400 font-mono">
            Continuous Autonomous AI Agent Assurance & Governance
          </p>
        </div>

        {/* Login Card */}
        <div className="bg-slate-900/90 backdrop-blur-md border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              <span>Cryptographic Session Login</span>
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
              JWT HS256 + 15m Expiry
            </span>
          </div>

          {error && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl flex items-start space-x-2.5 text-rose-300 text-xs animate-in fade-in">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <p className="font-semibold">Authentication Failed</p>
                <p className="text-rose-400/90 text-[11px] mt-0.5">{error}</p>
                {error.toLowerCase().includes('email not verified') && onNavigateToVerify && (
                  <button
                    type="button"
                    onClick={() => onNavigateToVerify(email)}
                    className="mt-2 inline-flex items-center text-[11px] font-semibold text-cyan-400 hover:text-cyan-300 underline"
                  >
                    Verify your email address now &rarr;
                  </button>
                )}
              </div>
            </div>
          )}

          {success && (
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl flex items-center space-x-2.5 text-emerald-300 text-xs animate-in fade-in">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <div>
                <p className="font-semibold">Session Authenticated</p>
                <p className="text-emerald-400/90 text-[11px]">Redirecting to control plane...</p>
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-slate-400" />
                <span>Account Email</span>
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="user@caim.internal"
                className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                <Key className="w-3.5 h-3.5 text-slate-400" />
                <span>Password</span>
              </label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••••••"
                className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors font-mono"
              />
            </div>

            <button
              type="submit"
              disabled={loading || success}
              className="w-full py-2.5 px-4 rounded-xl bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 text-white text-xs font-semibold shadow-md shadow-cyan-950/50 transition-all flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Verifying Credentials & Issuing JWT...</span>
                </>
              ) : success ? (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Authenticated</span>
                </>
              ) : (
                <>
                  <Fingerprint className="w-4 h-4" />
                  <span>Sign In & Authorize Bearer Token</span>
                </>
              )}
            </button>

            {onNavigateToSignup && (
              <div className="pt-1 text-center">
                <span className="text-xs text-slate-400">Don't have an account? </span>
                <button
                  type="button"
                  onClick={onNavigateToSignup}
                  className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold underline transition-colors"
                >
                  Create account
                </button>
              </div>
            )}
          </form>

          {/* Seed Account Quick Selection (Only displayed when server returns active seed accounts) */}
          {devAccounts.length > 0 && (
            <div className="pt-3 border-t border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-[11px] font-mono text-amber-400/90">
                <span className="flex items-center gap-1">
                  <Sparkles className="w-3 h-3 text-amber-400" />
                  [NON-PROD] Select Seed Account Email
                </span>
              </div>
              <div className="grid grid-cols-2 gap-2">
                {devAccounts.map((acc) => (
                  <button
                    key={acc.email}
                    type="button"
                    onClick={() => handleSelectAccount(acc.email)}
                    className="px-2.5 py-1.5 text-left bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 rounded-lg transition-all text-xs font-mono text-slate-300 hover:text-cyan-300"
                    title={acc.description || acc.email}
                  >
                    <div className="font-semibold text-[11px] flex items-center gap-1">
                      {acc.role === 'admin' ? (
                        <UserCheck className="w-3 h-3 text-cyan-400" />
                      ) : (
                        <ShieldCheck className="w-3 h-3 text-emerald-400" />
                      )}
                      {acc.label}
                    </div>
                    <div className="text-[10px] text-slate-400 truncate mt-0.5">{acc.email}</div>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer Security Notice */}
        <p className="text-[11px] text-center text-slate-500">
          Deterministic session tokens are cryptographically signed with short TTL and rotated via secure refresh tokens.
        </p>

      </div>
    </div>
  );
};
