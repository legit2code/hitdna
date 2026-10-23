import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  Mail, 
  KeyRound, 
  AlertCircle, 
  Loader2, 
  CheckCircle2, 
  ArrowRight, 
  RefreshCw,
  Sparkles,
  ExternalLink
} from 'lucide-react';

interface VerifyEmailViewProps {
  initialEmail?: string;
  initialToken?: string;
  onNavigateToLogin: (verifiedEmail?: string) => void;
}

export const VerifyEmailView: React.FC<VerifyEmailViewProps> = ({
  initialEmail = '',
  initialToken = '',
  onNavigateToLogin,
}) => {
  // Parse query params if available
  const urlParams = new URLSearchParams(window.location.search);
  const paramEmail = urlParams.get('email') || initialEmail;
  const paramToken = urlParams.get('token') || urlParams.get('code') || initialToken;

  const [email, setEmail] = useState<string>(paramEmail);
  const [token, setToken] = useState<string>(paramToken);
  const [loading, setLoading] = useState<boolean>(false);
  const [resending, setResending] = useState<boolean>(false);
  const [resendCooldown, setResendCooldown] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const [resendNotice, setResendNotice] = useState<string | null>(null);
  const [verified, setVerified] = useState<boolean>(false);

  // Dev-mode helper to auto-discover latest code from stubbed email sender
  const [devEmailCode, setDevEmailCode] = useState<string | null>(null);

  useEffect(() => {
    if (resendCooldown > 0) {
      const timer = setTimeout(() => setResendCooldown(resendCooldown - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [resendCooldown]);

  // If token and email are present in URL on mount, auto-trigger verification
  useEffect(() => {
    if (paramToken && paramEmail && !verified && !loading) {
      handleVerify(paramToken, paramEmail);
    }
  }, []);

  // In non-production preview, fetch latest sent email for this email to make testing effortless
  useEffect(() => {
    if (email && email.includes('@')) {
      fetch(`/api/auth/dev-sent-emails?email=${encodeURIComponent(email)}`)
        .then(res => res.json())
        .then(data => {
          if (data && data.emails && data.emails.length > 0) {
            const last = data.emails[data.emails.length - 1];
            // Match token from text or link
            const match = last.text.match(/verification code: ([a-zA-Z0-9_-]+)/i) || last.text.match(/token=([a-zA-Z0-9_-]+)/i);
            if (match && match[1]) {
              setDevEmailCode(match[1]);
            }
          }
        })
        .catch(() => {});
    }
  }, [email, resendNotice]);

  const handleVerify = async (tokenToUse?: string, emailToUse?: string) => {
    const activeToken = (tokenToUse || token).trim();
    const activeEmail = (emailToUse || email).trim();

    if (!activeToken) {
      setError('Please enter your verification code.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/auth/verify-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: activeToken,
          email: activeEmail || undefined,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Verification failed. The token may be invalid or expired.');
      }

      setVerified(true);
    } catch (err: any) {
      setError(err.message || 'Email verification failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (!email || !email.includes('@')) {
      setError('Please enter a valid email address to resend verification.');
      return;
    }

    setResending(true);
    setError(null);
    setResendNotice(null);

    try {
      const res = await fetch('/api/auth/resend-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim() }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to resend verification email.');
      }

      setResendNotice(data.message || 'A new verification code has been dispatched.');
      setResendCooldown(30);
    } catch (err: any) {
      setError(err.message || 'Failed to resend verification email.');
    } finally {
      setResending(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center items-center px-4 py-12 relative overflow-hidden font-sans selection:bg-cyan-500 selection:text-white">
      {/* Background ambient lighting */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md relative z-10 space-y-5">
        
        {/* Header Branding */}
        <div className="text-center space-y-1.5">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 mb-1 shadow-lg shadow-cyan-950/40">
            <Mail className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center justify-center gap-2">
            <span>Verify Your Email</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
              v2.0.1
            </span>
          </h1>
          <p className="text-xs text-slate-400">
            Account Activation & Identity Verification
          </p>
        </div>

        {/* Card */}
        <div className="bg-slate-900/90 backdrop-blur-md border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-5">
          
          {verified ? (
            <div className="space-y-4 text-center py-2 animate-in fade-in">
              <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 mx-auto shadow-lg shadow-emerald-950/30">
                <CheckCircle2 className="w-6 h-6" />
              </div>
              <div className="space-y-1">
                <h2 className="text-base font-semibold text-white">Email Address Verified!</h2>
                <p className="text-xs text-slate-300 max-w-sm mx-auto">
                  Your CAIM account has been activated with standard user permissions. You can now log in securely.
                </p>
              </div>

              <button
                type="button"
                onClick={() => onNavigateToLogin(email)}
                className="w-full py-2.5 px-4 rounded-xl bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 text-white text-xs font-semibold shadow-md shadow-cyan-950/50 transition-all flex items-center justify-center space-x-2"
              >
                <span>Proceed to Sign In</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <>
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                  <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Enter Verification Code</span>
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                  Valid for 24h
                </span>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">
                We sent a verification code to <span className="font-mono text-cyan-400">{email || 'your email'}</span>. 
                Please enter the code below to activate your account.
              </p>

              {error && (
                <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl flex items-start space-x-2.5 text-rose-300 text-xs animate-in fade-in">
                  <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="font-semibold">Verification Notice</p>
                    <p className="text-rose-400/90 text-[11px] mt-0.5">{error}</p>
                  </div>
                </div>
              )}

              {resendNotice && (
                <div className="p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-xl flex items-center space-x-2.5 text-cyan-300 text-xs animate-in fade-in">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
                  <p className="text-[11px]">{resendNotice}</p>
                </div>
              )}

              <form onSubmit={(e) => { e.preventDefault(); handleVerify(); }} className="space-y-4">
                {/* Email (Editable if needed) */}
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                    <Mail className="w-3.5 h-3.5 text-slate-400" />
                    <span>Registered Email Address</span>
                  </label>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="user@organization.com"
                    className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors font-mono"
                  />
                </div>

                {/* Token / Code Input */}
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                    <KeyRound className="w-3.5 h-3.5 text-slate-400" />
                    <span>Verification Code or Token</span>
                  </label>
                  <input
                    type="text"
                    required
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    placeholder="Paste 32-character code"
                    className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors font-mono tracking-wider"
                  />
                </div>

                {/* Non-prod convenience: Auto-fill latest stub code */}
                {devEmailCode && devEmailCode !== token && (
                  <div className="p-2.5 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-center justify-between text-xs font-mono">
                    <div className="flex items-center gap-1.5 text-amber-400 text-[11px]">
                      <Sparkles className="w-3 h-3 text-amber-400" />
                      <span>[STUB] Code: {devEmailCode.slice(0, 8)}...</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => setToken(devEmailCode)}
                      className="px-2 py-1 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 text-[10px] rounded-lg transition-colors"
                    >
                      Fill Code
                    </button>
                  </div>
                )}

                {/* Verify Button */}
                <button
                  type="submit"
                  disabled={loading || !token.trim()}
                  className="w-full py-2.5 px-4 rounded-xl bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 text-white text-xs font-semibold shadow-md shadow-cyan-950/50 transition-all flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Validating Token...</span>
                    </>
                  ) : (
                    <>
                      <ShieldCheck className="w-4 h-4" />
                      <span>Confirm & Activate Account</span>
                    </>
                  )}
                </button>
              </form>

              {/* Resend actions */}
              <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
                <button
                  type="button"
                  onClick={handleResend}
                  disabled={resending || resendCooldown > 0}
                  className="text-slate-400 hover:text-cyan-400 flex items-center gap-1.5 transition-colors disabled:opacity-50 disabled:cursor-not-allowed text-[11px]"
                >
                  <RefreshCw className={`w-3 h-3 ${resending ? 'animate-spin' : ''}`} />
                  <span>
                    {resendCooldown > 0 ? `Resend code in ${resendCooldown}s` : 'Resend verification code'}
                  </span>
                </button>

                <button
                  type="button"
                  onClick={() => onNavigateToLogin(email)}
                  className="text-cyan-400 hover:text-cyan-300 underline font-medium text-[11px]"
                >
                  Back to Sign In
                </button>
              </div>
            </>
          )}

        </div>

      </div>
    </div>
  );
};
