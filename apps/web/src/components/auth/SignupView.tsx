import React, { useState, useMemo } from 'react';
import { 
  ShieldCheck, 
  Lock, 
  Mail, 
  Key, 
  AlertCircle, 
  Loader2, 
  CheckCircle2, 
  Eye, 
  EyeOff, 
  FileText, 
  Check, 
  ArrowRight,
  ShieldAlert
} from 'lucide-react';

interface SignupViewProps {
  onNavigateToLogin: () => void;
  onNavigateToVerify: (email: string) => void;
}

export const SignupView: React.FC<SignupViewProps> = ({ 
  onNavigateToLogin, 
  onNavigateToVerify 
}) => {
  const [email, setEmail] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [termsAccepted, setTermsAccepted] = useState<boolean>(false);
  const [showTermsModal, setShowTermsModal] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<boolean>(false);

  // Real-time password evaluation against existing policy
  const passwordCriteria = useMemo(() => {
    const hasMinLength = password.length >= 12;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password);

    const lower = password.toLowerCase();
    const knownBreached = [
      'admin2026!secureroot#',
      'admin123!secure',
      'password123456',
      'password123!',
      '123456789012',
      'administrator',
      'qwertyuiop12',
      'letmein12345',
      'welcome123456!',
      'rootadmin2026',
    ];
    const isBreached = password.length > 0 && knownBreached.some((b) => lower === b || (b.length >= 8 && lower.includes(b)));

    const passedCount = [hasMinLength, hasUppercase, hasLowercase, hasNumber, hasSpecial].filter(Boolean).length;
    const isValid = passedCount === 5 && !isBreached;

    let strengthLabel = 'Very Weak';
    let strengthColor = 'bg-rose-500';
    let strengthPercent = 10;

    if (password.length > 0) {
      if (passedCount <= 2 || isBreached) {
        strengthLabel = isBreached ? 'Breached / Weak' : 'Weak';
        strengthColor = 'bg-rose-500';
        strengthPercent = 25;
      } else if (passedCount === 3 || passedCount === 4) {
        strengthLabel = 'Moderate';
        strengthColor = 'bg-amber-500';
        strengthPercent = 65;
      } else if (isValid) {
        strengthLabel = 'Strong';
        strengthColor = 'bg-emerald-500';
        strengthPercent = 100;
      }
    }

    return {
      hasMinLength,
      hasUppercase,
      hasLowercase,
      hasNumber,
      hasSpecial,
      isBreached,
      passedCount,
      isValid,
      strengthLabel,
      strengthColor,
      strengthPercent,
    };
  }, [password]);

  const passwordsMatch = password.length > 0 && password === confirmPassword;
  const isEmailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  const canSubmit = isEmailValid && passwordCriteria.isValid && passwordsMatch && termsAccepted && !loading;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) {
      if (!termsAccepted) {
        setError('You must accept the Terms of Service and Privacy Policy to create an account.');
        return;
      }
      if (!passwordCriteria.isValid) {
        setError('Password does not satisfy the security policy requirements.');
        return;
      }
      if (!passwordsMatch) {
        setError('Passwords do not match.');
        return;
      }
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // STRICT PRIVILEGE RESTRICTION:
      // Client submits ONLY email, password, and terms_accepted.
      // Roles or tenant_id are NEVER supplied or accepted from public registration.
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email.trim(),
          password,
          terms_accepted: true,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to create account.');
      }

      setSuccess(true);
      // Seamlessly transition to email verification confirmation view
      setTimeout(() => {
        onNavigateToVerify(email.trim());
      }, 700);
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred during signup.');
      setLoading(false);
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
            <ShieldCheck className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center justify-center gap-2">
            <span>Create CAIM Account</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
              v2.0.1
            </span>
          </h1>
          <p className="text-xs text-slate-400">
            Assurance, Governance & Autonomous AI Verification
          </p>
        </div>

        {/* Signup Card */}
        <div className="bg-slate-900/90 backdrop-blur-md border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              <span>Self-Registration</span>
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
              Role: Standard User
            </span>
          </div>

          {error && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl flex items-start space-x-2.5 text-rose-300 text-xs animate-in fade-in">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Registration Notice</p>
                <p className="text-rose-400/90 text-[11px] mt-0.5">{error}</p>
              </div>
            </div>
          )}

          {success && (
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl flex items-center space-x-2.5 text-emerald-300 text-xs animate-in fade-in">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <div>
                <p className="font-semibold">Account Created</p>
                <p className="text-emerald-400/90 text-[11px]">Redirecting to email verification...</p>
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email Input */}
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
                placeholder="name@organization.com"
                className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors font-mono"
              />
            </div>

            {/* Password Input */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                  <Key className="w-3.5 h-3.5 text-slate-400" />
                  <span>Password</span>
                </label>
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="text-[11px] text-slate-400 hover:text-slate-200 flex items-center gap-1"
                >
                  {showPassword ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                  <span>{showPassword ? 'Hide' : 'Show'}</span>
                </button>
              </div>
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Min 12 chars (upper, lower, digit, symbol)"
                className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors font-mono"
              />

              {/* Password Strength Meter */}
              {password.length > 0 && (
                <div className="space-y-2 pt-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-slate-400">Strength:</span>
                    <span className={`font-semibold ${
                      passwordCriteria.strengthLabel === 'Strong' 
                        ? 'text-emerald-400' 
                        : passwordCriteria.strengthLabel === 'Moderate' 
                          ? 'text-amber-400' 
                          : 'text-rose-400'
                    }`}>
                      {passwordCriteria.strengthLabel}
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div 
                      className={`h-full transition-all duration-300 ${passwordCriteria.strengthColor}`} 
                      style={{ width: `${passwordCriteria.strengthPercent}%` }}
                    />
                  </div>

                  {/* Checklist against existing password policy */}
                  <div className="grid grid-cols-2 gap-1.5 pt-1 text-[10px] text-slate-400 font-mono">
                    <div className={`flex items-center gap-1 ${passwordCriteria.hasMinLength ? 'text-emerald-400' : 'text-slate-500'}`}>
                      <Check className={`w-3 h-3 ${passwordCriteria.hasMinLength ? 'opacity-100' : 'opacity-30'}`} />
                      <span>12+ characters</span>
                    </div>
                    <div className={`flex items-center gap-1 ${passwordCriteria.hasUppercase ? 'text-emerald-400' : 'text-slate-500'}`}>
                      <Check className={`w-3 h-3 ${passwordCriteria.hasUppercase ? 'opacity-100' : 'opacity-30'}`} />
                      <span>Uppercase (A-Z)</span>
                    </div>
                    <div className={`flex items-center gap-1 ${passwordCriteria.hasLowercase ? 'text-emerald-400' : 'text-slate-500'}`}>
                      <Check className={`w-3 h-3 ${passwordCriteria.hasLowercase ? 'opacity-100' : 'opacity-30'}`} />
                      <span>Lowercase (a-z)</span>
                    </div>
                    <div className={`flex items-center gap-1 ${passwordCriteria.hasNumber ? 'text-emerald-400' : 'text-slate-500'}`}>
                      <Check className={`w-3 h-3 ${passwordCriteria.hasNumber ? 'opacity-100' : 'opacity-30'}`} />
                      <span>Number (0-9)</span>
                    </div>
                    <div className={`flex items-center gap-1 ${passwordCriteria.hasSpecial ? 'text-emerald-400' : 'text-slate-500'}`}>
                      <Check className={`w-3 h-3 ${passwordCriteria.hasSpecial ? 'opacity-100' : 'opacity-30'}`} />
                      <span>Symbol (!@#$...)</span>
                    </div>
                    <div className={`flex items-center gap-1 ${!passwordCriteria.isBreached ? 'text-emerald-400' : 'text-rose-400'}`}>
                      <Check className={`w-3 h-3 ${!passwordCriteria.isBreached ? 'opacity-100' : 'opacity-30'}`} />
                      <span>Unbreached secret</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Confirm Password */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                <Key className="w-3.5 h-3.5 text-slate-400" />
                <span>Confirm Password</span>
              </label>
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Repeat password"
                className={`w-full px-3.5 py-2.5 bg-slate-950 border rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none font-mono transition-colors ${
                  confirmPassword && !passwordsMatch 
                    ? 'border-rose-500/80 focus:border-rose-500 focus:ring-1 focus:ring-rose-500' 
                    : 'border-slate-700/80 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500'
                }`}
              />
              {confirmPassword.length > 0 && !passwordsMatch && (
                <p className="text-[10px] text-rose-400">Passwords do not match.</p>
              )}
              {passwordsMatch && (
                <p className="text-[10px] text-emerald-400 flex items-center gap-1">
                  <Check className="w-3 h-3" /> Passwords match
                </p>
              )}
            </div>

            {/* Terms of Service & Privacy Policy Acceptance Checkbox (Required) */}
            <div className="pt-2 border-t border-slate-800/80">
              <label className="flex items-start gap-2.5 cursor-pointer select-none group">
                <input
                  type="checkbox"
                  required
                  checked={termsAccepted}
                  onChange={(e) => setTermsAccepted(e.target.checked)}
                  className="mt-0.5 w-4 h-4 rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500/30 focus:ring-offset-slate-900 cursor-pointer"
                />
                <span className="text-xs text-slate-300 leading-snug">
                  I agree to the{' '}
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setShowTermsModal(true);
                    }}
                    className="text-cyan-400 hover:text-cyan-300 underline font-medium"
                  >
                    Terms of Service
                  </button>{' '}
                  and{' '}
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setShowTermsModal(true);
                    }}
                    className="text-cyan-400 hover:text-cyan-300 underline font-medium"
                  >
                    Privacy Policy
                  </button>
                  .
                </span>
              </label>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={!canSubmit}
              className="w-full py-2.5 px-4 rounded-xl bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 text-white text-xs font-semibold shadow-md shadow-cyan-950/50 transition-all flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Creating Account & Dispatching Verification...</span>
                </>
              ) : (
                <>
                  <span>Create Account & Verify Email</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Navigation to Login */}
          <div className="pt-2 border-t border-slate-800 text-center">
            <span className="text-xs text-slate-400">Already have an account? </span>
            <button
              type="button"
              onClick={onNavigateToLogin}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold underline transition-colors"
            >
              Sign In
            </button>
          </div>
        </div>

        {/* Security / RBAC Banner */}
        <div className="p-3 bg-slate-900/60 border border-slate-800/80 rounded-xl text-[11px] text-slate-400 space-y-1">
          <div className="flex items-center gap-1.5 text-slate-300 font-medium">
            <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
            <span>Strict Role & Tenant Governance</span>
          </div>
          <p className="text-[10px] text-slate-400 leading-relaxed">
            Public self-registration strictly assigns standard unprivileged access. Multi-tenant partitioning is resolved server-side.
          </p>
        </div>

      </div>

      {/* Terms of Service & Privacy Policy Modal */}
      {showTermsModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4 max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-white font-semibold text-sm">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span>Terms of Service & Privacy Policy</span>
              </div>
              <button
                type="button"
                onClick={() => setShowTermsModal(false)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-slate-800"
              >
                Close
              </button>
            </div>

            <div className="flex-1 overflow-y-auto pr-2 space-y-3 text-xs text-slate-300 leading-relaxed font-sans">
              <h3 className="font-semibold text-white">1. Scope of Continuous AI Assurance</h3>
              <p>
                CAIM provides continuous autonomous AI agent assurance, behavioral governance, and verification. 
                By creating an account, you acknowledge that all audit logs, capability declarations, and authorization boundaries 
                are cryptographically recorded and non-repudiable.
              </p>

              <h3 className="font-semibold text-white">2. Acceptable Use & RBAC</h3>
              <p>
                Accounts created via public self-registration are allocated standard user privileges. 
                Any automated probing, privilege escalation attempts, or unauthorized access to unassigned tenant boundaries will 
                be logged and immediately blocked.
              </p>

              <h3 className="font-semibold text-white">3. Email Verification & Security</h3>
              <p>
                To prevent automated bot abuse, account activation requires validating the supplied email address via an 
                out-of-band verification token. Verification links and tokens remain valid for 24 hours.
              </p>

              <h3 className="font-semibold text-white">4. Privacy & Data Handling</h3>
              <p>
                Personal credentials are encrypted using industry-standard cryptographic primitives. Passwords are never stored in plaintext 
                and are salted and hashed using bcrypt. We do not sell or monetize user credentials.
              </p>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setTermsAccepted(true);
                  setShowTermsModal(false);
                }}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-semibold"
              >
                Accept Terms & Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
