'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { Button, Input } from '@/components/ui';
import { Shield, KeyRound } from 'lucide-react';

export default function LoginPage() {
  const router = useRouter();
  const { login, loading, error, mfaRequired, mfaEmail, mfaPassword } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const ok = await login(email, password);
    if (ok === true) router.push('/dashboard');
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaEmail || !mfaPassword) return;
    const ok = await login(mfaEmail, mfaPassword, mfaCode);
    if (ok === true) router.push('/dashboard');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-reap3r-bg overflow-hidden relative">

      {/* ── Background effects ── */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_50%_40%,rgba(0,70,160,0.1),transparent_65%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_85%_85%,rgba(100,0,200,0.07),transparent_55%)]" />

      {/* Corner bracket decorations */}
      <div className="absolute top-8 left-8 w-16 h-16 border-t-2 border-l-2 border-reap3r-accent/15 rounded-tl-xl" />
      <div className="absolute top-8 right-8 w-16 h-16 border-t-2 border-r-2 border-reap3r-accent/15 rounded-tr-xl" />
      <div className="absolute bottom-8 left-8 w-16 h-16 border-b-2 border-l-2 border-reap3r-accent/15 rounded-bl-xl" />
      <div className="absolute bottom-8 right-8 w-16 h-16 border-b-2 border-r-2 border-reap3r-accent/15 rounded-br-xl" />

      {/* ── Main content ── */}
      <div className="w-full max-w-sm px-4 relative z-10">

        {/* Logo */}
        <div className="text-center mb-8">
          <div className="relative inline-flex items-center justify-center mb-5">
            <div className="absolute w-[72px] h-[72px] rounded-2xl border border-reap3r-accent/15 animate-pulse" />
            <div
              className="w-16 h-16 rounded-2xl flex items-center justify-center animate-glow relative"
              style={{
                background: 'linear-gradient(135deg, rgba(0,212,255,0.1), rgba(124,58,237,0.06))',
                border: '1px solid rgba(0,212,255,0.22)',
              }}
            >
              <Shield className="w-8 h-8 text-reap3r-accent" />
            </div>
          </div>

          <h1 className="text-2xl font-bold text-reap3r-text tracking-[0.18em] uppercase">
            MASSVISION
          </h1>
          <div className="flex items-center justify-center gap-3 mt-2">
            <div className="h-px w-10 bg-gradient-to-r from-transparent to-reap3r-accent/40" />
            <p className="text-[9px] text-reap3r-accent font-mono tracking-[0.5em] uppercase">
              REAP3R PLATFORM
            </p>
            <div className="h-px w-10 bg-gradient-to-l from-transparent to-reap3r-accent/40" />
          </div>
        </div>

        {/* MFA Form */}
        {mfaRequired ? (
          <div className="relative">
            <div className="absolute inset-x-0 top-0 h-px rounded-t-2xl bg-gradient-to-r from-transparent via-reap3r-accent/50 to-transparent" />
            <form
              onSubmit={handleMfaSubmit}
              className="bg-reap3r-card border border-reap3r-border rounded-2xl p-7 space-y-5 shadow-[0_24px_60px_rgba(0,0,0,0.6)]"
            >
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-reap3r-accent/10 border border-reap3r-accent/20 flex items-center justify-center shrink-0">
                  <KeyRound className="w-5 h-5 text-reap3r-accent" />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-reap3r-text uppercase tracking-[0.15em]">
                    Two-Factor Auth
                  </h3>
                  <p className="text-[10px] text-reap3r-muted mt-0.5">
                    Enter the 6-digit code from your authenticator
                  </p>
                </div>
              </div>

              <Input
                label="Authentication Code"
                type="text"
                placeholder="0 0 0  0 0 0"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                required
                autoFocus
                maxLength={6}
                className="text-center text-xl tracking-[0.6em]"
              />
              {error && <ErrorBox message={error} />}
              <Button type="submit" className="w-full" size="lg" loading={loading} disabled={mfaCode.length !== 6}>
                Verify Access
              </Button>
            </form>
          </div>
        ) : (
          /* Login Form */
          <div className="relative">
            <div className="absolute inset-x-0 top-0 h-px rounded-t-2xl bg-gradient-to-r from-transparent via-reap3r-accent/50 to-transparent" />
            <form
              onSubmit={handleSubmit}
              className="bg-reap3r-card border border-reap3r-border rounded-2xl p-7 space-y-5 shadow-[0_24px_60px_rgba(0,0,0,0.6)]"
            >
              {/* Subtle inner shine */}
              <div className="absolute inset-0 bg-gradient-to-br from-white/[0.018] to-transparent rounded-2xl pointer-events-none" />

              <Input
                label="Email Address"
                type="email"
                placeholder="admin@massvision.local"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
              />
              <Input
                label="Password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              {error && <ErrorBox message={error} />}

              <Button type="submit" className="w-full" size="lg" loading={loading}>
                Authenticate
              </Button>

              <div className="flex items-center gap-3 pt-1">
                <div className="flex-1 h-px bg-reap3r-border" />
                <span className="text-[9px] text-reap3r-muted/50 font-mono uppercase tracking-widest">
                  Secure
                </span>
                <div className="flex-1 h-px bg-reap3r-border" />
              </div>
              <div className="flex justify-center gap-5">
                {['TLS 1.3', 'AES-256', 'JWT'].map((label) => (
                  <span key={label} className="text-[9px] text-reap3r-muted/35 font-mono uppercase tracking-wider">
                    {label}
                  </span>
                ))}
              </div>
            </form>
          </div>
        )}

        <p className="text-center text-[9px] text-reap3r-muted/35 mt-6 font-mono tracking-[0.2em] uppercase">
          MASSVISION REAP3R &copy; {new Date().getFullYear()}
        </p>
      </div>
    </div>
  );
}

function ErrorBox({ message }: { message: string }) {
  return (
    <div className="bg-reap3r-danger/5 border border-reap3r-danger/20 rounded-lg px-3 py-2.5 text-xs text-reap3r-danger flex items-center gap-2">
      <svg className="w-3.5 h-3.5 shrink-0" viewBox="0 0 20 20" fill="currentColor">
        <path
          fillRule="evenodd"
          d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
          clipRule="evenodd"
        />
      </svg>
      {message}
    </div>
  );
}
