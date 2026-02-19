'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { Shield, Lock, Eye, EyeOff, ArrowRight } from 'lucide-react';

export default function LoginPage() {
  const { login } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(email, password);
      router.push('/dashboard');
    } catch (err: any) {
      setError(err.message ?? 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-reap3r-bg flex items-center justify-center p-4 relative overflow-hidden">

      {/* Background decorations */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute -top-32 -left-32 w-96 h-96 rounded-full"
          style={{ background: 'radial-gradient(circle, rgba(255,255,255,0.025) 0%, transparent 70%)' }} />
        <div className="absolute -bottom-32 -right-32 w-96 h-96 rounded-full"
          style={{ background: 'radial-gradient(circle, rgba(255,255,255,0.015) 0%, transparent 70%)' }} />
      </div>

      {/* Corner brackets */}
      <div className="absolute top-6 left-6 w-8 h-8 border-t-2 border-l-2 border-white/8 rounded-tl-md" />
      <div className="absolute top-6 right-6 w-8 h-8 border-t-2 border-r-2 border-white/8 rounded-tr-md" />
      <div className="absolute bottom-6 left-6 w-8 h-8 border-b-2 border-l-2 border-white/8 rounded-bl-md" />
      <div className="absolute bottom-6 right-6 w-8 h-8 border-b-2 border-r-2 border-white/8 rounded-br-md" />

      {/* Main card */}
      <div className="relative w-full max-w-sm animate-slide-up">
        <div className="relative bg-reap3r-card border border-reap3r-border rounded-2xl p-8 shadow-[0_24px_80px_rgba(0,0,0,0.8)]">
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/12 to-transparent rounded-t-2xl" />

          {/* Logo */}
          <div className="flex flex-col items-center mb-8">
            <div className="relative mb-4">
              <div className="w-14 h-14 rounded-2xl bg-white/6 border border-white/10 flex items-center justify-center animate-glow">
                <Shield className="text-white" style={{ width: '22px', height: '22px' }} />
              </div>
              <div className="absolute -top-1 -right-1 w-3 h-3 bg-reap3r-success rounded-full"
                   style={{ boxShadow: '0 0 8px rgba(34,197,94,0.8)' }} />
            </div>
            <h1 className="text-[13px] font-black text-white tracking-[0.3em] uppercase">MASSVISION</h1>
            <p className="text-[9px] text-reap3r-light font-mono tracking-[0.6em] uppercase mt-0.5">REAP3R</p>
          </div>

          <div className="text-center mb-6">
            <h2 className="text-sm font-bold text-white tracking-[0.12em] uppercase">Secure Access</h2>
            <p className="text-[11px] text-reap3r-muted mt-1">Enterprise Agent Management Platform</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.18em]">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@company.com"
                required
                className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white
                  placeholder:text-reap3r-muted/40 font-mono
                  focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20
                  transition-all duration-150"
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.18em]">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••"
                  required
                  className="w-full px-3 py-2.5 pr-10 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white
                    placeholder:text-reap3r-muted/40 font-mono
                    focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20
                    transition-all duration-150"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-reap3r-muted hover:text-reap3r-light transition-colors"
                >
                  {showPassword
                    ? <EyeOff style={{ width: '14px', height: '14px' }} />
                    : <Eye style={{ width: '14px', height: '14px' }} />
                  }
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2 px-3 py-2.5 bg-reap3r-danger/8 border border-reap3r-danger/25 rounded-lg">
                <Lock style={{ width: '12px', height: '12px', color: '#ef4444', flexShrink: 0 }} />
                <p className="text-[11px] text-reap3r-danger font-mono">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-3 px-4 mt-2
                bg-white text-black text-[11px] font-bold uppercase tracking-[0.1em] rounded-lg
                hover:bg-white/90 active:scale-[0.99] transition-all duration-150
                disabled:opacity-40 disabled:cursor-not-allowed
                shadow-[0_0_20px_rgba(255,255,255,0.06)]"
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-3.5 w-3.5" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Authenticating...
                </>
              ) : (
                <>
                  Sign In
                  <ArrowRight style={{ width: '13px', height: '13px' }} />
                </>
              )}
            </button>
          </form>

          <div className="mt-6 pt-4 border-t border-reap3r-border/60 flex items-center justify-center gap-4">
            {['TLS 1.3', 'AES-256', 'JWT'].map((badge) => (
              <span key={badge} className="text-[9px] text-reap3r-muted/50 font-mono uppercase tracking-wider">
                {badge}
              </span>
            ))}
          </div>
        </div>

        <p className="text-center text-[10px] text-reap3r-muted/30 font-mono mt-4 tracking-widest uppercase">
          MASSVISION © 2025
        </p>
      </div>
    </div>
  );
}
