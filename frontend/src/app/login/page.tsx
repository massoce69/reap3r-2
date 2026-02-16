'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { Button, Input } from '@/components/ui';
import { Shield } from 'lucide-react';

export default function LoginPage() {
  const router = useRouter();
  const { login, loading, error } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const ok = await login(email, password);
    if (ok) router.push('/dashboard');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-reap3r-bg">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 mx-auto rounded-2xl bg-reap3r-accent/10 flex items-center justify-center mb-4 animate-glow">
            <Shield className="w-8 h-8 text-reap3r-accent" />
          </div>
          <h1 className="text-2xl font-bold text-reap3r-text tracking-tight">MASSVISION</h1>
          <p className="text-xs text-reap3r-accent font-mono tracking-[0.3em] mt-1">REAP3R PLATFORM</p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="bg-reap3r-card border border-reap3r-border rounded-xl p-6 space-y-4">
          <Input
            label="Email"
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

          {error && (
            <div className="bg-reap3r-danger/10 border border-reap3r-danger/20 rounded-lg px-3 py-2 text-xs text-reap3r-danger">
              {error}
            </div>
          )}

          <Button type="submit" className="w-full" loading={loading}>
            Sign In
          </Button>
        </form>

        <p className="text-center text-xs text-reap3r-muted mt-6">
          Secured by MASSVISION Reap3r &copy; {new Date().getFullYear()}
        </p>
      </div>
    </div>
  );
}
