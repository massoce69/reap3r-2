// ─────────────────────────────────────────────
// MASSVISION Reap3r — Auth Provider
// ─────────────────────────────────────────────
'use client';
import { useEffect } from 'react';
import { useAuth } from './auth';

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const { initialize } = useAuth();

  useEffect(() => {
    initialize();
  }, [initialize]);

  return <>{children}</>;
}
