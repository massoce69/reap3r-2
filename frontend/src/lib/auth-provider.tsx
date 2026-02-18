// ─────────────────────────────────────────────
// MASSVISION Reap3r — Auth Provider
// ─────────────────────────────────────────────
'use client';
import { useEffect, useRef } from 'react';
import { useAuth } from './auth';
import { realtime } from './ws';

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const { initialize } = useAuth();
  const wsInitialized = useRef(false);

  useEffect(() => {
    initialize();
  }, [initialize]);

  // Connect WebSocket once when we have a token
  useEffect(() => {
    if (wsInitialized.current) return;
    const token = localStorage.getItem('reap3r_token');
    if (token) {
      wsInitialized.current = true;
      // Small delay to ensure hydration is complete
      const t = setTimeout(() => realtime.connect(token), 200);
      return () => clearTimeout(t);
    }
  }, []);

  return <>{children}</>;
}
