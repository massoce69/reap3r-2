// ─────────────────────────────────────────────
// MASSVISION Reap3r — Auth Provider
// ─────────────────────────────────────────────
'use client';
import { useEffect } from 'react';
import { useAuth } from './auth';
import { realtime } from './ws';

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const { initialize } = useAuth();

  useEffect(() => {
    initialize();
  }, [initialize]);

  // Connect WebSocket when we have a token
  useEffect(() => {
    const token = localStorage.getItem('reap3r_token');
    if (token && !realtime.connected) {
      realtime.connect(token);
    }
    return () => { realtime.disconnect(); };
  }, []);

  return <>{children}</>;
}
