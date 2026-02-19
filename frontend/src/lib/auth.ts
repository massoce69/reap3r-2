// ─────────────────────────────────────────────
// MASSVISION Reap3r — Auth Store (Zustand)
// ─────────────────────────────────────────────
import { create } from 'zustand';
import { api, setToken, clearToken } from './api';
import { realtime } from './ws';

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  org_id: string;
}

interface AuthState {
  user: User | null;
  initialized: boolean;
  loading: boolean;
  error: string | null;
  mfaRequired: boolean;
  mfaEmail: string | null;
  mfaPassword: string | null;
  login: (email: string, password: string, mfaCode?: string) => Promise<boolean | 'mfa'>;
  logout: () => void;
  initialize: () => Promise<void>;
}

export const useAuth = create<AuthState>((set) => ({
  user: null,
  initialized: false,
  loading: false,
  error: null,
  mfaRequired: false,
  mfaEmail: null,
  mfaPassword: null,

  login: async (email, password, mfaCode?) => {
    set({ loading: true, error: null });
    try {
      const res = await api.auth.login(email, password, mfaCode);
      
      // MFA challenge response
      if (res.mfa_required) {
        set({ loading: false, mfaRequired: true, mfaEmail: email, mfaPassword: password });
        return 'mfa';
      }

      if (res.token && res.user) {
        setToken(res.token, res.refresh_token);
        realtime.connect(res.token);
        set({ user: res.user, loading: false, mfaRequired: false, mfaEmail: null, mfaPassword: null });
        return true;
      }
      
      set({ error: 'Unexpected response', loading: false });
      return false;
    } catch (err: any) {
      set({ error: err.message, loading: false });
      return false;
    }
  },

  logout: () => {
    api.auth.logout().catch(() => {});
    clearToken();
    realtime.disconnect();
    set({ user: null });
    window.location.href = '/login';
  },

  initialize: async () => {
    // Check if we have a token in localStorage
    const token = localStorage.getItem('reap3r_token');
    
    if (!token) {
      try {
        const refreshed = await api.auth.refresh();
        if (refreshed?.token) {
          setToken(refreshed.token, refreshed.refresh_token);
        } else {
          set({ initialized: true, user: null });
          return;
        }
      } catch {
        set({ initialized: true, user: null });
        return;
      }
    }

    try {
      const user = await api.auth.me();
      const liveToken = localStorage.getItem('reap3r_token');
      if (liveToken) realtime.connect(liveToken);
      set({ user, initialized: true });
    } catch {
      clearToken();
      set({ user: null, initialized: true });
    }
  },
}));
