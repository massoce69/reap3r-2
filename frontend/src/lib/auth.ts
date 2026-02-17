// ─────────────────────────────────────────────
// MASSVISION Reap3r — Auth Store (Zustand)
// ─────────────────────────────────────────────
import { create } from 'zustand';
import { api, setToken, clearToken } from './api';

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

export const useAuth = create<AuthState>((set, get) => ({
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
        setToken(res.token);
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
    clearToken();
    set({ user: null });
    window.location.href = '/login';
  },

  initialize: async () => {
    // Check if we have a token in localStorage
    const token = localStorage.getItem('reap3r_token');
    
    if (!token) {
      set({ initialized: true, user: null });
      return;
    }

    try {
      const user = await api.auth.me();
      set({ user, initialized: true });
    } catch {
      clearToken();
      set({ user: null, initialized: true });
    }
  },
}));
