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
  login: (email: string, password: string) => Promise<boolean>;
  logout: () => void;
  initialize: () => Promise<void>;
}

export const useAuth = create<AuthState>((set) => ({
  user: null,
  initialized: false,
  loading: false,
  error: null,

  login: async (email, password) => {
    set({ loading: true, error: null });
    try {
      const res = await api.auth.login(email, password);
      setToken(res.token);
      set({ user: res.user, loading: false });
      return true;
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
