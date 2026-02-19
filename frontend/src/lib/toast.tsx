'use client';
// ─────────────────────────────────────────────
// MASSVISION Reap3r — Toast Notification System
// ─────────────────────────────────────────────
import React, { createContext, useContext, useState, useCallback, useRef, useEffect } from 'react';
import { CheckCircle, AlertTriangle, XCircle, Info, X } from 'lucide-react';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

interface Toast {
  id: string;
  type: ToastType;
  title: string;
  message?: string;
  duration?: number;
}

interface ToastContextValue {
  addToast: (toast: Omit<Toast, 'id'>) => void;
  removeToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
}

// Convenience helpers
export function useToastHelpers() {
  const { addToast } = useToast();
  return {
    success: (title: string, message?: string) => addToast({ type: 'success', title, message }),
    error: (title: string, message?: string) => addToast({ type: 'error', title, message, duration: 6000 }),
    warning: (title: string, message?: string) => addToast({ type: 'warning', title, message }),
    info: (title: string, message?: string) => addToast({ type: 'info', title, message }),
  };
}

const ICONS: Record<ToastType, React.ReactNode> = {
  success: <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0" />,
  error: <XCircle className="w-5 h-5 text-red-400 shrink-0" />,
  warning: <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />,
  info: <Info className="w-5 h-5 text-cyan-400 shrink-0" />,
};

const BORDER_COLORS: Record<ToastType, string> = {
  success: 'border-l-emerald-500',
  error: 'border-l-red-500',
  warning: 'border-l-amber-500',
  info: 'border-l-cyan-500',
};

function ToastItem({ toast, onRemove }: { toast: Toast; onRemove: () => void }) {
  const [exiting, setExiting] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const dur = toast.duration ?? 4000;
    timerRef.current = setTimeout(() => {
      setExiting(true);
      setTimeout(onRemove, 300);
    }, dur);
    return () => { if (timerRef.current) clearTimeout(timerRef.current); };
  }, [toast.duration, onRemove]);

  return (
    <div
      className={`
        flex items-start gap-3 px-4 py-3 rounded-lg border border-l-4
        bg-[#141414] border-white/10 ${BORDER_COLORS[toast.type]}
        shadow-xl shadow-black/40 backdrop-blur-sm
        transition-all duration-300 ease-out min-w-[320px] max-w-[440px]
        ${exiting ? 'opacity-0 translate-x-8' : 'opacity-100 translate-x-0'}
        animate-slide-in-right
      `}
    >
      {ICONS[toast.type]}
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-white">{toast.title}</p>
        {toast.message && <p className="text-xs text-white/50 mt-0.5 truncate">{toast.message}</p>}
      </div>
      <button onClick={() => { setExiting(true); setTimeout(onRemove, 300); }} className="text-white/30 hover:text-white/60 transition-colors shrink-0">
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const counterRef = useRef(0);

  const addToast = useCallback((t: Omit<Toast, 'id'>) => {
    const id = `toast-${++counterRef.current}-${Date.now()}`;
    setToasts((prev) => [...prev.slice(-6), { ...t, id }]); // Keep max 7
  }, []);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ addToast, removeToast }}>
      {children}
      {/* Toast Container */}
      <div className="fixed top-4 right-4 z-[9999] flex flex-col gap-2 pointer-events-none">
        {toasts.map((t) => (
          <div key={t.id} className="pointer-events-auto">
            <ToastItem toast={t} onRemove={() => removeToast(t.id)} />
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
