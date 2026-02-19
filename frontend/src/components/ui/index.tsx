import { cn } from '@/lib/utils';

/* ── Button ─────────────────────────────────────────── */

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
}

export function Button({
  variant = 'primary',
  size = 'md',
  loading,
  className,
  children,
  disabled,
  ...props
}: ButtonProps) {
  const base =
    'inline-flex items-center justify-center font-semibold rounded-lg transition-all duration-150 ' +
    'focus:outline-none focus-visible:ring-1 focus-visible:ring-white/30 ' +
    'disabled:opacity-30 disabled:cursor-not-allowed select-none tracking-[0.06em] uppercase';

  const variants = {
    primary:
      'bg-white text-black hover:bg-white/90 active:scale-[0.98] ' +
      'shadow-[0_0_16px_rgba(255,255,255,0.08)]',
    secondary:
      'bg-reap3r-card border border-reap3r-border text-reap3r-text ' +
      'hover:bg-reap3r-hover hover:border-reap3r-border-light active:scale-[0.98]',
    danger:
      'bg-reap3r-danger/10 border border-reap3r-danger/30 text-reap3r-danger ' +
      'hover:bg-reap3r-danger/18 hover:border-reap3r-danger/50 active:scale-[0.98]',
    ghost:
      'text-reap3r-muted hover:text-reap3r-text hover:bg-reap3r-hover active:scale-[0.98]',
  };

  const sizes = {
    sm: 'px-3 py-1.5 text-[10px] gap-1.5',
    md: 'px-4 py-2 text-[11px] gap-2',
    lg: 'px-5 py-2.5 text-xs gap-2',
  };

  return (
    <button
      className={cn(base, variants[variant], sizes[size], className)}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <svg className="animate-spin h-3.5 w-3.5 shrink-0" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      )}
      {children}
    </button>
  );
}

/* ── Input ──────────────────────────────────────────── */

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

export function Input({ label, error, className, ...props }: InputProps) {
  return (
    <div className="space-y-1.5">
      {label && (
        <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.18em]">
          {label}
        </label>
      )}
      <input
        className={cn(
          'w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-reap3r-text',
          'placeholder:text-reap3r-muted/40 font-mono',
          'focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20',
          'transition-all duration-150',
          error && 'border-reap3r-danger/60 focus:border-reap3r-danger focus:ring-reap3r-danger/20',
          className
        )}
        {...props}
      />
      {error && <p className="text-[10px] text-reap3r-danger font-mono">{error}</p>}
    </div>
  );
}

/* ── Badge ──────────────────────────────────────────── */

export function Badge({
  children,
  variant = 'default',
}: {
  children: React.ReactNode;
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'accent';
}) {
  const colors = {
    default: 'bg-reap3r-subtle/60 text-reap3r-light border-reap3r-border-light/60',
    success:  'bg-reap3r-success/10  text-reap3r-success  border-reap3r-success/20',
    warning:  'bg-reap3r-warning/10  text-reap3r-warning  border-reap3r-warning/20',
    danger:   'bg-reap3r-danger/10   text-reap3r-danger   border-reap3r-danger/20',
    accent:   'bg-white/8            text-white           border-white/15',
  };
  return (
    <span
      className={cn(
        'inline-flex items-center px-1.5 py-0.5 text-[10px] font-bold rounded border uppercase tracking-[0.06em] font-mono',
        colors[variant]
      )}
    >
      {children}
    </span>
  );
}

/* ── Card ───────────────────────────────────────────── */

export function Card({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        'relative bg-reap3r-card border border-reap3r-border rounded-xl p-6 overflow-hidden',
        'shadow-[0_2px_16px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.03)]',
        className
      )}
    >
      {/* Top accent gradient line */}
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/8 to-transparent" />
      {children}
    </div>
  );
}

/* ── Skeleton ───────────────────────────────────────── */

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('skeleton h-4', className)} />;
}

/* ── EmptyState ─────────────────────────────────────── */

export function EmptyState({
  icon,
  title,
  description,
}: {
  icon?: React.ReactNode;
  title: string;
  description?: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      {icon && (
        <div className="w-14 h-14 rounded-2xl bg-reap3r-subtle border border-reap3r-border flex items-center justify-center text-reap3r-muted mb-4">
          {icon}
        </div>
      )}
      <h3 className="text-xs font-bold text-reap3r-light uppercase tracking-[0.15em]">{title}</h3>
      {description && (
        <p className="text-xs text-reap3r-muted mt-2 max-w-xs leading-relaxed">{description}</p>
      )}
    </div>
  );
}

/* ── StatusDot ──────────────────────────────────────── */

export function StatusDot({ status }: { status: string }) {
  return <span className={cn('status-dot', status)} />;
}

/* ── PermissionBanner ───────────────────────────────── */

export function PermissionBanner({ message }: { message: string }) {
  return (
    <div className="bg-reap3r-danger/5 border border-reap3r-danger/20 rounded-lg px-4 py-3 text-xs text-reap3r-danger flex items-center gap-2">
      <svg className="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M12 15v.01M12 9v2m-7 4h14a2 2 0 001.4-3.4L13.4 4.6a2 2 0 00-2.8 0L3.6 11.6A2 2 0 005 15z"
        />
      </svg>
      {message}
    </div>
  );
}

/* ── Modal ──────────────────────────────────────────── */

export function Modal({
  open,
  onClose,
  title,
  children,
  maxWidth = 'max-w-md',
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  maxWidth?: string;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" />
      <div
        className={cn(
          'relative w-full bg-reap3r-card border border-reap3r-border rounded-2xl p-6 animate-slide-up',
          'shadow-[0_24px_80px_rgba(0,0,0,0.9),inset_0_1px_0_rgba(255,255,255,0.04)]',
          maxWidth
        )}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top line */}
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent rounded-t-2xl" />
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-sm font-bold text-reap3r-text tracking-[0.08em] uppercase">{title}</h3>
          <button
            onClick={onClose}
            className="text-reap3r-muted hover:text-reap3r-text transition-colors p-1 rounded-lg hover:bg-reap3r-hover"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

/* ── TabBar ─────────────────────────────────────────── */

export function TabBar<T extends string>({
  tabs,
  active,
  onChange,
}: {
  tabs: { key: T; label: string; icon?: React.ReactNode }[];
  active: T;
  onChange: (key: T) => void;
}) {
  return (
    <div className="flex gap-0.5 bg-reap3r-surface border border-reap3r-border rounded-xl p-1 w-fit">
      {tabs.map((t) => (
        <button
          key={t.key}
          onClick={() => onChange(t.key)}
          className={cn(
            'flex items-center gap-2 px-4 py-2 rounded-lg text-[11px] font-semibold uppercase tracking-[0.06em] transition-all duration-150',
            active === t.key
              ? 'bg-white/8 text-white border border-white/10'
              : 'text-reap3r-muted hover:text-reap3r-light hover:bg-reap3r-hover'
          )}
        >
          {t.icon}
          {t.label}
        </button>
      ))}
    </div>
  );
}
