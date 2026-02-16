import { cn } from '@/lib/utils';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
}

export function Button({ variant = 'primary', size = 'md', loading, className, children, disabled, ...props }: ButtonProps) {
  const base = 'inline-flex items-center justify-center font-medium rounded-lg transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-reap3r-accent/50 disabled:opacity-50 disabled:cursor-not-allowed';
  const variants = {
    primary: 'bg-reap3r-accent text-black hover:bg-reap3r-accent/90 active:bg-reap3r-accent/80',
    secondary: 'bg-reap3r-card border border-reap3r-border text-reap3r-text hover:bg-reap3r-hover',
    danger: 'bg-reap3r-danger/10 border border-reap3r-danger/30 text-reap3r-danger hover:bg-reap3r-danger/20',
    ghost: 'text-reap3r-muted hover:text-reap3r-text hover:bg-reap3r-hover',
  };
  const sizes = {
    sm: 'px-3 py-1.5 text-xs gap-1.5',
    md: 'px-4 py-2 text-sm gap-2',
    lg: 'px-6 py-3 text-base gap-2',
  };

  return (
    <button className={cn(base, variants[variant], sizes[size], className)} disabled={disabled || loading} {...props}>
      {loading && (
        <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      )}
      {children}
    </button>
  );
}

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

export function Input({ label, error, className, ...props }: InputProps) {
  return (
    <div className="space-y-1">
      {label && <label className="text-sm font-medium text-reap3r-muted">{label}</label>}
      <input
        className={cn(
          'w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-reap3r-text placeholder:text-reap3r-muted/50 focus:outline-none focus:ring-2 focus:ring-reap3r-accent/50 focus:border-reap3r-accent/50 transition-colors',
          error && 'border-reap3r-danger',
          className
        )}
        {...props}
      />
      {error && <p className="text-xs text-reap3r-danger">{error}</p>}
    </div>
  );
}

export function Badge({ children, variant = 'default' }: { children: React.ReactNode; variant?: 'default' | 'success' | 'warning' | 'danger' | 'accent' }) {
  const colors = {
    default: 'bg-reap3r-border/50 text-reap3r-muted',
    success: 'bg-reap3r-success/10 text-reap3r-success border-reap3r-success/20',
    warning: 'bg-reap3r-warning/10 text-reap3r-warning border-reap3r-warning/20',
    danger: 'bg-reap3r-danger/10 text-reap3r-danger border-reap3r-danger/20',
    accent: 'bg-reap3r-accent/10 text-reap3r-accent border-reap3r-accent/20',
  };
  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full border', colors[variant])}>
      {children}
    </span>
  );
}

export function Card({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('bg-reap3r-card border border-reap3r-border rounded-xl p-6', className)}>
      {children}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('skeleton h-4', className)} />;
}

export function EmptyState({ icon, title, description }: { icon?: React.ReactNode; title: string; description?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      {icon && <div className="text-reap3r-muted mb-4">{icon}</div>}
      <h3 className="text-lg font-medium text-reap3r-text">{title}</h3>
      {description && <p className="text-sm text-reap3r-muted mt-1">{description}</p>}
    </div>
  );
}

export function StatusDot({ status }: { status: string }) {
  return <span className={cn('status-dot', status)} />;
}

export function PermissionBanner({ message }: { message: string }) {
  return (
    <div className="bg-reap3r-danger/5 border border-reap3r-danger/20 rounded-lg px-4 py-3 text-sm text-reap3r-danger flex items-center gap-2">
      <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v.01M12 9v2m-7 4h14a2 2 0 001.4-3.4L13.4 4.6a2 2 0 00-2.8 0L3.6 11.6A2 2 0 005 15z" />
      </svg>
      {message}
    </div>
  );
}
