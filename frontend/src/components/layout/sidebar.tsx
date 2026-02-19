'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import { useAuth } from '@/lib/auth';
import {
  LayoutDashboard,
  Monitor,
  ListTodo,
  ScrollText,
  Settings,
  Download,
  LogOut,
  Shield,
  Building2,
  FolderOpen,
  Lock,
  MessageSquare,
  ShieldAlert,
  Users,
  Bell,
} from 'lucide-react';

const nav = [
  { href: '/dashboard',  label: 'Dashboard',  icon: LayoutDashboard },
  { href: '/companies',  label: 'Companies',   icon: Building2 },
  { href: '/folders',    label: 'Folders',     icon: FolderOpen },
  { href: '/agents',     label: 'Agents',      icon: Monitor },
  { href: '/jobs',       label: 'Jobs',        icon: ListTodo },
  { href: '/vault',      label: 'Vault',       icon: Lock },
  { href: '/chat',       label: 'Messaging',   icon: MessageSquare },
  { href: '/edr',        label: 'EDR / SOC',   icon: ShieldAlert },
  { href: '/alerting',   label: 'Alerting',    icon: Bell },
  { href: '/audit',      label: 'Audit Log',   icon: ScrollText },
  { href: '/admin',      label: 'Admin',       icon: Users },
  { href: '/deployment', label: 'Deployment',  icon: Download },
  { href: '/settings',   label: 'Settings',    icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();

  return (
    <aside className="w-56 h-screen bg-reap3r-surface flex flex-col fixed left-0 top-0 z-40 border-r border-reap3r-border">

      {/* ── Logo ── */}
      <div className="relative px-4 pt-5 pb-4 overflow-hidden shrink-0">
        {/* Gradient wash behind logo */}
        <div className="absolute inset-0 bg-gradient-to-br from-reap3r-accent/[0.06] via-transparent to-transparent pointer-events-none" />
        {/* Corner accent lines */}
        <div className="absolute top-0 right-0 w-12 h-12 border-t border-r border-reap3r-accent/10 rounded-bl-xl pointer-events-none" />

        <div className="relative flex items-center gap-3">
          <div className="relative shrink-0">
            <div className="w-9 h-9 rounded-xl bg-reap3r-accent/10 border border-reap3r-accent/20 flex items-center justify-center animate-glow">
              <Shield className="w-4.5 h-4.5 text-reap3r-accent" style={{ width: '18px', height: '18px' }} />
            </div>
            {/* Online indicator */}
            <div className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-reap3r-success rounded-full"
                 style={{ boxShadow: '0 0 6px rgba(0,229,160,0.8)' }} />
          </div>
          <div>
            <h1 className="text-[11px] font-bold text-reap3r-text tracking-[0.22em] uppercase leading-none">
              MASSVISION
            </h1>
            <p className="text-[9px] text-reap3r-accent font-mono tracking-[0.4em] uppercase mt-1 leading-none">
              REAP3R
            </p>
          </div>
        </div>
      </div>

      {/* Divider */}
      <div className="mx-4 h-px bg-gradient-to-r from-transparent via-reap3r-border to-transparent shrink-0" />

      {/* ── Navigation ── */}
      <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto overflow-x-hidden min-h-0">
        {nav.map(({ href, label, icon: Icon }) => {
          const active = pathname?.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                'group relative flex items-center gap-2.5 px-3 py-[7px] rounded-lg transition-all duration-150 overflow-hidden',
                active
                  ? 'bg-reap3r-accent/[0.08] border border-reap3r-accent/[0.15] text-reap3r-accent'
                  : 'border border-transparent text-reap3r-muted hover:text-reap3r-light hover:bg-reap3r-hover'
              )}
            >
              {/* Left accent bar for active */}
              {active && (
                <span
                  className="absolute left-0 top-1/2 -translate-y-1/2 w-[2px] h-4 bg-reap3r-accent rounded-r-full"
                  style={{ boxShadow: '0 0 8px rgba(0,212,255,0.9)' }}
                />
              )}
              {/* Subtle shine on active */}
              {active && (
                <div className="absolute inset-0 bg-gradient-to-r from-reap3r-accent/[0.04] to-transparent pointer-events-none" />
              )}

              <Icon
                className={cn(
                  'shrink-0 transition-colors',
                  active ? 'text-reap3r-accent' : 'text-reap3r-muted group-hover:text-reap3r-light'
                )}
                style={{ width: '13px', height: '13px' }}
              />
              <span className="text-[11px] font-medium tracking-[0.06em] uppercase leading-none">
                {label}
              </span>
            </Link>
          );
        })}
      </nav>

      {/* Divider */}
      <div className="mx-4 h-px bg-gradient-to-r from-transparent via-reap3r-border to-transparent shrink-0" />

      {/* ── User ── */}
      <div className="px-2 py-3 shrink-0">
        <div className="flex items-center gap-2.5 px-2.5 py-2.5 rounded-xl bg-reap3r-hover/60 border border-reap3r-border">
          <div
            className="w-7 h-7 rounded-lg flex items-center justify-center text-[11px] font-bold text-reap3r-text shrink-0 border border-reap3r-accent/15"
            style={{ background: 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(124,58,237,0.2))' }}
          >
            {user?.name?.charAt(0)?.toUpperCase() ?? '?'}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[11px] font-semibold text-reap3r-text truncate leading-none mb-1">
              {user?.name ?? 'User'}
            </p>
            <p className="text-[9px] text-reap3r-muted truncate font-mono uppercase tracking-widest leading-none">
              {user?.role ?? ''}
            </p>
          </div>
          <button
            onClick={logout}
            className="text-reap3r-muted/40 hover:text-reap3r-danger transition-colors shrink-0 p-1 rounded hover:bg-reap3r-danger/10"
            title="Logout"
          >
            <LogOut style={{ width: '12px', height: '12px' }} />
          </button>
        </div>
      </div>
    </aside>
  );
}

export function TopBar({ title, actions }: { title: string; actions?: React.ReactNode }) {
  return (
    <header className="h-12 bg-reap3r-surface/80 backdrop-blur-md border-b border-reap3r-border flex items-center justify-between px-6 sticky top-0 z-30">
      <div className="flex items-center gap-3">
        <div className="w-[3px] h-4 bg-reap3r-accent rounded-full opacity-80"
             style={{ boxShadow: '0 0 8px rgba(0,212,255,0.7)' }} />
        <h2 className="text-[11px] font-bold text-reap3r-text tracking-[0.2em] uppercase">
          {title}
        </h2>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}
