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
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/companies', label: 'Companies', icon: Building2 },
  { href: '/folders', label: 'Folders', icon: FolderOpen },
  { href: '/agents', label: 'Agents', icon: Monitor },
  { href: '/jobs', label: 'Jobs', icon: ListTodo },
  { href: '/vault', label: 'Vault', icon: Lock },
  { href: '/chat', label: 'Messaging', icon: MessageSquare },
  { href: '/edr', label: 'EDR / SOC', icon: ShieldAlert },
  { href: '/alerting', label: 'Alerting', icon: Bell },
  { href: '/audit', label: 'Audit Log', icon: ScrollText },
  { href: '/admin', label: 'Admin', icon: Users },
  { href: '/deployment', label: 'Deployment', icon: Download },
  { href: '/settings', label: 'Settings', icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();

  return (
    <aside className="w-60 h-screen bg-reap3r-surface border-r border-reap3r-border flex flex-col fixed left-0 top-0 z-40">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-reap3r-border">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-reap3r-accent/10 flex items-center justify-center">
            <Shield className="w-4 h-4 text-reap3r-accent" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-reap3r-text tracking-wide">MASSVISION</h1>
            <p className="text-[10px] text-reap3r-accent font-mono tracking-widest">REAP3R</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {nav.map((item) => {
          const active = pathname?.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-150',
                active
                  ? 'bg-reap3r-accent/10 text-reap3r-accent border border-reap3r-accent/20'
                  : 'text-reap3r-muted hover:text-reap3r-text hover:bg-reap3r-hover'
              )}
            >
              <item.icon className="w-4 h-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* User */}
      <div className="px-3 py-4 border-t border-reap3r-border">
        <div className="flex items-center gap-3 px-3 py-2">
          <div className="w-8 h-8 rounded-full bg-reap3r-accent/20 flex items-center justify-center text-xs font-bold text-reap3r-accent">
            {user?.name?.charAt(0)?.toUpperCase() ?? '?'}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-reap3r-text truncate">{user?.name ?? 'User'}</p>
            <p className="text-[10px] text-reap3r-muted truncate">{user?.role ?? ''}</p>
          </div>
          <button onClick={logout} className="text-reap3r-muted hover:text-reap3r-danger transition-colors" title="Logout">
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}

export function TopBar({ title, actions }: { title: string; actions?: React.ReactNode }) {
  return (
    <header className="h-14 bg-reap3r-surface/80 backdrop-blur-sm border-b border-reap3r-border flex items-center justify-between px-6 sticky top-0 z-30">
      <h2 className="text-lg font-semibold text-reap3r-text">{title}</h2>
      {actions && <div className="flex items-center gap-3">{actions}</div>}
    </header>
  );
}
