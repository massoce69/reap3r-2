'use client';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Badge } from '@/components/ui';
import { useAuth } from '@/lib/auth';
import { Settings as SettingsIcon, Users, Shield, Globe } from 'lucide-react';

export default function SettingsPage() {
  const { user } = useAuth();

  return (
    <>
      <TopBar title="Settings" />
      <div className="p-6 space-y-6">
        {/* Organization */}
        <Card>
          <h3 className="text-sm font-semibold text-reap3r-text mb-4 flex items-center gap-2">
            <Globe className="w-4 h-4 text-reap3r-accent" />
            Organization
          </h3>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-xs text-reap3r-muted uppercase tracking-wider">Org ID</p>
              <p className="text-reap3r-text font-mono">{user?.org_id}</p>
            </div>
            <div>
              <p className="text-xs text-reap3r-muted uppercase tracking-wider">Your Role</p>
              <Badge variant="accent">{user?.role}</Badge>
            </div>
          </div>
        </Card>

        {/* RBAC Info */}
        <Card>
          <h3 className="text-sm font-semibold text-reap3r-text mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4 text-reap3r-accent" />
            Role-Based Access Control
          </h3>
          <div className="space-y-3 text-sm">
            {[
              { role: 'super_admin', desc: 'Full platform access. Manage orgs, users, agents, policies.' },
              { role: 'org_admin', desc: 'Full org access. Manage users, agents, jobs, policies.' },
              { role: 'technician', desc: 'Run jobs, manage agents, view audit logs.' },
              { role: 'viewer', desc: 'Read-only access to agents, jobs, and audit logs.' },
            ].map((r) => (
              <div key={r.role} className="flex items-start gap-3 p-3 rounded-lg bg-reap3r-surface border border-reap3r-border">
                <Badge variant={r.role === user?.role ? 'accent' : 'default'}>{r.role}</Badge>
                <p className="text-xs text-reap3r-muted">{r.desc}</p>
              </div>
            ))}
          </div>
        </Card>

        {/* Policies placeholder */}
        <Card>
          <h3 className="text-sm font-semibold text-reap3r-text mb-4 flex items-center gap-2">
            <SettingsIcon className="w-4 h-4 text-reap3r-accent" />
            Policies
          </h3>
          <p className="text-sm text-reap3r-muted">
            Agent policies (unattended access, remote control, privacy mode, input lock, scripts) will be configurable here.
            Policies are enforced per org/site/group.
          </p>
        </Card>
      </div>
    </>
  );
}
