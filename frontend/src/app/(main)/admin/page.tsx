'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState, Modal, TabBar } from '@/components/ui';
import { api } from '@/lib/api';
import {
  Users, ShieldCheck, Key, ClipboardList, UserX, UserCheck, Plus,
  Settings, Shield, Clock, QrCode, Trash2
} from 'lucide-react';

type Tab = 'users' | 'teams' | 'policies' | 'logins';

export default function AdminPage() {
  const [tab, setTab] = useState<Tab>('users');
  const [users, setUsers] = useState<any[]>([]);
  const [teams, setTeams] = useState<any[]>([]);
  const [policies, setPolicies] = useState<any[]>([]);
  const [logins, setLogins] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // Create modals
  const [showCreateUser, setShowCreateUser] = useState(false);
  const [showCreateTeam, setShowCreateTeam] = useState(false);
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [newUserRole, setNewUserRole] = useState('user');
  const [teamName, setTeamName] = useState('');
  const [teamDesc, setTeamDesc] = useState('');

  // User action modals
  const [selectedUser, setSelectedUser] = useState<any | null>(null);
  const [showSessions, setShowSessions] = useState(false);
  const [showMFA, setShowMFA] = useState(false);
  const [showRoleChange, setShowRoleChange] = useState(false);
  const [sessions, setSessions] = useState<any[]>([]);
  const [mfaSecret, setMfaSecret] = useState('');
  const [mfaTotpUri, setMfaTotpUri] = useState('');
  const [roles, setRoles] = useState<any[]>([]);
  const [targetRole, setTargetRole] = useState('');

  const loadUsers = () => { setLoading(true); api.admin.users.list({}).then(r => { setUsers(r.data); setLoading(false); }).catch(() => setLoading(false)); };
  const loadTeams = () => { setLoading(true); api.admin.teams.list().then(r => { setTeams(r.data); setLoading(false); }).catch(() => setLoading(false)); };
  const loadPolicies = () => { setLoading(true); api.admin.policies.list().then(r => { setPolicies(r.data); setLoading(false); }).catch(() => setLoading(false)); };
  const loadLogins = () => { setLoading(true); api.admin.loginEvents({}).then(r => { setLogins(r.data); setLoading(false); }).catch(() => setLoading(false)); };

  useEffect(() => {
    if (tab === 'users') loadUsers();
    else if (tab === 'teams') loadTeams();
    else if (tab === 'policies') loadPolicies();
    else loadLogins();
  }, [tab]);

  const toggleSuspend = async (u: any) => { await api.admin.users.suspend(u.id, !u.is_suspended); loadUsers(); };

  const createTeam = async () => {
    if (!teamName) return;
    await api.admin.teams.create({ name: teamName, description: teamDesc });
    setShowCreateTeam(false); setTeamName(''); setTeamDesc(''); loadTeams();
  };

  const createUser = async () => {
    if (!newUserEmail || !newUserPassword) return;
    await api.admin.users.create({ email: newUserEmail, password: newUserPassword, role: newUserRole });
    setShowCreateUser(false); setNewUserEmail(''); setNewUserPassword(''); setNewUserRole('user'); loadUsers();
  };

  const openSessions = async (user: any) => {
    setSelectedUser(user);
    const res = await api.admin.users.getSessions(user.id);
    setSessions(res); setShowSessions(true);
  };

  const revokeSession = async (sessionId: string) => {
    await api.admin.sessions.revoke(sessionId);
    if (selectedUser) openSessions(selectedUser);
  };

  const revokeAllSessions = async () => {
    if (!selectedUser) return;
    await api.admin.users.revokeAllSessions(selectedUser.id);
    setSessions([]); setShowSessions(false);
  };

  const openMFA = async (user: any) => {
    setSelectedUser(user);
    if (!user.mfa_enabled) {
      const res = await api.admin.users.setupMFA(user.id);
      setMfaSecret(res.secret); setMfaTotpUri(res.totp_uri);
    }
    setShowMFA(true);
  };

  const toggleMFA = async (enable: boolean) => {
    if (!selectedUser) return;
    if (enable) await api.admin.users.enableMFA(selectedUser.id);
    else await api.admin.users.disableMFA(selectedUser.id);
    setShowMFA(false); loadUsers();
  };

  const openRoleChange = async (user: any) => {
    setSelectedUser(user); setTargetRole(user.role);
    const res = await api.admin.roles.list();
    setRoles(res); setShowRoleChange(true);
  };

  const changeRole = async () => {
    if (!selectedUser || !targetRole) return;
    await api.admin.users.changeRole(selectedUser.id, targetRole);
    setShowRoleChange(false); loadUsers();
  };

  const tabs: { key: Tab; label: string }[] = [
    { key: 'users', label: 'Users' },
    { key: 'teams', label: 'Teams' },
    { key: 'policies', label: 'Policies' },
    { key: 'logins', label: 'Login Events' },
  ];

  return (
    <>
      <TopBar title="Administration" actions={
        tab === 'users' ? (
          <Button size="sm" onClick={() => setShowCreateUser(true)}><Plus style={{ width: '12px', height: '12px', marginRight: '4px' }} />Create User</Button>
        ) : tab === 'teams' ? (
          <Button size="sm" onClick={() => setShowCreateTeam(true)}><Plus style={{ width: '12px', height: '12px', marginRight: '4px' }} />Create Team</Button>
        ) : undefined
      } />
      <div className="p-6 space-y-4 animate-fade-in">
        <TabBar tabs={tabs} active={tab} onChange={(k) => setTab(k as Tab)} />

        {loading ? (
          <div className="space-y-3">
            {[...Array(4)].map((_, i) => <div key={i} className="bg-reap3r-card border border-reap3r-border rounded-xl h-16 animate-pulse" />)}
          </div>
        ) : tab === 'users' ? (
          users.length === 0 ? (
            <EmptyState icon={<Users style={{ width: '28px', height: '28px' }} />} title="No users" description="Create a user to get started." />
          ) : (
            <div className="space-y-2">
              {users.map(u => (
                <Card key={u.id} className="flex items-center justify-between !py-3 group hover:border-reap3r-border-light transition-all">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-xl bg-white/6 border border-white/10 flex items-center justify-center text-[12px] font-bold text-white">
                      {u.email?.charAt(0).toUpperCase()}
                    </div>
                    <div>
                      <p className="text-[12px] font-semibold text-white">{u.email}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <Badge variant="default">{u.role}</Badge>
                        {u.mfa_enabled && <Badge variant="accent">MFA</Badge>}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={u.is_suspended ? 'danger' : 'success'}>{u.is_suspended ? 'Suspended' : 'Active'}</Badge>
                    <div className="flex gap-1 opacity-60 group-hover:opacity-100 transition-opacity">
                      <button onClick={() => openSessions(u)} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all" title="Sessions">
                        <Clock style={{ width: '12px', height: '12px' }} />
                      </button>
                      <button onClick={() => openMFA(u)} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all" title="MFA">
                        <Shield style={{ width: '12px', height: '12px' }} />
                      </button>
                      <button onClick={() => openRoleChange(u)} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all" title="Role">
                        <Settings style={{ width: '12px', height: '12px' }} />
                      </button>
                      <button onClick={() => toggleSuspend(u)}
                        className={`p-1.5 rounded-lg transition-all ${u.is_suspended ? 'text-reap3r-success hover:bg-reap3r-success/10' : 'text-reap3r-danger hover:bg-reap3r-danger/10'}`}
                        title={u.is_suspended ? 'Activate' : 'Suspend'}
                      >
                        {u.is_suspended ? <UserCheck style={{ width: '12px', height: '12px' }} /> : <UserX style={{ width: '12px', height: '12px' }} />}
                      </button>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )
        ) : tab === 'teams' ? (
          teams.length === 0 ? (
            <EmptyState icon={<ShieldCheck style={{ width: '28px', height: '28px' }} />} title="No teams" description="Create teams to group users." />
          ) : (
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {teams.map(t => (
                <Card key={t.id} className="hover:border-reap3r-border-light transition-all">
                  <div className="flex items-center gap-3 mb-2">
                    <div className="w-9 h-9 rounded-xl bg-white/6 border border-white/10 flex items-center justify-center">
                      <ShieldCheck className="text-reap3r-light" style={{ width: '14px', height: '14px' }} />
                    </div>
                    <div>
                      <h3 className="text-[12px] font-bold text-white">{t.name}</h3>
                      <p className="text-[10px] text-reap3r-muted">{t.member_count ?? 0} members</p>
                    </div>
                  </div>
                  {t.description && <p className="text-[11px] text-reap3r-muted leading-relaxed">{t.description}</p>}
                </Card>
              ))}
            </div>
          )
        ) : tab === 'policies' ? (
          policies.length === 0 ? (
            <EmptyState icon={<Key style={{ width: '28px', height: '28px' }} />} title="No policies" description="Organization policies will appear here." />
          ) : (
            <div className="space-y-2">
              {policies.map(p => (
                <Card key={p.id} className="flex items-center justify-between !py-3">
                  <div>
                    <p className="text-[12px] font-semibold text-white">{p.key}</p>
                    <p className="text-[10px] text-reap3r-muted">{p.description || 'No description'}</p>
                  </div>
                  <code className="text-[10px] bg-reap3r-surface px-2.5 py-1 rounded-lg text-white/80 font-mono border border-reap3r-border">{JSON.stringify(p.value)}</code>
                </Card>
              ))}
            </div>
          )
        ) : (
          logins.length === 0 ? (
            <EmptyState icon={<ClipboardList style={{ width: '28px', height: '28px' }} />} title="No login events" description="Login events will appear here." />
          ) : (
            <Card className="!p-0 overflow-hidden">
              <div className="divide-y divide-reap3r-border/40">
                {logins.map(l => (
                  <div key={l.id} className="flex items-center justify-between px-5 py-3 hover:bg-reap3r-hover/40 transition-colors">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-xl bg-white/4 border border-white/8 flex items-center justify-center text-[10px] font-bold text-white">
                        {l.email?.charAt(0)?.toUpperCase() ?? '?'}
                      </div>
                      <div>
                        <p className="text-[12px] font-semibold text-white">{l.email}</p>
                        <p className="text-[10px] text-reap3r-muted font-mono">{l.ip_address} · {l.user_agent?.substring(0, 50)}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={l.success ? 'success' : 'danger'}>{l.success ? 'Success' : 'Failed'}</Badge>
                      <span className="text-[10px] text-reap3r-muted font-mono">{new Date(l.created_at).toLocaleString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )
        )}
      </div>

      {/* Create User Modal */}
      <Modal open={showCreateUser} onClose={() => setShowCreateUser(false)} title="Create User">
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Email</label>
            <input value={newUserEmail} onChange={e => setNewUserEmail(e.target.value)} placeholder="user@company.com"
              className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20" />
          </div>
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Password</label>
            <input type="password" value={newUserPassword} onChange={e => setNewUserPassword(e.target.value)} placeholder="••••••••"
              className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20" />
          </div>
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Role</label>
            <select value={newUserRole} onChange={e => setNewUserRole(e.target.value)}
              className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20">
              <option value="user">User</option>
              <option value="admin">Admin</option>
              <option value="super_admin">Super Admin</option>
            </select>
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowCreateUser(false)}>Cancel</Button>
            <Button onClick={createUser} disabled={!newUserEmail || !newUserPassword}>Create</Button>
          </div>
        </div>
      </Modal>

      {/* Create Team Modal */}
      <Modal open={showCreateTeam} onClose={() => setShowCreateTeam(false)} title="Create Team">
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Team Name</label>
            <input value={teamName} onChange={e => setTeamName(e.target.value)} placeholder="Security Operations"
              className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20" />
          </div>
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Description</label>
            <textarea rows={2} value={teamDesc} onChange={e => setTeamDesc(e.target.value)} placeholder="Optional description..."
              className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20 resize-none" />
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowCreateTeam(false)}>Cancel</Button>
            <Button onClick={createTeam} disabled={!teamName}>Create</Button>
          </div>
        </div>
      </Modal>

      {/* Sessions Modal */}
      <Modal open={showSessions} onClose={() => setShowSessions(false)} title={`Sessions — ${selectedUser?.email ?? ''}`}>
        {sessions.length === 0 ? (
          <p className="text-[11px] text-reap3r-muted py-4 text-center">No active sessions.</p>
        ) : (
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {sessions.map(s => (
              <div key={s.id} className="flex items-center justify-between p-3 bg-reap3r-surface/60 border border-reap3r-border/60 rounded-xl">
                <div>
                  <p className="text-[11px] font-semibold text-white font-mono">{s.ip_address}</p>
                  <p className="text-[10px] text-reap3r-muted mt-0.5">{s.user_agent?.substring(0, 60)}</p>
                  <p className="text-[10px] text-reap3r-muted mt-0.5">Last used: {new Date(s.last_used_at).toLocaleString()}</p>
                </div>
                <Button size="sm" variant="danger" onClick={() => revokeSession(s.id)}>Revoke</Button>
              </div>
            ))}
          </div>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <Button variant="danger" onClick={revokeAllSessions}>Revoke All</Button>
          <Button variant="secondary" onClick={() => setShowSessions(false)}>Close</Button>
        </div>
      </Modal>

      {/* MFA Modal */}
      <Modal open={showMFA} onClose={() => setShowMFA(false)} title={`MFA — ${selectedUser?.email ?? ''}`}>
        {selectedUser?.mfa_enabled ? (
          <div className="space-y-4">
            <p className="text-[11px] text-white">MFA is currently <Badge variant="success">Enabled</Badge></p>
            <Button variant="danger" onClick={() => toggleMFA(false)}>Disable MFA</Button>
          </div>
        ) : (
          <div className="space-y-4">
            <p className="text-[11px] text-reap3r-light">Scan this QR code with your authenticator app:</p>
            <div className="bg-white p-4 rounded-xl flex flex-col items-center justify-center">
              {mfaTotpUri ? (
                <img
                  src={`https://api.qrserver.com/v1/create-qr-code/?size=160x160&data=${encodeURIComponent(mfaTotpUri)}`}
                  alt="TOTP QR code" className="w-40 h-40"
                />
              ) : (
                <QrCode className="w-32 h-32 text-gray-300" />
              )}
              <p className="text-[10px] text-gray-600 mt-2 font-mono break-all">Secret: {mfaSecret}</p>
            </div>
            <Button onClick={() => toggleMFA(true)}>Enable MFA</Button>
          </div>
        )}
      </Modal>

      {/* Role Change Modal */}
      <Modal open={showRoleChange} onClose={() => setShowRoleChange(false)} title={`Change Role — ${selectedUser?.email ?? ''}`}>
        <div className="space-y-4">
          <p className="text-[11px] text-reap3r-muted">Current role: <Badge>{selectedUser?.role}</Badge></p>
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">New Role</label>
            <select value={targetRole} onChange={e => setTargetRole(e.target.value)}
              className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20">
              {roles.map(r => <option key={r.key} value={r.key}>{r.name}</option>)}
            </select>
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowRoleChange(false)}>Cancel</Button>
            <Button onClick={changeRole}>Save</Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
