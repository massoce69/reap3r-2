'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { Users, ShieldCheck, Key, ClipboardList, UserX, UserCheck, Plus, X, Settings, Shield, Clock, QrCode } from 'lucide-react';

type Tab = 'users' | 'teams' | 'policies' | 'logins';

export default function AdminPage() {
  const [tab, setTab] = useState<Tab>('users');
  const [users, setUsers] = useState<any[]>([]);
  const [teams, setTeams] = useState<any[]>([]);
  const [policies, setPolicies] = useState<any[]>([]);
  const [logins, setLogins] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Create Team
  const [showCreateTeam, setShowCreateTeam] = useState(false);
  const [teamName, setTeamName] = useState('');
  const [teamDesc, setTeamDesc] = useState('');

  // Create User
  const [showCreateUser, setShowCreateUser] = useState(false);
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [newUserRole, setNewUserRole] = useState('user');

  // User Modals
  const [selectedUser, setSelectedUser] = useState<any | null>(null);
  const [showSessions, setShowSessions] = useState(false);
  const [showMFA, setShowMFA] = useState(false);
  const [showRoleChange, setShowRoleChange] = useState(false);
  const [sessions, setSessions] = useState<any[]>([]);
  const [mfaSecret, setMfaSecret] = useState('');
  const [roles, setRoles] = useState<any[]>([]);
  const [targetRole, setTargetRole] = useState('');

  const loadUsers = () => {
    setLoading(true);
    api.admin.users.list({}).then(r => { setUsers(r.data); setLoading(false); }).catch(() => setLoading(false));
  };

  const loadTeams = () => {
    setLoading(true);
    api.admin.teams.list().then(r => { setTeams(r.data); setLoading(false); }).catch(() => setLoading(false));
  };

  const loadPolicies = () => {
    setLoading(true);
    api.admin.policies.list().then(r => { setPolicies(r.data); setLoading(false); }).catch(() => setLoading(false));
  };

  const loadLogins = () => {
    setLoading(true);
    api.admin.loginEvents({}).then(r => { setLogins(r.data); setLoading(false); }).catch(() => setLoading(false));
  };

  useEffect(() => {
    if (tab === 'users') loadUsers();
    else if (tab === 'teams') loadTeams();
    else if (tab === 'policies') loadPolicies();
    else loadLogins();
  }, [tab]);

  const toggleSuspend = async (u: any) => {
    await api.admin.users.suspend(u.id, !u.is_suspended);
    loadUsers();
  };

  const createTeam = async () => {
    if (!teamName) return;
    await api.admin.teams.create({ name: teamName, description: teamDesc });
    setShowCreateTeam(false);
    setTeamName('');
    setTeamDesc('');
    loadTeams();
  };

  const createUser = async () => {
    if (!newUserEmail || !newUserPassword) return;
    await api.admin.users.create({ email: newUserEmail, password: newUserPassword, role: newUserRole });
    setShowCreateUser(false);
    setNewUserEmail('');
    setNewUserPassword('');
    setNewUserRole('user');
    loadUsers();
  };

  const openSessions = async (user: any) => {
    setSelectedUser(user);
    const res = await api.admin.users.getSessions(user.id);
    setSessions(res);
    setShowSessions(true);
  };

  const revokeSession = async (sessionId: string) => {
    await api.admin.sessions.revoke(sessionId);
    if (selectedUser) openSessions(selectedUser);
  };

  const revokeAllSessions = async () => {
    if (!selectedUser) return;
    await api.admin.users.revokeAllSessions(selectedUser.id);
    setSessions([]);
    setShowSessions(false);
  };

  const openMFA = async (user: any) => {
    setSelectedUser(user);
    if (!user.mfa_enabled) {
      const secret = Math.random().toString(36).substring(7);
      const res = await api.admin.users.setupMFA(user.id, secret);
      setMfaSecret(secret);
    }
    setShowMFA(true);
  };

  const toggleMFA = async (enable: boolean) => {
    if (!selectedUser) return;
    if (enable) {
      await api.admin.users.enableMFA(selectedUser.id);
    } else {
      await api.admin.users.disableMFA(selectedUser.id);
    }
    setShowMFA(false);
    loadUsers();
  };

  const openRoleChange = async (user: any) => {
    setSelectedUser(user);
    setTargetRole(user.role);
    const res = await api.admin.roles.list();
    setRoles(res);
    setShowRoleChange(true);
  };

  const changeRole = async () => {
    if (!selectedUser || !targetRole) return;
    await api.admin.users.changeRole(selectedUser.id, targetRole);
    setShowRoleChange(false);
    loadUsers();
  };

  const tabs: { key: Tab; label: string; icon: any }[] = [
    { key: 'users', label: 'Users', icon: Users },
    { key: 'teams', label: 'Teams', icon: ShieldCheck },
    { key: 'policies', label: 'Policies', icon: Key },
    { key: 'logins', label: 'Login Events', icon: ClipboardList },
  ];

  return (
    <>
      <TopBar title="Administration" />
      <div className="p-6 space-y-4">
        {/* Tabs */}
        <div className="flex gap-1 bg-reap3r-surface p-1 rounded-lg border border-reap3r-border w-fit">
          {tabs.map(t => (
            <button key={t.key} onClick={() => setTab(t.key)}
              className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm transition-colors ${tab === t.key ? 'bg-reap3r-accent/10 text-reap3r-accent' : 'text-reap3r-muted hover:text-reap3r-text'}`}>
              <t.icon className="w-4 h-4" />{t.label}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="text-reap3r-muted text-sm">Loading...</div>
        ) : tab === 'users' ? (
          <>
            <div className="flex justify-end">
              <Button size="sm" onClick={() => setShowCreateUser(!showCreateUser)}>
                {showCreateUser ? <><X className="w-3 h-3 mr-1" />Cancel</> : <><Plus className="w-3 h-3 mr-1" />Create User</>}
              </Button>
            </div>
            {showCreateUser && (
              <Card>
                <div className="space-y-3">
                  <input value={newUserEmail} onChange={e => setNewUserEmail(e.target.value)} placeholder="Email"
                    className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text" />
                  <input type="password" value={newUserPassword} onChange={e => setNewUserPassword(e.target.value)} placeholder="Password"
                    className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text" />
                  <select value={newUserRole} onChange={e => setNewUserRole(e.target.value)}
                    className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text">
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                    <option value="super_admin">Super Admin</option>
                  </select>
                  <Button size="sm" onClick={createUser}>Create User</Button>
                </div>
              </Card>
            )}
            {users.length === 0 ? (
              <EmptyState icon={<Users className="w-8 h-8" />} title="No users" description="No users found." />
            ) : (
              <div className="space-y-2">
                {users.map(u => (
                  <Card key={u.id} className="flex items-center justify-between !py-3">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-reap3r-accent/20 flex items-center justify-center text-reap3r-accent text-xs font-bold">
                        {u.email?.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-reap3r-text">{u.email}</p>
                        <p className="text-xs text-reap3r-muted">Role: {u.role}{u.mfa_enabled ? ' · MFA' : ''}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={u.is_suspended ? 'danger' : 'success'}>{u.is_suspended ? 'Suspended' : 'Active'}</Badge>
                      <Button size="sm" variant="ghost" onClick={() => openSessions(u)}>
                        <Clock className="w-3 h-3 mr-1" />Sessions
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => openMFA(u)}>
                        <Shield className="w-3 h-3 mr-1" />MFA
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => openRoleChange(u)}>
                        <Settings className="w-3 h-3 mr-1" />Role
                      </Button>
                      <Button size="sm" variant={u.is_suspended ? 'primary' : 'danger'} onClick={() => toggleSuspend(u)}>
                        {u.is_suspended ? <><UserCheck className="w-3 h-3 mr-1" />Activate</> : <><UserX className="w-3 h-3 mr-1" />Suspend</>}
                      </Button>
                    </div>
                  </Card>
                ))}
              </div>
            )}
          </>
        ) : tab === 'teams' ? (
          <>
            <div className="flex justify-end">
              <Button size="sm" onClick={() => setShowCreateTeam(!showCreateTeam)}>
                {showCreateTeam ? <><X className="w-3 h-3 mr-1" />Cancel</> : <><Plus className="w-3 h-3 mr-1" />Create Team</>}
              </Button>
            </div>
            {showCreateTeam && (
              <Card>
                <div className="space-y-3">
                  <input value={teamName} onChange={e => setTeamName(e.target.value)} placeholder="Team name"
                    className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text" />
                  <input value={teamDesc} onChange={e => setTeamDesc(e.target.value)} placeholder="Description (optional)"
                    className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text" />
                  <Button size="sm" onClick={createTeam}>Save</Button>
                </div>
              </Card>
            )}
            {teams.length === 0 ? (
              <EmptyState icon={<ShieldCheck className="w-8 h-8" />} title="No teams" description="Create teams to group users." />
            ) : (
              <div className="space-y-2">
                {teams.map(t => (
                  <Card key={t.id} className="flex items-center justify-between !py-3">
                    <div>
                      <p className="text-sm font-medium text-reap3r-text">{t.name}</p>
                      <p className="text-xs text-reap3r-muted">{t.description || 'No description'} · {t.member_count ?? 0} members</p>
                    </div>
                  </Card>
                ))}
              </div>
            )}
          </>
        ) : tab === 'policies' ? (
          policies.length === 0 ? (
            <EmptyState icon={<Key className="w-8 h-8" />} title="No policies" description="Organization policies will appear here." />
          ) : (
            <div className="space-y-2">
              {policies.map(p => (
                <Card key={p.id} className="flex items-center justify-between !py-3">
                  <div>
                    <p className="text-sm font-medium text-reap3r-text">{p.key}</p>
                    <p className="text-xs text-reap3r-muted">{p.description || 'No description'}</p>
                  </div>
                  <code className="text-xs bg-reap3r-bg px-2 py-1 rounded text-reap3r-accent">{JSON.stringify(p.value)}</code>
                </Card>
              ))}
            </div>
          )
        ) : (
          logins.length === 0 ? (
            <EmptyState icon={<ClipboardList className="w-8 h-8" />} title="No login events" description="User login events will appear here." />
          ) : (
            <div className="space-y-2">
              {logins.map(l => (
                <Card key={l.id} className="flex items-center justify-between !py-3">
                  <div>
                    <p className="text-sm font-medium text-reap3r-text">{l.email}</p>
                    <p className="text-xs text-reap3r-muted">{l.ip_address} · {l.user_agent?.substring(0, 60)}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={l.success ? 'success' : 'danger'}>{l.success ? 'Success' : 'Failed'}</Badge>
                    <span className="text-xs text-reap3r-muted">{new Date(l.created_at).toLocaleString()}</span>
                  </div>
                </Card>
              ))}
            </div>
          )
        )}
      </div>

      {/* Modals */}
      {showSessions && selectedUser && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowSessions(false)}>
          <div className="bg-reap3r-surface border border-reap3r-border rounded-lg p-6 max-w-2xl w-full m-4" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-reap3r-text">Sessions - {selectedUser.email}</h3>
              <button onClick={() => setShowSessions(false)} className="text-reap3r-muted hover:text-reap3r-text"><X className="w-5 h-5" /></button>
            </div>
            {sessions.length === 0 ? (
              <p className="text-sm text-reap3r-muted">No active sessions.</p>
            ) : (
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {sessions.map(s => (
                  <Card key={s.id} className="flex items-center justify-between !py-3">
                    <div>
                      <p className="text-sm font-medium text-reap3r-text">{s.ip_address}</p>
                      <p className="text-xs text-reap3r-muted">{s.user_agent?.substring(0, 80)}</p>
                      <p className="text-xs text-reap3r-muted mt-1">Last used: {new Date(s.last_used_at).toLocaleString()}</p>
                    </div>
                    <Button size="sm" variant="danger" onClick={() => revokeSession(s.id)}>Revoke</Button>
                  </Card>
                ))}
              </div>
            )}
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="danger" onClick={revokeAllSessions}>Revoke All</Button>
              <Button variant="ghost" onClick={() => setShowSessions(false)}>Close</Button>
            </div>
          </div>
        </div>
      )}

      {showMFA && selectedUser && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowMFA(false)}>
          <div className="bg-reap3r-surface border border-reap3r-border rounded-lg p-6 max-w-md w-full m-4" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-reap3r-text">MFA Setup - {selectedUser.email}</h3>
              <button onClick={() => setShowMFA(false)} className="text-reap3r-muted hover:text-reap3r-text"><X className="w-5 h-5" /></button>
            </div>
            {selectedUser.mfa_enabled ? (
              <div className="space-y-3">
                <p className="text-sm text-reap3r-text">MFA is currently <Badge variant="success">Enabled</Badge></p>
                <Button variant="danger" onClick={() => toggleMFA(false)}>Disable MFA</Button>
              </div>
            ) : (
              <div className="space-y-3">
                <p className="text-sm text-reap3r-text mb-2">Scan this QR code with your authenticator app:</p>
                <div className="bg-white p-4 rounded-lg flex items-center justify-center">
                  <QrCode className="w-32 h-32 text-gray-800" />
                  <p className="text-xs text-gray-600 mt-2">Secret: {mfaSecret}</p>
                </div>
                <p className="text-xs text-reap3r-muted">After scanning, enable MFA:</p>
                <Button variant="primary" onClick={() => toggleMFA(true)}>Enable MFA</Button>
              </div>
            )}
            <div className="mt-4 flex justify-end">
              <Button variant="ghost" onClick={() => setShowMFA(false)}>Close</Button>
            </div>
          </div>
        </div>
      )}

      {showRoleChange && selectedUser && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowRoleChange(false)}>
          <div className="bg-reap3r-surface border border-reap3r-border rounded-lg p-6 max-w-md w-full m-4" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-reap3r-text">Change Role - {selectedUser.email}</h3>
              <button onClick={() => setShowRoleChange(false)} className="text-reap3r-muted hover:text-reap3r-text"><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-3">
              <p className="text-sm text-reap3r-muted">Current role: <Badge>{selectedUser.role}</Badge></p>
              <select value={targetRole} onChange={e => setTargetRole(e.target.value)}
                className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text">
                {roles.map(r => (
                  <option key={r.key} value={r.key}>{r.name}</option>
                ))}
              </select>
              <Button onClick={changeRole}>Save Role</Button>
            </div>
            <div className="mt-4 flex justify-end">
              <Button variant="ghost" onClick={() => setShowRoleChange(false)}>Close</Button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
