'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState, Modal } from '@/components/ui';
import { api } from '@/lib/api';
import {
  Download, Copy, Key, Terminal, Monitor as MonitorIcon, Check,
  Plus, Trash2, ArrowRight
} from 'lucide-react';

export default function DeploymentPage() {
  const [tokens, setTokens] = useState<any[]>([]);
  const [commands, setCommands] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newTokenName, setNewTokenName] = useState('');
  const [creating, setCreating] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  useEffect(() => {
    api.enrollment.tokens.list().then(r => { setTokens(r.data); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  const createToken = async () => {
    if (!newTokenName.trim()) return;
    setCreating(true);
    try {
      await api.enrollment.tokens.create({ name: newTokenName, max_uses: 0 });
      const res = await api.enrollment.tokens.list();
      setTokens(res.data); setNewTokenName(''); setShowCreate(false);
    } finally { setCreating(false); }
  };

  const revokeToken = async (id: string) => {
    if (!confirm('Revoke this token?')) return;
    await api.enrollment.tokens.revoke(id);
    const res = await api.enrollment.tokens.list();
    setTokens(res.data);
    if (commands) setCommands(null);
  };

  const loadCommands = async (id: string) => {
    try { const cmds = await api.enrollment.tokens.commands(id); setCommands(cmds); } catch {}
  };

  const copy = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  return (
    <>
      <TopBar title="Agent Deployment" />
      <div className="p-6 space-y-4 animate-fade-in">

        {/* Deployment Commands */}
        <Card>
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl bg-white/6 border border-white/10 flex items-center justify-center">
              <Terminal className="text-reap3r-light" style={{ width: '16px', height: '16px' }} />
            </div>
            <div>
              <h3 className="text-[12px] font-bold text-white uppercase tracking-[0.08em]">Deploy Commands</h3>
              <p className="text-[10px] text-reap3r-muted">One-liner scripts to install agents on endpoints</p>
            </div>
          </div>

          {commands ? (
            <div className="space-y-3">
              <CommandBlock label="Windows (PowerShell)" icon={<MonitorIcon style={{ width: '12px', height: '12px' }} />}
                command={commands.windows_powershell} onCopy={() => copy(commands.windows_powershell, 'windows')} copied={copiedField === 'windows'} />
              <CommandBlock label="Linux (one-liner)" icon={<Terminal style={{ width: '12px', height: '12px' }} />}
                command={commands.linux_oneliner ?? commands.linux_bash} onCopy={() => copy(commands.linux_oneliner ?? commands.linux_bash, 'linux')} copied={copiedField === 'linux'} />
            </div>
          ) : tokens.filter(t => !t.revoked).length > 0 ? (
            <div className="space-y-2">
              <p className="text-[10px] text-reap3r-muted uppercase tracking-[0.08em] font-bold">Select a token to generate commands</p>
              <div className="flex gap-2 flex-wrap">
                {tokens.filter(t => !t.revoked).map(t => (
                  <button key={t.id} onClick={() => loadCommands(t.id)}
                    className="flex items-center gap-2 px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-xl text-[11px] text-reap3r-light hover:text-white hover:border-reap3r-border-light transition-all">
                    <Key style={{ width: '11px', height: '11px' }} /> {t.name}
                    <ArrowRight style={{ width: '10px', height: '10px' }} className="text-reap3r-muted" />
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <p className="text-[11px] text-reap3r-muted">Create an enrollment token first.</p>
          )}
        </Card>

        {/* Enrollment Tokens */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-white/6 border border-white/10 flex items-center justify-center">
                <Key className="text-reap3r-light" style={{ width: '16px', height: '16px' }} />
              </div>
              <div>
                <h3 className="text-[12px] font-bold text-white uppercase tracking-[0.08em]">Enrollment Tokens</h3>
                <p className="text-[10px] text-reap3r-muted">Tokens used by agents during enrollment</p>
              </div>
            </div>
            <Button size="sm" onClick={() => setShowCreate(true)}>
              <Plus style={{ width: '12px', height: '12px', marginRight: '4px' }} />Create
            </Button>
          </div>

          {loading ? (
            <div className="space-y-2">
              {[...Array(2)].map((_, i) => <div key={i} className="bg-reap3r-surface border border-reap3r-border rounded-xl h-14 animate-pulse" />)}
            </div>
          ) : tokens.length === 0 ? (
            <EmptyState icon={<Key style={{ width: '28px', height: '28px' }} />} title="No tokens" description="Create an enrollment token to start deploying agents." />
          ) : (
            <div className="space-y-2">
              {tokens.map(token => (
                <div key={token.id} className="flex items-center gap-3 px-4 py-3 bg-reap3r-surface/60 border border-reap3r-border/60 rounded-xl group hover:border-reap3r-border-light transition-all">
                  <div className="w-8 h-8 rounded-xl bg-white/4 border border-white/8 flex items-center justify-center shrink-0">
                    <Key className="text-reap3r-light" style={{ width: '12px', height: '12px' }} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-[12px] font-semibold text-white">{token.name}</p>
                    <p className="text-[10px] text-reap3r-muted font-mono truncate">{token.token}</p>
                  </div>
                  <Badge variant="default">{token.use_count}{token.max_uses > 0 ? `/${token.max_uses}` : ''} uses</Badge>
                  {token.revoked ? (
                    <Badge variant="danger">Revoked</Badge>
                  ) : (
                    <div className="flex items-center gap-1.5">
                      <button onClick={() => copy(token.token, token.id)}
                        className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all">
                        {copiedField === token.id
                          ? <Check className="text-reap3r-success" style={{ width: '12px', height: '12px' }} />
                          : <Copy style={{ width: '12px', height: '12px' }} />}
                      </button>
                      <button onClick={() => revokeToken(token.id)}
                        className="p-1.5 text-reap3r-muted hover:text-reap3r-danger hover:bg-reap3r-danger/10 rounded-lg transition-all opacity-0 group-hover:opacity-100">
                        <Trash2 style={{ width: '12px', height: '12px' }} />
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Agent Downloads */}
        <Card>
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl bg-white/6 border border-white/10 flex items-center justify-center">
              <Download className="text-reap3r-light" style={{ width: '16px', height: '16px' }} />
            </div>
            <div>
              <h3 className="text-[12px] font-bold text-white uppercase tracking-[0.08em]">Agent Downloads</h3>
              <p className="text-[10px] text-reap3r-muted">Pre-built agent binaries</p>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              { os: 'Windows', icon: MonitorIcon, desc: 'EXE/MSI installer (signed)', href: '/api/agent-binary/download?os=windows&arch=x86_64', color: 'text-blue-400' },
              { os: 'Linux', icon: Terminal, desc: 'Binary (sha256 + signature)', href: '/api/agent-binary/download?os=linux&arch=x86_64', color: 'text-green-400' },
            ].map(d => (
              <a key={d.os} href={d.href} className="block group">
                <div className="flex items-center gap-3 p-4 bg-reap3r-surface/60 border border-reap3r-border/60 rounded-xl hover:border-reap3r-border-light transition-all">
                  <div className="w-10 h-10 rounded-xl bg-white/4 border border-white/8 flex items-center justify-center">
                    <d.icon className={d.color} style={{ width: '16px', height: '16px' }} />
                  </div>
                  <div className="flex-1">
                    <p className="text-[12px] font-semibold text-white">{d.os} Agent</p>
                    <p className="text-[10px] text-reap3r-muted">{d.desc}</p>
                  </div>
                  <Download className="text-reap3r-muted group-hover:text-white transition-colors" style={{ width: '14px', height: '14px' }} />
                </div>
              </a>
            ))}
          </div>
        </Card>
      </div>

      {/* Create Token Modal */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create Enrollment Token">
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Token Name</label>
            <input value={newTokenName} onChange={e => setNewTokenName(e.target.value)} placeholder="Production, Lab, Client..."
              className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20" />
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button onClick={createToken} disabled={!newTokenName.trim() || creating}>Create</Button>
          </div>
        </div>
      </Modal>
    </>
  );
}

function CommandBlock({ label, icon, command, onCopy, copied }: {
  label: string; icon: React.ReactNode; command: string; onCopy: () => void; copied: boolean;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[10px] text-reap3r-muted font-bold uppercase tracking-[0.08em] flex items-center gap-1.5">{icon} {label}</span>
        <button onClick={onCopy} className="text-[10px] text-reap3r-light hover:text-white flex items-center gap-1 transition-colors">
          {copied ? <><Check className="text-reap3r-success" style={{ width: '10px', height: '10px' }} /> Copied</> : <><Copy style={{ width: '10px', height: '10px' }} /> Copy</>}
        </button>
      </div>
      <pre className="code-block px-4 py-3 text-[11px] overflow-x-auto whitespace-pre-wrap break-all">
        {command}
      </pre>
    </div>
  );
}
