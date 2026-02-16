'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Input, Badge } from '@/components/ui';
import { api } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { Download, Copy, Key, Terminal, Monitor as MonitorIcon, Check } from 'lucide-react';

export default function DeploymentPage() {
  const [tokens, setTokens] = useState<any[]>([]);
  const [commands, setCommands] = useState<any>(null);
  const [selectedTokenId, setSelectedTokenId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [newTokenName, setNewTokenName] = useState('');
  const [creating, setCreating] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      api.enrollment.tokens.list(),
    ]).then(([tokensRes]) => {
      setTokens(tokensRes.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  const createToken = async () => {
    if (!newTokenName.trim()) return;
    setCreating(true);
    try {
      await api.enrollment.tokens.create({ name: newTokenName, max_uses: 0 });
      const res = await api.enrollment.tokens.list();
      setTokens(res.data);
      setNewTokenName('');
    } finally {
      setCreating(false);
    }
  };

  const revokeToken = async (id: string) => {
    await api.enrollment.tokens.revoke(id);
    const res = await api.enrollment.tokens.list();
    setTokens(res.data);
  };

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  return (
    <>
      <TopBar title="Agent Deployment" />
      <div className="p-6 space-y-6">
        {/* Deployment Commands */}
        <Card>
          <h3 className="text-sm font-semibold text-reap3r-text mb-4 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-reap3r-accent" />
            Deployment Commands
          </h3>

          {commands && (
            <div className="space-y-4">
              <CommandBlock
                label="Windows (PowerShell)"
                icon={<MonitorIcon className="w-4 h-4" />}
                command={commands.windows_powershell}
                onCopy={() => copyToClipboard(commands.windows_powershell, 'windows')}
                copied={copiedField === 'windows'}
              />
              <CommandBlock
                label="Linux (one-liner)"
                icon={<Terminal className="w-4 h-4" />}
                command={commands.linux_oneliner}
                onCopy={() => copyToClipboard(commands.linux_oneliner, 'linux')}
                copied={copiedField === 'linux'}
              />
            </div>
          )}
          {!commands && tokens.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs text-reap3r-muted">Select a token to see deployment commands:</p>
              <div className="flex gap-2 flex-wrap">
                {tokens.filter(t => !t.revoked).map(t => (
                  <Button key={t.id} size="sm" variant="secondary" onClick={() => {
                    setSelectedTokenId(t.id);
                    api.enrollment.tokens.commands(t.id).then(setCommands).catch(() => {});
                  }}>{t.name}</Button>
                ))}
              </div>
            </div>
          )}
          {!commands && tokens.length === 0 && (
            <p className="text-sm text-reap3r-muted">Create an enrollment token first.</p>
          )}
        </Card>

        {/* Enrollment Tokens */}
        <Card>
          <h3 className="text-sm font-semibold text-reap3r-text mb-4 flex items-center gap-2">
            <Key className="w-4 h-4 text-reap3r-accent" />
            Enrollment Tokens
          </h3>

          <div className="flex gap-2 mb-4">
            <Input
              placeholder="Token name..."
              value={newTokenName}
              onChange={(e) => setNewTokenName(e.target.value)}
              className="!mb-0"
            />
            <Button onClick={createToken} loading={creating} disabled={!newTokenName.trim()}>
              Create Token
            </Button>
          </div>

          <div className="divide-y divide-reap3r-border">
            {tokens.map((token) => (
              <div key={token.id} className="flex items-center gap-3 py-3">
                <Key className="w-4 h-4 text-reap3r-muted" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-reap3r-text">{token.name}</p>
                  <p className="text-xs text-reap3r-muted font-mono truncate">{token.token}</p>
                </div>
                <Badge>{token.use_count}{token.max_uses > 0 ? `/${token.max_uses}` : ''} uses</Badge>
                {token.revoked ? (
                  <Badge variant="danger">Revoked</Badge>
                ) : (
                  <>
                    <Button variant="ghost" size="sm" onClick={() => copyToClipboard(token.token, token.id)}>
                      {copiedField === token.id ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    </Button>
                    <Button variant="danger" size="sm" onClick={() => revokeToken(token.id)}>Revoke</Button>
                  </>
                )}
              </div>
            ))}
            {tokens.length === 0 && !loading && (
              <p className="text-sm text-reap3r-muted py-4 text-center">No enrollment tokens. Create one to deploy agents.</p>
            )}
          </div>
        </Card>

        {/* Agent Downloads */}
        <Card>
          <h3 className="text-sm font-semibold text-reap3r-text mb-4 flex items-center gap-2">
            <Download className="w-4 h-4 text-reap3r-accent" />
            Agent Downloads
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="border border-reap3r-border rounded-lg p-4">
              <div className="flex items-center gap-3 mb-2">
                <MonitorIcon className="w-5 h-5 text-reap3r-accent" />
                <div>
                  <p className="text-sm font-medium text-reap3r-text">Windows Agent</p>
                  <p className="text-xs text-reap3r-muted">EXE/MSI installer (signed)</p>
                </div>
              </div>
              <Button variant="secondary" size="sm" className="w-full mt-2" disabled>
                <Download className="w-3 h-3" /> Download (coming soon)
              </Button>
            </div>
            <div className="border border-reap3r-border rounded-lg p-4">
              <div className="flex items-center gap-3 mb-2">
                <Terminal className="w-5 h-5 text-reap3r-accent" />
                <div>
                  <p className="text-sm font-medium text-reap3r-text">Linux Agent</p>
                  <p className="text-xs text-reap3r-muted">Binary (sha256 + signature)</p>
                </div>
              </div>
              <Button variant="secondary" size="sm" className="w-full mt-2" disabled>
                <Download className="w-3 h-3" /> Download (coming soon)
              </Button>
            </div>
          </div>
        </Card>
      </div>
    </>
  );
}

function CommandBlock({ label, icon, command, onCopy, copied }: {
  label: string; icon: React.ReactNode; command: string; onCopy: () => void; copied: boolean;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-reap3r-muted flex items-center gap-1.5">{icon} {label}</span>
        <button onClick={onCopy} className="text-xs text-reap3r-accent hover:underline flex items-center gap-1">
          {copied ? <><Check className="w-3 h-3" /> Copied!</> : <><Copy className="w-3 h-3" /> Copy</>}
        </button>
      </div>
      <pre className="bg-reap3r-bg border border-reap3r-border rounded-lg px-4 py-3 text-xs text-reap3r-text font-mono overflow-x-auto whitespace-pre-wrap break-all">
        {command}
      </pre>
    </div>
  );
}
