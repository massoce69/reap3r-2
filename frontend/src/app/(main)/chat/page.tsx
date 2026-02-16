'use client';
import { useEffect, useState, useRef } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { MessageSquare, Plus, Send, Hash } from 'lucide-react';

export default function ChatPage() {
  const { user } = useAuth();
  const [channels, setChannels] = useState<any[]>([]);
  const [activeChannel, setActiveChannel] = useState<string | null>(null);
  const [messages, setMessages] = useState<any[]>([]);
  const [newMessage, setNewMessage] = useState('');
  const [newChannelName, setNewChannelName] = useState('');
  const [showCreateChannel, setShowCreateChannel] = useState(false);
  const [loading, setLoading] = useState(true);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const loadChannels = () => {
    api.chat.channels.list().then(r => {
      setChannels(r.data);
      if (!activeChannel && r.data.length > 0) setActiveChannel(r.data[0].id);
      setLoading(false);
    }).catch(() => setLoading(false));
  };

  const loadMessages = (channelId: string) => {
    api.chat.channels.messages(channelId, { limit: '100' }).then(r => {
      setMessages(r.data.reverse());
      setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
    });
  };

  useEffect(() => { loadChannels(); }, []);
  useEffect(() => { if (activeChannel) loadMessages(activeChannel); }, [activeChannel]);

  const sendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newMessage.trim() || !activeChannel) return;
    await api.chat.channels.sendMessage(activeChannel, { body: newMessage.trim() });
    setNewMessage('');
    loadMessages(activeChannel);
  };

  const createChannel = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newChannelName.trim()) return;
    await api.chat.channels.create({ name: newChannelName.trim() });
    setNewChannelName(''); setShowCreateChannel(false); loadChannels();
  };

  const activeChannelData = channels.find(c => c.id === activeChannel);

  return (
    <>
      <TopBar title="Messaging" />
      <div className="p-6">
        <div className="flex h-[calc(100vh-8rem)] border border-reap3r-border rounded-lg overflow-hidden">
          {/* Channels sidebar */}
          <div className="w-56 bg-reap3r-surface border-r border-reap3r-border flex flex-col">
            <div className="p-3 border-b border-reap3r-border flex items-center justify-between">
              <span className="text-xs font-semibold text-reap3r-muted uppercase tracking-wider">Channels</span>
              <button onClick={() => setShowCreateChannel(true)} className="p-1 text-reap3r-muted hover:text-reap3r-accent"><Plus className="w-4 h-4" /></button>
            </div>
            {showCreateChannel && (
              <form onSubmit={createChannel} className="p-2 border-b border-reap3r-border">
                <input className="w-full px-2 py-1 bg-reap3r-bg border border-reap3r-border rounded text-xs text-reap3r-text" placeholder="Channel name" value={newChannelName} onChange={e => setNewChannelName(e.target.value)} autoFocus />
              </form>
            )}
            <div className="flex-1 overflow-y-auto p-2 space-y-0.5">
              {channels.map(c => (
                <button key={c.id} onClick={() => setActiveChannel(c.id)}
                  className={`w-full text-left px-3 py-2 rounded-lg text-sm flex items-center gap-2 transition-colors ${activeChannel === c.id ? 'bg-reap3r-accent/10 text-reap3r-accent' : 'text-reap3r-muted hover:text-reap3r-text hover:bg-reap3r-hover'}`}>
                  <Hash className="w-3.5 h-3.5" />{c.name}
                </button>
              ))}
            </div>
          </div>

          {/* Messages area */}
          <div className="flex-1 flex flex-col bg-reap3r-bg">
            {activeChannel ? (
              <>
                <div className="px-4 py-3 border-b border-reap3r-border bg-reap3r-surface/50">
                  <div className="flex items-center gap-2">
                    <Hash className="w-4 h-4 text-reap3r-muted" />
                    <span className="text-sm font-medium text-reap3r-text">{activeChannelData?.name ?? 'Channel'}</span>
                  </div>
                </div>
                <div className="flex-1 overflow-y-auto p-4 space-y-3">
                  {messages.length === 0 && <p className="text-center text-reap3r-muted text-sm py-10">No messages yet. Start the conversation!</p>}
                  {messages.map(m => (
                    <div key={m.id} className="flex gap-3">
                      <div className="w-8 h-8 rounded-full bg-reap3r-accent/20 flex items-center justify-center text-xs font-bold text-reap3r-accent flex-shrink-0">
                        {m.user_name?.charAt(0)?.toUpperCase() ?? '?'}
                      </div>
                      <div>
                        <div className="flex items-baseline gap-2">
                          <span className="text-sm font-medium text-reap3r-text">{m.user_name ?? 'Unknown'}</span>
                          <span className="text-[10px] text-reap3r-muted">{new Date(m.created_at).toLocaleTimeString()}</span>
                        </div>
                        <p className="text-sm text-reap3r-text/80 mt-0.5">{m.body}</p>
                      </div>
                    </div>
                  ))}
                  <div ref={messagesEndRef} />
                </div>
                <form onSubmit={sendMessage} className="p-3 border-t border-reap3r-border bg-reap3r-surface/50">
                  <div className="flex gap-2">
                    <input className="flex-1 px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text placeholder:text-reap3r-muted/50 focus:outline-none focus:ring-2 focus:ring-reap3r-accent/50" placeholder={`Message #${activeChannelData?.name ?? ''}...`} value={newMessage} onChange={e => setNewMessage(e.target.value)} />
                    <Button type="submit" size="sm"><Send className="w-4 h-4" /></Button>
                  </div>
                </form>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center">
                <EmptyState icon={<MessageSquare className="w-8 h-8" />} title="Select a channel" description="Choose a channel to start messaging." />
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
