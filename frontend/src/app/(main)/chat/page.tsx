'use client';
import { useEffect, useState, useRef, useCallback } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Button, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { useToastHelpers } from '@/lib/toast';
import { MessageSquare, Plus, Send, Hash, Trash2 } from 'lucide-react';

export default function ChatPage() {
  const toast = useToastHelpers();
  const [channels, setChannels] = useState<any[]>([]);
  const [activeChannel, setActiveChannel] = useState<string | null>(null);
  const [messages, setMessages] = useState<any[]>([]);
  const [newMessage, setNewMessage] = useState('');
  const [newChannelName, setNewChannelName] = useState('');
  const [showCreateChannel, setShowCreateChannel] = useState(false);
  const [loading, setLoading] = useState(true);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadChannels = () => {
    api.chat.channels.list().then(r => {
      setChannels(r.data);
      if (!activeChannel && r.data.length > 0) setActiveChannel(r.data[0].id);
      setLoading(false);
    }).catch(() => setLoading(false));
  };

  const loadMessages = useCallback((channelId: string) => {
    api.chat.channels.messages(channelId, { limit: '100' }).then(r => {
      setMessages(r.data.reverse());
      setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
    });
  }, []);

  useEffect(() => { loadChannels(); }, []);
  useEffect(() => {
    if (activeChannel) {
      loadMessages(activeChannel);
      // Auto-poll every 3 seconds for real-time chat
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(() => loadMessages(activeChannel), 3000);
    }
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [activeChannel, loadMessages]);

  const sendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newMessage.trim() || !activeChannel) return;
    try {
      await api.chat.channels.sendMessage(activeChannel, { body: newMessage.trim() });
      setNewMessage('');
      loadMessages(activeChannel);
    } catch (err: any) { toast.error('Send failed', err.message); }
  };

  const createChannel = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newChannelName.trim()) return;
    try {
      await api.chat.channels.create({ name: newChannelName.trim() });
      toast.success('Channel created');
      setNewChannelName(''); setShowCreateChannel(false); loadChannels();
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  const activeChannelData = channels.find(c => c.id === activeChannel);

  return (
    <>
      <TopBar title="Messaging" />
      <div className="p-6 h-[calc(100vh-3rem)] flex flex-col animate-fade-in">
        <div className="flex flex-1 min-h-0 border border-reap3r-border rounded-2xl overflow-hidden bg-reap3r-card shadow-[0_2px_16px_rgba(0,0,0,0.5)]">

          {/* Channels sidebar */}
          <div className="w-56 bg-reap3r-surface border-r border-reap3r-border flex flex-col shrink-0">
            <div className="p-3 border-b border-reap3r-border flex items-center justify-between">
              <span className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Channels</span>
              <button
                onClick={() => setShowCreateChannel(true)}
                className="p-1 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all"
              >
                <Plus style={{ width: '13px', height: '13px' }} />
              </button>
            </div>

            {showCreateChannel && (
              <form onSubmit={createChannel} className="p-2 border-b border-reap3r-border">
                <input
                  className="w-full px-2 py-1.5 bg-reap3r-card border border-reap3r-border rounded-lg text-xs text-white
                    placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20"
                  placeholder="channel-name"
                  value={newChannelName}
                  onChange={e => setNewChannelName(e.target.value)}
                  autoFocus
                />
              </form>
            )}

            <div className="flex-1 overflow-y-auto p-2 space-y-0.5">
              {channels.map(c => (
                <button
                  key={c.id}
                  onClick={() => setActiveChannel(c.id)}
                  className={`w-full text-left px-3 py-2 rounded-lg text-xs flex items-center gap-2 transition-all duration-150 ${
                    activeChannel === c.id
                      ? 'bg-white/8 text-white border border-white/10'
                      : 'text-reap3r-muted hover:text-reap3r-light hover:bg-reap3r-hover'
                  }`}
                >
                  <Hash style={{ width: '11px', height: '11px', flexShrink: 0 }} />
                  <span className="truncate font-medium">{c.name}</span>
                </button>
              ))}
              {channels.length === 0 && !loading && (
                <p className="text-[10px] text-reap3r-muted text-center px-3 py-4">No channels yet.</p>
              )}
            </div>
          </div>

          {/* Messages area */}
          <div className="flex-1 flex flex-col min-w-0">
            {activeChannel ? (
              <>
                <div className="px-5 py-3 border-b border-reap3r-border bg-reap3r-surface/40">
                  <div className="flex items-center gap-2">
                    <Hash className="text-reap3r-muted" style={{ width: '13px', height: '13px' }} />
                    <span className="text-sm font-semibold text-white">{activeChannelData?.name ?? 'Channel'}</span>
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto p-5 space-y-4">
                  {messages.length === 0 && (
                    <div className="flex flex-col items-center justify-center h-full">
                      <EmptyState
                        icon={<MessageSquare style={{ width: '24px', height: '24px' }} />}
                        title="No messages yet"
                        description="Start the conversation!"
                      />
                    </div>
                  )}
                  {messages.map(m => (
                    <div key={m.id} className="flex gap-3 group">
                      <div className="w-8 h-8 rounded-xl bg-white/6 border border-white/8 flex items-center justify-center text-[11px] font-bold text-white flex-shrink-0">
                        {m.user_name?.charAt(0)?.toUpperCase() ?? '?'}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-baseline gap-2">
                          <span className="text-[12px] font-semibold text-white">{m.user_name ?? 'Unknown'}</span>
                          <span className="text-[10px] text-reap3r-muted font-mono">
                            {new Date(m.created_at).toLocaleTimeString()}
                          </span>
                        </div>
                        <p className="text-[12px] text-reap3r-text/80 mt-0.5 leading-relaxed break-words">{m.body}</p>
                      </div>
                    </div>
                  ))}
                  <div ref={messagesEndRef} />
                </div>

                <form onSubmit={sendMessage} className="p-4 border-t border-reap3r-border">
                  <div className="flex gap-2">
                    <input
                      className="flex-1 px-4 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-xl text-sm text-white
                        placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20"
                      placeholder={`Message #${activeChannelData?.name ?? ''}...`}
                      value={newMessage}
                      onChange={e => setNewMessage(e.target.value)}
                    />
                    <Button type="submit" size="sm">
                      <Send style={{ width: '13px', height: '13px' }} />
                    </Button>
                  </div>
                </form>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center">
                <EmptyState
                  icon={<MessageSquare style={{ width: '28px', height: '28px' }} />}
                  title="Select a channel"
                  description="Choose a channel from the sidebar to start messaging."
                />
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
