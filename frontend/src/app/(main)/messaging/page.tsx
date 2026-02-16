'use client';
import { useEffect, useState, useRef } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { MessageCircle, Plus, Send, Hash, Users, X } from 'lucide-react';

export default function MessagingPage() {
  const [channels, setChannels] = useState<any[]>([]);
  const [selectedChannel, setSelectedChannel] = useState<any | null>(null);
  const [messages, setMessages] = useState<any[]>([]);
  const [messageText, setMessageText] = useState('');
  const [loading, setLoading] = useState(true);
  const [showCreateChannel, setShowCreateChannel] = useState(false);
  const [channelName, setChannelName] = useState('');
  const [channelDesc, setChannelDesc] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const loadChannels = async () => {
    try {
      const res = await api.chat.channels.list();
      setChannels(res.data || []);
    } catch (err) {
      console.error('Failed to load channels:', err);
    }
  };

  const loadMessages = async (channelId: string) => {
    try {
      const res = await api.chat.channels.messages(channelId);
      setMessages((res.data || []).reverse());
      scrollToBottom();
    } catch (err) {
      console.error('Failed to load messages:', err);
    }
  };

  useEffect(() => {
    (async () => {
      await loadChannels();
      setLoading(false);
    })();
  }, []);

  useEffect(() => {
    if (selectedChannel) {
      loadMessages(selectedChannel.id);
    }
  }, [selectedChannel]);

  const handleSendMessage = async () => {
    if (!messageText.trim() || !selectedChannel) return;
    try {
      await api.chat.channels.sendMessage(selectedChannel.id, { body: messageText });
      setMessageText('');
      await loadMessages(selectedChannel.id);
    } catch (err) {
      console.error('Failed to send message:', err);
    }
  };

  const handleCreateChannel = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.chat.channels.create({ name: channelName, type: 'group' });
      setShowCreateChannel(false);
      setChannelName('');
      setChannelDesc('');
      await loadChannels();
    } catch (err) {
      console.error('Failed to create channel:', err);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-reap3r-bg">
        <div className="w-8 h-8 border-2 border-reap3r-accent border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="flex h-[calc(100vh-60px)] bg-reap3r-bg">
      {/* Channels Sidebar */}
      <div className="w-64 border-r border-reap3r-border bg-reap3r-card/30 flex flex-col">
        <div className="p-4 border-b border-reap3r-border flex items-center justify-between">
          <h2 className="font-semibold text-sm text-reap3r-text">Channels</h2>
          <Button size="sm" variant="ghost" onClick={() => setShowCreateChannel(true)}>
            <Plus className="w-4 h-4" />
          </Button>
        </div>

        <div className="flex-1 overflow-y-auto">
          {channels.map(ch => (
            <button
              key={ch.id}
              onClick={() => setSelectedChannel(ch)}
              className={`w-full text-left px-4 py-3 border-b border-reap3r-border/30 hover:bg-reap3r-card/50 transition ${
                selectedChannel?.id === ch.id ? 'bg-reap3r-accent/10 border-l-2 border-reap3r-accent' : ''
              }`}
            >
              <div className="flex items-center gap-2">
                <Hash className="w-4 h-4 text-reap3r-muted" />
                <span className="text-sm font-medium text-reap3r-text truncate">{ch.name}</span>
              </div>
              <div className="text-xs text-reap3r-muted ml-6">{ch.member_count} members</div>
            </button>
          ))}
        </div>

        {showCreateChannel && (
          <form onSubmit={handleCreateChannel} className="border-t border-reap3r-border p-4 space-y-2">
            <input
              type="text"
              value={channelName}
              onChange={(e) => setChannelName(e.target.value)}
              placeholder="Channel name"
              className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded text-sm text-reap3r-text placeholder-reap3r-muted"
              required
            />
            <div className="flex gap-2">
              <Button type="submit" size="sm" className="flex-1">Create</Button>
              <Button type="button" size="sm" variant="ghost" className="flex-1" onClick={() => setShowCreateChannel(false)}>Cancel</Button>
            </div>
          </form>
        )}
      </div>

      {/* Messages Area */}
      <div className="flex-1 flex flex-col">
        {selectedChannel ? (
          <>
            {/* Header */}
            <div className="h-16 border-b border-reap3r-border bg-reap3r-card px-6 flex items-center justify-between">
              <div>
                <h1 className="font-semibold text-reap3r-text">{selectedChannel.name}</h1>
                <p className="text-xs text-reap3r-muted">{selectedChannel.member_count} members</p>
              </div>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              {messages.length === 0 ? (
                <EmptyState title="No messages" description="Be the first to message!" />
              ) : (
                messages.map((msg, i) => (
                  <div key={i} className="flex gap-3">
                    <div className="w-8 h-8 rounded-full bg-reap3r-accent/20 flex items-center justify-center flex-shrink-0">
                      <span className="text-xs font-semibold text-reap3r-accent">{msg.user_name?.[0]?.toUpperCase()}</span>
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-reap3r-text">{msg.user_name}</span>
                        <span className="text-xs text-reap3r-muted">{new Date(msg.created_at).toLocaleTimeString()}</span>
                      </div>
                      <p className="text-sm text-reap3r-text mt-1">{msg.body}</p>
                    </div>
                  </div>
                ))
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Message Input */}
            <div className="h-20 border-t border-reap3r-border bg-reap3r-card/30 p-4 flex items-center gap-2">
              <input
                type="text"
                value={messageText}
                onChange={(e) => setMessageText(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
                placeholder="Type a message..."
                className="flex-1 px-4 py-2 bg-reap3r-bg border border-reap3r-border rounded text-sm text-reap3r-text placeholder-reap3r-muted"
              />
              <Button onClick={handleSendMessage} variant="secondary" size="sm">
                <Send className="w-4 h-4" />
              </Button>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <EmptyState title="No channel selected" description="Select a channel to start messaging" />
          </div>
        )}
      </div>
    </div>
  );
}


