// ─────────────────────────────────────────────
// MASSVISION Reap3r — WebSocket Client
// ─────────────────────────────────────────────

type MessageHandler = (data: any) => void;

class RealtimeClient {
  private ws: WebSocket | null = null;
  private handlers = new Map<string, Set<MessageHandler>>();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private token: string | null = null;
  private connecting = false;
  private messageCount = 0;

  connect(token: string) {
    // Prevent duplicate connections
    if (this.connecting) {
      console.log('[WS] connect() skipped — already connecting');
      return;
    }
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      console.log('[WS] connect() skipped — already connected/connecting, readyState:', this.ws.readyState);
      return;
    }

    this.connecting = true;
    this.token = token;
    this.messageCount = 0;

    // Close any existing zombie connection
    if (this.ws) {
      try {
        this.ws.onclose = null;  // Remove onclose to prevent reconnect loop
        this.ws.onerror = null;
        this.ws.onmessage = null;
        this.ws.close();
      } catch {}
      this.ws = null;
    }

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    const wsBase =
      process.env.NEXT_PUBLIC_WS_URL?.trim() ||
      (typeof window !== 'undefined'
        ? `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`
        : 'ws://127.0.0.1:4000');

    const url = `${wsBase}/ws/ui?token=${token}`;
    console.log('[WS] Connecting to', url.replace(/token=.*/, 'token=***'));

    const ws = new WebSocket(url);
    this.ws = ws;

    ws.onopen = () => {
      this.connecting = false;
      console.log('[WS] Connected successfully');
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        const type = data.type;
        this.messageCount++;
        if (this.messageCount <= 3 || this.messageCount % 50 === 0) {
          console.log(`[WS] Message #${this.messageCount}: type=${type}`, type === 'rd:frame' ? `(seq=${data.payload?.sequence})` : '');
        }
        this.handlers.get(type)?.forEach((h) => h(data));
        this.handlers.get('*')?.forEach((h) => h(data));
      } catch (err) {
        console.error('[WS] Message parse error:', err);
      }
    };

    ws.onclose = (ev) => {
      this.connecting = false;
      console.log('[WS] Connection closed, code:', ev.code, 'reason:', ev.reason);
      // Only reconnect if we still have a token (not manually disconnected)
      if (this.token && this.ws === ws) {
        this.reconnectTimer = setTimeout(() => {
          console.log('[WS] Reconnecting...');
          this.connecting = false; // Reset so connect() proceeds
          this.ws = null;          // Reset so guard allows new connection
          if (this.token) this.connect(this.token);
        }, 4000);
      }
    };

    ws.onerror = (err) => {
      this.connecting = false;
      console.error('[WS] Error:', err);
    };
  }

  disconnect() {
    console.log('[WS] disconnect() called');
    this.token = null;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      try {
        this.ws.onclose = null;
        this.ws.onerror = null;
        this.ws.onmessage = null;
        this.ws.close();
      } catch {}
      this.ws = null;
    }
    this.connecting = false;
  }

  on(type: string, handler: MessageHandler) {
    if (!this.handlers.has(type)) this.handlers.set(type, new Set());
    this.handlers.get(type)!.add(handler);
    return () => {
      this.handlers.get(type)?.delete(handler);
    };
  }

  /** Send a JSON message to the UI WebSocket server. */
  send(type: string, payload: unknown) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type, payload }));
    }
  }

  get connected() {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  /** Number of WS messages received since last connect. */
  get rxCount() {
    return this.messageCount;
  }
}

export const realtime = new RealtimeClient();

/** React hook to access the realtime client. Connects on mount if token available. */
export function useRealtimeClient() {
  return realtime;
}
