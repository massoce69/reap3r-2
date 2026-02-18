// ─────────────────────────────────────────────
// MASSVISION Reap3r — WebSocket Client
// ─────────────────────────────────────────────

type MessageHandler = (data: any) => void;

class RealtimeClient {
  private ws: WebSocket | null = null;
  private handlers = new Map<string, Set<MessageHandler>>();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private token: string | null = null;

  connect(token: string) {
    this.token = token;
    const wsBase =
      process.env.NEXT_PUBLIC_WS_URL?.trim() ||
      (typeof window !== 'undefined'
        ? `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`
        : 'ws://127.0.0.1:4000');

    // Default path is proxied by Nginx: `/ws/*` -> backend
    this.ws = new WebSocket(`${wsBase}/ws/ui?token=${token}`);

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        const type = data.type;
        this.handlers.get(type)?.forEach((h) => h(data));
        this.handlers.get('*')?.forEach((h) => h(data));
      } catch {}
    };

    this.ws.onclose = () => {
      this.reconnectTimer = setTimeout(() => {
        if (this.token) this.connect(this.token);
      }, 3000);
    };

    this.ws.onerror = () => {
      this.ws?.close();
    };
  }

  disconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.ws?.close();
    this.ws = null;
    this.token = null;
  }

  on(type: string, handler: MessageHandler) {
    if (!this.handlers.has(type)) this.handlers.set(type, new Set());
    this.handlers.get(type)!.add(handler);
    return () => {
      this.handlers.get(type)?.delete(handler);
    };
  }

  get connected() {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}

export const realtime = new RealtimeClient();

/** React hook to access the realtime client. Connects on mount if token available. */
export function useRealtimeClient() {
  return realtime;
}
