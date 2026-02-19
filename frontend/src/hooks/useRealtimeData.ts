'use client';
// ─────────────────────────────────────────────
// MASSVISION Reap3r — Real-time data hooks
// ─────────────────────────────────────────────
import { useEffect, useRef, useCallback } from 'react';
import { realtime as realtimeClient } from '@/lib/ws';

/**
 * Subscribe to one or more WebSocket events and call `onEvent` for each.
 * Automatically un-subscribes on unmount.
 *
 * Example: useRealtimeEvents(['agent:enrolled', 'agent:offline'], (_event, data) => refetch());
 */
export function useRealtimeEvents(events: string[], onEvent: (event: string, data: any) => void) {
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;

  useEffect(() => {
    const unsubs = events.map((ev) =>
      realtimeClient.on(ev, (data: any) => onEventRef.current(ev, data)),
    );
    return () => unsubs.forEach((u) => u());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events.join(',')]);
}

/**
 * Auto-refresh data when specific WebSocket events occur.
 * Debounces rapid events (50ms) to avoid hammering the API.
 */
export function useRealtimeRefresh(events: string[], refetchFn: () => void, debounceMs = 250) {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const refetchRef = useRef(refetchFn);
  refetchRef.current = refetchFn;

  const debouncedRefetch = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => refetchRef.current(), debounceMs);
  }, [debounceMs]);

  useRealtimeEvents(events, debouncedRefetch);

  useEffect(() => {
    return () => { if (timerRef.current) clearTimeout(timerRef.current); };
  }, []);
}

/** Common event groups */
export const WS_AGENT_EVENTS = ['agent:enrolled', 'agent:offline', 'agent:metrics'];
export const WS_JOB_EVENTS = ['job:status', 'job:result'];
export const WS_EDR_EVENTS = ['edr:event'];
export const WS_ALERT_EVENTS = ['alert:fired', 'alert:resolved'];
export const WS_ALL_EVENTS = [...WS_AGENT_EVENTS, ...WS_JOB_EVENTS, ...WS_EDR_EVENTS, ...WS_ALERT_EVENTS];
