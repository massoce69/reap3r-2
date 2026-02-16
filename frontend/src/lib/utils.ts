import clsx from 'clsx';

export function cn(...args: Parameters<typeof clsx>) {
  return clsx(args);
}

export function formatDate(date: string | null): string {
  if (!date) return '—';
  return new Date(date).toLocaleString();
}

export function statusColor(status: string): string {
  switch (status) {
    case 'online': return 'text-reap3r-success';
    case 'offline': return 'text-reap3r-muted';
    case 'degraded': return 'text-reap3r-warning';
    case 'pending': return 'text-reap3r-accent';
    case 'success': return 'text-reap3r-success';
    case 'failed': return 'text-reap3r-danger';
    case 'running': return 'text-reap3r-accent';
    case 'queued': return 'text-reap3r-muted';
    case 'timeout': return 'text-reap3r-warning';
    case 'cancelled': return 'text-reap3r-muted';
    default: return 'text-reap3r-text';
  }
}
