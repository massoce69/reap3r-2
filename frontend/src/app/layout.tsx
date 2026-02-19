import type { Metadata } from 'next';
import { AuthProvider } from '@/lib/auth-provider';
import { ToastProvider } from '@/lib/toast';
import './globals.css';

export const metadata: Metadata = {
  title: 'MASSVISION Reap3r',
  description: 'Enterprise Agent-Driven Remote Management Platform',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="font-sans antialiased bg-reap3r-bg text-reap3r-text min-h-screen">
        <ToastProvider>
          <AuthProvider>
            {children}
          </AuthProvider>
        </ToastProvider>
      </body>
    </html>
  );
}
