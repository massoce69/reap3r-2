/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        reap3r: {
          bg:            '#080808',
          surface:       '#0f0f0f',
          card:          '#161616',
          'card-alt':    '#1c1c1c',
          border:        '#252525',
          'border-light':'#333333',
          hover:         '#1a1a1a',
          accent:        '#ffffff',
          'accent-dim':  '#a0a0a0',
          secondary:     '#6b6b6b',
          success:       '#22c55e',
          warning:       '#f59e0b',
          danger:        '#ef4444',
          text:          '#f0f0f0',
          muted:         '#5c5c5c',
          light:         '#9a9a9a',
          subtle:        '#2e2e2e',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'glow-white':    '0 0 20px rgba(255,255,255,0.06), 0 0 40px rgba(255,255,255,0.02)',
        'glow-white-sm': '0 0 10px rgba(255,255,255,0.08)',
        'glow-danger':   '0 0 12px rgba(239,68,68,0.2)',
        'glow-success':  '0 0 12px rgba(34,197,94,0.2)',
        'card':          '0 2px 16px rgba(0,0,0,0.6), 0 1px 0 rgba(255,255,255,0.04) inset',
        'card-hover':    '0 4px 24px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,255,255,0.08)',
        'modal':         '0 24px 80px rgba(0,0,0,0.9), 0 0 0 1px rgba(255,255,255,0.06)',
      },
      animation: {
        'pulse-slow':   'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow':         'glow-pulse 3s ease-in-out infinite',
        'fade-in':      'fadeIn 0.25s ease-out',
        'slide-up':     'slideUp 0.25s ease-out',
        'slide-right':  'slideRight 0.25s ease-out',
      },
      keyframes: {
        'glow-pulse': {
          '0%, 100%': { boxShadow: '0 0 8px rgba(255,255,255,0.06), 0 0 0 1px rgba(255,255,255,0.05)' },
          '50%':      { boxShadow: '0 0 20px rgba(255,255,255,0.12), 0 0 0 1px rgba(255,255,255,0.1)' },
        },
        fadeIn: {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%':   { transform: 'translateY(6px)', opacity: '0' },
          '100%': { transform: 'translateY(0)',   opacity: '1' },
        },
        slideRight: {
          '0%':   { transform: 'translateX(-6px)', opacity: '0' },
          '100%': { transform: 'translateX(0)',     opacity: '1' },
        },
      },
    },
  },
  plugins: [],
};
