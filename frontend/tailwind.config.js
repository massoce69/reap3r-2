/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        reap3r: {
          bg: '#020208',
          surface: '#06060d',
          card: '#0c0c18',
          'card-alt': '#101020',
          border: '#181830',
          'border-light': '#22223a',
          hover: '#0f0f1e',
          accent: '#00d4ff',
          'accent-dim': '#0093b3',
          secondary: '#7c3aed',
          success: '#00e5a0',
          warning: '#f5a623',
          danger: '#ff4757',
          text: '#eaeaf5',
          muted: '#4e4e68',
          light: '#9595b5',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'glow-accent': '0 0 20px rgba(0,212,255,0.15), 0 0 40px rgba(0,212,255,0.05)',
        'glow-accent-sm': '0 0 10px rgba(0,212,255,0.12)',
        'glow-danger': '0 0 12px rgba(255,71,87,0.2)',
        'card': '0 4px 24px rgba(0,0,0,0.5), 0 1px 0 rgba(255,255,255,0.03) inset',
        'card-hover': '0 8px 32px rgba(0,0,0,0.6), 0 0 0 1px rgba(0,212,255,0.1)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow-pulse 2.5s ease-in-out infinite',
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
      },
      keyframes: {
        'glow-pulse': {
          '0%, 100%': { boxShadow: '0 0 8px rgba(0,212,255,0.2), 0 0 0 1px rgba(0,212,255,0.1)' },
          '50%': { boxShadow: '0 0 24px rgba(0,212,255,0.4), 0 0 0 1px rgba(0,212,255,0.2)' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { transform: 'translateY(8px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [],
};
