/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'bg-primary': '#050810',
        'bg-secondary': '#0a1020',
        'accent-cyan': '#00f5ff',
        'accent-emerald': '#00ff88',
        'accent-red': '#ff2244',
        'accent-amber': '#ffaa00',
        'text-primary': '#e8eaf0',
        'text-mono': '#7db8d4',
      },
      fontFamily: {
        display: ['Orbitron', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
        sans: ['Inter', 'sans-serif'],
      },
      backgroundImage: {
        'cyber-grid': "radial-gradient(circle, rgba(0, 245, 255, 0.05) 1px, transparent 1px)",
      },
      backgroundSize: {
        'grid-size': '40px 40px',
      },
    },
  },
  plugins: [],
}
