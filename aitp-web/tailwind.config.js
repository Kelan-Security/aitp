/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'bg-primary': '#ffffff',
        'bg-secondary': '#f9fafb',
        'accent-cyan': '#000000',
        'accent-emerald': '#333333',
        'accent-red': '#000000',
        'accent-amber': '#666666',
        'text-primary': '#000000',
        'text-mono': '#333333',
      },
      fontFamily: {
        display: ['Orbitron', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
        sans: ['Inter', 'sans-serif'],
      },
      backgroundImage: {
        'cyber-grid': "radial-gradient(circle, rgba(0, 0, 0, 0.15) 1px, transparent 1px)",
      },
      backgroundSize: {
        'grid-size': '40px 40px',
      },
    },
  },
  plugins: [],
}
