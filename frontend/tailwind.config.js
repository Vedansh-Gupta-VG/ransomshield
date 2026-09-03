/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,jsx}",
    "./components/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: "#0a0e14",
        panel: "#121826",
        border: "#1f2937",
        accent: "#ef4444",
        accent2: "#22c55e",
        muted: "#6b7280",
      },
    },
  },
  plugins: [],
};
