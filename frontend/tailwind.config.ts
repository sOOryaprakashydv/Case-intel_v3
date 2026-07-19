import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#0b0e1a",
          900: "#12162a",
          800: "#1a2038",
          700: "#242b4a",
          600: "#33395c",
        },
        accent: {
          500: "#6366f1",
          400: "#818cf8",
          300: "#a5b4fc",
        },
        signal: {
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          low: "#22c55e",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(0,0,0,0.3), 0 4px 16px rgba(0,0,0,0.2)",
      },
      borderRadius: {
        xl2: "1.25rem",
      },
    },
  },
  plugins: [],
};
export default config;
