import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    // Local dev: forward /api/* to Flask on port 8080,
    // so the dashboard's relative /api/analyze path works on your machine too.
    proxy: {
      "/api": "http://127.0.0.1:8080",
    },
  },
});