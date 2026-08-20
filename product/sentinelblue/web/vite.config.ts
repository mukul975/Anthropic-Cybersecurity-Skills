import { defineConfig } from "vite";

export default defineConfig({
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8741",
        changeOrigin: true,
      },
    },
  },
});
