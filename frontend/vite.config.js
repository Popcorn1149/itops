import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

// mode "demo": build 1 file HTML duy nhất, API giả lập trong trình duyệt (để xem thử không cần server)
export default defineConfig(({ mode }) => ({
  plugins: [react(), ...(mode === "demo" ? [viteSingleFile()] : [])],
  server: { proxy: { "/api": "http://localhost:8100" } },
  build: { outDir: mode === "demo" ? "dist-demo" : "dist", chunkSizeWarningLimit: 3000 },
}));
