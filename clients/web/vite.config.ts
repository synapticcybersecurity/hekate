import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// The SPA is served by `hekate-server` at TWO mount points (/web/* and
// /send/*). With `base: "./"`, every asset URL emitted into index.html
// is relative, so the same dist/ directory works under both prefixes
// without rebuilding. The WASM module lives in `public/wasm/` and is
// loaded at runtime against `location.pathname` (see src/wasm.ts).
export default defineConfig({
  base: "./",
  plugins: [solid()],
  build: {
    target: "es2022",
    sourcemap: true,
    // Don't inline anything — keeps wasm + worker assets as separate
    // files the server can serve with proper MIME types and caching.
    assetsInlineLimit: 0,
  },
  server: {
    port: 5173,
    strictPort: true,
  },
});
