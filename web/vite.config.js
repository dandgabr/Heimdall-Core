import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { fileURLToPath } from 'node:url';

// The build lands directly in the package the Go binary embeds. `go build`
// therefore needs no Node: the committed dist/ is what //go:embed sees, and
// `make web` (or `pnpm build` here) regenerates it from source.
const outDir = fileURLToPath(new URL('../internal/webui/dist', import.meta.url));

export default defineConfig({
  // The SPA is mounted under /web/ by the Go server, so every asset URL it
  // emits is prefixed accordingly. index.html is served for client routes by
  // the webui handler's SPA fallback.
  base: '/web/',
  plugins: [svelte()],
  build: {
    outDir,
    emptyOutDir: true,
    sourcemap: false,
    assetsDir: 'assets',
    // A hashed bundle is the cache-immutable asset set; index.html stays
    // no-store at the handler.
    rollupOptions: {
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
});
