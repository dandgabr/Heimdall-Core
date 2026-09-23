import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

// Minimal Svelte 5 config. vitePreprocess lets a component use TypeScript or
// preprocessor syntax later without a config change; today the SPA is plain JS.
export default {
  preprocess: vitePreprocess(),
};
