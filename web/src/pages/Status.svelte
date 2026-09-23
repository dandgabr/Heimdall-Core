<script>
  import { onMount } from 'svelte';
  import { t } from '../lib/state.js';
  import { api } from '../lib/api.js';
  import { useLoader } from '../lib/loader.svelte.js';
  import ErrorBanner from '../ErrorBanner.svelte';

  const loader = useLoader(() => api.status());
  onMount(loader.reload);

  function uptime(seconds) {
    const s = Number(seconds) || 0;
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${sec}s`;
    return `${sec}s`;
  }
</script>

<section aria-labelledby="status-h">
  <header class="head">
    <h2 id="status-h">{$t('gui.status.title')}</h2>
    <button onclick={loader.reload} disabled={loader.loading}>{$t('gui.action.refresh')}</button>
  </header>
  <ErrorBanner error={loader.error} />
  {#if loader.loading}
    <p class="muted">{$t('gui.action.loading')}</p>
  {:else if loader.data}
    <div class="grid">
      <div class="card"><span class="label">{$t('gui.status.version')}</span><strong>{loader.data.version}</strong></div>
      <div class="card"><span class="label">{$t('gui.status.uptime')}</span><strong>{uptime(loader.data.uptime_seconds)}</strong></div>
      <div class="card"><span class="label">{$t('gui.status.providers')}</span><strong>{loader.data.providers}</strong></div>
      <div class="card"><span class="label">{$t('gui.status.combos')}</span><strong>{loader.data.combos}</strong></div>
      <div class="card"><span class="label">{$t('gui.status.credentials')}</span><strong>{loader.data.credentials}</strong></div>
      <div class="card"><span class="label">{$t('gui.status.client_keys')}</span><strong>{loader.data.client_keys}</strong></div>
    </div>
    <div class="gates">
      <span class="label">{$t('gui.status.gates')}</span>
      <ul>
        {#each loader.data.gates ?? [] as g (g)}<li><code>{g}</code></li>{/each}
      </ul>
    </div>
  {/if}
</section>

<style>
  .head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
  }
  h2 {
    margin: 0 0 1rem;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
    gap: 0.8rem;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.9rem;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }
  .card strong {
    font-size: 1.4rem;
  }
  .label {
    color: var(--muted);
    font-size: 0.8rem;
  }
  .gates {
    margin-top: 1.2rem;
  }
  .gates ul {
    list-style: none;
    padding: 0;
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
  }
  .gates li {
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.2rem 0.5rem;
  }
  .muted {
    color: var(--muted);
  }
</style>
