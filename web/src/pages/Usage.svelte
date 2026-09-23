<script>
  import { onMount } from 'svelte';
  import { t } from '../lib/state.js';
  import { api } from '../lib/api.js';
  import { useLoader } from '../lib/loader.svelte.js';
  import ErrorBanner from '../ErrorBanner.svelte';

  const loader = useLoader(() => api.usage());
  onMount(loader.reload);
</script>

{#snippet aggTable(rows, keyHead)}
  {#if (rows ?? []).length === 0}
    <p class="muted">{$t('gui.usage.empty')}</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th scope="col">{keyHead}</th>
          <th scope="col">{$t('gui.usage.requests')}</th>
          <th scope="col">{$t('gui.usage.attempts')}</th>
          <th scope="col">{$t('gui.usage.tokens')}</th>
          <th scope="col">{$t('gui.usage.cost')}</th>
        </tr>
      </thead>
      <tbody>
        {#each rows as r (r.key)}
          <tr>
            <td><code>{r.key}</code></td>
            <td>{r.requests}</td>
            <td>{r.attempts}</td>
            <td>{r.tokens}</td>
            <td>{r.cost_micros}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
{/snippet}

<section aria-labelledby="usage-h">
  <header class="head">
    <h2 id="usage-h">{$t('gui.usage.title')}</h2>
    <button onclick={loader.reload} disabled={loader.loading}>{$t('gui.action.refresh')}</button>
  </header>
  <ErrorBanner error={loader.error} />
  {#if loader.loading}
    <p class="muted">{$t('gui.action.loading')}</p>
  {:else if loader.data}
    <h3>{$t('gui.usage.total')}</h3>
    <div class="total">
      <div class="card"><span class="label">{$t('gui.usage.requests')}</span><strong>{loader.data.total.requests}</strong></div>
      <div class="card"><span class="label">{$t('gui.usage.attempts')}</span><strong>{loader.data.total.attempts}</strong></div>
      <div class="card"><span class="label">{$t('gui.usage.tokens')}</span><strong>{loader.data.total.tokens}</strong></div>
      <div class="card"><span class="label">{$t('gui.usage.cost')}</span><strong>{loader.data.total.cost_micros}</strong></div>
    </div>
    <h3>{$t('gui.usage.by_provider')}</h3>
    {@render aggTable(loader.data.by_provider, $t('gui.usage.key'))}
    <h3>{$t('gui.usage.by_credential')}</h3>
    {@render aggTable(loader.data.by_credential, $t('gui.usage.key'))}
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
  h3 {
    margin: 1.2rem 0 0.5rem;
    font-size: 0.95rem;
  }
  .total {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr));
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
    font-size: 1.3rem;
  }
  .label {
    color: var(--muted);
    font-size: 0.8rem;
  }
  .muted {
    color: var(--muted);
  }
</style>
