<script>
  import { onMount } from 'svelte';
  import { t } from '../lib/state.js';
  import { api } from '../lib/api.js';
  import { useLoader } from '../lib/loader.svelte.js';
  import ErrorBanner from '../ErrorBanner.svelte';

  const loader = useLoader(() => api.gates());
  onMount(loader.reload);

  const STAGES = [
    { key: 'pre_request', label: 'gui.gates.pre_request' },
    { key: 'on_response_chunk', label: 'gui.gates.on_response_chunk' },
    { key: 'post_response', label: 'gui.gates.post_response' },
  ];
</script>

<section aria-labelledby="gates-h">
  <header class="head">
    <h2 id="gates-h">{$t('gui.gates.title')}</h2>
    <button onclick={loader.reload} disabled={loader.loading}>{$t('gui.action.refresh')}</button>
  </header>
  <p class="help">{$t('gui.gates.order_help')}</p>
  <ErrorBanner error={loader.error} />
  {#if loader.loading}
    <p class="muted">{$t('gui.action.loading')}</p>
  {:else if loader.data}
    {#each STAGES as stage (stage.key)}
      <h3>{$t(stage.label)}</h3>
      {#if (loader.data[stage.key] ?? []).length === 0}
        <p class="muted">{$t('gui.gates.empty')}</p>
      {:else}
        <table>
          <thead>
            <tr>
              <th scope="col">{$t('gui.gates.id')}</th>
              <th scope="col">{$t('gui.gates.stages')}</th>
              <th scope="col">{$t('gui.gates.policy')}</th>
              <th scope="col">{$t('gui.gates.caps')}</th>
            </tr>
          </thead>
          <tbody>
            {#each loader.data[stage.key] as g (g.id)}
              <tr>
                <td><code>{g.id}</code></td>
                <td>{(g.stages ?? []).join(', ')}</td>
                <td>{g.failure_policy}</td>
                <td>{g.required_caps}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    {/each}
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
    margin: 0 0 0.4rem;
  }
  h3 {
    margin: 1.2rem 0 0.5rem;
    font-size: 0.95rem;
  }
  .help {
    color: var(--muted);
    font-size: 0.85rem;
    margin: 0 0 1rem;
  }
  .muted {
    color: var(--muted);
  }
</style>
