<script>
  import { onMount } from 'svelte';
  import { t } from '../lib/state.js';
  import { api } from '../lib/api.js';
  import { useLoader, toError } from '../lib/loader.svelte.js';
  import ErrorBanner from '../ErrorBanner.svelte';

  const loader = useLoader(() => api.providers());
  onMount(loader.reload);

  let testResults = $state({});
  let testBusy = $state({});
  let testError = $state(null);

  async function runTest(id) {
    testBusy = { ...testBusy, [id]: true };
    testError = null;
    try {
      const result = await api.providerTest(id);
      testResults = { ...testResults, [id]: result };
    } catch (e) {
      testError = toError(e);
    } finally {
      testBusy = { ...testBusy, [id]: false };
    }
  }
</script>

<section aria-labelledby="providers-h">
  <header class="head">
    <h2 id="providers-h">{$t('gui.providers.title')}</h2>
    <button onclick={loader.reload} disabled={loader.loading}>{$t('gui.action.refresh')}</button>
  </header>
  <ErrorBanner error={loader.error} />
  <ErrorBanner error={testError} />
  {#if loader.loading}
    <p class="muted">{$t('gui.action.loading')}</p>
  {:else if loader.data}
    <table>
      <thead>
        <tr>
          <th scope="col">{$t('gui.providers.id')}</th>
          <th scope="col">{$t('gui.providers.protocol')}</th>
          <th scope="col">{$t('gui.providers.auth')}</th>
          <th scope="col">{$t('gui.providers.ready')}</th>
          <th scope="col">{$t('gui.providers.reason')}</th>
          <th scope="col"></th>
        </tr>
      </thead>
      <tbody>
        {#each loader.data as p (p.id)}
          <tr>
            <td>
              <code>{p.id}</code>
              {#if p.future}<span class="tag" title={$t('gui.providers.future')}>{$t('gui.providers.future')}</span>{/if}
            </td>
            <td>{p.protocol}</td>
            <td>{(p.auth_modes ?? []).join(', ') || '—'}</td>
            <td>
              <span class:ok={p.ready} class:off={!p.ready}>{p.ready ? $t('gui.action.yes') : $t('gui.action.no')}</span>
            </td>
            <td>
              {#if p.reason_code}<code>{p.reason_code}</code>{/if}
              {#if p.risk_notice}
                <!-- risk_notice is an i18n CODE; its catalog text already
                     carries the "Risk notice:" prefix, so localise it directly. -->
                <div class="risk" role="note">{$t(p.risk_notice)}</div>
              {/if}
              {#if (p.pending_endpoints ?? []).length}
                <div class="muted">{$t('gui.providers.pending')}: {p.pending_endpoints.join(', ')}</div>
              {/if}
            </td>
            <td>
              <button onclick={() => runTest(p.id)} disabled={testBusy[p.id]}>
                {testBusy[p.id] ? $t('gui.providers.testing') : $t('gui.providers.test')}
              </button>
              {#if testResults[p.id]}
                <div class="muted">
                  {$t('gui.providers.test_result', {
                    status: String(testResults[p.id].status),
                    credential: testResults[p.id].credential_id || '—',
                  })}
                </div>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
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
  .ok {
    color: var(--ok);
  }
  .off {
    color: var(--muted);
  }
  .tag {
    margin-left: 0.4rem;
    font-size: 0.7rem;
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0 0.3rem;
  }
  .risk {
    margin-top: 0.4rem;
    font-size: 0.8rem;
    color: var(--warn);
    max-width: 32rem;
  }
  .muted {
    color: var(--muted);
    font-size: 0.8rem;
  }
</style>
