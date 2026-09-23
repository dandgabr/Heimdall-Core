<script>
  import { onMount } from 'svelte';
  import { t } from '../lib/state.js';
  import { api } from '../lib/api.js';
  import { useLoader } from '../lib/loader.svelte.js';
  import ErrorBanner from '../ErrorBanner.svelte';

  const loader = useLoader(() => api.quotas());
  onMount(loader.reload);

  function pct(w) {
    const limit = Number(w.limit) || 0;
    if (limit <= 0) return 0;
    return Math.min(100, Math.round((Number(w.used) / limit) * 100));
  }

  function limit(w) {
    const value = Number(w.limit) || 0;
    return value > 0 ? value : 1;
  }
</script>

<section aria-labelledby="quotas-h">
  <header class="head">
    <h2 id="quotas-h">{$t('gui.quotas.title')}</h2>
    <button onclick={loader.reload} disabled={loader.loading}>{$t('gui.action.refresh')}</button>
  </header>
  <ErrorBanner error={loader.error} />
  {#if loader.loading}
    <p class="muted">{$t('gui.action.loading')}</p>
  {:else if loader.data}
    {#if loader.data.length === 0}
      <p class="muted">{$t('gui.quotas.empty')}</p>
    {:else}
      {#each loader.data as q (q.credential)}
        <article class="cred">
          <h3>
            <code>{q.credential}</code>
            {#if q.provider}<span class="muted">· {q.provider}</span>{/if}
            {#if q.terminal_code}<span class="terminal"><code>{q.terminal_code}</code></span>{/if}
          </h3>
          {#if (q.windows ?? []).length === 0}
            <p class="muted">{$t('gui.action.none')}</p>
          {:else}
            <table>
              <thead>
                <tr>
                  <th scope="col">{$t('gui.quotas.kind')}</th>
                  <th scope="col">{$t('gui.quotas.used')}</th>
                  <th scope="col">{$t('gui.quotas.limit')}</th>
                  <th scope="col">{$t('gui.quotas.remaining')}</th>
                  <th scope="col">{$t('gui.quotas.resets')}</th>
                  <th scope="col">{$t('gui.quotas.source')}</th>
                </tr>
              </thead>
              <tbody>
                {#each q.windows as w, i (q.credential + '-' + i)}
                  <tr>
                    <td>{w.kind}</td>
                    <td>
                      {w.used}
                      <!-- A native progress bar avoids an inline style attribute,
                           which a strict `style-src 'self'` CSP would block. -->
                      <progress max={limit(w)} value={Number(w.used) || 0} aria-label={w.kind}>
                        {pct(w)}%
                      </progress>
                    </td>
                    <td>{w.limit}</td>
                    <td>{w.remaining}</td>
                    <td>{w.resets_at ? new Date(w.resets_at).toLocaleString() : '—'}</td>
                    <td>{w.source}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </article>
      {/each}
    {/if}
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
  .cred {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1rem;
    margin-bottom: 1rem;
  }
  .cred h3 {
    margin: 0 0 0.6rem;
    font-size: 0.95rem;
  }
  .terminal {
    margin-left: 0.5rem;
    color: var(--warn);
  }
  progress {
    display: block;
    width: 8rem;
    height: 0.4rem;
    margin-top: 0.3rem;
  }
  .muted {
    color: var(--muted);
  }
</style>
