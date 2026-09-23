<script>
  import { onMount } from 'svelte';
  import { t } from '../lib/state.js';
  import { api } from '../lib/api.js';
  import { useLoader, toError } from '../lib/loader.svelte.js';
  import ErrorBanner from '../ErrorBanner.svelte';
  import ConfirmDialog from '../ConfirmDialog.svelte';

  const loader = useLoader(() => api.clientKeys());
  onMount(loader.reload);

  let label = $state('');
  let error = $state(null);
  let busy = $state(false);
  let pendingRevoke = $state(null);
  // The created key is a ONE-TIME secret held only in component state.
  let created = $state(null);
  let copied = $state(false);

  async function createKey(event) {
    event.preventDefault();
    busy = true;
    error = null;
    try {
      created = await api.createClientKey(label.trim());
      label = '';
      copied = false;
      await loader.reload();
    } catch (e) {
      error = toError(e);
    } finally {
      busy = false;
    }
  }

  async function confirmRevoke() {
    const target = pendingRevoke;
    pendingRevoke = null;
    if (!target) return;
    try {
      await api.revokeClientKey(target.id);
      await loader.reload();
    } catch (e) {
      error = toError(e);
    }
  }

  async function copy() {
    if (!created?.key) return;
    try {
      await navigator.clipboard.writeText(created.key);
      copied = true;
    } catch {
      copied = false;
    }
  }
</script>

<section aria-labelledby="keys-h">
  <header class="head">
    <h2 id="keys-h">{$t('gui.keys.title')}</h2>
    <button onclick={loader.reload} disabled={loader.loading}>{$t('gui.action.refresh')}</button>
  </header>
  <p class="help">{$t('gui.keys.help')}</p>
  <ErrorBanner error={loader.error} />
  <ErrorBanner error={error} />

  <form class="create" onsubmit={createKey}>
    <h3>{$t('gui.keys.create')}</h3>
    <div class="row">
      <div>
        <label for="key-label">{$t('gui.keys.create_label')}</label>
        <input id="key-label" bind:value={label} autocomplete="off" />
      </div>
      <button class="primary" type="submit" disabled={busy}>{$t('gui.keys.create_submit')}</button>
    </div>
  </form>

  {#if created}
    <div class="reveal" role="note">
      <h3>{$t('gui.keys.new')}</h3>
      <p class="muted">{$t('gui.keys.new_help')}</p>
      <pre class="token">{created.key}</pre>
      <button onclick={copy}>{copied ? $t('gui.action.copied') : $t('gui.action.copy')}</button>
    </div>
  {/if}

  {#if loader.loading}
    <p class="muted">{$t('gui.action.loading')}</p>
  {:else if loader.data}
    {#if loader.data.length === 0}
      <p class="muted">{$t('gui.keys.empty')}</p>
    {:else}
      <table>
        <thead>
          <tr>
            <th scope="col">{$t('gui.keys.id')}</th>
            <th scope="col">{$t('gui.keys.label')}</th>
            <th scope="col">{$t('gui.keys.created')}</th>
            <th scope="col">{$t('gui.keys.status')}</th>
            <th scope="col"></th>
          </tr>
        </thead>
        <tbody>
          {#each loader.data as k (k.id)}
            <tr>
              <td><code>{k.id}</code></td>
              <td>{k.label || '—'}</td>
              <td>{k.created_at ? new Date(k.created_at).toLocaleString() : '—'}</td>
              <td>
                {#if k.revoked_at}
                  <span class="off">{$t('gui.keys.revoked_status')}</span>
                  <div class="muted">{new Date(k.revoked_at).toLocaleString()}</div>
                {:else}
                  <span class="ok">{$t('gui.keys.active')}</span>
                {/if}
              </td>
              <td>
                {#if !k.revoked_at}
                  <button class="danger" onclick={() => (pendingRevoke = k)}>{$t('gui.keys.revoke')}</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
</section>

<ConfirmDialog
  open={pendingRevoke !== null}
  title={$t('gui.keys.revoke_confirm')}
  body={$t('gui.keys.revoke_body')}
  confirmLabel={$t('gui.keys.revoke')}
  onConfirm={confirmRevoke}
  onCancel={() => (pendingRevoke = null)}
/>

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
    margin: 0 0 0.6rem;
    font-size: 0.95rem;
  }
  .help {
    color: var(--muted);
    font-size: 0.85rem;
    margin: 0 0 1rem;
  }
  .create {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1rem;
    margin-bottom: 1.2rem;
  }
  .row {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 0.6rem;
    align-items: end;
  }
  .reveal {
    background: var(--panel);
    border: 1px solid var(--warn);
    border-radius: var(--radius);
    padding: 1rem;
    margin-bottom: 1.2rem;
    max-width: 46rem;
  }
  .token {
    word-break: break-all;
    white-space: pre-wrap;
  }
  .ok {
    color: var(--ok);
  }
  .off {
    color: var(--muted);
  }
  .muted {
    color: var(--muted);
    font-size: 0.8rem;
  }
</style>
