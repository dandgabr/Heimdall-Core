<script>
  import { onMount } from 'svelte';
  import { t } from '../lib/state.js';
  import { api } from '../lib/api.js';
  import { useLoader, toError } from '../lib/loader.svelte.js';
  import ErrorBanner from '../ErrorBanner.svelte';
  import ConfirmDialog from '../ConfirmDialog.svelte';

  const loader = useLoader(() => api.credentials());
  onMount(loader.reload);

  let provider = $state('');
  let label = $state('');
  let key = $state('');
  let formError = $state(null);
  let busy = $state(false);
  let pendingDelete = $state(null);

  async function addKey(event) {
    event.preventDefault();
    if (!provider.trim() || !key.trim()) return;
    busy = true;
    formError = null;
    try {
      // The plaintext key lives only in this local variable for the request; it
      // is never written to storage and is cleared immediately after the POST.
      await api.addCredential(provider.trim(), label.trim(), key.trim());
      key = '';
      label = '';
      provider = '';
      await loader.reload();
    } catch (e) {
      formError = toError(e);
    } finally {
      busy = false;
    }
  }

  async function confirmDelete() {
    const target = pendingDelete;
    pendingDelete = null;
    if (!target) return;
    try {
      await api.deleteCredential(target.id);
      await loader.reload();
    } catch (e) {
      formError = toError(e);
    }
  }
</script>

<section aria-labelledby="creds-h">
  <header class="head">
    <h2 id="creds-h">{$t('gui.credentials.title')}</h2>
    <button onclick={loader.reload} disabled={loader.loading}>{$t('gui.action.refresh')}</button>
  </header>
  <ErrorBanner error={loader.error} />
  <ErrorBanner error={formError} />

  <form class="add" onsubmit={addKey}>
    <h3>{$t('gui.credentials.add')}</h3>
    <div class="row">
      <div>
        <label for="c-provider">{$t('gui.credentials.add_provider')}</label>
        <input id="c-provider" bind:value={provider} autocomplete="off" />
      </div>
      <div>
        <label for="c-label">{$t('gui.credentials.add_label')}</label>
        <input id="c-label" bind:value={label} autocomplete="off" />
      </div>
      <div>
        <label for="c-key">{$t('gui.credentials.add_key')}</label>
        <input id="c-key" type="password" bind:value={key} autocomplete="off" />
      </div>
      <button class="primary" type="submit" disabled={busy}>{$t('gui.credentials.add_submit')}</button>
    </div>
    <p class="muted">{$t('gui.credentials.add_key_help')}</p>
  </form>

  {#if loader.loading}
    <p class="muted">{$t('gui.action.loading')}</p>
  {:else if loader.data}
    {#if loader.data.length === 0}
      <p class="muted">{$t('gui.credentials.empty')}</p>
    {:else}
      <table>
        <thead>
          <tr>
            <th scope="col">{$t('gui.credentials.id')}</th>
            <th scope="col">{$t('gui.credentials.provider')}</th>
            <th scope="col">{$t('gui.credentials.mode')}</th>
            <th scope="col">{$t('gui.credentials.label')}</th>
            <th scope="col">{$t('gui.credentials.created')}</th>
            <th scope="col"></th>
          </tr>
        </thead>
        <tbody>
          {#each loader.data as c (c.id)}
            <tr>
              <td><code>{c.id}</code></td>
              <td>{c.provider}</td>
              <td>{c.auth_mode}</td>
              <td>{c.label || '—'}</td>
              <td>{c.created_at ? new Date(c.created_at).toLocaleString() : '—'}</td>
              <td>
                <button class="danger" onclick={() => (pendingDelete = c)}>{$t('gui.credentials.delete')}</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
</section>

<ConfirmDialog
  open={pendingDelete !== null}
  title={$t('gui.credentials.delete_confirm')}
  body={$t('gui.credentials.delete_body')}
  confirmLabel={$t('gui.credentials.delete')}
  onConfirm={confirmDelete}
  onCancel={() => (pendingDelete = null)}
/>

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
    margin: 0 0 0.6rem;
    font-size: 0.95rem;
  }
  .add {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1rem;
    margin-bottom: 1.2rem;
  }
  .row {
    display: grid;
    grid-template-columns: 1fr 1fr 2fr auto;
    gap: 0.6rem;
    align-items: end;
  }
  @media (max-width: 720px) {
    .row {
      grid-template-columns: 1fr;
    }
  }
  .muted {
    color: var(--muted);
    font-size: 0.8rem;
    margin: 0.5rem 0 0;
  }
</style>
