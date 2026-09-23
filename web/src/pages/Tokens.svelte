<script>
  import { t } from '../lib/state.js';
  import { api } from '../lib/api.js';
  import { toError } from '../lib/loader.svelte.js';
  import { login } from '../lib/state.js';
  import ErrorBanner from '../ErrorBanner.svelte';
  import ConfirmDialog from '../ConfirmDialog.svelte';

  // The rotated token is a ONE-TIME secret: held in local component state only
  // until the page is left. It is never persisted (not even sessionStorage) by
  // this page; "adopt" is the explicit operator action that swaps the session.
  let rotated = $state(null);
  let error = $state(null);
  let busy = $state(false);
  let confirmOpen = $state(false);
  let copied = $state(false);

  async function rotate() {
    confirmOpen = false;
    busy = true;
    error = null;
    try {
      rotated = await api.rotateToken();
      copied = false;
    } catch (e) {
      error = toError(e);
    } finally {
      busy = false;
    }
  }

  async function copy() {
    if (!rotated?.token) return;
    try {
      await navigator.clipboard.writeText(rotated.token);
      copied = true;
    } catch {
      copied = false;
    }
  }
</script>

<section aria-labelledby="tokens-h">
  <h2 id="tokens-h">{$t('gui.tokens.title')}</h2>
  <p class="help">{$t('gui.tokens.help')}</p>
  <ErrorBanner error={error} />

  <button class="danger" onclick={() => (confirmOpen = true)} disabled={busy}>
    {$t('gui.tokens.rotate')}
  </button>

  {#if rotated}
    <div class="reveal" role="note">
      <h3>{$t('gui.tokens.new')}</h3>
      <p class="muted">{$t('gui.tokens.new_help')}</p>
      <pre class="token">{rotated.token}</pre>
      <div class="actions">
        <button onclick={copy}>{copied ? $t('gui.action.copied') : $t('gui.action.copy')}</button>
        <button class="primary" onclick={() => login(rotated.token)}>{$t('gui.tokens.adopt')}</button>
      </div>
      <p class="muted">{$t('gui.tokens.path')}: <code>{rotated.path}</code></p>
    </div>
  {/if}
</section>

<ConfirmDialog
  open={confirmOpen}
  title={$t('gui.tokens.rotate_confirm')}
  body={$t('gui.tokens.rotate_body')}
  confirmLabel={$t('gui.tokens.rotate')}
  onConfirm={rotate}
  onCancel={() => (confirmOpen = false)}
/>

<style>
  h2 {
    margin: 0 0 0.4rem;
  }
  .help {
    color: var(--muted);
    font-size: 0.85rem;
    margin: 0 0 1rem;
    max-width: 46rem;
  }
  .reveal {
    margin-top: 1.2rem;
    background: var(--panel);
    border: 1px solid var(--warn);
    border-radius: var(--radius);
    padding: 1rem;
    max-width: 46rem;
  }
  .reveal h3 {
    margin: 0 0 0.4rem;
    font-size: 0.95rem;
  }
  .token {
    word-break: break-all;
    white-space: pre-wrap;
  }
  .actions {
    display: flex;
    gap: 0.5rem;
    margin: 0.6rem 0;
  }
  .muted {
    color: var(--muted);
    font-size: 0.8rem;
  }
</style>
