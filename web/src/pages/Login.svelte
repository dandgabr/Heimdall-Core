<script>
  // Login captures the management token. It verifies it against GET
  // /api/mgmt/status before admitting the operator, so a wrong token fails
  // here with the server's typed error rather than on the first page load.
  import { t } from '../lib/state.js';
  import { api, ApiError, setToken, hasToken } from '../lib/api.js';
  import { authenticated } from '../lib/state.js';
  import ErrorBanner from '../ErrorBanner.svelte';

  let { authError = null } = $props();
  let value = $state('');
  let localError = $state(null);
  // Prefer a failure from this form; fall back to the boot-time probe error.
  let error = $derived(localError ?? authError);
  let busy = $state(false);

  async function submit(event) {
    event.preventDefault();
    if (!value.trim()) return;
    busy = true;
    localError = null;
    const previous = hasToken();
    setToken(value.trim());
    try {
      await api.status();
      authenticated.set(true);
    } catch (e) {
      localError = e instanceof ApiError ? e : { code: 'error.internal', params: {} };
      if (!previous) setToken(null);
      authenticated.set(false);
    } finally {
      busy = false;
    }
  }
</script>

<main class="login">
  <form onsubmit={submit}>
    <h1>{$t('gui.app.title')}</h1>
    <p class="muted">{$t('gui.app.subtitle')}</p>
    <h2>{$t('gui.login.title')}</h2>
    <p class="help">{$t('gui.login.help')}</p>
    <ErrorBanner error={error} />
    <label for="token">{$t('gui.login.placeholder')}</label>
    <input
      id="token"
      type="password"
      autocomplete="off"
      bind:value
      placeholder={$t('gui.login.placeholder')}
    />
    <button class="primary" type="submit" disabled={busy}>{$t('gui.login.submit')}</button>
  </form>
</main>

<style>
  .login {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 1rem;
  }
  form {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.5rem;
    width: 100%;
    max-width: 26rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  h1 {
    margin: 0;
    font-size: 1.3rem;
  }
  h2 {
    margin: 0.8rem 0 0;
    font-size: 1rem;
  }
  .muted,
  .help {
    color: var(--muted);
    margin: 0;
    font-size: 0.85rem;
  }
  button {
    margin-top: 0.5rem;
  }
</style>
