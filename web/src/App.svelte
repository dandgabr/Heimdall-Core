<script>
  import { onMount } from 'svelte';
  import { locale, t, LANGUAGES, setLanguage, authenticated, logout } from './lib/state.js';
  import { page, startRouter, navigate, PAGES } from './lib/router.js';
  import { hasToken, api } from './lib/api.js';
  import ErrorBanner from './ErrorBanner.svelte';
  import Login from './pages/Login.svelte';
  import Status from './pages/Status.svelte';
  import Providers from './pages/Providers.svelte';
  import Credentials from './pages/Credentials.svelte';
  import Combos from './pages/Combos.svelte';
  import Quotas from './pages/Quotas.svelte';
  import Gates from './pages/Gates.svelte';
  import Usage from './pages/Usage.svelte';
  import Tokens from './pages/Tokens.svelte';
  import ClientKeys from './pages/ClientKeys.svelte';

  onMount(startRouter);

  let authError = $state(null);

  const PAGES_MAP = { status: Status, providers: Providers, credentials: Credentials, combos: Combos, quotas: Quotas, gates: Gates, usage: Usage, tokens: Tokens, 'client-keys': ClientKeys };

  // Verify the session token once at boot: a stale sessionStorage token from a
  // previous rotation must fall back to the login screen, not show empty pages.
  onMount(async () => {
    if (!hasToken()) return;
    try {
      await api.status();
      authenticated.set(true);
    } catch (e) {
      authError = e;
      logout();
    }
  });
</script>

{#if !$authenticated}
  <Login {authError} />
{:else}
  <div class="shell">
    <aside aria-label="{$t('gui.app.title')}">
      <div class="brand">
        <h1>{$t('gui.app.title')}</h1>
        <p class="muted">{$t('gui.app.subtitle')}</p>
      </div>
      <nav>
        {#each PAGES as p (p.id)}
          <button
            class="nav-link"
            class:active={$page === p.id}
            aria-current={$page === p.id ? 'page' : undefined}
            onclick={() => navigate(p.id)}
          >
            {$t(`gui.nav.${p.id}`)}
          </button>
        {/each}
      </nav>
      <div class="foot">
        <label for="lang">{$t('gui.lang.label')}</label>
        <select id="lang" value={$locale} onchange={(e) => setLanguage(e.currentTarget.value)}>
          {#each LANGUAGES as l (l.tag)}
            <option value={l.tag}>{l.label}</option>
          {/each}
        </select>
        <button class="signout" onclick={() => { logout(); }}>{$t('gui.logout')}</button>
      </div>
    </aside>
    <main>
      <ErrorBanner error={authError} />
      {#if $page === 'status'}<Status />{/if}
      {#if $page === 'providers'}<Providers />{/if}
      {#if $page === 'credentials'}<Credentials />{/if}
      {#if $page === 'combos'}<Combos />{/if}
      {#if $page === 'quotas'}<Quotas />{/if}
      {#if $page === 'gates'}<Gates />{/if}
      {#if $page === 'usage'}<Usage />{/if}
      {#if $page === 'tokens'}<Tokens />{/if}
      {#if $page === 'client-keys'}<ClientKeys />{/if}
    </main>
  </div>
{/if}

<style>
  .shell {
    display: grid;
    grid-template-columns: 15rem 1fr;
    min-height: 100vh;
  }
  aside {
    background: var(--panel);
    border-right: 1px solid var(--border);
    padding: 1.2rem 1rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .brand h1 {
    margin: 0;
    font-size: 1.15rem;
  }
  .muted {
    margin: 0.2rem 0 0;
    color: var(--muted);
    font-size: 0.8rem;
  }
  nav {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }
  .nav-link {
    text-align: left;
    background: transparent;
    border: 1px solid transparent;
  }
  .nav-link:hover {
    background: var(--panel-2);
  }
  .nav-link.active {
    background: var(--panel-2);
    border-color: var(--accent);
  }
  .foot {
    margin-top: auto;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  main {
    padding: 1.5rem 2rem;
    max-width: 72rem;
  }
  @media (max-width: 720px) {
    .shell {
      grid-template-columns: 1fr;
    }
    aside {
      border-right: none;
      border-bottom: 1px solid var(--border);
    }
    nav {
      flex-direction: row;
      flex-wrap: wrap;
    }
  }
</style>
