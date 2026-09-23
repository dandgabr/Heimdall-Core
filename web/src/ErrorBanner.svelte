<script>
  // ErrorBanner renders a typed error. The message is LOCALISED from the code
  // the server returned (never the server's own sentence): `$t(code, params)`.
  import { t } from './lib/state.js';

  let { error } = $props();

  function codeOf(e) {
    return e && e.code ? e.code : 'error.internal';
  }
  function paramsOf(e) {
    return e && e.params ? e.params : {};
  }
</script>

{#if error}
  <div class="banner" role="alert">
    <span class="code">{codeOf(error)}</span>
    <span>{$t(codeOf(error), paramsOf(error))}</span>
  </div>
{/if}

<style>
  .banner {
    display: flex;
    gap: 0.6rem;
    align-items: baseline;
    background: color-mix(in srgb, var(--err) 15%, var(--panel));
    border: 1px solid var(--err);
    border-radius: var(--radius);
    padding: 0.6rem 0.8rem;
    margin-bottom: 1rem;
  }
  .code {
    font-family: ui-monospace, monospace;
    font-size: 0.75rem;
    color: var(--err);
    white-space: nowrap;
  }
</style>
