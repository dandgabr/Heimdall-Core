<script>
  import { onMount } from 'svelte';
  import { t } from '../lib/state.js';
  import { api } from '../lib/api.js';
  import { useLoader, toError } from '../lib/loader.svelte.js';
  import ErrorBanner from '../ErrorBanner.svelte';
  import ConfirmDialog from '../ConfirmDialog.svelte';

  const STRATEGIES = [
    'fallback',
    'priority',
    'round_robin',
    'weighted',
    'fill_first',
    'cost',
    'p2c',
    'fusion',
    'pipeline',
    'auto',
  ];

  const loader = useLoader(() => api.combos());
  onMount(loader.reload);

  let name = $state('');
  let strategy = $state(STRATEGIES[0]);
  let stepsText = $state('{"kind":"model","ref":"gpt-4o-mini"}');
  let formError = $state(null);
  let busy = $state(false);
  let pendingDelete = $state(null);

  function parseSteps() {
    return stepsText
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  }

  async function createCombo(event) {
    event.preventDefault();
    if (!name.trim()) return;
    busy = true;
    formError = null;
    let steps;
    try {
      steps = parseSteps();
    } catch {
      formError = { code: 'gui.combos.invalid_json', params: {} };
      busy = false;
      return;
    }
    try {
      // The server validates the DAG on save; a cyclic/invalid combo comes back
      // as a typed route.* error which we localise by its code.
      await api.createCombo({ name: name.trim(), strategy, steps });
      name = '';
      stepsText = '';
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
      await api.deleteCombo(target.name);
      await loader.reload();
    } catch (e) {
      formError = toError(e);
    }
  }

  function stepsSummary(steps) {
    return (steps ?? []).map((s) => `${s.kind}:${s.ref}${s.weight ? ` (${s.weight})` : ''}`).join(' → ');
  }
</script>

<section aria-labelledby="combos-h">
  <header class="head">
    <h2 id="combos-h">{$t('gui.combos.title')}</h2>
    <button onclick={loader.reload} disabled={loader.loading}>{$t('gui.action.refresh')}</button>
  </header>
  <ErrorBanner error={loader.error} />
  <ErrorBanner error={formError} />

  <form class="add" onsubmit={createCombo}>
    <h3>{$t('gui.combos.create')}</h3>
    <div class="row">
      <div>
        <label for="combo-name">{$t('gui.combos.name')}</label>
        <input id="combo-name" bind:value={name} autocomplete="off" />
      </div>
      <div>
        <label for="combo-strategy">{$t('gui.combos.strategy_label')}</label>
        <select id="combo-strategy" bind:value={strategy}>
          {#each STRATEGIES as s (s)}<option value={s}>{s}</option>{/each}
        </select>
      </div>
    </div>
    <label for="combo-steps">{$t('gui.combos.steps_label')}</label>
    <textarea id="combo-steps" rows="3" bind:value={stepsText}></textarea>
    <button class="primary" type="submit" disabled={busy}>{$t('gui.combos.create_submit')}</button>
  </form>

  {#if loader.loading}
    <p class="muted">{$t('gui.action.loading')}</p>
  {:else if loader.data}
    {#if loader.data.length === 0}
      <p class="muted">{$t('gui.combos.empty')}</p>
    {:else}
      <table>
        <thead>
          <tr>
            <th scope="col">{$t('gui.combos.name')}</th>
            <th scope="col">{$t('gui.combos.strategy')}</th>
            <th scope="col">{$t('gui.combos.depth')}</th>
            <th scope="col">{$t('gui.combos.steps')}</th>
            <th scope="col"></th>
          </tr>
        </thead>
        <tbody>
          {#each loader.data as c (c.name)}
            <tr>
              <td><code>{c.name}</code></td>
              <td>{c.strategy}</td>
              <td>{c.depth}</td>
              <td><code class="steps">{stepsSummary(c.steps)}</code></td>
              <td><button class="danger" onclick={() => (pendingDelete = c)}>{$t('gui.combos.delete')}</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
</section>

<ConfirmDialog
  open={pendingDelete !== null}
  title={$t('gui.combos.delete_confirm')}
  body={$t('gui.combos.delete_body')}
  confirmLabel={$t('gui.combos.delete')}
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
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.6rem;
  }
  @media (max-width: 720px) {
    .row {
      grid-template-columns: 1fr;
    }
  }
  .steps {
    word-break: break-word;
  }
  .muted {
    color: var(--muted);
  }
</style>
