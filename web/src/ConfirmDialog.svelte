<script>
  // ConfirmDialog is a small, accessible confirmation modal used before a
  // destructive action (delete credential/combo, revoke key, rotate token).
  import { t } from './lib/state.js';

  let { open = false, title, body, confirmLabel, onConfirm, onCancel } = $props();

  function onKeydown(event) {
    if (event.key === 'Escape') onCancel();
  }
</script>

{#if open}
  <div
    class="overlay"
    role="presentation"
    onclick={(e) => e.target === e.currentTarget && onCancel()}
    onkeydown={onKeydown}
  >
    <div class="dialog" role="dialog" aria-modal="true" aria-label={title}>
      <h2>{title}</h2>
      {#if body}<p>{body}</p>{/if}
      <div class="actions">
        <button onclick={onCancel}>{$t('gui.action.cancel')}</button>
        <button class="danger" onclick={onConfirm}>{confirmLabel}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1rem;
  }
  .dialog {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.2rem;
    max-width: 26rem;
    width: 100%;
  }
  h2 {
    margin-top: 0;
    font-size: 1.05rem;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 1rem;
  }
</style>
