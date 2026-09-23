// Shared async-page plumbing (runes module): load a resource and surface a
// typed error the page localises. Kept as a factory so each page owns its own
// reactive state.
import { ApiError } from './api.js';

export function toError(e) {
  return e instanceof ApiError ? e : { code: 'error.internal', params: {} };
}

// useLoader takes a fetcher and returns reactive {data, error, loading, reload}.
export function useLoader(fn) {
  let data = $state(null);
  let error = $state(null);
  let loading = $state(true);

  async function reload() {
    loading = true;
    error = null;
    try {
      data = await fn();
      error = null;
    } catch (e) {
      error = toError(e);
    } finally {
      loading = false;
    }
  }

  return {
    get data() {
      return data;
    },
    get error() {
      return error;
    },
    get loading() {
      return loading;
    },
    reload,
  };
}
