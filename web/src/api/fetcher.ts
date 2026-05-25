/**
 * Shared fetcher used by orval-generated hooks AND by the hand-rolled
 * fallback client (`./client.ts`). The dev token comes from the env so
 * we don't ship it in JS bundles.
 */

const BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "/api";

function authHeader(): Record<string, string> {
  // In dev the token is hard-coded; production swaps this for an OIDC flow.
  const token =
    (import.meta.env.VITE_IPPON_DEV_TOKEN as string | undefined) ??
    "dev-token-replace-me";
  return { Authorization: `Bearer ${token}` };
}

export interface FetcherOptions extends Omit<RequestInit, "body"> {
  url: string;
  params?: Record<string, string | number | undefined | null>;
  data?: unknown;
}

function buildUrl(url: string, params: FetcherOptions["params"]): string {
  const u = new URL(url, BASE_URL.startsWith("http") ? BASE_URL : window.location.origin + BASE_URL);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v != null) u.searchParams.set(k, String(v));
    }
  }
  return u.toString();
}

export async function fetcher<T>(options: FetcherOptions): Promise<T> {
  const url = buildUrl(options.url, options.params);
  const init: RequestInit = {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...authHeader(),
      ...(options.headers ?? {}),
    },
    body: options.data !== undefined ? JSON.stringify(options.data) : undefined,
  };
  const r = await fetch(url, init);
  if (!r.ok) {
    const text = await r.text();
    throw new Error(`${r.status} ${r.statusText}: ${text}`);
  }
  return (await r.json()) as T;
}

export default fetcher;
