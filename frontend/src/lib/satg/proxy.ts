/**
 * Server-side forwarding to the FastAPI SATG backend. Imported only by the
 * route handlers in `src/app/api/satg/` — never by client components.
 *
 * The browser talks only to this Next.js app (same origin, no CORS). The
 * route handlers under `src/app/api/satg/` forward to the backend and never
 * interpret, alter or synthesize a verdict: the backend's status code and
 * body are returned unchanged. When the backend cannot be reached, the
 * response carries the `x-satg-proxy-error` header and no verdict, so the
 * client can never mistake a transport failure for a security decision.
 */

const DEFAULT_BACKEND_URL = "http://127.0.0.1:8000";
// Must cover the backend's worst normal path with the default settings:
// DNS pin 2 s + ML_TIMEOUT_SECONDS 3 s + SANDBOX_TIMEOUT 10 s (container
// start included) + container clean-up and margin. Raise it with those.
// The client's own timeout (client.ts) is longer, so this 504 reaches it.
const TIMEOUT_MS = 25_000;
// Resource guard for the proxy itself. The backend's own 64 KiB ingress limit
// (INGRESS-003) is stricter and stays authoritative; bodies between 64 KiB and
// this cap are forwarded so the backend can reject and audit them.
const MAX_FORWARD_BYTES = 1024 * 1024;

export type ProxyErrorCode = "BACKEND_UNREACHABLE" | "BACKEND_TIMEOUT" | "BACKEND_MISCONFIGURED" | "PROXY_BODY_TOO_LARGE" | "AUDIT_NOT_CONFIGURED";

/** Query parameters the audit route forwards (backend/app/audit/api.py). Everything else is dropped. */
export const AUDIT_QUERY_PARAMS = ["limit", "before_seq", "verdict", "rule_id", "tool", "agent_id", "request_id"] as const;
// The backend validates each value (identifiers are at most 128 characters); this only bounds the URL.
const MAX_AUDIT_QUERY_VALUE = 256;

function backendBaseUrl(): URL | null {
  try {
    const url = new URL(process.env.SATG_BACKEND_URL || DEFAULT_BACKEND_URL);
    return url.protocol === "http:" || url.protocol === "https:" ? url : null;
  } catch {
    return null;
  }
}

function proxyError(status: number, code: ProxyErrorCode, message: string): Response {
  return Response.json({ proxy_error: { code, message } }, { status, headers: { "x-satg-proxy-error": code, "cache-control": "no-store" } });
}

/** Forward one request to `path` on the backend and relay its response as-is. */
export async function forwardToBackend(path: "/health" | "/v1/toolcalls", init: { method: "GET" | "POST"; request?: Request }): Promise<Response> {
  const base = backendBaseUrl();
  if (!base) return proxyError(500, "BACKEND_MISCONFIGURED", "SATG_BACKEND_URL is not a valid http(s) URL");

  const headers = new Headers({ accept: "application/json" });
  let body: ArrayBuffer | undefined;
  if (init.request) {
    // Forward the exact bytes and Content-Type the client sent, so the
    // backend's strict ingress (content type, UTF-8, duplicate keys, depth,
    // NaN, size) judges the real request, not a re-serialized copy.
    const declared = Number(init.request.headers.get("content-length") ?? 0);
    if (declared > MAX_FORWARD_BYTES) return proxyError(413, "PROXY_BODY_TOO_LARGE", "Request body is too large to forward");
    body = await init.request.arrayBuffer();
    if (body.byteLength > MAX_FORWARD_BYTES) return proxyError(413, "PROXY_BODY_TOO_LARGE", "Request body is too large to forward");
    const contentType = init.request.headers.get("content-type");
    if (contentType !== null) headers.set("content-type", contentType);
  }

  return relay(new URL(path, base), { method: init.method, headers, body });
}

/** Keep only the audit query parameters the backend understands, first value each, bounded in length. */
export function pickAuditQuery(search: URLSearchParams): URLSearchParams {
  const picked = new URLSearchParams();
  for (const name of AUDIT_QUERY_PARAMS) {
    const value = search.get(name);
    if (value !== null && value !== "" && value.length <= MAX_AUDIT_QUERY_VALUE) picked.set(name, value);
  }
  return picked;
}

/**
 * Forward `GET /v1/audit/events` with the operator token, which lives only in
 * this server's environment (SATG_AUDIT_API_TOKEN): the browser never sends or
 * receives it. Only the known query parameters are forwarded.
 */
export async function forwardAuditEvents(search: URLSearchParams): Promise<Response> {
  const base = backendBaseUrl();
  if (!base) return proxyError(500, "BACKEND_MISCONFIGURED", "SATG_BACKEND_URL is not a valid http(s) URL");
  const token = process.env.SATG_AUDIT_API_TOKEN?.trim();
  if (!token) return proxyError(503, "AUDIT_NOT_CONFIGURED", "SATG_AUDIT_API_TOKEN is not set on the console server");
  const url = new URL("/v1/audit/events", base);
  url.search = pickAuditQuery(search).toString();
  return relay(url, { method: "GET", headers: new Headers({ accept: "application/json", authorization: `Bearer ${token}` }) });
}

/** Send one request to the backend and relay its status, content type and body as-is. */
async function relay(url: URL, init: { method: "GET" | "POST"; headers: Headers; body?: ArrayBuffer }): Promise<Response> {
  let upstream: Response;
  try {
    upstream = await fetch(url, {
      method: init.method,
      headers: init.headers,
      body: init.body,
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "TimeoutError") {
      return proxyError(504, "BACKEND_TIMEOUT", `SATG backend did not respond within ${TIMEOUT_MS / 1000}s`);
    }
    return proxyError(502, "BACKEND_UNREACHABLE", "SATG backend is not reachable");
  }

  const relayed = new Headers({ "cache-control": "no-store" });
  const upstreamType = upstream.headers.get("content-type");
  if (upstreamType !== null) relayed.set("content-type", upstreamType);
  return new Response(await upstream.arrayBuffer(), { status: upstream.status, headers: relayed });
}
