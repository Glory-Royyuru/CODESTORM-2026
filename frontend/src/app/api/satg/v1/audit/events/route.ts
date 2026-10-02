import { forwardAuditEvents } from "@/lib/satg/proxy";

/** Same-origin proxy for the backend's read-only `GET /v1/audit/events`. The operator token is added server-side. */
export async function GET(request: Request) {
  return forwardAuditEvents(new URL(request.url).searchParams);
}
