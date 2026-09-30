import { forwardToBackend } from "@/lib/satg/proxy";

/** Same-origin proxy for the SATG backend's `GET /health`. */
export async function GET() {
  return forwardToBackend("/health", { method: "GET" });
}
