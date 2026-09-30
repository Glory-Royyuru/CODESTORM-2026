import { forwardToBackend } from "@/lib/satg/proxy";

/** Same-origin proxy for the SATG backend's `POST /v1/toolcalls`. */
export async function POST(request: Request) {
  return forwardToBackend("/v1/toolcalls", { method: "POST", request });
}
