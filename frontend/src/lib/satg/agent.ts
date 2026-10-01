/**
 * Agent request translator for the Live Gateway's agent console.
 *
 * Turns one natural-language instruction into ONE structured tool call for a
 * tool the backend actually registers (backend/app/gateway/registry.py), and
 * serializes it as a POST /v1/toolcalls body. It decides nothing and executes
 * nothing: the body is sent with `submitToolCall` (client.ts) and the backend
 * alone returns ALLOW / ESCALATE / BLOCK. Mirrors demo/chat_agent.py.
 */

export type AgentTool = "search_customer" | "send_email" | "fetch_url";

export interface AgentToolCall {
  /** Self-asserted, like every agent_id: SATG has no authentication yet. */
  agentId: string;
  tool: AgentTool;
  parameters: Record<string, string>;
}

/** One finished step of this console session, in the shape the backend's ML context expects. */
export interface AgentStep {
  tool_name: string;
  arguments: Record<string, string>;
  observation: string;
}

// fetch_url is registered for research-bot only; the console uses that identity for URL
// requests instead of widening the registry.
const AGENT_FOR_TOOL: Record<AgentTool, string> = { search_customer: "support-bot-3", send_email: "support-bot-3", fetch_url: "research-bot" };

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/;
const URL_RE = /\bhttps?:\/\/\S+/i;
const CUSTOMER_RE = /\bCUST-\d+\b/i;
export const CUSTOMER_DATA_RE = /\bcustomer (?:information|info|record|records|data|details)\b/i;

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const clean = (s: string) => s.trim().replace(/[.!?]+$/, "").trim().replace(/^["']|["']$/g, "");

function emailBody(text: string, address: string): string {
  const patterns = [
    /\b(?:saying|that says|telling them|with the message|with message|with body)\s+(?:that\s+)?(.+)$/i,
    /\bwith\s+(.+)$/i,
    new RegExp(`\\bsend\\s+(.+?)\\s+to\\s+${escapeRe(address)}`, "i"),
  ];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (!match) continue;
    const body = clean(match[1].replace(address, ""));
    if (body && !/^(?:an?|the)?\s*e-?mail$/i.test(body)) return body[0].toUpperCase() + body.slice(1);
  }
  return "Message from support";
}

function subjectFrom(body: string): string {
  const subject = body.replace(/^(?:that|the)\s+/i, "").split(/\s+/).slice(0, 8).join(" ").slice(0, 60) || "Message from support";
  return subject[0].toUpperCase() + subject.slice(1);
}

/** Deterministic translation; null when the instruction is not a supported request. */
export function parseInstruction(text: string): AgentToolCall | null {
  const lowered = text.toLowerCase();
  const url = text.match(URL_RE);
  const email = text.match(EMAIL_RE);
  const customer = text.match(CUSTOMER_RE);
  let call: Omit<AgentToolCall, "agentId"> | null = null;
  if (email && /\b(?:e-?mail|send|mail|write)\b/.test(lowered)) {
    const to = email[0].replace(/\.$/, "");
    const body = emailBody(text, to);
    call = { tool: "send_email", parameters: { to, subject: subjectFrom(body), body } };
  } else if (url && /\b(?:open|fetch|get|visit|load|browse|download|check)\b/.test(lowered)) {
    call = { tool: "fetch_url", parameters: { url: url[0].replace(/[.,;)]+$/, "") } };
  } else if (customer && (/\b(?:find|look\s*up|lookup|search|show|get)\b/.test(lowered) || lowered.includes("customer"))) {
    call = { tool: "search_customer", parameters: { customer_id: customer[0].toUpperCase() } };
  }
  return call ? { ...call, agentId: AGENT_FOR_TOOL[call.tool] } : null;
}

/** The exact JSON body sent to POST /v1/toolcalls. `context` is untrusted input for the ML layer only. */
export function buildRequestBody(call: AgentToolCall, task: string, previousSteps: AgentStep[], observation: string | null): string {
  const context: Record<string, unknown> = { task, previous_steps: previousSteps.slice(-8) };
  if (observation) context.observation = observation;
  return JSON.stringify({ agent_id: call.agentId, tool: call.tool, parameters: call.parameters, context });
}
