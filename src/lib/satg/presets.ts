/**
 * Example request bodies for the Live Gateway editor.
 *
 * These are *inputs only*. Tool names, agents and parameters come from the
 * backend's registry (backend/app/gateway/registry.py) and its rule table
 * (backend/README.md). `expected` is a label telling the user what the
 * example is meant to exercise — it is never shown as a result and is not
 * used to decide anything. The verdict always comes from the backend.
 */

export interface RequestPreset {
  id: string;
  group: "Allowed" | "Registry" | "Parameters" | "Destination" | "Canonicalization" | "Ingress";
  title: string;
  description: string;
  /** What the example is designed to trigger, e.g. "BLOCK · TOOL-001". */
  expected: string;
  body: string;
}

const pretty = (v: unknown) => JSON.stringify(v, null, 2);

/** parameters nested `levels` objects deep → total JSON depth levels + 2. */
function deeplyNested(levels: number): string {
  let inner = `"x"`;
  for (let i = 0; i < levels; i++) inner = `{"n${levels - i}": ${inner}}`;
  return `{\n  "agent_id": "support-bot-3",\n  "tool": "get_weather",\n  "parameters": {"city": ${inner}}\n}`;
}

export const PRESETS: RequestPreset[] = [
  {
    id: "allow-email",
    group: "Allowed",
    title: "Email to an allow-listed domain",
    description: "support-bot-3 is authorized for send_email and company.com is on the email egress allowlist.",
    expected: "ALLOW · BASE-001",
    body: pretty({ agent_id: "support-bot-3", tool: "send_email", parameters: { to: "user@company.com", subject: "Support", body: "Hello" } }),
  },
  {
    id: "allow-weather",
    group: "Allowed",
    title: "Weather lookup (any agent)",
    description: "get_weather is open to every agent and has no egress destination.",
    expected: "ALLOW · BASE-001",
    body: pretty({ agent_id: "research-bot", tool: "get_weather", parameters: { city: "Berlin" } }),
  },
  {
    id: "allow-customer",
    group: "Allowed",
    title: "Customer search by an authorized agent",
    description: "sales-bot-1 is on search_customer's allowed-agents list.",
    expected: "ALLOW · BASE-001",
    body: pretty({ agent_id: "sales-bot-1", tool: "search_customer", parameters: { customer_id: "CUST-1042" } }),
  },
  {
    id: "unknown-tool",
    group: "Registry",
    title: "Unregistered tool",
    description: "transfer_funds is not in the tool registry.",
    expected: "BLOCK · TOOL-001",
    body: pretty({ agent_id: "support-bot-3", tool: "transfer_funds", parameters: { account: "ACC-1", amount: 5000 } }),
  },
  {
    id: "disabled-tool",
    group: "Registry",
    title: "Disabled destructive tool",
    description: "delete_database is registered but disabled.",
    expected: "BLOCK · TOOL-002",
    body: pretty({ agent_id: "admin-bot", tool: "delete_database", parameters: { database_name: "customers" } }),
  },
  {
    id: "unauthorized-agent",
    group: "Registry",
    title: "Agent not authorized for the tool",
    description: "sales-bot-1 is not on send_email's allowed-agents list.",
    expected: "BLOCK · TOOL-003",
    body: pretty({ agent_id: "sales-bot-1", tool: "send_email", parameters: { to: "user@company.com", subject: "Offer", body: "Hi" } }),
  },
  {
    id: "missing-param",
    group: "Parameters",
    title: "Required parameter missing",
    description: "send_email requires to, subject and body; body is omitted.",
    expected: "BLOCK · PARAM-001",
    body: pretty({ agent_id: "support-bot-3", tool: "send_email", parameters: { to: "user@company.com", subject: "Support" } }),
  },
  {
    id: "wrong-type",
    group: "Parameters",
    title: "Parameter with the wrong type",
    description: "customer_id must be a string; a number is sent.",
    expected: "BLOCK · PARAM-002",
    body: pretty({ agent_id: "sales-bot-1", tool: "search_customer", parameters: { customer_id: 1042 } }),
  },
  {
    id: "header-injection",
    group: "Parameters",
    title: "Email header injection",
    description: "A CRLF in the single-line subject tries to smuggle a Bcc header.",
    expected: "BLOCK · PARAM-005",
    body: pretty({ agent_id: "support-bot-3", tool: "send_email", parameters: { to: "user@company.com", subject: "Hi\r\nBcc: attacker@evil.example", body: "Hello" } }),
  },
  {
    id: "external-destination",
    group: "Destination",
    title: "Recipient outside the allowlist",
    description: "Exfiltration attempt to a domain not on the email egress allowlist.",
    expected: "BLOCK · DEST-001",
    body: pretty({ agent_id: "support-bot-3", tool: "send_email", parameters: { to: "audit-team@exfil-collector.net", subject: "Customer export", body: "See attached" } }),
  },
  {
    id: "ambiguous-destination",
    group: "Destination",
    title: "Ambiguous recipient address",
    description: "Two @ signs: a mail library might deliver to evil.example even though company.com appears last.",
    expected: "BLOCK · DEST-002",
    body: pretty({ agent_id: "support-bot-3", tool: "send_email", parameters: { to: "a@evil.example@company.com", subject: "Support", body: "Hello" } }),
  },
  {
    id: "invisible-char",
    group: "Canonicalization",
    title: "Zero-width character in a value",
    description: "A U+200B zero-width space hidden inside the city name.",
    expected: "BLOCK · CANON-001",
    body: `{\n  "agent_id": "research-bot",\n  "tool": "get_weather",\n  "parameters": {"city": "Ber\\u200blin"}\n}`,
  },
  {
    id: "duplicate-key",
    group: "Ingress",
    title: "Duplicate JSON key",
    description: "Two \"to\" keys: parsers disagree on which one wins, so the body is rejected.",
    expected: "BLOCK · INGRESS-002 (HTTP 400)",
    body: `{\n  "agent_id": "support-bot-3",\n  "tool": "send_email",\n  "parameters": {\n    "to": "user@company.com",\n    "to": "attacker@evil.example",\n    "subject": "Support",\n    "body": "Hello"\n  }\n}`,
  },
  {
    id: "unknown-field",
    group: "Ingress",
    title: "Unknown top-level field",
    description: "An extra \"role\" field is not part of the tool-call schema.",
    expected: "BLOCK · INGRESS-005 (HTTP 422)",
    body: pretty({ agent_id: "support-bot-3", tool: "get_weather", parameters: { city: "Berlin" }, role: "admin" }),
  },
  {
    id: "nan-value",
    group: "Ingress",
    title: "NaN in the body",
    description: "NaN is not valid JSON; the strict parser refuses it.",
    expected: "BLOCK · INGRESS-001 (HTTP 400)",
    body: `{\n  "agent_id": "support-bot-3",\n  "tool": "get_weather",\n  "parameters": {"city": NaN}\n}`,
  },
  {
    id: "deep-nesting",
    group: "Ingress",
    title: "Nesting deeper than 8 levels",
    description: "The body nests objects 9 levels deep.",
    expected: "BLOCK · INGRESS-004 (HTTP 400)",
    body: deeplyNested(7),
  },
];
