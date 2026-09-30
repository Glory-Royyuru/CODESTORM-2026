/* Assertions for the simulated network boundary and the crypt-arithmetic quarantine guard. Exits 1 on failure. */
import { decodeCanonical, quarantineScan } from "../src/lib/gateway/anomaly/guard";
import { quarantineEnvelope } from "../src/lib/gateway/anomaly/ledger";
import { toWire } from "../src/lib/gateway/ingress";
import { classifyIp, parseIp } from "../src/lib/gateway/network/cidr";
import { EGRESS_PROXY, enforceConnect, newEbpfState } from "../src/lib/gateway/network/ebpf";
import { hostIsDenied, inspectDestination } from "../src/lib/gateway/network/firewall";
import { generateIntegrityKey, signRequest, verifyRequest } from "../src/lib/gateway/network/identity";
import { SimulatedDns } from "../src/lib/gateway/network/resolver";

let failures = 0;
function check(name: string, ok: boolean) {
  if (!ok) failures++;
  console.log(`${ok ? "ok  " : "FAIL"} ${name}`);
}

/* CIDR deny ranges */
const denied: [string, string][] = [
  ["127.0.0.1", "LOOPBACK"],
  ["::1", "LOOPBACK"],
  ["0.0.0.0", "ZERO_ADDRESS"],
  ["::", "ZERO_ADDRESS"],
  ["10.2.3.4", "RFC1918_PRIVATE"],
  ["172.31.255.255", "RFC1918_PRIVATE"],
  ["192.168.0.1", "RFC1918_PRIVATE"],
  ["169.254.169.254", "LINK_LOCAL_METADATA"],
  ["fe80::1", "LINK_LOCAL_METADATA"],
  ["fd00::1", "UNIQUE_LOCAL_V6"],
  ["224.0.0.251", "MULTICAST_BROADCAST"],
  ["255.255.255.255", "MULTICAST_BROADCAST"],
  ["ff02::1", "MULTICAST_BROADCAST"],
  ["::ffff:169.254.169.254", "LINK_LOCAL_METADATA"],
];
for (const [ip, want] of denied) check(`deny ${ip} → ${want}`, classifyIp(parseIp(ip)!)?.check === want);
for (const ip of ["8.8.8.8", "172.32.0.1", "2606:4700::1111"]) check(`public ${ip}`, classifyIp(parseIp(ip)!) === null);
for (const h of ["2852039166", "0xa9fea9fe", "0251.0376.0251.0376", "localhost", "metadata.google.internal"]) check(`host denied ${h}`, hostIsDenied(h));

/* Destination firewall + DNS pinning */
const dns = new SimulatedDns();
const allow = ["partner-portal.com", "github.com"];
const ok = inspectDestination("https://api.github.com/zen", allow, dns);
check("allow-listed host is pinned", ok.decision === "ALLOW" && ok.pinnedIp === ok.resolvedIps[0] && ok.registrableDomain === "github.com");
const meta = inspectDestination("https://169.254.169.254/latest/meta-data/", allow, dns);
check("metadata IP literal HARD_DENY", meta.decision === "HARD_DENY" && meta.checks.find((c) => c.check === "LINK_LOCAL_METADATA")?.status === "BLOCKED");
check("integer IP refused at parse", inspectDestination("https://2852039166/", allow, dns).checks[0].status === "BLOCKED");
check("non-allowlisted eTLD+1", inspectDestination("https://github.com.evil.io/", allow, dns).decision === "HARD_DENY");
const rebind = inspectDestination("https://assets.partner-portal.com/x.png", allow, dns);
check("rebinding name: first answer pinned", rebind.pinnedIp === "93.184.216.34");
check("rebinding name: second answer is metadata", dns.resolve("assets.partner-portal.com").ips[0] === "169.254.169.254");

/* eBPF */
const st = newEbpfState(1000);
check("proxy → pinned passes", enforceConnect(st, { tool: "t", dst: EGRESS_PROXY.ip, port: EGRESS_PROXY.port, upstream: "1.2.3.4", pinnedIp: "1.2.3.4", bytes: 100 }, 0).action === "PASS");
check("direct socket dropped", enforceConnect(st, { tool: "t", dst: "169.254.169.254", port: 80, pinnedIp: "1.2.3.4", bytes: 10 }, 0).action === "DROP");
check("upstream ≠ pin dropped", enforceConnect(st, { tool: "t", dst: EGRESS_PROXY.ip, port: EGRESS_PROXY.port, upstream: "5.6.7.8", pinnedIp: "1.2.3.4", bytes: 10 }, 0).action === "DROP");
check("byte budget enforced", enforceConnect(st, { tool: "t", dst: EGRESS_PROXY.ip, port: EGRESS_PROXY.port, upstream: "1.2.3.4", pinnedIp: "1.2.3.4", bytes: 950 }, 0).action === "DROP");

/* HMAC request integrity */
const key = generateIntegrityKey();
const req = { decisionId: "d", sessionId: "s", tool: "fetch_webpage", argsDigest: "a", manifestHash: "m", pinnedIp: "1.2.3.4" };
const tag = signRequest(req, key);
check("HMAC verifies", verifyRequest(req, tag, key));
check("HMAC binds pinned IP", !verifyRequest({ ...req, pinnedIp: "169.254.169.254" }, tag, key));
check("missing HMAC fails closed", !verifyRequest(req, undefined, key));
check("foreign key fails closed", !verifyRequest(req, tag, generateIntegrityKey()));

/* Quarantine guard */
const types = (raw: string) => quarantineScan(raw).anomalies.map((a) => a.type);
const TWO_256 = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
check("2^256 overflow", types(`{"amount": ${TWO_256}}`).join() === "ARITHMETIC_INTEGER_OVERFLOW");
check("2^53+1 malformed bigint", types(`{"amount": 9007199254740993}`).join() === "MALFORMED_BIGINT");
check("1e400 overflow", types(`{"x": 1e400}`).join() === "ARITHMETIC_INTEGER_OVERFLOW");
check("safe ints pass", types(`{"amount": 48000, "n": -12.5}`).length === 0);
check("numbers inside strings ignored", types(`{"memo": "${TWO_256}"}`).length === 0);
check("OpenAI nested arguments scanned", types(toWire("OPENAI", "transfer_funds", { amount: "__N__" }).replace('\\"__N__\\"', TWO_256)).join() === "ARITHMETIC_INTEGER_OVERFLOW");
check("odd-length hex signature", types(`{"signature": "abc"}`).join() === "NON_CANONICAL_ENCODING");
check("zero signature", types(`{"signature": "${"00".repeat(64)}"}`).join() === "SIGNATURE_VERIFICATION_FAILURE");
check("homoglyph key", types(`{"ѕignature": "00"}`).join() === "NON_CANONICAL_ENCODING");
check("alg none DPoP", types(`{"dpop_proof": "eyJhbGciOiJub25lIn0.e30.AA"}`).join() === "DPOP_PROOF_TAMPERING");
check("CRC mismatch", types(`{"payload": "hello", "crc32": "00000000"}`).join() === "CORRUPT_CRYPTO_TOKEN");
check("CRC match", types(`{"payload": "hello", "crc32": "3610a686"}`).length === 0);
check("canonical base64 decodes", decodeCanonical("aGVsbG8=") instanceof Uint8Array);
check("superfluous padding refused", typeof decodeCanonical("aGVsbG8==") === "string");

const scan = quarantineScan(`{"amount": ${"9".repeat(500)}}`);
const env = quarantineEnvelope(scan.anomalies[0], { sessionId: "s", agentId: "a", tool: "t", receiptId: "r", at: 0 });
check("envelope snippet ≤ 64 bytes", env.quarantined_hex_snippet.length === 128 && env.raw_payload_bytes === 500);
check("envelope never holds the raw value", !JSON.stringify(env).includes("9".repeat(100)));

console.log(failures ? `\n${failures} check(s) FAILED` : "\nall network / quarantine checks passed");
process.exit(failures ? 1 : 0);
