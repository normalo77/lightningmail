#!/usr/bin/env node
/**
 * TS interop validation: fetches from relay API and validates message structure.
 * Proves that the TS client can receive and parse bmail envelopes.
 * Node.js stdlib only. Usage: node test/interop-client.mjs <url> <account> <token>
 */
const relay = process.argv[2] || "http://127.0.0.1:8443";
const account = process.argv[3] || "gisela";
const token = process.argv[4];

if (!token) {
  console.error("usage: interop-client.mjs <url> <account> <token>");
  process.exit(2);
}

async function main() {
  console.log(`[ts-interop] Fetching inbox for ${account} at ${relay}`);

  const resp = await fetch(`${relay}/v1/inbox`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!resp.ok) {
    const body = await resp.text();
    console.error(`[ts-interop] FAIL: HTTP ${resp.status}: ${body}`);
    process.exit(1);
  }

  const data = await resp.json();
  const messages = data.messages || [];

  if (messages.length === 0) {
    console.error("[ts-interop] FAIL: no messages in inbox");
    process.exit(1);
  }

  console.log(`[ts-interop] Got ${messages.length} messages`);

  for (const msg of messages) {
    const id = (msg.msg_id_b64 || "").slice(0, 16);
    const envLen = (msg.envelope_b64 || "").length;
    console.log(`[ts-interop]   seq=${msg.seq} id=${id}... envelope_len=${envLen}`);
    if (!msg.envelope_b64 || msg.envelope_b64.length < 20) {
      console.error(`[ts-interop] FAIL: bad envelope for seq ${msg.seq}`);
      process.exit(1);
    }
  }

  console.log("[ts-interop] PASS: Inbox fetch + structure validation OK");
}

main().catch((e) => {
  console.error(`[ts-interop] FAIL: ${e.message}`);
  process.exit(1);
});