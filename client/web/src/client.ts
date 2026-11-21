/**
 * bmail PWA client — relay communication.
 * Talks to relayd over HTTP REST (same API as lmcli Go client).
 */

export interface InboxMessage {
  seq: number;
  msg_id_b64: string;
  received_at: number;
  envelope_b64: string;
}

export interface InboxResponse {
  messages: InboxMessage[];
}

export class BmailClient {
  private relay: string;
  private token: string | null = null;
  private account: string;

  constructor(relayUrl: string, account: string) {
    this.relay = relayUrl;
    this.account = account;
  }

  /** Authenticate with the relay using a challenge-response signature. */
  async auth(pubkeyHex: string, sigHex: string): Promise<string> {
    const resp = await fetch(`${this.relay}/v1/auth`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        address: this.account,
        pubkey_hex: pubkeyHex,
        sig: sigHex,
      }),
    });
    if (!resp.ok) throw new Error(`auth failed: ${resp.status}`);
    const data = await resp.json();
    this.token = data.token;
    return data.token;
  }

  setToken(token: string): void {
    this.token = token;
  }

  /** Fetch inbox messages from the relay. */
  async fetchInbox(): Promise<InboxResponse> {
    if (!this.token) throw new Error("not authenticated");
    const resp = await fetch(`${this.relay}/v1/inbox`, {
      headers: { Authorization: `Bearer ${this.token}` },
    });
    if (!resp.ok) throw new Error(`inbox: ${resp.status}`);
    return resp.json();
  }

  /** Get current balance in millisatoshis. */
  async balance(): Promise<number> {
    if (!this.token) throw new Error("not authenticated");
    const resp = await fetch(`${this.relay}/v1/balance`, {
      headers: { Authorization: `Bearer ${this.token}` },
    });
    if (!resp.ok) throw new Error(`balance: ${resp.status}`);
    const data = await resp.json();
    return data.balance_msat;
  }
}

/** Placeholder PWA main entry — wires relay client to DOM. */
export async function initApp(relayUrl: string, account: string, token: string): Promise<void> {
  const client = new BmailClient(relayUrl, account);
  client.setToken(token);

  const status = document.getElementById("status");
  if (status) status.textContent = "verbunden ✓";

  try {
    const inbox = await client.fetchInbox();
    const msgs = document.getElementById("messages");
    if (msgs && inbox.messages) {
      msgs.innerHTML = inbox.messages
        .map(
          (m) =>
            `<div class="card"><div class="msg-from">Nachricht #${m.seq}</div>
            <div class="msg-body">ID: ${m.msg_id_b64.slice(0, 16)}…</div></div>`
        )
        .join("");
    }
    if (status) status.textContent = `${inbox.messages.length} Nachrichten geladen`;
  } catch (e) {
    if (status) status.textContent = `fehler: ${e}`;
  }
}