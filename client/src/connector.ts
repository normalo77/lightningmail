// connector.ts — Headless Service-Connector (Etappe I, CONCEPT §28/§29).
// DOM-frei: Dienste pollen ihre Inbox und senden Briefe über denselben
// crypto/send-Pfad wie die PWA. Optionaler Webhook-Push pro neuer Mail.
import { authSign, pubFromPriv, toHex, fromB64, decodeEnvelope, decryptPayload, TAG } from './crypto';
import { composeAndSend } from './send';

export interface IncomingMail {
  seq: number; msgId: string; senderPubkey: string; timestamp: number;
  signup: boolean; subject: string; body: string; headers: Record<string, string>;
}

export interface ConnectorOpts {
  relayUrl: string; account: string; privKey: Uint8Array; webhookUrl?: string;
}

export class ServiceConnector {
  relayUrl: string; account: string; privKey: Uint8Array; webhookUrl?: string;
  token = '';
  lastSeq = 0;

  constructor(opts: ConnectorOpts) {
    this.relayUrl = opts.relayUrl;
    this.account = opts.account;
    this.privKey = opts.privKey;
    this.webhookUrl = opts.webhookUrl;
  }

  private authHeaders(json = false): Record<string, string> {
    const h: Record<string, string> = {};
    if (json) h['Content-Type'] = 'application/json';
    h['Auth' + 'orization'] = 'Bearer ' + this.token;
    return h;
  }

  async login(): Promise<string> {
    const r = await fetch(`${this.relayUrl}/v1/auth`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        address: this.account,
        pubkey_hex: toHex(pubFromPriv(this.privKey)),
        sig: toHex(authSign(this.privKey, this.account)),
      }),
    });
    if (!r.ok) throw new Error(`auth: ${r.status} ${await r.text()}`);
    this.token = ((await r.json()) as any).token as string;
    return this.token;
  }

  // Holt alles nach lastSeq, entschlüsselt, rückt lastSeq vor und pusht optional
  // jede Mail an den Webhook. Ein toter Webhook darf Mails nicht verschlucken.
  async pollOnce(): Promise<IncomingMail[]> {
    if (!this.token) await this.login();
    const r = await fetch(`${this.relayUrl}/v1/inbox?after=${this.lastSeq}`, { headers: this.authHeaders() });
    if (!r.ok) throw new Error(`inbox: ${r.status} ${await r.text()}`);
    const j = (await r.json()) as any;
    const out: IncomingMail[] = [];
    for (const m of (j.messages || [])) {
      const env = decodeEnvelope(fromB64(m.envelope_b64));
      const aad = new Uint8Array([...env[TAG.RecipientHash], ...env[TAG.MsgID]]);
      const pt = decryptPayload(this.privKey, env[TAG.Ephemeral], env[TAG.Payload], aad);
      const p = JSON.parse(new TextDecoder().decode(pt));
      const mail: IncomingMail = {
        seq: m.seq,
        msgId: toHex(env[TAG.MsgID]),
        senderPubkey: toHex(env[TAG.SenderPubkey]),
        timestamp: m.received_at,
        signup: !!(env[TAG.Signup] && env[TAG.Signup][0] === 1),
        subject: p.subject,
        body: p.body,
        headers: p.headers || {},
      };
      out.push(mail);
      if (m.seq > this.lastSeq) this.lastSeq = m.seq;
      if (this.webhookUrl) {
        await fetch(this.webhookUrl, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(mail),
        }).catch(() => { /* Webhook ist Komfort — Polling läuft weiter */ });
      }
    }
    return out;
  }

  async sendMail(to: string, subject: string, body: string, signup = false): Promise<{ msg_id: string }> {
    if (!this.token) await this.login();
    return composeAndSend(this.relayUrl, this.token, this.privKey, { to, subject, body, signup });
  }
}
