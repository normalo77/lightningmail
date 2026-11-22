# embed_rp.py — Referenz-OIDC-RP fuer den „Sign in with lightningmail“-Button.
# Pure-Python ES256 (P-256) ID-Token-Pruefung gegen das Relay-JWKS. Keine
# Abhaengigkeiten, kein Client-Secret (stateless public client). Siehe
# site/embed.html fuer den Einbau in eigene Seiten.
import base64, hashlib, json, http.client, threading, time, urllib.parse

ALLOWED_ISSUERS = {
    "https://relay-a.lightningmail.app",
    "https://relay-b.lightningmail.app",
    "https://relay.lightningmail.app",
}

# --- P-256 (NIST) in reinem Python; Verifikation only, ~ms pro Token ---
# Konstanten: SEC2 secp256r1, gegen OpenSSL validiert (d=1-Trick) + b algebraisch.
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5  # noqa


def _inv(k, m=P):
    return pow(k, -1, m)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        s = (3 * x1 * x1 + A) * _inv(2 * y1) % P
    else:
        s = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (s * s - x1 - x2) % P
    return (x3, (s * (x1 - x3) - y1) % P)


def _mul(k, pt):
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc


def _b64u(b):
    return base64.urlsafe_b64encode(bytes(b)).decode().rstrip("=")


def _b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jGET(url):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or u.hostname is None:
        raise ValueError("nur https erlaubt: " + url)
    conn = http.client.HTTPSConnection(u.netloc, timeout=15)
    try:
        conn.request("GET", u.path + ("?" + u.query if u.query else ""))
        r = conn.getresponse()
        return json.loads(r.read())
    finally:
        conn.close()


def _formPOST(url, data):
    body = urllib.parse.urlencode(data).encode()
    u = urllib.parse.urlsplit(url)
    conn = http.client.HTTPSConnection(u.netloc, timeout=15)
    try:
        conn.request("POST", u.path, body=body, headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body))})
        r = conn.getresponse()
        return r.status, json.loads(r.read())
    finally:
        conn.close()


_jwks_cache = {}  # issuer -> (ts, jwks)
_cache_lock = threading.Lock()


def _jwks(issuer):
    with _cache_lock:
        hit = _jwks_cache.get(issuer)
        if hit and time.time() - hit[0] < 300:
            return hit[1]
    disc = _jGET(issuer + "/.well-known/openid-configuration")
    import urllib.parse as _up
    if _up.urlsplit(disc["jwks_uri"]).netloc != _up.urlsplit(issuer).netloc:
        raise ValueError("jwks_uri nicht unter Issuer-Origin")
    jw = _jGET(disc["jwks_uri"])
    with _cache_lock:
        _jwks_cache[issuer] = (time.time(), jw)
    return jw


def verify_id_token(id_token, issuer, client_id, nonce):
    """Prueft Sig (ES256/JWKS), iss, aud, nonce, exp/iat. Gibt Claims zurueck."""
    h = id_token.split(".")
    if len(h) != 3:
        raise ValueError("id_token Format")
    hdr = json.loads(_b64u_dec(h[0]))
    cl = json.loads(_b64u_dec(h[1]))
    if hdr.get("alg") != "ES256":
        raise ValueError("alg != ES256")
    jw = _jwks(issuer)
    if hdr.get("kid"):
        keys = [k for k in jw.get("keys", []) if k.get("kid") == hdr["kid"]]
    else:
        keys = list(jw.get("keys", []))
    msg = (h[0] + "." + h[1]).encode()
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    sig = _b64u_dec(h[2])
    if len(sig) != 64:
        raise ValueError("sig Laenge")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if not (1 <= r < N and 1 <= s < N):
        raise ValueError("sig Bereiche")
    ok = False
    for k in keys:
        if k.get("kty") != "EC" or k.get("crv") != "P-256":
            continue
        Q = (_b64u_int(k["x"]), _b64u_int(k["y"]))
        w = _inv(s, N)
        x1 = _add(_mul(z * w % N, (GX, GY)), _mul(r * w % N, Q))
        if x1 and x1[0] % N == r:
            ok = True
            break
    if not ok:
        raise ValueError("Signatur ungueltig")
    now = time.time()
    if cl.get("iss") != issuer:
        raise ValueError("iss")
    aud = cl.get("aud")
    if aud != client_id and (not isinstance(aud, list) or client_id not in aud):
        raise ValueError("aud")
    if not nonce or cl.get("nonce") != nonce:
        raise ValueError("nonce")
    if now - 30 >= cl.get("exp", 0) or now < cl.get("iat", now + 1) - 300:
        raise ValueError("exp/iat")
    return cl


def _b64u_int(s):
    return int.from_bytes(_b64u_dec(s), "big")


def embed_verify(payload):
    """Kompletter Callback-Tausch: code -> token -> geprüfte Claims."""
    issuer = str(payload.get("issuer") or "").rstrip("/")
    if issuer not in ALLOWED_ISSUERS:
        raise ValueError("issuer nicht freigeschaltet")
    code = str(payload.get("code") or "")
    verifier = str(payload.get("verifier") or "")
    client_id = str(payload.get("client_id") or "")
    redirect_uri = str(payload.get("redirect_uri") or "")
    nonce = payload.get("nonce")
    if not (code and verifier and client_id and redirect_uri and nonce):
        raise ValueError("code/verifier/client_id/redirect_uri noetig")
    disc = _jGET(issuer + "/.well-known/openid-configuration")
    st, tok = _formPOST(disc["token_endpoint"], {
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": redirect_uri, "client_id": client_id,
        "code_verifier": verifier})
    if st != 200 or "id_token" not in tok:
        raise ValueError("token endpoint: HTTP %d %s" % (st, str(tok.get("error") or tok)[:120]))
    claims = verify_id_token(tok["id_token"], issuer, client_id, nonce)
    return {"claims": claims, "access_token_present": bool(tok.get("access_token"))}


if __name__ == "__main__":
    # self-check: JWT mit frischem P-256-Key signieren (reines Python) und
    # verifizieren; Manipulation muss durchfallen.
    import secrets as _s
    assert (GY * GY - (GX ** 3 + A * GX + B)) % P == 0, "G nicht auf Kurve"
    assert _mul(N, (GX, GY)) is None, "N*G != Infinity"
    d = _s.randbits(255) % (N - 1) + 1
    Q = _mul(d, (GX, GY))
    hdr = _b64u(json.dumps({"alg": "ES256", "kid": "t"}).encode())
    pl = _b64u(json.dumps({"iss": "https://self.test", "aud": "cid", "nonce": "n1",
                           "exp": time.time() + 60, "iat": time.time() - 1}).encode())
    msg = (hdr + "." + pl).encode()
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    while True:
        kk = _s.randbits(255) % (N - 1) + 1
        R = _mul(kk, (GX, GY))
        r = R[0] % N
        if r == 0:
            continue
        sv = _inv(kk, N) * (z + r * d) % N
        if sv:
            break
    sig = _b64u(r.to_bytes(32, "big") + sv.to_bytes(32, "big"))
    tok = hdr + "." + pl + "." + sig
    _jwks_cache["https://self.test"] = (time.time(), {"keys": [
        {"kty": "EC", "crv": "P-256", "kid": "t",
         "x": _b64u(Q[0].to_bytes(32, "big")), "y": _b64u(Q[1].to_bytes(32, "big"))}]})
    ALLOWED_ISSUERS.add("https://self.test")
    assert verify_id_token(tok, "https://self.test", "cid", "n1")["iss"] == "https://self.test"
    try:
        verify_id_token(hdr + "." + pl + "." + _b64u((r + 1).to_bytes(32, "big") + sv.to_bytes(32, "big")),
                        "https://self.test", "cid", "n1")
        raise SystemExit("FAIL: tampered sig accepted")
    except ValueError:
        pass
    try:
        verify_id_token(tok, "https://self.test", "cid", "boese-nonce")
        raise SystemExit("FAIL: wrong nonce accepted")
    except ValueError:
        pass
    print("embed_rp self-check OK")
