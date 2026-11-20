#!/usr/bin/env python3
# test_forum.py — Forum-Logik isoliert gegen temporare Stats-DB
import io, importlib.util, json, os, sys, tempfile, base64, hashlib, time as tm
import hmac as hm

spec = importlib.util.spec_from_file_location("bserve", "/root/lm-work/lightningmail/site/serve.py")
m = importlib.util.module_from_spec(spec)
sys.modules["bserve"] = m
try:
    spec.loader.exec_module(m)
except SystemExit:
    pass

tmp = tempfile.mkdtemp()
m.STATS_DB = os.path.join(tmp, "stats.db")
m.forum_hmac_key_file = os.path.join(tmp, "forum_hmac.key")
m._init_db()

def ok(c, msg):
    print(("PASS " if c else "FAIL ") + msg)
    if not c:
        sys.exit(1)

def call(handler, body=None, token=""):
    h = m.H.__new__(m.H)
    raw = json.dumps(body).encode() if body is not None else b""
    h.headers = {"Content-Length": str(len(raw)), "X-Forum-Token": token}
    h.rfile = io.BytesIO(raw)
    out = {}
    def _json(self, obj, code=200):
        out["code"] = code
        out["body"] = obj
    m.H._json = _json
    handler(h)
    return out.get("code"), out.get("body", {})

key = m.H._forum_secret()
def fses(sub, pubkey):
    p = base64.urlsafe_b64encode(json.dumps({"sub": sub, "pubkey": pubkey, "relay": "alpha", "exp": int(tm.time()) + 60}).encode()).decode().rstrip("=")
    return "fses:" + p + "." + hm.new(key, p.encode(), hashlib.sha256).hexdigest()

tokA, tokB = fses("alice@test", "02AA"), fses("bob@test", "02BB")

code, o = call(m.H._api_forum_post, {"title": "Top-Thema", "body": "Hallo Forum"}, tokA)
ok(code == 200 and o.get("id"), f"Top-Post mit ID: {o}")
TID = o["id"]
code, o = call(m.H._api_forum_post, {"title": "Re: Top", "body": "Antwort 1", "parent": TID}, tokB)
ok(code == 200, "Reply auf Top-Post")
RID = o["id"]
code, o = call(m.H._api_forum_post, {"title": "x", "body": "y", "parent": 99999}, tokB)
ok(code == 404, "Reply auf unbekannten Parent -> 404")

code, o = call(m.H._api_forum_vote, {"id": TID, "dir": 1}, tokA)
ok(code == 200 and o["score"] == 1, f"Alice upvote -> score {o}")
code, o = call(m.H._api_forum_vote, {"id": TID, "dir": -1}, tokB)
ok(code == 200 and o["score"] == 0, f"Bob downvote -> score {o}")
code, o = call(m.H._api_forum_vote, {"id": RID, "dir": 1}, tokA)
ok(code == 200 and o["score"] == 1, "Vote auf Reply moeglich")
code, o = call(m.H._api_forum_vote, {"id": TID, "dir": 0}, tokA)
ok(code == 200 and o["score"] == -1, f"Toggle Zurueckziehen -> score {o}")

code, o = call(m.H._api_forum, token=tokA)
posts = {p["id"]: p for p in o["posts"]}
ok(posts[TID]["parent"] == 0 and posts[RID]["parent"] == TID, "GET liefert parent")
ok(posts[TID]["score"] == -1 and posts[TID]["my"] == 0, "GET score/my nach Toggle")
code, o = call(m.H._api_forum, token=tokB)
posts = {p["id"]: p for p in o["posts"]}
ok(posts[TID]["my"] == -1, "GET my-Vote Bob = down")
ok(posts[RID]["score"] == 1, "Reply-Score = 1")

code, o = call(m.H._api_forum_vote, {"id": TID, "dir": 1}, "")
ok(code == 401, "Vote ohne gueltigen Token -> 401")
code, o = call(m.H._api_forum_vote, {"id": TID, "dir": 7}, tokA)
ok(code == 400, "dir=7 -> 400")
code, o = call(m.H._api_forum_vote, {"id": 999, "dir": 1}, tokA)
ok(code == 404, "Vote auf unbekannten Post -> 404")

import sqlite3
c = sqlite3.connect(m.STATS_DB)
ok("parent" in [r[1] for r in c.execute("PRAGMA table_info(forum_posts)")], "parent-Spalte migriert")
m._init_db()
ok(True, "Reinit (duplicate-column-Pfad) uebersteht forum_votes")
ok(list(c.execute("SELECT COUNT(*) FROM forum_votes"))[0][0] == 2, "votes-Zeilen konsistent (Toggle hat Alices TID-Stimme geloescht)")
print("ALLE FORUM-CHECKS OK")
