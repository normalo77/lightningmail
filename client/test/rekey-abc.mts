import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { parseSec1PEM, pubFromPriv } from "../src/crypto";
for (const n of ["alice", "bob"]) {
  const pub = pubFromPriv(parseSec1PEM(readFileSync(`app/public/keys/${n}.key`, "utf8")));
  const h = createHash("sha256").update(Buffer.from(pub)).digest("hex");
  console.log(n, Buffer.from(pub).toString("hex"), h);
}
