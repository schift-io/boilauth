import { test } from "node:test";
import assert from "node:assert/strict";
import { createPasswordHasher, encodeFirebaseHash, hashKind } from "../src/index.js";
import { firebaseScryptHash } from "../src/hash/firebase-scrypt.js";
import { FIREBASE_SAMPLE_KEY } from "./helpers.js";

// pyca/bcrypt tests/test_bcrypt.py
const BCRYPT_VECTORS: [string, string][] = [
  ["U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"],
  ["U*U*", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"],
  ["U*U*U", "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"],
  ["Kk4DQuMMfZL9o", "$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm"],
  ["9IeRXmnGxMYbs", "$2b$04$pQ7gRO7e6wx/936oXhNjrOUNOHL1D0h1N2IDbJZYs.1ppzSof6SPy"],
];

const hasher = createPasswordHasher({ firebaseKeys: [FIREBASE_SAMPLE_KEY] });

test("bcrypt published vectors verify, and wrong passwords do not", async () => {
  for (const [pw, h] of BCRYPT_VECTORS) {
    assert.equal(hashKind(h), "bcrypt");
    assert.equal(await hasher.verify({ hash: h, password: pw }), true, h);
    assert.equal(await hasher.verify({ hash: h, password: pw + "x" }), false, h);
    assert.equal(hasher.needsRehash(h), true);
  }
});

test("firebase scrypt reproduces the firebase/scrypt README sample hash", async () => {
  const out = await firebaseScryptHash("user1password", "42xEC+ixf3L2lw==", FIREBASE_SAMPLE_KEY);
  assert.equal(
    out.toString("base64"),
    "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==",
  );
  const stored = encodeFirebaseHash({
    keyId: "sample-project",
    rounds: 8,
    memCost: 14,
    salt: "42xEC+ixf3L2lw==",
    saltSeparator: "Bw==",
    hash: out.toString("base64"),
  });
  assert.equal(hashKind(stored), "firebase-scrypt");
  assert.equal(await hasher.verify({ hash: stored, password: "user1password" }), true);
  assert.equal(await hasher.verify({ hash: stored, password: "user1passwore" }), false);
});

test("firebase hash with an unconfigured keyId fails loudly, not silently", async () => {
  const stored = encodeFirebaseHash({ keyId: "other", rounds: 8, memCost: 14, salt: "AA==", saltSeparator: "Bw==", hash: "AA==" });
  await assert.rejects(hasher.verify({ hash: stored, password: "x" }), /no Firebase signer key/);
});

test("new hashes are argon2id at the preset and do not need rehash", async () => {
  const h = await hasher.hash("correct horse battery");
  assert.match(h, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
  assert.equal(hasher.needsRehash(h), false);
  assert.equal(await hasher.verify({ hash: h, password: "correct horse battery" }), true);
  const weak = await createPasswordHasher({ argon2: { memoryCost: 8192, timeCost: 1 } }).hash("pw");
  assert.equal(hasher.needsRehash(weak), true);
});

test("unknown formats are rejected", async () => {
  assert.equal(hashKind("5f4dcc3b5aa765d61d8327deb882cf99"), "unknown");
  assert.equal(await hasher.verify({ hash: "5f4dcc3b5aa765d61d8327deb882cf99", password: "password" }), false);
});
