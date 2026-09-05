import { createData, SolanaSigner } from "arbundles";
import bs58 from "bs58";
import { getPublicKey } from "@noble/ed25519";
import { createHash } from "node:crypto";
import base64url from "base64url";

// Deterministic Ed25519 keypair from seed 0x01 * 32.
const seed = Buffer.alloc(32, 0x01);
const pub = await getPublicKey(seed);
const secret64 = Buffer.concat([seed, Buffer.from(pub)]);
const signer = new SolanaSigner(bs58.encode(secret64));

const data = "hello gitlawb ed25519 golden";
const tags = [
  { name: "App-Name", value: "gitlawb" },
  { name: "Schema", value: "gitlawb/ref-update/v1" },
];

const item = createData(data, signer, { tags });
await item.sign(signer);
const raw = Buffer.from(item.getRaw());
const id = item.id;
const sigBytes = base64url.toBuffer(item.signature);
const idCheck = base64url.encode(createHash("sha256").update(sigBytes).digest());
if (idCheck !== id) {
  console.error(`MISMATCH: id=${id} sha256(sig)=${idCheck}`);
  process.exit(1);
}
const sigData = await item.getSignatureData();
console.log("id           =", id);
console.log("signature_b64=", item.signature);
console.log("signature_len=", sigBytes.length);
console.log("owner_b64    =", item.owner);
console.log("owner_len    =", base64url.toBuffer(item.owner).length);
console.log("sigtype      =", item.signatureType);
console.log("binary_len   =", raw.length);
console.log("binary_hex   =", raw.toString("hex"));
console.log("deephash_hex =", Buffer.from(sigData).toString("hex"));
console.log("data_b64     =", base64url.encode(Buffer.from(data)));
console.log("isValid      =", await item.isValid());
