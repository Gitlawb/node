import { createData, EthereumSigner } from "arbundles";
import { createHash } from "node:crypto";
import base64url from "base64url";

const data = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{};':\",./<>?`~";
const tags = [
  { name: "tag1", value: "value1" },
  { name: "tag2", value: "value2" },
];
const anchor = "thisSentenceIs32BytesLongTrustMe";
const target = "OXcT1sVRSA5eGwt2k6Yuz8-3e3g9WJi5uSE99CWqsBs";
const signer = new EthereumSigner("8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f");

const item = createData(data, signer, { anchor, target, tags });
const raw = item.getRaw();
const id = item.id;

// `item.signature` is base64url(rawSignature). Decode and sha256.
const sigBytes = base64url.toBuffer(item.signature);
const idCheck = base64url.encode(createHash("sha256").update(sigBytes).digest());
if (idCheck !== id) {
  console.error(`MISMATCH: id=${id} sha256(sig)=${idCheck}`);
  process.exit(1);
}

console.log("id           =", id);
console.log("signature_b64=", item.signature);
console.log("signature_len=", sigBytes.length);
console.log("binary_len   =", raw.length);
console.log("binary_hex   =", raw.toString("hex"));
