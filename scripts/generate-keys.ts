// scripts/generate-keys.ts — Prints a new RSA key for OIDC_PRIVATE_KEY
// Usage: npm run keys:generate
import { generateKeyPairSync } from "crypto";

const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding:  { type: "spki", format: "pem" },
});

console.log("Add this single line to your environment variables (it is a base64-encoded PEM).");
console.log("Keep it secret. Rotating it invalidates previously issued OIDC tokens.\n");
console.log(`OIDC_PRIVATE_KEY=${Buffer.from(privateKey).toString("base64")}`);
