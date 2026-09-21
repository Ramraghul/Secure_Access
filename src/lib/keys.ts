// src/lib/keys.ts — RSA signing key for OpenID Connect tokens (RS256)
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, KeyObject } from "crypto";
import { config } from "../config";
import { logger } from "./logger";

export interface PublicJwk {
  kty: string;
  n:   string;
  e:   string;
  kid: string;
  use: "sig";
  alg: "RS256";
}

export interface SigningKey {
  kid:        string;
  privateKey: KeyObject;
  publicKey:  KeyObject;
  publicJwk:  PublicJwk;
  ephemeral:  boolean;
}

// Accepts a PEM, a PEM with literal "\n" sequences (common in dashboards), or base64 of a PEM
function parsePem(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.includes("-----BEGIN")) return trimmed.replace(/\\n/g, "\n");
  return Buffer.from(trimmed, "base64").toString("utf8");
}

let cached: SigningKey | null = null;

export function getSigningKey(): SigningKey {
  if (cached) return cached;

  let privateKey: KeyObject;
  let ephemeral = false;

  if (config.oidc.privateKey) {
    privateKey = createPrivateKey(parsePem(config.oidc.privateKey));
  } else {
    privateKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
    ephemeral  = true;
    if (!config.isTest) {
      logger.warn("OIDC_PRIVATE_KEY is not set — using an ephemeral RSA key. OIDC tokens become invalid on restart. Run `npm run keys:generate`.");
    }
  }

  if (privateKey.asymmetricKeyType !== "rsa") {
    throw new Error("OIDC_PRIVATE_KEY must be an RSA private key");
  }

  const publicKey = createPublicKey(privateKey);
  const jwk = publicKey.export({ format: "jwk" }) as { kty: string; n: string; e: string };

  // RFC 7638 JWK thumbprint as the key id
  const kid = createHash("sha256")
    .update(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n }))
    .digest("base64url");

  cached = {
    kid,
    privateKey,
    publicKey,
    publicJwk: { kty: jwk.kty, n: jwk.n, e: jwk.e, kid, use: "sig", alg: "RS256" },
    ephemeral,
  };
  return cached;
}
