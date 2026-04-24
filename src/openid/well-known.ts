import { Request, Response } from "express";
export const discovery = (req: Request, res: Response) => {
  const base = `${req.protocol}://${req.get("host")}`;
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/api/v1/openid/authorize`,
    token_endpoint: `${base}/api/v1/openid/token`,
    userinfo_endpoint: `${base}/api/v1/openid/userinfo`,
    jwks_uri: `${base}/api/v1/openid/jwks`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "profile", "email", "offline_access"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    claims_supported: ["sub", "name", "email", "given_name", "family_name"],
    grant_types_supported: ["authorization_code", "refresh_token"],
  });
};
