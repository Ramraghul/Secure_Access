// public/oauth/callback.js — The demo OIDC client: validates the redirect,
// exchanges the code with PKCE, verifies the id_token and calls UserInfo.
(function () {
  "use strict";

  const { oidcStore, el, json, toast, busy, decodeJwt, errorMessage, rawRequest, verifyJwtWithJwks, mountRequestLog } = window.SA;
  const root = document.getElementById("callback");
  mountRequestLog(document.getElementById("log"));

  const params  = new URLSearchParams(location.search);
  const pending = oidcStore.get();
  const steps   = el("ol", { class: "steps" });
  const output  = el("div", { class: "stack" });

  root.replaceChildren(
    el("section", { class: "card" },
      el("div", { class: "card-head" }, el("h1", {}, "Signing you in"), el("span", { class: "muted small" }, "Authorization Code + PKCE")),
      steps),
    output);

  function step(text, status, detail) {
    const item = el("li", { class: status }, el("div", {}, el("strong", {}, text), detail ? el("div", { class: "muted small" }, detail) : null));
    steps.append(item);
    return status !== "failed";
  }

  const card = (title, subtitle, ...body) => el("section", { class: "card" },
    el("div", { class: "card-head" }, el("h2", {}, title), subtitle ? el("span", { class: "muted small" }, subtitle) : null), ...body);

  async function run() {
    // 1. Result of the authorization request
    if (params.get("error")) {
      step("Authorization response", "failed", `${params.get("error")}: ${params.get("error_description") || "the request was not approved"}`);
      oidcStore.set(null);
      output.append(el("p", {}, el("a", { class: "btn", href: "/" }, "Back to the console")));
      return;
    }
    const code = params.get("code");
    if (!code) return step("Authorization response", "failed", "No authorization code in the URL");
    if (!pending) return step("Authorization response", "failed", "No pending sign-in in this tab — start the flow from the console");
    step("Authorization code received", "done", "One-time code, valid for 2 minutes");

    // 2. CSRF protection: state must match what this app generated
    if (!step("State matches (CSRF check)", params.get("state") === pending.state ? "done" : "failed",
      params.get("state") === pending.state ? "The response belongs to the request this tab started" : "State mismatch — possible CSRF, stopping")) return;

    // 3. Mix-up protection: the issuer that answered is the one we asked
    const iss = params.get("iss");
    step("Issuer matches", !iss || iss === location.origin ? "done" : "failed", iss || "iss parameter not present");

    // 4. Exchange the code with the PKCE verifier
    const form = {
      grant_type: "authorization_code", code, redirect_uri: pending.redirectUri,
      client_id: pending.clientId, code_verifier: pending.verifier,
    };
    oidcStore.set(null); // the code and verifier are single use
    const tokenRes = await rawRequest("POST", "/api/v1/openid/token", { form });
    if (!step("Code exchanged at /openid/token with PKCE", tokenRes.ok ? "done" : "failed", tokenRes.ok ? "Server re-hashed the verifier and matched the challenge" : errorMessage(tokenRes))) return;
    let tokens = tokenRes.data;

    // 5. Verify the id_token signature against the JWKS, then its claims
    const idToken  = decodeJwt(tokens.id_token);
    const signature = await verifyJwtWithJwks(tokens.id_token).catch(err => ({ valid: false, reason: err.message }));
    step("id_token signature verified with JWKS", signature.valid ? "done" : "failed",
      signature.valid ? `RS256, key id ${signature.kid.slice(0, 12)}…` : signature.reason || "Signature did not verify");

    const now = Math.floor(Date.now() / 1000);
    const claimsOk = idToken.payload.aud === pending.clientId && idToken.payload.nonce === pending.nonce && idToken.payload.exp > now;
    step("id_token claims checked (aud, nonce, exp)", claimsOk ? "done" : "failed",
      `aud=${idToken.payload.aud} · nonce ${idToken.payload.nonce === pending.nonce ? "matches" : "does NOT match"}`);

    // 6. UserInfo
    const userinfo = await rawRequest("GET", "/api/v1/openid/userinfo", { token: tokens.access_token });
    step("Profile fetched from /openid/userinfo", userinfo.ok ? "done" : "failed", userinfo.ok ? `Hello, ${userinfo.data.name || userinfo.data.email || userinfo.data.sub}` : errorMessage(userinfo));

    const tokenView = el("div");
    const renderTokens = () => tokenView.replaceChildren(json({
      token_type: tokens.token_type,
      expires_in: tokens.expires_in,
      scope: tokens.scope,
      access_token: `${tokens.access_token.slice(0, 32)}…`,
      id_token: `${tokens.id_token.slice(0, 32)}…`,
      refresh_token: tokens.refresh_token ? `${tokens.refresh_token.slice(0, 24)}…` : "(not issued — offline_access not granted)",
    }));
    renderTokens();

    const actions = el("div", { class: "row" });
    if (tokens.refresh_token) {
      actions.append(el("button", {
        class: "btn", type: "button",
        onclick: e => busy(e.currentTarget, async () => {
          const res = await rawRequest("POST", "/api/v1/openid/token", {
            form: { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: pending.clientId },
          });
          if (!res.ok) { toast(errorMessage(res), "error"); return; }
          tokens = res.data;
          renderTokens();
          toast("Tokens refreshed — the previous refresh token no longer works", "success");
        }),
      }, "Refresh tokens"));
      actions.append(el("button", {
        class: "btn danger", type: "button",
        onclick: e => busy(e.currentTarget, async () => {
          await rawRequest("POST", "/api/v1/openid/revoke", { form: { token: tokens.refresh_token, client_id: pending.clientId } });
          const check = await rawRequest("GET", "/api/v1/openid/userinfo", { token: tokens.access_token });
          toast(check.status === 401 ? "Revoked — the session no longer works" : "Revocation requested", "success");
        }),
      }, "Revoke (sign out of demo app)"));
    }
    actions.append(el("a", { class: "btn primary", href: "/" }, "Back to the console"));

    output.append(
      el("div", { class: "grid-2" },
        card("id_token claims", "decoded JWT payload", json(idToken.payload)),
        card("UserInfo response", "claims released by the granted scopes", json(userinfo.data))),
      card("Token response", "from /openid/token", tokenView, el("div", { style: "margin-top:.75rem" }, actions)));
  }

  run().catch(err => step("Unexpected error", "failed", err.message));
})();
