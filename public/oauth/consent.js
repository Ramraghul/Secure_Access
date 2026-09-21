// public/oauth/consent.js — Login (if needed) + consent screen for /openid/authorize
(function () {
  "use strict";

  const { store, el, toast, busy, errorMessage, rawRequest, api, mountLogin } = window.SA;
  const root   = document.getElementById("consent");
  const params = new URLSearchParams(location.search);
  const authorizationRequest = Object.fromEntries(params.entries());

  const card = (...children) => el("section", { class: "card" }, ...children);

  async function start() {
    root.replaceChildren(card(el("div", { class: "empty" }, "Checking the request…")));

    const details = await rawRequest("GET", `/api/v1/openid/consent?${params}`);
    if (!details.ok) {
      root.replaceChildren(card(
        el("h1", {}, "This sign-in request can't continue"),
        el("div", { class: "callout bad" }, errorMessage(details)),
        details.data?.redirectTo
          ? el("p", {}, el("a", { class: "btn", href: details.data.redirectTo }, "Return to the application"))
          : el("p", { class: "muted" }, "The application sent an invalid request, so you are not being redirected back to it.")));
      return;
    }

    const me = store.get() ? await api("GET", "/api/v1/auth/me") : null;
    if (me?.ok) showConsent(details.data, me.data.user);
    else showLogin(details.data);
  }

  function header(client) {
    return el("div", { class: "stack" },
      el("span", { class: "muted small" }, "Sign in with SecureAccess"),
      el("h1", {}, client.name),
      el("p", { class: "muted" }, "wants to access your SecureAccess account."));
  }

  function showLogin(details) {
    const host = el("div");
    root.replaceChildren(card(header(details.client), host));
    mountLogin(host, { onSuccess: () => start() });
  }

  function showConsent(details, user) {
    const allow = el("button", { class: "btn primary", type: "button" }, "Allow");
    const deny  = el("button", { class: "btn", type: "button" }, "Deny");

    const decide = (decision, button) => busy(button, async () => {
      const res = await api("POST", "/api/v1/openid/consent", { body: { ...authorizationRequest, decision } });
      if (!res.ok || !res.data?.redirectTo) { toast(errorMessage(res), "error"); return; }
      location.assign(res.data.redirectTo);
    });
    allow.addEventListener("click", () => decide("allow", allow));
    deny.addEventListener("click", () => decide("deny", deny));

    const redirectHost = (() => { try { return new URL(details.redirectUri).host; } catch { return details.redirectUri; } })();

    root.replaceChildren(card(
      header(details.client),
      el("div", { class: "row space callout" },
        el("span", {}, "Signed in as ", el("strong", {}, user.email)),
        el("button", { class: "link-btn", type: "button", onclick: () => { store.set(null); start(); } }, "Use another account")),
      el("h3", { style: "margin-top:1rem" }, "This will allow the app to:"),
      el("ul", { class: "scope-list" }, details.scopes.map(scope =>
        el("li", {}, el("span", { class: "chip" }, scope.name), el("span", {}, scope.description)))),
      el("p", { class: "muted small", style: "margin-top:1rem" },
        `You will be sent back to ${redirectHost}. Client ID: `, el("span", { class: "mono" }, details.client.clientId)),
      el("div", { class: "row", style: "justify-content:flex-end" }, deny, allow)));
  }

  start();
})();
