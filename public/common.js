// public/common.js — Shared browser helpers for the console and the OAuth pages.
// No framework and no build step. All DOM is created with el(), never innerHTML,
// so API data can never be interpreted as markup (XSS-safe by construction).
(function (global) {
  "use strict";

  const SESSION_KEY = "secureaccess.session";
  const OIDC_KEY    = "secureaccess.oidc";

  // Tokens live in sessionStorage: scoped to this tab, cleared when it closes.
  const storage = (key) => ({
    get() {
      try { return JSON.parse(sessionStorage.getItem(key)) || null; } catch { return null; }
    },
    set(value) {
      try {
        if (value) sessionStorage.setItem(key, JSON.stringify(value));
        else sessionStorage.removeItem(key);
      } catch { /* storage unavailable (private mode) — session lasts until reload */ }
    },
  });

  const store     = storage(SESSION_KEY);
  const oidcStore = storage(OIDC_KEY);

  // ── DOM helpers ─────────────────────────────────────────────────
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === undefined || value === null || value === false) continue;
      if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
      else if (key === "class") node.className = value;
      else if (typeof value === "boolean") node[key] = value;
      else node.setAttribute(key, value);
    }
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : String(child));
    }
    return node;
  }

  const json = (value) => el("pre", { class: "json" }, JSON.stringify(value, null, 2));

  function field(label, input, hint) {
    return el("label", { class: "field" },
      el("span", { class: "field-label" }, label),
      input,
      hint ? el("span", { class: "field-hint" }, hint) : null);
  }

  function toast(message, type = "info") {
    let host = document.getElementById("toasts");
    if (!host) {
      host = el("div", { id: "toasts", class: "toasts", "aria-live": "polite" });
      document.body.append(host);
    }
    const node = el("div", { class: `toast ${type}`, role: type === "error" ? "alert" : "status" }, message);
    host.append(node);
    setTimeout(() => node.remove(), type === "error" ? 6000 : 3500);
  }

  // Disables a button while an async action runs
  async function busy(button, fn) {
    const label = button.textContent;
    button.disabled = true;
    button.classList.add("loading");
    try {
      return await fn();
    } finally {
      button.disabled = false;
      button.classList.remove("loading");
      button.textContent = label;
    }
  }

  const fmtDate = (value) => (value ? new Date(value).toLocaleString() : "—");

  function timeAgo(value) {
    if (!value) return "never";
    const seconds = Math.round((Date.now() - new Date(value).getTime()) / 1000);
    if (seconds < 60) return "just now";
    if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
    return `${Math.floor(seconds / 86400)} d ago`;
  }

  function errorMessage(res) {
    const d = res && res.data;
    if (!d) return res && res.status ? `Request failed (HTTP ${res.status})` : "Network error";
    let message = d.message || d.error_description || d.error || `HTTP ${res.status}`;
    if (d.details && typeof d.details === "object") {
      const parts = Object.entries(d.details)
        .filter(([key]) => key !== "lockedUntil")
        .map(([key, value]) => `${key === "_errors" ? "" : key + ": "}${[].concat(value).join(", ")}`);
      if (parts.length) message += ` — ${parts.join("; ")}`;
      if (d.details.lockedUntil) message += ` (until ${new Date(d.details.lockedUntil).toLocaleTimeString()})`;
    }
    return message;
  }

  // ── Encoding / crypto helpers ───────────────────────────────────
  const b64urlToBytes = (value) => {
    const b64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  };
  const bytesToB64url = (bytes) =>
    btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  function decodeJwt(token) {
    try {
      const [header, payload] = token.split(".");
      const decode = (part) => JSON.parse(new TextDecoder().decode(b64urlToBytes(part)));
      return { header: decode(header), payload: decode(payload) };
    } catch {
      return null;
    }
  }

  const randomString = (bytes = 32) => bytesToB64url(crypto.getRandomValues(new Uint8Array(bytes)));

  async function pkcePair() {
    const verifier  = randomString(32);
    const digest    = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return { verifier, challenge: bytesToB64url(digest) };
  }

  // Verifies an RS256 JWT in the browser against the server's published JWKS
  async function verifyJwtWithJwks(token) {
    const [header, payload, signature] = token.split(".");
    const { kid } = decodeJwt(token).header;
    const res  = await rawRequest("GET", "/api/v1/openid/jwks");
    const jwk  = (res.data?.keys || []).find(k => k.kid === kid);
    if (!jwk) return { valid: false, reason: `No key with kid ${kid}` };
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5", key, b64urlToBytes(signature), new TextEncoder().encode(`${header}.${payload}`)
    );
    return { valid, kid };
  }

  // ── API client ──────────────────────────────────────────────────
  const listeners = new Set();
  const onRequest = (fn) => listeners.add(fn);

  const HIDE     = /^(password|currentpassword|newpassword|code|code_verifier|client_secret|clientsecret|backupcode|totp_code|secret|temporarypassword)$/i;
  const TRUNCATE = /^(accesstoken|access_token|refreshtoken|refresh_token|id_token|mfatoken|token|qrcode|otpauthurl|redirectto)$/i;

  // What the request log shows: secrets hidden, long tokens shortened
  function redact(value, key = "") {
    if (Array.isArray(value)) return /backupcodes/i.test(key) ? value.map(() => "••••••") : value.map(v => redact(v));
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redact(v, k)]));
    }
    if (typeof value === "string" && HIDE.test(key)) return "••••••";
    if (typeof value === "string" && TRUNCATE.test(key) && value.length > 24) return `${value.slice(0, 20)}…`;
    return value;
  }

  async function rawRequest(method, path, options = {}) {
    const { body, form, token, basic } = options;
    const init = { method, headers: {} };
    if (token) init.headers.Authorization = `Bearer ${token}`;
    if (basic) init.headers.Authorization = `Basic ${btoa(basic)}`;
    if (form) {
      init.headers["Content-Type"] = "application/x-www-form-urlencoded";
      init.body = new URLSearchParams(form).toString();
    } else if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }

    const started = performance.now();
    const entry = { method, path, at: new Date(), requestBody: redact(body ?? form ?? null) };
    let res;
    try {
      res = await fetch(path, init);
    } catch (err) {
      Object.assign(entry, { status: 0, ms: Math.round(performance.now() - started), responseBody: { error: "NETWORK_ERROR", message: err.message } });
      listeners.forEach(fn => fn(entry));
      return { ok: false, status: 0, data: { error: "NETWORK_ERROR", message: "Cannot reach the API" }, text: "", headers: new Headers() };
    }

    const type = res.headers.get("content-type") || "";
    let data = null;
    let text = "";
    if (type.includes("application/json")) data = await res.json().catch(() => null);
    else text = await res.text();

    Object.assign(entry, {
      status: res.status,
      ms: Math.round(performance.now() - started),
      requestId: res.headers.get("x-request-id"),
      responseBody: data !== null ? redact(data) : (text.length > 400 ? `${text.slice(0, 400)}…` : text),
    });
    listeners.forEach(fn => fn(entry));
    return { ok: res.ok, status: res.status, data, text, headers: res.headers };
  }

  let refreshing = null;

  async function refreshSession() {
    if (refreshing) return refreshing;
    refreshing = (async () => {
      const session = store.get();
      if (!session?.refreshToken) return false;
      const res = await rawRequest("POST", "/api/v1/auth/refresh", { body: { refreshToken: session.refreshToken } });
      if (!res.ok) {
        store.set(null);
        return false;
      }
      saveSession(res.data);
      return true;
    })();
    try {
      return await refreshing;
    } finally {
      refreshing = null;
    }
  }

  function saveSession(data) {
    store.set({
      accessToken:  data.accessToken,
      refreshToken: data.refreshToken,
      expiresAt:    Date.now() + (data.expiresIn || 900) * 1000,
    });
  }

  // Authenticated request that transparently refreshes an expired access token once
  async function api(method, path, options = {}) {
    const session = store.get();
    const res = await rawRequest(method, path, { ...options, token: session?.accessToken });
    if (res.status === 401 && res.data?.error === "INVALID_TOKEN" && !options.retried && await refreshSession()) {
      return api(method, path, { ...options, retried: true });
    }
    return res;
  }

  // ── Request log widget ──────────────────────────────────────────
  function mountRequestLog(list) {
    onRequest(entry => {
      const statusClass = entry.status >= 500 || entry.status === 0 ? "bad" : entry.status >= 400 ? "warn" : "ok";
      const item = el("li", { class: "log-item" },
        el("details", {},
          el("summary", {},
            el("span", { class: `method m-${entry.method.toLowerCase()}` }, entry.method),
            el("span", { class: "log-path" }, entry.path.replace(/\?.*$/, (q) => q.length > 40 ? "?…" : q)),
            el("span", { class: `status ${statusClass}` }, entry.status || "ERR"),
            el("span", { class: "log-ms" }, `${entry.ms} ms`)),
          el("div", { class: "log-body" },
            entry.requestId ? el("div", { class: "muted small" }, `X-Request-Id: ${entry.requestId}`) : null,
            entry.requestBody ? [el("div", { class: "log-label" }, "Request"), json(entry.requestBody)] : null,
            el("div", { class: "log-label" }, "Response"),
            typeof entry.responseBody === "string" ? el("pre", { class: "json" }, entry.responseBody || "(empty)") : json(entry.responseBody))));
      list.prepend(item);
      while (list.children.length > 60) list.lastElementChild.remove();
    });
  }

  // ── Login widget (password step + MFA step), used by console and consent page ──
  const DEMO_ACCOUNTS = [
    { label: "Auditor demo", note: "read-only admin", email: "auditor@secureaccess.dev", password: "Auditor!Demo#2026" },
    { label: "User demo",    note: "self-service",    email: "demo@secureaccess.dev",    password: "DemoUser!Try#2026" },
  ];

  function mountLogin(container, { onSuccess }) {
    const email    = el("input", { type: "email", name: "email", autocomplete: "username", required: true, placeholder: "you@example.com" });
    const password = el("input", { type: "password", name: "password", autocomplete: "current-password", required: true, placeholder: "••••••••••••" });
    const submit   = el("button", { class: "btn primary block", type: "submit" }, "Sign in");

    const passwordForm = el("form", { class: "stack" },
      field("Email", email),
      field("Password", password),
      submit,
      el("div", { class: "demo-accounts" },
        el("span", { class: "muted small" }, "Try a protected demo account:"),
        DEMO_ACCOUNTS.map(acc => el("button", {
          type: "button", class: "chip-btn", title: acc.email,
          onclick: () => { email.value = acc.email; password.value = acc.password; submit.focus(); },
        }, acc.label, el("span", { class: "muted" }, ` · ${acc.note}`)))));

    passwordForm.addEventListener("submit", (event) => {
      event.preventDefault();
      busy(submit, async () => {
        const res = await rawRequest("POST", "/api/v1/auth/login", { body: { email: email.value, password: password.value } });
        if (res.status === 200) return finish(res.data);
        if (res.status === 202) return showMfa(res.data.mfaToken);
        toast(errorMessage(res), "error");
      });
    });

    function showMfa(mfaToken) {
      let useBackup = false;
      const code     = el("input", { name: "code", inputmode: "numeric", autocomplete: "one-time-code", placeholder: "123456", maxlength: "6", required: true });
      // Unticked by default: the code is asked on every sign-in unless the user opts in
      const remember = el("input", { type: "checkbox" });
      const verify   = el("button", { class: "btn primary block", type: "submit" }, "Verify");
      const codeField = field("6-digit code from your authenticator app", code);
      const toggle = el("button", {
        type: "button", class: "link-btn",
        onclick: () => {
          useBackup = !useBackup;
          codeField.querySelector(".field-label").textContent = useBackup ? "Backup code" : "6-digit code from your authenticator app";
          code.placeholder = useBackup ? "A1B2C3D4E5" : "123456";
          code.maxLength   = useBackup ? 20 : 6;
          code.value = "";
          toggle.textContent = useBackup ? "Use authenticator code instead" : "Use a backup code instead";
          code.focus();
        },
      }, "Use a backup code instead");

      const mfaForm = el("form", { class: "stack" },
        el("div", { class: "callout" }, el("strong", {}, "Multi-factor authentication"), el("p", {}, "Your password was correct. Enter a code to finish signing in.")),
        codeField,
        el("label", { class: "check" }, remember, " Remember this device for 30 days (skip the code here)"),
        verify,
        el("div", { class: "row space" }, toggle, el("button", { type: "button", class: "link-btn", onclick: () => container.replaceChildren(passwordForm) }, "← Back")));

      mfaForm.addEventListener("submit", (event) => {
        event.preventDefault();
        busy(verify, async () => {
          const body = { mfaToken, rememberDevice: remember.checked, ...(useBackup ? { backupCode: code.value } : { code: code.value }) };
          const res = await rawRequest("POST", "/api/v1/auth/login/mfa", { body });
          if (res.ok) return finish(res.data);
          toast(errorMessage(res), "error");
          if (res.data?.error === "INVALID_MFA_TOKEN") container.replaceChildren(passwordForm);
        });
      });

      container.replaceChildren(mfaForm);
      code.focus();
    }

    function finish(data) {
      saveSession(data);
      toast(`Signed in as ${data.user.email}`, "success");
      if (data.mfa === "trusted_device") {
        toast(`No MFA code asked: this device is remembered until ${new Date(data.device.trustedUntil).toLocaleDateString()}. Forget it under Devices & sessions.`);
      }
      onSuccess(data);
    }

    container.replaceChildren(passwordForm);
  }

  global.SA = {
    store, oidcStore, el, json, field, toast, busy, fmtDate, timeAgo, errorMessage,
    decodeJwt, randomString, pkcePair, verifyJwtWithJwks,
    rawRequest, api, refreshSession, saveSession, onRequest, mountRequestLog, mountLogin,
  };
})(window);
