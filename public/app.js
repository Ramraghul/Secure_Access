// public/app.js — SecureAccess interactive console
(function () {
  "use strict";

  const {
    store, oidcStore, el, json, field, toast, busy, fmtDate, timeAgo, errorMessage, decodeJwt, pkcePair,
    randomString, rawRequest, api, refreshSession, mountRequestLog, mountLogin,
  } = window.SA;

  const main  = document.getElementById("main");
  const state = { me: null, tab: "overview", timers: [] };

  mountRequestLog(document.getElementById("log"));
  document.getElementById("clear-log").addEventListener("click", () => document.getElementById("log").replaceChildren());

  // ── Permissions (mirrors src/utils/permissions.ts) ──────────────
  function can(permission) {
    const [action, resource] = permission.split(":");
    return (state.me?.user.permissions || []).some(p => {
      const [a, r] = p.split(":");
      return (a === action || a === "manage") && (r === resource || r === "*");
    });
  }

  const ACTIONS   = ["create", "read", "update", "delete", "manage", "export"];
  const RESOURCES = ["user", "role", "user-role", "audit", "client", "*"];

  // ── Small UI builders ───────────────────────────────────────────
  const card = (title, subtitle, ...body) => el("section", { class: "card" },
    el("div", { class: "card-head" }, el("h2", {}, title), subtitle ? el("span", { class: "muted small" }, subtitle) : null),
    ...body);

  const badge = (text, tone = "") => el("span", { class: `badge ${tone}` }, text);
  const chips = (items) => items.length
    ? el("div", { class: "chips" }, items.map(i => el("span", { class: "chip" }, i)))
    : el("span", { class: "muted small" }, "none");

  function table(headers, rows, emptyText = "Nothing here yet") {
    if (!rows.length) return el("div", { class: "table-wrap" }, el("div", { class: "empty" }, emptyText));
    return el("div", { class: "table-wrap" },
      el("table", {}, el("thead", {}, el("tr", {}, headers.map(h => el("th", {}, h)))), el("tbody", {}, rows)));
  }

  const loading = () => el("div", { class: "empty" }, "Loading…");

  function clearTimers() {
    state.timers.forEach(clearInterval);
    state.timers = [];
  }

  async function act(button, fn, successMessage) {
    return busy(button, async () => {
      const res = await fn();
      if (!res.ok) { toast(errorMessage(res), "error"); return null; }
      if (successMessage) toast(typeof successMessage === "function" ? successMessage(res) : successMessage, "success");
      return res;
    });
  }

  // ── Health indicator ────────────────────────────────────────────
  async function checkHealth() {
    const pill = document.getElementById("health");
    try {
      const data = await (await fetch("/health")).json();
      pill.textContent = data.status === "ok" ? `API online · v${data.version}` : "Database unavailable";
      pill.className = `pill ${data.status === "ok" ? "ok" : "warn"}`;
    } catch {
      pill.textContent = "API offline";
      pill.className = "pill bad";
    }
  }

  // ── Session lifecycle ───────────────────────────────────────────
  async function loadMe() {
    const res = await api("GET", "/api/v1/auth/me");
    if (!res.ok) {
      store.set(null);
      state.me = null;
      return false;
    }
    state.me = res.data;
    return true;
  }

  function signOutLocally(message) {
    store.set(null);
    state.me = null;
    if (message) toast(message);
    render();
  }

  async function render() {
    clearTimers();
    if (store.get() && !state.me) {
      main.replaceChildren(loading());
      await loadMe();
    }
    if (state.me) renderDashboard(); else renderAuth();
  }

  // ── Signed-out screen ───────────────────────────────────────────
  function renderAuth() {
    const loginHost = el("div");
    const registerHost = el("div");
    let mode = "login";

    const loginTab    = el("button", { class: "tab active", type: "button", onclick: () => switchMode("login") }, "Sign in");
    const registerTab = el("button", { class: "tab", type: "button", onclick: () => switchMode("register") }, "Create account");
    const body = el("div");

    function switchMode(next) {
      mode = next;
      loginTab.classList.toggle("active", mode === "login");
      registerTab.classList.toggle("active", mode === "register");
      body.replaceChildren(mode === "login" ? loginHost : registerHost);
    }

    mountLogin(loginHost, { onSuccess: async () => { await loadMe(); state.tab = "overview"; render(); } });
    registerHost.append(registerForm(email => {
      switchMode("login");
      const input = loginHost.querySelector("input[type=email]");
      if (input) input.value = email;
      loginHost.querySelector("input[type=password]")?.focus();
    }));
    switchMode("login");

    main.replaceChildren(el("div", { class: "auth-wrap" },
      el("section", { class: "hero" },
        el("h1", {}, "Identity & access, end to end"),
        el("p", { class: "muted" }, "SecureAccess is a TypeScript + Express + PostgreSQL identity backend. This console calls its real API — watch every request in the log."),
        el("ul", { class: "feature-list" },
          el("li", {}, el("span", {}, el("strong", {}, "Login hardening"), " — bcrypt, account lockout, constant-time user lookup")),
          el("li", {}, el("span", {}, el("strong", {}, "TOTP MFA"), " — QR enrolment, one-time backup codes, replay protection, trusted devices")),
          el("li", {}, el("span", {}, el("strong", {}, "Sessions"), " — 15-minute JWTs, rotating refresh tokens with reuse detection, sign-out everywhere")),
          el("li", {}, el("span", {}, el("strong", {}, "RBAC"), " — roles made of action:resource permissions with manage and * wildcards")),
          el("li", {}, el("span", {}, el("strong", {}, "Audit trail"), " — every request recorded with secrets masked; search and CSV export")),
          el("li", {}, el("span", {}, el("strong", {}, "OpenID Connect provider"), " — Authorization Code + PKCE, RS256 id_tokens, JWKS, UserInfo"))),
        el("p", { class: "muted small" }, "Demo accounts are protected: you can explore everything, but their credentials cannot be changed.")),
      el("section", { class: "card" },
        el("nav", { class: "tabs" }, loginTab, registerTab),
        body)));
  }

  const PASSWORD_RULES = [
    ["12+ characters", pw => pw.length >= 12],
    ["Uppercase letter", pw => /[A-Z]/.test(pw)],
    ["Lowercase letter", pw => /[a-z]/.test(pw)],
    ["Number", pw => /\d/.test(pw)],
    ["Symbol", pw => /[^A-Za-z0-9\s]/.test(pw)],
    ["No 4 repeated characters", pw => pw.length > 0 && !/(.)\1{3,}/.test(pw)],
  ];

  function passwordInput(name, autocomplete) {
    const input = el("input", { type: "password", name, autocomplete, required: true, minlength: "12" });
    const rules = el("ul", { class: "pw-rules" }, PASSWORD_RULES.map(([label]) => el("li", {}, label)));
    input.addEventListener("input", () => {
      PASSWORD_RULES.forEach(([, test], i) => rules.children[i].classList.toggle("met", test(input.value)));
    });
    return { input, rules };
  }

  function registerForm(onRegistered) {
    const firstName = el("input", { name: "firstName", autocomplete: "given-name", required: true });
    const lastName  = el("input", { name: "lastName", autocomplete: "family-name", required: true });
    const email     = el("input", { type: "email", name: "email", autocomplete: "email", required: true });
    const pw        = passwordInput("password", "new-password");
    const submit    = el("button", { class: "btn primary block", type: "submit" }, "Create account");

    const form = el("form", { class: "stack" },
      el("div", { class: "grid-2" }, field("First name", firstName), field("Last name", lastName)),
      field("Email", email),
      field("Password", pw.input),
      pw.rules,
      submit);

    form.addEventListener("submit", event => {
      event.preventDefault();
      act(submit, () => rawRequest("POST", "/api/v1/auth/register", {
        body: { firstName: firstName.value, lastName: lastName.value, email: email.value, password: pw.input.value },
      }), "Account created — you can sign in now").then(res => res && onRegistered(email.value));
    });
    return form;
  }

  // ── Signed-in dashboard ─────────────────────────────────────────
  const VIEWS = {
    overview: ["Overview", () => true, renderOverview],
    security: ["Security & MFA", () => true, renderSecurity],
    devices:  ["Devices & sessions", () => true, renderDevices],
    users:    ["Users", () => can("read:user"), renderUsers],
    roles:    ["Roles", () => can("read:role"), renderRoles],
    audit:    ["Audit log", () => can("read:audit"), renderAudit],
    oidc:     ["OpenID Connect", () => true, renderOidc],
  };

  function renderDashboard() {
    clearTimers();
    const { user } = state.me;
    const visible = Object.entries(VIEWS).filter(([, [, allowed]]) => allowed());
    if (!visible.some(([id]) => id === state.tab)) state.tab = "overview";

    const initials = `${user.firstName[0] || ""}${user.lastName[0] || ""}`.toUpperCase();
    const userBar = el("div", { class: "user-bar" },
      el("div", { class: "avatar", "aria-hidden": "true" }, initials),
      el("div", { class: "who" },
        el("strong", {}, `${user.firstName} ${user.lastName}`),
        el("span", { class: "muted small" }, user.email)),
      el("div", { class: "chips" }, user.roles.map(r => badge(r, "accent")), user.mfaEnabled ? badge("MFA on", "ok") : badge("MFA off", "warn"),
        user.isProtected ? badge("protected demo") : null),
      el("div", { class: "actions row" },
        el("button", { class: "btn sm", type: "button", onclick: e => logout(e.currentTarget, false) }, "Sign out"),
        el("button", { class: "btn sm danger", type: "button", onclick: e => logout(e.currentTarget, true) }, "Sign out everywhere")));

    const banners = [];
    if (user.mustChangePassword) {
      banners.push(el("div", { class: "callout warn" }, el("strong", {}, "Password change required. "),
        "An administrator reset your password. Choose a new one under Security & MFA."));
    }

    const panel = el("div", { class: "panel" });
    const tabs = el("nav", { class: "tabs", role: "tablist" }, visible.map(([id, [label]]) =>
      el("button", {
        class: `tab ${state.tab === id ? "active" : ""}`, role: "tab", type: "button",
        "aria-selected": String(state.tab === id),
        onclick: () => { state.tab = id; renderDashboard(); },
      }, label)));

    main.replaceChildren(userBar, ...banners, tabs, panel);
    VIEWS[state.tab][2](panel);
  }

  async function logout(button, everywhere) {
    const res = await act(button, () => api("POST", everywhere ? "/api/v1/auth/logout-all" : "/api/v1/auth/logout"));
    if (res || !store.get()) signOutLocally(everywhere ? `Signed out of ${res?.data.revokedSessions ?? "all"} session(s)` : "Signed out");
  }

  // ── Overview ────────────────────────────────────────────────────
  function renderOverview(panel) {
    const { user, devices } = state.me;
    const session = store.get();
    const decoded = decodeJwt(session.accessToken);

    const countdown = el("strong", {});
    const tick = () => {
      const seconds = Math.max(0, Math.round((session.expiresAt - Date.now()) / 1000));
      countdown.textContent = seconds > 0 ? `${Math.floor(seconds / 60)}m ${String(seconds % 60).padStart(2, "0")}s` : "expired — the next call refreshes it";
    };
    tick();
    state.timers.push(setInterval(tick, 1000));

    panel.replaceChildren(
      el("div", { class: "grid-2" },
        card("Identity", `member since ${new Date(user.createdAt).toLocaleDateString()}`,
          el("div", { class: "stack" },
            el("div", {}, el("div", { class: "field-label" }, "Roles"), chips(user.roles)),
            el("div", {}, el("div", { class: "field-label" }, "Effective permissions"), chips(user.permissions)),
            el("div", { class: "grid-stats" },
              el("div", { class: "stat" }, el("div", { class: "stat-value" }, user.mfaEnabled ? "On" : "Off"), el("div", { class: "stat-label" }, "Multi-factor auth")),
              el("div", { class: "stat" }, el("div", { class: "stat-value" }, devices.length), el("div", { class: "stat-label" }, "Known devices")),
              el("div", { class: "stat" }, el("div", { class: "stat-value" }, timeAgo(user.lastLoginAt)), el("div", { class: "stat-label" }, "Last login"))),
            user.permissions.length === 0
              ? el("p", { class: "muted small" }, "Standard users manage only their own account. Sign in as the auditor demo to see the admin tabs.")
              : null)),
        card("Access token", "HS512 JWT",
          el("div", { class: "stack" },
            el("div", { class: "row space" }, el("span", {}, "Expires in ", countdown),
              el("div", { class: "row" },
                el("button", {
                  class: "btn sm", type: "button",
                  onclick: e => busy(e.currentTarget, async () => {
                    if (await refreshSession()) { toast("Tokens rotated — the old refresh token is now invalid", "success"); renderDashboard(); }
                    else signOutLocally("Session expired");
                  }),
                }, "Rotate tokens"),
                el("button", {
                  class: "btn sm", type: "button",
                  onclick: () => navigator.clipboard.writeText(store.get().accessToken).then(() => toast("Access token copied — paste it into Swagger's Authorize dialog", "success")),
                }, "Copy token"))),
            el("div", { class: "field-label" }, "Decoded claims"),
            json(decoded ? decoded.payload : {}),
            el("p", { class: "muted small" }, "sid links the token to a server-side session, so signing out takes effect immediately even though the JWT has not expired.")))));
  }

  // ── Security & MFA ──────────────────────────────────────────────
  function renderSecurity(panel) {
    const { user } = state.me;
    const protectedNote = user.isProtected
      ? el("div", { class: "callout warn" }, "This is a protected demo account — these forms show how the API refuses changes (403 PROTECTED_ACCOUNT).")
      : null;

    // Profile
    const firstName = el("input", { value: user.firstName, required: true });
    const lastName  = el("input", { value: user.lastName, required: true });
    const saveProfile = el("button", { class: "btn primary", type: "submit" }, "Save");
    const profileForm = el("form", { class: "inline-form" }, field("First name", firstName), field("Last name", lastName), saveProfile);
    profileForm.addEventListener("submit", e => {
      e.preventDefault();
      act(saveProfile, () => api("PATCH", "/api/v1/auth/me", { body: { firstName: firstName.value, lastName: lastName.value } }), "Profile updated")
        .then(async res => { if (res) { await loadMe(); renderDashboard(); } });
    });

    // Password
    const current = el("input", { type: "password", autocomplete: "current-password", required: true });
    const next = passwordInput("newPassword", "new-password");
    const changeBtn = el("button", { class: "btn primary", type: "submit" }, "Change password");
    const passwordForm = el("form", { class: "stack" }, field("Current password", current), field("New password", next.input), next.rules, el("div", {}, changeBtn));
    passwordForm.addEventListener("submit", e => {
      e.preventDefault();
      act(changeBtn, () => api("POST", "/api/v1/auth/change-password", { body: { currentPassword: current.value, newPassword: next.input.value } }),
        res => `Password changed — ${res.data.revokedSessions} other session(s) signed out`)
        .then(async res => { if (res) { await loadMe(); renderDashboard(); } });
    });

    const mfaCard = card("Multi-factor authentication", user.mfaEnabled ? "enabled" : "disabled");
    user.mfaEnabled ? renderMfaDisable(mfaCard) : renderMfaEnable(mfaCard);

    panel.replaceChildren(
      protectedNote || "",
      el("div", { class: "grid-2" },
        el("div", {}, card("Profile", null, profileForm), card("Password", "signs out your other sessions", passwordForm)),
        mfaCard));
  }

  function renderMfaEnable(container) {
    const start = el("button", { class: "btn primary", type: "button" }, "Set up authenticator app");
    const body = el("div", { class: "stack" },
      el("p", {}, "Protect the account with a time-based one-time code (Google Authenticator, 1Password, Authy…)."),
      el("div", {}, start));
    container.append(body);

    start.addEventListener("click", () => act(start, () => api("POST", "/api/v1/auth/mfa/setup")).then(res => {
      if (!res) return;
      const { qrCode, secret, backupCodes } = res.data;
      const code = el("input", { inputmode: "numeric", maxlength: "6", placeholder: "123456", required: true, autocomplete: "one-time-code" });
      const verifyBtn = el("button", { class: "btn primary", type: "submit" }, "Verify & enable");
      const verifyForm = el("form", { class: "inline-form" }, field("Code from the app", code), verifyBtn);
      verifyForm.addEventListener("submit", e => {
        e.preventDefault();
        act(verifyBtn, () => api("POST", "/api/v1/auth/mfa/verify", { body: { token: code.value } }), "MFA enabled — all devices must pass MFA once")
          .then(async ok => { if (ok) { await loadMe(); renderDashboard(); } });
      });

      body.replaceChildren(
        el("ol", { class: "steps" },
          el("li", {}, el("div", { class: "stack" }, el("strong", {}, "Scan the QR code"),
            el("img", { class: "qr", src: qrCode, alt: "QR code for your authenticator app" }),
            el("span", { class: "muted small" }, "Or enter this key manually:"),
            el("div", { class: "secret-box" }, secret))),
          el("li", {}, el("div", { class: "stack" }, el("strong", {}, "Save your backup codes"),
            el("span", { class: "muted small" }, "Each works once if you lose your phone. They are stored only as bcrypt hashes and will not be shown again."),
            el("div", { class: "backup-codes" }, backupCodes.map(c => el("span", {}, c))))),
          el("li", {}, el("div", { class: "stack" }, el("strong", {}, "Confirm with a code"), verifyForm))));
      code.focus();
    }));
  }

  function renderMfaDisable(container) {
    const password = el("input", { type: "password", autocomplete: "current-password", required: true });
    const code = el("input", { placeholder: "123456 or a backup code", required: true, autocomplete: "one-time-code" });
    const btn = el("button", { class: "btn danger", type: "submit" }, "Disable MFA");
    const form = el("form", { class: "stack" },
      el("div", { class: "callout ok" }, "Sign-ins from untrusted devices require a code."),
      field("Password", password), field("Authenticator or backup code", code), el("div", {}, btn));
    form.addEventListener("submit", e => {
      e.preventDefault();
      const value = code.value.trim();
      const factor = /^\d{6}$/.test(value) ? { code: value } : { backupCode: value };
      act(btn, () => api("POST", "/api/v1/auth/mfa/disable", { body: { password: password.value, ...factor } }), "MFA disabled")
        .then(async res => { if (res) { await loadMe(); renderDashboard(); } });
    });
    container.append(form);
  }

  // ── Devices & sessions ──────────────────────────────────────────
  async function renderDevices(panel) {
    const currentHost  = card("This device", "how the server identifies you");
    const devicesHost  = card("Devices", "a trusted device skips the MFA code for 30 days");
    const sessionsHost = card("Active sessions", "one per sign-in; OIDC apps included");
    currentHost.append(loading());
    devicesHost.append(loading());
    sessionsHost.append(loading());
    panel.replaceChildren(currentHost, devicesHost, sessionsHost);

    const [current, devices, sessions] = await Promise.all([
      api("GET", "/api/v1/devices/current"),
      api("GET", "/api/v1/devices"),
      api("GET", "/api/v1/auth/sessions"),
    ]);

    if (current.ok) {
      const d = current.data.currentDevice;
      currentHost.lastChild.replaceWith(el("div", { class: "grid-stats" },
        el("div", { class: "stat" }, el("div", { class: "stat-label" }, "Detected as"), el("strong", {}, d.name)),
        el("div", { class: "stat" }, el("div", { class: "stat-label" }, "IP address"), el("strong", {}, d.ipAddress)),
        el("div", { class: "stat" }, el("div", { class: "stat-label" }, "Trust"), d.isTrusted ? badge(`trusted until ${fmtDate(d.trustedUntil)}`, "ok") : badge("not trusted", "warn")),
        el("div", { class: "stat" }, el("div", { class: "stat-label" }, "Fingerprint (SHA-256)"), el("span", { class: "mono" }, `${d.fingerprint.slice(0, 24)}…`))));
    }

    if (devices.ok) {
      devicesHost.lastChild.replaceWith(table(["Device", "Trust", "Sessions", "Last used", ""],
        devices.data.devices.map(d => el("tr", {},
          el("td", {}, d.deviceName, d.current ? el("span", {}, " ", badge("this device", "accent")) : null, el("span", { class: "sub" }, d.ipAddress)),
          el("td", {}, d.isTrusted ? [badge("trusted", "ok"), el("span", { class: "sub" }, `until ${fmtDate(d.trustedUntil)}`)] : badge("untrusted")),
          el("td", {}, d.activeSessions),
          el("td", {}, timeAgo(d.lastUsedAt)),
          el("td", { class: "actions" },
            d.isTrusted
              ? el("button", {
                  class: "btn sm", type: "button",
                  onclick: e => act(e.currentTarget, () => api("POST", `/api/v1/devices/${d.id}/revoke`), "Trust removed — the MFA code will be asked on this device")
                    .then(res => res && renderDevices(panel)),
                }, "Untrust")
              : el("button", {
                  class: "btn sm", type: "button",
                  disabled: !state.me.user.mfaEnabled,
                  title: state.me.user.mfaEnabled ? "Skip the MFA code on this device for 30 days" : "Enable MFA first — trust only skips the MFA code",
                  onclick: e => {
                    const value = (prompt("Enter a code from your authenticator app (or a backup code) to trust this device for 30 days:") || "").trim();
                    if (!value) return;
                    const factor = /^[0-9]{6}$/.test(value) ? { code: value } : { backupCode: value };
                    act(e.currentTarget, () => api("POST", `/api/v1/devices/${d.id}/trust`, { body: factor }), r => `Device trusted until ${fmtDate(r.data.trustedUntil)}`)
                      .then(res => res && renderDevices(panel));
                  },
                }, "Trust"),
            " ",
            el("button", {
              class: "btn sm danger", type: "button",
              onclick: e => confirm(`Forget "${d.deviceName}" and sign out its sessions?`) &&
                act(e.currentTarget, () => api("DELETE", `/api/v1/devices/${d.id}`), "Device removed")
                  .then(res => { if (!res) return; d.current ? signOutLocally("This device was removed") : renderDevices(panel); }),
            }, "Remove"))))));
    }

    if (sessions.ok) {
      sessionsHost.lastChild.replaceWith(table(["Session", "Where", "Started", "Expires", ""],
        sessions.data.sessions.map(s => el("tr", {},
          el("td", {}, s.type === "oidc" ? badge(`OIDC · ${s.clientName}`, "accent") : badge("console / API"), s.current ? el("span", {}, " ", badge("current", "ok")) : null,
            s.scope ? el("span", { class: "sub" }, s.scope) : null),
          el("td", {}, s.device?.deviceName || "—", el("span", { class: "sub" }, s.ipAddress)),
          el("td", {}, timeAgo(s.createdAt)),
          el("td", {}, fmtDate(s.expiresAt)),
          el("td", { class: "actions" }, el("button", {
            class: "btn sm danger", type: "button",
            onclick: e => act(e.currentTarget, () => api("DELETE", `/api/v1/auth/sessions/${s.id}`), "Session revoked")
              .then(res => { if (!res) return; s.current ? signOutLocally("You revoked this session") : renderDevices(panel); }),
          }, "Revoke"))))));
    }
  }

  // ── Users (admin) ───────────────────────────────────────────────
  function renderUsers(panel) {
    const query = { page: 1, search: "", status: "" };
    const search = el("input", { type: "search", placeholder: "Search name or email" });
    const status = el("select", {}, el("option", { value: "" }, "All statuses"), el("option", { value: "active" }, "Active"), el("option", { value: "inactive" }, "Inactive"));
    const go = el("button", { class: "btn", type: "submit" }, "Search");
    const filters = el("form", { class: "inline-form" }, search, status, go);
    const results = el("div", {}, loading());
    const result  = el("div");

    filters.addEventListener("submit", e => {
      e.preventDefault();
      Object.assign(query, { page: 1, search: search.value.trim(), status: status.value });
      load();
    });

    panel.replaceChildren(card("Users", can("update:user") ? "manage accounts" : "read-only", el("div", { class: "stack" }, filters, result, results)));

    async function load() {
      const params = new URLSearchParams({ page: query.page, limit: 10 });
      if (query.search) params.set("search", query.search);
      if (query.status) params.set("status", query.status);
      const res = await api("GET", `/api/v1/users?${params}`);
      if (!res.ok) { results.replaceChildren(el("div", { class: "callout bad" }, errorMessage(res))); return; }

      const { data, pagination } = res.data;
      const self = state.me.user.id;
      results.replaceChildren(
        table(["User", "Status", "Roles", "Last login", ""], data.map(u => {
          const locked = u.lockedUntil && new Date(u.lockedUntil) > new Date();
          const actions = [];
          if (can("update:user") && u.id !== self) {
            actions.push(el("button", {
              class: "btn sm", type: "button",
              onclick: e => act(e.currentTarget, () => api("POST", `/api/v1/users/${u.id}/${u.isActive ? "deactivate" : "activate"}`),
                u.isActive ? "User deactivated and signed out" : "User activated").then(r => r && load()),
            }, u.isActive ? "Deactivate" : "Activate"));
          }
          if (can("manage:user")) {
            actions.push(el("button", {
              class: "btn sm", type: "button",
              onclick: e => confirm(`Issue a temporary password for ${u.email}? Their sessions will be revoked.`) &&
                act(e.currentTarget, () => api("POST", `/api/v1/users/${u.id}/reset-password`)).then(r => {
                  if (!r) return;
                  result.replaceChildren(el("div", { class: "callout warn" },
                    el("strong", {}, `Temporary password for ${u.email}: `), el("span", { class: "mono" }, r.data.temporaryPassword),
                    el("p", { class: "small" }, "Shown once. The user must change it after signing in.")));
                  load();
                }),
            }, "Reset password"));
          }
          if (can("delete:user") && u.id !== self) {
            actions.push(el("button", {
              class: "btn sm danger", type: "button",
              onclick: e => confirm(`Permanently delete ${u.email}?`) &&
                act(e.currentTarget, () => api("DELETE", `/api/v1/users/${u.id}`), "User deleted").then(r => r && load()),
            }, "Delete"));
          }
          return el("tr", {},
            el("td", {}, `${u.firstName} ${u.lastName}`, el("span", { class: "sub" }, u.email)),
            el("td", {}, el("div", { class: "chips" },
              u.isActive ? badge("active", "ok") : badge("inactive", "bad"),
              locked ? badge("locked", "warn") : null,
              u.mfaEnabled ? badge("MFA", "ok") : null,
              u.isProtected ? badge("protected") : null,
              u.mustChangePassword ? badge("must change pw", "warn") : null)),
            el("td", {}, chips(u.roles.map(r => r.role.name))),
            el("td", {}, timeAgo(u.lastLoginAt)),
            el("td", { class: "actions" }, actions.flatMap((a, i) => i ? [" ", a] : [a])));
        }), "No users match"),
        el("div", { class: "row space" },
          el("span", { class: "muted small" }, `${pagination.total} user(s) · page ${pagination.page} of ${Math.max(1, pagination.totalPages)}`),
          el("div", { class: "row" },
            el("button", { class: "btn sm", type: "button", disabled: pagination.page <= 1, onclick: () => { query.page--; load(); } }, "← Prev"),
            el("button", { class: "btn sm", type: "button", disabled: pagination.page >= pagination.totalPages, onclick: () => { query.page++; load(); } }, "Next →"))));
    }

    load();
  }

  // ── Roles (admin) ───────────────────────────────────────────────
  function permissionMatrix(selected = []) {
    const set = new Set(selected.map(p => `${p.action}:${p.resource}`));
    const boxes = [];
    const tableEl = el("div", { class: "table-wrap" }, el("table", { class: "perm-matrix" },
      el("thead", {}, el("tr", {}, el("th", {}, "Resource"), ACTIONS.map(a => el("th", {}, a)))),
      el("tbody", {}, RESOURCES.map(resource => el("tr", {},
        el("td", {}, el("span", { class: "chip" }, resource)),
        ACTIONS.map(action => {
          const box = el("input", { type: "checkbox", checked: set.has(`${action}:${resource}`), "aria-label": `${action} ${resource}` });
          boxes.push({ box, action, resource });
          return el("td", {}, box);
        }))))));
    return { element: tableEl, value: () => boxes.filter(b => b.box.checked).map(({ action, resource }) => ({ action, resource })) };
  }

  async function resolveUserId(input) {
    const value = input.trim();
    if (/^[0-9a-f-]{36}$/i.test(value)) return value;
    if (!can("read:user")) return null;
    const res = await api("GET", `/api/v1/users?search=${encodeURIComponent(value)}&limit=20`);
    return res.ok ? res.data.data.find(u => u.email.toLowerCase() === value.toLowerCase())?.id ?? null : null;
  }

  async function renderRoles(panel) {
    panel.replaceChildren(loading());
    const res = await api("GET", "/api/v1/roles");
    if (!res.ok) { panel.replaceChildren(el("div", { class: "callout bad" }, errorMessage(res))); return; }
    const roles = res.data;
    const sections = [];

    if (can("create:role")) {
      const name = el("input", { placeholder: "support", required: true, pattern: "[a-z0-9][a-z0-9_-]*" });
      const description = el("input", { placeholder: "What this role is for" });
      const matrix = permissionMatrix([{ action: "read", resource: "user" }]);
      const create = el("button", { class: "btn primary", type: "submit" }, "Create role");
      const form = el("form", { class: "stack" },
        el("div", { class: "grid-2" }, field("Name", name, "lowercase, digits, - or _"), field("Description", description)),
        el("div", { class: "field-label" }, "Permissions"), matrix.element,
        el("p", { class: "muted small" }, "manage = every action on that resource · * = every resource"),
        el("div", {}, create));
      form.addEventListener("submit", e => {
        e.preventDefault();
        act(create, () => api("POST", "/api/v1/roles", { body: { name: name.value, description: description.value || undefined, permissions: matrix.value() } }), "Role created")
          .then(r => r && renderRoles(panel));
      });
      sections.push(el("details", { class: "card" }, el("summary", {}, el("strong", {}, "＋ Create a role")), el("div", { class: "stack", style: "margin-top:.75rem" }, form)));
    }

    if (can("manage:user-role")) {
      const roleSelect = el("select", {}, roles.map(r => el("option", { value: r.id }, r.name)));
      const userInput = el("input", { placeholder: "user@example.com or user ID", required: true });
      const assign = el("button", { class: "btn primary", type: "submit" }, "Assign");
      const form = el("form", { class: "inline-form" }, field("Role", roleSelect), field("User", userInput), assign);
      form.addEventListener("submit", async e => {
        e.preventDefault();
        const userId = await resolveUserId(userInput.value);
        if (!userId) { toast("User not found — enter an exact email or a user ID", "error"); return; }
        act(assign, () => api("POST", `/api/v1/roles/${roleSelect.value}/assign`, { body: { userId } }), "Role assigned").then(r => r && renderRoles(panel));
      });
      sections.push(card("Assign a role", "takes effect on the user's next request", form));
    }

    const roleCards = roles.map(role => {
      const body = el("div", { class: "stack" },
        role.description ? el("p", { class: "muted" }, role.description) : null,
        el("div", {}, el("div", { class: "field-label" }, "Permissions"), chips(role.permissions.map(p => `${p.action}:${p.resource}`))),
        el("div", {}, el("div", { class: "field-label" }, `Members (${role.users.length})`),
          role.users.length
            ? el("div", { class: "chips" }, role.users.map(({ user }) => el("span", { class: "chip" }, user.email,
                can("manage:user-role") ? el("button", {
                  class: "link-btn", type: "button", title: `Revoke ${role.name} from ${user.email}`, "aria-label": `Revoke from ${user.email}`,
                  onclick: e => confirm(`Revoke "${role.name}" from ${user.email}?`) &&
                    act(e.currentTarget, () => api("POST", `/api/v1/roles/${role.id}/revoke`, { body: { userId: user.id } }), "Role revoked").then(r => r && renderRoles(panel)),
                }, " ×") : null)))
            : el("span", { class: "muted small" }, "no members")));

      const actions = el("div", { class: "row" });
      if (!role.isSystem && can("update:role")) {
        actions.append(el("button", {
          class: "btn sm", type: "button",
          onclick: () => {
            const matrix = permissionMatrix(role.permissions);
            const save = el("button", { class: "btn primary sm", type: "button" }, "Save permissions");
            save.addEventListener("click", () => act(save, () => api("PUT", `/api/v1/roles/${role.id}`, { body: { permissions: matrix.value() } }), "Role updated").then(r => r && renderRoles(panel)));
            body.replaceChildren(matrix.element, el("div", { class: "row" }, save, el("button", { class: "btn sm ghost", type: "button", onclick: () => renderRoles(panel) }, "Cancel")));
          },
        }, "Edit"));
      }
      if (!role.isSystem && can("delete:role")) {
        actions.append(el("button", {
          class: "btn sm danger", type: "button",
          onclick: e => confirm(`Delete role "${role.name}"?`) && act(e.currentTarget, () => api("DELETE", `/api/v1/roles/${role.id}`), "Role deleted").then(r => r && renderRoles(panel)),
        }, "Delete"));
      }

      return el("section", { class: "card" },
        el("div", { class: "card-head" },
          el("h2", {}, role.name, " ", role.isSystem ? badge("system") : badge("custom", "accent")),
          actions),
        body);
    });

    panel.replaceChildren(...sections, el("div", { class: "grid-2" }, roleCards));
  }

  // ── Audit log (admin) ───────────────────────────────────────────
  async function renderAudit(panel) {
    const query = { page: 1, event: "", action: "", statusCode: "" };
    const statsHost = el("div", { class: "grid-stats" }, loading());
    const event  = el("select", {}, el("option", { value: "" }, "All events"));
    const action = el("select", {}, ["", "GET", "POST", "PUT", "PATCH", "DELETE"].map(m => el("option", { value: m }, m || "All methods")));
    const status = el("input", { type: "number", min: "100", max: "599", placeholder: "Status" });
    const apply  = el("button", { class: "btn", type: "submit" }, "Filter");
    const filters = el("form", { class: "inline-form" }, event, action, status, apply);
    const results = el("div", {}, loading());

    const tools = el("div", { class: "row" });
    if (can("export:audit")) {
      tools.append(el("button", {
        class: "btn sm", type: "button",
        onclick: e => busy(e.currentTarget, async () => {
          const params = new URLSearchParams(Object.entries({ event: query.event, action: query.action, statusCode: query.statusCode }).filter(([, v]) => v));
          const res = await fetch(`/api/v1/audit/export?${params}`, { method: "POST", headers: { Authorization: `Bearer ${store.get().accessToken}` } });
          if (!res.ok) { toast(`Export failed (HTTP ${res.status})`, "error"); return; }
          const url = URL.createObjectURL(await res.blob());
          el("a", { href: url, download: `audit-${new Date().toISOString().slice(0, 10)}.csv` }).click();
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        }),
      }, "Export CSV"));
    }
    if (can("manage:audit")) {
      tools.append(el("button", {
        class: "btn sm danger", type: "button",
        onclick: e => {
          const days = prompt("Delete audit records older than how many days?", "90");
          if (!days) return;
          act(e.currentTarget, () => api("POST", "/api/v1/audit/purge", { body: { olderThanDays: Number(days) } }), r => `Deleted ${r.data.deleted} record(s)`)
            .then(r => r && renderAudit(panel));
        },
      }, "Purge old records"));
    }

    filters.addEventListener("submit", e => {
      e.preventDefault();
      Object.assign(query, { page: 1, event: event.value, action: action.value, statusCode: status.value });
      load();
    });

    panel.replaceChildren(statsHost, card("Audit trail", "newest first · secrets masked at write time", el("div", { class: "stack" }, el("div", { class: "row space" }, filters, tools), results)));

    api("GET", "/api/v1/audit/retention").then(res => {
      if (!res.ok) { statsHost.replaceChildren(); return; }
      const s = res.data;
      Object.keys(s.eventCounts).sort().forEach(name => event.append(el("option", { value: name }, `${name} (${s.eventCounts[name]})`)));
      statsHost.replaceChildren(
        el("div", { class: "stat" }, el("div", { class: "stat-value" }, s.totalRecords), el("div", { class: "stat-label" }, "Total records")),
        el("div", { class: "stat" }, el("div", { class: "stat-value" }, s.last30Days), el("div", { class: "stat-label" }, "Last 30 days")),
        el("div", { class: "stat" }, el("div", { class: "stat-value" }, s.failedLoginsLast24h), el("div", { class: "stat-label" }, "Failed sign-ins (24h)")),
        el("div", { class: "stat" }, el("div", { class: "stat-value" }, `${s.configuredRetentionDays}d`), el("div", { class: "stat-label" }, "Retention policy")));
    });

    async function load() {
      const params = new URLSearchParams({ page: query.page, limit: 15 });
      for (const key of ["event", "action", "statusCode"]) if (query[key]) params.set(key, query[key]);
      const res = await api("GET", `/api/v1/audit?${params}`);
      if (!res.ok) { results.replaceChildren(el("div", { class: "callout bad" }, errorMessage(res))); return; }
      const { data, pagination } = res.data;

      results.replaceChildren(
        table(["When", "Who", "Event", "Request", "Status", ""], data.map(log => {
          const tone = log.statusCode >= 500 ? "bad" : log.statusCode >= 400 ? "warn" : "ok";
          const detailRow = el("tr", { hidden: true }, el("td", { colspan: "6" }, json(log.metadata)));
          const row = el("tr", {},
            el("td", {}, timeAgo(log.timestamp), el("span", { class: "sub" }, fmtDate(log.timestamp))),
            el("td", {}, log.user ? log.user.email : el("span", { class: "muted" }, "anonymous"), el("span", { class: "sub" }, log.ipAddress)),
            el("td", {}, log.event ? badge(log.event, "accent") : el("span", { class: "muted" }, "—")),
            el("td", {}, el("span", { class: `method m-${log.action.toLowerCase()}` }, log.action), " ", el("span", { class: "mono" }, log.resource)),
            el("td", {}, badge(String(log.statusCode ?? "—"), tone)),
            el("td", { class: "actions" }, el("button", {
              class: "btn sm ghost", type: "button",
              onclick: e => { detailRow.hidden = !detailRow.hidden; e.currentTarget.textContent = detailRow.hidden ? "Details" : "Hide"; },
            }, "Details")));
          return [row, detailRow];
        }).flat(), "No audit records match"),
        el("div", { class: "row space" },
          el("span", { class: "muted small" }, `${pagination.total} record(s) · page ${pagination.page} of ${Math.max(1, pagination.totalPages)}`),
          el("div", { class: "row" },
            el("button", { class: "btn sm", type: "button", disabled: pagination.page <= 1, onclick: () => { query.page--; load(); } }, "← Prev"),
            el("button", { class: "btn sm", type: "button", disabled: pagination.page >= pagination.totalPages, onclick: () => { query.page++; load(); } }, "Next →"))));
    }

    load();
  }

  // ── OpenID Connect ──────────────────────────────────────────────
  async function startOidcDemo(button) {
    await busy(button, async () => {
      const { verifier, challenge } = await pkcePair();
      const request = {
        clientId:    "secureaccess-demo",
        redirectUri: `${location.origin}/oauth/callback.html`,
        scope:       "openid profile email offline_access",
        state:       randomString(16),
        nonce:       randomString(16),
        verifier,
      };
      oidcStore.set(request);
      const params = new URLSearchParams({
        response_type: "code", client_id: request.clientId, redirect_uri: request.redirectUri, scope: request.scope,
        state: request.state, nonce: request.nonce, code_challenge: challenge, code_challenge_method: "S256",
      });
      location.assign(`/api/v1/openid/authorize?${params}`);
    });
  }

  async function renderOidc(panel) {
    const start = el("button", { class: "btn primary", type: "button", onclick: e => startOidcDemo(e.currentTarget) }, "Sign in to the demo app with SecureAccess →");

    const flow = card("Try the OpenID Connect flow", "Authorization Code + PKCE",
      el("div", { class: "stack" },
        el("p", {}, "Act as a third-party app (\"SecureAccess Demo App\") that lets people sign in with their SecureAccess account."),
        el("ol", { class: "steps" },
          el("li", {}, "The app creates a random PKCE verifier and sends its SHA-256 hash to /openid/authorize."),
          el("li", {}, "SecureAccess shows a consent screen: who is asking and which data (scopes)."),
          el("li", {}, "After you allow it, the browser returns to the app with a one-time code (valid 2 minutes)."),
          el("li", {}, "The app exchanges code + verifier at /openid/token for an RS256 id_token, access_token and refresh_token."),
          el("li", {}, "The app verifies the id_token signature with the public JWKS and calls /openid/userinfo.")),
        el("div", {}, start)));

    const discoveryHost = card("Discovery document", "/.well-known/openid-configuration", loading());
    panel.replaceChildren(el("div", { class: "grid-2" }, flow, discoveryHost));

    rawRequest("GET", "/.well-known/openid-configuration").then(res => discoveryHost.lastChild.replaceWith(json(res.data)));

    if (can("read:client")) panel.append(await clientsCard(panel));
  }

  async function clientsCard(panel) {
    const host = card("Registered clients", "apps allowed to use SecureAccess for sign-in");
    const res = await api("GET", "/api/v1/openid/clients");
    if (!res.ok) { host.append(el("div", { class: "callout bad" }, errorMessage(res))); return host; }

    host.append(table(["Client", "Type", "Redirect URIs", "Created", ""], res.data.clients.map(c => el("tr", {},
      el("td", {}, c.name, el("span", { class: "sub mono" }, c.clientId)),
      el("td", {}, c.isConfidential ? badge("confidential", "accent") : badge("public + PKCE")),
      el("td", {}, chips(c.redirectUris)),
      el("td", {}, fmtDate(c.createdAt)),
      el("td", { class: "actions" }, can("delete:client") && c.clientId !== "secureaccess-demo"
        ? el("button", {
            class: "btn sm danger", type: "button",
            onclick: e => confirm(`Delete client "${c.name}"? Its sessions are revoked.`) &&
              act(e.currentTarget, () => api("DELETE", `/api/v1/openid/clients/${c.id}`), "Client deleted").then(r => r && renderOidc(panel)),
          }, "Delete")
        : null)))));

    if (can("create:client")) {
      const name = el("input", { placeholder: "My web app", required: true });
      const uris = el("textarea", { placeholder: "https://app.example.com/callback\n/oauth/callback.html", required: true });
      const confidential = el("input", { type: "checkbox" });
      const create = el("button", { class: "btn primary", type: "submit" }, "Register client");
      const output = el("div");
      const form = el("form", { class: "stack" },
        el("div", { class: "grid-2" }, field("Name", name), field("Redirect URIs", uris, "One per line. Paths starting with / use this server's origin.")),
        el("label", { class: "check" }, confidential, " Confidential (server-side app with a client secret)"),
        el("div", {}, create), output);
      form.addEventListener("submit", e => {
        e.preventDefault();
        const redirectUris = uris.value.split("\n").map(u => u.trim()).filter(Boolean);
        act(create, () => api("POST", "/api/v1/openid/clients", { body: { name: name.value, redirectUris, isConfidential: confidential.checked } }), "Client registered")
          .then(r => {
            if (!r) return;
            output.replaceChildren(el("div", { class: "callout warn" },
              el("div", {}, el("strong", {}, "client_id: "), el("span", { class: "mono" }, r.data.clientId)),
              r.data.clientSecret ? el("div", {}, el("strong", {}, "client_secret: "), el("span", { class: "mono" }, r.data.clientSecret), el("p", { class: "small" }, "Shown once — store it now.")) : null));
          });
      });
      host.append(el("details", { style: "margin-top:1rem" }, el("summary", {}, el("strong", {}, "＋ Register a client")), el("div", { style: "margin-top:.75rem" }, form)));
    }
    return host;
  }

  // ── Boot ────────────────────────────────────────────────────────
  checkHealth();
  render();
})();
