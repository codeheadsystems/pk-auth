// SPDX-License-Identifier: MIT
// Shared demo glue, driven by the @pk-auth/passkeys-browser SDK. Each adapter's
// demo points its <script type="module"> at this file; the data-demo attribute on
// <body> selects path overrides where the ceremony endpoints differ.

import { PkAuthClient, base64url } from "./passkeys-browser/index.js";

const TOKEN_KEY = "pkauth-demo-token";

// All three adapters now mount the ceremony at /auth/passkeys/... — the per-adapter overrides
// previously needed for Dropwizard have been removed.
const ceremonyOptions = {};

let token = localStorage.getItem(TOKEN_KEY);
let lastPhone = "";

const pk = new PkAuthClient(
  {
    apiBase: "",
    getToken: () => token,
  },
  ceremonyOptions,
);

function setToken(t) {
  token = t;
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
  renderJwt();
}

function renderJwt() {
  const el = document.getElementById("jwt-out");
  if (!token) {
    el.textContent = "No token yet — log in to see decoded claims.";
    return;
  }
  try {
    const [, payload] = token.split(".");
    const json = new TextDecoder().decode(base64url.decode(payload));
    el.textContent = JSON.stringify(JSON.parse(json), null, 2);
  } catch (e) {
    el.textContent = "Failed to decode JWT: " + e;
  }
}

function show(id, value, klass) {
  const el = document.getElementById(id);
  el.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  el.className = klass ?? "";
}

async function run(id, fn) {
  try {
    await fn();
  } catch (e) {
    show(id, e.message ?? String(e), "err");
  }
}

// Bind handlers.
const $ = (id) => document.getElementById(id);

$("btn-register").addEventListener("click", () =>
  run("register-out", async () => {
    const result = await pk.ceremonies.register({
      username: $("reg-username").value.trim(),
      label: $("reg-label").value.trim() || null,
    });
    show("register-out", result, "ok");
  }),
);

$("btn-login").addEventListener("click", () =>
  run("login-out", async () => {
    const result = await pk.ceremonies.authenticate({
      username: $("login-username").value.trim() || undefined,
    });
    setToken(result.token);
    show("login-out", result, "ok");
  }),
);

$("btn-logout").addEventListener("click", () => {
  setToken(null);
  show("login-out", "Logged out.");
});

$("btn-account").addEventListener("click", () =>
  run("account-out", async () => show("account-out", await pk.admin.getAccount())),
);

$("btn-register-again").addEventListener("click", () => $("btn-register").click());

// The credential label is untrusted text: it is whatever the caller supplied at
// register/finish or via PATCH /auth/admin/credentials/{id}, stored verbatim and echoed back by
// listCredentials. Build the row from DOM nodes and set the label through textContent —
// interpolating it into innerHTML would execute markup that an attacker stored in their own label,
// which in a real admin console means it fires in a staff member's session.
function credButton(action, text, credentialId) {
  const button = document.createElement("button");
  button.textContent = text;
  button.dataset.action = action;
  button.dataset.id = credentialId;
  return button;
}

function credentialListItem(cred) {
  const li = document.createElement("li");
  const name = document.createElement("b");
  name.textContent = cred.label;
  const id = document.createElement("small");
  id.textContent = `${cred.credentialId.slice(0, 16)}…`;
  li.append(
    name,
    " ",
    id,
    " ",
    credButton("rename", "Rename", cred.credentialId),
    " ",
    credButton("delete", "Delete", cred.credentialId),
  );
  return li;
}

$("btn-creds").addEventListener("click", () =>
  run("login-out", async () => {
    const list = await pk.admin.listCredentials();
    const ul = $("cred-list");
    ul.replaceChildren();
    for (const cred of list) {
      ul.appendChild(credentialListItem(cred));
    }
  }),
);

$("cred-list").addEventListener("click", async (event) => {
  const target = event.target.closest("button");
  if (!target) return;
  const id = target.dataset.id;
  if (target.dataset.action === "rename") {
    const label = prompt("New label?");
    if (!label) return;
    await pk.admin.renameCredential(id, label);
  } else if (target.dataset.action === "delete") {
    if (!confirm("Delete this passkey?")) return;
    await pk.admin.removeCredential(id);
  }
  $("btn-creds").click();
});

$("btn-backup-regen").addEventListener("click", () =>
  run("backup-out", async () => {
    const batch = await pk.admin.regenerateBackupCodes();
    show("backup-out", "Codes (view once — save them!):\n" + batch.codes.join("\n"));
  }),
);
$("btn-backup-count").addEventListener("click", () =>
  run("backup-out", async () => show("backup-out", await pk.admin.remainingBackupCodes())),
);
$("btn-email-start").addEventListener("click", () =>
  run("email-out", async () => show("email-out", await pk.admin.startEmailVerification($("email").value.trim()))),
);
$("btn-email-complete").addEventListener("click", () =>
  run("email-out", async () =>
    show("email-out", await pk.admin.completeEmailVerification($("email-token").value.trim())),
  ),
);
$("btn-phone-start").addEventListener("click", () =>
  run("phone-out", async () => {
    lastPhone = $("phone").value.trim();
    show("phone-out", await pk.admin.startPhoneVerification(lastPhone));
  }),
);
$("btn-phone-complete").addEventListener("click", () =>
  run("phone-out", async () =>
    show("phone-out", await pk.admin.completePhoneVerification(lastPhone, $("otp-code").value.trim())),
  ),
);

renderJwt();
