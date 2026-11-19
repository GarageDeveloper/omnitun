// The window: profiles with their sessions, the questions of connections
// in progress, and what the app has to say. Everything goes through the
// app's commands (src/main.rs); nothing here touches the network.
"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const STRINGS = {
  en: {
    edit: "Manage VPNs",
    settings: "Settings",
    empty: "No VPN yet: create or import one with Manage VPNs.",
    connect: "Connect",
    disconnect: "Disconnect",
    cancel: "Cancel",
    ok: "OK",
    download: "Download",
    update: (v) => `Version ${v} is available.`,
    reject: "Reject",
    once: "This time",
    pin: "Trust and save",
    "trust-intro": "The server's certificate cannot be verified:",
    "trust-advice": "Compare the fingerprint with the one given by your IT department.",
    daemon: (e) => `The Omnitun service cannot be reached (${e}). Is it running, and are you a member of the omnitun group? A new member signs in again first.`,
    connected: "Connected",
    connecting: "Connecting…",
    reconnecting: "Reconnecting…",
    disconnecting: "Disconnecting…",
    failed: "Failed",
    address: "Address",
    routes: "Routes",
    full: "all traffic",
    traffic: "Traffic",
    since: "Up for",
    login: "Complete the login in your browser.",
    refused: (u) => `Refused to open ${u}: not the profile's server.`,
    pinned: "Certificate saved in the profile.",
  },
  fr: {
    edit: "Gérer les VPN",
    settings: "Réglages",
    empty: "Aucun VPN : créez-en ou importez-en avec Gérer les VPN.",
    connect: "Connecter",
    disconnect: "Déconnecter",
    cancel: "Annuler",
    ok: "OK",
    download: "Télécharger",
    update: (v) => `La version ${v} est disponible.`,
    reject: "Refuser",
    once: "Cette fois",
    pin: "Faire confiance et enregistrer",
    "trust-intro": "Le certificat du serveur ne peut pas être vérifié :",
    "trust-advice": "Comparez l'empreinte avec celle donnée par votre service informatique.",
    daemon: (e) => `Le service Omnitun est injoignable (${e}). Tourne-t-il, et êtes-vous membre du groupe omnitun ? Un nouveau membre doit d'abord rouvrir sa session.`,
    connected: "Connecté",
    connecting: "Connexion…",
    reconnecting: "Reconnexion…",
    disconnecting: "Déconnexion…",
    failed: "Échec",
    address: "Adresse",
    routes: "Routes",
    full: "tout le trafic",
    traffic: "Trafic",
    since: "Depuis",
    login: "Terminez la connexion dans votre navigateur.",
    refused: (u) => `Ouverture de ${u} refusée : ce n'est pas le serveur du profil.`,
    pinned: "Certificat enregistré dans le profil.",
  },
};
let T = STRINGS.en;
const t = (key, ...args) => (typeof T[key] === "function" ? T[key](...args) : T[key] ?? key);

let profiles = [];
let sessions = [];
/** Last message per profile id: errors and warnings of connections. */
const messages = new Map();
/** Profiles with a connection in progress from this window. */
const busy = new Set();

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const child of children) node.append(child);
  return node;
}

function bytes(n) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

function duration(seconds) {
  const h = Math.floor(seconds / 3600), m = Math.floor((seconds % 3600) / 60);
  return h ? `${h} h ${m} min` : `${m} min`;
}

function render() {
  const list = document.getElementById("list");
  list.replaceChildren();
  document.getElementById("empty").hidden = profiles.length > 0;
  let folder = null;
  for (const p of profiles) {
    if ((p.folder ?? null) !== folder) {
      folder = p.folder ?? null;
      if (folder) list.append(el("div", { class: "folder" }, folder));
    }
    const s = sessions.find((x) => x.id === p.id);
    const state = s?.state ?? "disconnected";
    const up = s && state !== "failed";
    const button = el("button", {
      onclick: () => (up ? disconnect(p.id) : connect(p.id)),
    }, up ? t("disconnect") : t("connect"));
    // A connection in progress may be cancelled: only a request not yet
    // known to the service, or a disconnection, waits.
    button.disabled = (busy.has(p.id) && !s) || state === "disconnecting";
    const card = el("div", { class: "card" },
      el("div", { class: "row" },
        el("span", { class: `dot ${state}` }),
        el("span", { class: "name", title: p.name }, p.name),
        el("span", { class: "protocol" }, s && state !== "connected" ? t(state) : p.protocol),
        el("button", { class: "gear", title: t("settings"), onclick: () => invoke("open_manager", { id: p.id }) }, "⚙"),
        button));
    if (s && state === "connected") {
      const now = Date.now() / 1000;
      const details = el("div", { class: "details" });
      const add = (k, v) => details.append(el("span", {}, k), el("span", {}, v));
      if (s.address) add(t("address"), `${s.address}${s.interface ? ` (${s.interface})` : ""}`);
      add(t("routes"), s.full_tunnel ? t("full") : s.routes.slice(0, 4).join(", ") + (s.routes.length > 4 ? "…" : ""));
      add(t("traffic"), `↓ ${bytes(s.rx_bytes)}  ↑ ${bytes(s.tx_bytes)}`);
      if (s.connected_since) add(t("since"), duration(Math.max(0, now - s.connected_since)));
      card.append(details);
    }
    // The session's own word on its state; an error of the window's request
    // only when the session says nothing (it is usually the same failure).
    const detail = s?.detail && state !== "connected";
    if (detail) {
      card.append(el("div", { class: `message ${state === "failed" ? "error" : ""}` }, s.detail));
    }
    const message = messages.get(p.id);
    if (message && !(message.kind === "error" && (detail || state === "connected"))) {
      card.append(el("div", { class: `message ${message.kind}` }, message.text));
    }
    list.append(card);
  }
}

async function loadProfiles() {
  try {
    profiles = await invoke("profiles");
  } catch (e) {
    profiles = [];
    banner(String(e));
  }
  render();
}

async function loadSessions() {
  sessions = await invoke("sessions");
  render();
}

function banner(text) {
  const node = document.getElementById("banner");
  node.hidden = !text;
  node.textContent = text ?? "";
}

async function connect(id) {
  busy.add(id);
  messages.delete(id);
  render();
  try {
    await invoke("connect", { id });
  } catch (e) {
    messages.set(id, { kind: "error", text: String(e) });
  } finally {
    busy.delete(id);
    render();
  }
}

async function disconnect(id) {
  messages.delete(id);
  try {
    await invoke("disconnect", { id });
  } catch (e) {
    messages.set(id, { kind: "error", text: String(e) });
  }
  render();
}

function profileId(name) {
  return profiles.find((p) => p.name === name)?.id;
}

// Questions come one at a time per connection; several connections wait
// in turn.
const questions = [];
let asking = false;

function nextQuestion() {
  if (asking || questions.length === 0) return;
  asking = true;
  const q = questions.shift();
  (q.type === "prompt" ? askPrompt(q.data) : askTrust(q.data)).finally(() => {
    asking = false;
    nextQuestion();
  });
}

function askPrompt(p) {
  return new Promise((resolve) => {
    const dialog = document.getElementById("prompt");
    const input = document.getElementById("prompt-input");
    document.getElementById("prompt-profile").textContent = p.profile;
    document.getElementById("prompt-message").textContent = p.message;
    const hidden = p.kind === "secret" || p.kind === "otp";
    input.type = hidden ? "password" : "text";
    input.inputMode = p.digits ? "numeric" : "text";
    input.hidden = p.kind === "confirm";
    input.value = "";
    dialog.onclose = async () => {
      const ok = dialog.returnValue === "ok";
      const value = ok ? (p.kind === "confirm" ? "yes" : input.value) : null;
      input.value = "";
      await invoke("answer", { id: p.id, value });
      resolve();
    };
    dialog.returnValue = "cancel";
    dialog.showModal();
    if (!input.hidden) input.focus();
  });
}

function askTrust(view) {
  return new Promise((resolve) => {
    const dialog = document.getElementById("trust");
    const c = view.certificate;
    document.getElementById("trust-profile").textContent = view.profile;
    document.getElementById("trust-host").textContent = `${c.host}:${c.port}`;
    document.getElementById("trust-reason").textContent = c.reason ?? "";
    document.getElementById("trust-sha").textContent = `SHA-256 ${c.sha256.match(/.{2}/g).join(":")}`;
    dialog.onclose = async () => {
      await invoke("trust", { id: view.id, decision: dialog.returnValue || "reject" });
      resolve();
    };
    dialog.returnValue = "reject";
    dialog.showModal();
  });
}

async function main() {
  T = (await invoke("language")) === "fr" ? STRINGS.fr : STRINGS.en;
  for (const node of document.querySelectorAll("[data-i18n]")) node.textContent = t(node.dataset.i18n);
  document.getElementById("edit").addEventListener("click", () => invoke("open_manager", { id: null }).catch((e) => banner(String(e))));
  await listen("profiles-changed", loadProfiles);
  document.getElementById("settings").addEventListener("click", () => invoke("open_settings"));
  document.getElementById("prompt-cancel").addEventListener("click", () => document.getElementById("prompt").close("cancel"));
  document.getElementById("update-open").addEventListener("click", () => invoke("open_releases"));
  document.getElementById("version").textContent = `Omnitun ${await invoke("version")}`;
  // Profiles may change in the editor: read them again when shown.
  window.addEventListener("focus", loadProfiles);

  await listen("sessions", loadSessions);
  await listen("daemon", (e) => banner(e.payload ? t("daemon", e.payload) : null));
  await listen("prompt", (e) => { questions.push({ type: "prompt", data: e.payload }); nextQuestion(); });
  await listen("trust", (e) => { questions.push({ type: "trust", data: e.payload }); nextQuestion(); });
  await listen("error", (e) => banner(String(e.payload)));
  await listen("update", (e) => showUpdate(e.payload));
  await listen("notice", (e) => {
    const n = e.payload;
    const id = profileId(n.profile);
    if (!id) return;
    if (n.kind === "warning") messages.set(id, { kind: "warning", text: n.text });
    else if (n.kind === "login") messages.set(id, { kind: "", text: t("login") });
    else if (n.kind === "refused") messages.set(id, { kind: "warning", text: t("refused", n.text) });
    else if (n.kind === "pinned") messages.set(id, { kind: "", text: t("pinned") });
    render();
  });

  const update = await invoke("update");
  if (update) showUpdate(update);
  await loadProfiles();
  await loadSessions();
}

function showUpdate(version) {
  document.getElementById("update-text").textContent = t("update", version);
  document.getElementById("update").hidden = false;
}

main();
