// The Settings window, as the macOS app's: General (sign-in, quitting,
// updates, language, notifications), Service (its state, a restart, the
// diagnostic report) and About.
"use strict";

const { invoke } = window.__TAURI__.core;
const files = window.__TAURI__.dialog;

let FRENCH = false;
const FR = {
  "Settings": "Réglages",
  "General": "Général",
  "Service": "Service",
  "About": "À propos",
  "Open Omnitun at sign-in": "Ouvrir Omnitun à l'ouverture de session",
  "Disconnect VPNs when I quit Omnitun": "Déconnecter les VPN quand je quitte Omnitun",
  "Without the app, a code or a browser login cannot be asked again when a VPN reconnects.":
    "Sans l'app, un code ou une connexion par navigateur ne peut pas être redemandé lors d'une reconnexion.",
  "Check for updates every day": "Rechercher des mises à jour chaque jour",
  "Check Now": "Rechercher maintenant",
  "Version %@ is available.": "La version %@ est disponible.",
  "Omnitun is up to date.": "Omnitun est à jour.",
  "Download": "Télécharger",
  "Language": "Langue",
  "Same as Windows": "Comme Windows",
  "Takes effect when Omnitun restarts; your VPNs stay connected.": "Prend effet au redémarrage d'Omnitun ; vos VPN restent connectés.",
  "Notifications": "Notifications",
  "Connected": "Connexion établie",
  "Unexpected disconnection or failure (recommended)": "Déconnexion inattendue ou échec (recommandé)",
  "Security alerts (changed certificate) are always shown.": "Les alertes de sécurité (certificat modifié) s'affichent toujours.",
  "VPN Service": "Service VPN",
  "Checking…": "Vérification…",
  "Running · version %@ · %lld session(s)": "Actif · version %@ · %lld session(s)",
  "Restart the Service": "Redémarrer le service",
  "Open Services…": "Ouvrir les Services…",
  "Check": "Vérifier",
  "Restarting the service disconnects every VPN.": "Redémarrer le service déconnecte tous les VPN.",
  "Diagnostic": "Diagnostic",
  "Create Diagnostic Report…": "Créer un rapport de diagnostic…",
  "A text file to send when something goes wrong: versions, VPNs and their sessions, the service's log of the last day. No password, key or certificate; servers, accounts, domains and addresses are replaced. Read it before sending it.":
    "Un fichier texte à envoyer quand quelque chose ne va pas : versions, VPN et leurs sessions, journal du service des dernières 24 heures. Aucun mot de passe, clé ou certificat ; serveurs, comptes, domaines et adresses sont remplacés. Relisez-le avant de l'envoyer.",
  "The report could not be saved": "Le rapport n'a pas pu être enregistré",
  "Omnitun diagnostic": "Diagnostic Omnitun",
  "Text file": "Fichier texte",
  "Version %@": "Version %@",
  "A VPN client for FortiGate SSL VPN, IPsec, OpenVPN, L2TP and WireGuard, several at a time.":
    "Un client VPN pour le VPN SSL FortiGate, IPsec, OpenVPN, L2TP et WireGuard, plusieurs à la fois.",
  "Source Code on GitHub": "Code source sur GitHub",
  "Licensed under the MIT License or the Apache License 2.0, at your choice.": "Sous licence MIT ou Apache 2.0, au choix.",
  "MIT License": "Licence MIT",
  "Apache License 2.0": "Licence Apache 2.0",
  "Third-Party Licenses…": "Licences des composants tiers…",
};
function tr(text, ...args) {
  let s = FRENCH ? (FR[text] ?? text) : text;
  for (const a of args) s = s.replace(/%@|%lld/, String(a));
  return s;
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (k === "checked" || k === "disabled" || k === "value") node[k] = v;
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const child of children.flat()) if (child !== null && child !== undefined && child !== false) node.append(child);
  return node;
}
const caption = (text) => el("p", { class: "caption" }, text);
const section = (title, ...children) => el("div", { class: "section" }, title ? el("h3", {}, title) : null, ...children);
const field = (label, control, ...notes) =>
  el("div", { class: "field" }, el("div", { class: "label" }, label), el("div", { class: "control" }, control), ...notes.filter(Boolean));
function checkbox(label, checked, onChange) {
  const box = el("input", { type: "checkbox", checked, onchange: () => onChange(box.checked) });
  return el("label", { class: "check" }, box, label);
}

let settings = null;
let startLanguage = null;
let tab = "general";
let service = { state: "checking" };
let update = null; // { text, version }
let busy = false;

async function save() {
  try { await invoke("set_settings", { settings }); } catch { /* kept for this run */ }
}

function general() {
  const loginRow = el("div");
  invoke("open_at_login").then((on) => {
    loginRow.replaceChildren(field("", checkbox(tr("Open Omnitun at sign-in"), on, async (v) => {
      try { await invoke("set_open_at_login", { on: v }); } catch { render(); }
    })));
  });
  const languages = [["system", tr("Same as Windows")], ["en", "English"], ["fr", "Français"]];
  const language = el("select", {
    onchange: async () => { settings.language = languages[language.selectedIndex][0]; await save(); render(); },
  }, languages.map(([, label]) => el("option", {}, label)));
  language.selectedIndex = Math.max(0, languages.findIndex(([v]) => v === settings.language));
  return [
    section(tr("General"),
      loginRow,
      field("", checkbox(tr("Disconnect VPNs when I quit Omnitun"), settings.disconnect_on_quit, (v) => { settings.disconnect_on_quit = v; save(); }),
        caption(tr("Without the app, a code or a browser login cannot be asked again when a VPN reconnects."))),
      field("", [
        checkbox(tr("Check for updates every day"), settings.check_updates, (v) => { settings.check_updates = v; save(); }),
        el("button", {
          disabled: busy,
          onclick: async () => {
            busy = true; render();
            try {
              const checked = await invoke("check_now");
              update = checked.kind === "newer" ? { text: tr("Version %@ is available.", checked.version), version: checked.version }
                : checked.kind === "up_to_date" ? { text: tr("Omnitun is up to date.") } : null;
            } catch (e) {
              update = { text: String(e) };
            }
            busy = false; render();
          },
        }, tr("Check Now")),
      ], update ? el("p", { class: "caption" }, update.text, " ", update.version ? el("button", { class: "link", onclick: () => invoke("open_link", { which: "releases" }) }, tr("Download")) : null) : null)),
    section(tr("Language"),
      field(tr("Language"), language,
        settings.language !== startLanguage ? caption(tr("Takes effect when Omnitun restarts; your VPNs stay connected.")) : null)),
    section(tr("Notifications"),
      field("", checkbox(tr("Connected"), settings.notify_connected, (v) => { settings.notify_connected = v; save(); })),
      field("", checkbox(tr("Unexpected disconnection or failure (recommended)"), settings.notify_failures, (v) => { settings.notify_failures = v; save(); }),
        caption(tr("Security alerts (changed certificate) are always shown.")))),
  ];
}

async function checkService() {
  service = { state: "checking" };
  render();
  try {
    const info = await invoke("service_info");
    service = { state: "running", ...info };
  } catch (e) {
    service = { state: "down", error: String(e) };
  }
  render();
}

function serviceTab() {
  const status = service.state === "checking"
    ? el("span", { class: "muted" }, tr("Checking…"))
    : service.state === "running"
      ? el("span", { style: "color:var(--ok)" }, `● ${tr("Running · version %@ · %lld session(s)", service.version, service.sessions)}`)
      : el("span", { class: "error-text" }, service.error);
  return [
    section(tr("VPN Service"),
      el("div", { class: "block" }, status),
      el("div", { class: "row-gap" },
        el("button", {
          disabled: service.state !== "running",
          onclick: async () => {
            try { await invoke("restart_service"); } catch { /* shown by the check */ }
            setTimeout(checkService, 4000);
            service = { state: "checking" };
            render();
          },
        }, tr("Restart the Service")),
        el("button", { onclick: () => invoke("open_services") }, tr("Open Services…")),
        el("button", { onclick: checkService }, tr("Check"))),
      caption(tr("Restarting the service disconnects every VPN."))),
    section(tr("Diagnostic"),
      el("div", { class: "row-gap" }, el("button", {
        disabled: busy,
        onclick: async () => {
          const day = new Date().toISOString().slice(0, 10);
          const path = await files.save({ defaultPath: `${tr("Omnitun diagnostic")} ${day}.txt`, filters: [{ name: tr("Text file"), extensions: ["txt"] }] });
          if (!path) return;
          busy = true; render();
          try {
            await invoke("diagnostic_report", { path });
          } catch (e) {
            await files.message(String(e), { title: tr("The report could not be saved"), kind: "error" });
          }
          busy = false; render();
        },
      }, tr("Create Diagnostic Report…"))),
      caption(tr("A text file to send when something goes wrong: versions, VPNs and their sessions, the service's log of the last day. No password, key or certificate; servers, accounts, domains and addresses are replaced. Read it before sending it."))),
  ];
}

function about(version) {
  return [
    el("div", { class: "section", style: "text-align:center;padding:22px" },
      el("img", { src: "icon.png", width: 72, height: 72, alt: "" }),
      el("h2", { style: "margin:8px 0 2px" }, "Omnitun"),
      el("p", { class: "muted" }, tr("Version %@", version)),
      el("p", {}, tr("A VPN client for FortiGate SSL VPN, IPsec, OpenVPN, L2TP and WireGuard, several at a time.")),
      el("p", {}, el("button", { class: "link", onclick: () => invoke("open_link", { which: "source" }) }, tr("Source Code on GitHub"))),
      el("p", { class: "muted" }, "© 2026 GarageDeveloper and the Omnitun contributors"),
      el("p", { class: "muted" }, tr("Licensed under the MIT License or the Apache License 2.0, at your choice.")),
      el("div", { class: "row-gap", style: "justify-content:center" },
        el("button", { class: "link", onclick: () => invoke("open_link", { which: "mit" }) }, tr("MIT License")),
        el("button", { class: "link", onclick: () => invoke("open_link", { which: "apache" }) }, tr("Apache License 2.0")),
        el("button", { class: "link", onclick: () => invoke("open_notices").catch((e) => files.message(String(e))) }, tr("Third-Party Licenses…")))),
  ];
}

let version = "";
function render() {
  const tabs = [["general", tr("General")], ["service", tr("Service")], ["about", tr("About")]];
  document.getElementById("tabs").replaceChildren(...tabs.map(([k, label]) => el("button", {
    class: tab === k ? "active" : "",
    onclick: () => { tab = k; if (k === "service") checkService(); else render(); },
  }, label)));
  const content = tab === "service" ? serviceTab() : tab === "about" ? about(version) : general();
  document.getElementById("body").replaceChildren(...content);
}

async function main() {
  FRENCH = (await invoke("language")) === "fr";
  document.title = tr("Settings");
  settings = await invoke("settings");
  startLanguage = settings.language;
  version = await invoke("version");
  render();
}

main();
