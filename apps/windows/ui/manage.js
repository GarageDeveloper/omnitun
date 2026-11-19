// The profiles window: the list of VPNs and folders on the left, the
// editor of the selected one on the right, as the macOS app's Manage VPNs
// window. The form is vpn-ffi's ProfileForm, checked and saved by Rust
// (src/manage.rs); this file only shows it.
"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const files = window.__TAURI__.dialog;

// ---------------------------------------------------------------- strings

const FRENCH = navigator.language.toLowerCase().startsWith("fr");
/** French for each English text; %@ and %lld are replaced in order. */
const FR = {
  "Manage VPNs": "Gérer les VPN",
  "SSL VPN": "VPN SSL",
  "New VPN": "Nouveau VPN",
  "SSL VPN (FortiGate)": "VPN SSL (FortiGate)",
  "L2TP over IPsec": "L2TP sur IPsec",
  "New Folder…": "Nouveau dossier…",
  "New Folder Inside…": "Nouveau dossier dedans…",
  "Rename Folder…": "Renommer le dossier…",
  "Rename…": "Renommer…",
  "Duplicate": "Dupliquer",
  "Disconnect": "Se déconnecter",
  "Connect": "Se connecter",
  "Connect in Split Mode": "Connecter en mode split",
  "Connect Directly, Without %@": "Connecter directement, sans %@",
  "Move to Folder": "Déplacer vers un dossier",
  "None": "Aucun",
  "Delete…": "Supprimer…",
  "Delete": "Supprimer",
  "Import": "Importer",
  "Profile File (.vpnprofile)…": "Fichier de profil (.vpnprofile)…",
  "OpenVPN or WireGuard File (.ovpn, .conf)…": "Fichier OpenVPN ou WireGuard (.ovpn, .conf)…",
  "New Folder": "Nouveau dossier",
  "“/” separates subfolders, as in Clients/Acme.": "« / » sépare les sous-dossiers, comme dans Clients/Acme.",
  "OK": "OK",
  "Cancel": "Annuler",
  "Rename “%@”": "Renommer « %@ »",
  "Up to 64 characters, without “/”; unique in its folder.": "64 caractères au plus, sans « / » ; unique dans son dossier.",
  "Rename": "Renommer",
  "Cannot rename “%@”": "Impossible de renommer « %@ »",
  "Cannot move “%@”": "Impossible de déplacer « %@ »",
  "%@ copy": "%@ copie",
  "The saved secrets of “%@” were not copied": "Les secrets enregistrés de « %@ » n'ont pas été copiés",
  "Type them in the copy's editor. %@": "Saisissez-les dans l'éditeur de la copie. %@",
  "Cannot duplicate “%@”": "Impossible de dupliquer « %@ »",
  "“%@” is connected": "« %@ » est connecté",
  "Disconnect it before deleting it.": "Déconnectez-le avant de le supprimer.",
  "Delete “%@”?": "Supprimer « %@ » ?",
  "The profile and its saved secrets are removed. The other profiles and the comments in your file are left unchanged.":
    "Le profil et ses secrets enregistrés sont supprimés. Les autres profils et les commentaires de votre fichier ne changent pas.",
  "Cannot delete the profile": "Suppression impossible",
  "Select a VPN, or create one with +.": "Sélectionnez un VPN, ou créez-en un avec +.",
  "Drag VPNs here from the list to file them in this folder.": "Faites glisser des VPN depuis la liste pour les ranger dans ce dossier.",
  "Edit": "Modifier",
  "Export as a Profile File…": "Exporter en fichier de profil…",
  "Cannot export the profile": "Impossible d'exporter le profil",
  "General": "Général",
  "Advanced": "Avancé",
  "Network": "Réseau",
  "Schedule": "Horaires",
  "Name": "Nom",
  "Description": "Description",
  "Optional": "Optionnel",
  "Folder": "Dossier",
  "Remote Gateway": "Passerelle distante",
  "Server": "Serveur",
  "Method": "Méthode",
  "Password": "Mot de passe",
  "SAML (browser)": "SAML (navigateur)",
  "User Name": "Identifiant",
  "Save the password in the Credential Manager": "Enregistrer le mot de passe dans le Gestionnaire d'identification",
  "Advanced Options": "Options avancées",
  "Port": "Port",
  "Realm": "Royaume",
  "SAML Callback Port": "Port de retour SAML",
  "Trusted certificate fingerprints (SHA-256, one per line)": "Empreintes de certificats de confiance (SHA-256, une par ligne)",
  "Gateway Identity": "Identité de la passerelle",
  "Pre-shared key": "Clé partagée",
  "Certificate": "Certificat",
  "No pre-shared key: you and the gateway prove your identities with certificates.":
    "Pas de clé partagée : la passerelle et vous prouvez votre identité par certificat.",
  "No pre-shared key: you sign in with your user name and password, the gateway with its certificate.":
    "Pas de clé partagée : vous vous identifiez par votre nom d’utilisateur et votre mot de passe, la passerelle par son certificat.",
  "Authentication Method": "Méthode d'authentification",
  "Pre-shared Key": "Clé partagée",
  "Authentication (XAuth)": "Authentification (XAuth)",
  "Ask at connection": "Demander à la connexion",
  "Save credentials": "Sauvegarder les identifiants",
  "Disable": "Désactiver",
  "User name and password": "Identifiant et mot de passe",
  "Saved in the Credential Manager": "Enregistré dans le Gestionnaire d'identification",
  "Asked at connection": "Demandé à la connexion",
  "Forget": "Oublier",
  "Removes the saved value from the Credential Manager when you save.": "Retire la valeur du Gestionnaire d'identification à l'enregistrement.",
  "Client Certificate": "Certificat client",
  "issued by %@": "émis par %@",
  "expired": "expiré",
  "Not in the certificate store": "Absent du magasin de certificats",
  "The certificate imported with the OpenVPN file is used. A certificate from the store would replace it.":
    "Le certificat importé avec le fichier OpenVPN est utilisé. Un certificat du magasin le remplacerait.",
  "The certificate files named in the profile file are used. A certificate from the store would replace them.":
    "Les fichiers de certificat indiqués dans le fichier du profil sont utilisés. Un certificat du magasin les remplacerait.",
  "Certificates with their private key in your personal certificate store, such as one installed by your organization.":
    "Les certificats dont la clé privée est dans votre magasin de certificats personnel, comme celui qu'installe votre organisation.",
  "The key stays in the certificate store, which may ask you to allow its use at connection.":
    "La clé reste dans le magasin de certificats, qui peut vous demander d'autoriser son utilisation à la connexion.",
  "Gateway Certificate": "Certificat de la passerelle",
  "Certificate Authority": "Autorité de certification",
  "Authorities trusted by Windows": "Autorités reconnues par Windows",
  "Choose…": "Choisir…",
  "Remove": "Retirer",
  "Authorities trusted by Windows, such as those your organization installs, are always accepted.":
    "Les autorités reconnues par Windows, comme celles que votre organisation installe, sont toujours acceptées.",
  "A certificate that cannot be verified is shown at the first connection, so you can decide to trust it.":
    "Un certificat qui ne peut pas être vérifié est présenté à la première connexion : vous décidez alors de lui faire confiance.",
  "Servers": "Serveurs",
  "Add a Server": "Ajouter un serveur",
  "The servers are tried in this order.": "Les serveurs sont essayés dans cet ordre.",
  "Server Certificate": "Certificat du serveur",
  "Only this authority is trusted, not the system's: OpenVPN servers have their own.":
    "Seule cette autorité est reconnue, pas celles du système : les serveurs OpenVPN ont la leur.",
  "With fingerprints, only these certificates are accepted and the authority is not needed.":
    "Avec des empreintes, seuls ces certificats sont acceptés et l’autorité n’est pas nécessaire.",
  "Server Name": "Nom du serveur",
  "The name the server certificate must carry (verify-x509-name).": "Le nom que doit porter le certificat du serveur (verify-x509-name).",
  "Compared With": "Comparé avec",
  "Whole subject": "Le sujet entier",
  "Common name": "Le nom commun",
  "Start of the common name": "Le début du nom commun",
  "Require a certificate meant for a server": "Exiger un certificat destiné à un serveur",
  "Without it, any client of the same authority could pose as the server.":
    "Sans cela, n’importe quel client de la même autorité pourrait se faire passer pour le serveur.",
  "Control Channel": "Canal de contrôle",
  "Static Key": "Clé statique",
  "OpenVPN static key": "Clé statique OpenVPN",
  "This file is not an OpenVPN static key.": "Ce fichier n’est pas une clé statique OpenVPN.",
  "Key Direction": "Sens de la clé",
  "Both directions": "Les deux sens",
  "HMAC Digest": "Condensat HMAC",
  "Data Ciphers": "Chiffrements des données",
  "Choose at least one cipher.": "Choisissez au moins un chiffrement.",
  "Compression": "Compression",
  "Packets are never compressed: choose the framing the server expects.":
    "Les paquets ne sont jamais compressés : choisissez le format qu’attend le serveur.",
  "Renegotiate Keys Every": "Renouveler les clés toutes les",
  "seconds": "secondes",
  "Code Question": "Question du code",
  "A one-time code asked with the password (static-challenge).": "Un code à usage unique demandé avec le mot de passe (static-challenge).",
  "Show the code while it is typed": "Afficher le code pendant la saisie",
  "VPN Settings": "Paramètres VPN",
  "Version 1": "Version 1",
  "Version 2": "Version 2",
  "Mode": "Mode",
  "Main": "Principal",
  "Aggressive": "Agressif",
  "Main mode protects the identities; the gateway chooses the tunnel before seeing the Local ID.":
    "Le mode principal protège les identités ; la passerelle choisit le tunnel avant de voir l'ID local.",
  "Options": "Options",
  "Mode Config": "Config Mode",
  "The gateway assigns the address, routes and DNS. Manual configuration is not supported yet.":
    "La passerelle attribue l'adresse, les routes et le DNS. La configuration manuelle n'est pas encore prise en charge.",
  "Local ID": "Identifiant local",
  "Remote ID": "Identifiant distant",
  "Proposals": "Propositions",
  "IKE proposals (one per line)": "Propositions IKE (une par ligne)",
  "ESP proposals (one per line)": "Propositions ESP (une par ligne)",
  "Phase 1": "Phase 1",
  "Phase 2": "Phase 2",
  "Key Lifetime": "Durée de vie de la clé",
  "Dead peer detection": "Détection de la perte du pair",
  "NAT traversal": "NAT Traversal",
  "Always on: ESP travels in UDP, so no kernel IPsec is needed.": "Toujours actif : l'ESP passe dans UDP, sans IPsec du noyau.",
  "kilobytes": "Ko",
  "Perfect forward secrecy (PFS)": "Perfect Forward Secrecy (PFS)",
  "DH Group": "Groupe DH",
  "DH Groups": "Groupes DH",
  "Allow legacy algorithms (3DES, DH group 2)": "Autoriser les algorithmes anciens (3DES, groupe DH 2)",
  "Only for old gateways that offer nothing better: these algorithms are no longer considered secure.":
    "Uniquement pour les anciennes passerelles qui ne proposent rien de mieux : ces algorithmes ne sont plus considérés comme sûrs.",
  "Encryption": "Chiffrement",
  "PRF": "PRF",
  "Authentication": "Authentification",
  "AES-GCM in phase 1 needs IKEv2.": "AES-GCM en phase 1 nécessite IKEv2.",
  "ChaCha20-Poly1305 needs IKEv2.": "ChaCha20-Poly1305 nécessite IKEv2.",
  "3DES needs legacy algorithms allowed.": "3DES nécessite d’autoriser les algorithmes anciens.",
  "Add a Proposal": "Ajouter une proposition",
  "DH group 2 needs legacy algorithms allowed.": "Le groupe DH 2 nécessite d’autoriser les algorithmes anciens.",
  "Edit the proposals as text": "Modifier les propositions en texte",
  "These proposals cannot be shown as choices.": "Ces propositions ne peuvent pas être présentées sous forme de choix.",
  "For settings the choices above do not offer, in the syntax “aes256-sha256-modp2048”.":
    "Pour les réglages absents des choix ci-dessus, avec la syntaxe « aes256-sha256-modp2048 ».",
  "Private Key": "Clé privée",
  "Public Key": "Clé publique",
  "Copy, for the server's administrator": "Copier, pour l'administrateur du serveur",
  "Copy": "Copier",
  "Not a WireGuard key": "Ce n'est pas une clé WireGuard",
  "Unknown": "Inconnue",
  "Generate a New Key Pair": "Générer une nouvelle paire de clés",
  "The server's administrator then declares the new public key.": "L'administrateur du serveur déclare ensuite la nouvelle clé publique.",
  "Server Public Key": "Clé publique du serveur",
  "Addresses in the tunnel (Address, one per line)": "Adresses dans le tunnel (Address, une par ligne)",
  "Networks of the server (AllowedIPs, one per line; 0.0.0.0/0 for everything)":
    "Réseaux du serveur (AllowedIPs, un par ligne ; 0.0.0.0/0 pour tout)",
  "DNS servers (one per line)": "Serveurs DNS (un par ligne)",
  "DNS search domains (one per line)": "Domaines de recherche DNS (un par ligne)",
  "Keepalive (seconds)": "Maintien de connexion (secondes)",
  "Off": "Désactivé",
  "Keeps NAT mappings open: 25 seconds is usual.": "Garde ouvertes les traductions NAT : 25 secondes est l'usage.",
  "MTU": "MTU",
  "Group Name": "Nom de groupe",
  "The IKE identity; with one, phase 1 uses aggressive mode.": "L'identité IKE ; avec un nom de groupe, la phase 1 utilise le mode agressif.",
  "PPP Authentication": "Authentification PPP",
  "Choose at least one authentication.": "Choisissez au moins une authentification.",
  "PAP sends the password in clear inside IPsec and does not authenticate the server: turn it on only if the server asks for it (Meraki).":
    "PAP envoie le mot de passe en clair dans IPsec et n’authentifie pas le serveur : ne l’activez que si le serveur le demande (Meraki).",
  "DNS servers if the server assigns none (one per line, 4 at most)": "Serveurs DNS si le serveur n'en attribue aucun (un par ligne, 4 au plus)",
  "Note": "Note",
  "Add": "Ajouter",
  "Paste Lines": "Coller des lignes",
  "One entry per line: the network or domain, then its note": "Une entrée par ligne : le réseau ou le domaine, puis sa note",
  "Traffic": "Trafic",
  "As the gateway decides": "Selon la passerelle",
  "Everything through the VPN": "Tout le trafic par le VPN",
  "Only these networks": "Seulement ces réseaux",
  "The networks the gateway announces, or all traffic if it asks for it.": "Les réseaux que la passerelle annonce, ou tout le trafic si elle le demande.",
  "All traffic, except the domains kept outside.": "Tout le trafic, sauf les domaines gardés en dehors.",
  "A split tunnel at every connection: the list below, the rest of the traffic outside.":
    "Split tunnel à chaque connexion : la liste ci-dessous, le reste du trafic en dehors.",
  "Announced by the gateway": "Annoncé par la passerelle",
  "Last connection, %@": "Dernière connexion, %@",
  "All traffic": "Tout le trafic",
  "default route": "route par défaut",
  "network": "réseau",
  "and %lld more": "et %lld de plus",
  "DNS domain": "domaine DNS",
  "Nothing": "Rien",
  "Shown after a first connection.": "Affiché après une première connexion.",
  "Read only: the gateway decides, at every connection. To set your own networks, choose “Only these networks”; to send everything whatever it says, “Everything through the VPN”.":
    "Lecture seule : c'est la passerelle qui décide, à chaque connexion. Pour imposer vos réseaux, choisissez « Seulement ces réseaux » ; pour tout envoyer quoi qu'elle dise, « Tout le trafic par le VPN ».",
  "Networks through the VPN": "Réseaux par le VPN",
  "A network (10.1.0.0/16), a single address, or a domain: *.corp.example for every name under it, routed as they are resolved.":
    "Un réseau (10.1.0.0/16), une adresse seule, ou un domaine : *.corp.example pour tous les noms en dessous, routés dès qu'ils sont résolus.",
  "Add the networks the gateway announces": "Ajouter les réseaux annoncés par la passerelle",
  "Off: only this list. On: this list on top of what the gateway announces.":
    "Décoché : seulement cette liste. Coché : cette liste en plus de ce que la passerelle annonce.",
  "Networks in split mode": "Réseaux du mode split",
  "The menu also offers to connect in split mode, with these networks instead.":
    "Le menu propose aussi de se connecter en mode split, avec ces réseaux à la place.",
  "Outside the VPN, if the gateway sends everything": "En dehors du VPN, si la passerelle envoie tout",
  "Outside the VPN": "En dehors du VPN",
  "Used only when the gateway asks for all traffic; otherwise they are outside already. Resolved by the DNS in place before the VPN, and reached directly (video calls, say). Public addresses only.":
    "Utilisés seulement quand la passerelle demande tout le trafic ; sinon ils passent déjà en dehors. Résolus par le DNS en place avant le VPN, et joints directement (visioconférence, par exemple). Adresses publiques uniquement.",
  "Resolved by the DNS in place before the VPN, and reached directly (video calls, say). Public addresses only.":
    "Résolus par le DNS en place avant le VPN, et joints directement (visioconférence, par exemple). Adresses publiques uniquement.",
  "Also offer split mode": "Proposer aussi le mode split",
  "The menu offers “Connect in Split Mode”: only these networks, for that connection.":
    "Le menu propose « Connecter en mode split » : seulement ces réseaux, pour cette connexion-là.",
  "One list for the VPN: the same as in “Only these networks”. Changing the mode keeps it.":
    "Une seule liste pour le VPN : c'est la même que dans « Seulement ces réseaux ». Changer de mode la garde telle quelle.",
  "Added to the gateway's networks": "Ajoutés aux réseaux de la passerelle",
  "Unused while everything goes through the VPN.": "Inutilisés tant que tout passe par le VPN.",
  "Added when the gateway announces networks, like the route lines of an OpenVPN file.":
    "Ajoutés quand la passerelle annonce des réseaux, comme les lignes route d'un fichier OpenVPN.",
  "DNS domains resolved through this VPN": "Domaines DNS résolus par ce VPN",
  "Connect Through": "Connecter à travers",
  "Chain this VPN through others: it then goes through whichever is up, or brings up the first one before itself.":
    "Chaîner ce VPN à d'autres : il passe alors par celui qui est connecté, ou connecte d'abord le premier.",
  "Connected normally, this VPN goes through the first of these that is up, or brings up %@ first; its networks may overlap theirs. The menu also offers to connect it directly.":
    "Connecté normalement, ce VPN passe par le premier de ceux-ci qui est connecté, ou connecte d'abord %@ ; ses réseaux peuvent chevaucher les leurs. Le menu permet aussi de le connecter directement.",
  "Allow networks that overlap another VPN's": "Autoriser les réseaux qui chevauchent ceux d'un autre VPN",
  "Without it, a VPN that would take traffic from another one is not connected.":
    "Sans cette option, un VPN qui prendrait le trafic d'un autre n'est pas connecté.",
  "Company VPN: never at the same time as another VPN": "VPN d'entreprise : jamais en même temps qu'un autre VPN",
  "Before it connects, the other VPNs are disconnected, after asking you. While it is up, the others wait.":
    "Avant sa connexion, les autres VPN sont déconnectés, après vous l'avoir demandé. Tant qu'il est connecté, les autres attendent.",
  "Disconnect automatically": "Déconnecter automatiquement",
  "Even with the app closed: the service disconnects. You are warned 5 minutes before and can postpone.":
    "Même quand l'app est fermée : c'est le service qui déconnecte. Vous êtes prévenu 5 minutes avant et pouvez prolonger.",
  "Limits": "Limites",
  "After being connected for": "Après une connexion de",
  "Reconnections after a drop do not start the time again. Postponing starts it again.":
    "Les reconnexions après une coupure ne relancent pas le décompte. Prolonger le relance.",
  "After no keyboard or mouse activity for": "Après une inactivité clavier et souris de",
  "Not available on Windows yet: the limit is kept for macOS.": "Pas encore disponible sous Windows : la limite est gardée pour macOS.",
  "At": "À",
  "The first time after connecting. Postponing moves it an hour later.": "La première fois après la connexion. Prolonger la recule d'une heure.",
  "Choose at least one limit.": "Choisissez au moins une limite.",
  "h": "h",
  "min": "min",
  "Create the VPN “%@”?": "Créer le VPN « %@ » ?",
  "Save the changes made to “%@”?": "Enregistrer les modifications de « %@ » ?",
  "Your changes are lost if you don’t save them.": "Vos modifications seront perdues si vous ne les enregistrez pas.",
  "Create": "Créer",
  "Save": "Enregistrer",
  "Don’t Save": "Ne pas enregistrer",
  "The VPN is added when you click Create.": "Le VPN est ajouté quand vous cliquez sur Créer.",
  "Unsaved changes": "Modifications non enregistrées",
  "Changes apply at the next connection.": "Les modifications s'appliqueront à la prochaine connexion.",
  "All changes are saved.": "Toutes les modifications sont enregistrées.",
  "Save and Reconnect": "Enregistrer et reconnecter",
  "Revert": "Annuler les modifications",
  "This WireGuard file cannot be imported": "Ce fichier WireGuard ne peut pas être importé",
  "This OpenVPN file cannot be imported": "Ce fichier OpenVPN ne peut pas être importé",
  "Import WireGuard File": "Importer un fichier WireGuard",
  "Import OpenVPN File": "Importer un fichier OpenVPN",
  "User password": "Mot de passe de l'utilisateur",
  "Optional: asked at the first connection otherwise": "Facultatif : sinon demandé à la première connexion",
  "Passwords are never imported. The certificates and keys of the file are copied into the profile: the file is no longer needed.":
    "Les mots de passe ne sont jamais importés. Les certificats et les clés du fichier sont recopiés dans le profil : le fichier n’est plus nécessaire.",
  "The keys of the file go to the Credential Manager, the rest into the profile: the file is no longer needed. Its commands (PostUp…) are never run.":
    "Les clés du fichier vont dans le Gestionnaire d'identification, le reste dans le profil : le fichier n'est plus nécessaire. Ses commandes (PostUp…) ne sont jamais exécutées.",
  "Add and Connect": "Ajouter et se connecter",
  "This VPN profile cannot be used": "Ce profil VPN est inutilisable",
  "Add a VPN from a profile file": "Ajouter un VPN depuis un fichier de profil",
  "Type": "Type",
  "All traffic goes through this VPN": "Tout le trafic passe par ce VPN",
  "Networks": "Réseaux",
  "Split Mode": "Mode split",
  "Name Resolution": "Résolution de noms",
  "Names ending in .%@": "Noms se terminant par .%@",
  "Check the server and the fingerprint with whoever sent you this file before adding it.":
    "Vérifiez le serveur et l'empreinte auprès de la personne qui vous a envoyé ce fichier avant de l'ajouter.",
  "A VPN of that name exists already: choose another name.": "Un VPN porte déjà ce nom : choisissez-en un autre.",
  "Cannot connect “%@”": "Impossible de connecter « %@ »",
  "VPN profile": "Profil VPN",
  "OpenVPN or WireGuard configuration": "Configuration OpenVPN ou WireGuard",
  "Certificate (PEM or DER)": "Certificat (PEM ou DER)",
  "All files": "Tous les fichiers",
  "Paste the lines, one entry per line: the network or domain, then its note.":
    "Collez les lignes, une entrée par ligne : le réseau ou le domaine, puis sa note.",
};
function tr(text, ...args) {
  let s = FRENCH ? (FR[text] ?? text) : text;
  for (const a of args) s = s.replace(/%@|%lld/, String(a));
  return s;
}

const KIND_NAMES = { "forti-ssl": "SSL VPN", ipsec: "IPsec", openvpn: "OpenVPN", l2tp: "L2TP", wireguard: "WireGuard" };
const KIND_OF_FORM = { FortiSsl: "forti-ssl", Ipsec: "ipsec", OpenVpn: "openvpn", L2tp: "l2tp", WireGuard: "wireguard" };
const kindName = (protocol) => tr(KIND_NAMES[protocol] ?? protocol);
const SECRET_KEYS = ["password", "psk", "private_key"];

// ---------------------------------------------------------------- state

let profiles = []; // ProfileSummary, in file order
let sessions = []; // SessionInfo
const ui = {
  selection: null, // { profile: id } or { folder: path }
  original: null, // id being edited; null for a new profile
  form: null,
  saved: null,
  error: null,
  typed: {}, // secrets typed, by key
  forgotten: new Set(),
  stored: new Set(),
  storedQuery: 0,
  tab: "general",
  advanced: false,
  offering: false, // split mode offered (Network tab), not saved
  parked: [], // the split list while not offered
  lastPfs: 14,
  collapsed: new Set(),
  identities: null, // certificate store, loaded once per window
  identitiesError: null,
  local: {}, // messages of sections (CA file, static key, proposals)
  lastOptions: {}, // connection options per id, for Save and Reconnect
};

function readList(key) {
  try { return JSON.parse(localStorage.getItem(key) ?? "[]"); } catch { return []; }
}
function writeList(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* not kept */ }
}
let emptyFolders = readList("emptyFolders");
function announcedOf(id) {
  try { return JSON.parse(localStorage.getItem(`announced:${id}`) ?? "null"); } catch { return null; }
}

const isNew = () => ui.form !== null && ui.original === null;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function hasChanges() {
  if (!ui.form) return false;
  return isNew() || !same(ui.form, ui.saved) || Object.values(ui.typed).some((v) => v) || ui.forgotten.size > 0;
}
const sessionOf = (id) => sessions.find((s) => s.id === id);
function isOn(id) {
  const s = sessionOf(id);
  return !!s && ["connecting", "connected", "reconnecting"].includes(s.state);
}
const profileById = (id) => profiles.find((p) => p.id === id);

// ---------------------------------------------------------------- helpers

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (k === "checked" || k === "disabled" || k === "value" || k === "hidden") node[k] = v;
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const child of children.flat()) if (child !== null && child !== undefined && child !== false) node.append(child);
  return node;
}
const caption = (text) => el("p", { class: "caption" }, text);
const warning = (text) => el("p", { class: "warning" }, text);

async function call(command, args) {
  try {
    return await invoke(command, args);
  } catch (e) {
    throw new Error(String(e));
  }
}
const changedProfiles = () => invoke("profiles_changed").catch(() => {});

// ---------------------------------------------------------------- popups

function closeMenu() { document.getElementById("menu").hidden = true; }
/** A menu at (x, y): items { label, action, disabled } or "-". */
function popup(x, y, items) {
  const menu = document.getElementById("menu");
  menu.replaceChildren(...items.map((item) => item === "-" ? el("hr") : el("button", {
    disabled: item.disabled,
    onclick: () => { closeMenu(); item.action(); },
  }, item.label)));
  menu.hidden = false;
  const r = menu.getBoundingClientRect();
  menu.style.left = `${Math.min(x, innerWidth - r.width - 4)}px`;
  menu.style.top = `${Math.min(y, innerHeight - r.height - 4)}px`;
}
document.addEventListener("mousedown", (e) => { if (!e.target.closest("#menu")) closeMenu(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeMenu(); });
function popupBelow(button, items) {
  const r = button.getBoundingClientRect();
  popup(r.left, r.bottom + 2, items);
}

/**
 * A modal: title, text, an optional body, buttons { id, label, primary,
 * danger }. `act(id)` may keep it open by returning false. Resolves to the
 * button's id ("cancel" for Esc).
 */
function modal({ title, text = "", body = null, buttons, act = null, focus = null }) {
  return new Promise((resolve) => {
    const dialog = document.getElementById("modal");
    document.getElementById("modal-title").textContent = title;
    const t = document.getElementById("modal-text");
    t.textContent = text;
    t.hidden = !text;
    document.getElementById("modal-body").replaceChildren(...(body ? [body] : []));
    const finish = (id) => { dialog.close(); resolve(id); };
    const press = async (id) => {
      if (act && id !== "cancel") {
        const keep = (await act(id)) === false;
        if (keep) return;
      }
      finish(id);
    };
    document.getElementById("modal-buttons").replaceChildren(...buttons.map((b) => el("button", {
      type: b.primary ? "submit" : "button",
      class: b.primary ? "primary" : b.danger ? "danger" : "",
      disabled: b.disabled,
      "data-id": b.id,
      onclick: (e) => { e.preventDefault(); press(b.id); },
    }, b.label)));
    dialog.oncancel = (e) => { e.preventDefault(); finish("cancel"); };
    dialog.querySelector("form").onsubmit = (e) => {
      e.preventDefault();
      const primary = buttons.find((b) => b.primary && !b.disabled);
      if (primary) press(primary.id);
    };
    dialog.showModal();
    (focus ?? dialog.querySelector("#modal-body input, #modal-body textarea, menu .primary"))?.focus();
  });
}
const alertBox = (title, text = "") => modal({ title, text, buttons: [{ id: "ok", label: tr("OK"), primary: true }] });

/** Asks for a line of text; null when cancelled. */
async function askText(title, text, value = "", okLabel = tr("OK")) {
  const input = el("input", { type: "text", value });
  const id = await modal({
    title, text, body: input, focus: input,
    buttons: [{ id: "cancel", label: tr("Cancel") }, { id: "ok", label: okLabel, primary: true }],
  });
  return id === "ok" ? input.value : null;
}

// ---------------------------------------------------------------- folders

function normalizeFolder(text) {
  return text.split("/").map((p) => p.trim()).filter(Boolean).join("/");
}
function allFolders() {
  const set = new Set();
  const add = (path) => {
    const parts = path.split("/");
    for (let i = 1; i <= parts.length; i++) set.add(parts.slice(0, i).join("/"));
  };
  for (const p of profiles) if (p.folder) add(p.folder);
  for (const f of emptyFolders) add(f);
  return [...set].sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" }));
}
function dropUsedEmptyFolders() {
  const used = new Set(profiles.map((p) => p.folder).filter(Boolean));
  emptyFolders = emptyFolders.filter((f) => !used.has(f) && !profiles.some((p) => p.folder?.startsWith(`${f}/`)));
  writeList("emptyFolders", emptyFolders);
}

async function newFolder(parent = null, then = null) {
  const typed = await askText(tr("New Folder"), tr("“/” separates subfolders, as in Clients/Acme."));
  if (typed === null) return;
  const name = normalizeFolder(typed);
  if (!name) return;
  const path = parent ? `${parent}/${name}` : name;
  if (!allFolders().includes(path)) {
    emptyFolders.push(path);
    writeList("emptyFolders", emptyFolders);
  }
  if (parent) ui.collapsed.delete(parent);
  if (then) await then(path);
  renderTree();
}

async function renameFolder(path) {
  const last = path.split("/").pop();
  const typed = await askText(tr("Rename “%@”", last), tr("“/” separates subfolders, as in Clients/Acme."), path);
  if (typed === null) return;
  const renamed = normalizeFolder(typed);
  if (!renamed || renamed === path) return;
  await leave(async () => {
    for (const p of profiles) {
      if (p.folder === path || p.folder?.startsWith(`${path}/`)) {
        try {
          await call("move_profile", { id: p.id, folder: renamed + p.folder.slice(path.length), before: null });
        } catch (e) {
          await alertBox(tr("Cannot move “%@”", p.name), e.message);
        }
      }
    }
    emptyFolders = emptyFolders.map((f) => (f === path || f.startsWith(`${path}/`) ? renamed + f.slice(path.length) : f));
    writeList("emptyFolders", emptyFolders);
    if (ui.selection?.folder === path) ui.selection = { folder: renamed };
    await profilesMoved();
  });
}

async function moveTo(id, folder, before = null) {
  await leave(async () => {
    const p = profileById(id);
    if (!p) return;
    try {
      await call("move_profile", { id, folder, before });
    } catch (e) {
      await alertBox(tr("Cannot move “%@”", p.name), e.message);
    }
    await profilesMoved();
  });
}

async function profilesMoved() {
  await loadProfiles();
  dropUsedEmptyFolders();
  if (ui.original) await select(ui.original, true);
  changedProfiles();
  render();
}

// ---------------------------------------------------------------- list

async function loadProfiles() {
  try {
    profiles = await call("profile_summaries");
  } catch (e) {
    profiles = [];
    ui.error = e.message;
  }
}

async function loadSessions() {
  try {
    sessions = await invoke("sessions");
  } catch {
    sessions = [];
  }
  for (const s of sessions) {
    if (s.announced) {
      try {
        localStorage.setItem(`announced:${s.id}`, JSON.stringify({ ...s.announced, at: Date.now() }));
      } catch { /* not kept */ }
    }
  }
}

function renderTree() {
  const tree = document.getElementById("tree");
  const scroll = tree.scrollTop;
  tree.replaceChildren();
  const folders = allFolders();
  const level = (parent, depth) => {
    const children = folders.filter((f) => {
      const i = f.lastIndexOf("/");
      return (i < 0 ? null : f.slice(0, i)) === parent;
    });
    for (const f of children) {
      const open = !ui.collapsed.has(f);
      const row = el("div", {
        class: `item${ui.selection?.folder === f ? " selected" : ""}`,
        style: `padding-left:${8 + depth * 14}px`,
        onclick: () => leave(() => showFolder(f)),
        ondblclick: () => renameFolder(f),
        oncontextmenu: (e) => {
          e.preventDefault();
          popup(e.clientX, e.clientY, [
            { label: tr("New Folder Inside…"), action: () => newFolder(f) },
            { label: tr("Rename Folder…"), action: () => renameFolder(f) },
          ]);
        },
      },
      el("span", {
        class: "twisty",
        onclick: (e) => { e.stopPropagation(); open ? ui.collapsed.add(f) : ui.collapsed.delete(f); renderTree(); },
      }, open ? "▾" : "▸"),
      el("span", { class: "icon" }, "📁"),
      el("span", { class: "lines" }, el("div", { class: "title" }, f.split("/").pop())));
      dropTarget(row, (id) => moveTo(id, f, null));
      tree.append(row);
      if (open) level(f, depth + 1);
    }
    for (const p of profiles.filter((p) => (p.folder ?? null) === parent)) {
      const s = sessionOf(p.id);
      const row = el("div", {
        class: `item${ui.selection?.profile === p.id ? " selected" : ""}`,
        style: `padding-left:${8 + depth * 14 + 18}px`,
        draggable: "true",
        onclick: () => {
          if (ui.selection?.profile === p.id && ui.form) return;
          leave(() => select(p.id));
        },
        ondblclick: () => rename(p.id),
        oncontextmenu: (e) => { e.preventDefault(); popup(e.clientX, e.clientY, profileMenu(p)); },
        ondragstart: (e) => { e.dataTransfer.setData("text/plain", p.id); e.dataTransfer.effectAllowed = "move"; },
      },
      el("span", { class: `dot ${s?.state ?? ""}` }),
      el("span", { class: "lines" },
        el("div", { class: "title" }, p.name),
        el("div", { class: "sub" }, kindName(p.protocol))));
      dropTarget(row, (id) => id !== p.id && moveTo(id, p.folder ?? null, p.id));
      tree.append(row);
    }
  };
  level(null, 0);
  tree.scrollTop = scroll;
  document.getElementById("remove").disabled = !ui.selection?.profile;
}

function dropTarget(node, onDrop) {
  node.addEventListener("dragover", (e) => { e.preventDefault(); e.stopPropagation(); node.classList.add("drop"); });
  node.addEventListener("dragleave", () => node.classList.remove("drop"));
  node.addEventListener("drop", (e) => {
    e.preventDefault();
    e.stopPropagation();
    node.classList.remove("drop");
    const id = e.dataTransfer.getData("text/plain");
    if (profileById(id)) onDrop(id);
  });
}

function connectItems(p) {
  if (isOn(p.id)) return [{ label: tr("Disconnect"), action: () => disconnect(p.id) }];
  const items = [{ label: tr("Connect"), action: () => leave(() => connect(p.id)) }];
  if (p.split_routes?.length) items.push({ label: tr("Connect in Split Mode"), action: () => leave(() => connect(p.id, { split: true })) });
  if (p.via?.length) {
    const names = p.via.map((v) => profileById(v)?.name ?? v).join(" / ");
    items.push({ label: tr("Connect Directly, Without %@", names), action: () => leave(() => connect(p.id, { direct: true })) });
  }
  return items;
}

function profileMenu(p) {
  const folders = allFolders();
  return [
    { label: tr("Rename…"), action: () => rename(p.id) },
    { label: tr("Duplicate"), action: () => duplicate(p.id) },
    "-",
    ...connectItems(p),
    "-",
    {
      label: `${tr("Move to Folder")} ▸`,
      action: () => {
        const r = document.querySelector(".item.selected")?.getBoundingClientRect();
        popup(r ? r.right : 200, r ? r.top : 100, [
          { label: tr("None"), action: () => moveTo(p.id, null) },
          ...(folders.length ? ["-", ...folders.map((f) => ({ label: f, action: () => moveTo(p.id, f) }))] : []),
          "-",
          { label: tr("New Folder…"), action: () => newFolder(null, (path) => moveTo(p.id, path)) },
        ]);
      },
    },
    "-",
    { label: tr("Delete…"), action: () => remove(p.id) },
  ];
}

// ---------------------------------------------------------------- actions

async function connect(id, options = {}) {
  ui.lastOptions[id] = options;
  try {
    await call("connect", { id, direct: !!options.direct, split: !!options.split });
  } catch (e) {
    await alertBox(tr("Cannot connect “%@”", profileById(id)?.name ?? id), e.message);
  }
}
async function disconnect(id) {
  try { await call("disconnect", { id }); } catch { /* shown by the session */ }
}

async function rename(id) {
  await leave(async () => {
    await select(id);
    let typed = ui.saved?.name ?? "";
    for (;;) {
      const value = await askText(tr("Rename “%@”", ui.saved.name), tr("Up to 64 characters, without “/”; unique in its folder."), typed, tr("Rename"));
      if (value === null) return;
      typed = value.trim();
      if (!typed || typed === ui.saved.name) return;
      try {
        await call("save_profile", { original: id, form: { ...ui.saved, name: typed }, secrets: {} });
        await loadProfiles();
        await select(id, true);
        changedProfiles();
        render();
        return;
      } catch (e) {
        await alertBox(tr("Cannot rename “%@”", ui.saved.name), e.message);
      }
    }
  });
}

async function duplicate(id) {
  await leave(async () => {
    const p = profileById(id);
    try {
      const copy = await call("duplicate_profile", { id, name: tr("%@ copy", p.name) });
      await loadProfiles();
      await select(copy.id);
      changedProfiles();
      render();
      if (copy.secrets_error) {
        await alertBox(tr("The saved secrets of “%@” were not copied", p.name), tr("Type them in the copy's editor. %@", copy.secrets_error));
      }
    } catch (e) {
      await alertBox(tr("Cannot duplicate “%@”", p.name), e.message);
    }
  });
}

async function remove(id) {
  const p = profileById(id);
  if (!p) return;
  if (isOn(id)) {
    await alertBox(tr("“%@” is connected", p.name), tr("Disconnect it before deleting it."));
    return;
  }
  const answer = await modal({
    title: tr("Delete “%@”?", p.name),
    text: tr("The profile and its saved secrets are removed. The other profiles and the comments in your file are left unchanged."),
    buttons: [{ id: "cancel", label: tr("Cancel") }, { id: "delete", label: tr("Delete"), danger: true }],
  });
  if (answer !== "delete") return;
  try {
    await call("remove_profile", { id });
  } catch (e) {
    await alertBox(tr("Cannot delete the profile"), e.message);
    return;
  }
  if (sessionOf(id)) disconnect(id);
  await loadProfiles();
  changedProfiles();
  if (ui.original === id || ui.selection?.profile === id) {
    ui.form = ui.saved = ui.original = null;
    await select(profiles[0]?.id ?? null);
  }
  render();
}

async function exportProfile(id) {
  const p = profileById(id);
  const path = await files.save({ defaultPath: `${p.name}.vpnprofile`, filters: [{ name: tr("VPN profile"), extensions: ["vpnprofile"] }] });
  if (!path) return;
  try {
    await call("export_profile", { id, path });
  } catch (e) {
    await alertBox(tr("Cannot export the profile"), e.message);
  }
}

// ---------------------------------------------------------------- editing state

async function select(id, keepTab = false) {
  ui.selection = id ? { profile: id } : null;
  ui.error = null;
  ui.local = {};
  if (!keepTab) ui.tab = "general";
  ui.advanced = false;
  if (!id) {
    ui.form = ui.saved = ui.original = null;
  } else {
    try {
      const form = await call("profile_form", { id });
      ui.form = form;
      ui.saved = structuredClone(form);
      ui.original = id;
    } catch (e) {
      ui.form = ui.saved = ui.original = null;
      ui.error = e.message;
    }
  }
  resetNetworkState();
  clearSecrets();
}

function showFolder(path) {
  ui.selection = { folder: path };
  ui.form = ui.saved = ui.original = null;
  ui.error = null;
  clearSecrets();
  render();
}

function resetNetworkState() {
  ui.offering = false;
  ui.parked = [];
  const f = ui.form;
  ui.lastPfs = f ? (f.pfs_group ?? f.phase1_dh_groups?.[0] ?? 14) : 14;
}

function clearSecrets() {
  ui.typed = {};
  ui.forgotten = new Set();
  ui.stored = new Set();
  const id = ui.original;
  const query = ++ui.storedQuery;
  if (!id) return;
  call("stored_secrets", { id, keys: SECRET_KEYS }).then((found) => {
    if (query !== ui.storedQuery) return;
    ui.stored = new Set(Object.entries(found).filter(([, v]) => v).map(([k]) => k));
    if (ui.form) renderBody();
  }).catch(() => {});
}

async function startNew(kind) {
  const folder = ui.selection?.folder ?? null;
  await leave(async () => {
    ui.selection = null;
    ui.original = ui.saved = null;
    ui.error = null;
    ui.local = {};
    ui.tab = "general";
    ui.advanced = false;
    ui.form = await call("new_profile_form", { kind });
    if (folder) ui.form.folder = folder;
    resetNetworkState();
    clearSecrets();
    render();
  });
}

async function revert() {
  if (isNew()) {
    ui.form = null;
    await select(profiles[0]?.id ?? null);
  } else {
    ui.form = structuredClone(ui.saved);
    ui.error = null;
    ui.local = {};
    resetNetworkState();
    clearSecrets();
  }
  render();
}

/** Saves the form and its secrets; false (with `ui.error`) on failure. */
async function save() {
  const f = ui.form;
  const secrets = {};
  for (const key of ui.forgotten) secrets[key] = null;
  if (!f.save_password) secrets.password = null;
  for (const [key, value] of Object.entries(ui.typed)) {
    if (!value) continue;
    if (key === "password" && !f.save_password) continue;
    secrets[key] = value;
  }
  try {
    const result = await call("save_profile", { original: ui.original, form: f, secrets });
    ui.original = result.id;
    ui.selection = { profile: result.id };
    ui.saved = structuredClone(f);
    await loadProfiles();
    changedProfiles();
    if (result.error) {
      ui.error = result.error;
      renderTree();
      renderChrome();
      return false;
    }
    ui.error = null;
    clearSecrets();
    // The form as Rust reads it back (trimmed lists, normalized folder).
    try {
      const form = await call("profile_form", { id: result.id });
      ui.form = form;
      ui.saved = structuredClone(form);
    } catch { /* kept as typed */ }
    render();
    return true;
  } catch (e) {
    ui.error = e.message;
    renderChrome();
    return false;
  }
}

/** Runs `then` once the edits are saved or dropped, as the user says. */
async function leave(then) {
  if (!hasChanges()) return then();
  const name = ui.form.name || tr("New VPN");
  const answer = await modal({
    title: isNew() ? tr("Create the VPN “%@”?", name) : tr("Save the changes made to “%@”?", name),
    text: tr("Your changes are lost if you don’t save them."),
    buttons: [
      { id: "drop", label: tr("Don’t Save"), danger: true },
      { id: "cancel", label: tr("Cancel") },
      { id: "save", label: isNew() ? tr("Create") : tr("Save"), primary: true },
    ],
  });
  if (answer === "save") {
    if (await save()) return then();
  } else if (answer === "drop") {
    ui.form = ui.saved ? structuredClone(ui.saved) : null;
    clearSecrets();
    return then();
  }
}

// ---------------------------------------------------------------- bindings

/**
 * Keys of focusable controls survive a re-render: the one that had the
 * focus gets it back, with its caret.
 */
function rerender(fn) {
  const active = document.activeElement;
  const key = active?.dataset?.key;
  const start = active?.selectionStart;
  const end = active?.selectionEnd;
  const body = document.querySelector(".ed-body");
  const scroll = body?.scrollTop;
  fn();
  const nextBody = document.querySelector(".ed-body");
  if (nextBody && scroll !== undefined) nextBody.scrollTop = scroll;
  if (key) {
    const again = document.querySelector(`[data-key="${CSS.escape(key)}"]`);
    if (again) {
      again.focus();
      try { if (start !== undefined && start !== null) again.setSelectionRange(start, end); } catch { /* not text */ }
    }
  }
}
const edited = () => renderChrome();
const editedDeep = () => rerender(renderBody);

const conv = {
  text: { get: (v) => v ?? "", set: (s) => s },
  opt: { get: (v) => v ?? "", set: (s) => (s === "" ? null : s) },
  port: {
    get: (v) => (v ? String(v) : ""),
    set: (s) => { const n = parseInt(s.replace(/\D/g, ""), 10); return Number.isFinite(n) && n <= 65535 ? n : 0; },
  },
  num: {
    get: (v) => String(v ?? 0),
    set: (s) => { const n = parseInt(s.replace(/\D/g, "").slice(0, 9), 10); return Number.isFinite(n) ? n : 0; },
  },
  optnum: {
    get: (v) => (v === null || v === undefined ? "" : String(v)),
    set: (s) => { const d = s.replace(/\D/g, "").slice(0, 5); if (!d) return null; const n = parseInt(d, 10); return n <= 65535 ? n : null; },
  },
  lines: { get: (v) => (v ?? []).join("\n"), set: (s) => s.split("\n") },
};

/** A text input bound to `obj[field]` through a conversion. */
function input(obj, field, key, { as = "text", placeholder = "", cls = "", type = "text", deep = false, title = null, disabled = false } = {}) {
  const c = conv[as];
  const node = el("input", {
    type, class: cls, placeholder, "data-key": key, value: c.get(obj[field]), title, disabled,
    spellcheck: "false", autocomplete: "off",
    oninput: () => { obj[field] = c.set(node.value); deep ? editedDeep() : edited(); },
  });
  return node;
}
function textarea(obj, field, key, { mono = true, deep = false } = {}) {
  const node = el("textarea", {
    class: mono ? "mono" : "", "data-key": key, spellcheck: "false",
    oninput: () => { obj[field] = conv.lines.set(node.value); deep ? editedDeep() : edited(); },
  });
  node.value = conv.lines.get(obj[field]);
  return node;
}
function checkbox(label, checked, onChange, { title = null, disabled = false, key = null } = {}) {
  const box = el("input", { type: "checkbox", checked, disabled, "data-key": key, onchange: () => onChange(box.checked) });
  return el("label", { class: "check", title }, box, label);
}
/** A checkbox bound to a boolean field; the body is shown again. */
const toggle = (label, obj, field, opts = {}) =>
  checkbox(label, !!obj[field], (v) => { obj[field] = v; editedDeep(); }, { key: field, ...opts });
/** A select of [value, label] options; `value` is compared as JSON. */
function choice(options, value, onChange, { key = null, disabled = false } = {}) {
  const node = el("select", { "data-key": key, disabled, onchange: () => onChange(options[node.selectedIndex][0]) },
    options.map(([v, label]) => el("option", {}, label)));
  const i = options.findIndex(([v]) => same(v, value));
  node.selectedIndex = Math.max(0, i);
  return node;
}
function radios(name, options, value, onChange, { vertical = false } = {}) {
  return el("div", { class: `radios${vertical ? " vertical" : ""}` }, options.map(([v, label]) => {
    const r = el("input", { type: "radio", name, checked: same(v, value), onchange: () => onChange(v) });
    return el("label", { class: "check" }, r, label);
  }));
}
/** A row: label on the left, controls on the right, notes under them. */
function field(label, controls, ...notes) {
  return el("div", { class: "field" },
    el("div", { class: "label" }, label),
    el("div", { class: "control" }, controls),
    ...notes.filter(Boolean));
}
function block(label, control, ...notes) {
  return el("div", { class: "block" }, el("div", { class: "label" }, label), control, ...notes.filter(Boolean));
}
function section(title, ...children) {
  return el("div", { class: "section" }, title ? el("h3", {}, title) : null, ...children.flat().filter(Boolean));
}
function disclosure(...children) {
  return [
    el("button", {
      class: `disclosure${ui.advanced ? " open" : ""}`,
      onclick: () => { ui.advanced = !ui.advanced; editedDeep(); },
    }, tr("Advanced Options")),
    ...(ui.advanced ? children.flat() : []),
  ];
}

// ---------------------------------------------------------------- editor pieces

function secretField(key, label) {
  const stored = ui.stored.has(key) && !ui.forgotten.has(key);
  const node = el("input", {
    type: "password", "data-key": `secret:${key}`, autocomplete: "new-password",
    placeholder: stored ? tr("Saved in the Credential Manager") : tr("Asked at connection"),
    oninput: () => {
      ui.typed[key] = node.value;
      if (node.value) ui.forgotten.delete(key);
      key === "private_key" ? editedDeep() : edited();
    },
  });
  node.value = ui.typed[key] ?? "";
  return field(label, [
    node,
    stored ? el("button", {
      title: tr("Removes the saved value from the Credential Manager when you save."),
      onclick: () => { ui.forgotten.add(key); editedDeep(); },
    }, tr("Forget")) : null,
  ]);
}

function loadIdentities() {
  if (ui.identities !== null || ui.identitiesLoading) return;
  ui.identitiesLoading = true;
  call("identities").then((ids) => { ui.identities = ids; }).catch((e) => {
    ui.identities = [];
    ui.identitiesError = e.message;
  }).finally(() => { ui.identitiesLoading = false; if (ui.form) editedDeep(); });
}

function clientCertificateSection(filesInProfile) {
  const f = ui.form;
  loadIdentities();
  const now = Date.now() / 1000;
  const options = [[null, tr("None")]];
  for (const i of ui.identities ?? []) {
    const issued = tr("issued by %@", i.issuer);
    options.push([i.sha256, i.not_after && i.not_after < now ? `${i.name} (${issued}, ${tr("expired")})` : `${i.name} (${issued})`]);
  }
  if (f.client_certificate && !options.some(([v]) => v === f.client_certificate)) {
    options.push([f.client_certificate, tr("Not in the certificate store")]);
  }
  const fromFile = f.kind === "OpenVpn"
    ? tr("The certificate imported with the OpenVPN file is used. A certificate from the store would replace it.")
    : tr("The certificate files named in the profile file are used. A certificate from the store would replace them.");
  return section(tr("Client Certificate"),
    field(tr("Certificate"), choice(options, f.client_certificate, (v) => { f.client_certificate = v; editedDeep(); }, { key: "client_certificate" }),
      ui.identitiesError ? warning(ui.identitiesError) : null,
      filesInProfile && !f.client_certificate ? caption(fromFile) : null,
      caption(f.client_certificate
        ? tr("The key stays in the certificate store, which may ask you to allow its use at connection.")
        : tr("Certificates with their private key in your personal certificate store, such as one installed by your organization."))));
}

async function chooseCertificateFile(localKey) {
  const path = await files.open({
    multiple: false,
    filters: [{ name: tr("Certificate (PEM or DER)"), extensions: ["pem", "crt", "cer", "der"] }, { name: tr("All files"), extensions: ["*"] }],
  });
  if (!path) return;
  try {
    ui.form.ca_pem = await call("certificate_file", { path });
    delete ui.local[localKey];
  } catch (e) {
    ui.local[localKey] = e.message;
  }
  editedDeep();
}

function caRow(localKey, emptyText) {
  const f = ui.form;
  const names = f.ca_pem ? (ui.certNames?.pem === f.ca_pem ? ui.certNames.names : null) : [];
  if (names === null) {
    call("certificate_names", { pem: f.ca_pem }).then((n) => { ui.certNames = { pem: f.ca_pem, names: n }; editedDeep(); });
  }
  return field(tr("Certificate Authority"), [
    el("div", { style: "flex:1 1 200px" }, names?.length ? names.map((n) => el("div", { class: "caption" }, n)) : el("span", { class: "muted" }, emptyText)),
    el("button", { onclick: () => chooseCertificateFile(localKey) }, tr("Choose…")),
    f.ca_pem ? el("button", { onclick: () => { f.ca_pem = null; editedDeep(); } }, tr("Remove")) : null,
  ], ui.local[localKey] ? warning(ui.local[localKey]) : null);
}

function fingerprints() {
  return block(tr("Trusted certificate fingerprints (SHA-256, one per line)"), textarea(ui.form, "trusted_certificates", "trusted_certificates"));
}

function gatewayCertificateSection() {
  return section(tr("Gateway Certificate"),
    caRow("gatewayCa", tr("Authorities trusted by Windows")),
    caption(tr("Authorities trusted by Windows, such as those your organization installs, are always accepted.")),
    fingerprints(),
    caption(tr("A certificate that cannot be verified is shown at the first connection, so you can decide to trust it.")));
}

function serversSection() {
  const f = ui.form;
  const rows = f.servers.map((s, i) => el("div", { class: "control", style: "margin:4px 0" },
    input(s, "host", `server-host-${i}`, { placeholder: "vpn.example.com", deep: false }),
    input(s, "port", `server-port-${i}`, { as: "port", placeholder: "1194", cls: "narrow" }),
    choice([["Udp", "UDP"], ["Tcp", "TCP"]], s.transport, (v) => { s.transport = v; edited(); }, { key: `server-transport-${i}` }),
    el("button", {
      class: "icon-button", title: tr("Remove"), disabled: f.servers.length <= 1,
      onclick: () => { f.servers.splice(i, 1); editedDeep(); },
    }, "⊖")));
  return section(tr("Servers"), rows,
    el("div", { class: "row-gap" }, el("button", {
      disabled: f.servers.length >= 16,
      onclick: () => {
        const last = f.servers[f.servers.length - 1];
        f.servers.push({ host: "", port: last?.port ?? 1194, transport: last?.transport ?? "Udp" });
        editedDeep();
      },
    }, `⊕ ${tr("Add a Server")}`)),
    f.servers.length > 1 ? caption(tr("The servers are tried in this order.")) : null);
}

function serverCertificateSection() {
  const f = ui.form;
  return section(tr("Server Certificate"),
    caRow("serverCa", tr("None")),
    caption(tr("Only this authority is trusted, not the system's: OpenVPN servers have their own.")),
    fingerprints(),
    caption(tr("With fingerprints, only these certificates are accepted and the authority is not needed.")),
    field(tr("Server Name"), input(f, "verify_x509_name", "verify_x509_name", {
      as: "opt", placeholder: tr("Optional"), deep: true, title: tr("The name the server certificate must carry (verify-x509-name)."),
    })),
    f.verify_x509_name !== null ? field(tr("Compared With"), choice(
      [["Subject", tr("Whole subject")], ["Name", tr("Common name")], ["NamePrefix", tr("Start of the common name")]],
      f.verify_x509_match, (v) => { f.verify_x509_match = v; edited(); }, { key: "verify_x509_match" })) : null,
    field("", toggle(tr("Require a certificate meant for a server"), f, "remote_cert_tls", { title: "remote-cert-tls server" }),
      f.remote_cert_tls ? null : warning(tr("Without it, any client of the same authority could pose as the server."))));
}

async function chooseStaticKey() {
  const path = await files.open({ multiple: false });
  if (!path) return;
  try {
    const text = await call("read_text", { path });
    if (!text.includes("-----BEGIN OpenVPN Static key V1-----")) {
      ui.local.staticKey = tr("This file is not an OpenVPN static key.");
    } else {
      ui.form.static_key = text;
      delete ui.local.staticKey;
    }
  } catch (e) {
    ui.local.staticKey = e.message;
  }
  editedDeep();
}

function openVpnAdvanced() {
  const f = ui.form;
  const ciphers = ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"];
  const has = (c) => f.data_ciphers.some((d) => d.toUpperCase() === c);
  return [
    field(tr("Control Channel"), choice([["None", tr("None")], ["TlsAuth", "tls-auth"], ["TlsCrypt", "tls-crypt"]],
      f.control_channel, (v) => { f.control_channel = v; editedDeep(); }, { key: "control_channel" })),
    f.control_channel !== "None" ? field(tr("Static Key"), [
      el("span", { class: "muted", style: "flex:1" }, f.static_key ? tr("OpenVPN static key") : tr("None")),
      el("button", { onclick: chooseStaticKey }, tr("Choose…")),
    ], ui.local.staticKey ? warning(ui.local.staticKey) : null) : null,
    f.control_channel === "TlsAuth" ? field(tr("Key Direction"), choice([[null, tr("Both directions")], [0, "0"], [1, "1"]],
      f.key_direction, (v) => { f.key_direction = v; edited(); }, { key: "key_direction" })) : null,
    f.control_channel === "TlsAuth" ? field(tr("HMAC Digest"), choice(["SHA1", "SHA256", "SHA384", "SHA512"].map((d) => [d, d]),
      f.auth_digest.toUpperCase(), (v) => { f.auth_digest = v; edited(); }, { key: "auth_digest" })) : null,
    field(tr("Data Ciphers"), ciphers.map((c) => checkbox(c, has(c), (on) => {
      f.data_ciphers = on ? [...f.data_ciphers, c] : f.data_ciphers.filter((d) => d.toUpperCase() !== c);
      editedDeep();
    }, { key: `cipher-${c}` })), f.data_ciphers.length ? null : warning(tr("Choose at least one cipher."))),
    field(tr("Compression"), choice([["None", tr("None")], ["Lzo", "comp-lzo"], ["Stub", "compress"], ["StubV2", "compress stub-v2"]],
      f.compression, (v) => { f.compression = v; edited(); }, { key: "compression" }),
      caption(tr("Packets are never compressed: choose the framing the server expects."))),
    field(tr("Renegotiate Keys Every"), [input(f, "reneg_sec", "reneg_sec", { as: "num", cls: "narrow" }), tr("seconds")]),
    f.password_auth ? field(tr("Code Question"), input(f, "static_challenge", "static_challenge", {
      as: "opt", placeholder: tr("Optional"), deep: true, title: tr("A one-time code asked with the password (static-challenge)."),
    })) : null,
    f.password_auth && f.static_challenge !== null ? field("", toggle(tr("Show the code while it is typed"), f, "static_challenge_echo")) : null,
  ];
}

const ENCRYPTIONS = [
  ["aes128", "AES128"], ["aes192", "AES192"], ["aes256", "AES256"], ["aes128gcm16", "AES128-GCM"],
  ["aes256gcm16", "AES256-GCM"], ["chacha20poly1305", "ChaCha20-Poly1305"], ["3des", "3DES"],
];
const HASHES = [["sha1", "SHA1"], ["sha256", "SHA256"], ["sha384", "SHA384"], ["sha512", "SHA512"]];
const DH = [[2, "MODP 1024"], [5, "MODP 1536"], [14, "MODP 2048"], [15, "MODP 3072"], [16, "MODP 4096"], [17, "MODP 6144"],
  [18, "MODP 8192"], [19, "ECP 256"], [20, "ECP 384"], [21, "ECP 521"], [31, "Curve25519"]];
const DH_ORDER = [21, 20, 19, 31, 18, 17, 16, 15, 14, 5, 2];
const aead = (e) => e.includes("gcm") || e === "chacha20poly1305";

function suiteRows(suites, { gcm, ikev2, legacy, phase1, key }) {
  const rows = suites.map((s, i) => {
    const offered = ENCRYPTIONS.filter(([v]) => (v.includes("gcm") ? gcm : v === "chacha20poly1305" ? ikev2 : v === "3des" ? legacy : true) || v === s.encryption);
    const showHash = !aead(s.encryption) || phase1;
    return field(i === 0 ? tr("Proposals") : "", [
      choice(offered, s.encryption, (v) => { s.encryption = v; editedDeep(); }, { key: `${key}-enc-${i}` }),
      showHash ? el("span", { class: "muted" }, aead(s.encryption) ? tr("PRF") : tr("Authentication")) : null,
      showHash ? choice(HASHES, s.hash, (v) => { s.hash = v; edited(); }, { key: `${key}-hash-${i}` }) : null,
      el("button", { class: "icon-button", title: tr("Remove"), disabled: suites.length <= 1, onclick: () => { suites.splice(i, 1); editedDeep(); } }, "⊖"),
    ]);
  });
  const any = (test) => suites.some((s) => test(s.encryption));
  return [
    ...rows,
    !gcm && any((e) => e.includes("gcm")) ? warning(tr("AES-GCM in phase 1 needs IKEv2.")) : null,
    !ikev2 && any((e) => e === "chacha20poly1305") ? warning(tr("ChaCha20-Poly1305 needs IKEv2.")) : null,
    !legacy && any((e) => e === "3des") ? warning(tr("3DES needs legacy algorithms allowed.")) : null,
    field("", el("button", {
      disabled: suites.length >= 6,
      onclick: () => { const last = suites[suites.length - 1]; suites.push(last ? { ...last } : { encryption: "aes256", hash: "sha256" }); editedDeep(); },
    }, `⊕ ${tr("Add a Proposal")}`)),
  ];
}

function dhGroupsRow() {
  const f = ui.form;
  const offered = DH.filter(([id]) => id !== 2 || f.legacy_algorithms || f.phase1_dh_groups.includes(2) || f.pfs_group === 2);
  return field(tr("DH Groups"), el("div", { class: "grid-checks" }, offered.map(([id, name]) => checkbox(String(id), f.phase1_dh_groups.includes(id), (on) => {
    const set = new Set(f.phase1_dh_groups);
    on ? set.add(id) : set.delete(id);
    f.phase1_dh_groups = [...set].sort((a, b) => DH_ORDER.indexOf(a) - DH_ORDER.indexOf(b));
    editedDeep();
  }, { title: name, key: `dh-${id}` }))),
  !f.legacy_algorithms && (f.phase1_dh_groups.includes(2) || f.pfs_group === 2) ? warning(tr("DH group 2 needs legacy algorithms allowed.")) : null);
}

function legacyToggle() {
  return field("", toggle(tr("Allow legacy algorithms (3DES, DH group 2)"), ui.form, "legacy_algorithms"),
    caption(tr("Only for old gateways that offer nothing better: these algorithms are no longer considered secure.")));
}

function proposalsToggle() {
  const f = ui.form;
  return field("", checkbox(tr("Edit the proposals as text"), f.custom_proposals, async (on) => {
    delete ui.local.proposals;
    try {
      if (on) {
        ui.form = await call("proposals_as_text", { form: f });
      } else {
        ui.form = await call("proposals_as_choices", { form: f });
        if (ui.form.custom_proposals) ui.local.proposals = tr("These proposals cannot be shown as choices.");
      }
    } catch (e) {
      ui.local.proposals = e.message;
    }
    editedDeep();
  }, { key: "custom_proposals" }),
  ui.local.proposals ? warning(ui.local.proposals) : caption(tr("For settings the choices above do not offer, in the syntax “aes256-sha256-modp2048”.")));
}

function proposalsText() {
  return [
    block(tr("IKE proposals (one per line)"), textarea(ui.form, "ike_proposals", "ike_proposals")),
    block(tr("ESP proposals (one per line)"), textarea(ui.form, "esp_proposals", "esp_proposals")),
  ];
}

// ---------------------------------------------------------------- tabs

function generalTab() {
  const f = ui.form;
  const folders = allFolders();
  const folderInput = input(f, "folder", "folder", { as: "opt", placeholder: tr("None") });
  const parts = [section(null,
    isNew()
      ? field(tr("Name"), input(f, "name", "name", { placeholder: "paris" }))
      : field(tr("Name"), [el("span", { style: "flex:1" }, ui.saved.name), el("button", { onclick: () => rename(ui.original) }, tr("Rename…"))]),
    field(tr("Description"), input(f, "description", "description", { as: "opt", placeholder: tr("Optional") })),
    field(tr("Folder"), [folderInput, folders.length ? el("button", {
      title: tr("“/” separates subfolders, as in Clients/Acme."),
      onclick: (e) => popupBelow(e.currentTarget, [
        { label: tr("None"), action: () => { f.folder = null; editedDeep(); } }, "-",
        ...folders.map((path) => ({ label: path, action: () => { f.folder = path; editedDeep(); } })),
      ]),
    }, "📁") : null]),
    f.kind !== "OpenVpn" ? field(f.kind === "Ipsec" ? tr("Remote Gateway") : tr("Server"), input(f, "host", "host", { placeholder: "vpn.example.com" })) : null)];

  switch (f.kind) {
    case "FortiSsl":
      parts.push(section(null,
        field(tr("Method"), choice([[false, tr("Password")], [true, tr("SAML (browser)")]], f.saml, (v) => { f.saml = v; editedDeep(); }, { key: "saml" })),
        ...(f.saml ? [] : [
          field(tr("User Name"), input(f, "username", "username", { as: "opt" })),
          field("", toggle(tr("Save the password in the Credential Manager"), f, "save_password")),
          f.save_password ? secretField("password", tr("Password")) : null,
        ])));
      parts.push(section(null, ...disclosure(
        field(tr("Port"), input(f, "port", "port", { as: "port", cls: "narrow" })),
        field(tr("Realm"), input(f, "realm", "realm", { as: "opt" })),
        f.saml ? field(tr("SAML Callback Port"), input(f, "saml_port", "saml_port", { as: "port", cls: "narrow" })) : null,
        fingerprints())));
      parts.push(clientCertificateSection(f.has_client_certificate));
      break;
    case "Ipsec": {
      const v2 = f.ike_version === 2;
      const gc = v2 && f.gateway_certificate;
      const cc = v2 && f.client_certificate !== null;
      parts.push(section(null,
        v2 ? field(tr("Gateway Identity"), radios("gateway_certificate", [[false, tr("Pre-shared key")], [true, tr("Certificate")]],
          f.gateway_certificate, (v) => { f.gateway_certificate = v; editedDeep(); })) : null,
        gc && cc ? caption(tr("No pre-shared key: you and the gateway prove your identities with certificates."))
          : gc && f.xauth ? caption(tr("No pre-shared key: you sign in with your user name and password, the gateway with its certificate."))
            : [field(tr("Authentication Method"), el("span", {}, tr("Pre-shared key"))), secretField("psk", tr("Pre-shared Key"))]));
      if (gc) parts.push(gatewayCertificateSection());
      if (v2) parts.push(clientCertificateSection(false));
      if (!cc) {
        const mode = !f.xauth ? "off" : f.save_password ? "save" : "ask";
        parts.push(section(null,
          field(tr("Authentication (XAuth)"), radios("xauth", [["ask", tr("Ask at connection")], ["save", tr("Save credentials")], ["off", tr("Disable")]], mode, (v) => {
            if (v === "off") { f.xauth = false; f.save_password = true; } else { f.xauth = true; f.save_password = v === "save"; }
            editedDeep();
          }, { vertical: true })),
          f.xauth ? field(tr("User Name"), input(f, "username", "username", { as: "opt" })) : null,
          f.xauth && f.save_password ? secretField("password", tr("Password")) : null));
      }
      break;
    }
    case "OpenVpn":
      parts.push(serversSection());
      parts.push(section(null,
        field("", toggle(tr("User name and password"), f, "password_auth")),
        ...(f.password_auth ? [
          field(tr("User Name"), input(f, "username", "username", { as: "opt" })),
          field("", toggle(tr("Save the password in the Credential Manager"), f, "save_password")),
          f.save_password ? secretField("password", tr("Password")) : null,
        ] : [])));
      parts.push(clientCertificateSection(f.has_client_certificate));
      parts.push(serverCertificateSection());
      parts.push(section(null, ...disclosure(openVpnAdvanced())));
      break;
    case "L2tp":
      parts.push(section(null,
        secretField("psk", tr("Pre-shared Key")),
        field(tr("Group Name"), input(f, "local_id", "local_id", {
          as: "opt", placeholder: tr("Optional"), title: tr("The IKE identity; with one, phase 1 uses aggressive mode."),
        }))));
      parts.push(section(null,
        field(tr("User Name"), input(f, "username", "username", { as: "opt" })),
        field("", toggle(tr("Save the password in the Credential Manager"), f, "save_password")),
        f.save_password ? secretField("password", tr("Password")) : null));
      parts.push(section(null, ...disclosure(l2tpAdvanced())));
      break;
    case "WireGuard":
      parts.push(...wireGuardSections());
      break;
  }
  return parts;
}

function l2tpAdvanced() {
  const f = ui.form;
  const nonePpp = !f.ppp_mschapv2 && !f.ppp_chap && !f.ppp_pap;
  return [
    field(tr("Port"), input(f, "port", "port", { as: "port", cls: "narrow" })),
    field(tr("Remote ID"), input(f, "remote_id", "remote_id", { as: "opt", placeholder: tr("Optional") })),
    ...(f.custom_proposals ? proposalsText() : []),
    el("h3", {}, tr("Phase 1")),
    ...(f.custom_proposals ? [] : [...suiteRows(f.phase1_suites, { gcm: false, ikev2: false, legacy: f.legacy_algorithms, phase1: true, key: "p1" }), dhGroupsRow()]),
    field(tr("Key Lifetime"), [input(f, "phase1_lifetime", "phase1_lifetime", { as: "num", cls: "narrow" }), tr("seconds")]),
    el("h3", {}, tr("Phase 2")),
    ...(f.custom_proposals ? [] : suiteRows(f.phase2_suites, { gcm: true, ikev2: false, legacy: f.legacy_algorithms, phase1: false, key: "p2" })),
    field(tr("Key Lifetime"), [input(f, "phase2_lifetime", "phase2_lifetime", { as: "num", cls: "narrow" }), tr("seconds")]),
    legacyToggle(),
    proposalsToggle(),
    field("", toggle(tr("Dead peer detection"), f, "dpd")),
    field(tr("PPP Authentication"), [
      checkbox("MS-CHAPv2", f.ppp_mschapv2, (v) => { f.ppp_mschapv2 = v; editedDeep(); }, { key: "ppp_mschapv2" }),
      checkbox("CHAP", f.ppp_chap, (v) => { f.ppp_chap = v; editedDeep(); }, { key: "ppp_chap" }),
      checkbox("PAP", f.ppp_pap, (v) => { f.ppp_pap = v; editedDeep(); }, { key: "ppp_pap" }),
    ], nonePpp ? warning(tr("Choose at least one authentication.")) : null,
    caption(tr("PAP sends the password in clear inside IPsec and does not authenticate the server: turn it on only if the server asks for it (Meraki)."))),
    block(tr("DNS servers if the server assigns none (one per line, 4 at most)"), textarea(f, "dns_servers", "dns_servers")),
  ];
}

function wireGuardSections() {
  const f = ui.form;
  const typedKey = ui.typed.private_key ?? "";
  if (typedKey && ui.wgPublic?.key !== typedKey) {
    call("wireguard_public_key", { privateKey: typedKey }).then((k) => {
      ui.wgPublic = { key: typedKey, public: k };
      if (k) f.local_public_key = k;
      editedDeep();
    });
  }
  const publicKey = typedKey ? (ui.wgPublic?.key === typedKey ? ui.wgPublic.public : null) : f.local_public_key;
  return [
    section(null,
      secretField("private_key", tr("Private Key")),
      field(tr("Public Key"), publicKey
        ? [el("span", { class: "mono", style: "flex:1;user-select:text" }, publicKey),
          el("button", { title: tr("Copy, for the server's administrator"), onclick: () => navigator.clipboard.writeText(publicKey).catch(() => {}) }, tr("Copy"))]
        : el("span", { class: "muted" }, typedKey ? tr("Not a WireGuard key") : tr("Unknown"))),
      field("", el("button", {
        title: tr("The server's administrator then declares the new public key."),
        onclick: async () => { ui.typed.private_key = await call("new_wireguard_private_key"); ui.forgotten.delete("private_key"); editedDeep(); },
      }, tr("Generate a New Key Pair")))),
    section(null,
      field(tr("Server Public Key"), input(f, "peer_public_key", "peer_public_key", { placeholder: "base64", cls: "mono" })),
      field("", toggle(tr("Pre-shared key"), f, "preshared_key")),
      f.preshared_key ? secretField("psk", tr("Pre-shared Key")) : null),
    section(null,
      block(tr("Addresses in the tunnel (Address, one per line)"), textarea(f, "addresses", "addresses")),
      block(tr("Networks of the server (AllowedIPs, one per line; 0.0.0.0/0 for everything)"), textarea(f, "allowed_ips", "allowed_ips")),
      block(tr("DNS servers (one per line)"), textarea(f, "dns_servers", "dns_servers")),
      block(tr("DNS search domains (one per line)"), textarea(f, "dns_search", "dns_search"))),
    section(null, ...disclosure(
      field(tr("Port"), input(f, "port", "port", { as: "port", cls: "narrow" })),
      field(tr("Keepalive (seconds)"), input(f, "persistent_keepalive", "persistent_keepalive", {
        as: "optnum", cls: "narrow", placeholder: tr("Off"), title: tr("Keeps NAT mappings open: 25 seconds is usual."),
      })),
      field(tr("MTU"), input(f, "mtu", "mtu", { as: "optnum", cls: "narrow", placeholder: "1420" })))),
  ];
}

function advancedTab() {
  const f = ui.form;
  const v2 = f.ike_version === 2;
  const kbOn = f.phase2_lifetime_kb !== null;
  return [
    section(tr("VPN Settings"),
      field("IKE", radios("ike", [[1, tr("Version 1")], [2, tr("Version 2")]], f.ike_version, (v) => { f.ike_version = v; editedDeep(); })),
      !v2 ? field(tr("Mode"), radios("aggr", [[false, tr("Main")], [true, tr("Aggressive")]], f.aggressive_mode, (v) => { f.aggressive_mode = v; editedDeep(); }),
        f.aggressive_mode ? null : caption(tr("Main mode protects the identities; the gateway chooses the tunnel before seeing the Local ID."))) : null,
      field(tr("Options"), el("span", { title: tr("The gateway assigns the address, routes and DNS. Manual configuration is not supported yet.") }, tr("Mode Config"))),
      field(tr("Port"), input(f, "port", "port", { as: "port", cls: "narrow" })),
      field(tr("Local ID"), input(f, "local_id", "local_id", { as: "opt", placeholder: tr("Optional") })),
      field(tr("Remote ID"), input(f, "remote_id", "remote_id", { as: "opt", placeholder: tr("Optional") }))),
    f.custom_proposals ? section(tr("Proposals"), ...proposalsText()) : null,
    section(tr("Phase 1"),
      ...(f.custom_proposals ? [] : [...suiteRows(f.phase1_suites, { gcm: v2, ikev2: v2, legacy: f.legacy_algorithms, phase1: true, key: "p1" }), dhGroupsRow()]),
      field(tr("Key Lifetime"), [input(f, "phase1_lifetime", "phase1_lifetime", { as: "num", cls: "narrow" }), tr("seconds")]),
      field("", toggle(tr("Dead peer detection"), f, "dpd")),
      !v2 ? field("", checkbox(tr("NAT traversal"), true, () => {}, { disabled: true, title: tr("Always on: ESP travels in UDP, so no kernel IPsec is needed.") })) : null),
    section(tr("Phase 2"),
      ...(f.custom_proposals ? [] : suiteRows(f.phase2_suites, { gcm: true, ikev2: v2, legacy: f.legacy_algorithms, phase1: false, key: "p2" })),
      field(tr("Key Lifetime"), [
        checkbox("", f.phase2_lifetime !== 0, (on) => { f.phase2_lifetime = on ? 43200 : 0; editedDeep(); }, { key: "p2-seconds-on" }),
        input(f, "phase2_lifetime", "phase2_lifetime", { as: "num", cls: "narrow", disabled: f.phase2_lifetime === 0 }), tr("seconds"),
      ]),
      field("", [
        checkbox("", kbOn, (on) => { f.phase2_lifetime_kb = on ? 5120 : null; editedDeep(); }, { key: "p2-kb-on" }),
        el("input", {
          type: "text", class: "narrow", "data-key": "phase2_lifetime_kb", disabled: !kbOn, value: kbOn ? String(f.phase2_lifetime_kb) : "",
          oninput: (e) => { const n = parseInt(e.target.value.replace(/\D/g, "").slice(0, 12), 10); f.phase2_lifetime_kb = Number.isFinite(n) ? n : 0; edited(); },
        }), tr("kilobytes"),
      ]),
      ...(f.custom_proposals ? [] : [
        field("", checkbox(tr("Perfect forward secrecy (PFS)"), f.pfs_group !== null, (on) => { f.pfs_group = on ? ui.lastPfs : null; editedDeep(); }, { key: "pfs" })),
        field(tr("DH Group"), choice(DH.filter(([id]) => id !== 2 || f.legacy_algorithms || f.pfs_group === 2).map(([id, name]) => [id, `${id} (${name})`]),
          f.pfs_group ?? ui.lastPfs, (v) => { ui.lastPfs = v; if (f.pfs_group !== null) f.pfs_group = v; editedDeep(); }, { key: "pfs_group", disabled: f.pfs_group === null })),
      ])),
    section(null, legacyToggle()),
    section(null, proposalsToggle()),
  ];
}

const PLACEHOLDERS = { network: "10.1.0.0/16, *.corp.example", domain: "corp.example", pattern: "*.zoom.us" };

function notedList(title, entries, kind, key, onSet = null) {
  const set = (list) => (onSet ? onSet(list) : entries.splice(0, entries.length, ...list));
  const errors = new Map();
  const check = (i, value, mark) => {
    const text = value.trim();
    if (!text) { mark.hidden = true; return; }
    call("entry_error", { kind, value: text }).then((err) => {
      mark.hidden = !err;
      mark.title = err ?? "";
      errors.set(i, err);
    });
  };
  const grid = el("div", { class: "list-grid" }, entries.map((entry, i) => {
    const mark = el("span", { class: "bad-mark", hidden: true }, "⚠");
    const value = el("input", {
      type: "text", class: "mono", "data-key": `${key}-v-${i}`, placeholder: PLACEHOLDERS[kind], value: entry.value, spellcheck: "false",
      oninput: () => { entry.value = value.value; check(i, value.value, mark); edited(); },
    });
    check(i, entry.value, mark);
    return [
      value,
      el("input", { type: "text", "data-key": `${key}-n-${i}`, placeholder: tr("Note"), value: entry.note, oninput: (e) => { entry.note = e.target.value; edited(); } }),
      mark,
      el("button", { class: "icon-button", title: tr("Remove"), onclick: () => { const list = [...entries]; list.splice(i, 1); set(list); editedDeep(); } }, "⊖"),
    ];
  }).flat());
  return block(title, el("div", {},
    entries.length ? grid : null,
    el("div", { class: "row-gap" },
      el("button", { onclick: () => { set([...entries, { value: "", note: "" }]); editedDeep(); } }, `⊕ ${tr("Add")}`),
      el("button", {
        title: tr("One entry per line: the network or domain, then its note"),
        onclick: async () => {
          const area = el("textarea", { class: "mono", rows: 8 });
          const id = await modal({
            title: tr("Paste Lines"), text: tr("Paste the lines, one entry per line: the network or domain, then its note."), body: area, focus: area,
            buttons: [{ id: "cancel", label: tr("Cancel") }, { id: "ok", label: tr("Add"), primary: true }],
          });
          if (id !== "ok") return;
          const parsed = await call("parse_list", { text: area.value });
          const list = [...entries];
          const last = list[list.length - 1];
          if (last && !last.value.trim() && !last.note.trim()) list.pop();
          set([...list, ...parsed]);
          editedDeep();
        },
      }, tr("Paste Lines")))));
}

const merged = (a, b) => [...a, ...b.filter((e) => !a.some((x) => x.value === e.value))];

function setMode(mode) {
  const f = ui.form;
  const old = f.tunnel_mode;
  if (old === mode) return;
  if (mode === "Split") {
    const list = f.split_routes.length ? f.split_routes : ui.parked;
    if (!f.extra_routes.length) f.routes = list;
    else { f.routes = null; f.extra_routes = merged(f.extra_routes, list); }
    f.split_routes = [];
  } else if (old === "Split") {
    const list = f.routes ?? f.extra_routes;
    f.routes = null;
    f.extra_routes = [];
    if (list.length) { f.split_routes = list; ui.offering = true; }
  }
  f.tunnel_mode = mode;
  editedDeep();
}

function networkTab() {
  const f = ui.form;
  const mode = f.tunnel_mode;
  const parts = [];
  const captions = {
    Automatic: tr("The networks the gateway announces, or all traffic if it asks for it."),
    Full: tr("All traffic, except the domains kept outside."),
    Split: tr("A split tunnel at every connection: the list below, the rest of the traffic outside."),
  };
  parts.push(section(null, field(tr("Traffic"), radios("mode", [
    ["Automatic", tr("As the gateway decides")], ["Full", tr("Everything through the VPN")], ["Split", tr("Only these networks")],
  ], mode, setMode, { vertical: true }), caption(captions[mode]))));

  const networks = mode === "Split" ? (f.routes ?? f.extra_routes) : f.split_routes;
  const setNetworks = (list) => {
    if (mode !== "Split") f.split_routes = list;
    else if (f.routes !== null) f.routes = list;
    else f.extra_routes = list;
  };

  if (mode === "Automatic") {
    const a = ui.original ? announcedOf(ui.original) : null;
    const rows = [];
    if (a) {
      if (a.full_tunnel) rows.push([tr("All traffic"), tr("default route")]);
      for (const r of a.routes.slice(0, 50)) rows.push([r, tr("network")]);
      if (a.routes.length > 50) rows.push([tr("and %lld more", a.routes.length - 50), ""]);
      for (const d of a.dns_domains) rows.push([d, tr("DNS domain")]);
    }
    parts.push(section(tr("Announced by the gateway"),
      a ? caption(tr("Last connection, %@", new Date(a.at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }))) : null,
      a ? (rows.length ? el("div", { class: "readonly-list" }, rows.map(([v, k]) => [el("span", { class: "mono" }, v), el("span", { class: "muted" }, k)]).flat())
        : el("span", { class: "muted" }, tr("Nothing"))) : el("span", { class: "muted" }, tr("Shown after a first connection.")),
      caption(tr("Read only: the gateway decides, at every connection. To set your own networks, choose “Only these networks”; to send everything whatever it says, “Everything through the VPN”."))));
  }

  if (mode === "Split") {
    parts.push(section(null,
      notedList(tr("Networks through the VPN"), networks, "network", "networks", setNetworks),
      caption(tr("A network (10.1.0.0/16), a single address, or a domain: *.corp.example for every name under it, routed as they are resolved.")),
      field("", checkbox(tr("Add the networks the gateway announces"), f.routes === null, (on) => {
        if (on) { f.extra_routes = merged(f.routes ?? [], f.extra_routes); f.routes = null; } else { f.routes = f.extra_routes; f.extra_routes = []; }
        editedDeep();
      }, { key: "add_announced" }), caption(tr("Off: only this list. On: this list on top of what the gateway announces.")))));
    if (f.split_routes.length) {
      parts.push(section(null, notedList(tr("Networks in split mode"), f.split_routes, "network", "split_routes"),
        caption(tr("The menu also offers to connect in split mode, with these networks instead."))));
    }
  } else {
    parts.push(section(null,
      notedList(mode === "Automatic" ? tr("Outside the VPN, if the gateway sends everything") : tr("Outside the VPN"), f.excluded_domains, "pattern", "excluded_domains"),
      caption(mode === "Automatic"
        ? tr("Used only when the gateway asks for all traffic; otherwise they are outside already. Resolved by the DNS in place before the VPN, and reached directly (video calls, say). Public addresses only.")
        : tr("Resolved by the DNS in place before the VPN, and reached directly (video calls, say). Public addresses only."))));
    const offered = ui.offering || f.split_routes.length > 0;
    parts.push(section(null,
      field("", checkbox(tr("Also offer split mode"), offered, (on) => {
        if (on) { ui.offering = true; if (!f.split_routes.length) f.split_routes = ui.parked; } else { ui.parked = f.split_routes; f.split_routes = []; ui.offering = false; }
        editedDeep();
      }, { key: "offer_split" }), caption(tr("The menu offers “Connect in Split Mode”: only these networks, for that connection."))),
      offered ? notedList(tr("Networks through the VPN"), networks, "network", "networks", setNetworks) : null,
      offered ? caption(tr("One list for the VPN: the same as in “Only these networks”. Changing the mode keeps it.")) : null));
    if (f.extra_routes.length) {
      parts.push(section(null, notedList(tr("Added to the gateway's networks"), f.extra_routes, "network", "extra_routes"),
        caption(mode === "Full" ? tr("Unused while everything goes through the VPN.") : tr("Added when the gateway announces networks, like the route lines of an OpenVPN file."))));
    }
  }

  parts.push(section(null, notedList(tr("DNS domains resolved through this VPN"), f.dns_domains, "domain", "dns_domains")));

  const others = profiles.filter((p) => p.id !== ui.original);
  if (others.length) {
    parts.push(section(tr("Connect Through"),
      others.map((p) => {
        const at = f.via.indexOf(p.id);
        return el("div", {}, checkbox(at >= 0 ? `${at + 1}. ${p.name}` : p.name, at >= 0, (on) => {
          f.via = on ? [...f.via, p.id] : f.via.filter((v) => v !== p.id);
          editedDeep();
        }, { key: `via-${p.id}` }));
      }),
      caption(f.via.length
        ? tr("Connected normally, this VPN goes through the first of these that is up, or brings up %@ first; its networks may overlap theirs. The menu also offers to connect it directly.", profileById(f.via[0])?.name ?? f.via[0])
        : tr("Chain this VPN through others: it then goes through whichever is up, or brings up the first one before itself."))));
  }

  parts.push(section(null,
    field("", toggle(tr("Allow networks that overlap another VPN's"), f, "allow_route_overlap"),
      caption(tr("Without it, a VPN that would take traffic from another one is not connected."))),
    field("", toggle(tr("Company VPN: never at the same time as another VPN"), f, "exclusive"),
      caption(tr("Before it connects, the other VPNs are disconnected, after asking you. While it is up, the others wait.")))));
  return parts;
}

function parseHM(text, fallback = [0, 0]) {
  const m = /^\s*(\d+):(\d{1,2})\s*$/.exec(text ?? "");
  return m ? [parseInt(m[1], 10), parseInt(m[2], 10)] : fallback;
}
const formatHM = (h, m) => `${h}:${String(m).padStart(2, "0")}`;

function durationField(field_, key) {
  const f = ui.form;
  const [h, m] = parseHM(f[field_]);
  const hours = el("input", { type: "number", class: "tiny", min: 0, max: 999, step: 1, value: h, "data-key": `${key}-h` });
  const minutes = el("input", { type: "number", class: "tiny", min: 0, max: 59, step: 5, value: m, "data-key": `${key}-m` });
  const write = () => {
    const hh = Math.min(999, Math.max(0, parseInt(hours.value, 10) || 0));
    const mm = Math.min(59, Math.max(0, parseInt(minutes.value, 10) || 0));
    f[field_] = formatHM(hh, mm);
    edited();
  };
  hours.oninput = write;
  minutes.oninput = write;
  return [hours, tr("h"), minutes, tr("min")];
}

function scheduleTab() {
  const f = ui.form;
  const limit = (label, field_, initial, control, note, { unavailable = false } = {}) => {
    const on = (f[field_] ?? "").trim() !== "";
    return field(checkbox(label, on, (v) => { f[field_] = v ? initial : ""; editedDeep(); }, { key: `${field_}-on`, disabled: unavailable && !on }),
      on ? control() : [], caption(note), unavailable ? warning(tr("Not available on Windows yet: the limit is kept for macOS.")) : null);
  };
  const none = ["disconnect_after", "disconnect_idle", "disconnect_at"].every((k) => !(f[k] ?? "").trim());
  return [
    section(null, field("", toggle(tr("Disconnect automatically"), f, "disconnect_enabled"),
      caption(tr("Even with the app closed: the service disconnects. You are warned 5 minutes before and can postpone.")))),
    el("div", { class: f.disconnect_enabled ? "" : "disabled" }, section(tr("Limits"),
      limit(tr("After being connected for"), "disconnect_after", "8:00", () => durationField("disconnect_after", "after"),
        tr("Reconnections after a drop do not start the time again. Postponing starts it again.")),
      limit(tr("After no keyboard or mouse activity for"), "disconnect_idle", "1:00", () => durationField("disconnect_idle", "idle"),
        tr("Network traffic does not count: it never stops. Using the computer again keeps the VPN up."), { unavailable: true }),
      limit(tr("At"), "disconnect_at", "19:00", () => {
        const [h, m] = parseHM(f.disconnect_at, [19, 0]);
        const time = el("input", {
          type: "time", "data-key": "at-time", value: `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`,
          oninput: () => { const [hh, mm] = time.value.split(":").map((x) => parseInt(x, 10)); if (Number.isFinite(hh)) { f.disconnect_at = formatHM(hh, mm || 0); edited(); } },
        });
        return time;
      }, tr("The first time after connecting. Postponing moves it an hour later.")),
      f.disconnect_enabled && none ? warning(tr("Choose at least one limit.")) : null)),
  ];
}

FR["Network traffic does not count: it never stops. Using the computer again keeps the VPN up."] =
  "Le trafic réseau ne compte pas : il ne s'arrête jamais. Utiliser à nouveau l'ordinateur garde le VPN.";

// ---------------------------------------------------------------- detail pane

function render() {
  renderTree();
  renderDetail();
}

function renderDetail() {
  const detail = document.getElementById("detail");
  if (ui.form) {
    detail.replaceChildren(
      el("div", { class: "ed-header", id: "ed-header" }),
      el("div", { class: "tabs", id: "ed-tabs" }),
      el("div", { class: "ed-body", id: "ed-body" }),
      el("div", { class: "ed-footer", id: "ed-footer" }));
    renderChrome();
    renderBody();
  } else if (ui.selection?.folder) {
    detail.replaceChildren(folderOverview(ui.selection.folder));
  } else if (ui.error) {
    detail.replaceChildren(el("p", { class: "placeholder error-text" }, ui.error));
  } else {
    detail.replaceChildren(el("p", { class: "placeholder" }, tr("Select a VPN, or create one with +.")));
  }
}

function serverText(f) {
  const host = f.kind === "OpenVpn" ? f.servers[0]?.host ?? "" : f.host;
  const port = f.kind === "OpenVpn" ? f.servers[0]?.port ?? 0 : f.port;
  return host ? (port ? `${host}:${port}` : host) : "";
}

/** The header, the tabs and the footer: what an edit may change. */
function renderChrome() {
  const f = ui.form;
  const header = document.getElementById("ed-header");
  if (!header || !f) return;
  const id = ui.original;
  const on = id && isOn(id);
  const summary = id ? profileById(id) : null;
  header.replaceChildren(...[
    el("div", { class: "lines" },
      el("div", { class: "title" }, f.name || tr("New VPN")),
      el("div", { class: "sub" }, [kindName(KIND_OF_FORM[f.kind]), serverText(f)].filter(Boolean).join(" · "))),
    id ? el("label", { class: "switch", title: on ? tr("Disconnect") : tr("Connect") },
      el("input", { type: "checkbox", checked: on, onchange: (e) => (e.target.checked ? leave(() => connect(id)) : disconnect(id)) }),
      el("span")) : null,
    id && summary ? el("button", {
      onclick: (e) => popupBelow(e.currentTarget, [...connectItems(summary), "-", { label: tr("Export as a Profile File…"), action: () => exportProfile(id) }]),
    }, "…") : null].filter(Boolean));

  const tabs = [["general", tr("General")], ...(f.kind === "Ipsec" ? [["advanced", tr("Advanced")]] : []), ["network", tr("Network")], ["schedule", tr("Schedule")]];
  if (!tabs.some(([k]) => k === ui.tab)) ui.tab = "general";
  document.getElementById("ed-tabs").replaceChildren(...tabs.map(([k, label]) => el("button", {
    class: ui.tab === k ? "active" : "",
    onclick: () => { ui.tab = k; if (k === "general") ui.advanced = false; renderChrome(); renderBody(); },
  }, label)));

  const footer = document.getElementById("ed-footer");
  const changes = hasChanges();
  const connected = id && isOn(id);
  const parts = [];
  if (ui.error) parts.push(el("div", { class: "error-text" }, ui.error));
  if (isNew()) {
    parts.push(el("span", { class: "status" }, tr("The VPN is added when you click Create.")),
      el("button", { onclick: revert }, tr("Cancel")),
      el("button", { class: "primary", onclick: save }, tr("Create")));
  } else {
    parts.push(el("span", { class: `status${changes ? " dirty" : ""}` },
      changes ? tr("Unsaved changes") : connected ? tr("Changes apply at the next connection.") : tr("All changes are saved.")));
    if (connected) {
      parts.push(el("button", {
        onclick: async () => {
          if (hasChanges() && !(await save())) return;
          await disconnect(id);
          await connect(id, ui.lastOptions[id] ?? {});
        },
      }, tr("Save and Reconnect")));
    }
    parts.push(el("button", { disabled: !changes, onclick: revert }, tr("Revert")),
      el("button", { class: "primary", disabled: !changes, onclick: save }, tr("Save")));
  }
  footer.replaceChildren(...parts);
}

function renderBody() {
  const body = document.getElementById("ed-body");
  if (!body || !ui.form) return;
  const content = ui.tab === "advanced" ? advancedTab() : ui.tab === "network" ? networkTab() : ui.tab === "schedule" ? scheduleTab() : generalTab();
  body.replaceChildren(...content.flat().filter(Boolean));
  renderChrome();
}

function folderOverview(path) {
  const inside = profiles.filter((p) => p.folder === path || p.folder?.startsWith(`${path}/`));
  return el("div", { class: "overview" },
    el("div", { class: "head" },
      el("span", {}, "📁"),
      el("h2", {}, path),
      el("button", { onclick: () => renameFolder(path) }, tr("Rename…"))),
    inside.length ? inside.map((p) => {
      const sub = p.folder === path ? "" : ` · ${p.folder.slice(path.length + 1)}`;
      const on = isOn(p.id);
      return el("div", { class: "entry" },
        el("div", { class: "lines" },
          el("div", {}, p.name),
          el("div", { class: "muted" }, `${kindName(p.protocol)} · ${p.host}${sub}`)),
        el("button", { onclick: () => leave(() => select(p.id).then(render)) }, tr("Edit")),
        el("label", { class: "switch", title: on ? tr("Disconnect") : tr("Connect") },
          el("input", { type: "checkbox", checked: on, onchange: (e) => (e.target.checked ? connect(p.id) : disconnect(p.id)) }),
          el("span")));
    }) : el("p", { class: "muted" }, tr("Drag VPNs here from the list to file them in this folder.")));
}

// ---------------------------------------------------------------- imports

async function importProfileFile() {
  const path = await files.open({ multiple: false, filters: [{ name: tr("VPN profile"), extensions: ["vpnprofile"] }] });
  if (!path) return;
  let received;
  try {
    received = await call("read_vpnprofile", { path });
  } catch (e) {
    await alertBox(tr("This VPN profile cannot be used"), e.message);
    return;
  }
  const form = received.form;
  const names = form.ca_pem ? await call("certificate_names", { pem: form.ca_pem }) : [];
  const grid = el("div", {});
  const row = (label, value) => grid.append(field(label, el("span", {}, value)));
  row(tr("Type"), kindName(KIND_OF_FORM[form.kind]));
  row(tr("Server"), el("b", {}, serverText(form)));
  if (names.length) row(tr("Certificate Authority"), names.join(", "));
  if (form.trusted_certificates.length) {
    row(tr("Certificate"), el("span", { class: "mono" }, form.trusted_certificates.map((c) => c.match(/.{1,4}/g).join(" ")).join("\n")));
  }
  if (form.tunnel_mode === "Full") row(tr("Traffic"), tr("All traffic goes through this VPN"));
  const listText = (l) => l.map((e) => (e.note ? `${e.value} (${e.note})` : e.value)).join(", ");
  if (form.routes?.length) row(tr("Networks"), listText(form.routes));
  if (form.split_routes.length) row(tr("Split Mode"), listText(form.split_routes));
  if (form.dns_domains.length) {
    row(tr("Name Resolution"), el("span", {}, form.dns_domains.map((d) => el("div", { class: d.value.includes(".") ? "" : "warning" }, tr("Names ending in .%@", d.value)))));
  }
  const taken = el("p", { class: "warning", hidden: true }, tr("A VPN of that name exists already: choose another name."));
  const error = el("p", { class: "error-text", hidden: true });
  const nameInput = el("input", { type: "text", value: form.name });
  const userInput = el("input", { type: "text", value: form.username ?? "" });
  const askUser = ["Ipsec", "L2tp"].includes(form.kind) || (form.kind === "FortiSsl" && !form.saml) || (form.kind === "OpenVpn" && form.password_auth);
  const isTaken = () => profiles.some((p) => p.name === nameInput.value.trim() && !p.folder);
  const body = el("div", {}, grid, caption(tr("Check the server and the fingerprint with whoever sent you this file before adding it.")),
    field(tr("Name"), nameInput), taken, askUser ? field(tr("User Name"), userInput) : null, error);
  const refresh = () => {
    taken.hidden = !isTaken();
    for (const b of document.querySelectorAll("#modal-buttons button[data-id^=add]")) b.disabled = isTaken();
  };
  nameInput.oninput = refresh;
  setTimeout(refresh);
  await modal({
    title: tr("Add a VPN from a profile file"), text: path.split(/[\\/]/).pop(), body, focus: nameInput,
    buttons: [{ id: "cancel", label: tr("Cancel") }, { id: "add", label: tr("Add") }, { id: "add-connect", label: tr("Add and Connect"), primary: true }],
    act: async (id) => {
      form.name = nameInput.value.trim();
      if (askUser) form.username = userInput.value.trim() || null;
      try {
        const result = await call("save_profile", { original: null, form, secrets: {} });
        await imported([result.id], id === "add-connect");
        return true;
      } catch (e) {
        error.textContent = e.message;
        error.hidden = false;
        return false;
      }
    },
  });
}

async function importConfigFile() {
  const path = await files.open({ multiple: false, filters: [{ name: tr("OpenVPN or WireGuard configuration"), extensions: ["ovpn", "conf"] }] });
  if (!path) return;
  const wireguard = await call("is_wireguard_config", { path });
  let item;
  try {
    item = (await call("import_preview", { source: wireguard ? "wireguard" : "openvpn", path }))[0];
  } catch (e) {
    await alertBox(wireguard ? tr("This WireGuard file cannot be imported") : tr("This OpenVPN file cannot be imported"), e.message);
    return;
  }
  const password = el("input", { type: "password", placeholder: tr("Optional: asked at the first connection otherwise"), autocomplete: "new-password" });
  const error = el("p", { class: "error-text", hidden: true });
  const body = el("div", {},
    field(tr("Name"), el("b", {}, item.name)),
    item.notes.length ? el("div", { style: "max-height:200px;overflow:auto" }, item.notes.map((n) => el("p", { class: "caption" }, `ℹ ${n}`))) : null,
    item.needs_password ? field(tr("User password"), password) : null,
    caption(wireguard
      ? tr("The keys of the file go to the Credential Manager, the rest into the profile: the file is no longer needed. Its commands (PostUp…) are never run.")
      : tr("Passwords are never imported. The certificates and keys of the file are copied into the profile: the file is no longer needed.")),
    error);
  await modal({
    title: wireguard ? tr("Import WireGuard File") : tr("Import OpenVPN File"), text: path.split(/[\\/]/).pop(), body,
    buttons: [{ id: "cancel", label: tr("Cancel") }, { id: "add", label: tr("Add") }, { id: "add-connect", label: tr("Add and Connect"), primary: true }],
    act: async (id) => {
      try {
        let ids;
        if (wireguard) {
          ids = [await call("add_wireguard", { path })];
        } else {
          ids = await call("add_imported", { toml: item.toml, secrets: [password.value ? { password: password.value } : {}] });
        }
        await imported(ids, id === "add-connect");
        return true;
      } catch (e) {
        error.textContent = e.message;
        error.hidden = false;
        return false;
      }
    },
  });
}

/** After an import: the list again, the first added profile selected. */
async function imported(ids, connectNow) {
  await loadProfiles();
  changedProfiles();
  if (ids[0]) {
    await select(ids[0]);
    if (connectNow) connect(ids[0]);
  }
  render();
}

// ---------------------------------------------------------------- start

async function main() {
  document.title = tr("Manage VPNs");
  const add = document.getElementById("add");
  add.title = tr("New VPN");
  add.onclick = () => popupBelow(add, [
    { label: tr("SSL VPN (FortiGate)"), action: () => startNew("FortiSsl") },
    { label: "IPsec", action: () => startNew("Ipsec") },
    { label: "OpenVPN", action: () => startNew("OpenVpn") },
    { label: tr("L2TP over IPsec"), action: () => startNew("L2tp") },
    { label: "WireGuard", action: () => startNew("WireGuard") },
    "-",
    { label: tr("New Folder…"), action: () => newFolder(ui.selection?.folder ?? null) },
  ]);
  const removeButton = document.getElementById("remove");
  removeButton.title = tr("Delete");
  removeButton.onclick = () => ui.selection?.profile && remove(ui.selection.profile);
  const importButton = document.getElementById("import");
  importButton.textContent = `${tr("Import")} ▾`;
  importButton.onclick = () => popupBelow(importButton, [
    { label: tr("Profile File (.vpnprofile)…"), action: importProfileFile },
    { label: tr("OpenVPN or WireGuard File (.ovpn, .conf)…"), action: importConfigFile },
  ]);
  dropTarget(document.getElementById("tree"), (id) => moveTo(id, null, null));

  // Closing with unsaved edits asks first.
  const current = window.__TAURI__.webviewWindow.getCurrentWebviewWindow();
  current.onCloseRequested(async (event) => {
    if (!hasChanges()) return;
    event.preventDefault();
    let closing = false;
    await leave(() => { closing = true; });
    if (closing) current.destroy();
  });

  await listen("sessions", async () => {
    await loadSessions();
    renderTree();
    if (ui.form) renderChrome();
    else if (ui.selection?.folder) renderDetail();
  });
  await listen("select", (e) => leave(async () => {
    await loadProfiles();
    const target = e.payload;
    await select(target && profileById(target) ? target : (ui.original ?? profiles[0]?.id ?? null));
    render();
  }));
  // Another window may have changed the file (an import, a pinned certificate).
  window.addEventListener("focus", async () => {
    if (hasChanges()) return;
    await loadProfiles();
    renderTree();
  });

  await loadProfiles();
  await loadSessions();
  const wanted = decodeURIComponent(location.hash.slice(1));
  await select(wanted && profileById(wanted) ? wanted : profiles[0]?.id ?? null);
  render();
}

main();
