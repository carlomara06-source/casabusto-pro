/**
 * Casa Busto Pro — Server sicuro
 * --------------------------------
 * Cosa fa questo server:
 *  1) Custodisce la tua chiave API OpenAPI in un posto sicuro (variabile d'ambiente),
 *     così NON finisce mai dentro il browser né dentro un file leggibile.
 *  2) Mette un login davanti all'app: solo chi conosce la password entra.
 *  3) Fa da "ponte": riceve la richiesta dall'app, aggiunge lui la chiave,
 *     chiama l'API OpenAPI e restituisce solo il risultato. Il browser non vede mai la chiave.
 *
 * NON devi modificare questo file per l'uso normale. Tutte le tue impostazioni
 * (chiave, password) vanno nel file ".env" (vedi .env.example e ISTRUZIONI.md).
 */

import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ---- Configurazione letta dal file .env ----
const OPENAPI_KEY = process.env.OPENAPI_KEY || "";
const OPENAPI_BASE = process.env.OPENAPI_BASE || "https://realestate.openapi.com";
const APP_PASSWORD_HASH = process.env.APP_PASSWORD_HASH || "";
const APP_USERNAME = process.env.APP_USERNAME || "admin";
const SESSION_SECRET = process.env.SESSION_SECRET || "cambia-questo-segreto-lungo-e-casuale";

if (!OPENAPI_KEY) {
  console.warn("\n⚠️  ATTENZIONE: OPENAPI_KEY non impostata nel file .env. Le chiamate API falliranno finché non la imposti.\n");
}
if (!APP_PASSWORD_HASH) {
  console.warn("\n⚠️  ATTENZIONE: APP_PASSWORD_HASH non impostata. Genera la password con: npm run hash (vedi ISTRUZIONI.md)\n");
}

app.use(express.json({ limit: "1mb" }));

// Necessario quando l'app gira dietro il proxy di un hosting (Render, Railway, ecc.)
app.set("trust proxy", 1);

// Su hosting con HTTPS il cookie diventa "secure"; in locale (http) resta non-secure
// così il cookie di sessione viene salvato e rimandato correttamente dal browser.
const IS_HTTPS = process.env.FORCE_HTTPS === "1" || process.env.NODE_ENV === "production";

// ---- Sessioni per il login ----
app.use(session({
  name: "casabusto.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_HTTPS,            // false in locale → il cookie funziona su http://localhost
    maxAge: 1000 * 60 * 60 * 12  // 12 ore
  }
}));

// ---- Token in memoria (alternativa robusta ai cookie) ----
// Dopo il login, oltre al cookie diamo all'app un token che rimanda a ogni richiesta.
// Funziona anche se il browser blocca i cookie su localhost.
import crypto from "crypto";
const TOKEN_TTL = 1000 * 60 * 60 * 12; // 12 ore

// I token sono FIRMATI con il segreto del server: restano validi anche dopo un riavvio
// (non dipendono dalla memoria). Scadono dopo TOKEN_TTL.
function firma(data){
  return crypto.createHmac("sha256", SESSION_SECRET).update(data).digest("hex");
}
function newToken(user) {
  const exp = Date.now() + TOKEN_TTL;
  const payload = `${user}.${exp}`;
  const sig = firma(payload);
  // formato: utente.scadenza.firma  (codificato in base64url per sicurezza)
  return Buffer.from(`${payload}.${sig}`).toString("base64url");
}
function tokenValido(t) {
  try {
    const decoded = Buffer.from(t, "base64url").toString("utf8");
    const parts = decoded.split(".");
    if (parts.length !== 3) return false;
    const [user, exp, sig] = parts;
    if (firma(`${user}.${exp}`) !== sig) return false;   // firma non valida
    if (Date.now() > Number(exp)) return false;           // scaduto
    return true;
  } catch (e) {
    return false;
  }
}

// ---- Middleware: accetta sessione-cookie OPPURE token nell'header ----
function estraiToken(req){
  // cerca il token in vari header possibili, in modo tollerante
  let t = req.headers["x-app-token"] || req.headers["x-app-token".toLowerCase()];
  if(!t && req.headers["authorization"]){
    const a = req.headers["authorization"];
    t = a.startsWith("Bearer ") ? a.slice(7) : a;
  }
  if(Array.isArray(t)) t = t[0];
  return (t || "").trim();
}
function requireLogin(req, res, next) {
  if (req.session && req.session.authed) return next();
  const auth = estraiToken(req);
  if (auth && tokenValido(auth)) return next();
  // diagnostica utile nei log del terminale
  console.log("[AUTH] richiesta rifiutata. token ricevuto:", auth ? (auth.slice(0,10)+"…") : "(nessuno)",
              "| valido:", auth ? tokenValido(auth) : false);
  return res.status(401).json({ error: "non autenticato" });
}

// =================== ROTTE DI AUTENTICAZIONE ===================

// Login: riceve { username, password }, verifica contro l'hash salvato
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "username e password obbligatori" });
  }
  if (!APP_PASSWORD_HASH) {
    return res.status(500).json({ error: "password non configurata sul server" });
  }
  const userOk = username === APP_USERNAME;
  let passOk = false;
  try {
    passOk = await bcrypt.compare(password, APP_PASSWORD_HASH);
  } catch (e) {
    passOk = false;
  }
  if (userOk && passOk) {
    req.session.authed = true;
    req.session.user = username;
    const token = newToken(username); // token di backup, indipendente dal cookie
    return res.json({ ok: true, token });
  }
  return res.status(401).json({ error: "credenziali non valide" });
});

// Logout
app.post("/api/logout", (req, res) => {
  // i token sono firmati e scadono da soli; basta distruggere la sessione lato cookie.
  // L'app dal canto suo dimentica il token in memoria.
  if (req.session) { req.session.destroy(() => res.json({ ok: true })); }
  else res.json({ ok: true });
});

// Stato sessione (l'app lo chiede all'avvio per sapere se mostrare il login)
app.get("/api/me", (req, res) => {
  const t = req.headers["x-app-token"];
  const authedByToken = t && tokenValido(t);
  const authedBySession = !!(req.session && req.session.authed);
  res.json({ authed: authedBySession || authedByToken, user: req.session?.user || null });
});

// =================== API OMI GRATUITA (3eurotools) ===================
// Mappa quartieri app → zone OMI catastali di Busto Arsizio (codice B300)
const ZONA_OMI_MAP = {
  "Centro":               "B1",
  "Tribunale":            "B1",
  "Sant'Edoardo":         "C1",
  "Sant'Anna":            "C1",
  "Santissimi Apostoli":  "C1",
  "San Michele":          "C2",
  "Madonna Regina":       "C2",
  "Redentore":            "D2",
  "Beata Giuliana":       "D1",
  "Borsano":              "D3",
  "Sacconago":            "D4"
};

// Recupera quotazioni OMI per tutte le zone di Busto Arsizio (gratuito, nessuna chiave)
app.get("/api/omi", requireLogin, async (req, res) => {
  try {
    const url = "https://3eurotools.it/api-quotazioni-immobiliari-omi/ricerca?codice_comune=B300&operazione=acquisto&tipo_immobile=abitazioni_civili";
    const apiRes = await fetch(url);
    if (!apiRes.ok) {
      return res.status(502).json({ error: "Errore nel recuperare i dati OMI", status: apiRes.status });
    }
    const zoneOMI = await apiRes.json();
    // Costruisce la risposta: per ogni quartiere, prende il valore medio dalla zona OMI corrispondente
    const risultati = {};
    for (const [quartiere, zonaCode] of Object.entries(ZONA_OMI_MAP)) {
      const zona = zoneOMI[zonaCode];
      if (zona && zona.abitazioni_civili) {
        risultati[quartiere] = {
          zona_omi: zonaCode,
          min: zona.abitazioni_civili.prezzo_acquisto_min,
          max: zona.abitazioni_civili.prezzo_acquisto_max,
          med: zona.abitazioni_civili.prezzo_acquisto_medio,
          stato: zona.abitazioni_civili.stato_di_conservazione_mediano_della_zona
        };
      }
    }
    return res.json({ ok: true, data: risultati, fonte: "OMI - Agenzia delle Entrate" });
  } catch (e) {
    return res.status(502).json({ error: "Errore nel contattare l'API OMI", detail: String(e) });
  }
});

// Proxy per i tile WMS catastali (Agenzia delle Entrate) — evita CORS dal browser
app.get("/api/catasto-tile", requireLogin, async (req, res) => {
  const bbox = req.query.bbox;
  if (!bbox) return res.status(400).end();
  const url = `https://wms.cartografia.agenziaentrate.gov.it/inspire/wms/ows01.php?SERVICE=WMS&VERSION=1.3.0&REQUEST=GetMap&LAYERS=CP.CadastralParcel&STYLES=&FORMAT=image/png&TRANSPARENT=true&CRS=EPSG:3857&WIDTH=256&HEIGHT=256&BBOX=${encodeURIComponent(bbox)}`;
  try {
    const r = await fetch(url);
    const buf = await r.arrayBuffer();
    res.set("Content-Type", "image/png");
    res.set("Cache-Control", "public, max-age=86400");
    res.send(Buffer.from(buf));
  } catch(e) {
    res.status(502).end();
  }
});

// =================== FILE STATICI (l'app) ===================
// L'app (index.html) viene servita da qui. È protetta: senza login l'API non risponde.
app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`\n✅ Casa Busto Pro in ascolto su http://localhost:${PORT}`);
  console.log(`   Apri quell'indirizzo nel browser. Ti chiederà il login.\n`);
});
