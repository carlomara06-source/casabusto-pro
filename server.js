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

// =================== PROXY VERSO L'API OPENAPI ===================
/**
 * L'app chiama QUESTO endpoint, non l'API direttamente.
 * Il server aggiunge la chiave e inoltra la richiesta. Così la chiave resta qui.
 *
 * Body atteso dall'app:
 *  {
 *    endpoint: "IT-sqm_value_advanced",   // quale endpoint OpenAPI usare
 *    method: "POST",                       // POST o GET
 *    payload: { ... }                      // i parametri (es. latitude, longitude, citta...)
 *  }
 */
app.post("/api/openapi", requireLogin, async (req, res) => {
  const { endpoint, method = "POST", payload = {} } = req.body || {};
  if (!endpoint || !/^[A-Za-z0-9_\-]+$/.test(endpoint)) {
    return res.status(400).json({ error: "endpoint non valido" });
  }
  if (!OPENAPI_KEY) {
    return res.status(500).json({ error: "chiave API non configurata sul server" });
  }
  const url = `${OPENAPI_BASE}/${endpoint}`;
  try {
    const opts = {
      method: method.toUpperCase() === "GET" ? "GET" : "POST",
      headers: {
        "Authorization": `Bearer ${OPENAPI_KEY}`,
        "Content-Type": "application/json"
      }
    };
    if (opts.method === "POST") opts.body = JSON.stringify(payload);
    const apiRes = await fetch(url, opts);
    const text = await apiRes.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }
    // Se OpenAPI rifiuta, restituisco 502 (non il codice originale) così il browser
    // non confonde un errore API con un errore di sessione (che è sempre 401).
    if (!apiRes.ok) {
      return res.status(502).json({
        error: "OpenAPI ha rifiutato la richiesta",
        statusOpenAPI: apiRes.status,
        endpointChiamato: endpoint,
        urlChiamato: url,
        rispostaOpenAPI: data
      });
    }
    return res.status(apiRes.status).json(data);
  } catch (e) {
    return res.status(502).json({ error: "errore nel contattare l'API OpenAPI", detail: String(e) });
  }
});

/**
 * Recupero risultato asincrono: alcune richieste OpenAPI restituiscono un id
 * e vanno poi lette con una GET su /{endpoint}/{id}. Questo endpoint lo fa per te.
 */
app.post("/api/openapi-result", requireLogin, async (req, res) => {
  const { endpoint, id } = req.body || {};
  if (!endpoint || !/^[A-Za-z0-9_\-]+$/.test(endpoint) || !id || !/^[A-Za-z0-9_\-]+$/.test(id)) {
    return res.status(400).json({ error: "parametri non validi" });
  }
  const url = `${OPENAPI_BASE}/${endpoint}/${id}`;
  try {
    const apiRes = await fetch(url, {
      method: "GET",
      headers: { "Authorization": `Bearer ${OPENAPI_KEY}` }
    });
    const text = await apiRes.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }
    return res.status(apiRes.status).json(data);
  } catch (e) {
    return res.status(502).json({ error: "errore nel recuperare il risultato", detail: String(e) });
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
