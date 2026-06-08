import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import https from "https";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

const APP_PASSWORD_HASH = process.env.APP_PASSWORD_HASH || "";
const APP_USERNAME     = process.env.APP_USERNAME || "admin";
const SESSION_SECRET   = process.env.SESSION_SECRET || "cambia-questo-segreto";
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "";
const SCRAPERAPI_KEY    = process.env.SCRAPERAPI_KEY || "";

if (!APP_PASSWORD_HASH) console.warn("\n⚠️  APP_PASSWORD_HASH non impostata nel .env\n");

app.use(express.json({ limit: "30mb" })); // 30 MB per le immagini base64
app.set("trust proxy", 1);

const IS_HTTPS = process.env.FORCE_HTTPS === "1" || process.env.NODE_ENV === "production";

app.use(session({
  name: "casabusto.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: IS_HTTPS, maxAge: 1000*60*60*12 }
}));

// ---- Token HMAC (alternativa cookie) ----
const TOKEN_TTL = 1000*60*60*12;
function firma(d){ return crypto.createHmac("sha256",SESSION_SECRET).update(d).digest("hex"); }
function newToken(user){ const exp=Date.now()+TOKEN_TTL; const p=`${user}.${exp}`; return Buffer.from(`${p}.${firma(p)}`).toString("base64url"); }
function tokenValido(t){
  try{
    const dec=Buffer.from(t,"base64url").toString("utf8");
    const pts=dec.split(".");
    if(pts.length!==3)return false;
    const[user,exp,sig]=pts;
    if(firma(`${user}.${exp}`)!==sig)return false;
    if(Date.now()>Number(exp))return false;
    return true;
  }catch{return false;}
}
function estraiToken(req){
  let t=req.headers["x-app-token"]||"";
  if(!t&&req.headers["authorization"]){const a=req.headers["authorization"];t=a.startsWith("Bearer ")?a.slice(7):a;}
  if(Array.isArray(t))t=t[0];
  return (t||"").trim();
}
function requireLogin(req,res,next){
  if(req.session&&req.session.authed)return next();
  const auth=estraiToken(req);
  if(auth&&tokenValido(auth))return next();
  return res.status(401).json({error:"non autenticato"});
}

// =================== AUTH ===================
app.post("/api/login", async (req,res)=>{
  const{username,password}=req.body||{};
  if(!username||!password)return res.status(400).json({error:"credenziali mancanti"});
  if(!APP_PASSWORD_HASH)return res.status(500).json({error:"password non configurata"});
  const ok=(username===APP_USERNAME)&&await bcrypt.compare(password,APP_PASSWORD_HASH).catch(()=>false);
  if(ok){ req.session.authed=true; req.session.user=username; return res.json({ok:true,token:newToken(username)}); }
  return res.status(401).json({error:"credenziali non valide"});
});

app.post("/api/logout",(req,res)=>{
  if(req.session)req.session.destroy(()=>res.json({ok:true}));
  else res.json({ok:true});
});

app.get("/api/me",(req,res)=>{
  const t=estraiToken(req);
  res.json({authed:!!(req.session?.authed)||tokenValido(t),user:req.session?.user||null});
});

// =================== OMI (3eurotools gratuito) ===================
const ZONA_OMI_MAP = {
  "Centro":"B1","Tribunale":"B1","Sant'Edoardo":"C1","Sant'Anna":"C1",
  "Santissimi Apostoli":"C1","San Michele":"C2","Madonna Regina":"C2",
  "Redentore":"D2","Beata Giuliana":"D1","Borsano":"D3","Sacconago":"D4"
};

app.get("/api/omi", requireLogin, async (req,res)=>{
  try{
    const url="https://3eurotools.it/api-quotazioni-immobiliari-omi/ricerca?codice_comune=B300&operazione=acquisto&tipo_immobile=abitazioni_civili";
    const r=await fetch(url);
    if(!r.ok)return res.status(502).json({error:"Errore API OMI",status:r.status});
    const zone=await r.json();
    const risultati={};
    for(const[q,zc]of Object.entries(ZONA_OMI_MAP)){
      const z=zone[zc];
      if(z?.abitazioni_civili) risultati[q]={zona_omi:zc,min:z.abitazioni_civili.prezzo_acquisto_min,max:z.abitazioni_civili.prezzo_acquisto_max,med:z.abitazioni_civili.prezzo_acquisto_medio,stato:z.abitazioni_civili.stato_di_conservazione_mediano_della_zona};
    }
    return res.json({ok:true,data:risultati,fonte:"OMI - Agenzia delle Entrate"});
  }catch(e){return res.status(502).json({error:"Errore OMI",detail:String(e)});}
});

// =================== CATASTO WMS PROXY ===================
// Agente HTTPS che accetta il certificato self-signed dell'Agenzia delle Entrate
const _catastoAgent=new https.Agent({rejectUnauthorized:false});

// Conversione EPSG:3857 (Web Mercator) → lat/lon ETRS89 per WMS EPSG:4258
function _mercToLatLon(x,y){
  const R=6378137;
  return{
    lat:(2*Math.atan(Math.exp(y/R))-Math.PI/2)*(180/Math.PI),
    lon:x/R*(180/Math.PI)
  };
}

app.get("/api/catasto-tile", requireLogin, async (req,res)=>{
  const bboxStr=req.query.bbox;
  if(!bboxStr)return res.status(400).end();
  // MapLibre passa {bbox-epsg-3857}: minX,minY,maxX,maxY in metri
  const [x1,y1,x2,y2]=bboxStr.split(',').map(Number);
  const sw=_mercToLatLon(x1,y1), ne=_mercToLatLon(x2,y2);
  // WMS 1.3.0 + EPSG:4258: ordine assi = LAT,LON (minLat,minLon,maxLat,maxLon)
  const bbox4258=`${sw.lat.toFixed(7)},${sw.lon.toFixed(7)},${ne.lat.toFixed(7)},${ne.lon.toFixed(7)}`;
  const p=new URLSearchParams({SERVICE:"WMS",VERSION:"1.3.0",REQUEST:"GetMap",
    LAYERS:"CP.CadastralParcel",STYLES:"",FORMAT:"image/png",TRANSPARENT:"true",
    CRS:"EPSG:4258",WIDTH:"256",HEIGHT:"256",BBOX:bbox4258});
  const wmsUrl=`https://wms.cartografia.agenziaentrate.gov.it/inspire/wms/ows01.php?${p}`;
  try{
    const buf=await new Promise((resolve,reject)=>{
      const req2=https.get(wmsUrl,{agent:_catastoAgent},r2=>{
        const chunks=[];
        r2.on('data',c=>chunks.push(c));
        r2.on('end',()=>resolve(Buffer.concat(chunks)));
        r2.on('error',reject);
      });
      req2.on('error',reject);
      req2.setTimeout(10000,()=>{req2.destroy();reject(new Error('timeout'));});
    });
    res.set("Content-Type","image/png").set("Cache-Control","public,max-age=86400").send(buf);
  }catch(e){
    console.warn('[catasto]',e.message);
    res.status(502).end();
  }
});

// =================== FRAME PROXY (strip X-Frame-Options + anti-bot headers) ===================
const FRAME_ALLOWED = ['immobiliare.it','idealista.it','casa.it','wikicasa.it','tecnoborsa.it','agenziaentrate.gov.it','borsino','immobiliare24.it'];

// Cache in memoria (1 ora) — evita di sprecare crediti ScraperAPI su richieste ripetute
const frameCache = new Map(); // url → {html, contentType, origin, ts}
const FRAME_CACHE_TTL = 60 * 60 * 1000; // 1 ora

// Headers completi di Chrome 124 su macOS — bypassano bot-detection base
const CHROME_HEADERS = {
  "User-Agent":              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Accept":                  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
  "Accept-Language":         "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
  "Cache-Control":           "max-age=0",
  "Sec-Ch-Ua":               '"Google Chrome";v="124", "Chromium";v="124", "Not-A.Brand";v="99"',
  "Sec-Ch-Ua-Mobile":        "?0",
  "Sec-Ch-Ua-Platform":      '"macOS"',
  "Sec-Fetch-Dest":          "document",
  "Sec-Fetch-Mode":          "navigate",
  "Sec-Fetch-Site":          "none",
  "Sec-Fetch-User":          "?1",
  "Upgrade-Insecure-Requests":"1",
  "Dnt":                     "1",
  "Referer":                 "https://www.google.it/"
};

app.get("/api/frame", requireLogin, async (req,res)=>{
  const url=req.query.url;
  if(!url)return res.status(400).send("URL mancante");
  let urlObj;
  try{ urlObj=new URL(url); }catch{ return res.status(400).send("URL non valido"); }
  if(!FRAME_ALLOWED.some(d=>urlObj.hostname.includes(d)))
    return res.status(403).send("Dominio non consentito");

  // Cache hit?
  const cacheKey = url.split('&t=')[0]; // ignora cache-buster
  const cached = frameCache.get(cacheKey);
  if(cached && Date.now() - cached.ts < FRAME_CACHE_TTL){
    console.log(`[frame] cache hit → ${urlObj.hostname}`);
    return sendCachedProxied(res, cached);
  }

  // Controlla se l'HTML è una Cloudflare challenge
  function isCloudflareChallenge(html){
    return html.length < 10000 && (
      html.includes("Just a moment") ||
      html.includes("cf-browser-verification") ||
      html.includes("challenge-platform") ||
      html.includes("__cf_chl_")
    );
  }

  // Inietta anti-framebusting + helpers nel HTML e invia la risposta
  function sendProxied(res, html, contentType, origin){
    // 1. Rimuovi script di framebusting comuni
    html = html.replace(/if\s*\([\s\S]{0,30}top[\s\S]{0,30}(?:self|window|location)[\s\S]{0,80}location\s*=/gi, '/*fb*/if(false');
    // 2. Patch window.top (deve essere PRIMA di ogni altro script)
    const topPatch = `<script>(function(){try{Object.defineProperty(window,'top',{get:function(){return window.self;},configurable:true});}catch(e){}}());<\/script>`;
    // 3. Helpers links + base href
    const helpers = `<base href="${origin}/"><script>
      (function(){
        function fixLinks(){
          document.querySelectorAll('a[href]').forEach(function(a){
            if(!a.target)a.target='_blank';
            if(!a.rel)a.rel='noopener noreferrer';
          });
        }
        if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',fixLinks);
        else fixLinks();
        new MutationObserver(fixLinks).observe(document.body||document.documentElement,{childList:true,subtree:true});
      })();
    <\/script>`;
    html = html.replace(/<head([^>]*)>/i, `<head$1>${topPatch}${helpers}`);
    // Salva in cache
    frameCache.set(cacheKey, {html, contentType, origin, ts:Date.now()});
    res.set("Content-Type", contentType || "text/html; charset=utf-8")
       .set("X-Robots-Tag","noindex")
       .send(html);
  }

  function sendCachedProxied(res, c){
    res.set("Content-Type", c.contentType || "text/html; charset=utf-8")
       .set("X-Robots-Tag","noindex")
       .send(c.html);
  }

  let lastError = "Sito non raggiungibile";

  // === PASSO 1: Fetch diretto con Chrome headers (veloce, 12s) ===
  try{
    console.log(`[frame] passo 1 — fetch diretto → ${urlObj.hostname}`);
    const r = await fetch(url, {
      headers: CHROME_HEADERS,
      redirect: "follow",
      signal: AbortSignal.timeout(12000)
    });
    if(r.ok || r.status === 200){
      const html = await r.text();
      if(!isCloudflareChallenge(html) && html.length > 500){
        console.log(`[frame] passo 1 OK (${html.length} chars)`);
        return sendProxied(res, html, r.headers.get("content-type"), urlObj.origin);
      }else{
        lastError = "Cloudflare challenge rilevata — uso proxy avanzato";
        console.log(`[frame] passo 1 bloccato da Cloudflare`);
      }
    }else{
      lastError = `HTTP ${r.status}`;
      console.log(`[frame] passo 1 → HTTP ${r.status}`);
    }
  }catch(e){
    lastError = e.name === "TimeoutError" ? "Timeout fetch diretto (12s)" : e.message;
    console.log(`[frame] passo 1 errore: ${lastError}`);
  }

  // === PASSO 2: ScraperAPI con rendering JS (bypassa Cloudflare) ===
  if(SCRAPERAPI_KEY){
    try{
      const scraperUrl = `https://api.scraperapi.com/?api_key=${SCRAPERAPI_KEY}&url=${encodeURIComponent(url)}&render=true&country_code=it&device_type=desktop`;
      console.log(`[frame] passo 2 — ScraperAPI render=true → ${urlObj.hostname}`);
      const r = await fetch(scraperUrl, {
        signal: AbortSignal.timeout(55000) // ScraperAPI può essere lento (headless browser)
      });
      if(r.ok){
        const html = await r.text();
        if(html.length > 500){
          console.log(`[frame] passo 2 ScraperAPI OK (${html.length} chars)`);
          return sendProxied(res, html, r.headers.get("content-type"), urlObj.origin);
        }else{
          lastError = `ScraperAPI risposta vuota (${html.length} chars)`;
        }
      }else{
        lastError = `ScraperAPI HTTP ${r.status}`;
      }
    }catch(e){
      lastError = e.name==="TimeoutError"
        ? "Timeout ScraperAPI (55s) — il sito è molto lento o il piano free ha esaurito i crediti"
        : `ScraperAPI: ${e.message}`;
      console.log(`[frame] passo 2 errore: ${lastError}`);
    }
  }

  // === FALLBACK: pagina errore dettagliata ===
  const hasKey = !!SCRAPERAPI_KEY;
  res.status(502).send(`<!DOCTYPE html><html lang="it"><head><meta charset="utf-8">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,-apple-system,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;background:#f4f2ed;color:#0f1a26;text-align:center;padding:32px}
  h2{font-size:20px;font-weight:700;margin-bottom:12px}
  .btn{display:inline-block;padding:11px 22px;border-radius:10px;text-decoration:none;font-weight:700;font-size:14px;margin:4px}
  .btn-r{background:#c0572b;color:#fff}
  .btn-g{background:#fff;color:#333;border:1.5px solid #ddd}
  .err{background:#fff3f0;border:1px solid #f0c8b8;border-radius:10px;padding:14px 18px;font-size:12.5px;color:#8a4030;max-width:460px;text-align:left;margin-bottom:18px;line-height:1.5}
  .tip{background:#f0f4ff;border:1px solid #b8c8f0;border-radius:10px;padding:14px 18px;font-size:12px;color:#2a3a5a;max-width:460px;text-align:left;line-height:1.7;margin-bottom:18px}
  code{background:#e8e4e0;padding:2px 6px;border-radius:4px;font-family:monospace;font-size:11.5px}
</style>
</head><body>
  <div style="font-size:44px;margin-bottom:14px">🔒</div>
  <h2>${urlObj.hostname} non accessibile in anteprima</h2>
  <div class="err"><b>Errore:</b> ${lastError}</div>
  ${hasKey
    ? `<div class="tip">✓ ScraperAPI configurata ma il sito ha comunque bloccato la richiesta.<br>
        Possibili cause: crediti esauriti · piano free limitato · sito con protezione extra.<br>
        Controlla i crediti su <a href="https://www.scraperapi.com/dashboard" target="_blank" style="color:#3a5aa0">scraperapi.com/dashboard</a>.</div>`
    : `<div class="tip"><b>💡 Per bypassare il blocco:</b><br>
        1. Crea account gratuito su <a href="https://www.scraperapi.com/" target="_blank" style="color:#3a5aa0">scraperapi.com</a> (5.000 req/mese gratis)<br>
        2. Copia la tua API key dalla dashboard<br>
        3. Su Render → Environment → aggiungi <code>SCRAPERAPI_KEY</code> = tua chiave<br>
        4. Riavvia il deploy — i portali si caricheranno automaticamente</div>`
  }
  <div>
    <a href="${url}" target="_blank" class="btn btn-r">Apri ${urlObj.hostname} ↗</a>
    <a href="javascript:history.back()" class="btn btn-g">← Torna</a>
  </div>
</body></html>`);
});

// =================== ANALISI FOTO AI (Claude) ===================
const OMI_FALLBACK = {
  "Centro":2004,"Tribunale":1900,"Sant'Edoardo":1850,"Sant'Anna":1690,
  "Santissimi Apostoli":1700,"San Michele":1700,"Madonna Regina":1650,
  "Redentore":1620,"Beata Giuliana":1560,"Borsano":1453,"Sacconago":1479
};

app.post("/api/analizza-foto", requireLogin, async (req,res)=>{
  if(!ANTHROPIC_API_KEY){
    return res.status(503).json({
      error:"Analisi AI non attiva. Aggiungi ANTHROPIC_API_KEY=sk-ant-... nel file .env e riavvia il server."
    });
  }
  const{immagini,zona,mq,tipo,prezzoRichiesto,note}=req.body||{};
  if(!immagini||!immagini.length)return res.status(400).json({error:"Nessuna immagine fornita"});
  if(immagini.length>12)return res.status(400).json({error:"Massimo 12 foto per analisi"});

  const omiBase=OMI_FALLBACK[zona]||1800;

  const system=`Sei un perito immobiliare iscritto all'albo, esperto del mercato di Busto Arsizio (VA), Lombardia.
Analizzi foto di immobili per stimarne il valore di mercato, la vendibilità e il posizionamento di prezzo rispetto all'OMI.
Rispondi SEMPRE con JSON valido e compatto, senza markdown, senza backtick, con questa struttura:
{"stato_conservativo":{"voto":7,"descrizione":"..."},"classe_qualitativa":"civile","punti_forza":["..."],"criticita":["..."],"stima_valore":{"euro_al_mq":1750,"totale_stimato":157500,"motivazione":"..."},"vendibilita":{"percentuale":72,"spiegazione":"...","tempo_stimato_vendita":"2-4 mesi"},"analisi_prezzo":{"fuori_prezzo_percentuale":8,"direzione":"sopra","prezzo_consigliato":157500,"nota":"..."},"piano_azione":"..."}`;

  const content=[
    ...immagini.map(img=>({
      type:"image",
      source:{type:"base64",media_type:img.mime||"image/jpeg",data:img.data}
    })),
    {type:"text",text:
      `Immobile da valutare:\n- Tipo: ${tipo||"Appartamento"}\n- Zona: ${zona||"Centro"}, Busto Arsizio\n` +
      `- Superficie: ${mq||0} mq\n- Valore OMI zona: circa ${omiBase} €/mq\n` +
      (prezzoRichiesto?`- Prezzo richiesto dal proprietario: € ${Number(prezzoRichiesto).toLocaleString("it-IT")}\n`:"") +
      (note?`- Note aggiuntive: ${note}\n`:"") +
      `\nAnalizza le ${immagini.length} foto e fornisci la valutazione completa in JSON.`
    }
  ];

  try{
    const r=await fetch("https://api.anthropic.com/v1/messages",{
      method:"POST",
      headers:{
        "x-api-key":ANTHROPIC_API_KEY,
        "anthropic-version":"2023-06-01",
        "content-type":"application/json"
      },
      body:JSON.stringify({
        model:"claude-opus-4-5",
        max_tokens:2000,
        system,
        messages:[{role:"user",content}]
      }),
      signal:AbortSignal.timeout(60000)
    });
    if(!r.ok){
      const err=await r.json().catch(()=>({}));
      throw new Error(err.error?.message||`HTTP ${r.status}`);
    }
    const d=await r.json();
    const raw=(d.content?.[0]?.text||"").trim();
    let analisi;
    try{ analisi=JSON.parse(raw); }
    catch{ analisi={raw,error:"Parsing JSON fallito — vedi raw"}; }
    res.json({ok:true,analisi});
  }catch(e){
    res.status(502).json({error:e.message});
  }
});

// =================== ANNUNCI LIVE (Subito.it multi-pagina) ===================
const ZONE_BUSTO=["Centro","Tribunale","Sant'Edoardo","Sant'Anna","Santissimi Apostoli","San Michele","Madonna Regina","Redentore","Beata Giuliana","Borsano","Sacconago"];
function detectZonaBusto(text){
  const t=(text||"").toLowerCase();
  // Match diretto del nome quartiere
  for(const z of ZONE_BUSTO){if(t.includes(z.toLowerCase()))return z;}
  // Match via/piazza → zona OMI (80+ strade di Busto Arsizio)
  const viaMap={
    // ── CENTRO ──
    "piazza manzoni":"Centro","via milano":"Centro","corso europa":"Centro",
    "via magenta":"Centro","via galvani":"Centro","via manzoni":"Centro",
    "viale stelvio":"Centro","corso sempione":"Centro","piazza vittoria":"Centro",
    "via garibaldi":"Centro","via cairoli":"Centro","via cavour":"Centro",
    "via verdi":"Centro","via dante":"Centro","via roma":"Centro",
    "piazza san giovanni":"Centro","via torino":"Centro","via morazzone":"Centro",
    "corso matteotti":"Centro","via pellico":"Centro","via monviso":"Centro",
    "via marco polo":"Centro","piazza plebiscito":"Centro","via broletto":"Centro",
    "corso italia":"Centro","via cattaneo":"Centro","via venezia":"Centro",
    "via padre monti":"Centro","via toselli":"Centro",
    // ── TRIBUNALE ──
    "via marsala":"Tribunale","via duca d'aosta":"Tribunale","viale dandolo":"Tribunale",
    "via battisti":"Tribunale","via pirandello":"Tribunale","via goldoni":"Tribunale",
    "via saffi":"Tribunale","via toscana":"Tribunale","via galileo":"Tribunale",
    "viale italia":"Tribunale","piazza del tribunale":"Tribunale","via vico":"Tribunale",
    "via avogadro":"Tribunale","via volta":"Tribunale",
    // ── SANT'EDOARDO ──
    "via mameli":"Sant'Edoardo","via cadorna":"Sant'Edoardo","via carducci":"Sant'Edoardo",
    "via de amicis":"Sant'Edoardo","via pascoli":"Sant'Edoardo","via petrarca":"Sant'Edoardo",
    "via rossini":"Sant'Edoardo","via donizetti":"Sant'Edoardo","via bellini":"Sant'Edoardo",
    "via sant'edoardo":"Sant'Edoardo","via cherubini":"Sant'Edoardo","via palestrina":"Sant'Edoardo",
    // ── SANT'ANNA ──
    "via foscolo":"Sant'Anna","via leopardi":"Sant'Anna","via sant'anna":"Sant'Anna",
    "via solferino":"Sant'Anna","via piave":"Sant'Anna","via isonzo":"Sant'Anna",
    "via tagliamento":"Sant'Anna","via vittorio veneto":"Sant'Anna","via montegrappa":"Sant'Anna",
    "via sempione":"Sant'Anna","viale sempione":"Sant'Anna",
    // ── SANTISSIMI APOSTOLI ──
    "via apostoli":"Santissimi Apostoli","via corridoni":"Santissimi Apostoli",
    "via crispi":"Santissimi Apostoli","via xx settembre":"Santissimi Apostoli",
    "via oberdan":"Santissimi Apostoli","via matteotti":"Santissimi Apostoli",
    "piazza del lavoro":"Santissimi Apostoli",
    // ── SAN MICHELE ──
    "via san michele":"San Michele","via cosenz":"San Michele",
    "via predazzo":"San Michele","piazza san michele":"San Michele",
    "viale san michele":"San Michele","via varesina":"San Michele",
    // ── MADONNA REGINA ──
    "via madonna regina":"Madonna Regina","via monte bianco":"Madonna Regina",
    "via monte cervino":"Madonna Regina","via cascina del sole":"Madonna Regina",
    "via montello":"Madonna Regina","via dolomiti":"Madonna Regina",
    // ── REDENTORE ──
    "via redentore":"Redentore","via campone":"Redentore","via ticino":"Redentore",
    "via adda":"Redentore","via oglio":"Redentore","via trento":"Redentore",
    // ── BEATA GIULIANA ──
    "via giuliana":"Beata Giuliana","via monte nero":"Beata Giuliana",
    "via lombardia":"Beata Giuliana","via montebello":"Beata Giuliana",
    "via monte san gabriele":"Beata Giuliana","via nerviano":"Beata Giuliana",
    // ── BORSANO ──
    "via borsano":"Borsano","via san carlo borromeo":"Borsano",
    "via carso":"Borsano","viale borsano":"Borsano","via prima strada":"Borsano",
    // ── SACCONAGO ──
    "via sacconago":"Sacconago","via monte rosa":"Sacconago",
    "viale sacconago":"Sacconago","via san giovanni":"Sacconago"
  };
  for(const[via,zona]of Object.entries(viaMap)){if(t.includes(via))return zona;}
  return null;
}

// Subito.it usa Next.js — i dati listing sono nel JSON __NEXT_DATA__ embeddato
function parseSubitoPage(html, contratto){
  const m=html.match(/<script id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/);
  if(!m)return[];
  let state;
  try{const d=JSON.parse(m[1]);state=d?.props?.pageProps?.initialState;}catch{return[];}
  const raw=state?.items?.originalList||[];
  const RESI=['Appartamenti','Ville singole e a schiera','Case indipendenti','Mansarde','Nuove Costruzioni'];
  const now=Date.now();
  const annunci=[];
  for(const it of raw){
    if(it?.kind!=='AdItem')continue;
    if(!RESI.includes(it.category?.label))continue;
    const feat=it.features||{};
    // Prezzo
    const priceRaw=feat['/price']?.values?.[0]?.value||feat['/price']?.values?.[0]?.key||'';
    let prezzo=0;
    if(priceRaw){const v=parseInt(String(priceRaw).replace(/[^0-9]/g,''),10);if(v>0)prezzo=v;}
    // mq
    const sizeRaw=feat['/size']?.values?.[0]?.value||feat['/size']?.values?.[0]?.key||'';
    const mq=sizeRaw?parseInt(String(sizeRaw).replace(/[^0-9]/g,''),10):0;
    // Stanze (locali)
    const stanzeRaw=feat['/room']?.values?.[0]?.value||feat['/room']?.values?.[0]?.key||'';
    const stanze=stanzeRaw?parseInt(String(stanzeRaw).replace(/[^0-9]/g,''),10):0;
    // Classe energetica
    const energiaRaw=feat['/energy_class']?.values?.[0]?.value||feat['/energy_class']?.values?.[0]?.key||'';
    const energia=energiaRaw?String(energiaRaw).replace(/[^A-Ga-g0-9+]/g,'').toUpperCase().slice(0,3):'';
    // Data
    const pubDate=it.date||null;
    const pubMs=pubDate?new Date(pubDate).getTime():0;
    const daysAgo=(pubMs>0&&!isNaN(pubMs))?Math.max(0,Math.floor((now-pubMs)/(1000*60*60*24))):null;
    const titolo=it.subject||'';
    const body=it.body||'';
    const link=it.urls?.default||'';
    if(!link)continue;
    const tipoM=titolo.match(/^(bilocale|trilocale|quadrilocale|quintilocale|monolocale|villa|attico|appartamento|casa|loft|rustico|mansarda)/i);
    const catTipoMap={'Appartamenti':'Appartamento','Ville singole e a schiera':'Villa','Case indipendenti':'Casa','Mansarde':'Mansarda','Nuove Costruzioni':'Nuova costruzione'};
    const tipo=tipoM?tipoM[1][0].toUpperCase()+tipoM[1].slice(1).toLowerCase():(catTipoMap[it.category?.label]||'Appartamento');
    // Zona: cerca in titolo, poi in body (spesso contiene l'indirizzo)
    const zona=detectZonaBusto(titolo)||detectZonaBusto(body)||'N/D';
    annunci.push({id:it.urn||'',fonte:'Subito.it',contratto,tipo,zona,
      mq:mq||null,prezzo:prezzo||null,stanze:stanze||null,energia:energia||null,
      titolo,link,pubDate,daysAgo});
  }
  return annunci;
}

// Cache 30 min
let _annunciCache=null, _annunciCacheTs=0;
const ANNUNCI_CACHE_TTL=30*60*1000;

app.get("/api/annunci-live", requireLogin, async (req,res)=>{
  if(_annunciCache&&Date.now()-_annunciCacheTs<ANNUNCI_CACHE_TTL){
    return res.json(_annunciCache);
  }

  const annunci=[];
  // 3 pagine vendita + 3 pagine affitto = fino a ~140 annunci
  const sources=[
    {url:"https://www.subito.it/annunci-lombardia/vendita/immobili/varese/busto-arsizio/",contratto:"vendita"},
    {url:"https://www.subito.it/annunci-lombardia/vendita/immobili/varese/busto-arsizio/?o=2",contratto:"vendita"},
    {url:"https://www.subito.it/annunci-lombardia/vendita/immobili/varese/busto-arsizio/?o=3",contratto:"vendita"},
    {url:"https://www.subito.it/annunci-lombardia/affitto/immobili/varese/busto-arsizio/",contratto:"affitto"},
    {url:"https://www.subito.it/annunci-lombardia/affitto/immobili/varese/busto-arsizio/?o=2",contratto:"affitto"},
    {url:"https://www.subito.it/annunci-lombardia/affitto/immobili/varese/busto-arsizio/?o=3",contratto:"affitto"},
  ];

  for(const{url,contratto}of sources){
    try{
      const r=await fetch(url,{headers:CHROME_HEADERS,signal:AbortSignal.timeout(14000)});
      if(!r.ok){console.warn(`[annunci] Subito.it HTTP ${r.status} ${url}`);continue;}
      const html=await r.text();
      if(!html.includes('__NEXT_DATA__')){console.warn(`[annunci] no Next.js JSON in ${url}`);continue;}
      const parsed=parseSubitoPage(html,contratto);
      console.log(`[annunci] ${url} → ${parsed.length} annunci`);
      annunci.push(...parsed);
    }catch(e){console.warn(`[annunci] ${url}:`,e.message);}
  }

  // Deduplicazione per link
  const seen=new Set();
  const uniq=annunci.filter(a=>{if(seen.has(a.link))return false;seen.add(a.link);return true;});

  // Statistiche per zona
  const zoneStats={};
  for(const a of uniq){
    const z=a.zona;
    if(!zoneStats[z])zoneStats[z]={count:0,vendita:0,affitto:0,prezziMq:[]};
    zoneStats[z].count++;
    if(a.contratto==="vendita")zoneStats[z].vendita++;else zoneStats[z].affitto++;
    // Per €/mq: solo vendita con valori sensati
    if(a.contratto==="vendita"&&a.prezzo>30000&&a.mq>30&&a.mq<500)
      zoneStats[z].prezziMq.push(Math.round(a.prezzo/a.mq));
  }
  for(const s of Object.values(zoneStats)){
    s.medMq=s.prezziMq.length?Math.round(s.prezziMq.reduce((a,b)=>a+b,0)/s.prezziMq.length):0;
    delete s.prezziMq;
  }

  const result={ok:true,totale:uniq.length,annunci:uniq,zoneStats,fonte:'Subito.it',ts:new Date().toISOString()};
  _annunciCache=result; _annunciCacheTs=Date.now();
  res.json(result);
});

// =================== STATIC ===================
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

app.listen(PORT,()=>{
  console.log(`\n✅ CasaBusto Pro → http://localhost:${PORT}`);
  if(!ANTHROPIC_API_KEY)console.log("   ⚠️  ANTHROPIC_API_KEY non impostata — analisi foto AI disabilitata\n");
  else console.log("   ✓  Analisi foto AI attiva (Claude)\n");
});
