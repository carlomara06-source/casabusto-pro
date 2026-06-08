import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";

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
app.get("/api/catasto-tile", requireLogin, async (req,res)=>{
  const bbox=req.query.bbox;
  if(!bbox)return res.status(400).end();
  const p=new URLSearchParams({SERVICE:"WMS",VERSION:"1.3.0",REQUEST:"GetMap",LAYERS:"CP.CadastralParcel",STYLES:"",FORMAT:"image/png",TRANSPARENT:"true",CRS:"EPSG:3857",WIDTH:"256",HEIGHT:"256",BBOX:bbox});
  try{
    const r=await fetch(`https://wms.cartografia.agenziaentrate.gov.it/inspire/wms/ows01.php?${p}`);
    const buf=await r.arrayBuffer();
    res.set("Content-Type","image/png").set("Cache-Control","public,max-age=86400").send(Buffer.from(buf));
  }catch{res.status(502).end();}
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

// =================== ANNUNCI LIVE (RSS) ===================
const ZONE_BUSTO=["Centro","Tribunale","Sant'Edoardo","Sant'Anna","Santissimi Apostoli","San Michele","Madonna Regina","Redentore","Beata Giuliana","Borsano","Sacconago"];
function detectZonaBusto(text){
  const t=(text||"").toLowerCase();
  for(const z of ZONE_BUSTO){if(t.includes(z.toLowerCase()))return z;}
  const viaMap={"via galvani":"Centro","via magenta":"Centro","corso sempione":"Centro","piazza vittoria":"Centro","via manzoni":"Centro","viale stelvio":"Centro","via marsala":"Tribunale","via duca d'aosta":"Tribunale","viale dandolo":"Tribunale","via foscolo":"Sant'Anna","via leopardi":"Sant'Anna","via mameli":"Sant'Edoardo","via san michele":"San Michele","via redentore":"Redentore","via borsano":"Borsano","via sacconago":"Sacconago","via giuliana":"Beata Giuliana","via madonna regina":"Madonna Regina"};
  for(const[via,zona]of Object.entries(viaMap)){if(t.includes(via))return zona;}
  return null;
}
function xmlGet(item,tag){
  const m=item.match(new RegExp(`<${tag}[^>]*>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?<\\/${tag}>`,"i"));
  return(m?.[1]||"").replace(/<[^>]+>/g," ").replace(/\s+/g," ").trim();
}

app.get("/api/annunci-live", requireLogin, async (req,res)=>{
  const annunci=[];
  // Feed RSS multipli — Immobiliare.it RSS NON è dietro Cloudflare, va con Chrome headers
  const feeds=[
    {nome:"Immobiliare.it",url:"https://www.immobiliare.it/feeds/rss/annunci/immobili-in-vendita/busto-arsizio-varese/",contratto:"vendita"},
    {nome:"Immobiliare.it",url:"https://www.immobiliare.it/feeds/rss/annunci/immobili-in-affitto/busto-arsizio-varese/",contratto:"affitto"},
    // Feed zone limitrofe per completezza
    {nome:"Immobiliare.it",url:"https://www.immobiliare.it/feeds/rss/annunci/immobili-in-vendita/busto-arsizio-varese/?prezzoMassimo=300000",contratto:"vendita"},
    {nome:"Wikicasa.it",url:"https://www.wikicasa.it/rss/vendita/busto-arsizio/",contratto:"vendita"}
  ];
  for(const feed of feeds){
    try{
      const r=await fetch(feed.url,{
        headers:{...CHROME_HEADERS,
          "Accept":"application/rss+xml,application/xml,text/xml,application/atom+xml,*/*;q=0.8",
          "Cache-Control":"no-cache","Pragma":"no-cache"},
        signal:AbortSignal.timeout(10000)
      });
      if(!r.ok){console.warn(`[annunci] ${feed.nome} HTTP ${r.status}`);continue;}
      const xml=await r.text();
      if(!xml.includes("<item>")){console.warn(`[annunci] no <item>`);continue;}
      const items=[...xml.matchAll(/<item>([\s\S]*?)<\/item>/g)];
      for(const[,it]of items.slice(0,30)){
        const titolo=xmlGet(it,"title"),desc=xmlGet(it,"description"),link=xmlGet(it,"link"),pub=xmlGet(it,"pubDate");
        const full=titolo+" "+desc;
        const pm=full.match(/(?:€|EUR)\s*([\d.,\s]{3,12})/i);
        let prezzo=pm?parseInt(pm[1].replace(/[.,\s]/g,""),10):0;
        if(prezzo<10000||prezzo>9000000)prezzo=0;
        const am=full.match(/(\d{2,4})\s*m[²q2]/i);
        const mq=am?parseInt(am[1],10):0;
        const zona=detectZonaBusto(full)||"N/D";
        const tm=titolo.match(/^(bilocale|trilocale|quadrilocale|quintilocale|monolocale|villa|attico|appartamento|casa|loft|rustico|mansarda|studio)/i);
        const tipo=tm?tm[1][0].toUpperCase()+tm[1].slice(1).toLowerCase():"Appartamento";
        annunci.push({fonte:feed.nome,contratto:feed.contratto||"vendita",tipo,zona,mq:mq||null,prezzo:prezzo||null,titolo,link,pubDate:pub,desc:desc.slice(0,200)});
      }
    }catch(e){console.warn(`[annunci] ${feed.nome}:`,e.message);}
  }
  const portali=[
    {nome:"Immobiliare.it",url:"https://www.immobiliare.it/vendita-case/busto-arsizio-varese/",color:"#e8392a"},
    {nome:"Idealista",url:"https://www.idealista.it/vendita-case/busto-arsizio-varese/",color:"#006699"},
    {nome:"Casa.it",url:"https://www.casa.it/vendita/residenziale/busto-arsizio/",color:"#ff6633"},
    {nome:"Wikicasa",url:"https://www.wikicasa.it/vendita-case/busto-arsizio/",color:"#28a745"}
  ];
  res.json({ok:true,totale:annunci.length,annunci,portali,ts:new Date().toISOString()});
});

// =================== STATIC ===================
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

app.listen(PORT,()=>{
  console.log(`\n✅ CasaBusto Pro → http://localhost:${PORT}`);
  if(!ANTHROPIC_API_KEY)console.log("   ⚠️  ANTHROPIC_API_KEY non impostata — analisi foto AI disabilitata\n");
  else console.log("   ✓  Analisi foto AI attiva (Claude)\n");
});
