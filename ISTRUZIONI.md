# Casa Busto Pro — Istruzioni

Questa è la versione "seria" di Casa Busto: la tua **chiave API resta protetta** su un piccolo
server (il browser non la vede mai), c'è un **login** all'ingresso, e i dati di mercato
**si aggiornano da soli** premendo un pulsante — niente più copia-incolla.

Per funzionare, l'app ha bisogno che il suo server sia avviato. Sotto trovi due strade:
- **A) Sul tuo computer** — la più semplice per iniziare e provare.
- **B) Online (hosting)** — per averla raggiungibile sempre, anche da telefono.

---

## PRIMA DI TUTTO: la sicurezza della chiave

Le chiavi che hai incollato nella chat vanno considerate "bruciate".
1. Entra nel pannello di OpenAPI.com.
2. **Revoca/elimina** le vecchie chiavi.
3. **Genera una chiave nuova** e tienila da parte: la metterai nel file `.env` (passo 3 sotto),
   che resta solo tuo e non va mai condiviso.

---

## A) Avvio sul tuo computer (consigliato per iniziare)

### Passo 1 — Installa Node.js (una volta sola)
Vai su https://nodejs.org e scarica la versione **LTS**. Installala con le impostazioni predefinite.
(Node.js è il "motore" che fa girare il server. È gratuito.)

### Passo 2 — Apri la cartella nel terminale
- Scompatta la cartella `casabusto-pro` dove preferisci (es. sul Desktop).
- **Windows:** apri la cartella, clicca nella barra dell'indirizzo, scrivi `cmd` e premi Invio.
- **Mac:** apri l'app *Terminale*, scrivi `cd ` (con lo spazio) e trascina dentro la cartella, poi Invio.

### Passo 3 — Crea il file delle impostazioni
Nella cartella c'è un file chiamato `.env.example`.
1. Fanne una copia e rinominala in `.env` (esattamente così, con il punto davanti e senza estensione).
2. Aprila con un editor di testo (Blocco note va benissimo) e compila:
   - `OPENAPI_KEY=` → la tua **chiave nuova**.
   - `SESSION_SECRET=` → una stringa lunga e a caso (pesta sui tasti, almeno 30 caratteri).
   - `APP_USERNAME=` → il nome utente che vuoi (puoi lasciare `admin`).
   - `APP_PASSWORD_HASH=` → lo generi al passo 4.

### Passo 4 — Installa e crea la password
Nel terminale (dentro la cartella) digita questi comandi, uno alla volta:

```
npm install
```
(attende qualche secondo: scarica i componenti necessari)

```
npm run hash "scrivi-qui-la-password-che-vuoi"
```
Ti stamperà una riga tipo `APP_PASSWORD_HASH=$2a$10$....`.
**Copia tutta quella riga** e incollala nel file `.env` al posto della riga `APP_PASSWORD_HASH=`.
(La password in chiaro non viene salvata: nel file resta solo la versione "cifrata".)

### Passo 5 — Avvia
```
npm start
```
Vedrai il messaggio: *Casa Busto Pro in ascolto su http://localhost:3000*.
Apri quell'indirizzo nel browser: comparirà il **login**. Entra con il tuo utente e password.

Per spegnere il server: torna nel terminale e premi `Ctrl + C`.
Per riaccenderlo un'altra volta: riapri la cartella nel terminale e digita di nuovo `npm start`.

---

## B) Metterla online (per usarla sempre, anche da telefono)

Se vuoi che sia raggiungibile senza tenere il computer acceso, puoi caricarla su un servizio di
hosting che supporta Node.js. Molti hanno un piano gratuito adatto a un uso come il tuo
(per esempio **Render**, **Railway** o **Fly.io**).

Il procedimento generale è:
1. Crea un account sul servizio scelto.
2. Carica la cartella `casabusto-pro` (di solito tramite GitHub o caricamento diretto).
3. Nelle **impostazioni del servizio** (sezione "Environment" / "Variabili d'ambiente") inserisci
   gli stessi valori del file `.env`: `OPENAPI_KEY`, `APP_USERNAME`, `APP_PASSWORD_HASH`,
   `SESSION_SECRET`. **Non** caricare il file `.env` direttamente: su hosting le variabili si
   mettono nel loro pannello, ed è ancora più sicuro.
4. Imposta il comando di avvio su `npm start` (la maggior parte lo rileva da sola).
5. Il servizio ti darà un indirizzo web (es. `https://casabusto-tuonome.onrender.com`):
   aprilo, fai il login, e sei operativa da qualunque dispositivo.

> Nota: su hosting con HTTPS il login diventa ancora più sicuro (il server lo attiva da solo
> quando rileva l'ambiente di produzione).

Se decidi di andare su uno di questi servizi e ti blocchi in un punto, dimmi **quale hai scelto**
e ti scrivo i passaggi precisi per quel servizio.

---

## Come si usa, una volta entrata

- Tutte le sezioni che già conosci (Dashboard, Mappa, Mercato, Previsioni, Immobili, Aste,
  Valutazione, Agenda, ecc.) funzionano come prima.
- La novità è la sezione **"Aggiorna dati API"**: premi **"Aggiorna TUTTE le zone di Busto"**
  e l'app interroga OpenAPI tramite il server, aggiornando i valori €/mq di tutte le zone da sola.
  Puoi anche aggiornare una singola zona dal pulsante accanto a ciascuna.
- I dati dell'app (immobili, vendite, agenda…) restano salvati **nel browser** che usi.
  Ricordati di usare **Esporta backup** ogni tanto, soprattutto se cambi dispositivo.

---

## In breve, perché così è sicuro

- La **chiave API** vive solo sul server (file `.env` o variabili dell'hosting). Il browser
  riceve solo i risultati, mai la chiave.
- Il **login** è vero: la password non è scritta in chiaro da nessuna parte (si salva solo il suo
  "hash"), e la verifica avviene sul server.
- Il file `.gitignore` impedisce di caricare per sbaglio la chiave online.

Buon lavoro con Casa Busto Pro!
