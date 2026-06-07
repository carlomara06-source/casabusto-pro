/**
 * Genera l'hash sicuro della tua password.
 * Uso:  node genera-password.js  "la-tua-password"
 *
 * Copia la riga che ti stampa dentro il file .env (campo APP_PASSWORD_HASH).
 * La password in chiaro non viene salvata da nessuna parte.
 */
import bcrypt from "bcryptjs";

const pwd = process.argv[2];
if (!pwd) {
  console.log('\nUso: node genera-password.js "la-tua-password"\n');
  process.exit(1);
}
const hash = bcrypt.hashSync(pwd, 10);
console.log("\nIncolla questa riga nel file .env:\n");
console.log(`APP_PASSWORD_HASH=${hash}\n`);
