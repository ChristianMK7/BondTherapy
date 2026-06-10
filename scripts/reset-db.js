// Wipe all user-generated data from the local SQLite database.
// Run with:   node scripts/reset-db.js --confirm
// Without --confirm, prints what would be deleted and exits without changes.
//
// Keeps the schema intact (no DROP TABLE). Removes:
//   clients, therapists, bookings, messages, password_resets, reviews,
//   booking_messages, contact_replies, blog_posts
// Also clears uploaded files under uploads/ (CVs, photos, certificates).

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const ROOT = path.join(__dirname, '..');
const DB_PATH = path.join(ROOT, 'data', 'bond.db');
const UPLOAD_DIR = path.join(ROOT, 'uploads');
const TABLES = [
  'booking_messages', 'contact_replies', 'reviews', 'password_resets',
  'bookings', 'messages', 'therapists', 'clients', 'blog_posts'
];

const args = new Set(process.argv.slice(2));
const confirmed = args.has('--confirm');

if (!fs.existsSync(DB_PATH)) {
  console.log(`No database found at ${DB_PATH} — nothing to wipe.`);
  process.exit(0);
}

const db = new Database(DB_PATH);

console.log(`Database: ${DB_PATH}\n`);
console.log('Current row counts:');
for (const t of TABLES) {
  try {
    const r = db.prepare(`SELECT COUNT(*) AS c FROM ${t}`).get();
    console.log(`  ${t.padEnd(20)} ${r.c}`);
  } catch {
    console.log(`  ${t.padEnd(20)} (table not present)`);
  }
}

let uploadCount = 0;
if (fs.existsSync(UPLOAD_DIR)) {
  uploadCount = fs.readdirSync(UPLOAD_DIR).filter(f => !f.startsWith('.')).length;
  console.log(`  ${'uploads/'.padEnd(20)} ${uploadCount} files`);
}

if (!confirmed) {
  console.log(`\nDry run. Re-run with --confirm to actually wipe everything above.`);
  console.log(`  node scripts/reset-db.js --confirm`);
  process.exit(0);
}

const wipe = db.transaction(() => {
  for (const t of TABLES) {
    try {
      db.exec(`DELETE FROM ${t}`);
      db.exec(`DELETE FROM sqlite_sequence WHERE name = '${t}'`);
    } catch (e) {
      console.warn(`  skipped ${t}: ${e.message}`);
    }
  }
});
wipe();

if (fs.existsSync(UPLOAD_DIR)) {
  for (const f of fs.readdirSync(UPLOAD_DIR)) {
    if (f.startsWith('.')) continue;
    try { fs.unlinkSync(path.join(UPLOAD_DIR, f)); } catch {}
  }
}

console.log(`\nDone. All test data cleared.`);
