// Builds a passcode-locked page from a private HTML file.
// The page is encrypted (AES-GCM, key derived from the passcode with PBKDF2),
// so its contents cannot be read from the published source without the passcode.
//
// Usage: node tools/lock-page.mjs <private-source.html> <output.html> <passcode>
// Keep the private source file out of this repo; only the locked output is committed.
import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

const [src, out, passcode] = process.argv.slice(2);
if (!src || !out || !passcode) {
  console.error("Usage: node tools/lock-page.mjs <private-source.html> <output.html> <passcode>");
  process.exit(1);
}

const ITERATIONS = 600000;
const b64 = (buf) => Buffer.from(buf).toString("base64");
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(passcode), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey(
  { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
  baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
);
const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, readFileSync(src));
const payload = JSON.stringify({ salt: b64(salt), iv: b64(iv), iter: ITERATIONS, data: b64(cipher) });

const page = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>Pittsburgh Rental Market Map | Matt Cercone Real Estate</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500&family=IBM+Plex+Sans:wght@400;500&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root{--charcoal:#1c1b1a; --slate:#2e3a46; --gold:#c9a227; --gold-soft:#e4c766; --paper:#e9e5db; --brick:#8c3b2e; --line-dark:rgba(233,229,219,0.18);}
  *{box-sizing:border-box;}
  body{margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px 16px;
    background:var(--charcoal); color:var(--paper); font-family:'IBM Plex Sans',sans-serif; -webkit-font-smoothing:antialiased;}
  .gate{width:100%; max-width:420px; border:1px solid var(--line-dark); border-top:3px solid var(--gold); padding:36px 32px;}
  .kicker{font-family:'IBM Plex Mono',monospace; font-size:12px; color:var(--gold); text-transform:uppercase; letter-spacing:0.06em;}
  h1{font-family:'Fraunces',serif; font-weight:500; font-size:30px; line-height:1.1; margin:10px 0 12px;}
  p{color:rgba(233,229,219,0.75); font-size:14.5px; line-height:1.5; margin:0 0 24px;}
  label{display:block; font-family:'IBM Plex Mono',monospace; font-size:11px; text-transform:uppercase; letter-spacing:0.06em; color:rgba(233,229,219,0.65); margin-bottom:6px;}
  input{width:100%; border:none; border-bottom:1.5px solid var(--paper); background:transparent; color:var(--paper);
    padding:10px 2px; font-size:16px; font-family:'IBM Plex Sans',sans-serif;}
  input:focus{outline:none; border-bottom-color:var(--gold);}
  button{margin-top:22px; background:var(--gold); color:var(--charcoal); border:none; padding:13px 26px;
    font-family:'IBM Plex Mono',monospace; font-size:13px; cursor:pointer;}
  button:hover{background:var(--gold-soft);}
  button:disabled{opacity:0.6; cursor:wait;}
  .err{min-height:20px; margin-top:14px; font-size:13.5px; color:#e8907f;}
  .links{margin-top:26px; padding-top:18px; border-top:1px solid var(--line-dark); font-family:'IBM Plex Mono',monospace; font-size:12.5px;}
  .links a{color:var(--gold); text-decoration:none;}
  .links a:hover{text-decoration:underline;}
</style>
</head>
<body>
<main class="gate">
  <div class="kicker">Private resource</div>
  <h1>Pittsburgh Rental Market Map</h1>
  <p>Rent ranges by neighborhood across Pittsburgh. Enter the passcode to view the map.</p>
  <form id="gate" autocomplete="off">
    <label for="code">Passcode</label>
    <input id="code" type="password" required autofocus>
    <button id="go" type="submit">Unlock map →</button>
    <div class="err" id="err" role="alert"></div>
  </form>
  <div class="links">Need access? <a href="index.html#contact">Contact Matt</a> · <a href="resources.html">← Resources</a></div>
</main>
<script type="application/json" id="locked">${payload}</script>
<script>
(function(){
  var KEY = "rental-map-code";
  var box = JSON.parse(document.getElementById("locked").textContent);
  function bytes(s){ return Uint8Array.from(atob(s), function(c){ return c.charCodeAt(0); }); }
  async function unlock(code){
    var base = await crypto.subtle.importKey("raw", new TextEncoder().encode(code), "PBKDF2", false, ["deriveKey"]);
    var key = await crypto.subtle.deriveKey({name:"PBKDF2", salt:bytes(box.salt), iterations:box.iter, hash:"SHA-256"},
      base, {name:"AES-GCM", length:256}, false, ["decrypt"]);
    var plain = await crypto.subtle.decrypt({name:"AES-GCM", iv:bytes(box.iv)}, key, bytes(box.data));
    return new TextDecoder().decode(plain);
  }
  function show(html){ document.open(); document.write(html); document.close(); }
  var form = document.getElementById("gate"), input = document.getElementById("code"),
      btn = document.getElementById("go"), err = document.getElementById("err");
  if (!window.crypto || !crypto.subtle) {
    err.textContent = "This browser can't open the map. Try an up-to-date browser.";
    btn.disabled = true; return;
  }
  try {
    var saved = sessionStorage.getItem(KEY);
    if (saved) unlock(saved).then(show, function(){ try{ sessionStorage.removeItem(KEY); }catch(e){} });
  } catch(e){}
  form.addEventListener("submit", async function(e){
    e.preventDefault();
    var code = input.value.trim();
    if (!code) return;
    btn.disabled = true; err.textContent = ""; btn.textContent = "Unlocking…";
    try {
      var html = await unlock(code);
      try{ sessionStorage.setItem(KEY, code); }catch(e){}
      show(html);
    } catch(ex) {
      err.textContent = "That passcode isn't right. Please try again.";
      btn.disabled = false; btn.textContent = "Unlock map →";
      input.select();
    }
  });
})();
</script>
</body>
</html>
`;
writeFileSync(out, page);
console.log("Wrote " + out);
