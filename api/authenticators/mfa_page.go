package authenticators

// The second-factor page shown after the password prompt. It is a
// small standalone page so it works before the console loads. Users who
// have not enrolled yet (and must) set up an authenticator app here;
// enrolled users enter a code.
const mfaPageHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Atlantiraptor – two-factor sign in</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;background:#f6f7f9;color:#1a1a1a;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#fff;border:1px solid #e3e5e8;border-radius:12px;padding:28px;width:360px;box-shadow:0 4px 20px rgba(0,0,0,.06)}
h1{font-size:18px;margin:0 0 6px} p{margin:0 0 14px;color:#555;font-size:13px}
input{width:100%;box-sizing:border-box;font:20px/1 ui-monospace,monospace;letter-spacing:4px;padding:10px 12px;border:1px solid #cfd3d8;border-radius:8px}
button{margin-top:14px;width:100%;padding:10px;border:0;border-radius:8px;background:#4f46e5;color:#fff;font-size:14px;cursor:pointer}
button:disabled{opacity:.6;cursor:default} .err{color:#b42318;font-size:13px;min-height:20px;margin-top:10px}
.hint{font-size:12px;color:#777;margin-top:14px} .hidden{display:none}
.qr{display:block;margin:6px auto 10px;width:200px;height:200px;background:#fff;padding:6px;border-radius:8px}
.secret{font:13px ui-monospace,monospace;word-break:break-all;background:#f1f2f4;border-radius:6px;padding:8px;user-select:all}
.codes{font:14px ui-monospace,monospace;display:grid;grid-template-columns:1fr 1fr;gap:4px;background:#fff7e6;border:1px solid #f3d19e;border-radius:8px;padding:10px}
@media (prefers-color-scheme: dark){body{background:#111317;color:#e8e8e8}.card{background:#1a1d23;border-color:#2b2f36}p,.hint{color:#9aa0a8}input{background:#111317;color:#e8e8e8;border-color:#3a3f47}.secret{background:#111317}.codes{background:#2a2312;border-color:#5c4a1f}}
</style></head>
<body>
<div class="card">
  <div id="loading"><p>Loading…</p></div>

  <form id="verify" class="hidden" autocomplete="off">
    <h1>Two-factor sign in</h1>
    <p>Signed in as <b>{{.User}}</b>. Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p>
    <input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="11" required>
    <button id="verifyBtn" type="submit">Verify</button>
    <div class="hint">Lost your phone? Use a recovery code, or ask an administrator to reset two-factor sign in for you.</div>
  </form>

  <div id="enroll" class="hidden">
    <h1>Set up two-factor sign in</h1>
    <p>Your account <b>{{.User}}</b> needs two-factor sign in. It takes a minute: you need an authenticator app such as Google Authenticator, Microsoft Authenticator, 1Password or Yubico Authenticator.</p>
    <button id="beginBtn" type="button">Start</button>
    <form id="enrollForm" class="hidden" autocomplete="off">
      <p>1. Scan this code with your app, or type the key.</p>
      <img id="qr" class="qr" alt="Authenticator QR code">
      <div id="secret" class="secret"></div>
      <p style="margin-top:14px">2. Enter the 6-digit code your app shows.</p>
      <input id="enrollCode" inputmode="numeric" maxlength="6" required>
      <button id="confirmBtn" type="submit">Turn on two-factor sign in</button>
    </form>
  </div>

  <div id="codesPanel" class="hidden">
    <h1>Save your recovery codes</h1>
    <p>Each code works once if you lose your phone. They will not be shown again. Copy them somewhere safe now.</p>
    <div id="codes" class="codes"></div>
    <button id="continueBtn" type="button">I saved them, continue</button>
  </div>

  <div class="err" id="err" role="alert"></div>
</div>
<script>
(function(){
  var base = {{.BasePath}}.replace(/\/+$/, '');
  var token = {{.CsrfToken}};
  function $(id){ return document.getElementById(id); }
  function show(id){ ['loading','verify','enroll','codesPanel'].forEach(function(x){ $(x).classList.toggle('hidden', x !== id); }); }
  function err(m){ $('err').textContent = m || ''; }

  // Only same-origin pages inside the console are allowed as return
  // targets, and the fully resolved URL is used.
  function target(){
    var home = base + '/app/index.html';
    var r = new URLSearchParams(location.search).get('return') || '';
    if (!r || r.charAt(0) !== '/' || /[\u0000-\u001f\u007f\\]/.test(r) || r.indexOf('//') === 0) return home;
    try {
      var u = new URL(r, location.origin);
      if (u.origin !== location.origin) return home;
      if (u.pathname.indexOf(base + '/app/') !== 0 || u.pathname.indexOf('/app/mfa.html') >= 0) return home;
      return u.href;
    } catch (e) { return home; }
  }

  function post(path, body){
    return fetch(base + '/api/v1/atl/mfa/' + path, {
      method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': token},
      body: JSON.stringify(body || {})
    }).then(function(r){
      return r.json().catch(function(){ return {}; }).then(function(d){
        if (!r.ok) throw new Error(d.message || 'Request failed.');
        return d;
      });
    });
  }

  fetch(base + '/api/v1/atl/mfa/whoami', {credentials: 'same-origin'})
    .then(function(r){ return r.json(); })
    .then(function(s){
      if (s.enrolled) { show('verify'); $('code').focus(); }
      else if (s.required) { show('enroll'); }
      else { location.replace(target()); }
    })
    .catch(function(){ show('verify'); });

  $('verify').addEventListener('submit', function(e){
    e.preventDefault(); err(''); $('verifyBtn').disabled = true;
    post('verify', {code: $('code').value})
      .then(function(){ location.replace(target()); })
      .catch(function(x){ err(x.message); $('verifyBtn').disabled = false; });
  });

  $('beginBtn').addEventListener('click', function(){
    err(''); $('beginBtn').disabled = true;
    post('enroll/begin').then(function(d){
      if (d.qr_png) { $('qr').src = d.qr_png; } else { $('qr').classList.add('hidden'); }
      $('secret').textContent = d.secret;
      $('beginBtn').classList.add('hidden');
      $('enrollForm').classList.remove('hidden');
      $('enrollCode').focus();
    }).catch(function(x){ err(x.message); $('beginBtn').disabled = false; });
  });

  $('enrollForm').addEventListener('submit', function(e){
    e.preventDefault(); err(''); $('confirmBtn').disabled = true;
    post('enroll/confirm', {code: $('enrollCode').value}).then(function(d){
      var box = $('codes'); box.textContent = '';
      (d.recovery_codes || []).forEach(function(c){ var s = document.createElement('span'); s.textContent = c; box.appendChild(s); });
      show('codesPanel');
    }).catch(function(x){ err(x.message); $('confirmBtn').disabled = false; });
  });

  $('continueBtn').addEventListener('click', function(){ location.replace(target()); });
})();
</script>
</body></html>`
