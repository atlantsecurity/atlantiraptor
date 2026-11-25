package authenticators

// The second-factor page shown after the password prompt. It is a
// small standalone page so it works before the console loads.
const mfaPageHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Atlantiraptor – two-factor sign in</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;background:#f6f7f9;color:#1a1a1a;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#fff;border:1px solid #e3e5e8;border-radius:12px;padding:28px;width:340px;box-shadow:0 4px 20px rgba(0,0,0,.06)}
h1{font-size:18px;margin:0 0 6px} p{margin:0 0 16px;color:#555;font-size:13px}
input{width:100%;box-sizing:border-box;font:20px/1 ui-monospace,monospace;letter-spacing:4px;padding:10px 12px;border:1px solid #cfd3d8;border-radius:8px}
button{margin-top:14px;width:100%;padding:10px;border:0;border-radius:8px;background:#4f46e5;color:#fff;font-size:14px;cursor:pointer}
button:disabled{opacity:.6;cursor:default} .err{color:#b42318;font-size:13px;min-height:20px;margin-top:10px}
.hint{font-size:12px;color:#777;margin-top:14px}
@media (prefers-color-scheme: dark){body{background:#111317;color:#e8e8e8}.card{background:#1a1d23;border-color:#2b2f36}p,.hint{color:#9aa0a8}input{background:#111317;color:#e8e8e8;border-color:#3a3f47}}
</style></head>
<body><form class="card" id="f" autocomplete="off">
<h1>Two-factor sign in</h1>
<p>Signed in as <b>{{.User}}</b>. Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p>
<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="11" autofocus required>
<button id="go" type="submit">Verify</button>
<div class="err" id="err" role="alert"></div>
<div class="hint">Lost your phone? Use a recovery code, or ask an administrator to reset two-factor sign in for you.</div>
</form>
<script>
(function(){
  var base = {{.BasePath}}.replace(/\/+$/, '');
  var token = {{.CsrfToken}};
  // Only same-origin paths inside the console are allowed as return
  // targets: no control characters, and the resolved URL must stay on
  // this origin.
  function target(){
    var home = base + '/app/index.html';
    var r = new URLSearchParams(location.search).get('return') || '';
    if (!r || r.charAt(0) !== '/' || /[\u0000-\u001f\u007f\\]/.test(r) || r.indexOf('//') === 0) return home;
    try {
      var u = new URL(r, location.origin);
      if (u.origin !== location.origin || u.pathname.indexOf('/app/mfa.html') >= 0) return home;
      return u.pathname + u.search + u.hash;
    } catch (e) { return home; }
  }
  var form = document.getElementById('f'), btn = document.getElementById('go'), err = document.getElementById('err');
  form.addEventListener('submit', function(e){
    e.preventDefault();
    btn.disabled = true; err.textContent = '';
    fetch(base + '/api/v1/atl/mfa/verify', {
      method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': token},
      body: JSON.stringify({code: document.getElementById('code').value})
    }).then(function(r){
      return r.json().catch(function(){ return {}; }).then(function(d){
        if (r.ok) { location.replace(target()); return; }
        err.textContent = d.message || 'Verification failed.';
        btn.disabled = false;
      });
    }).catch(function(){ err.textContent = 'Network error.'; btn.disabled = false; });
  });
})();
</script>
</body></html>`
