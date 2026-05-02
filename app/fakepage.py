"""
Fake Login Page Generator - SECURITY TRAINING USE ONLY.

Generates realistic-looking simulated login pages for phishing awareness training.
All pages display a visible training overlay and DO NOT collect, store, or transmit
any credentials. For use in controlled security training environments only.
"""


TRAINING_BANNER = """
<div id="phishx-banner" style="
  position:fixed; top:0; left:0; width:100%; z-index:99999;
  background:#d29922; color:#0d1117; font-family:sans-serif;
  font-size:13px; font-weight:700; text-align:center;
  padding:8px 12px; letter-spacing:0.03em; box-shadow:0 2px 8px rgba(0,0,0,0.4);">
  &#9888; PHISH X SIMULATION - THIS IS A FAKE PAGE FOR SECURITY TRAINING ONLY.
  No credentials are collected or transmitted.
  &nbsp;|&nbsp; <span style="text-decoration:underline;cursor:pointer"
    onclick="document.getElementById('phishx-explainer').style.display='block'">
    What is this?
  </span>
</div>
<div id="phishx-explainer" style="
  display:none; position:fixed; top:36px; left:0; width:100%; z-index:99998;
  background:#161b22; color:#e6edf3; font-family:sans-serif; font-size:13px;
  padding:16px 24px; border-bottom:1px solid #30363d; line-height:1.6;">
  <strong>Security Awareness Training - Phish X</strong><br/>
  This page simulates a phishing login page used in real attacks.
  Real attackers clone login pages from Google, Microsoft, banks, etc.
  to steal your credentials.<br/><br/>
  <strong>How to spot a fake login page:</strong>
  Check the browser URL bar carefully. Attackers use domains like
  <em>accounts.google.com.verify-login.net</em> or <em>microsoft-signin.com</em>
  instead of the real domain. Always check the address bar before entering
  your password.
  <button onclick="document.getElementById('phishx-explainer').style.display='none'"
    style="margin-left:16px;padding:4px 12px;background:#58a6ff;color:#0d1117;
    border:none;border-radius:6px;cursor:pointer;font-weight:700;">Close</button>
</div>
<div style="height:36px;"></div>
"""

def _google_page(spoofed_url: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Sign in - Google Accounts</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Google Sans',Roboto,arial,sans-serif; background:#fff; color:#202124; }}
    .container {{ min-height:100vh; display:flex; align-items:center; justify-content:center; }}
    .card {{ width:450px; padding:48px 40px 36px; border:1px solid #dadce0; border-radius:8px; }}
    .logo {{ text-align:center; margin-bottom:24px; }}
    .logo svg {{ width:75px; height:24px; }}
    h1 {{ font-size:24px; font-weight:400; text-align:center; margin-bottom:8px; }}
    .subtitle {{ font-size:16px; color:#202124; text-align:center; margin-bottom:28px; }}
    .input-wrap {{ position:relative; margin-bottom:24px; }}
    .input-wrap input {{ width:100%; padding:13px 15px; border:1px solid #dadce0;
      border-radius:4px; font-size:16px; outline:none; transition:border 0.2s; }}
    .input-wrap input:focus {{ border-color:#1a73e8; box-shadow:0 0 0 2px rgba(26,115,232,0.2); }}
    .input-wrap label {{ position:absolute; left:13px; top:-9px; background:#fff;
      font-size:12px; color:#1a73e8; padding:0 4px; }}
    .forgot {{ font-size:14px; color:#1a73e8; margin-bottom:24px; display:block; text-decoration:none; }}
    .btn-row {{ display:flex; justify-content:space-between; align-items:center; margin-top:28px; }}
    .create {{ color:#1a73e8; font-size:14px; font-weight:500; text-decoration:none; }}
    .btn {{ background:#1a73e8; color:#fff; border:none; border-radius:4px;
      padding:10px 24px; font-size:14px; font-weight:500; cursor:pointer; }}
    .btn:hover {{ background:#1765cc; }}
    .divider {{ border:none; border-top:1px solid #e8eaed; margin:32px 0; }}
    .footer {{ text-align:center; font-size:12px; color:#5f6368; margin-top:12px; }}
  </style>
</head>
<body>
{TRAINING_BANNER}
<div class="container">
  <div class="card">
    <div class="logo">
      <svg viewBox="0 0 75 24" xmlns="http://www.w3.org/2000/svg">
        <text y="20" font-size="22" font-family="Product Sans,sans-serif" font-weight="400">
          <tspan fill="#4285F4">G</tspan><tspan fill="#EA4335">o</tspan>
          <tspan fill="#FBBC05">o</tspan><tspan fill="#4285F4">g</tspan>
          <tspan fill="#34A853">l</tspan><tspan fill="#EA4335">e</tspan>
        </text>
      </svg>
    </div>
    <h1>Sign in</h1>
    <p class="subtitle">Use your Google Account</p>
    <form onsubmit="handleSubmit(event)">
      <div class="input-wrap">
        <input type="email" id="email" placeholder=" " autocomplete="email" />
        <label>Email or phone</label>
      </div>
      <div class="input-wrap" id="pwdWrap" style="display:none">
        <input type="password" id="password" placeholder=" " />
        <label>Enter your password</label>
      </div>
      <a href="#" class="forgot" id="forgotLink" style="display:none">Forgot password?</a>
      <div class="btn-row">
        <a href="#" class="create" id="createLink">Create account</a>
        <button class="btn" type="submit" id="nextBtn">Next</button>
      </div>
    </form>
    <hr class="divider"/>
    <p class="footer">Not your computer? Use Private Browsing windows to sign in.</p>
  </div>
</div>
<script>
  var step = 1;
  function handleSubmit(e) {{
    e.preventDefault();
    if (step === 1) {{
      document.getElementById('pwdWrap').style.display='block';
      document.getElementById('forgotLink').style.display='block';
      document.getElementById('createLink').style.display='none';
      step = 2;
    }} else {{
      showCaught();
    }}
  }}
  function showCaught() {{
    document.querySelector('.card').innerHTML = `
      <div style="text-align:center;padding:32px 0;">
        <div style="font-size:48px;margin-bottom:16px;">&#9888;</div>
        <h2 style="color:#d29922;font-size:20px;margin-bottom:12px;">You entered credentials on a FAKE page!</h2>
        <p style="color:#5f6368;font-size:15px;margin-bottom:20px;">
          In a real attack, your username and password would now be stolen.<br/>
          <strong>Always check the URL before entering your password.</strong>
        </p>
        <p style="font-size:13px;color:#888;">Simulated spoofed URL shown to victim:<br/>
          <code style="color:#f85149;">{spoofed_url}</code></p>
        <p style="font-size:13px;color:#888;margin-top:8px;">Real Google sign-in is always at:<br/>
          <code style="color:#3fb950;">accounts.google.com</code></p>
      </div>`;
  }}
</script>
</body>
</html>"""


def _microsoft_page(spoofed_url: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Sign in to your Microsoft account</title>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ font-family:'Segoe UI',Tahoma,sans-serif; background:#f2f2f2; color:#1b1b1b; }}
    .outer {{ min-height:100vh; display:flex; align-items:center; justify-content:center; }}
    .card {{ width:440px; background:#fff; border-radius:0; padding:44px 44px 40px; box-shadow:0 2px 6px rgba(0,0,0,0.1); }}
    .ms-logo {{ margin-bottom:16px; }}
    .ms-logo svg {{ width:108px; height:24px; }}
    h1 {{ font-size:24px; font-weight:600; margin-bottom:12px; }}
    .desc {{ font-size:13px; color:#444; margin-bottom:24px; }}
    input {{ width:100%; padding:8px 0; border:none; border-bottom:2px solid #666;
      font-size:15px; outline:none; background:transparent; margin-bottom:8px; }}
    input:focus {{ border-bottom-color:#0067b8; }}
    .err {{ color:#a80000; font-size:12px; height:16px; margin-bottom:12px; }}
    .options {{ font-size:13px; color:#0067b8; margin-bottom:24px; cursor:pointer; }}
    .next-btn {{ width:100%; background:#0067b8; color:#fff; border:none;
      padding:10px; font-size:15px; cursor:pointer; font-family:inherit; }}
    .next-btn:hover {{ background:#005fa3; }}
    .back {{ font-size:13px; color:#0067b8; margin-top:20px; cursor:pointer; display:block; }}
    .divider {{ border:none; border-top:1px solid #e0e0e0; margin:28px 0; }}
    .create {{ font-size:13px; color:#0067b8; }}
  </style>
</head>
<body>
{TRAINING_BANNER}
<div class="outer">
  <div class="card">
    <div class="ms-logo">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 108 24">
        <rect x="0" y="0" width="11" height="11" fill="#F25022"/>
        <rect x="12" y="0" width="11" height="11" fill="#7FBA00"/>
        <rect x="0" y="12" width="11" height="11" fill="#00A4EF"/>
        <rect x="12" y="12" width="11" height="11" fill="#FFB900"/>
        <text x="28" y="18" font-size="15" font-family="Segoe UI,sans-serif" fill="#1b1b1b">Microsoft</text>
      </svg>
    </div>
    <h1 id="cardTitle">Sign in</h1>
    <p class="desc" id="cardDesc">to continue to Microsoft</p>
    <form onsubmit="handleSubmit(event)">
      <input type="email" id="email" placeholder="Email, phone, or Skype" autocomplete="username"/>
      <div id="pwdSection" style="display:none">
        <input type="password" id="password" placeholder="Password" autocomplete="current-password"/>
      </div>
      <div class="err" id="errMsg"></div>
      <div class="options" id="noAccountLink">No account? Create one!</div>
      <button class="next-btn" type="submit">Next</button>
    </form>
    <hr class="divider"/>
    <a class="create" href="#">Sign-in options</a>
  </div>
</div>
<script>
  var step = 1;
  function handleSubmit(e) {{
    e.preventDefault();
    if (step === 1) {{
      var em = document.getElementById('email').value;
      if (!em) {{ document.getElementById('errMsg').textContent='Enter a valid email.'; return; }}
      document.getElementById('cardTitle').textContent = em;
      document.getElementById('cardDesc').textContent = 'Microsoft account';
      document.getElementById('pwdSection').style.display='block';
      document.getElementById('noAccountLink').style.display='none';
      step = 2;
    }} else {{
      showCaught();
    }}
  }}
  function showCaught() {{
    document.querySelector('.card').innerHTML = `
      <div style="text-align:center;padding:24px 0;">
        <div style="font-size:48px;margin-bottom:16px;">&#9888;</div>
        <h2 style="color:#d29922;font-size:20px;margin-bottom:12px;">You entered credentials on a FAKE page!</h2>
        <p style="color:#444;font-size:14px;margin-bottom:16px;">
          In a real attack your Microsoft credentials would be stolen.<br/>
          <strong>Real Microsoft sign-in is always at login.microsoftonline.com or login.live.com</strong>
        </p>
        <p style="font-size:12px;color:#888;">Simulated spoofed domain:<br/>
          <code style="color:#f85149;">{spoofed_url}</code></p>
      </div>`;
  }}
</script>
</body>
</html>"""


def _bank_page(bank_name: str, spoofed_url: str, accent: str = "#003087") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>{bank_name} - Secure Online Banking</title>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ font-family:Arial,sans-serif; background:#f4f4f4; color:#333; }}
    header {{ background:{accent}; color:#fff; padding:16px 32px; display:flex; align-items:center; }}
    header span {{ font-size:22px; font-weight:700; letter-spacing:0.02em; }}
    .outer {{ min-height:calc(100vh - 58px); display:flex; align-items:center; justify-content:center; }}
    .card {{ background:#fff; width:400px; padding:36px 40px; border-radius:4px;
      box-shadow:0 2px 12px rgba(0,0,0,0.1); }}
    h2 {{ font-size:20px; margin-bottom:6px; }}
    .subtitle {{ font-size:13px; color:#666; margin-bottom:24px; }}
    label {{ font-size:13px; font-weight:600; display:block; margin-bottom:4px; margin-top:16px; }}
    input {{ width:100%; padding:10px 12px; border:1px solid #ccc; border-radius:3px;
      font-size:14px; outline:none; }}
    input:focus {{ border-color:{accent}; box-shadow:0 0 0 2px rgba(0,100,200,0.15); }}
    .btn {{ width:100%; background:{accent}; color:#fff; border:none; border-radius:3px;
      padding:12px; font-size:15px; font-weight:700; cursor:pointer; margin-top:24px; }}
    .btn:hover {{ opacity:0.9; }}
    .help {{ font-size:12px; color:{accent}; margin-top:12px; text-align:center; cursor:pointer; }}
    .security-note {{ font-size:11px; color:#888; margin-top:20px; border-top:1px solid #eee;
      padding-top:12px; display:flex; gap:8px; align-items:flex-start; }}
  </style>
</head>
<body>
{TRAINING_BANNER}
<header>
  <span>&#127963; {bank_name}</span>
</header>
<div class="outer">
  <div class="card" id="loginCard">
    <h2>Online Banking Login</h2>
    <p class="subtitle">Secure access to your account</p>
    <form onsubmit="handleSubmit(event)">
      <label>Customer number / Username</label>
      <input type="text" id="user" placeholder="Enter your username" autocomplete="username"/>
      <label>Password</label>
      <input type="password" id="password" placeholder="Enter your password"/>
      <label>Memorable word (characters 2 &amp; 5)</label>
      <input type="text" id="memo" maxlength="2" placeholder="e.g. ab"/>
      <button class="btn" type="submit">Log In Securely</button>
    </form>
    <p class="help">Forgotten your login details?</p>
    <div class="security-note">&#128274; Your connection is secure. All data is protected with 256-bit encryption.</div>
  </div>
</div>
<script>
  function handleSubmit(e) {{
    e.preventDefault();
    document.getElementById('loginCard').innerHTML = `
      <div style="text-align:center;padding:24px 0;">
        <div style="font-size:48px;margin-bottom:16px;">&#9888;</div>
        <h2 style="color:#d29922;font-size:20px;margin-bottom:12px;">You entered credentials on a FAKE banking page!</h2>
        <p style="font-size:14px;color:#444;margin-bottom:16px;">
          In a real attack your username, password, and memorable word would be stolen.<br/>
          <strong>Always verify the URL before entering banking details.</strong>
        </p>
        <p style="font-size:12px;color:#888;">Simulated spoofed domain shown to victim:<br/>
          <code style="color:#f85149;">{spoofed_url}</code></p>
      </div>`;
  }}
</script>
</body>
</html>"""


def _office365_page(spoofed_url: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Sign In - Microsoft 365</title>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ font-family:'Segoe UI',sans-serif; background:#0078d4;
      display:flex; min-height:100vh; align-items:center; justify-content:center; }}
    .card {{ background:#fff; width:440px; padding:44px; border-radius:2px;
      box-shadow:0 4px 24px rgba(0,0,0,0.2); }}
    .logo {{ display:flex; align-items:center; gap:10px; margin-bottom:24px; }}
    .logo-icon {{ display:grid; grid-template-columns:1fr 1fr; gap:2px; width:20px; height:20px; }}
    .logo-icon div {{ border-radius:1px; }}
    h1 {{ font-size:24px; font-weight:600; margin-bottom:4px; color:#1b1b1b; }}
    .org {{ font-size:13px; color:#605e5c; margin-bottom:24px; }}
    input {{ width:100%; border:none; border-bottom:2px solid #605e5c; padding:8px 0;
      font-size:15px; outline:none; margin-bottom:20px; background:transparent; }}
    input:focus {{ border-bottom-color:#0078d4; }}
    .sign-btn {{ background:#0078d4; color:#fff; border:none; width:100%;
      padding:10px; font-size:15px; cursor:pointer; font-family:inherit; letter-spacing:0.02em; }}
    .sign-btn:hover {{ background:#006cbe; }}
    .options {{ font-size:13px; color:#0078d4; margin-top:16px; cursor:pointer; }}
    .cant {{ font-size:13px; color:#0078d4; margin-top:8px; cursor:pointer; display:block; }}
  </style>
</head>
<body>
{TRAINING_BANNER}
<div class="card">
  <div class="logo">
    <div class="logo-icon">
      <div style="background:#F25022"></div><div style="background:#7FBA00"></div>
      <div style="background:#00A4EF"></div><div style="background:#FFB900"></div>
    </div>
    <strong style="font-size:16px;color:#1b1b1b;">Microsoft 365</strong>
  </div>
  <h1 id="title">Sign in</h1>
  <p class="org" id="org">Access your Microsoft 365 account</p>
  <form onsubmit="handleSubmit(event)">
    <input type="email" id="email" placeholder="Email address" autocomplete="username"/>
    <div id="pwdDiv" style="display:none">
      <input type="password" id="password" placeholder="Password" autocomplete="current-password"/>
    </div>
    <button class="sign-btn" type="submit">Next</button>
  </form>
  <div class="options">Sign-in options</div>
  <a class="cant">Can't access your account?</a>
</div>
<script>
  var step=1;
  function handleSubmit(e){{
    e.preventDefault();
    if(step===1){{
      var em=document.getElementById('email').value;
      if(!em)return;
      document.getElementById('title').textContent=em;
      document.getElementById('org').textContent='Microsoft account';
      document.getElementById('pwdDiv').style.display='block';
      step=2;
    }}else{{
      document.querySelector('.card').innerHTML=`
        <div style="text-align:center;padding:24px 0;">
          <div style="font-size:48px;margin-bottom:16px;">&#9888;</div>
          <h2 style="color:#d29922;font-size:20px;margin-bottom:12px;">Credentials captured on a FAKE Microsoft 365 page!</h2>
          <p style="font-size:14px;color:#444;margin-bottom:16px;">
            Real Microsoft 365 sign-in is at <strong>login.microsoftonline.com</strong><br/>
            Always verify the URL bar before entering your credentials.
          </p>
          <p style="font-size:12px;color:#888;">Spoofed domain example:<br/>
            <code style="color:#f85149;">{spoofed_url}</code></p>
        </div>`;
    }}
  }}
</script>
</body>
</html>"""


PAGE_TEMPLATES = [
    {
        "id": "google",
        "name": "Google",
        "description": "Google account sign-in (gmail, workspace)",
        "real_domain": "accounts.google.com",
        "example_spoofed": "accounts.google.com.verify-login.net",
        "accent": "#1a73e8",
    },
    {
        "id": "microsoft",
        "name": "Microsoft",
        "description": "Microsoft account sign-in",
        "real_domain": "login.microsoftonline.com",
        "example_spoofed": "microsoft-signin-secure.com",
        "accent": "#0067b8",
    },
    {
        "id": "office365",
        "name": "Microsoft 365 / Office 365",
        "description": "Microsoft 365 corporate login",
        "real_domain": "login.microsoftonline.com",
        "example_spoofed": "office365-login-portal.com",
        "accent": "#0078d4",
    },
    {
        "id": "barclays",
        "name": "Barclays Bank",
        "description": "Generic bank online banking login",
        "real_domain": "bank.barclays.co.uk",
        "example_spoofed": "barclays-secure-login.com",
        "accent": "#00aeef",
    },
    {
        "id": "hsbc",
        "name": "HSBC Bank",
        "description": "Generic bank online banking login",
        "real_domain": "www.hsbc.co.uk",
        "example_spoofed": "hsbc-online-banking-verify.com",
        "accent": "#db0011",
    },
]


def build_fake_page(page_id: str, spoofed_url: str | None = None) -> str | None:
    """Generate the HTML for a simulated fake login page."""
    meta = next((p for p in PAGE_TEMPLATES if p["id"] == page_id), None)
    if not meta:
        return None
    url = spoofed_url or meta["example_spoofed"]
    if page_id == "google":
        return _google_page(url)
    if page_id == "microsoft":
        return _microsoft_page(url)
    if page_id == "office365":
        return _office365_page(url)
    if page_id == "barclays":
        return _bank_page("Barclays", url, "#00aeef")
    if page_id == "hsbc":
        return _bank_page("HSBC", url, "#db0011")
    return None


def list_page_templates() -> list[dict]:
    return [
        {k: v for k, v in p.items() if k != "accent"}
        for p in PAGE_TEMPLATES
    ]
