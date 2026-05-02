#!/usr/bin/env python3
"""
Emerald Ad Blocker — build pipeline.

Fetches upstream filter lists (EasyList, EasyPrivacy, uBlock, Peter Lowe,
uBlock Annoyances/Privacy/Unbreak, Fanboy Annoyances, AdGuard Tracking),
converts ABP/uBlock syntax to WKContentRuleList JSON, fixes known bugs in
the original hand-curated rules, and writes all output files under output/.

Output
------
  output/adblock.json      — network ad-blocking rules for WKContentRuleList
  output/trackers.json     — tracker/analytics blocking rules
  output/cosmetic.js       — WKUserScript: CSS hiding + anti-adblock stubs
  output/scriptlets.js     — WKUserScript: uBO-style scriptlet engine + configs
"""

import json
import re
import ssl
import sys
import textwrap
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
FILES_DIR = ROOT / "Files"
OUTPUT_DIR = ROOT / "output"

# ---------------------------------------------------------------------------
# Upstream list URLs
# ---------------------------------------------------------------------------
UPSTREAM_LISTS: dict[str, str] = {
    # Core ad / tracker lists
    "easylist":          "https://easylist.to/easylist/easylist.txt",
    "easyprivacy":       "https://easylist.to/easylist/easyprivacy.txt",
    "ublock":            "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "peter_lowe":        (
        "https://pgl.yoyo.org/adservers/serverlist.php"
        "?hostformat=adblockplus&showintro=0&mimetype=plaintext"
    ),
    # Extended coverage
    "ublock_annoyances": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances.txt",
    "ublock_privacy":    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    "ublock_unbreak":    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
    "fanboy_annoyances": "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
    # AdGuard Tracking removed — 190k rules overwhelm the 149k WK cap and overlap
    # heavily with EasyPrivacy. Re-add if the browser splits into two rule lists.
}

# ---------------------------------------------------------------------------
# CDN domains — broad blocks break legitimate sites; remove any rule whose
# url-filter contains these unless it's an explicitly tracking-only subdomain.
# ---------------------------------------------------------------------------
CDN_DOMAINS = [
    "cloudflare.com",
    "fastly.net",
    "gstatic.com",
    "akamaized.net",
]

# For amazonaws.com we only remove *broad* matches; specific tracking buckets
# (adtago, analyticsengine, advice-ads, …) are fine.
TRACKING_S3_PREFIXES = {
    "adtago", "analyticsengine", "analytics", "advice-ads",
    "ad-", "ads-", "tracker", "tracking",
}

# ---------------------------------------------------------------------------
# Non-ad-network domains — video players, community widgets, etc.
# ---------------------------------------------------------------------------
NON_AD_NETWORKS = [
    "vimeo.com",
    "wistia.com",
    "wistia.net",
    "brightcove.com",
    "jwplayer.com",
    "kaltura.com",
    "flowplayer.com",
    "disqus.com",
    "disquscdn.com",
    "aarp.org",
]

# ---------------------------------------------------------------------------
# ABP resource-type → WKContentRuleList resource-type
# ---------------------------------------------------------------------------
RESOURCE_TYPE_MAP: dict[str, str] = {
    "script": "script",
    "image": "image",
    "stylesheet": "style-sheet",
    "object": "media",
    "xmlhttprequest": "fetch",
    "subdocument": "document",
    "ping": "ping",
    "media": "media",
    "font": "font",
    "popup": "popup",
    "document": "document",
    "websocket": "websocket",
    "other": "raw",
}

# Options that make a rule impossible to represent cleanly — skip entirely.
SKIP_OPTIONS = {"redirect", "redirect-rule", "csp", "permissions", "rewrite"}

# WKContentRuleList rule limit per compiled list.
MAX_RULES = 149_000


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _ssl_context() -> ssl.SSLContext:
    """Return an SSL context that trusts certifi's CA bundle (or the default)."""
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        ctx = ssl.create_default_context()
    return ctx


def fetch_list(name: str, url: str) -> str:
    print(f"  Fetching {name} …", end=" ", flush=True)
    req = urllib.request.Request(
        url, headers={"User-Agent": "EmeraldAdBlocker/2.0 build-pipeline"}
    )
    try:
        with urllib.request.urlopen(req, context=_ssl_context(), timeout=45) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        print(f"OK ({len(text):,} bytes, {text.count(chr(10)):,} lines)")
        return text
    except urllib.error.URLError as exc:
        print(f"FAILED — {exc}")
        return ""


# ---------------------------------------------------------------------------
# CDN / non-ad-network detection
# ---------------------------------------------------------------------------

def _escaped(domain: str) -> str:
    return re.escape(domain)


def is_cdn_rule(url_filter: str) -> bool:
    """True when the rule would broadly block a CDN infrastructure domain."""
    # Pure CDN domains — any match is a false-positive risk.
    for cdn in CDN_DOMAINS:
        if _escaped(cdn) in url_filter or cdn.replace(".", "\\.") in url_filter:
            return True

    # amazonaws.com — allow only tracking-specific subdomains.
    if "amazonaws" in url_filter:
        subdomain_part = url_filter.split("amazonaws")[0]
        is_tracking = any(p in subdomain_part for p in TRACKING_S3_PREFIXES)
        if not is_tracking:
            return True

    return False


def is_non_ad_network(url_filter: str) -> bool:
    for domain in NON_AD_NETWORKS:
        if _escaped(domain) in url_filter or domain.replace(".", "\\.") in url_filter:
            return True
    return False


# ---------------------------------------------------------------------------
# Rule deduplication key
# ---------------------------------------------------------------------------

def rule_key(rule: dict) -> str:
    t = rule.get("trigger", {})
    a = rule.get("action", {})
    return json.dumps(
        {
            "uf": t.get("url-filter", ""),
            "rt": sorted(t.get("resource-type", [])),
            "lt": sorted(t.get("load-type", [])),
            "at": a.get("type", ""),
            "sel": a.get("selector", ""),
        },
        sort_keys=True,
    )


# ---------------------------------------------------------------------------
# Fix original hand-curated rules
# ---------------------------------------------------------------------------

def fix_original_rules(rules: list[dict]) -> list[dict]:
    """Remove CDN bugs, non-ad-networks, and duplicates from original rules."""
    seen: set[str] = set()
    fixed: list[dict] = []
    n_cdn = n_non_ad = n_dup = 0

    for rule in rules:
        uf = rule.get("trigger", {}).get("url-filter", "")

        if is_cdn_rule(uf):
            n_cdn += 1
            continue
        if is_non_ad_network(uf):
            n_non_ad += 1
            continue

        key = rule_key(rule)
        if key in seen:
            n_dup += 1
            continue
        seen.add(key)
        fixed.append(rule)

    print(
        f"    removed {n_cdn} CDN rules, {n_non_ad} non-ad-network rules, "
        f"{n_dup} duplicates → {len(fixed)} kept"
    )
    return fixed


# ---------------------------------------------------------------------------
# ABP / uBlock filter → WKContentRuleList rule
# ---------------------------------------------------------------------------

def _domain_to_regex(domain: str) -> str:
    """Escape a domain literal for use in a WK ICU regex url-filter."""
    return re.sub(r"\.", r"\\.", domain)


def abp_to_wk(line: str) -> dict | None:
    """
    Convert one ABP/uBlock filter line to a WKContentRuleList rule dict.
    Returns None for lines that should be skipped.
    """
    line = line.strip()

    # Skip blank lines, comments, directives, cosmetic filters, exceptions.
    if not line:
        return None
    first = line[0]
    if first in ("!", "[", "@", "#", " ", "\t"):
        return None
    if "##" in line or "#@#" in line or "#?#" in line or "#$#" in line:
        return None
    # uBlock scriptlet / extended syntax
    if line.startswith("+js(") or line.startswith("js("):
        return None

    # Split options.
    options_str = ""
    pattern = line
    if "$" in line:
        # Find the last $ that isn't inside a regex literal (//pattern//).
        in_regex = line.startswith("/") and line.count("/") >= 2
        if not in_regex:
            idx = line.rfind("$")
            pattern = line[:idx]
            options_str = line[idx + 1:]

    # Parse options.
    resource_types: list[str] = []
    load_types: list[str] = []

    if options_str:
        for opt in (o.strip() for o in options_str.split(",") if o.strip()):
            negated = opt.startswith("~")
            key_lower = opt.lstrip("~").lower()

            if key_lower in SKIP_OPTIONS:
                return None
            if key_lower.startswith("domain=") or key_lower.startswith("denyallow="):
                return None  # domain-restricted rules are too complex for now
            if key_lower in ("third-party", "3p"):
                if not negated:
                    load_types.append("third-party")
            elif key_lower in ("first-party", "1p"):
                if not negated:
                    load_types.append("first-party")
            elif key_lower in RESOURCE_TYPE_MAP:
                if not negated:
                    wk_type = RESOURCE_TYPE_MAP[key_lower]
                    if wk_type not in resource_types:
                        resource_types.append(wk_type)
            # All other options (important, badfilter, collapse, …) — ignore.

    # Convert the pattern part to an ICU regex url-filter.
    url_filter: str

    if pattern.startswith("||"):
        # Domain anchor: ||domain.com^  or  ||domain.com/path
        rest = pattern[2:].rstrip("^").rstrip("/")
        if not rest:
            return None
        # Strip trailing wildcard
        rest = rest.rstrip("*")
        if not rest:
            return None
        # Handle embedded wildcards (e.g. ||ad*.example.com^)
        parts = re.split(r"\*", rest)
        escaped_parts = [re.sub(r"([.+?{}()\[\]\\^$|])", r"\\\1", p) for p in parts]
        inner = ".*".join(escaped_parts)
        url_filter = f"[a-z][a-z0-9+\\-.]*://([a-z0-9\\-.]+\\.)?{inner}"
    elif pattern.startswith("|") and not pattern.startswith("||"):
        # URL-start anchor: |https://...
        rest = pattern[1:].rstrip("^")
        if not rest:
            return None
        escaped = re.sub(r"([.+?{}()\[\]\\^$|])", r"\\\1", rest)
        escaped = escaped.replace("\\*", ".*").replace("\\^", "[/?&]?")
        url_filter = escaped
    elif pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2:
        # Regex literal: /pattern/
        inner = pattern[1:-1]
        try:
            re.compile(inner)
        except re.error:
            return None
        url_filter = inner
    else:
        # Plain pattern with possible wildcards and anchors.
        p = pattern.rstrip("^")
        if not p or p == "*":
            return None
        escaped = re.sub(r"([.+?{}()\[\]\\^$|])", r"\\\1", p)
        escaped = escaped.replace("\\*", ".*").replace("\\^", "[/?&]?")
        if not escaped or escaped in (".*", ".*.*"):
            return None
        url_filter = f".*{escaped}"

    # Guard against rules that are far too broad.
    if url_filter in (".*", ".*.*", ".*.*.*", ".*[a-z0-9+\\-.]*://"):
        return None

    # Apply CDN / non-ad-network filters to upstream rules too.
    if is_cdn_rule(url_filter) or is_non_ad_network(url_filter):
        return None

    # Validate the regex compiles (Python's re is a reasonable proxy for ICU).
    try:
        re.compile(url_filter, re.IGNORECASE)
    except re.error:
        return None

    trigger: dict[str, Any] = {"url-filter": url_filter}
    if resource_types:
        trigger["resource-type"] = resource_types
    if load_types:
        trigger["load-type"] = load_types

    return {"trigger": trigger, "action": {"type": "block"}}


# ---------------------------------------------------------------------------
# Parse an upstream list
# ---------------------------------------------------------------------------

def parse_upstream(name: str, text: str) -> list[dict]:
    if not text:
        print(f"    {name}: (empty — skipped)")
        return []

    rules: list[dict] = []
    seen: set[str] = set()
    errors = 0

    for line in text.splitlines():
        try:
            rule = abp_to_wk(line)
        except Exception:
            errors += 1
            continue
        if rule is None:
            continue
        key = rule_key(rule)
        if key in seen:
            continue
        seen.add(key)
        rules.append(rule)

    print(f"    {name}: {len(rules):,} rules (parse errors: {errors})")
    return rules


# ---------------------------------------------------------------------------
# Cosmetic filter extraction for cosmetic.js
# ---------------------------------------------------------------------------

def extract_cosmetic_selectors(text: str) -> list[str]:
    """Return generic (domain-agnostic) CSS selectors from EasyList cosmetic filters."""
    selectors: list[str] = []
    seen: set[str] = set()

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("@@"):
            continue
        if "##" not in line:
            continue
        domain_part, _, selector = line.partition("##")
        selector = selector.strip()
        # Generic: no domain prefix, or explicit wildcard.
        if (not domain_part or domain_part == "*") and selector and selector not in seen:
            # Skip extended pseudo-class selectors uBlock/ABP-specific syntax.
            if ":has(" in selector or ":-abp-" in selector or ":xpath(" in selector:
                continue
            seen.add(selector)
            selectors.append(selector)

    # Cap to avoid a JS file that's enormous.
    return selectors[:3_000]


# ---------------------------------------------------------------------------
# Scriptlet extraction for scriptlets.js
# ---------------------------------------------------------------------------

# Scriptlet names we know how to run in the engine.
SUPPORTED_SCRIPTLETS = {
    "set-constant", "trusted-set-constant",
    "abort-on-property-read", "aopr",
    "abort-on-property-write", "aopw",
    "no-fetch-if",
    "no-xhr-if",
    "prevent-setTimeout",
    "prevent-setInterval",
    "remove-attr",
    "remove-class",
}


def extract_scriptlet_configs(texts: dict[str, str]) -> list[tuple[str, list[str]]]:
    """
    Extract generic (wildcard-domain) +js() scriptlet calls from all filter lists.
    Returns a deduplicated list of (scriptlet_name, [arg, ...]) tuples,
    sorted by frequency descending.
    """
    from collections import Counter
    counter: Counter = Counter()

    for text in texts.values():
        for line in text.splitlines():
            line = line.strip()
            # Generic scriptlet: *##+js(...) or ##+js(...)
            if "##+js(" not in line:
                continue
            domain_part, _, rest = line.partition("##+js(")
            # Only generic (no domain, or explicit wildcard)
            domain_part = domain_part.strip()
            if domain_part and domain_part != "*":
                continue
            # Strip closing paren
            rest = rest.rstrip(")")
            parts = [p.strip() for p in rest.split(",", 1)]
            if not parts:
                continue
            name = parts[0]
            if name not in SUPPORTED_SCRIPTLETS:
                continue
            args = [a.strip() for a in parts[1].split(",")] if len(parts) > 1 else []
            counter[(name, tuple(args))] += 1

    # Return top 200 most-common generic configs.
    return [(name, list(args)) for (name, args), _ in counter.most_common(200)]


# ---------------------------------------------------------------------------
# scriptlets.js generator
# ---------------------------------------------------------------------------

SCRIPTLETS_JS_TEMPLATE = r"""// Emerald Ad Blocker — scriptlets.js
// Injected by WKUserScript at document_start.
// Generated by src/build.py — do not edit by hand.
// Implements a subset of uBlock Origin's scriptlet API.
(function () {
  'use strict';

  // ── Utilities ─────────────────────────────────────────────────────────────

  var _noop = function () {};

  /** Walk a dot-separated property chain, calling cb(parent, lastKey) when ready. */
  function onChain(chain, cb) {
    var parts = chain.split('.');
    var last  = parts.pop();
    function resolve(obj, remaining) {
      if (!remaining.length) { try { cb(obj, last); } catch (_) {} return; }
      var key = remaining[0];
      var rest = remaining.slice(1);
      // If already present, descend immediately.
      if (obj[key] !== undefined && obj[key] !== null) {
        resolve(obj[key], rest);
        return;
      }
      // Otherwise poll briefly (max 4 s) for the property to appear.
      var attempts = 0;
      var iv = setInterval(function () {
        if (obj[key] !== undefined && obj[key] !== null) {
          clearInterval(iv);
          resolve(obj[key], rest);
        } else if (++attempts > 40) {
          clearInterval(iv);
        }
      }, 100);
    }
    resolve(window, parts);
  }

  /** Parse a "value" token from a scriptlet arg into a JS primitive. */
  function parseValue(v) {
    if (v === 'true')       return true;
    if (v === 'false')      return false;
    if (v === 'null')       return null;
    if (v === 'undefined')  return undefined;
    if (v === 'noopFunc' || v === 'noop') return _noop;
    if (v === 'trueFunc')   return function () { return true; };
    if (v === 'falseFunc')  return function () { return false; };
    if (v === 'emptyStr' || v === '')  return '';
    if (v === '[]')         return [];
    if (v === '{}')         return {};
    var n = Number(v);
    if (!isNaN(n) && v !== '') return n;
    return v;
  }

  // ── Scriptlet implementations ─────────────────────────────────────────────

  /** set-constant: freeze a property to a fixed value. */
  function setConstant(chain, valueStr) {
    var value = parseValue(valueStr);
    onChain(chain, function (obj, key) {
      try {
        Object.defineProperty(obj, key, {
          get: function () { return value; },
          set: _noop,
          enumerable: true, configurable: false,
        });
      } catch (_) {
        try { obj[key] = value; } catch (_2) {}
      }
    });
  }

  /** abort-on-property-read: throw TypeError when the property is read. */
  function abortOnRead(chain) {
    onChain(chain, function (obj, key) {
      try {
        Object.defineProperty(obj, key, {
          get: function () { throw new TypeError('Blocked by Emerald'); },
          set: _noop,
          enumerable: false, configurable: false,
        });
      } catch (_) {}
    });
  }

  /** abort-on-property-write: throw TypeError when the property is written. */
  function abortOnWrite(chain) {
    onChain(chain, function (obj, key) {
      try {
        Object.defineProperty(obj, key, {
          get: function () { return undefined; },
          set: function () { throw new TypeError('Blocked by Emerald'); },
          enumerable: false, configurable: false,
        });
      } catch (_) {}
    });
  }

  /** no-fetch-if: block fetch() calls whose URL matches pattern. */
  function noFetchIf(pattern) {
    var re = pattern ? new RegExp(pattern) : null;
    var _fetch = window.fetch;
    if (typeof _fetch !== 'function') return;
    window.fetch = function (input) {
      var url = typeof input === 'string' ? input : (input && input.url) || '';
      if (!re || re.test(url)) {
        return Promise.resolve(new Response('', { status: 200 }));
      }
      return _fetch.apply(this, arguments);
    };
  }

  /** no-xhr-if: block XMLHttpRequest calls whose URL matches pattern. */
  function noXhrIf(pattern) {
    var re = pattern ? new RegExp(pattern) : null;
    var _open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      if (!re || re.test(url)) {
        Object.defineProperty(this, '_blocked', { value: true });
      }
      return _open.apply(this, arguments);
    };
    var _send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function () {
      if (this._blocked) return;
      return _send.apply(this, arguments);
    };
  }

  /** prevent-setTimeout: neutralise setTimeout callbacks matching pattern. */
  function preventSetTimeout(pattern, delay) {
    var re = pattern ? new RegExp(pattern) : null;
    var _st = window.setTimeout;
    window.setTimeout = function (fn, d) {
      var src = typeof fn === 'function' ? fn.toString() : String(fn);
      var delayMatch = delay === undefined || delay === '' || String(d) === String(delay);
      if (delayMatch && (!re || re.test(src))) return 0;
      return _st.apply(this, arguments);
    };
  }

  /** prevent-setInterval: neutralise setInterval callbacks matching pattern. */
  function preventSetInterval(pattern, delay) {
    var re = pattern ? new RegExp(pattern) : null;
    var _si = window.setInterval;
    window.setInterval = function (fn, d) {
      var src = typeof fn === 'function' ? fn.toString() : String(fn);
      var delayMatch = delay === undefined || delay === '' || String(d) === String(delay);
      if (delayMatch && (!re || re.test(src))) return 0;
      return _si.apply(this, arguments);
    };
  }

  /** remove-attr: remove an attribute from matching elements (+ MutationObserver). */
  function removeAttr(attr, selector) {
    selector = selector || '*';
    function sweep() {
      try {
        document.querySelectorAll(selector + '[' + attr + ']').forEach(function (el) {
          el.removeAttribute(attr);
        });
      } catch (_) {}
    }
    if (document.readyState !== 'loading') sweep();
    else document.addEventListener('DOMContentLoaded', sweep, { once: true });
    var _obs = new MutationObserver(sweep);
    _obs.observe(document.documentElement, { childList: true, subtree: true, attributes: true });
  }

  /** remove-class: remove a CSS class from matching elements. */
  function removeClass(cls, selector) {
    selector = selector || '.' + cls;
    function sweep() {
      try {
        document.querySelectorAll(selector).forEach(function (el) {
          el.classList.remove(cls);
        });
      } catch (_) {}
    }
    if (document.readyState !== 'loading') sweep();
    else document.addEventListener('DOMContentLoaded', sweep, { once: true });
    var _obs = new MutationObserver(sweep);
    _obs.observe(document.documentElement, { childList: true, subtree: true });
  }

  // ── Dispatch table ────────────────────────────────────────────────────────

  var DISPATCH = {
    'set-constant':          function (a) { setConstant(a[0], a[1]); },
    'trusted-set-constant':  function (a) { setConstant(a[0], a[1]); },
    'abort-on-property-read':  function (a) { abortOnRead(a[0]); },
    'aopr':                    function (a) { abortOnRead(a[0]); },
    'abort-on-property-write': function (a) { abortOnWrite(a[0]); },
    'aopw':                    function (a) { abortOnWrite(a[0]); },
    'no-fetch-if':           function (a) { noFetchIf(a[0]); },
    'no-xhr-if':             function (a) { noXhrIf(a[0]); },
    'prevent-setTimeout':    function (a) { preventSetTimeout(a[0], a[1]); },
    'prevent-setInterval':   function (a) { preventSetInterval(a[0], a[1]); },
    'remove-attr':           function (a) { removeAttr(a[0], a[1]); },
    'remove-class':          function (a) { removeClass(a[0], a[1]); },
  };

  function run(name, args) {
    var fn = DISPATCH[name];
    if (fn) { try { fn(args || []); } catch (_) {} }
  }

  // ── Hardcoded high-value configurations (always applied) ──────────────────

  // Freeze properties anti-adblock scripts check for "ad blocker detected".
  setConstant('adsbygoogle.loaded',         'true');
  setConstant('adsbygoogle.push',           'noopFunc');
  setConstant('canRunAds',                  'true');
  setConstant('blockAdBlock',               'noopFunc');
  setConstant('adsBlocked',                 'false');
  setConstant('ads_not_blocked',            'true');
  setConstant('yahoojp.top.ads',            'true');

  // Block fetch/XHR to known tracker endpoints.
  noFetchIf('googlesyndication\\.com');
  noFetchIf('doubleclick\\.net');
  noFetchIf('google-analytics\\.com/collect');
  noFetchIf('google-analytics\\.com/g/collect');
  noFetchIf('facebook\\.net/en_US/fbevents');
  noFetchIf('hotjar\\.com');
  noFetchIf('fullstory\\.com');

  noXhrIf('googlesyndication\\.com');
  noXhrIf('doubleclick\\.net');
  noXhrIf('google-analytics\\.com/collect');
  noXhrIf('facebook\\.net/en_US/fbevents');

  // Neutralise anti-adblock timer polls.
  preventSetTimeout('checkAdBlock|adBlockDetect|detectAdBlock|adsbygoogle');
  preventSetInterval('checkAdBlock|adBlockDetect|detectAdBlock');

  // ── Extracted generic configs from upstream filter lists ──────────────────
  // (generated by src/build.py — replaceable section below)

  var GENERIC_CONFIGS = INJECTED_CONFIGS;

  for (var _i = 0; _i < GENERIC_CONFIGS.length; _i++) {
    var _cfg = GENERIC_CONFIGS[_i];
    run(_cfg[0], _cfg[1]);
  }

})();
"""


def build_scriptlets_js(configs: list[tuple[str, list[str]]]) -> str:
    config_js = json.dumps(
        [[name, args] for name, args in configs],
        indent=2,
    )
    return SCRIPTLETS_JS_TEMPLATE.replace("INJECTED_CONFIGS", config_js)


# ---------------------------------------------------------------------------
# Deduplication across merged lists
# ---------------------------------------------------------------------------

def dedup(rules: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result: list[dict] = []
    for rule in rules:
        key = rule_key(rule)
        if key not in seen:
            seen.add(key)
            result.append(rule)
    return result


# ---------------------------------------------------------------------------
# cosmetic.js generator
# ---------------------------------------------------------------------------

COSMETIC_JS_TEMPLATE = """\
// Emerald Ad Blocker — cosmetic.js
// Injected by WKUserScript at document_start.
// Generated by src/build.py — do not edit by hand.
// Selectors sourced from EasyList cosmetic filters.
(function () {
  'use strict';

  // ── 1. Anti-adblock stubs ────────────────────────────────────────────────

  // Fool "can we run ads?" checks.
  try {
    Object.defineProperty(window, 'canRunAds', { get: function () { return true; } });
    Object.defineProperty(window, 'canShowAds', { get: function () { return true; } });
  } catch (_) {}

  // adsbygoogle — appear to load but silently no-op push().
  if (!window.adsbygoogle || !Array.isArray(window.adsbygoogle)) {
    try {
      var _abl = [];
      _abl.loaded = true;
      _abl.push = function (o) {
        if (o && typeof o.google_ad_client !== 'undefined') return;
      };
      Object.defineProperty(window, 'adsbygoogle', { get: function () { return _abl; }, configurable: true });
    } catch (_) {}
  }

  // googletag (GPT) — stub every method the ad stack calls.
  var _gtSlot = {
    addService: function () { return _gtSlot; },
    defineSizeMapping: function () { return _gtSlot; },
    setTargeting: function () { return _gtSlot; },
    setCollapseEmptyDiv: function () { return _gtSlot; },
    getSlotElementId: function () { return ''; },
    getAdUnitPath: function () { return ''; },
  };
  var _gtPubads = {
    addEventListener: function () {},
    removeEventListener: function () {},
    setTargeting: function () { return _gtPubads; },
    collapseEmptyDivs: function () {},
    enableSingleRequest: function () {},
    enableLazyLoad: function () {},
    set: function () { return _gtPubads; },
    get: function () { return null; },
    refresh: function () {},
    display: function () {},
    disableInitialLoad: function () {},
    clearTargeting: function () { return _gtPubads; },
    getTargeting: function () { return []; },
    getTargetingKeys: function () { return []; },
  };
  var _googletag = {
    cmd: { push: function (fn) { try { fn(); } catch (_) {} } },
    pubads: function () { return _gtPubads; },
    companionAds: function () { return {}; },
    content: function () { return {}; },
    sizeMapping: function () { return { addSize: function () { return this; }, build: function () { return []; } }; },
    defineSlot: function () { return _gtSlot; },
    defineOutOfPageSlot: function () { return _gtSlot; },
    display: function () {},
    enableServices: function () {},
    destroySlots: function () {},
    getVersion: function () { return ''; },
  };
  try {
    if (!window.googletag || !window.googletag.pubads) {
      window.googletag = _googletag;
    } else {
      window.googletag.cmd = window.googletag.cmd || _googletag.cmd;
    }
  } catch (_) {}

  // ── 2. CSS hiding of known ad containers ─────────────────────────────────

  var SELECTORS = [
    // Hard-coded high-signal selectors (always injected)
    '[id^="google_ads_"]','[id^="div-gpt-ad"]','[id^="dfp-ad-"]',
    '.adsbygoogle','ins.adsbygoogle','.gpt-ad','.dfp-ad',
    '[data-ad-unit]','[data-adunit]','[data-google-query-id]',
    '[id*="taboola"]','[class*="taboola"]',
    '[id*="outbrain"]','[class*="outbrain"]',
    '[id*="revcontent"]','[class*="revcontent"]',
    '[class*="sponsored-content"]','[class*="sponsored_content"]',
    '[id*="sponsored"]','[class*="native-ad"]',
    'div[id^="ad-"]','div[class^="ad-"]',
    'div[id$="-ad"]','div[class$="-ad"]',
    '[data-ad-placeholder]','[data-advertisement]',
    '.ad-banner','.ad-container','.ad-wrapper','.ad-slot',
    '.advertisement','.advertising','.advertise',
    'iframe[src*="doubleclick.net"]','iframe[src*="googlesyndication.com"]',
    'iframe[src*="adnxs.com"]','iframe[src*="pubmatic.com"]',
    // EasyList cosmetic filters (generated)
    EASYLIST_SELECTORS
  ];

  function injectCSS() {
    var style = document.createElement('style');
    style.id = '__emerald_cosmetic__';
    style.textContent = SELECTORS.join(',\\n') + ' { display: none !important; }';
    (document.head || document.documentElement).appendChild(style);
  }

  if (document.head || document.documentElement) {
    injectCSS();
  } else {
    document.addEventListener('DOMContentLoaded', injectCSS, { once: true });
  }

  // ── 3. MutationObserver — catch dynamically injected ad nodes ─────────────

  var _hidden = new WeakSet();

  function hideNode(node) {
    if (_hidden.has(node)) return;
    if (!(node instanceof Element)) return;
    for (var i = 0; i < SELECTORS.length; i++) {
      try {
        if (node.matches(SELECTORS[i])) {
          node.style.setProperty('display', 'none', 'important');
          _hidden.add(node);
          return;
        }
      } catch (_) {}
    }
    // Also scan children if this is a container.
    var descendants = node.querySelectorAll ? node.querySelectorAll(SELECTORS.join(',')) : [];
    for (var j = 0; j < descendants.length; j++) {
      if (!_hidden.has(descendants[j])) {
        descendants[j].style.setProperty('display', 'none', 'important');
        _hidden.add(descendants[j]);
      }
    }
  }

  var observer = new MutationObserver(function (mutations) {
    for (var i = 0; i < mutations.length; i++) {
      var added = mutations[i].addedNodes;
      for (var j = 0; j < added.length; j++) {
        hideNode(added[j]);
      }
    }
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });

})();
"""


def build_cosmetic_js(selectors: list[str]) -> str:
    # Format selectors as a JS array literal (one per line, quoted).
    js_selectors = ",\n    ".join(
        json.dumps(s) for s in selectors
    )
    return COSMETIC_JS_TEMPLATE.replace("    EASYLIST_SELECTORS", f"    {js_selectors}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # ── Load originals ────────────────────────────────────────────────────────
    print("\n=== Loading original hand-curated rules ===")
    with open(FILES_DIR / "adblock.json") as f:
        orig_adblock: list[dict] = json.load(f)
    with open(FILES_DIR / "trackers.json") as f:
        orig_trackers: list[dict] = json.load(f)
    print(f"  adblock.json : {len(orig_adblock):,} rules")
    print(f"  trackers.json: {len(orig_trackers):,} rules")

    # ── Fix originals ─────────────────────────────────────────────────────────
    print("\n=== Fixing original rules ===")
    print("  adblock.json →")
    fixed_adblock = fix_original_rules(orig_adblock)
    print("  trackers.json →")
    fixed_trackers = fix_original_rules(orig_trackers)

    # ── Fetch upstream ────────────────────────────────────────────────────────
    print("\n=== Fetching upstream filter lists ===")
    raw: dict[str, str] = {}
    for name, url in UPSTREAM_LISTS.items():
        raw[name] = fetch_list(name, url)

    # ── Parse upstream ────────────────────────────────────────────────────────
    print("\n=== Parsing upstream lists ===")
    easylist_rules       = parse_upstream("easylist",          raw.get("easylist", ""))
    easyprivacy_rules    = parse_upstream("easyprivacy",        raw.get("easyprivacy", ""))
    ublock_rules         = parse_upstream("ublock",             raw.get("ublock", ""))
    peter_lowe_rules     = parse_upstream("peter_lowe",         raw.get("peter_lowe", ""))
    ublock_annoy_rules   = parse_upstream("ublock_annoyances",  raw.get("ublock_annoyances", ""))
    ublock_priv_rules    = parse_upstream("ublock_privacy",     raw.get("ublock_privacy", ""))
    ublock_unbreak_rules = parse_upstream("ublock_unbreak",     raw.get("ublock_unbreak", ""))
    fanboy_rules         = parse_upstream("fanboy_annoyances",  raw.get("fanboy_annoyances", ""))

    # ── Merge & deduplicate ───────────────────────────────────────────────────
    print("\n=== Merging and deduplicating ===")

    # adblock.json: curated → EasyList → uBlock → Annoyances → Fanboy
    adblock_merged = dedup(
        fixed_adblock
        + easylist_rules
        + ublock_rules
        + ublock_annoy_rules
        + fanboy_rules
        + ublock_unbreak_rules
    )
    # trackers.json: curated → EasyPrivacy → Peter Lowe → uBlock Privacy
    trackers_merged = dedup(
        fixed_trackers
        + easyprivacy_rules
        + peter_lowe_rules
        + ublock_priv_rules
    )

    if len(adblock_merged) > MAX_RULES:
        print(f"  WARNING: adblock ({len(adblock_merged):,}) exceeds WK limit → truncating")
        adblock_merged = adblock_merged[:MAX_RULES]
    if len(trackers_merged) > MAX_RULES:
        print(f"  WARNING: trackers ({len(trackers_merged):,}) exceeds WK limit → truncating")
        trackers_merged = trackers_merged[:MAX_RULES]

    print(f"  Final adblock.json : {len(adblock_merged):,} rules")
    print(f"  Final trackers.json: {len(trackers_merged):,} rules")

    # ── Write JSON outputs ────────────────────────────────────────────────────
    print("\n=== Writing output files ===")
    adblock_out = OUTPUT_DIR / "adblock.json"
    trackers_out = OUTPUT_DIR / "trackers.json"

    with open(adblock_out, "w") as f:
        json.dump(adblock_merged, f, indent=2)
    print(f"  Wrote {adblock_out.relative_to(ROOT)}")

    with open(trackers_out, "w") as f:
        json.dump(trackers_merged, f, indent=2)
    print(f"  Wrote {trackers_out.relative_to(ROOT)}")

    # ── Build cosmetic.js ─────────────────────────────────────────────────────
    easylist_text = raw.get("easylist", "")
    cosmetic_selectors = extract_cosmetic_selectors(easylist_text)
    print(f"  Extracted {len(cosmetic_selectors):,} EasyList cosmetic selectors")

    cosmetic_js = build_cosmetic_js(cosmetic_selectors)
    cosmetic_out = OUTPUT_DIR / "cosmetic.js"
    with open(cosmetic_out, "w") as f:
        f.write(cosmetic_js)
    print(f"  Wrote {cosmetic_out.relative_to(ROOT)}")

    # ── Build scriptlets.js ───────────────────────────────────────────────────
    scriptlet_configs = extract_scriptlet_configs(raw)
    print(f"  Extracted {len(scriptlet_configs):,} generic scriptlet configs")

    scriptlets_js = build_scriptlets_js(scriptlet_configs)
    scriptlets_out = OUTPUT_DIR / "scriptlets.js"
    with open(scriptlets_out, "w") as f:
        f.write(scriptlets_js)
    print(f"  Wrote {scriptlets_out.relative_to(ROOT)}")

    print("\n=== Done ✓ ===\n")


if __name__ == "__main__":
    main()
