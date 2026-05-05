#!/usr/bin/env python3
"""
Emerald Ad Blocker — build pipeline (v3).

Changes from v2:
  - Exception rules (@@) → ignore-previous-rules with if-domain
  - domain= option → if-domain / unless-domain in triggers
  - Expanded scriptlet engine: 25+ scriptlets (up from 12)
  - Site-specific scriptlet extraction → output/scriptlet_rules.json
  - WebSocket/WebRTC blocking → output/websocket_block.js
  - Improved MutationObserver performance in cosmetic.js
  - :has-text() procedural cosmetic filter support

Output
------
  output/adblock.json          — network ad-blocking rules (WKContentRuleList)
  output/trackers.json         — tracker/analytics blocking rules
  output/exceptions.json       — exception rules (WKContentRuleList ignore-previous-rules)
  output/cosmetic.js           — WKUserScript: CSS hiding + anti-adblock stubs
  output/scriptlets.js         — WKUserScript: uBO-style scriptlet engine + configs
  output/scriptlet_rules.json  — per-domain scriptlet configs for browser-side injection
  output/websocket_block.js    — WKUserScript: WebSocket/WebRTC interception
"""

import json
import re
import ssl
import sys
import textwrap
import hashlib
import urllib.request
import urllib.error
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
FILES_DIR = ROOT / "Files"
OUTPUT_DIR = ROOT / "output"
CACHE_DIR = ROOT / ".cache"

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
}

# ---------------------------------------------------------------------------
# CDN / false-positive protection
# ---------------------------------------------------------------------------
CDN_DOMAINS = ["cloudflare.com", "fastly.net", "gstatic.com", "akamaized.net"]

TRACKING_S3_PREFIXES = {
    "adtago", "analyticsengine", "analytics", "advice-ads",
    "ad-", "ads-", "tracker", "tracking",
}

NON_AD_NETWORKS = [
    "vimeo.com", "wistia.com", "wistia.net", "brightcove.com",
    "jwplayer.com", "kaltura.com", "flowplayer.com",
    "disqus.com", "disquscdn.com", "aarp.org",
]

# ---------------------------------------------------------------------------
# ABP resource-type → WKContentRuleList resource-type
# ---------------------------------------------------------------------------
RESOURCE_TYPE_MAP: dict[str, str] = {
    "script": "script", "image": "image", "stylesheet": "style-sheet",
    "object": "media", "xmlhttprequest": "fetch", "subdocument": "document",
    "ping": "ping", "media": "media", "font": "font", "popup": "popup",
    "document": "document", "websocket": "websocket", "other": "raw",
}

# Options handled via sidecar files instead of WKContentRuleList
SIDECAR_OPTIONS = {"redirect", "redirect-rule", "removeparam"}

# Options that are truly impossible in WebKit — skip entirely
SKIP_OPTIONS = {"csp", "permissions", "rewrite"}

MAX_RULES = 149_000


# ---------------------------------------------------------------------------
# Network helpers with hash-based caching
# ---------------------------------------------------------------------------

def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _cache_path(name: str) -> Path:
    return CACHE_DIR / f"{name}.txt"


def _hash_path(name: str) -> Path:
    return CACHE_DIR / f"{name}.sha256"


def fetch_list(name: str, url: str) -> str:
    """Fetch an upstream list, using a local cache when content is unchanged."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = _cache_path(name)
    hash_file = _hash_path(name)

    print(f"  Fetching {name} …", end=" ", flush=True)
    req = urllib.request.Request(
        url, headers={"User-Agent": "EmeraldAdBlocker/3.0 build-pipeline"}
    )
    try:
        with urllib.request.urlopen(req, context=_ssl_context(), timeout=45) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        # Network failed — fall back to cache if available
        if cache.exists():
            text = cache.read_text(encoding="utf-8")
            print(f"FAILED ({exc}) — using cached ({len(text):,} bytes)")
            return text
        print(f"FAILED — {exc}")
        return ""

    new_hash = hashlib.sha256(text.encode()).hexdigest()
    old_hash = hash_file.read_text().strip() if hash_file.exists() else ""

    if new_hash == old_hash:
        print(f"OK (unchanged, {len(text):,} bytes)")
    else:
        cache.write_text(text, encoding="utf-8")
        hash_file.write_text(new_hash)
        print(f"OK (updated, {len(text):,} bytes, {text.count(chr(10)):,} lines)")

    return text


# ---------------------------------------------------------------------------
# CDN / non-ad-network detection
# ---------------------------------------------------------------------------

def is_cdn_rule(url_filter: str) -> bool:
    for cdn in CDN_DOMAINS:
        escaped = cdn.replace(".", "\\.")
        if escaped in url_filter or cdn.replace(".", "\\.") in url_filter:
            return True
    if "amazonaws" in url_filter:
        subdomain_part = url_filter.split("amazonaws")[0]
        if not any(p in subdomain_part for p in TRACKING_S3_PREFIXES):
            return True
    return False


def is_non_ad_network(url_filter: str) -> bool:
    for domain in NON_AD_NETWORKS:
        escaped = domain.replace(".", "\\.")
        if escaped in url_filter:
            return True
    return False


# ---------------------------------------------------------------------------
# Rule deduplication
# ---------------------------------------------------------------------------

def rule_key(rule: dict) -> str:
    t = rule.get("trigger", {})
    a = rule.get("action", {})
    return json.dumps({
        "uf": t.get("url-filter", ""),
        "rt": sorted(t.get("resource-type", [])),
        "lt": sorted(t.get("load-type", [])),
        "id": sorted(t.get("if-domain", [])),
        "ud": sorted(t.get("unless-domain", [])),
        "at": a.get("type", ""),
    }, sort_keys=True)


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
# Upstream filter lists occasionally include rules that block an entire site
# root rather than a specific ad/tracker endpoint. We maintain an exact-match
# set of the known-bad url-filter values and drop them at build time.
# ---------------------------------------------------------------------------
_BLANKET_DOMAIN_BLOCK_FILTERS: frozenset[str] = frozenset({
    r"^[a-z]+://([a-z0-9.-]+\.)?reddit\.com",
    r"^[a-z]+://([a-z0-9.-]+\.)?open\.spotify\.com",
    r"^[a-z]+://([a-z0-9.-]+\.)?redd\.it",
    r"^[a-z]+://([a-z0-9.-]+\.)?facebook\.com",
    r"^[a-z]+://([a-z0-9.-]+\.)?instagram\.com",
})


def drop_main_domain_blocks(rules: list[dict]) -> list[dict]:
    """Remove block rules that would block an entire safe domain root."""
    result: list[dict] = []
    dropped = 0
    for rule in rules:
        if rule.get("action", {}).get("type") != "block":
            result.append(rule)
            continue
        if rule.get("trigger", {}).get("url-filter", "") in _BLANKET_DOMAIN_BLOCK_FILTERS:
            dropped += 1
            continue
        result.append(rule)
    if dropped:
        print(f"    drop_main_domain_blocks: removed {dropped} blanket domain block(s)")
    return result


_EXCLUSIVE_CONDITIONS = ("if-domain", "unless-domain", "if-top-url", "unless-top-url")


def sanitize_rules(rules: list[dict]) -> list[dict]:
    """
    Enforce WebKit's constraint: a trigger may have at most one of
    if-domain, unless-domain, if-top-url, unless-top-url.
    When a rule has multiple, keep if-domain (most specific) and drop the rest.
    """
    result: list[dict] = []
    n_fixed = 0
    for rule in rules:
        t = rule.get("trigger", {})
        present = [k for k in _EXCLUSIVE_CONDITIONS if k in t]
        if len(present) <= 1:
            result.append(rule)
            continue
        # More than one condition — fix by keeping if-domain preferentially
        fixed_trigger = dict(t)
        if "if-domain" in fixed_trigger or "if-top-url" in fixed_trigger:
            fixed_trigger.pop("unless-domain", None)
            fixed_trigger.pop("unless-top-url", None)
        else:
            # Only unless-* present (shouldn't happen, but just drop all but first)
            for k in present[1:]:
                fixed_trigger.pop(k, None)
        result.append({"trigger": fixed_trigger, "action": rule["action"]})
        n_fixed += 1
    if n_fixed:
        print(f"    sanitize_rules: fixed {n_fixed} multi-condition trigger(s)")
    return result


# ---------------------------------------------------------------------------
# Fix original hand-curated rules
# ---------------------------------------------------------------------------

def fix_original_rules(rules: list[dict]) -> list[dict]:
    seen: set[str] = set()
    fixed: list[dict] = []
    n_cdn = n_non_ad = n_dup = n_wk = 0
    for rule in rules:
        uf = rule.get("trigger", {}).get("url-filter", "")
        # Apply WebKit fixes to hand-curated rules
        uf = expand_shorthand_character_classes(uf)
        rule["trigger"]["url-filter"] = uf
        if is_cdn_rule(uf):
            n_cdn += 1
            continue
        if is_non_ad_network(uf):
            n_non_ad += 1
            continue
        if not is_webkit_compatible(uf):
            n_wk += 1
            continue
        key = rule_key(rule)
        if key in seen:
            n_dup += 1
            continue
        seen.add(key)
        fixed.append(rule)
    print(f"    removed {n_cdn} CDN, {n_non_ad} non-ad, {n_wk} WK-incompat, {n_dup} dupes → {len(fixed)} kept")
    return fixed


# ---------------------------------------------------------------------------
# WebKit regex compatibility — adopted from Bieletees' tested fixes.
# WebKit's content-blocking engine uses a restricted subset of ICU regex.
# ---------------------------------------------------------------------------

def expand_shorthand_character_classes(regex: str) -> str:
    """Expand \\w, \\d, \\s into their literal character class equivalents."""
    regex = re.sub(r"(?<!\\)\\w", "[a-zA-Z0-9_]", regex)
    regex = re.sub(r"(?<!\\)\\d", "[0-9]", regex)
    regex = re.sub(r"(?<!\\)\\s", "[ \\t\\r\\n\\v\\f]", regex)
    return regex


def is_webkit_compatible(regex: str) -> bool:
    """
    Check if a regex string is compatible with WebKit's content-blocking engine.
    WebKit uses ICU regexes but disables many features.
    """
    # 1. Basic Python compile check.
    try:
        re.compile(regex, re.IGNORECASE)
    except re.error:
        return False

    # 2. Unsupported features (non-capturing groups, lookarounds, etc.)
    if "(?" in regex:
        return False

    # 3. $ in middle of regex (only valid as end-anchor)
    if "$" in regex:
        for m in re.finditer(r"\$", regex):
            if m.end() < len(regex):
                next_char = regex[m.end()]
                if next_char not in ("|", ")"):
                    return False

    # 4. Shorthand character classes that weren't expanded
    if re.search(r"\\[wdsWDS]", regex):
        return False

    # 5. Bounded repetitions {n,m} — WebKit only supports *, +, ?
    if "{" in regex:
        return False

    # 6. Disjunctions/alternation (a|b) — not supported by WebKit's engine
    if "|" in regex:
        return False

    # 7. Backreferences (\\1, \\2, ...)
    if re.search(r"\\\d", regex):
        return False

    # 8. Excessive length
    if len(regex) > 512:
        return False

    # 9. Nested character classes
    if "[[" in regex or "]]" in regex:
        return False

    return True


# ---------------------------------------------------------------------------
# ABP / uBlock filter → WKContentRuleList rule
# ---------------------------------------------------------------------------

def _escape_for_icu(text: str) -> str:
    """Escape a literal string for use in an ICU regex url-filter."""
    return re.sub(r"([.+?{}()\[\]\\^$|])", r"\\\1", text)


def _pattern_to_url_filter(pattern: str) -> str | None:
    """Convert ABP pattern to WK ICU regex url-filter. Returns None if invalid."""
    if pattern.startswith("||"):
        # Domain anchor: ||domain.com^ → match domain in any protocol
        rest = pattern[2:].rstrip("^").rstrip("/").rstrip("*")
        if not rest:
            return None
        parts = re.split(r"\*", rest)
        escaped_parts = [_escape_for_icu(p) for p in parts]
        inner = ".*".join(escaped_parts)
        # Use simple, ICU-safe character classes (no backslash escapes inside [])
        url_filter = f"^[a-z]+://([a-z0-9.-]+\\.)?{inner}"
    elif pattern.startswith("|") and not pattern.startswith("||"):
        # URL-start anchor: |https://...
        rest = pattern[1:].rstrip("^")
        if not rest:
            return None
        escaped = _escape_for_icu(rest)
        escaped = escaped.replace("\\*", ".*").replace("\\^", "[/?&]?")
        url_filter = escaped
    elif pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2:
        # Regex literal: /pattern/
        url_filter = pattern[1:-1]
    else:
        # Plain pattern with possible wildcards
        p = pattern.rstrip("^")
        if not p or p == "*":
            return None
        escaped = _escape_for_icu(p)
        escaped = escaped.replace("\\*", ".*").replace("\\^", "[/?&]?")
        if not escaped or escaped in (".*", ".*.*"):
            return None
        url_filter = f".*{escaped}"

    # Expand shorthand classes and validate against WebKit constraints
    url_filter = expand_shorthand_character_classes(url_filter)
    if not is_webkit_compatible(url_filter):
        return None

    return url_filter


def abp_to_wk(line: str, is_exception: bool = False) -> dict | None:
    """
    Convert one ABP/uBlock filter line to a WKContentRuleList rule dict.
    If is_exception=True, the action is ignore-previous-rules instead of block.
    """
    line = line.strip()
    if not line:
        return None

    first = line[0]
    if first in ("!", "[", "#", " ", "\t"):
        return None
    if "##" in line or "#@#" in line or "#?#" in line or "#$#" in line:
        return None
    if line.startswith("+js(") or line.startswith("js("):
        return None

    # Handle exception rules
    if line.startswith("@@"):
        return abp_to_wk(line[2:], is_exception=True)

    # Skip exceptions in non-exception parsing mode (they're handled separately)
    if not is_exception and line.startswith("@"):
        return None

    # Split options — use Bieletees' smarter detection to avoid false splits
    # on patterns where $ is part of the literal match, not an option separator
    options_str = ""
    pattern = line
    if "$" in line:
        idx = line.rfind("$")
        if idx > 0:
            potential_options = line[idx + 1:].split(",")
            known_opts = (
                list(RESOURCE_TYPE_MAP.keys()) + list(SKIP_OPTIONS)
                + list(SIDECAR_OPTIONS)
                + ["domain", "denyallow", "third-party", "first-party",
                   "3p", "1p", "important", "badfilter", "match-case",
                   "removeparam", "redirect", "redirect-rule"]
            )
            if any(opt.lstrip("~").split("=")[0].lower() in known_opts
                   for opt in potential_options):
                pattern = line[:idx]
                options_str = line[idx + 1:]

    # Parse options
    resource_types: list[str] = []
    load_types: list[str] = []
    if_domains: list[str] = []
    unless_domains: list[str] = []

    if options_str:
        for opt in (o.strip() for o in options_str.split(",") if o.strip()):
            negated = opt.startswith("~")
            key_lower = opt.lstrip("~").lower()

            if key_lower in SKIP_OPTIONS:
                return None
            if key_lower.startswith("denyallow="):
                return None

            # $redirect and $removeparam: still generate the block rule for
            # network blocking; the sidecar extractors handle the rest separately.
            if key_lower.startswith("redirect=") or key_lower.startswith("redirect-rule="):
                continue  # skip this option but don't skip the whole rule
            if key_lower.startswith("removeparam=") or key_lower == "removeparam":
                continue

            # NEW: domain= support → if-domain / unless-domain
            if key_lower.startswith("domain="):
                domain_value = opt.split("=", 1)[1]
                for d in domain_value.split("|"):
                    d = d.strip()
                    if not d:
                        continue
                    if d.startswith("~"):
                        unless_domains.append("*" + d[1:])
                    else:
                        if_domains.append("*" + d)
                continue

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

    # Convert pattern to url-filter
    url_filter = _pattern_to_url_filter(pattern)
    if url_filter is None:
        return None

    # Guard against overly broad rules
    if url_filter in (".*", ".*.*", ".*.*.*", ".*[a-z0-9+\\\\-.]*://"):
        return None

    # CDN / non-ad-network safety (skip for exception rules — they're allowlists)
    if not is_exception:
        if is_cdn_rule(url_filter) or is_non_ad_network(url_filter):
            return None

    # url_filter was already validated by _pattern_to_url_filter → _is_icu_safe

    trigger: dict[str, Any] = {"url-filter": url_filter}
    if resource_types:
        trigger["resource-type"] = resource_types
    if load_types:
        trigger["load-type"] = load_types
    # WebKit: a trigger cannot have more than one of if-domain, unless-domain,
    # if-top-url, unless-top-url. When domain= mixes positive and negated entries
    # we'd get both if-domain + unless-domain, which causes a compile error.
    # Prefer if-domain (more specific scope) and discard unless-domain.
    if if_domains and unless_domains:
        unless_domains = []

    if if_domains:
        trigger["if-domain"] = if_domains
    if unless_domains:
        trigger["unless-domain"] = unless_domains

    action_type = "ignore-previous-rules" if is_exception else "block"
    return {"trigger": trigger, "action": {"type": action_type}}


# ---------------------------------------------------------------------------
# Parse upstream lists (block rules + exception rules separately)
# ---------------------------------------------------------------------------

def parse_upstream(name: str, text: str) -> tuple[list[dict], list[dict]]:
    """Returns (block_rules, exception_rules)."""
    if not text:
        print(f"    {name}: (empty — skipped)")
        return [], []

    blocks: list[dict] = []
    exceptions: list[dict] = []
    seen_b: set[str] = set()
    seen_e: set[str] = set()
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
        if rule["action"]["type"] == "ignore-previous-rules":
            if key not in seen_e:
                seen_e.add(key)
                exceptions.append(rule)
        else:
            if key not in seen_b:
                seen_b.add(key)
                blocks.append(rule)

    print(f"    {name}: {len(blocks):,} block + {len(exceptions):,} exception (errors: {errors})")
    return blocks, exceptions


# ---------------------------------------------------------------------------
# Cosmetic filter extraction
# ---------------------------------------------------------------------------

def extract_cosmetic_selectors(texts: dict[str, str]) -> list[str]:
    """Generic CSS selectors from EasyList + uBlock cosmetic filters."""
    selectors: list[str] = []
    seen: set[str] = set()

    for text in texts.values():
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("!") or line.startswith("@@"):
                continue
            if "##" not in line:
                continue
            domain_part, _, selector = line.partition("##")
            selector = selector.strip()
            if (not domain_part or domain_part == "*") and selector and selector not in seen:
                # Allow native :has() (WebKit supports it), skip other extended syntax
                if ":-abp-" in selector or ":xpath(" in selector:
                    continue
                if ":has-text(" in selector or ":matches-css(" in selector:
                    continue  # handled separately as procedural filters
                seen.add(selector)
                selectors.append(selector)

    return selectors[:3_000]  # keep high-signal selectors, lighter output


def cosmetic_to_native_rules(selectors: list[str]) -> list[dict]:
    """
    Convert generic CSS selectors to native WKContentRuleList css-display-none
    rules. These are applied before paint — zero flicker, zero JS overhead.

    Excludes Google/YouTube domains to prevent breaking video players and
    other Google services. Network-level ad blocking still applies on those
    domains — only cosmetic element hiding is skipped.
    """
    # Domains where cosmetic hiding causes breakage (video players, etc.)
    # Network blocking rules for ad domains (doubleclick, googlesyndication)
    # still apply — this only skips CSS element hiding.
    COSMETIC_EXCLUDE_DOMAINS = [
        # Google / YouTube — video players and Google services
        "*youtube.com", "*youtu.be", "*googlevideo.com", "*ytimg.com",
        "*google.com", "*googleapis.com", "*gstatic.com",
        "*googleusercontent.com",
        # GitHub — complex layout; EasyList selectors can accidentally hide
        # Primer CSS components and break page width/structure.
        "*github.com", "*githubusercontent.com",
        # Spotify — streaming player; cosmetic hiding is not needed and
        # can interfere with player initialisation.
        "*spotify.com", "*scdn.co",
    ]

    rules: list[dict] = []
    for sel in selectors:
        # WKContentRuleList css-display-none only supports simple selectors
        if "," in sel or "::" in sel or "iframe[src" in sel:
            continue
        rules.append({
            "trigger": {
                "url-filter": ".*",
                "unless-domain": COSMETIC_EXCLUDE_DOMAINS,
            },
            "action": {"type": "css-display-none", "selector": sel}
        })
    return rules


def extract_domain_cosmetic_selectors(texts: dict[str, str]) -> dict[str, list[str]]:
    """
    Extract domain-specific cosmetic selectors → {domain: [selector, ...]}.
    The browser injects only matching selectors per domain via WKUserScript.
    """
    domain_selectors: dict[str, list[str]] = defaultdict(list)
    seen: dict[str, set[str]] = defaultdict(set)

    for text in texts.values():
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("!") or line.startswith("@@"):
                continue
            if "##" not in line:
                continue
            domain_part, _, selector = line.partition("##")
            selector = selector.strip()
            if not selector:
                continue
            # Skip generic (handled by native rules) and extended syntax
            if not domain_part or domain_part == "*":
                continue
            if ":-abp-" in selector or ":xpath(" in selector:
                continue
            if ":has-text(" in selector or ":matches-css(" in selector:
                continue
            # Handle comma-separated domains
            for domain in domain_part.split(","):
                domain = domain.strip().lstrip("~")
                if not domain or domain.startswith("~"):
                    continue
                if selector not in seen[domain]:
                    seen[domain].add(selector)
                    domain_selectors[domain].append(selector)

    # Cap per-domain to avoid huge entries
    return {d: sels[:200] for d, sels in domain_selectors.items()}


def extract_has_text_filters(texts: dict[str, str]) -> list[dict]:
    """Extract :has-text() procedural cosmetic filters for JS-based hiding."""
    filters: list[dict] = []
    seen: set[str] = set()

    for text in texts.values():
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("!") or line.startswith("@@"):
                continue
            if "##" not in line or ":has-text(" not in line:
                continue
            domain_part, _, selector = line.partition("##")
            if domain_part and domain_part != "*":
                continue  # skip domain-specific for now
            # Parse :has-text(pattern)
            match = re.match(r"(.+?):has-text\((.+?)\)$", selector)
            if not match:
                continue
            css_sel = match.group(1).strip()
            text_pattern = match.group(2).strip().strip("/")
            key = f"{css_sel}|{text_pattern}"
            if key in seen:
                continue
            seen.add(key)
            filters.append({"selector": css_sel, "text": text_pattern})

    return filters[:500]


# ---------------------------------------------------------------------------
# Scriptlet extraction
# ---------------------------------------------------------------------------

SUPPORTED_SCRIPTLETS = {
    # Original 12
    "set-constant", "trusted-set-constant",
    "abort-on-property-read", "aopr",
    "abort-on-property-write", "aopw",
    "no-fetch-if", "no-xhr-if",
    "prevent-setTimeout", "prevent-setInterval",
    "remove-attr", "remove-class",
    # NEW: 15 more scriptlets
    "prevent-addEventListener", "addEventListener-defuser",
    "prevent-window-open",
    "noeval", "noeval-if",
    "set-attr",
    "set-cookie",
    "remove-node-text",
    "json-prune",
    "no-setInterval-if", "no-setTimeout-if",
    "adjust-setInterval", "adjust-setTimeout",
    "disable-newtab-links",
    "window-close-if",
    "prevent-refresh",
    "abort-current-inline-script", "acis",
}


def extract_scriptlet_configs(texts: dict[str, str]) -> list[tuple[str, list[str]]]:
    """Generic (wildcard-domain) +js() scriptlet configs."""
    counter: Counter = Counter()
    for text in texts.values():
        for line in text.splitlines():
            line = line.strip()
            if "##+js(" not in line:
                continue
            domain_part, _, rest = line.partition("##+js(")
            domain_part = domain_part.strip()
            if domain_part and domain_part != "*":
                continue
            rest = rest.rstrip(")")
            parts = [p.strip() for p in rest.split(",", 1)]
            if not parts:
                continue
            name = parts[0]
            if name not in SUPPORTED_SCRIPTLETS:
                continue
            args = [a.strip() for a in parts[1].split(",")] if len(parts) > 1 else []
            counter[(name, tuple(args))] += 1
    return [(name, list(args)) for (name, args), _ in counter.most_common(300)]


def extract_site_scriptlet_configs(texts: dict[str, str]) -> dict[str, list[list[str]]]:
    """Domain-specific +js() scriptlet configs → {hostname: [[name, arg, ...], ...]}."""
    rules: dict[str, list[list[str]]] = defaultdict(list)
    for text in texts.values():
        for line in text.splitlines():
            line = line.strip()
            if "##+js(" not in line:
                continue
            domain_part, _, rest = line.partition("##+js(")
            domain_part = domain_part.strip()
            if not domain_part or domain_part == "*":
                continue
            rest = rest.rstrip(")")
            parts = [p.strip() for p in rest.split(",", 1)]
            if not parts:
                continue
            name = parts[0]
            if name not in SUPPORTED_SCRIPTLETS:
                continue
            args = [a.strip() for a in parts[1].split(",")] if len(parts) > 1 else []
            for domain in domain_part.split(","):
                domain = domain.strip().lstrip("*.")
                if domain:
                    rules[domain].append([name] + args)
    return dict(rules)


# ---------------------------------------------------------------------------
# $redirect extraction → redirect_rules.json
# Maps url patterns to redirect resource names for browser-side
# WKURLSchemeHandler implementation.
# ---------------------------------------------------------------------------

# uBO redirect resource names we can stub
KNOWN_REDIRECT_RESOURCES = {
    # Script stubs
    "noopjs", "noop.js",
    "google-analytics_analytics.js", "google-analytics.com/analytics.js",
    "googletagmanager_gtm.js", "googletagmanager.com/gtm.js",
    "googlesyndication_adsbygoogle.js", "googlesyndication.com/adsbygoogle.js",
    "googletagservices_gpt.js", "googletagservices.com/gpt.js",
    "google-analytics_ga.js", "google-analytics.com/ga.js",
    "google-analytics_cx_api.js",
    "scorecardresearch_beacon.js",
    "outbrain-widget.js",
    "amazon_ads.js", "amazon-adsystem.com/aax2/apstag.js",
    "doubleclick_instream_ad_status.js",
    "fingerprint2.js", "fingerprint3.js",
    "prebid-ads.js",
    # Image/pixel stubs
    "1x1.gif", "2x2.png", "3x2.png", "32x32.png",
    "noopimage", "noop-1s.mp4", "noopvast-2.0", "noopvast-3.0", "noopvast-4.0",
    "noopmp3-0.1s", "noopmp4-1s",
    # Frame stubs
    "noopframe", "noop.html",
    # Text stubs
    "nooptext", "noop.txt",
    "empty",
}


def extract_redirect_rules(texts: dict[str, str]) -> list[dict]:
    """
    Extract $redirect and $redirect-rule filters.
    Returns list of {pattern, resource, domains?} for browser-side handling.
    """
    rules: list[dict] = []
    seen: set[str] = set()

    for text in texts.values():
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("!") or line.startswith("["):
                continue
            if line.startswith("@@"):
                continue
            if "$" not in line:
                continue

            idx = line.rfind("$")
            pattern = line[:idx]
            options_str = line[idx + 1:]

            redirect_resource = None
            domains: list[str] = []

            for opt in options_str.split(","):
                opt = opt.strip()
                if opt.startswith("redirect=") or opt.startswith("redirect-rule="):
                    redirect_resource = opt.split("=", 1)[1].strip()
                elif opt.startswith("domain="):
                    domains = [d.strip() for d in opt.split("=", 1)[1].split("|") if d.strip()]

            if not redirect_resource:
                continue
            if redirect_resource not in KNOWN_REDIRECT_RESOURCES:
                continue

            key = f"{pattern}|{redirect_resource}"
            if key in seen:
                continue
            seen.add(key)

            entry: dict[str, Any] = {
                "pattern": pattern,
                "resource": redirect_resource,
            }
            if domains:
                entry["domains"] = domains
            rules.append(entry)

    return rules[:2000]


# ---------------------------------------------------------------------------
# $removeparam extraction → removeparam_rules.json
# ---------------------------------------------------------------------------

def extract_removeparam_rules(texts: dict[str, str]) -> list[dict]:
    """
    Extract $removeparam filters.
    Returns list of {param, pattern?, domains?} for browser-side URL stripping.
    """
    rules: list[dict] = []
    seen: set[str] = set()

    for text in texts.values():
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("!") or line.startswith("["):
                continue

            is_exception = line.startswith("@@")
            if is_exception:
                line = line[2:]

            if "$" not in line or "removeparam" not in line:
                continue

            idx = line.rfind("$")
            pattern = line[:idx] if idx > 0 else ""
            options_str = line[idx + 1:]

            param_name = None
            domains: list[str] = []

            for opt in options_str.split(","):
                opt = opt.strip()
                if opt.startswith("removeparam="):
                    param_name = opt.split("=", 1)[1].strip()
                elif opt == "removeparam":
                    continue  # bare removeparam without value — skip
                elif opt.startswith("domain="):
                    domains = [d.strip() for d in opt.split("=", 1)[1].split("|") if d.strip()]

            if not param_name:
                continue

            # Skip regex params (start with /) — too complex for simple stripping
            if param_name.startswith("/"):
                continue

            key = f"{param_name}|{pattern}"
            if key in seen:
                continue
            seen.add(key)

            entry: dict[str, Any] = {"param": param_name}
            if pattern:
                entry["pattern"] = pattern
            if domains:
                entry["domains"] = domains
            if is_exception:
                entry["exception"] = True
            rules.append(entry)

    return rules


# ---------------------------------------------------------------------------
# $badfilter processing
# ---------------------------------------------------------------------------

def apply_badfilters(texts: dict[str, str]) -> dict[str, str]:
    """
    Process $badfilter directives: collect all lines ending with $badfilter,
    then remove the corresponding filter (without $badfilter) from all lists.
    Returns modified texts dict.
    """
    bad_lines: set[str] = set()
    for text in texts.values():
        for line in text.splitlines():
            line = line.strip()
            if line.endswith("$badfilter"):
                # The original filter is the same line without $badfilter
                original = line.rsplit("$badfilter", 1)[0]
                # Remove trailing comma if present
                original = original.rstrip(",").rstrip("$").rstrip(",")
                if original:
                    bad_lines.add(original)

    if not bad_lines:
        return texts

    result: dict[str, str] = {}
    removed = 0
    for name, text in texts.items():
        filtered_lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped in bad_lines:
                removed += 1
                continue
            filtered_lines.append(line)
        result[name] = "\n".join(filtered_lines)

    print(f"    $badfilter: removed {removed} invalidated filters")
    return result


# ---------------------------------------------------------------------------
# scriptlets.js template — expanded to 25+ scriptlets
# ---------------------------------------------------------------------------

SCRIPTLETS_JS_TEMPLATE = r"""// Emerald Ad Blocker — scriptlets.js (v3)
// Injected by WKUserScript at document_start.
// Generated by src/build.py — do not edit by hand.
// Implements uBlock Origin's scriptlet API (25+ scriptlets).
(function () {
  'use strict';

  // ── Subframe guard ────────────────────────────────────────────────────────
  // Exit immediately in cross-origin iframes. Injecting scriptlets there
  // wraps fetch/XHR/timers inside media-player frames and breaks playback.
  // Fully sandboxed frames (no allow-scripts) are blocked at the WebKit level
  // before this runs — this guard catches the cross-origin frames that do
  // execute scripts but must not have their APIs modified.
  if (window.self !== window.top) {
    try { window.top.location.href; } catch (e) { return; }
  }

  // YouTube-specific flag: ytadblock.js owns ad interception on YouTube.
  // Applying our generic fetch/XHR blocks there breaks the video player
  // because noFetchIf rejects requests YouTube's player expects to resolve.
  var _isYT = /(?:^|\.)(?:youtube\.com|youtu\.be|googlevideo\.com|ytimg\.com)$/.test(
    location.hostname
  );

  var _noop = function () {};

  // ── Utilities ─────────────────────────────────────────────────────────────

  function onChain(chain, cb) {
    var parts = chain.split('.');
    var last  = parts.pop();
    function resolve(obj, remaining) {
      if (!remaining.length) { try { cb(obj, last); } catch (_) {} return; }
      var key = remaining[0];
      var rest = remaining.slice(1);
      if (obj[key] !== undefined && obj[key] !== null) {
        resolve(obj[key], rest);
        return;
      }
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

  function parseValue(v) {
    if (v === 'true')       return true;
    if (v === 'false')      return false;
    if (v === 'null')       return null;
    if (v === 'undefined')  return undefined;
    if (v === 'noopFunc' || v === 'noop') return _noop;
    if (v === 'trueFunc')   return function () { return true; };
    if (v === 'falseFunc')  return function () { return false; };
    if (v === 'throwFunc')  return function () { throw ''; };
    if (v === 'emptyStr' || v === '')  return '';
    if (v === 'emptyArr' || v === '[]')  return [];
    if (v === 'emptyObj' || v === '{}')  return {};
    var n = Number(v);
    if (!isNaN(n) && v !== '') return n;
    return v;
  }

  function safeSelf() {
    return { 'RegExp': self.RegExp, 'Array': self.Array };
  }

  // ── Scriptlet implementations ─────────────────────────────────────────────

  function setConstant(chain, valueStr) {
    var value = parseValue(valueStr);
    onChain(chain, function (obj, key) {
      try {
        Object.defineProperty(obj, key, {
          get: function () { return value; },
          set: _noop,
          enumerable: true, configurable: false,
        });
      } catch (_) { try { obj[key] = value; } catch (_2) {} }
    });
  }

  function abortOnRead(chain) {
    onChain(chain, function (obj, key) {
      try {
        Object.defineProperty(obj, key, {
          get: function () { throw new TypeError('Blocked by Emerald'); },
          set: _noop, enumerable: false, configurable: false,
        });
      } catch (_) {}
    });
  }

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

  function abortCurrentInlineScript(prop, search) {
    var re = search ? new RegExp(search) : null;
    onChain(prop, function (obj, key) {
      var desc = Object.getOwnPropertyDescriptor(obj, key) || { value: obj[key], writable: true };
      var currentValue = desc.value !== undefined ? desc.value : (desc.get ? desc.get() : undefined);
      try {
        Object.defineProperty(obj, key, {
          get: function () {
            if (re) {
              var cs = document.currentScript;
              if (cs && cs.src === '' && re.test(cs.textContent)) {
                throw new ReferenceError('Blocked by Emerald');
              }
            }
            return currentValue;
          },
          set: function (v) { currentValue = v; },
          enumerable: true, configurable: true,
        });
      } catch (_) {}
    });
  }

  function noFetchIf(pattern) {
    // On YouTube, ytadblock.js handles fetch interception; doing it here too
    // causes the video player to break (rejected promises it doesn't expect).
    if (_isYT) return;
    var re = pattern ? new RegExp(pattern) : null;
    var _fetch = window.fetch;
    if (typeof _fetch !== 'function') return;
    window.fetch = function (input) {
      var url = typeof input === 'string' ? input : (input && input.url) || '';
      if (!re || re.test(url)) {
        return Promise.reject(new TypeError('Failed to fetch'));
      }
      return _fetch.apply(this, arguments);
    };
  }

  function noXhrIf(pattern) {
    if (_isYT) return;
    var re = pattern ? new RegExp(pattern) : null;
    var _open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      if (!re || re.test(url)) {
        Object.defineProperty(this, '_blocked', { value: true, configurable: true });
      }
      return _open.apply(this, arguments);
    };
    var _send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function () {
      if (this._blocked) {
        // Fire a network-error event so callers get proper rejection handling
        // rather than an XHR that hangs forever.
        var self = this;
        setTimeout(function () {
          try {
            self.dispatchEvent(new ProgressEvent('error'));
            self.dispatchEvent(new ProgressEvent('loadend'));
          } catch (_) {}
          if (typeof self.onerror === 'function') try { self.onerror(); } catch (_) {}
        }, 0);
        return;
      }
      return _send.apply(this, arguments);
    };
  }

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

  function preventAddEventListener(type, pattern) {
    var reType = type ? new RegExp(type) : null;
    var reFn = pattern ? new RegExp(pattern) : null;
    var _ael = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (t, fn, opts) {
      if (reType && !reType.test(t)) return _ael.apply(this, arguments);
      if (reFn) {
        var src = typeof fn === 'function' ? fn.toString() : String(fn);
        if (!reFn.test(src)) return _ael.apply(this, arguments);
      }
      // Silently swallow the listener
    };
  }

  function preventWindowOpen(pattern) {
    var re = pattern ? new RegExp(pattern) : null;
    var _open = window.open;
    window.open = function (url) {
      if (!re || re.test(url || '')) return null;
      return _open.apply(this, arguments);
    };
  }

  function noeval(pattern) {
    var re = pattern ? new RegExp(pattern) : null;
    var _eval = window.eval;
    window.eval = function (code) {
      if (!re || re.test(code)) return undefined;
      return _eval.call(this, code);
    };
  }

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
    new MutationObserver(sweep).observe(document.documentElement,
      { childList: true, subtree: true, attributes: true });
  }

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
    new MutationObserver(sweep).observe(document.documentElement,
      { childList: true, subtree: true });
  }

  function setAttr(selector, attr, value) {
    function sweep() {
      try {
        document.querySelectorAll(selector).forEach(function (el) {
          if (el.getAttribute(attr) !== value) el.setAttribute(attr, value);
        });
      } catch (_) {}
    }
    if (document.readyState !== 'loading') sweep();
    else document.addEventListener('DOMContentLoaded', sweep, { once: true });
    new MutationObserver(sweep).observe(document.documentElement,
      { childList: true, subtree: true });
  }

  function setCookie(name, value) {
    try {
      document.cookie = name + '=' + value + ';path=/;max-age=86400';
    } catch (_) {}
  }

  function jsonPrune(rawPaths) {
    var paths = rawPaths ? rawPaths.split(' ') : [];
    if (!paths.length) return;
    var _parse = JSON.parse;
    JSON.parse = function () {
      var r = _parse.apply(this, arguments);
      if (r && typeof r === 'object') {
        paths.forEach(function (p) {
          var parts = p.split('.');
          var obj = r;
          for (var i = 0; i < parts.length - 1; i++) {
            if (!obj || typeof obj !== 'object') return;
            obj = obj[parts[i]];
          }
          if (obj && typeof obj === 'object') {
            delete obj[parts[parts.length - 1]];
          }
        });
      }
      return r;
    };
    var _rj = Response.prototype.json;
    Response.prototype.json = function () {
      return _rj.apply(this, arguments).then(function (data) {
        if (data && typeof data === 'object') {
          paths.forEach(function (p) {
            var parts = p.split('.');
            var obj = data;
            for (var i = 0; i < parts.length - 1; i++) {
              if (!obj || typeof obj !== 'object') return;
              obj = obj[parts[i]];
            }
            if (obj && typeof obj === 'object') {
              delete obj[parts[parts.length - 1]];
            }
          });
        }
        return data;
      });
    };
  }

  function adjustSetInterval(pattern, multiplier) {
    var re = pattern ? new RegExp(pattern) : null;
    var mult = parseFloat(multiplier) || 0.001;
    var _si = window.setInterval;
    window.setInterval = function (fn, d) {
      var src = typeof fn === 'function' ? fn.toString() : String(fn);
      if (!re || re.test(src)) {
        arguments[1] = Math.round((d || 0) * mult);
      }
      return _si.apply(this, arguments);
    };
  }

  function adjustSetTimeout(pattern, multiplier) {
    var re = pattern ? new RegExp(pattern) : null;
    var mult = parseFloat(multiplier) || 0.001;
    var _st = window.setTimeout;
    window.setTimeout = function (fn, d) {
      var src = typeof fn === 'function' ? fn.toString() : String(fn);
      if (!re || re.test(src)) {
        arguments[1] = Math.round((d || 0) * mult);
      }
      return _st.apply(this, arguments);
    };
  }

  function disableNewtabLinks() {
    document.addEventListener('click', function (e) {
      var a = e.target.closest('a[target="_blank"]');
      if (a) a.removeAttribute('target');
    }, true);
  }

  function windowCloseIf(pattern) {
    var re = pattern ? new RegExp(pattern) : /./;
    if (re.test(location.href)) {
      window.close();
    }
  }

  function preventRefresh(delay) {
    var d = parseInt(delay, 10);
    var observer = new MutationObserver(function () {
      var metas = document.querySelectorAll('meta[http-equiv="refresh"]');
      metas.forEach(function (m) { m.remove(); });
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(function () { observer.disconnect(); }, 10000);
  }

  function removeNodeText(nodeName, pattern) {
    var re = pattern ? new RegExp(pattern) : null;
    var tag = (nodeName || 'script').toUpperCase();
    function sweep() {
      try {
        document.querySelectorAll(tag).forEach(function (el) {
          if (re && re.test(el.textContent)) {
            el.textContent = '';
          }
        });
      } catch (_) {}
    }
    if (document.readyState !== 'loading') sweep();
    else document.addEventListener('DOMContentLoaded', sweep, { once: true });
    new MutationObserver(sweep).observe(document.documentElement,
      { childList: true, subtree: true });
  }

  // ── Dispatch table ────────────────────────────────────────────────────────

  var DISPATCH = {
    'set-constant':               function (a) { setConstant(a[0], a[1]); },
    'trusted-set-constant':       function (a) { setConstant(a[0], a[1]); },
    'abort-on-property-read':     function (a) { abortOnRead(a[0]); },
    'aopr':                       function (a) { abortOnRead(a[0]); },
    'abort-on-property-write':    function (a) { abortOnWrite(a[0]); },
    'aopw':                       function (a) { abortOnWrite(a[0]); },
    'abort-current-inline-script':function (a) { abortCurrentInlineScript(a[0], a[1]); },
    'acis':                       function (a) { abortCurrentInlineScript(a[0], a[1]); },
    'no-fetch-if':                function (a) { noFetchIf(a[0]); },
    'no-xhr-if':                  function (a) { noXhrIf(a[0]); },
    'prevent-setTimeout':         function (a) { preventSetTimeout(a[0], a[1]); },
    'no-setTimeout-if':           function (a) { preventSetTimeout(a[0], a[1]); },
    'prevent-setInterval':        function (a) { preventSetInterval(a[0], a[1]); },
    'no-setInterval-if':          function (a) { preventSetInterval(a[0], a[1]); },
    'prevent-addEventListener':   function (a) { preventAddEventListener(a[0], a[1]); },
    'addEventListener-defuser':   function (a) { preventAddEventListener(a[0], a[1]); },
    'prevent-window-open':        function (a) { preventWindowOpen(a[0]); },
    'noeval':                     function (a) { noeval(a[0]); },
    'noeval-if':                  function (a) { noeval(a[0]); },
    'remove-attr':                function (a) { removeAttr(a[0], a[1]); },
    'remove-class':               function (a) { removeClass(a[0], a[1]); },
    'set-attr':                   function (a) { setAttr(a[0], a[1], a[2]); },
    'set-cookie':                 function (a) { setCookie(a[0], a[1]); },
    'json-prune':                 function (a) { jsonPrune(a[0]); },
    'adjust-setInterval':         function (a) { adjustSetInterval(a[0], a[1]); },
    'adjust-setTimeout':          function (a) { adjustSetTimeout(a[0], a[1]); },
    'disable-newtab-links':       function (a) { disableNewtabLinks(); },
    'window-close-if':            function (a) { windowCloseIf(a[0]); },
    'prevent-refresh':            function (a) { preventRefresh(a[0]); },
    'remove-node-text':           function (a) { removeNodeText(a[0], a[1]); },
  };

  function run(name, args) {
    var fn = DISPATCH[name];
    if (fn) { try { fn(args || []); } catch (_) {} }
  }

  // ── Hardcoded high-value configs ──────────────────────────────────────────

  setConstant('adsbygoogle.loaded', 'true');
  setConstant('adsbygoogle.push', 'noopFunc');
  setConstant('canRunAds', 'true');
  setConstant('blockAdBlock', 'noopFunc');
  setConstant('adsBlocked', 'false');
  setConstant('ads_not_blocked', 'true');
  setConstant('fuckAdBlock', 'noopFunc');
  setConstant('sniffAdBlock', 'noopFunc');
  setConstant('__aapolygon.showAd', 'noopFunc');
  setConstant('detectAdBlock', 'noopFunc');
  setConstant('check_adblock', 'noopFunc');
  setConstant('isAdBlockActive', 'false');
  setConstant('Admiral', 'noopFunc');

  noFetchIf('googlesyndication\\.com');
  noFetchIf('doubleclick\\.net');
  noFetchIf('google-analytics\\.com/collect');
  noFetchIf('google-analytics\\.com/g/collect');
  noFetchIf('facebook\\.net/en_US/fbevents');
  noFetchIf('hotjar\\.com');
  noFetchIf('fullstory\\.com');
  noFetchIf('clarity\\.ms');

  noXhrIf('googlesyndication\\.com');
  noXhrIf('doubleclick\\.net');
  noXhrIf('google-analytics\\.com/collect');
  noXhrIf('facebook\\.net/en_US/fbevents');

  // Target known anti-adblocker library names only, not generic "AdBlock" strings
  // that would also match legitimate ad-block tester detection code.
  preventSetTimeout('blockadblock|BlockAdBlock|fuckAdBlock|FuckAdBlock');
  preventSetInterval('blockadblock|BlockAdBlock|fuckAdBlock|FuckAdBlock');

  // ── Extracted generic configs ─────────────────────────────────────────────

  var GENERIC_CONFIGS = INJECTED_CONFIGS;
  for (var _i = 0; _i < GENERIC_CONFIGS.length; _i++) {
    var _cfg = GENERIC_CONFIGS[_i];
    run(_cfg[0], _cfg[1]);
  }

})();
"""


def build_scriptlets_js(configs: list[tuple[str, list[str]]]) -> str:
    config_js = json.dumps([[name, args] for name, args in configs], indent=2)
    return SCRIPTLETS_JS_TEMPLATE.replace("INJECTED_CONFIGS", config_js)


# ---------------------------------------------------------------------------
# WebSocket / WebRTC blocking script
# ---------------------------------------------------------------------------

WEBSOCKET_BLOCK_JS = r"""// Emerald Ad Blocker — websocket_block.js
// Injected by WKUserScript at document_start.
// Blocks WebSocket connections to known trackers and prevents WebRTC IP leaks.
(function () {
  'use strict';

  // ── WebSocket blocking ────────────────────────────────────────────────────

  var _WS = window.WebSocket;
  var BLOCKED_WS = [
    /google-analytics/i, /doubleclick/i, /googlesyndication/i,
    /facebook\.net/i, /fbcdn\.net.*beacon/i,
    /hotjar\.com/i, /fullstory\.com/i, /segment\.(com|io)/i,
    /mixpanel\.com/i, /amplitude\.com/i,
    /clarity\.ms/i, /mouseflow\.com/i,
    /taboola\.com/i, /outbrain\.com/i,
    /criteo\.(com|net)/i, /pubmatic\.com/i,
    /adnxs\.com/i, /rubiconproject\.com/i,
  ];

  window.WebSocket = function (url, protocols) {
    var urlStr = String(url);
    for (var i = 0; i < BLOCKED_WS.length; i++) {
      if (BLOCKED_WS[i].test(urlStr)) {
        return {
          readyState: 3, CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3,
          send: function () {}, close: function () {},
          addEventListener: function () {}, removeEventListener: function () {},
          onopen: null, onclose: null, onmessage: null, onerror: null,
          binaryType: 'blob', bufferedAmount: 0, extensions: '', protocol: '',
          url: urlStr,
        };
      }
    }
    if (protocols !== undefined) return new _WS(url, protocols);
    return new _WS(url);
  };
  window.WebSocket.prototype = _WS.prototype;
  window.WebSocket.CONNECTING = 0;
  window.WebSocket.OPEN = 1;
  window.WebSocket.CLOSING = 2;
  window.WebSocket.CLOSED = 3;

  // ── WebRTC IP leak prevention ─────────────────────────────────────────────

  var _RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
  if (_RTC) {
    window.RTCPeerConnection = function (config, constraints) {
      if (config && config.iceServers) {
        config.iceServers = [];
      }
      return new _RTC(config, constraints);
    };
    window.RTCPeerConnection.prototype = _RTC.prototype;
    if (window.webkitRTCPeerConnection) {
      window.webkitRTCPeerConnection = window.RTCPeerConnection;
    }
  }

  // ── navigator.sendBeacon blocking ─────────────────────────────────────────

  var _beacon = navigator.sendBeacon;
  var BLOCKED_BEACON = [
    /google-analytics/i, /doubleclick/i, /facebook/i,
    /analytics/i, /collect/i, /pixel/i, /beacon/i,
  ];

  if (_beacon) {
    navigator.sendBeacon = function (url) {
      var urlStr = String(url);
      for (var i = 0; i < BLOCKED_BEACON.length; i++) {
        if (BLOCKED_BEACON[i].test(urlStr)) return true; // pretend success
      }
      return _beacon.apply(navigator, arguments);
    };
  }

})();
"""


# ---------------------------------------------------------------------------
# cosmetic.js template — improved MutationObserver performance
# ---------------------------------------------------------------------------

COSMETIC_JS_TEMPLATE = """\
// Emerald Ad Blocker — cosmetic.js (v3)
// Injected by WKUserScript at document_start.
// Generated by src/build.py — do not edit by hand.
(function () {
  'use strict';

  // ── 1. Anti-adblock stubs ────────────────────────────────────────────────

  try {
    Object.defineProperty(window, 'canRunAds', { get: function () { return true; } });
    Object.defineProperty(window, 'canShowAds', { get: function () { return true; } });
  } catch (_) {}

  if (!window.adsbygoogle || !Array.isArray(window.adsbygoogle)) {
    try {
      var _abl = [];
      _abl.loaded = true;
      _abl.push = function () {};
      Object.defineProperty(window, 'adsbygoogle', { get: function () { return _abl; }, configurable: true });
    } catch (_) {}
  }

  var _gtSlot = {
    addService: function () { return _gtSlot; },
    defineSizeMapping: function () { return _gtSlot; },
    setTargeting: function () { return _gtSlot; },
    setCollapseEmptyDiv: function () { return _gtSlot; },
    getSlotElementId: function () { return ''; },
    getAdUnitPath: function () { return ''; },
  };
  var _gtPubads = {
    addEventListener: function () {}, removeEventListener: function () {},
    setTargeting: function () { return _gtPubads; },
    collapseEmptyDivs: function () {}, enableSingleRequest: function () {},
    enableLazyLoad: function () {},
    set: function () { return _gtPubads; }, get: function () { return null; },
    refresh: function () {}, display: function () {},
    disableInitialLoad: function () {},
    clearTargeting: function () { return _gtPubads; },
    getTargeting: function () { return []; },
    getTargetingKeys: function () { return []; },
    updateCorrelator: function () {},
    setPrivacySettings: function () { return _gtPubads; },
    getSlots: function () { return []; },
  };
  var _googletag = {
    cmd: { push: function (fn) { try { fn(); } catch (_) {} } },
    pubads: function () { return _gtPubads; },
    companionAds: function () { return {}; },
    content: function () { return {}; },
    sizeMapping: function () { return { addSize: function () { return this; }, build: function () { return []; } }; },
    defineSlot: function () { return _gtSlot; },
    defineOutOfPageSlot: function () { return _gtSlot; },
    display: function () {}, enableServices: function () {},
    destroySlots: function () {}, getVersion: function () { return ''; },
    apiReady: true,
  };
  try {
    if (!window.googletag || !window.googletag.pubads) {
      window.googletag = _googletag;
    } else {
      window.googletag.cmd = window.googletag.cmd || _googletag.cmd;
    }
  } catch (_) {}

  // ── 2. CSS hiding ─────────────────────────────────────────────────────────

  var SELECTORS = [
    '[id^="google_ads_"]','[id^="div-gpt-ad"]','[id^="dfp-ad-"]',
    '.adsbygoogle','ins.adsbygoogle','.gpt-ad','.dfp-ad',
    '[data-ad-unit]','[data-adunit]','[data-google-query-id]',
    '[id*="taboola"]','[class*="taboola"]',
    '[id*="outbrain"]','[class*="outbrain"]',
    '[id*="revcontent"]','[class*="revcontent"]',
    '[class*="sponsored-content"]','[class*="sponsored_content"]',
    '[class*="native-ad"]',
    '[data-ad-placeholder]','[data-advertisement]',
    '.ad-banner','.ad-container','.ad-wrapper','.ad-slot',
    '.advertisement','.advertising','.advertise',
    'iframe[src*="doubleclick.net"]','iframe[src*="googlesyndication.com"]',
    'iframe[src*="adnxs.com"]','iframe[src*="pubmatic.com"]',
    // YouTube search sponsored results (cosmetic.js runs even on YT)
    'ytd-search-pyv-renderer','ytd-promoted-sparkles-web-renderer',
    'ytd-promoted-sparkles-text-search-renderer','ytd-display-ad-renderer',
    'ytd-banner-promo-renderer','ytd-statement-banner-renderer',
    '#masthead-ad',
    // YouTube watch page ads
    'ytd-action-companion-ad-renderer','ytd-companion-slot-renderer',
    'ytd-video-masthead-ad-v3-renderer','ytd-player-legacy-desktop-watch-ads-renderer',
    'ytd-promoted-video-renderer','ytd-ad-slot-renderer',
    '#player-ads','.ytp-ad-overlay-container','.ytp-ad-overlay-slot',
    '.ytp-ad-module',
    // Reddit sponsored posts (new shreddit UI + old Reddit)
    'shreddit-ad-post','.promotedlink',
    '[data-testid="post-container"][data-promoted="true"]',
    EASYLIST_SELECTORS
  ];

  // Build a single joined selector string for querySelectorAll
  var _allSelectors = SELECTORS.join(',');

  function injectCSS() {
    // Split selectors into batches of 500 to avoid style engine perf cliffs
    var batchSize = 500;
    for (var b = 0; b < SELECTORS.length; b += batchSize) {
      var batch = SELECTORS.slice(b, b + batchSize);
      var style = document.createElement('style');
      style.id = '__emerald_cosmetic_' + b + '__';
      style.textContent = batch.join(',\\n') + ' { display: none !important; }';
      (document.head || document.documentElement).appendChild(style);
    }
  }

  if (document.head || document.documentElement) {
    injectCSS();
  } else {
    document.addEventListener('DOMContentLoaded', injectCSS, { once: true });
  }

  // ── 3. MutationObserver (optimized) ───────────────────────────────────────

  // Use a single querySelectorAll per batch instead of per-element matching
  var _hidden = new WeakSet();
  var _pending = false;

  function scanAndHide() {
    _pending = false;
    try {
      var matches = document.querySelectorAll(_allSelectors);
      for (var i = 0; i < matches.length; i++) {
        if (!_hidden.has(matches[i])) {
          matches[i].style.setProperty('display', 'none', 'important');
          _hidden.add(matches[i]);
        }
      }
    } catch (_) {}
  }

  var observer = new MutationObserver(function () {
    if (!_pending) {
      _pending = true;
      requestAnimationFrame(scanAndHide);
    }
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });

  // ── 4. :has-text() procedural cosmetic filters ────────────────────────────

  var HAS_TEXT_FILTERS = HAS_TEXT_INJECTED;

  if (HAS_TEXT_FILTERS.length > 0) {
    function applyHasText() {
      HAS_TEXT_FILTERS.forEach(function (f) {
        try {
          var re = new RegExp(f.text, 'i');
          document.querySelectorAll(f.selector).forEach(function (el) {
            if (re.test(el.textContent)) {
              el.style.setProperty('display', 'none', 'important');
            }
          });
        } catch (_) {}
      });
    }
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', applyHasText, { once: true });
    } else {
      applyHasText();
    }
    // Re-run on DOM changes (throttled)
    var _htPending = false;
    new MutationObserver(function () {
      if (!_htPending) {
        _htPending = true;
        setTimeout(function () { _htPending = false; applyHasText(); }, 500);
      }
    }).observe(document.documentElement, { childList: true, subtree: true });
  }

})();
"""


def build_cosmetic_js(selectors: list[str], has_text_filters: list[dict]) -> str:
    js_selectors = ",\n    ".join(json.dumps(s) for s in selectors)
    ht_json = json.dumps(has_text_filters)
    result = COSMETIC_JS_TEMPLATE.replace("    EASYLIST_SELECTORS", f"    {js_selectors}")
    result = result.replace("HAS_TEXT_INJECTED", ht_json)
    return result


# ---------------------------------------------------------------------------
# Auto-split helper — splits a rule list into 149K chunks
# ---------------------------------------------------------------------------

def write_rules_auto_split(
    rules: list[dict], base_name: str, output_dir: Path, root: Path
) -> list[str]:
    """
    Write rules to one or more JSON files. If len(rules) <= MAX_RULES,
    writes a single file. Otherwise splits into base_name-1.json, -2.json, etc.
    Returns list of filenames written.
    """
    files_written: list[str] = []
    if len(rules) <= MAX_RULES:
        out = output_dir / f"{base_name}.json"
        with open(out, "w") as f:
            json.dump(rules, f, separators=(",", ":"))
        size_mb = out.stat().st_size / (1024 * 1024)
        print(f"  Wrote {out.relative_to(root)} ({len(rules):,} rules, {size_mb:.1f} MB)")
        files_written.append(f"{base_name}.json")
    else:
        chunks = [rules[i:i + MAX_RULES] for i in range(0, len(rules), MAX_RULES)]
        for idx, chunk in enumerate(chunks, 1):
            fname = f"{base_name}-{idx}.json"
            out = output_dir / fname
            with open(out, "w") as f:
                json.dump(chunk, f, separators=(",", ":"))
            size_mb = out.stat().st_size / (1024 * 1024)
            print(f"  Wrote {out.relative_to(root)} ({len(chunk):,} rules, {size_mb:.1f} MB)")
            files_written.append(fname)
        print(f"  Split {base_name} into {len(chunks)} files ({len(rules):,} total)")
    return files_written


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

    # ── Apply $badfilter directives ───────────────────────────────────────────
    print("\n=== Processing $badfilter directives ===")
    raw = apply_badfilters(raw)

    # ── Parse upstream (blocks + exceptions) ──────────────────────────────────
    print("\n=== Parsing upstream lists ===")

    AD_LISTS = ["easylist", "ublock", "ublock_annoyances", "fanboy_annoyances", "ublock_unbreak"]
    TRACKER_LISTS = ["easyprivacy", "peter_lowe", "ublock_privacy"]

    adblock_blocks: list[dict] = []
    tracker_blocks: list[dict] = []
    all_exceptions: list[dict] = []

    for name in UPSTREAM_LISTS:
        blocks, exceptions = parse_upstream(name, raw.get(name, ""))
        if name in TRACKER_LISTS:
            tracker_blocks.extend(blocks)
        else:
            adblock_blocks.extend(blocks)
        all_exceptions.extend(exceptions)

    # ── Build native cosmetic rules (css-display-none) ────────────────────────
    print("\n=== Building native cosmetic rules ===")
    cosmetic_selectors = extract_cosmetic_selectors(raw)
    native_cosmetic = cosmetic_to_native_rules(cosmetic_selectors)
    print(f"  {len(native_cosmetic):,} selectors → native css-display-none rules (pre-paint, zero flicker)")

    # ── Merge & deduplicate ───────────────────────────────────────────────────
    print("\n=== Merging and deduplicating ===")

    # YouTube/Google safety net — MUST be at the end of every rule list so
    # ignore-previous-rules overrides all upstream rules, not just curated ones.
    # This prevents blocking YouTube's player API (youtubei/v1/player) and
    # other Google service endpoints that match ad-like URL patterns.
    # Network ad blocking for YouTube is handled by Emerald's own userscript.
    YOUTUBE_SAFETY_NET = [
        {
            "trigger": {
                "url-filter": ".*",
                "if-domain": [
                    "*youtube.com", "*youtu.be", "*googlevideo.com",
                    "*ytimg.com", "*google.com", "*googleapis.com",
                    "*gstatic.com", "*googleusercontent.com",
                ]
            },
            "action": {"type": "ignore-previous-rules"}
        }
    ]

    # adblock.json: curated + upstream + native cosmetic + YouTube safety net (last!)
    # Note: Spotify and GitHub are excluded from *cosmetic* hiding only
    # (see COSMETIC_EXCLUDE_DOMAINS). Network-level ad/tracker blocking still
    # applies on those domains — only element hiding is skipped.
    adblock_merged = dedup(fixed_adblock + adblock_blocks + native_cosmetic) + YOUTUBE_SAFETY_NET
    trackers_merged = dedup(fixed_trackers + tracker_blocks) + YOUTUBE_SAFETY_NET
    exceptions_merged = dedup(all_exceptions)

    total = len(adblock_merged) + len(trackers_merged) + len(exceptions_merged)
    print(f"  adblock    : {len(adblock_merged):,} rules (incl. {len(native_cosmetic):,} cosmetic)")
    print(f"  trackers   : {len(trackers_merged):,} rules")
    print(f"  exceptions : {len(exceptions_merged):,} rules")
    print(f"  total      : {total:,} rules")

    # ── Drop blanket main-domain blocks (upstream list false-positives) ──────
    print("\n=== Dropping blanket main-domain blocks ===")
    adblock_merged = drop_main_domain_blocks(adblock_merged)
    trackers_merged = drop_main_domain_blocks(trackers_merged)

    # ── Sanitize: enforce WebKit single-condition-per-trigger constraint ──────
    print("\n=== Sanitizing rules (WebKit constraint) ===")
    adblock_merged = sanitize_rules(adblock_merged)
    trackers_merged = sanitize_rules(trackers_merged)
    exceptions_merged = sanitize_rules(exceptions_merged)

    # ── Write JSON outputs (with auto-split) ──────────────────────────────────
    print("\n=== Writing output files ===")

    write_rules_auto_split(adblock_merged, "adblock", OUTPUT_DIR, ROOT)
    write_rules_auto_split(trackers_merged, "trackers", OUTPUT_DIR, ROOT)
    write_rules_auto_split(exceptions_merged, "exceptions", OUTPUT_DIR, ROOT)

    # ── Build cosmetic.js (JS fallback for complex selectors) ─────────────────
    # Native css-display-none handles most selectors. cosmetic.js handles
    # the rest: anti-adblock stubs, :has-text(), and selectors too complex
    # for the native engine (compound selectors with commas, iframe[src]).
    has_text_filters = extract_has_text_filters(raw)
    # Only keep selectors that didn't make it into native rules
    js_only_selectors = [s for s in cosmetic_selectors
                         if "," in s or "::" in s or "iframe[src" in s]
    print(f"  {len(js_only_selectors):,} complex selectors → cosmetic.js (JS fallback)")
    print(f"  {len(has_text_filters):,} :has-text() procedural filters")

    cosmetic_js = build_cosmetic_js(js_only_selectors, has_text_filters)
    cosmetic_out = OUTPUT_DIR / "cosmetic.js"
    with open(cosmetic_out, "w") as f:
        f.write(cosmetic_js)
    print(f"  Wrote {cosmetic_out.relative_to(ROOT)}")

    # ── Domain-specific cosmetic selectors ────────────────────────────────────
    domain_cosmetics = extract_domain_cosmetic_selectors(raw)
    domain_out = OUTPUT_DIR / "cosmetic_domains.json"
    with open(domain_out, "w") as f:
        json.dump(domain_cosmetics, f, separators=(",", ":"))
    size_kb = domain_out.stat().st_size / 1024
    print(f"  Wrote {domain_out.relative_to(ROOT)} ({len(domain_cosmetics):,} domains, {size_kb:.0f} KB)")

    # ── Build scriptlets.js ───────────────────────────────────────────────────
    scriptlet_configs = extract_scriptlet_configs(raw)
    print(f"  Extracted {len(scriptlet_configs):,} generic scriptlet configs")

    scriptlets_js = build_scriptlets_js(scriptlet_configs)
    scriptlets_out = OUTPUT_DIR / "scriptlets.js"
    with open(scriptlets_out, "w") as f:
        f.write(scriptlets_js)
    print(f"  Wrote {scriptlets_out.relative_to(ROOT)}")

    # ── Build scriptlet_rules.json (site-specific) ────────────────────────────
    site_configs = extract_site_scriptlet_configs(raw)
    site_out = OUTPUT_DIR / "scriptlet_rules.json"
    with open(site_out, "w") as f:
        json.dump(site_configs, f, separators=(",", ":"))
    print(f"  Wrote {site_out.relative_to(ROOT)} ({len(site_configs):,} domains)")

    # ── Write websocket_block.js ──────────────────────────────────────────────
    ws_out = OUTPUT_DIR / "websocket_block.js"
    with open(ws_out, "w") as f:
        f.write(WEBSOCKET_BLOCK_JS)
    print(f"  Wrote {ws_out.relative_to(ROOT)}")

    # ── Extract and write redirect_rules.json ─────────────────────────────────
    redirect_rules = extract_redirect_rules(raw)
    redirect_out = OUTPUT_DIR / "redirect_rules.json"
    with open(redirect_out, "w") as f:
        json.dump(redirect_rules, f, separators=(",", ":"))
    print(f"  Wrote {redirect_out.relative_to(ROOT)} ({len(redirect_rules):,} rules)")

    # ── Extract and write removeparam_rules.json ──────────────────────────────
    removeparam_rules = extract_removeparam_rules(raw)
    removeparam_out = OUTPUT_DIR / "removeparam_rules.json"
    with open(removeparam_out, "w") as f:
        json.dump(removeparam_rules, f, separators=(",", ":"))
    print(f"  Wrote {removeparam_out.relative_to(ROOT)} ({len(removeparam_rules):,} rules)")

    print("\n=== Done ✓ ===\n")


if __name__ == "__main__":
    main()
