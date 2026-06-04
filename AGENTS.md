# AGENTS.md

## Project Overview

Emerald Ad Blocker is the built-in ad blocker for the Emerald browser, a macOS WebKit-based browser. It blocks ads, trackers, and anti-adblock detection using two WebKit APIs:

- **WKContentRuleList** — declarative JSON rules that block/allow network requests (Safari content blocker format)
- **WKUserScript** — JavaScript injected into every page at `document_start`

The ad blocker is NOT a Safari extension. It runs inside a WKWebView managed by the Emerald browser app (closed-source). This repo contains only the filter lists, build tooling, and injected scripts.

## Architecture

```
src/BuildTool/          Swift CLI that fetches upstream filter lists, converts them
                        via SafariConverterLib, and generates all output files
  Sources/main.swift    Entry point — fetching, conversion, exception injection
  Sources/JSTemplates.swift   All JS templates as Swift string literals
  Package.swift         Depends on AdguardTeam/SafariConverterLib 4.2.0+

output/                 Generated files consumed by the Emerald browser
  adblock.json          WKContentRuleList JSON (ads)
  trackers.json         WKContentRuleList JSON (trackers)
  exceptions.json       WKContentRuleList JSON (exceptions only)
  cosmetic.js           WKUserScript — CSS hiding + anti-detection + bait element protection
  scriptlets.js         WKUserScript — scriptlet engine with per-domain configs
  tracker_stubs.js      WKUserScript — stubs tracker JS APIs (GA, fbq, amplitude, etc.)
  websocket_block.js    WKUserScript — blocks ad/tracker WebSocket and sendBeacon calls
  ytadblock.js          WKUserScript — YouTube-specific ad blocker (adapted vBlockTube)

TestApp/                Standalone WKWebView test browser for local verification
Files/                  Legacy JSON files (pre-SafariConverterLib)
.github/workflows/      CI: weekly filter list update via GitHub Actions
```

## Critical Constraints

### WKContentRuleList (JSON rules)

- **150,000 rule limit** per list. WebKit silently rejects the entire list if exceeded.
- **ASCII only** in `url-filter` and `selector` fields. A single non-ASCII character (Cyrillic, CJK, etc.) causes WebKit to reject the entire JSON file with no useful error. The build tool strips these in `convertAndWrite()`.
- **Rule order matters.** `ignore-previous-rules` actions only apply to rules that appear BEFORE them in the array. The first-party exception and Kahoot blanket exception are appended at the end of the array for this reason.
- **No regex lookahead/lookbehind.** WebKit's url-filter uses a restricted regex subset.
- **`load-type` values:** `first-party` and `third-party` only. WebKit determines this by comparing the page's eTLD+1 with the request's eTLD+1 — subdomains of different services (e.g., `kahoot.it` requesting `kahoot.com`) are treated as third-party.
- **SafariConverterLib rejects wildcard exceptions** like `@@||*^$~third-party` as "too wide." These must be injected directly into the JSON output array, not passed as filter rules.

### WKUserScript (JavaScript injection)

- **Runs on EVERY page.** WKUserScript does not support `@match` or `@include` annotations. Every script executes on every navigation unless it contains an explicit domain guard that calls `return` early.
- **Domain guards are mandatory.** Every JS file must check `window.location.hostname` at the top and `return` on domains where it shouldn't run. Missing or incorrect guards have caused:
  - Google Workspace redirecting to `ogs.google.com` (ytadblock.js wrapping fetch/XHR violated Trusted Types CSP)
  - Kahoot failing to initialize (tracker_stubs.js stubbed Amplitude with a no-op)
  - Kahoot loading slowly (cosmetic.js bait element Proxy overhead on every DOM measurement)
- **Domain guard regex pattern:** Use `/(^|\.)domain\.(tld)$/` to match both bare domains and subdomains. The pattern `/\.domain\.tld$/` only matches subdomains and will miss `domain.tld` itself.
- **All four scripts + ytadblock.js must have consistent skip lists.** When adding a domain exception, update the guard in ALL scripts that should skip it.
- **`configurable: true` on defineProperty.** Multiple scripts may define the same global (e.g., `canRunAds`). Using `configurable: false` causes the second script to throw, which kills the entire IIFE and breaks everything after it.
- **No Trusted Types violations.** Google pages enforce `require-trusted-types-for 'script'`. Any script that wraps `createElement`, `innerHTML`, or similar DOM APIs will cause CSP errors on Google domains. Guard these behind domain checks.

### Build Tool (Swift)

- **Runs on macOS only.** Requires Swift 5.9+ and Xcode Command Line Tools. CI uses `runs-on: macos-latest`.
- **`swift run` from `src/BuildTool/`.** This fetches all upstream lists, converts them, and regenerates every file in `output/`.
- **JS files are generated from Swift string literals** in `JSTemplates.swift`, not from standalone `.js` files. Edit `JSTemplates.swift`, not the output files directly.
- **`ytadblock.js` is the exception** — it's maintained as a standalone file in `output/` (adapted from vBlockTube), not generated by the build tool.
- **WKContentRuleListStore verification cannot run in CI.** It requires an NSApplication run loop not available in headless GitHub Actions. Test locally with the TestApp.
- **Safe-site exceptions** are ABP-format rules in the `safeExceptions` array in `main.swift`. These whitelist specific domains/APIs that match tracker patterns but are needed for site functionality (e.g., `cdn.amplitude.com` on Kahoot, `dc.services.visualstudio.com` on MakeCode).

### Testing

- **Use the TestApp** (`cd TestApp && swift run`) to verify changes locally. It loads all scripts and compiles the JSON rule lists into WKContentRuleLists.
- **Test these sites after any change:**
  - `youtube.com` — video ads blocked, no "ad blocker detected" message
  - `kahoot.it` and `create.kahoot.it` — loads quickly, APIs functional
  - `statcounter.com` — dashboard loads, own analytics not blocked
  - `docs.google.com` / `mail.google.com` — no redirect to `ogs.google.com`
  - `makecode.com` — loads without excessive delay
  - `adblock-tester.com` — ad blocker not detected

### Common Pitfalls

1. **Editing output files directly.** All files in `output/` except `ytadblock.js` are regenerated by `swift run`. Edits will be overwritten. Change `JSTemplates.swift` or `main.swift` instead.
2. **Adding a domain exception in only one place.** Exceptions must be added in: (a) the `safeExceptions` array in `main.swift` for network rules, (b) the domain guard in each JS template in `JSTemplates.swift` that should skip the domain, and (c) possibly as a JSON-level `ignore-previous-rules` rule in `convertAndWrite()` for cross-origin API sites.
3. **Regex guard matching subdomains but not bare domains.** `/\.kahoot\.it$/` matches `create.kahoot.it` but NOT `kahoot.it`. Use `/(^|\.)kahoot\.(it|com)$/`.
4. **Prototype overrides on performance-sensitive sites.** The bait element protection in `cosmetic.js` wraps `getComputedStyle`, `offsetHeight`, and `offsetWidth`. This adds overhead to every DOM measurement. Sites with heavy layout computation (React SPAs like Kahoot) need a full early `return`, not just `_skipCSSHiding`.
5. **Non-ASCII in upstream filter lists.** Upstream lists contain rules with Cyrillic, CJK, and other non-ASCII characters. The build tool strips these, but new filter list sources should be tested for this.

## Upstream Filter Lists

The build tool fetches from these sources (defined in `main.swift`):

| List | Category | Notes |
|------|----------|-------|
| EasyList | ads | Core ABP-format ad blocking |
| EasyPrivacy | trackers | Core tracker blocking |
| Peter Lowe's | trackers | Domain-level blocking |
| AdGuard Base (Safari) | ads | Safari-optimized from filters.adtidy.org |
| AdGuard Tracking (Safari) | trackers | Safari-optimized |
| AdGuard Social (Safari) | ads | Social widget blocking |
| AdGuard Annoyances (Safari) | ads | Cookie notices, newsletters |
| AdGuard Mobile (Safari) | ads | Mobile-specific rules |
| AdGuard URL Tracking (Android) | removeparam | URL parameter stripping data |
| uBlock Unbreak | ads | Exception rules to fix false positives |

## File Ownership

- **This repo** is maintained by [@Bieletees](https://github.com/Bieletees) (Emerald browser developer)
- **Contributions** are submitted via pull request from forks
- **The Emerald browser app itself is closed-source** — this repo only contains the ad blocker component
