# Emerald Ad Blocker

WKContentRuleList-based ad and tracker blocker for WebKit browsers (iOS/macOS). This repo is a **contributor fork** of [Bieletees/Emerald-Ad-Blocker](https://github.com/Bieletees/Emerald-Ad-Blocker). Changes are submitted upstream via pull requests.

## Architecture

The build pipeline fetches upstream filter lists (EasyList, EasyPrivacy, AdGuard, Peter Lowe's, uBlock Origin), converts them to Safari-compatible JSON via AdGuard's SafariConverterLib, and generates JavaScript content scripts. All output lands in `output/`.

### Key files

- `src/BuildTool/Sources/main.swift` — Build pipeline entry point. Fetches lists, converts via SafariConverterLib, appends safe-site exceptions, writes output JSON and JS files.
- `src/BuildTool/Sources/JSTemplates.swift` — Templates for all JS output files (cosmetic.js, scriptlets.js, tracker_stubs.js, websocket_block.js). These are the source of truth for JS content scripts.
- `output/` — Generated files bundled by integrators. Never edit output JS directly; edit the templates in JSTemplates.swift instead.
- `.github/workflows/update-lists.yml` — Weekly CI that rebuilds from upstream lists and opens a PR.

### How content scripts work

All JS files are injected as WKUserScripts at `document_start`. Each script has a domain guard at the top that returns early on safe-listed domains (Google, YouTube, Kahoot, StatCounter). The domain guard pattern:

```javascript
var host = window.location.hostname;
if (/pattern/.test(host)) { return; }
```

When adding a new safe-listed domain, add the early return to ALL four scripts AND add exception rules in `main.swift`'s `safeExceptions` array.

### ytadblock.js

This is a wrapped copy of vBlockTube (~230KB). It has its own domain guard that skips non-YouTube pages. It should NOT be injected on every page by integrators due to parse overhead. See `output/SWIFT_INTEGRATION.md` for the conditional injection pattern.

## Constraints

### Do not edit output/ JS files directly
The BuildTool regenerates them on every run. Edit `JSTemplates.swift` for cosmetic.js, scriptlets.js, tracker_stubs.js, websocket_block.js. Edit `main.swift` for exception rules and the build pipeline.

### Do not commit .build/ directories
`src/BuildTool/.build/` and `TestApp/.build/` are in `.gitignore`. SPM recreates them on `swift package resolve`.

### Domain guard consistency
When exempting a new domain from the ad blocker, add the guard to ALL of these:
1. `cosmetic.js` template in `JSTemplates.swift` (full early `return`)
2. `scriptlets.js` template in `JSTemplates.swift` (full early `return`)
3. `tracker_stubs.js` template in `JSTemplates.swift` (full early `return`)
4. `websocket_block.js` template in `JSTemplates.swift` (full early `return`)
5. `safeExceptions` array in `main.swift` (network-level `ignore-previous-rules`)

Missing any one of these causes partial breakage on that domain.

### WKContentRuleList limits
Safari allows 150,000 rules per compiled list. The build pipeline targets ~50K rules per list. The `convertAndWrite()` function appends a first-party exception and per-site catch-all exceptions at the END of each list. `ignore-previous-rules` only works on rules that appear before it in the same list.

### Safe-site exception pattern
Exception rules in `main.swift` use AdBlock Plus syntax: `@@||domain.com^$domain=site.com`. These are converted by SafariConverterLib into `ignore-previous-rules` JSON entries. A catch-all `.*` exception for a domain is also appended at the end of each JSON file by `convertAndWrite()`.

### Performance considerations
- JS content scripts with early returns have minimal execution cost but still incur parse cost proportional to file size
- ytadblock.js (230KB) must only be injected on YouTube domains
- The other four scripts total ~62KB and are acceptable on all pages

### Testing
The TestApp (`TestApp/`) is a standalone WKWebView browser for local testing. Build with `cd TestApp && swift run`. It loads all output files and compiles the content rule lists. Use Safari Web Inspector (Develop menu) to debug.

### This is a fork
All changes should be PR-ready for upstream. Keep commits clean, don't introduce fork-specific features that wouldn't make sense in the upstream repo.

## Build

```
cd src/BuildTool
rm -rf .build
swift package resolve
swift run
```

## Test

```
cd TestApp
rm -rf .build
swift run
```
