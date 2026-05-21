# Emerald Ad Blocker

A WKContentRuleList-based ad and tracker blocker for iOS/macOS browsers built on WebKit. Rules are compiled from [EasyList](https://easylist.to/), [EasyPrivacy](https://easylist.to/), [AdGuard](https://github.com/AdguardTeam/AdguardFilters) (Safari-optimized), [uBlock Origin](https://github.com/uBlockOrigin/uAssets), and [Peter Lowe's list](https://pgl.yoyo.org/adservers/) using [AdGuard's SafariConverterLib](https://github.com/AdguardTeam/SafariConverterLib), then written as ready-to-use JSON + JavaScript files.

---

## Repository layout

```
Emerald-Ad-Blocker/
├── Files/                      # Hand-curated baseline rules (source of truth)
│   ├── adblock.json            #   Ad-network block rules
│   └── trackers.json           #   Tracker/analytics block rules
│
├── src/
│   ├── BuildTool/              # Swift build pipeline (primary)
│   │   ├── Package.swift
│   │   └── Sources/
│   │       ├── main.swift      #   Fetches lists, converts via SafariConverterLib
│   │       └── JSTemplates.swift #  JS output file templates
│   └── build.py                # Python build pipeline (legacy fallback)
│
├── output/                     # Generated files — bundle these in your app
│   ├── adblock.json            #   WKContentRuleList (ads)
│   ├── trackers.json           #   WKContentRuleList (trackers)
│   ├── exceptions.json         #   WKContentRuleList (safe-site exceptions)
│   ├── cosmetic.js             #   WKUserScript — CSS hiding + anti-adblock stubs
│   ├── scriptlets.js           #   WKUserScript — uBO-style scriptlet engine
│   ├── tracker_stubs.js        #   WKUserScript — silently stubs tracker JS APIs
│   ├── websocket_block.js      #   WKUserScript — WebSocket/WebRTC blocking
│   ├── cosmetic_domains.json   #   Per-domain CSS selectors (sidecar)
│   ├── scriptlet_rules.json    #   Per-domain scriptlet configs (sidecar)
│   ├── removeparam_rules.json  #   URL tracking parameter rules (sidecar)
│   ├── redirect_rules.json     #   Surrogate resource mappings (sidecar)
│   └── SWIFT_INTEGRATION.md    #   Full Swift wiring guide
│
├── .cache/                     # Cached upstream list downloads
│
└── .github/
    └── workflows/
        └── update-lists.yml    # GitHub Actions — weekly automated update + PR
```

---

## Output files

### `output/adblock.json`

WKContentRuleList JSON compiled from:

- EasyList network filters
- AdGuard Base, Social, Annoyances, and Mobile filters (Safari-specific builds)
- uBlock Origin unbreak rules (exceptions only)

### `output/trackers.json`

WKContentRuleList JSON compiled from:

- EasyPrivacy
- AdGuard Tracking Protection filter (Safari-specific build)
- Peter Lowe's Ad and tracking server list

### `output/exceptions.json`

WKContentRuleList `ignore-previous-rules` entries for sites whose first-party APIs overlap with tracker patterns (Google Workspace, YouTube, Kahoot, StatCounter, DownDetector).

### `output/cosmetic.js`

WKUserScript injected at `document_start`. It:

1. Stubs anti-adblock detection APIs (`window.canRunAds`, `adsbygoogle`, `googletag`, bait element spoofing)
2. Injects CSS `display: none` rules for known ad containers
3. Installs a `MutationObserver` that hides dynamically injected ad nodes
4. Applies YouTube-specific cosmetic hiding (ad slots, masthead, overlay ads)

### `output/scriptlets.js`

WKUserScript injected at `document_start`. Implements uBO-style scriptlets (`set-constant`, `no-fetch-if`, `no-xhr-if`, `prevent-setTimeout`, etc.) with per-domain configs extracted from upstream filter lists.

### `output/tracker_stubs.js`

WKUserScript injected at `document_start`. Silently no-ops the JS APIs of:
Google Analytics, Facebook Pixel, Mixpanel, Amplitude, Hotjar, Heap, FullStory,
Segment, Intercom, Drift, TikTok Pixel, Pinterest Tag, Criteo, Twitter Pixel,
Snapchat Pixel, LinkedIn Insight, Microsoft Clarity, Mouseflow.

### `output/websocket_block.js`

WKUserScript injected at `document_start`. Blocks WebSocket connections to known tracker domains and prevents WebRTC IP leaks.

### Sidecar data files

- `cosmetic_domains.json` — per-domain CSS selectors for site-specific cosmetic filtering
- `scriptlet_rules.json` — per-domain scriptlet configs for browser-side injection
- `removeparam_rules.json` — URL tracking parameter stripping rules
- `redirect_rules.json` — surrogate resource mappings for `$redirect` rules

---

## Running the build

Requirements: **macOS** with **Swift 5.9+** (Xcode Command Line Tools).

```
cd src/BuildTool && swift run
```

The build tool will:

1. Fetch EasyList, EasyPrivacy, AdGuard (Base, Tracking, Social, Annoyances, Mobile), Peter Lowe's, and uBlock unbreak from their canonical URLs
2. Convert all filters to WKContentRuleList JSON via SafariConverterLib
3. Add safe-site exception rules for YouTube, Kahoot, StatCounter, and Google Workspace
4. Generate JS output files (cosmetic hiding, scriptlets, tracker stubs, WebSocket blocking)
5. Write all output files

The legacy Python pipeline (`python src/build.py`) is kept as a reference but is no longer used by CI.

---

## Automated weekly updates

`.github/workflows/update-lists.yml` runs every Sunday at 02:00 UTC. It:

1. Runs `cd src/BuildTool && swift run` on `macos-latest`
2. Checks whether any output file changed
3. If so, opens a pull request on the `chore/update-filter-lists` branch with a diff summary and rule counts

You can also trigger it manually from the **Actions** tab.

---

## Swift integration (quick start)

Full code is in [`output/SWIFT_INTEGRATION.md`](output/SWIFT_INTEGRATION.md). The one-minute version:

```swift
// 1. Compile and attach content rule lists.
let store = WKContentRuleListStore.default()!
let adList      = try await store.compileContentRuleList(forIdentifier: "emerald.adblock",
                      encodedContentRuleList: adblockJSON)
let trackerList = try await store.compileContentRuleList(forIdentifier: "emerald.trackers",
                      encodedContentRuleList: trackersJSON)
config.userContentController.add(adList)
config.userContentController.add(trackerList)

// 2. Inject user scripts at document start.
for source in [cosmeticJS, scriptletsJS, trackerStubsJS, websocketBlockJS] {
    config.userContentController.addUserScript(
        WKUserScript(source: source, injectionTime: .atDocumentStart, forMainFrameOnly: false)
    )
}
```

---

## License

See [LICENSE](LICENSE).
