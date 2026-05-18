# Emerald Ad Blocker

A WKContentRuleList-based ad and tracker blocker for iOS/macOS browsers built on WebKit.  Rules are compiled from [EasyList](https://easylist.to/), [EasyPrivacy](https://easylist.to/), [uBlock Origin](https://github.com/uBlockOrigin/uAssets), AdGuard, and [Peter Lowe's list](https://pgl.yoyo.org/adservers/), then merged with a hand-curated baseline and written as ready-to-use JSON + JavaScript files.

---

## Repository layout

```
Emerald-Ad-Blocker/
├── Files/                      # Hand-curated baseline rules (source of truth)
│   ├── adblock.json            #   Ad-network block rules
│   └── trackers.json           #   Tracker/analytics block rules
│
├── src/
│   └── build.py                # Build pipeline — run this to regenerate output/
│
├── output/                     # Generated files — bundle these in your app
│   ├── adblock.json            #   WKContentRuleList (ads)
│   ├── trackers.json           #   WKContentRuleList (trackers)
│   ├── cosmetic.js             #   WKUserScript — CSS hiding + anti-adblock stubs
│   ├── tracker_stubs.js        #   WKUserScript — silently stubs tracker JS APIs
│   ├── ytadblocker.js          #   WKUserScript — YouTube ad blocker
│   └── SWIFT_INTEGRATION.md   #   Full Swift wiring guide
│
└── .github/
    └── workflows/
        └── update-lists.yml    # GitHub Actions — weekly automated update + PR
```

---

## Output files

### `output/adblock.json`
WKContentRuleList JSON compiled from:
- Hand-curated `Files/adblock.json` (CDN-bug-fixed, deduplicated)
- EasyList network filters
- uBlock Origin network filters

### `output/trackers.json`
WKContentRuleList JSON compiled from:
- Hand-curated `Files/trackers.json` (fixed, deduplicated)
- EasyPrivacy
- Peter Lowe's Ad and tracking server list

### `output/cosmetic.js`
WKUserScript injected at `document_start`.  It:
1. Stubs anti-adblock detection APIs (`window.canRunAds`, `adsbygoogle`, `googletag`)
2. Injects CSS `display: none` rules for known ad containers using EasyList cosmetic selectors
3. Installs a `MutationObserver` that hides dynamically injected ad nodes

### `output/tracker_stubs.js`
WKUserScript injected at `document_start`.  Silently no-ops the JS APIs of:
Google Analytics, Facebook Pixel, Mixpanel, Amplitude, Hotjar, Heap, FullStory,
Segment, Intercom, Drift, TikTok Pixel, Pinterest Tag, Criteo, Twitter Pixel,
Snapchat Pixel, LinkedIn Insight, Microsoft Clarity, Mouseflow, Lucky Orange,
VWO, Optimizely, Braze.

### `output/ytadblocker.js`
WKUserScript injected at `document_start`.  It blocks the following:
Video and Shorts ads,
Suggestion ads,
YouTube ad tracking.

### `output/SWIFT_INTEGRATION.md`
Step-by-step Swift code showing how to:
- Compile and attach the two content rule lists
- Inject both user scripts at `documentStart`
- Implement a per-site whitelist toggle
- Auto-update lists in the background

---

## Running the build

Requirements: **Python 3.11+**, standard library only (no third-party packages).

```bash
python src/build.py
```

The script will:
1. Load `Files/adblock.json` and `Files/trackers.json`
2. Remove CDN-blocking false positives (`cloudflare.com`, `fastly.net`, `gstatic.com`, `akamaized.net`, broad `amazonaws.com`)
3. Remove non-ad-network entries (`vimeo.com`, `wistia.com`, `disqus.com`, `aarp.org`, …)
4. Deduplicate (~40 duplicate rules in the originals)
5. Fetch EasyList, EasyPrivacy, uBlock, and Peter Lowe's list from their canonical URLs
6. Convert ABP/uBlock filter syntax to WKContentRuleList JSON
7. Merge, deduplicate, and cap at the 149 000-rule WebKit limit
8. Write `output/adblock.json`, `output/trackers.json`, and `output/cosmetic.js`

Expected output:

```
=== Loading original hand-curated rules ===
  adblock.json : 185 rules
  trackers.json: 7 rules

=== Fixing original rules ===
  adblock.json → removed 1 CDN rules, 1 non-ad-network rules, 40 duplicates → 143 kept
  ...

=== Fetching upstream filter lists ===
  Fetching easylist … OK (...)
  ...

=== Writing output files ===
  Wrote output/adblock.json
  Wrote output/trackers.json
  Wrote output/cosmetic.js

=== Done ✓ ===
```

---

## Automated weekly updates

`.github/workflows/update-lists.yml` runs every Sunday at 02:00 UTC.  It:
1. Runs `python src/build.py`
2. Checks whether any output file changed
3. If so, opens a pull request on the `chore/update-filter-lists` branch with a diff summary and rule counts

You can also trigger it manually from the **Actions** tab.

---

## Swift integration (quick start)

Full code is in [`output/SWIFT_INTEGRATION.md`](output/SWIFT_INTEGRATION.md).  The one-minute version:

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
for source in [cosmeticJS, trackerStubsJS] {
    config.userContentController.addUserScript(
        WKUserScript(source: source, injectionTime: .atDocumentStart, forMainFrameOnly: false)
    )
}
```

---

## License

See [LICENSE](LICENSE).
