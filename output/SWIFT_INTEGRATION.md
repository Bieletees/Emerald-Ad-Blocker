# Emerald Ad Blocker — Swift Integration Guide

This guide covers wiring every output file from the build pipeline into a WKWebView-based iOS/macOS browser.

---

## Output files

| File | What it is |
|---|---|
| `output/adblock.json` | WKContentRuleList — blocks ad-network requests |
| `output/trackers.json` | WKContentRuleList — blocks tracker/analytics requests |
| `output/cosmetic.js` | WKUserScript — CSS hiding + anti-adblock API stubs |
| `output/tracker_stubs.js` | WKUserScript — silently stubs tracker JS APIs |
| `output/ytadblock.js` | WKUserScript — YouTube ad blocker |
| `output/block_sources.json` | Domain → filter-list mapping for blocked-URL notifications |

---

## Blocked URL notification page ⚠️ Requires browser-side implementation

`output/block_sources.json` maps every blocked domain to the human-readable
filter list(s) that block it (e.g. `"doubleclick.net": ["EasyList", "Peter Lowe's Ad and tracking server list"]`).

The **block page UI must be implemented in your browser app** — the build pipeline
only provides the data file.  A complete reference implementation is in
`TestApp/Sources/EmeraldTestBrowser/main.swift`.  The key pieces are:

### 1. Load the mapping at startup

```swift
let path = Bundle.main.url(forResource: "block_sources", withExtension: "json")!
let data = try! Data(contentsOf: path)
let blockSources = try! JSONDecoder().decode([String: [String]].self, from: data)
```

### 2. Register a script message handler for "Proceed anyway"

```swift
// In your WKWebViewConfiguration setup:
config.userContentController.add(self, name: "proceedToURL")
```

### 3. Implement `decidePolicyFor` in your `WKNavigationDelegate`

```swift
// Hosts the user chose to visit despite being blocked (session-only)
var bypassedHosts: Set<String> = []

func webView(_ webView: WKWebView,
             decidePolicyFor action: WKNavigationAction,
             decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
    guard action.targetFrame?.isMainFrame == true,
          let url  = action.request.url,
          let host = url.host else { decisionHandler(.allow); return }

    if bypassedHosts.contains(host.lowercased()) { decisionHandler(.allow); return }

    guard let lists = findBlockLists(for: host, in: blockSources) else {
        decisionHandler(.allow); return
    }
    decisionHandler(.cancel)
    showBlockPage(url: url, lists: lists, in: webView)
}

/// Walk from the full hostname up to the eTLD+1 looking for a match.
func findBlockLists(for host: String, in sources: [String: [String]]) -> [String]? {
    var parts = host.lowercased().components(separatedBy: ".")
    while parts.count >= 2 {
        if let lists = sources[parts.joined(separator: ".")] { return lists }
        parts.removeFirst()
    }
    return nil
}
```

### 4. Render the block page HTML

```swift
func showBlockPage(url: URL, lists: [String], in webView: WKWebView) {
    let safeURL = url.absoluteString
        .replacingOccurrences(of: "&", with: "&amp;")
        .replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: "\"", with: "&quot;")
    let items = lists.map { "<li>\($0)</li>" }.joined(separator: "\n")
    let html = """
    <!DOCTYPE html><html><head><meta charset="utf-8">
    <title>Page Blocked — Emerald</title>
    <style>
    body{font-family:-apple-system,sans-serif;background:#1a1a2e;color:#eee;
         display:flex;align-items:center;justify-content:center;min-height:100vh}
    .card{background:#16213e;border:1px solid #0f3460;border-radius:12px;
          max-width:600px;width:90%;padding:2rem;text-align:center}
    h1{color:#e94560;margin:.5rem 0 1rem}
    .url{font-family:monospace;background:#0f3460;padding:.6rem;border-radius:6px;
         word-break:break-all;color:#a8d8ea;margin-bottom:1rem}
    ul{list-style:none;text-align:left}
    li{background:#0f3460;border-left:3px solid #e94560;padding:.4rem .8rem;
       margin:.3rem 0;border-radius:0 4px 4px 0}
    .proceed{margin-top:1rem;padding:.5rem 1.2rem;background:none;
             border:1px solid #445;border-radius:6px;color:#667;cursor:pointer}
    .proceed:hover{border-color:#e94560;color:#e94560}
    </style></head><body>
    <div class="card">
      <div style="font-size:3rem">🛡</div>
      <h1>Page Blocked by Emerald</h1>
      <div class="url">\(safeURL)</div>
      <p>Appears in:</p><ul>\(items)</ul>
      <button class="proceed"
        onclick="window.webkit.messageHandlers.proceedToURL.postMessage('\(url.absoluteString)')">
        Proceed anyway
      </button>
    </div></body></html>
    """
    webView.loadHTMLString(html, baseURL: nil)
}
```

### 5. Handle the "Proceed anyway" message

```swift
// WKScriptMessageHandler
func userContentController(_ ucc: WKUserContentController,
                            didReceive message: WKScriptMessage) {
    guard message.name == "proceedToURL",
          let urlString = message.body as? String,
          let url = URL(string: urlString),
          let host = url.host else { return }
    bypassedHosts.insert(host.lowercased())   // allow for rest of session
    webView.load(URLRequest(url: url))
}
```

The bypass is **session-only** — it clears when the browser restarts, so the block page reappears on the next launch.  If you want persistence, save `bypassedHosts` to `UserDefaults`.

---

## 1. Loading WKContentRuleList rules

Bundle `adblock.json` and `trackers.json` in your app target, then compile and attach them at `WKWebViewConfiguration` time.  Compilation is cached by WebKit; subsequent launches that pass the same `identifier` are nearly free if the JSON has not changed.

```swift
import WebKit

actor RuleListStore {

    static let shared = RuleListStore()
    private let store = WKContentRuleListStore.default()!

    /// Compile (or load from cache) one rule list from a bundled JSON file.
    func ruleList(identifier: String, jsonFile: String) async throws -> WKContentRuleList {
        // Try cache first.
        if let cached = try? await store.contentRuleList(forIdentifier: identifier) {
            return cached
        }
        guard
            let url = Bundle.main.url(forResource: jsonFile, withExtension: "json"),
            let json = try? String(contentsOf: url, encoding: .utf8)
        else {
            throw URLError(.fileDoesNotExist)
        }
        return try await store.compileContentRuleList(
            forIdentifier: identifier,
            encodedContentRuleList: json
        )
    }
}
```

### Attaching at launch

```swift
func makeWebViewConfiguration() async throws -> WKWebViewConfiguration {
    let config = WKWebViewConfiguration()

    async let adList     = RuleListStore.shared.ruleList(identifier: "emerald.adblock",  jsonFile: "adblock")
    async let trackList  = RuleListStore.shared.ruleList(identifier: "emerald.trackers", jsonFile: "trackers")

    let (ads, trackers) = try await (adList, trackList)
    config.userContentController.add(ads)
    config.userContentController.add(trackers)

    return config
}
```

> **Tip:** Keep a strong reference to each `WKContentRuleList` and re-attach after a list update so you only recompile what changed.

---

## 2. Injecting WKUserScripts at documentStart

**Core scripts** run on every page and must be injected at `.atDocumentStart`.
**`ytadblock.js`** is 230 KB+ and should **only** be injected on YouTube domains.
Injecting it on every page forces WebKit to parse 230 KB of JavaScript on every
navigation, which noticeably slows page loads on sites like Kahoot.

```swift
import WebKit

extension WKUserContentController {

    /// Add the lightweight Emerald scripts (runs on every page).
    func addEmeraldScripts() {
        for filename in ["scriptlets", "tracker_stubs", "websocket_block", "cosmetic"] {
            guard
                let url    = Bundle.main.url(forResource: filename, withExtension: "js"),
                let source = try? String(contentsOf: url, encoding: .utf8)
            else { continue }

            let script = WKUserScript(
                source: source,
                injectionTime: .atDocumentStart,
                forMainFrameOnly: false          // also covers iframes
            )
            add(script)
        }
    }
}
```

### YouTube-only injection for ytadblock.js

`ytadblock.js` must only be injected on YouTube pages. Add and remove it
dynamically based on the navigation URL:

```swift
class BrowserController {

    private var ytScript: WKUserScript?
    private var ytInjected = false

    /// Call once at startup to load the script source.
    func loadYTScript() {
        guard let url = Bundle.main.url(forResource: "ytadblock", withExtension: "js"),
              let src = try? String(contentsOf: url, encoding: .utf8) else { return }
        ytScript = WKUserScript(source: src, injectionTime: .atDocumentStart,
                                forMainFrameOnly: true)
    }

    /// Call from webView(_:didStartProvisionalNavigation:) or
    /// webView(_:decidePolicyFor:) with the navigating URL.
    func updateYTScript(for url: URL?, ucc: WKUserContentController) {
        guard let script = ytScript else { return }
        let isYT = url?.host.map { host in
            host.hasSuffix("youtube.com") || host.hasSuffix("youtubekids.com")
        } ?? false

        if isYT && !ytInjected {
            ucc.addUserScript(script)
            ytInjected = true
        } else if !isYT && ytInjected {
            let others = ucc.userScripts.filter { $0 !== script }
            ucc.removeAllUserScripts()
            others.forEach { ucc.addUserScript($0) }
            ytInjected = false
        }
    }
}
```

> **Why this matters:** `ytadblock.js` contains the full vBlockTube userscript
> (~230 KB). Even though a domain guard at the top skips execution on non-YouTube
> pages, the JavaScript engine must still **parse** the entire file on every
> injection. Conditional injection eliminates this overhead entirely.

---

## 3. Per-site whitelist toggle

A whitelist is implemented with an `ignore-previous-rules` action scoped to specific domains.  Compile one dynamic list per whitelisted domain and attach/remove it at will — no need to recompile the base lists.

```swift
/// Build a WKContentRuleList that cancels all blocking for `host`.
func whitelistRuleList(for host: String, store: WKContentRuleListStore) async throws -> WKContentRuleList {
    let rule: [String: Any] = [
        "trigger": [
            "url-filter": ".*",
            "if-domain": [host]
        ],
        "action": ["type": "ignore-previous-rules"]
    ]
    let json = try String(
        data: JSONSerialization.data(withJSONObject: [rule]),
        encoding: .utf8
    )!
    return try await store.compileContentRuleList(
        forIdentifier: "emerald.whitelist.\(host)",
        encodedContentRuleList: json
    )
}

// Toggle ON — add whitelist rule for the current site.
func enableWhitelist(for webView: WKWebView, host: String) async throws {
    let list = try await whitelistRuleList(for: host, store: WKContentRuleListStore.default()!)
    webView.configuration.userContentController.add(list)
}

// Toggle OFF — remove it.
func disableWhitelist(for webView: WKWebView, host: String) {
    // Removing by identifier requires keeping a reference or storing them in a dict.
    // Simplest approach: remove all and re-attach base lists.
    Task {
        let ucc = webView.configuration.userContentController
        ucc.removeAllContentRuleLists()
        if let ads  = try? await RuleListStore.shared.ruleList(identifier: "emerald.adblock",  jsonFile: "adblock"),
           let trk  = try? await RuleListStore.shared.ruleList(identifier: "emerald.trackers", jsonFile: "trackers") {
            ucc.add(ads)
            ucc.add(trk)
        }
    }
}
```

### Persisting the whitelist

```swift
// Store whitelisted hosts in UserDefaults (or your own store).
var whitelistedHosts: Set<String> {
    get { Set(UserDefaults.standard.stringArray(forKey: "emerald.whitelist") ?? []) }
    set { UserDefaults.standard.set(Array(newValue), forKey: "emerald.whitelist") }
}
```

---

## 4. Auto-update logic

Check the GitHub repository for a new `adblock.json` / `trackers.json` on a background schedule (e.g., at app launch if > 7 days since last check).

```swift
import Foundation
import WebKit

struct ListUpdater {

    private static let baseURL = "https://raw.githubusercontent.com/<your-org>/Emerald-Ad-Blocker/main/output/"
    private static let files   = ["adblock", "trackers"]

    /// Download fresh lists and recompile into the WKContentRuleListStore.
    static func updateIfNeeded() async {
        let defaults = UserDefaults.standard
        let lastCheck = defaults.double(forKey: "emerald.lastListUpdate")
        let sevenDays: TimeInterval = 7 * 24 * 3_600

        guard Date().timeIntervalSince1970 - lastCheck > sevenDays else { return }

        let store = WKContentRuleListStore.default()!

        await withTaskGroup(of: Void.self) { group in
            for file in files {
                group.addTask {
                    guard
                        let url  = URL(string: "\(baseURL)\(file).json"),
                        let json = try? String(contentsOf: url, encoding: .utf8)
                    else { return }

                    _ = try? await store.compileContentRuleList(
                        forIdentifier: "emerald.\(file)",
                        encodedContentRuleList: json
                    )
                }
            }
        }

        defaults.set(Date().timeIntervalSince1970, forKey: "emerald.lastListUpdate")
    }
}
```

Call it from your `AppDelegate` or `App.init`:

```swift
Task.detached(priority: .background) {
    await ListUpdater.updateIfNeeded()
}
```

> **Note:** Replace `<your-org>` with the actual GitHub organisation/user name. If you ship the lists bundled rather than fetching them remotely, you can skip this section and rely solely on App Store updates.

---

## 5. Full configuration example

```swift
@MainActor
class BrowserViewController: UIViewController, WKNavigationDelegate {

    private var webView: WKWebView!
    private var ytScript: WKUserScript?
    private var ytInjected = false

    override func viewDidLoad() {
        super.viewDidLoad()
        Task { await setUp() }
    }

    private func setUp() async {
        let config = (try? await makeWebViewConfiguration()) ?? WKWebViewConfiguration()
        webView = WKWebView(frame: view.bounds, configuration: config)
        webView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        webView.navigationDelegate = self
        view.addSubview(webView)
        webView.load(URLRequest(url: URL(string: "https://example.com")!))
    }

    private func makeWebViewConfiguration() async throws -> WKWebViewConfiguration {
        let config = WKWebViewConfiguration()

        // 1. Content rule lists.
        async let adList    = RuleListStore.shared.ruleList(identifier: "emerald.adblock",  jsonFile: "adblock")
        async let trackList = RuleListStore.shared.ruleList(identifier: "emerald.trackers", jsonFile: "trackers")
        let (ads, trackers) = try await (adList, trackList)
        config.userContentController.add(ads)
        config.userContentController.add(trackers)

        // 2. Core user scripts (lightweight, every page).
        config.userContentController.addEmeraldScripts()

        // 3. YouTube ad blocker (heavy, YouTube only).
        if let url = Bundle.main.url(forResource: "ytadblock", withExtension: "js"),
           let src = try? String(contentsOf: url, encoding: .utf8) {
            ytScript = WKUserScript(source: src, injectionTime: .atDocumentStart,
                                    forMainFrameOnly: true)
        }

        return config
    }

    // MARK: — YouTube script injection

    func webView(_ webView: WKWebView, didStartProvisionalNavigation _: WKNavigation!) {
        guard let script = ytScript else { return }
        let isYT = webView.url?.host.map { host in
            host.hasSuffix("youtube.com") || host.hasSuffix("youtubekids.com")
        } ?? false
        let ucc = webView.configuration.userContentController

        if isYT && !ytInjected {
            ucc.addUserScript(script)
            ytInjected = true
        } else if !isYT && ytInjected {
            let others = ucc.userScripts.filter { $0 !== script }
            ucc.removeAllUserScripts()
            others.forEach { ucc.addUserScript($0) }
            ytInjected = false
        }
    }

    // MARK: — Whitelist toggle (call from your UI)

    func toggleWhitelist(for host: String, enabled: Bool) {
        if enabled {
            Task { try? await enableWhitelist(for: webView, host: host) }
        } else {
            disableWhitelist(for: webView, host: host)
        }
        // Persist.
        var hosts = whitelistedHosts
        if enabled { hosts.insert(host) } else { hosts.remove(host) }
        whitelistedHosts = hosts
    }
}
```

---

## 6. Notes on WKContentRuleList limits

| Limit | Value |
|---|---|
| Rules per compiled list | 150 000 |
| Compiled lists per `WKWebView` | Unlimited (additive) |
| Regex engine | ICU (RE2-compatible; no look-ahead/behind) |
| Compilation | Async; cache keyed on `identifier` + JSON hash |

The build pipeline enforces a 149 000-rule cap per file to leave headroom.

---

## 7. Testing the integration

1. Open Safari → Developer menu → enable the Web Inspector for Simulator.
2. Load a page with known ads (e.g. a news site).
3. In the Console, run `window.canRunAds` — should return `true` (stub active).
4. In the Network tab, verify `doubleclick.net` requests show as blocked.
5. Inspect the DOM — ad container `div`s should have `display: none`.
