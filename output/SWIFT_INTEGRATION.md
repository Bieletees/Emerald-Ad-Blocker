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

Both JS files must run *before* any page script; use `.atDocumentStart` and inject into `.allFrames` so iframes are covered too.

```swift
import WebKit

extension WKUserContentController {

    /// Add all Emerald user-scripts.
    func addEmeraldScripts() {
        for filename in ["cosmetic", "tracker_stubs"] {
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

Add the call into your configuration builder:

```swift
func makeWebViewConfiguration() async throws -> WKWebViewConfiguration {
    let config = WKWebViewConfiguration()
    // … attach rule lists (see section 1) …
    config.userContentController.addEmeraldScripts()
    return config
}
```

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
class BrowserViewController: UIViewController {

    private var webView: WKWebView!

    override func viewDidLoad() {
        super.viewDidLoad()
        Task { await setUp() }
    }

    private func setUp() async {
        let config = (try? await makeWebViewConfiguration()) ?? WKWebViewConfiguration()
        webView = WKWebView(frame: view.bounds, configuration: config)
        webView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
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

        // 2. User scripts.
        config.userContentController.addEmeraldScripts()

        return config
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
