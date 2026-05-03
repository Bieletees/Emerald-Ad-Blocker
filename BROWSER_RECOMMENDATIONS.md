# Browser-Side Recommendations for Emerald

Everything below requires changes **inside the Emerald app itself** — the
filter list pipeline (`src/build.py`) already handles the rest.

## Output files from the v3 pipeline

| File | What it is | How the browser uses it |
|---|---|---|
| `output/adblock.json` | Network ad-blocking rules | Compile as `WKContentRuleList` |
| `output/trackers.json` | Tracker/analytics rules | Compile as `WKContentRuleList` |
| `output/exceptions.json` | Exception/unbreak rules | Compile as `WKContentRuleList` (attach last) |
| `output/cosmetic.js` | CSS hiding + anti-adblock stubs + `:has-text()` filters | Inject as `WKUserScript` at `documentStart` |
| `output/scriptlets.js` | uBO-style scriptlet engine (25+ scriptlets) | Inject as `WKUserScript` at `documentStart` |
| `output/scriptlet_rules.json` | Per-domain scriptlet configs | Load at startup, inject per-navigation |
| `output/redirect_rules.json` | `$redirect` mappings (pattern → stub resource) | Serve stubs via `WKURLSchemeHandler` |
| `output/removeparam_rules.json` | `$removeparam` rules (param names + URL patterns) | Strip params in `decidePolicyFor:` |
| `output/websocket_block.js` | WebSocket/WebRTC/sendBeacon blocking | Inject as `WKUserScript` at `documentStart` |
| `output/tracker_stubs.js` | JS API stubs for 20+ tracker SDKs | Inject as `WKUserScript` at `documentStart` |

---

## 1. Inject all four user scripts

Injection order matters — scriptlets and websocket blocking must run
before page scripts. Cosmetic last so it sees the final DOM.

```swift
// Read JS files once at startup, keep in memory
private var userScriptSources: [(String, String)] = []

func loadUserScripts() {
    for filename in ["scriptlets", "websocket_block", "tracker_stubs", "cosmetic"] {
        guard
            let url    = Bundle.main.url(forResource: filename, withExtension: "js"),
            let source = try? String(contentsOf: url, encoding: .utf8)
        else { continue }
        userScriptSources.append((filename, source))
    }
}

func attachUserScripts(to config: WKWebViewConfiguration) {
    for (_, source) in userScriptSources {
        config.userContentController.addUserScript(
            WKUserScript(source: source,
                         injectionTime: .atDocumentStart,
                         forMainFrameOnly: false)
        )
    }
}
```

---

## 2. Compile three WKContentRuleLists with caching

Compile once, cache by identifier. Only recompile when the JSON changes.
This makes subsequent launches instant.

```swift
let store = WKContentRuleListStore.default()!

struct RuleListConfig {
    let identifier: String
    let filename: String
}

let ruleListConfigs = [
    RuleListConfig(identifier: "emerald.adblock",    filename: "adblock"),
    RuleListConfig(identifier: "emerald.trackers",   filename: "trackers"),
    RuleListConfig(identifier: "emerald.exceptions", filename: "exceptions"),  // must be last
]

func loadContentRuleLists(into config: WKWebViewConfiguration) async {
    for rlConfig in ruleListConfigs {
        // Try cached first
        if let cached = try? await store.lookUpContentRuleList(
            forIdentifier: rlConfig.identifier
        ) {
            config.userContentController.add(cached)
            continue
        }

        // Not cached — compile from JSON
        guard
            let url  = Bundle.main.url(forResource: rlConfig.filename, withExtension: "json"),
            let json = try? String(contentsOf: url, encoding: .utf8),
            let list = try? await store.compileContentRuleList(
                forIdentifier: rlConfig.identifier,
                encodedContentRuleList: json
            )
        else { continue }

        config.userContentController.add(list)
    }
}
```

Three rule lists = **447,000 rule capacity** (3× Safari's limit).

To force recompilation after an auto-update, remove the cached list
first:

```swift
func invalidateCache(identifier: String) async {
    try? await store.removeContentRuleList(forIdentifier: identifier)
}
```

---

## 3. Loading speed optimizations

### 3a. Background compilation

Never block the main thread on rule list compilation. Let the WebView
load immediately with whatever is cached, then update in the background.

```swift
func setupWebView() -> WKWebView {
    let config = WKWebViewConfiguration()

    // Attach JS scripts synchronously (they're small, already in memory)
    attachUserScripts(to: config)

    let webView = WKWebView(frame: .zero, configuration: config)

    // Compile rule lists in background — they'll apply to subsequent navigations
    Task {
        await loadContentRuleLists(into: config)
    }

    return webView
}
```

### 3b. Hash-based recompilation

Only recompile when the JSON actually changes. Store a hash in
UserDefaults.

```swift
import CryptoKit

func needsRecompile(filename: String, identifier: String) -> Bool {
    guard
        let url  = Bundle.main.url(forResource: filename, withExtension: "json"),
        let data = try? Data(contentsOf: url)
    else { return false }

    let hash = SHA256.hash(data: data).description
    let key  = "emerald.rulehash.\(identifier)"

    if UserDefaults.standard.string(forKey: key) == hash {
        return false  // same content, skip compilation
    }

    UserDefaults.standard.set(hash, forKey: key)
    return true
}
```

### 3c. Lazy JS file loading

Read all JS files once at app start into memory. Don't re-read from
disk on every tab or navigation.

```swift
// In AppDelegate or similar — call once
func applicationDidFinishLaunching() {
    loadUserScripts()  // reads 4 JS files into userScriptSources array
}
```

---

## 4. Per-site scriptlet injection

The pipeline emits `output/scriptlet_rules.json` — a mapping of
`{hostname: [[scriptlet_name, arg, ...], ...]}`. Load at startup,
inject matching configs on each navigation.

```swift
let scriptletRules: [String: [[String]]] = {
    guard let url = Bundle.main.url(forResource: "scriptlet_rules", withExtension: "json"),
          let data = try? Data(contentsOf: url),
          let rules = try? JSONDecoder().decode([String: [[String]]].self, from: data)
    else { return [:] }
    return rules
}()

func injectSiteScriptlets(for host: String, into controller: WKUserContentController) {
    // Check exact host, then parent domain
    let configs = scriptletRules[host]
        ?? scriptletRules[String(host.drop(while: { $0 != "." }).dropFirst())]
    guard let configs, !configs.isEmpty else { return }

    let calls = configs.map { cfg in
        let name = cfg[0]
        let args = cfg.dropFirst()
            .map { "\"\($0.replacingOccurrences(of: "\"", with: "\\\""))\"" }
        return "run(\"\(name)\", [\(args.joined(separator: ", "))]);"
    }.joined(separator: "\n")

    controller.addUserScript(
        WKUserScript(source: "(function(){ \(calls) })();",
                     injectionTime: .atDocumentStart,
                     forMainFrameOnly: true)
    )
}
```

This defeats anti-adblock walls on Forbes, Wired, Business Insider, and
hundreds of other sites.

---

## 5. URL tracking parameter stripping + $removeparam

The pipeline emits `output/removeparam_rules.json` with param names and
URL patterns from upstream filter lists. Combine these with the hardcoded
tracking params for comprehensive coverage.

```swift
// Load $removeparam rules from pipeline output
struct RemoveParamRule: Decodable {
    let param: String
    let pattern: String?
    let domains: [String]?
    let exception: Bool?
}

let removeParamRules: [RemoveParamRule] = {
    guard let url = Bundle.main.url(forResource: "removeparam_rules", withExtension: "json"),
          let data = try? Data(contentsOf: url),
          let rules = try? JSONDecoder().decode([RemoveParamRule].self, from: data)
    else { return [] }
    return rules
}()

// Hardcoded high-value tracking params (always stripped)
private let trackingParams: Set<String> = [
    "gclid", "dclid", "gbraid", "wbraid", "_ga", "_gl", "gclsrc",
    "fbclid", "fb_action_ids", "fb_action_types", "fb_ref", "fb_source",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_source_platform", "utm_creative_format", "utm_marketing_tactic",
    "mc_eid", "mc_cid", "mkt_tok", "oly_enc_id", "oly_anon_id", "vero_id", "__s",
    "igshid", "twclid", "ttclid", "msclkid",
    "hsa_acc", "hsa_cam", "hsa_grp", "hsa_ad", "hsa_src",
    "hsa_tgt", "hsa_kw", "hsa_mt", "hsa_net", "hsa_ver",
    "s_kwcid", "si", "wickedid", "li_fat_id",
]

func stripTrackingParams(from url: URL) -> URL? {
    guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false),
          let items = components.queryItems
    else { return nil }

    // Merge hardcoded params with $removeparam rules applicable to this URL
    var paramsToStrip = trackingParams
    let urlStr = url.absoluteString
    for rule in removeParamRules {
        if rule.exception == true { continue }
        if let pattern = rule.pattern, !urlStr.contains(pattern) { continue }
        paramsToStrip.insert(rule.param)
    }

    guard items.contains(where: { paramsToStrip.contains($0.name.lowercased()) })
    else { return nil }

    let cleaned = items.filter { !paramsToStrip.contains($0.name.lowercased()) }
    components.queryItems = cleaned.isEmpty ? nil : cleaned
    return components.url
}

// In decidePolicyFor:
func webView(_ webView: WKWebView,
             decidePolicyFor action: WKNavigationAction,
             decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
    if let original = action.request.url,
       let clean = stripTrackingParams(from: original) {
        decisionHandler(.cancel)
        webView.load(URLRequest(url: clean))
        return
    }
    decisionHandler(.allow)
}
```

---

## 6. Redirect engine via WKURLSchemeHandler

The pipeline emits `output/redirect_rules.json` mapping URL patterns to
uBO redirect resource names. Instead of blocking these URLs and breaking
sites, serve local no-op stubs.

```swift
class RedirectStubHandler: NSObject, WKURLSchemeHandler {

    // Map uBO resource names to stub JS/content
    private let stubs: [String: (String, String)] = [  // (content, mimeType)
        // Script stubs
        "noopjs":                              ("void 0;", "application/javascript"),
        "noop.js":                             ("void 0;", "application/javascript"),
        "google-analytics_analytics.js":       (gaStub, "application/javascript"),
        "google-analytics.com/analytics.js":   (gaStub, "application/javascript"),
        "google-analytics_ga.js":              (gaStub, "application/javascript"),
        "google-analytics.com/ga.js":          (gaStub, "application/javascript"),
        "googlesyndication_adsbygoogle.js":    (adsByGoogleStub, "application/javascript"),
        "googlesyndication.com/adsbygoogle.js":(adsByGoogleStub, "application/javascript"),
        "googletagmanager_gtm.js":             (gtmStub, "application/javascript"),
        "googletagservices_gpt.js":            (gptStub, "application/javascript"),
        "scorecardresearch_beacon.js":         ("void 0;", "application/javascript"),
        "amazon_ads.js":                       ("void 0;", "application/javascript"),
        "outbrain-widget.js":                  ("void 0;", "application/javascript"),
        "fingerprint2.js":                     ("void 0;", "application/javascript"),
        "fingerprint3.js":                     ("void 0;", "application/javascript"),
        // Image stubs
        "1x1.gif":                             (gifB64, "image/gif"),
        "2x2.png":                             (pngB64, "image/png"),
        "noopimage":                           (gifB64, "image/gif"),
        // Frame/text stubs
        "noopframe":                           ("<html><body></body></html>", "text/html"),
        "noop.html":                           ("<html><body></body></html>", "text/html"),
        "nooptext":                            ("", "text/plain"),
        "noop.txt":                            ("", "text/plain"),
        "empty":                               ("", "text/plain"),
    ]

    func webView(_ webView: WKWebView, start task: WKURLSchemeTask) {
        guard let url = task.request.url,
              let stubName = url.host,
              let (content, mime) = stubs[stubName]
        else {
            task.didFailWithError(URLError(.fileDoesNotExist))
            return
        }

        let data = content.data(using: .utf8) ?? Data()
        let response = URLResponse(url: url, mimeType: mime,
                                    expectedContentLength: data.count,
                                    textEncodingName: "utf-8")
        task.didReceive(response)
        task.didReceive(data)
        task.didFinish()
    }

    func webView(_ webView: WKWebView, stop task: WKURLSchemeTask) {}
}

// Stub content constants
private let gaStub = """
window.ga=window.ga||function(){(ga.q=ga.q||[]).push(arguments)};
ga.l=+new Date;window.GoogleAnalyticsObject='ga';
"""
private let adsByGoogleStub = """
window.adsbygoogle=window.adsbygoogle||[];
window.adsbygoogle.loaded=true;
window.adsbygoogle.push=function(){};
"""
private let gtmStub = """
window.dataLayer=window.dataLayer||[];
function gtag(){dataLayer.push(arguments);}
"""
private let gptStub = "void 0;"
private let gifB64 = "R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw=="
private let pngB64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQABNjN9GQA..."

// Register during WKWebView setup
let config = WKWebViewConfiguration()
config.setURLSchemeHandler(RedirectStubHandler(), forURLScheme: "emerald-stub")
```

To use: when a request matches a pattern in `redirect_rules.json`,
cancel the original request and load `emerald-stub://RESOURCE_NAME`
instead.

---

## 7. Auto-update filter lists

Fetch fresh output files from this repo's `main` branch daily.
Invalidate the cached rule lists and recompile on next launch.

```swift
class FilterListUpdater {
    private let baseURL = "https://raw.githubusercontent.com/Bieletees/Emerald-Ad-Blocker/main/output/"
    private let files = ["adblock.json", "trackers.json", "exceptions.json",
                         "cosmetic.js", "scriptlets.js", "tracker_stubs.js",
                         "websocket_block.js", "scriptlet_rules.json",
                         "redirect_rules.json", "removeparam_rules.json"]

    func updateIfNeeded() async {
        let lastUpdate = UserDefaults.standard.object(forKey: "lastFilterUpdate") as? Date ?? .distantPast
        guard Date().timeIntervalSince(lastUpdate) > 86400 else { return }  // once per day

        let destDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Filters")
        try? FileManager.default.createDirectory(at: destDir, withIntermediateDirectories: true)

        for file in files {
            guard let url = URL(string: baseURL + file) else { continue }
            do {
                let (data, _) = try await URLSession.shared.data(from: url)
                try data.write(to: destDir.appendingPathComponent(file))
            } catch {
                print("Failed to update \(file): \(error)")
            }
        }

        // Invalidate cached rule lists so they recompile on next launch
        let store = WKContentRuleListStore.default()!
        for id in ["emerald.adblock", "emerald.trackers", "emerald.exceptions"] {
            try? await store.removeContentRuleList(forIdentifier: id)
        }

        UserDefaults.standard.set(Date(), forKey: "lastFilterUpdate")
    }
}
```

---

## 8. Per-site whitelist toggle

```swift
func whitelistDomain(_ domain: String) async throws {
    let rule = """
    [{"trigger":{"url-filter":".*","if-domain":["*\(domain)"]},
      "action":{"type":"ignore-previous-rules"}}]
    """
    let store = WKContentRuleListStore.default()!
    if let list = try? await store.compileContentRuleList(
        forIdentifier: "emerald.whitelist", encodedContentRuleList: rule
    ) {
        webView.configuration.userContentController.add(list)
    }

    // Persist
    var whitelist = UserDefaults.standard.stringArray(forKey: "whitelistedDomains") ?? []
    if !whitelist.contains(domain) {
        whitelist.append(domain)
        UserDefaults.standard.set(whitelist, forKey: "whitelistedDomains")
    }
}
```

---

## 9. Cookie banner auto-dismiss

```swift
let cookieBannerScript = """
(function() {
    'use strict';
    var observer = new MutationObserver(function() {
        var reject = document.querySelector('#onetrust-reject-all-handler')
            || document.querySelector('.ot-pc-refuse-all-handler')
            || document.querySelector('#CybotCookiebotDialogBodyButtonDecline')
            || document.querySelector('.coi-banner__reject')
            || document.querySelector('.qc-cmp2-summary-buttons button:first-child');
        if (reject) { reject.click(); observer.disconnect(); return; }

        var banners = document.querySelectorAll(
            '#cookie-banner, #cookie-consent, #gdpr-banner, ' +
            '.cookie-banner, .cookie-consent, .gdpr-banner, ' +
            '#CybotCookiebotDialog, #onetrust-banner-sdk, ' +
            '.qc-cmp2-container, #usercentrics-root'
        );
        banners.forEach(function(el) { el.style.setProperty('display', 'none', 'important'); });
        document.documentElement.style.overflow = '';
        document.body.style.overflow = '';
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(function() { observer.disconnect(); }, 10000);
})();
"""
```

---

## 10. Element picker

Long-press → highlight → "Block this" → persist the CSS selector per
domain in UserDefaults → inject as `WKUserScript` on subsequent visits.

---

## 11. Blocking stats badge

Show a shield icon with a count of blocked requests per page. Track in
`decidePolicyFor:` and display in the toolbar.

---

## Effort vs. impact

| # | Recommendation | Effort | Impact |
|---|---|---|---|
| 1 | Inject all four scripts | Trivial | Very high |
| 2 | Three cached WKContentRuleLists | Trivial | High |
| 3 | Loading speed optimizations | Low | High |
| 4 | Per-site scriptlets | Medium | Very high |
| 5 | URL param stripping + $removeparam | Low | High |
| 6 | Redirect engine (WKURLSchemeHandler) | Medium | High |
| 7 | Auto-update | Low | High |
| 8 | Whitelist toggle | Low | High |
| 9 | Cookie banner dismiss | Medium | Very high |
| 10 | Element picker | High | Very high |
| 11 | Blocking stats | Medium | High |

## What this covers vs. uBO MV2

With all recommendations implemented, Emerald reaches ~90% of uBO MV2
parity. The remaining ~10% is:

- `$csp` / `$permissions` — HTTP header injection (impossible in WebKit)
- HTML filtering — response body modification (impossible in WebKit)
- Full procedural cosmetic filter syntax (`:xpath()`, `:matches-css()` —
  implementable in JS but not yet in the pipeline)
- Dynamic filtering matrix UI (possible but high effort)

Everything else — network blocking, exception rules, domain-restricted
filters, scriptlets, cosmetic hiding, `:has-text()`, `$redirect`,
`$removeparam`, `$badfilter`, WebSocket blocking, anti-adblock bypass —
is handled by the pipeline and the recommendations above.
