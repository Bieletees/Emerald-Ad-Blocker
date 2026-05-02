# Browser-Side Recommendations for Emerald

This file collects improvements that require changes inside the browser itself
(not just to the filter lists). Each section includes a concrete description of
what to implement, why it matters, and a minimal Swift code sketch.

These are filed here rather than as issues in a closed-source repo so they can
be discussed openly and tracked alongside the filter list work.

---

## 1. Inject scriptlets.js at documentStart (highest impact)

**What:** Add `output/scriptlets.js` as a third `WKUserScript` alongside the
two that already exist.

**Why:** The scriptlet engine intercepts `fetch()`, `XMLHttpRequest`, property
reads/writes, and timer callbacks *before any page script runs*. This is how
uBO disarms anti-adblock walls on sites like Forbes, Wired, and GQ that survive
pure network blocking.

```swift
// Injection order matters — scriptlets must run first.
for filename in ["scriptlets", "tracker_stubs", "cosmetic"] {
    guard
        let url    = Bundle.main.url(forResource: filename, withExtension: "js"),
        let source = try? String(contentsOf: url, encoding: .utf8)
    else { continue }

    config.userContentController.addUserScript(
        WKUserScript(source: source,
                     injectionTime: .atDocumentStart,
                     forMainFrameOnly: false)
    )
}
```

---

## 2. URL tracking parameter stripping

**What:** Before a navigation commits, strip known tracking query parameters
(`fbclid`, `gclid`, `utm_*`, `mc_eid`, `igshid`, `twclid`, `ttclid`,
`msclkid`, `_ga`, `ref_`, `s_kwcid`) from the URL.

**Why:** These parameters survive network blocking entirely — they're in the
URL, not a network request. Stripping them also prevents cross-site tracking
via shared links.

```swift
import WebKit

private let trackingParams: Set<String> = [
    "fbclid", "gclid", "dclid", "gbraid", "wbraid",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_source_platform", "utm_creative_format", "utm_marketing_tactic",
    "mc_eid", "mc_cid",
    "igshid",
    "twclid",
    "ttclid",
    "msclkid",
    "_ga", "_gl",
    "ref_", "ref",
    "s_kwcid",
    "mkt_tok",
    "oly_enc_id", "oly_anon_id",
    "vero_id",
    "__s",
    "hsa_acc", "hsa_cam", "hsa_grp", "hsa_ad", "hsa_src",
    "hsa_tgt", "hsa_kw", "hsa_mt", "hsa_net", "hsa_ver",
]

extension WKNavigationDelegate {

    func stripTrackingParams(from url: URL) -> URL? {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let items = components.queryItems,
              items.contains(where: { trackingParams.contains($0.name.lowercased()) })
        else { return nil }  // nil = nothing to strip, use original

        components.queryItems = items.filter {
            !trackingParams.contains($0.name.lowercased())
        }.nonEmpty

        return components.url
    }
}

// In your WKNavigationDelegate:
func webView(_ webView: WKWebView,
             decidePolicyFor action: WKNavigationAction,
             decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {

    if let original = action.request.url,
       let clean    = stripTrackingParams(from: original) {
        decisionHandler(.cancel)
        webView.load(URLRequest(url: clean))
        return
    }
    decisionHandler(.allow)
}

private extension Array {
    var nonEmpty: [Element]? { isEmpty ? nil : self }
}
```

---

## 3. Per-site scriptlet injection (advanced uBO parity)

**What:** Filter lists contain thousands of site-specific `+js()` rules like:

```
forbes.com##+js(set-constant, adsbygoogle.loaded, true)
wired.com##+js(prevent-setTimeout, adblock)
```

Right now `scriptlets.js` only applies the *generic* (wildcard) subset.
To run site-specific scriptlets, the browser needs to inject a small
per-domain script before `document_start`.

**Why:** This closes the biggest remaining gap with uBO. Forbes, Wired,
GQ, and many other paywalled/ad-walled sites are only defeatable with
the right site-specific scriptlet.

**Approach:**

1. The build pipeline can emit a `output/scriptlet_rules.json` — a mapping
   of `hostname → [[scriptlet_name, arg, ...], ...]`.

2. The browser reads this file at startup and, when navigating to `host`,
   generates a one-off `WKUserScript` with the right `run()` calls.

```swift
// Pseudocode — load at app start
let scriptletRules: [String: [[String]]] =
    JSONDecoder().decode(from: Bundle.main.url(forResource: "scriptlet_rules", withExtension: "json")!)

// In your WKNavigationDelegate decidePolicyFor:
if let host    = action.request.url?.host,
   let configs = scriptletRules[host] ?? scriptletRules["*.\(host)"] {

    let calls = configs.map { cfg in
        let args = cfg.dropFirst().map { "\"\($0)\"" }.joined(separator: ", ")
        return "run(\"\(cfg[0])\", [\(args)]);"
    }.joined(separator: "\n")

    let source = """
    (function(){
      \(scriptletEngineSource)   // inline or load from scriptlets.js
      \(calls)
    })();
    """

    let script = WKUserScript(source: source,
                               injectionTime: .atDocumentStart,
                               forMainFrameOnly: true)
    webView.configuration.userContentController.addUserScript(script)
}
```

> **Note:** `WKUserScript` objects added after the `WKWebView` is created
> only apply to *subsequent* navigations. Build this into the
> `decidePolicyFor` flow, not `viewDidLoad`.

---

## 4. CNAME uncloaking

**What:** Some trackers disguise themselves as first-party subdomains using
CNAME records, e.g. `metrics.yoursite.com → tracker.hotjar.com`. WKWebView
does not expose the resolved CNAME to `WKNavigationDelegate` by default.

**Why:** Blocks an entire class of tracking that network rules completely miss.

**Approach:** Apple added `_WKWebsitePolicies` CNAME cloaking protection in
Safari 14 / iOS 14. In a custom browser you can enable it via the private
`WKWebsiteDataStore` API, or implement your own DNS resolver in
`WKURLSchemeHandler` for `http://` (HTTPS interception requires a root cert
which App Store apps cannot install).

A pragmatic alternative: use the **AdGuard DNS** or **NextDNS** DoH endpoint
as a system-level DNS override in the app's network configuration — this
handles CNAME uncloaking at the DNS layer without any custom code.

---

## 5. Auto-update without an App Store release

**What:** Fetch fresh `adblock.json`, `trackers.json`, `cosmetic.js`, and
`scriptlets.js` from this repo's `main` branch on a background schedule,
recompile the content rule lists, and apply them without requiring an update.

**Why:** The GitHub Action in this repo publishes updated lists weekly.
Without auto-update, users only get new rules when they update the app.

The full Swift code for this is already in
[`output/SWIFT_INTEGRATION.md`](output/SWIFT_INTEGRATION.md) — section 4.

---

## 6. Cosmetic filter feedback loop

**What:** When a user long-presses an element and selects "Block this element",
generate a CSS selector for it, add it to a local user-rules list, and inject
it via `WKUserScript` on subsequent visits to that domain.

**Why:** This is the "element picker" feature in uBO and is one of the most
requested features in any ad blocker. It doesn't require any filter list
changes — it's purely a browser UI + local storage feature.

**Approach:**

1. Inject a JS listener that activates on a custom URL scheme message
   (`emerald://pick-element`).
2. When the user taps, highlight elements under the finger, generate a
   CSS selector (using `element.id`, `element.className`, tag + nth-child).
3. Store `{domain: "example.com", selector: ".ad-banner"}` in UserDefaults
   or a local SQLite file.
4. At `decidePolicyFor`, build a `WKUserScript` that hides all stored
   selectors for the current domain.

---

## Summary of effort vs. impact

| Recommendation | Effort | Impact |
|---|---|---|
| Inject scriptlets.js | Trivial (add one line) | Very high — closes anti-adblock gap |
| URL param stripping | Low (one delegate method) | High — stops link tracking |
| Per-site scriptlets | Medium (JSON + dynamic script) | Very high — Forbes/Wired level |
| CNAME uncloaking | High | Medium — niche but real |
| Auto-update | Low (already documented) | High — keeps users protected |
| Element picker | High | Very high — user delight |
