/// Emerald Ad Blocker — Build Tool (Swift + SafariConverterLib)
///
/// Single-command build that generates ALL output files:
///   - adblock.json, trackers.json, annoyances.json, exceptions.json (via SafariConverterLib)
///   - cosmetic.js, scriptlets.js, websocket_block.js, tracker_stubs.js
///   - scriptlet_rules.json, cosmetic_domains.json
///   - redirect_rules.json, removeparam_rules.json
///
/// Usage:
///   cd src/BuildTool && swift run
///
/// Runs on macOS with Swift 5.9+ (Xcode Command Line Tools).
/// Also runs on GitHub Actions with `runs-on: macos-latest`.

import Foundation
import ContentBlockerConverter
import CommonCrypto

// MARK: - Configuration

let projectRoot: URL = {
    let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    for candidate in [cwd, cwd.deletingLastPathComponent(), cwd.deletingLastPathComponent().deletingLastPathComponent()] {
        if FileManager.default.fileExists(atPath: candidate.appendingPathComponent("Files").path) {
            return candidate
        }
    }
    return cwd.deletingLastPathComponent().deletingLastPathComponent()
}()

let outputDir = projectRoot.appendingPathComponent("output")
let cacheDir = projectRoot.appendingPathComponent(".cache")
let filesDir = projectRoot.appendingPathComponent("Files")

struct FilterList {
    let name: String
    let url: String
    let category: Category
    enum Category { case ads, trackers, annoyances, removeparam }
}

let filterLists: [FilterList] = [
    .init(name: "easylist", url: "https://easylist.to/easylist/easylist.txt", category: .ads),
    .init(name: "easyprivacy", url: "https://easylist.to/easylist/easyprivacy.txt", category: .trackers),
    .init(name: "peter_lowe", url: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&mimetype=plaintext", category: .trackers),
    .init(name: "adguard_base", url: "https://filters.adtidy.org/extension/safari/filters/2.txt", category: .ads),
    .init(name: "adguard_tracking", url: "https://filters.adtidy.org/extension/safari/filters/3.txt", category: .trackers),
    .init(name: "adguard_social", url: "https://filters.adtidy.org/extension/safari/filters/4.txt", category: .annoyances),
    .init(name: "adguard_annoyances", url: "https://filters.adtidy.org/extension/safari/filters/14.txt", category: .annoyances),
    .init(name: "adguard_mobile", url: "https://filters.adtidy.org/extension/safari/filters/11.txt", category: .ads),
    .init(name: "adguard_url_tracking", url: "https://filters.adtidy.org/android/filters/17.txt", category: .removeparam),
    .init(name: "ublock_unbreak", url: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt", category: .ads),
]

// MARK: - Fetching with cache

func fetchList(_ list: FilterList) -> String {
    print("  Fetching \(list.name) …", terminator: " ")

    let cacheFile = cacheDir.appendingPathComponent("\(list.name).txt")
    let hashFile = cacheDir.appendingPathComponent("\(list.name).sha256")

    guard let url = URL(string: list.url) else { print("INVALID URL"); return "" }

    var request = URLRequest(url: url, timeoutInterval: 45)
    request.setValue("EmeraldAdBlocker/4.0 build-tool", forHTTPHeaderField: "User-Agent")

    let semaphore = DispatchSemaphore(value: 0)
    var result = ""

    URLSession.shared.dataTask(with: request) { data, _, error in
        defer { semaphore.signal() }
        if let error = error {
            if let cached = try? String(contentsOf: cacheFile, encoding: .utf8) {
                result = cached
                print("FAILED — using cached (\(cached.count) bytes)")
            } else {
                print("FAILED — \(error.localizedDescription)")
            }
            return
        }
        guard let data = data, let text = String(data: data, encoding: .utf8) else {
            print("FAILED — no data"); return
        }
        result = text
        try? FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
        let newHash = sha256(data)
        let oldHash = (try? String(contentsOf: hashFile, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if newHash == oldHash {
            print("OK (unchanged, \(text.count) bytes)")
        } else {
            try? text.write(to: cacheFile, atomically: true, encoding: .utf8)
            try? newHash.write(to: hashFile, atomically: true, encoding: .utf8)
            print("OK (updated, \(text.count) bytes)")
        }
    }.resume()
    semaphore.wait()
    return result
}

// MARK: - Rule conversion via SafariConverterLib

func convertAndWrite(rules: [String], outputName: String) -> Int {
    let converter = ContentBlockerConverter()
    let result = converter.convertArray(
        rules: rules,
        safariVersion: .safari16_4,
        advancedBlocking: false,
        maxJsonSizeBytes: nil,
        progress: nil
    )

    // Parse the JSON, strip non-ASCII rules, append first-party exception
    var finalJSON = result.safariRulesJSON
    var ruleCount = result.safariRulesCount

    if let jsonData = finalJSON.data(using: .utf8),
       var rulesArray = try? JSONSerialization.jsonObject(with: jsonData) as? [[String: Any]] {

        // Strip rules with non-ASCII in url-filter or selector
        let beforeCount = rulesArray.count
        rulesArray = rulesArray.filter { rule in
            let trigger = rule["trigger"] as? [String: Any] ?? [:]
            let action = rule["action"] as? [String: Any] ?? [:]
            let urlFilter = trigger["url-filter"] as? String ?? ""
            let selector = action["selector"] as? String ?? ""
            return urlFilter.allSatisfy(\.isASCII) && selector.allSatisfy(\.isASCII)
        }
        let stripped = beforeCount - rulesArray.count
        if stripped > 0 {
            print("    Stripped \(stripped) rules with non-ASCII characters")
        }

        // Append first-party exception at the end — only for resource types
        // sites need to function (document, script, CSS, font, fetch, etc.)
        // but NOT images or media, so first-party ad banners still get blocked.
        rulesArray.append([
            "trigger": [
                "url-filter": ".*",
                "load-type": ["first-party"],
                "resource-type": ["document", "script", "style-sheet", "font", "fetch", "raw", "websocket", "ping", "popup"]
            ],
            "action": ["type": "ignore-previous-rules"]
        ])

        // Re-block common ad URL patterns AFTER the ignore-previous-rules entry.
        // Rules placed after ignore-previous-rules are not suppressed by it,
        // so these will block even first-party ad fetches that the exception
        // above would otherwise unblock.
        //
        // Patterns are conservative to avoid false positives:
        //   - Path segments that only appear in ad delivery endpoints
        //   - Known ad script filenames served as first-party proxied resources
        //   - Tracking pixel endpoints (1x1 GIF/PNG paths)
        //
        // WKContentRuleList regex subset: no lookahead/lookbehind, ASCII only.
        let adReblockPatterns: [(urlFilter: String, resourceTypes: [String])] = [
            // Ad delivery path segments
            ("/ads/",              ["script", "fetch", "raw", "image"]),
            ("/advert/",          ["script", "fetch", "raw", "image"]),
            ("/banner/",          ["script", "fetch", "raw", "image"]),
            ("/banners/",         ["script", "fetch", "raw", "image"]),
            ("/ad-server/",       ["script", "fetch", "raw"]),
            ("/adserver/",        ["script", "fetch", "raw"]),
            ("/adservice/",       ["script", "fetch", "raw"]),
            ("/pagead/",          ["script", "fetch", "raw"]),
            // Known first-party-proxied ad script filenames
            ("/adsbygoogle\\.js", ["script"]),
            ("/gpt\\.js",         ["script"]),
            ("/prebid\\.js",      ["script"]),
            // Tracking pixel patterns (1x1 images, impression beacons)
            ("/pixel\\.gif",      ["image", "fetch", "raw"]),
            ("/pixel\\.png",      ["image", "fetch", "raw"]),
            ("/1\\.gif",          ["image", "fetch", "raw"]),
            ("/tracking\\.gif",   ["image", "fetch", "raw"]),
            ("/impression\\.gif", ["image", "fetch", "raw"]),
            ("/beacon\\.gif",     ["image", "fetch", "raw"]),
        ]

        for pattern in adReblockPatterns {
            rulesArray.append([
                "trigger": [
                    "url-filter": pattern.urlFilter,
                    "resource-type": pattern.resourceTypes
                ],
                "action": ["type": "block"]
            ])
        }

        // Kahoot blanket exception — kahoot.it makes cross-origin API calls
        // to kahoot.com backends which WebKit treats as third-party.
        rulesArray.append([
            "trigger": [
                "url-filter": ".*",
                "if-domain": ["*kahoot.it", "*kahoot.com"]
            ],
            "action": ["type": "ignore-previous-rules"]
        ])

        // Microsoft blanket exception — Microsoft's sign-in flow (OAuth/OIDC)
        // chains across login.microsoftonline.com, login.live.com,
        // accounts.microsoft.com, and microsoft.com. Any blocked request in
        // this chain causes the redirect loop where the user is asked to sign
        // in again immediately after doing so.
        rulesArray.append([
            "trigger": [
                "url-filter": ".*",
                "if-domain": [
                    "*microsoftonline.com",
                    "*microsoft.com",
                    "*live.com",
                    "*bing.com",
                    "*msftauth.net",
                    "*msecnd.net",
                    "*msauth.net",
                    "*office.com",
                    "*office365.com",
                    "*sharepoint.com",
                    "*outlook.com",
                    "*windows.net",
                    "*azure.com",
                    "*azurewebsites.net"
                ]
            ],
            "action": ["type": "ignore-previous-rules"]
        ])

        ruleCount = rulesArray.count

        if let outputData = try? JSONSerialization.data(withJSONObject: rulesArray, options: []),
           let outputString = String(data: outputData, encoding: .utf8) {
            finalJSON = outputString
        }
    }

    let path = outputDir.appendingPathComponent(outputName)
    try? finalJSON.write(to: path, atomically: true, encoding: .utf8)

    let size = (try? Data(contentsOf: path).count) ?? 0
    print("  Wrote output/\(outputName) (\(ruleCount) rules, \(size / 1024) KB)")

    if result.errorsCount > 0 {
        print("    ⚠ \(result.errorsCount) conversion errors (rules skipped)")
    }

    return ruleCount
}

// MARK: - JS File Generation

func extractSiteScriptlets(from allTexts: [String: String]) -> [String: [[String]]] {
    var siteScriptlets: [String: [[String]]] = [:]
    for text in allTexts.values {
        for line in text.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.contains("##+js(") else { continue }
            let jsParts = trimmed.components(separatedBy: "##+js(")
            guard jsParts.count == 2 else { continue }
            let domainPart = jsParts[0].trimmingCharacters(in: .whitespaces)
            guard !domainPart.isEmpty, domainPart != "*" else { continue }
            var scriptlet = jsParts[1]
            if scriptlet.hasSuffix(")") { scriptlet.removeLast() }
            let args = scriptlet.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            for domain in domainPart.components(separatedBy: ",") {
                let d = domain.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "*."))
                guard !d.isEmpty else { continue }
                if siteScriptlets[d] == nil { siteScriptlets[d] = [] }
                siteScriptlets[d]?.append(args)
            }
        }
    }
    return siteScriptlets
}

func writeJSFiles(allTexts: [String: String], siteScriptlets: [String: [[String]]]) {
    // cosmetic.js — bundled in the repo, not regenerated here
    // (the template is complex and maintained manually)
    // Just copy it from the existing output if present, or skip.

    // scriptlets.js — same, maintained via template
    // websocket_block.js — same
    // tracker_stubs.js — same

    // What we CAN generate: the sidecar JSON files

    // cosmetic_domains.json — per-domain CSS selectors
    var domainSelectors: [String: [String]] = [:]
    for text in allTexts.values {
        for line in text.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.contains("##"), !trimmed.hasPrefix("!"), !trimmed.hasPrefix("@@") else { continue }
            let parts = trimmed.components(separatedBy: "##")
            guard parts.count == 2 else { continue }
            let domainPart = parts[0].trimmingCharacters(in: .whitespaces)
            let selector = parts[1].trimmingCharacters(in: .whitespaces)
            guard !domainPart.isEmpty, domainPart != "*", !selector.isEmpty else { continue }
            guard !selector.contains(":-abp-"), !selector.contains(":has-text(") else { continue }
            for domain in domainPart.components(separatedBy: ",") {
                let d = domain.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "~*."))
                guard !d.isEmpty else { continue }
                if domainSelectors[d] == nil { domainSelectors[d] = [] }
                if (domainSelectors[d]?.count ?? 0) < 200 {
                    domainSelectors[d]?.append(selector)
                }
            }
        }
    }
    let domainCosmeticPath = outputDir.appendingPathComponent("cosmetic_domains.json")
    if let data = try? JSONSerialization.data(withJSONObject: domainSelectors, options: []) {
        try? data.write(to: domainCosmeticPath)
        print("  Wrote output/cosmetic_domains.json (\(domainSelectors.count) domains)")
    }

    // scriptlet_rules.json — write the passed-in siteScriptlets
    let scriptletRulesPath = outputDir.appendingPathComponent("scriptlet_rules.json")
    if let data = try? JSONSerialization.data(withJSONObject: siteScriptlets, options: []) {
        try? data.write(to: scriptletRulesPath)
        print("  Wrote output/scriptlet_rules.json (\(siteScriptlets.count) domains)")
    }

    // removeparam_rules.json
    var removeparamRules: [[String: Any]] = []
    for text in allTexts.values {
        for line in text.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.contains("removeparam"), trimmed.contains("$") else { continue }
            guard !trimmed.hasPrefix("!"), !trimmed.hasPrefix("[") else { continue }
            let isException = trimmed.hasPrefix("@@")
            let cleaned = isException ? String(trimmed.dropFirst(2)) : trimmed
            guard let dollarIdx = cleaned.lastIndex(of: "$") else { continue }
            let options = String(cleaned[cleaned.index(after: dollarIdx)...])
            for opt in options.components(separatedBy: ",") {
                let o = opt.trimmingCharacters(in: .whitespaces)
                if o.hasPrefix("removeparam=") {
                    let param = String(o.dropFirst("removeparam=".count))
                    guard !param.hasPrefix("/") else { continue }
                    var entry: [String: Any] = ["param": param]
                    if isException { entry["exception"] = true }
                    removeparamRules.append(entry)
                }
            }
        }
    }
    let removeparamPath = outputDir.appendingPathComponent("removeparam_rules.json")
    if let data = try? JSONSerialization.data(withJSONObject: removeparamRules, options: []) {
        try? data.write(to: removeparamPath)
        print("  Wrote output/removeparam_rules.json (\(removeparamRules.count) rules)")
    }

    // redirect_rules.json
    var redirectRules: [[String: Any]] = []
    for text in allTexts.values {
        for line in text.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.contains("redirect=") || trimmed.contains("redirect-rule=") else { continue }
            guard trimmed.contains("$"), !trimmed.hasPrefix("!"), !trimmed.hasPrefix("@@") else { continue }
            guard let dollarIdx = trimmed.lastIndex(of: "$") else { continue }
            let pattern = String(trimmed[..<dollarIdx])
            let options = String(trimmed[trimmed.index(after: dollarIdx)...])
            var resource: String?
            for opt in options.components(separatedBy: ",") {
                let o = opt.trimmingCharacters(in: .whitespaces)
                if o.hasPrefix("redirect=") { resource = String(o.dropFirst("redirect=".count)) }
                if o.hasPrefix("redirect-rule=") { resource = String(o.dropFirst("redirect-rule=".count)) }
            }
            if let r = resource, !r.isEmpty {
                redirectRules.append(["pattern": pattern, "resource": r])
            }
        }
    }
    let redirectPath = outputDir.appendingPathComponent("redirect_rules.json")
    if let data = try? JSONSerialization.data(withJSONObject: redirectRules, options: []) {
        try? data.write(to: redirectPath)
        print("  Wrote output/redirect_rules.json (\(redirectRules.count) rules)")
    }
}

// MARK: - Main

print("\n╔══════════════════════════════════════════════════════════════╗")
print("║  Emerald Ad Blocker — Build Tool (SafariConverterLib)       ║")
print("╚══════════════════════════════════════════════════════════════╝\n")

try? FileManager.default.createDirectory(at: outputDir, withIntermediateDirectories: true)

// Fetch all lists
print("=== Fetching upstream filter lists ===")
var allTexts: [String: String] = [:]
var adRules: [String] = []
var trackerRules: [String] = []
var annoyancesRules: [String] = []

for list in filterLists {
    let text = fetchList(list)
    guard !text.isEmpty else { continue }
    allTexts[list.name] = text

    let lines = text.components(separatedBy: "\n")
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .filter { !$0.isEmpty && !$0.hasPrefix("[") }

    switch list.category {
    case .ads:
        adRules.append(contentsOf: lines)
    case .trackers:
        trackerRules.append(contentsOf: lines)
    case .annoyances:
        annoyancesRules.append(contentsOf: lines)
    case .removeparam:
        break // handled in writeJSFiles
    }
}

print("\n  Total: \(adRules.count) ad rules, \(trackerRules.count) tracker rules, \(annoyancesRules.count) annoyances rules\n")

// MARK: - Custom blocking rules
// ABP-format rules for domains not covered (or under-covered) by the
// upstream filter lists (EasyList, AdGuard Base Safari, EasyPrivacy).
// These are appended to adRules before conversion so SafariConverterLib
// compiles them into the WKContentRuleList JSON alongside upstream rules.
let customBlockRules: [String] = [
    // ── Microsoft / Bing ads ──────────────────────────────────────────────
    // bat.bing.com: Bing Ads Universal Event Tracking (UET) beacon
    // bingads.microsoft.com: Bing Ads API / JS SDK loader
    // ads.microsoft.com: Microsoft Advertising portal CDN assets
    "||bat.bing.com^",
    "||bingads.microsoft.com^",
    "||ads.microsoft.com^",

    // ── Unity Ads ─────────────────────────────────────────────────────────
    // Covers auction, webview, config, adserver, and any future subdomains.
    "||unityads.unity3d.com^",

    // ── Yahoo / Verizon Media ads ─────────────────────────────────────────
    "||gemini.yahoo.com^",
    "||ads.host.yahooinc.com^",
    "||udcm.yahoo.com^",
    "||log.fc.yahoo.com^",
    "||adtech.yahooinc.com^",

    // ── TikTok ads ────────────────────────────────────────────────────────
    // ads-api: TikTok for Business API
    // ads-sg: Southeast-Asia ad delivery endpoint
    // business-api: TikTok Business Center API
    "||ads-api.tiktok.com^",
    "||ads-sg.tiktok.com^",
    "||business-api.tiktok.com^",

    // ── Apple iAd / AdServices ────────────────────────────────────────────
    // iadsdk: Legacy iAd SDK used in hybrid/WebView apps
    // api-adservices: SKAdNetwork attribution API (privacy-preserving but still tracking)
    "||iadsdk.apple.com^",
    "||api-adservices.apple.com^",

    // ── Facebook Audience Network ─────────────────────────────────────────
    "||an.facebook.com^",

    // ── Dynamic Yield ─────────────────────────────────────────────────────
    // A/B testing + personalisation platform used for ad targeting.
    "||cdn.dynamicyield.com^",

    // ── JW Player ad serving ──────────────────────────────────────────────
    "||g.jwpsrv.com^",
    "||ssl.p.jwpcdn.com^",

    // ── Impact (affiliate / conversion tracking) ──────────────────────────
    "||impact.com^",
    "||ad.impact.com^",

    // ── FingerprintJS ────────────────────────────────────────────────────
    // Browser fingerprinting-as-a-service, used for ad fraud detection
    // and cross-site identity linking.
    "||fingerprintjs.com^",

    // ── The Trade Desk ────────────────────────────────────────────────────
    // Demand-side platform (programmatic ad buying).
    "||thetradedesk.com^",

    // ── Kochava (mobile attribution / tracking) ───────────────────────────
    "||kochava.com^",
    "||control.kochava.com^",

    // ── Oppo OEM tracking ─────────────────────────────────────────────────
    "||data.ads.oppomobile.com^",
    "||adx.ads.oppomobile.com^",
    "||ck.ads.oppomobile.com^",
    "||adsfs.oppomobile.com^",

    // ── Realme OEM tracking ───────────────────────────────────────────────
    "||bdapi-ads.realmemobile.com^",
    "||bdapi-in-ads.realmemobile.com^",

    // ── Yandex analytics / AppMetrica ─────────────────────────────────────
    "||appmetrica.yandex.ru^",
    "||metrika.yandex.ru^",

    // ── VK ads ───────────────────────────────────────────────────────────
    "||ads.vk.com^",

    // ── Quora tracking pixel ──────────────────────────────────────────────
    "||pixel.quora.com^",
]
print("  Adding \(customBlockRules.count) custom blocking rules")
adRules.append(contentsOf: customBlockRules)

// Add safe-site exception rules for sites whose APIs match tracker patterns.
//
// SCOPING POLICY: Every exception MUST carry a $domain= qualifier that limits
// it to the Microsoft/partner property where the resource is legitimately
// needed. Unscoped exceptions (no $domain=) would whitelist the host globally
// and silently cancel out customBlockRules entries for ad/tracking subdomains
// like bat.bing.com, bingads.microsoft.com, and ads.microsoft.com.
//
// The Microsoft blanket if-domain exception appended in convertAndWrite() is
// intentionally kept for WKContentRuleList (it fires only when the *page* is
// on a Microsoft domain), but the ABP-format safeExceptions here must all be
// domain-scoped so they don't leak into third-party contexts.
let safeExceptions = [
    // First-party exception is injected directly into JSON (SafariConverterLib
    // rejects wildcard exceptions as "too wide"). See convertAndWrite().

    // StatCounter — own domain matches tracker patterns in EasyPrivacy
    "@@||statcounter.com^$domain=statcounter.com",
    "@@||*.statcounter.com^$domain=statcounter.com",

    // Kahoot — own domains + required third-party dependencies
    "@@||kahoot.it^$domain=kahoot.it|kahoot.com",
    "@@||kahoot.com^$domain=kahoot.it|kahoot.com",
    "@@||cdn.amplitude.com^$domain=kahoot.it|kahoot.com",
    "@@||api.amplitude.com^$domain=kahoot.it|kahoot.com",
    "@@||amplitude.com^$domain=kahoot.it|kahoot.com",
    "@@||googletagmanager.com/gtm.js$domain=kahoot.it|kahoot.com",
    "@@||sentry.io^$domain=kahoot.it|kahoot.com",
    "@@||hotjar.com^$domain=kahoot.it|kahoot.com",
    "@@||hotjar.io^$domain=kahoot.it|kahoot.com",
    "@@||onetrust.com^$domain=kahoot.it|kahoot.com",
    "@@||accounts.google.com^$domain=kahoot.it|kahoot.com",

    // YouTube — ad blocking handled by ytadblock.js, don't block infra
    "@@||googlevideo.com^$domain=youtube.com|youtu.be|music.youtube.com",
    "@@||ytimg.com^$domain=youtube.com|youtu.be|music.youtube.com",
    "@@||ggpht.com^$domain=youtube.com|youtu.be|music.youtube.com",
    "@@||youtube.com^$domain=youtube.com|music.youtube.com",
    "@@||googleapis.com^$domain=youtube.com|youtu.be|music.youtube.com",

    // Google Workspace — needs Google's own infrastructure (cross-domain)
    "@@||googleapis.com^$domain=docs.google.com|sheets.google.com|slides.google.com|drive.google.com|mail.google.com|calendar.google.com|meet.google.com|accounts.google.com",
    "@@||gstatic.com^$domain=docs.google.com|sheets.google.com|slides.google.com|drive.google.com|mail.google.com|calendar.google.com|meet.google.com|accounts.google.com",
    "@@||google.com^$domain=docs.google.com|sheets.google.com|slides.google.com|drive.google.com|mail.google.com|calendar.google.com|meet.google.com|accounts.google.com",

    // Microsoft MakeCode — depends on Application Insights telemetry for functionality
    "@@||dc.services.visualstudio.com^$domain=makecode.com|makecode.microbit.org|arcade.makecode.com|pxt.io",

    // Microsoft sign-in & core infrastructure — scoped to Microsoft-owned domains only.
    //
    // IMPORTANT: bat.bing.com, bingads.microsoft.com, and ads.microsoft.com are
    // intentionally NOT whitelisted here. They are third-party ad/tracking hosts
    // that must remain blocked on non-Microsoft sites. The $domain= list below
    // covers only the Microsoft properties where the sign-in chain and core
    // product functionality legitimately require these requests.
    //
    // microsoftonline.com — OAuth/OIDC token endpoint, needed on all MS properties
    "@@||microsoftonline.com^$domain=microsoft.com|microsoftonline.com|live.com|outlook.com|office.com|office365.com|sharepoint.com|bing.com|msn.com|xbox.com|azure.com",
    // login.live.com / account.live.com — Microsoft Account (MSA) sign-in
    "@@||live.com^$domain=microsoft.com|microsoftonline.com|live.com|outlook.com|office.com|office365.com|sharepoint.com|bing.com",
    // msftauth.net — Microsoft federated auth CDN (ESTS)
    "@@||msftauth.net^$domain=microsoft.com|microsoftonline.com|live.com|outlook.com|office.com|office365.com|sharepoint.com|bing.com",
    // msecnd.net — Microsoft CDN for auth pages and Office assets
    "@@||msecnd.net^$domain=microsoft.com|microsoftonline.com|live.com|outlook.com|office.com|office365.com|sharepoint.com|bing.com",
    // msauth.net — Microsoft auth redirect helper
    "@@||msauth.net^$domain=microsoft.com|microsoftonline.com|live.com|outlook.com|office.com|office365.com|sharepoint.com|bing.com",
    // windows.net — Azure Storage / Azure AD tenant endpoints used by M365
    "@@||windows.net^$domain=microsoft.com|microsoftonline.com|azure.com|office.com|office365.com|sharepoint.com",
    // azure.com — Azure portal and resource endpoints
    "@@||azure.com^$domain=microsoft.com|microsoftonline.com|azure.com|office.com|office365.com",
    // azurewebsites.net — Azure-hosted first-party Microsoft web apps
    "@@||azurewebsites.net^$domain=microsoft.com|microsoftonline.com|azure.com|office.com|office365.com",
    // office.com / office365.com — Office Online, M365 portal
    "@@||office.com^$domain=microsoft.com|microsoftonline.com|live.com|outlook.com|office.com|office365.com|sharepoint.com",
    "@@||office365.com^$domain=microsoft.com|microsoftonline.com|live.com|outlook.com|office.com|office365.com|sharepoint.com",
    // sharepoint.com — SharePoint Online and OneDrive
    "@@||sharepoint.com^$domain=microsoft.com|microsoftonline.com|live.com|outlook.com|office.com|office365.com|sharepoint.com",
    // outlook.com — Outlook Web App
    "@@||outlook.com^$domain=microsoft.com|microsoftonline.com|live.com|outlook.com|office.com|office365.com",
    // microsoft.com — general Microsoft infra, scoped to MS properties only
    // Excludes bat.bing.com / bingads.microsoft.com / ads.microsoft.com which
    // are ad subdomains and must remain blocked everywhere.
    "@@||microsoft.com^$domain=microsoft.com|microsoftonline.com|live.com|outlook.com|office.com|office365.com|sharepoint.com|bing.com|msn.com|xbox.com|azure.com",
    // bing.com — Bing search results page functionality.
    // bat.bing.com (UET tracker) is a subdomain and is explicitly blocked in
    // customBlockRules; the @@||bing.com^ exception is scoped to MS domains
    // so it cannot unblock bat.bing.com on third-party sites.
    "@@||bing.com^$domain=bing.com|microsoft.com|microsoftonline.com|live.com|msn.com|outlook.com|office.com",

    // Microsoft cross-domain infrastructure — M365 properties load assets from
    // shared Microsoft CDNs and auth backends across domain boundaries.
    // These are all domain-scoped to Microsoft properties only.
    "@@||*.microsoft.com^$domain=microsoft.com|live.com|microsoftonline.com|bing.com|outlook.com|office.com|office365.com|sharepoint.com",
    "@@||*.microsoftonline.com^$domain=microsoft.com|live.com|microsoftonline.com|bing.com|outlook.com|office.com|office365.com|sharepoint.com",
    "@@||*.live.com^$domain=microsoft.com|live.com|microsoftonline.com|bing.com|outlook.com|office.com|office365.com|sharepoint.com",
    "@@||*.msn.com^$domain=microsoft.com|live.com|microsoftonline.com|bing.com|outlook.com|office.com|office365.com|sharepoint.com",
    "@@||*.office.com^$domain=microsoft.com|live.com|microsoftonline.com|bing.com|outlook.com|office.com|office365.com|sharepoint.com",
    "@@||*.office365.com^$domain=microsoft.com|live.com|microsoftonline.com|bing.com|outlook.com|office.com|office365.com|sharepoint.com",
    "@@||*.sharepoint.com^$domain=microsoft.com|live.com|microsoftonline.com|bing.com|outlook.com|office.com|office365.com|sharepoint.com",
    "@@||*.gfx.ms^$domain=microsoft.com|live.com|microsoftonline.com|bing.com|outlook.com|office.com|office365.com|sharepoint.com",
    "@@||*.s-microsoft.com^$domain=microsoft.com|live.com|microsoftonline.com|bing.com|outlook.com|office.com|office365.com|sharepoint.com",
]
print("  Adding \(safeExceptions.count) safe-site exception rules")
adRules.append(contentsOf: safeExceptions)
trackerRules.append(contentsOf: safeExceptions)
annoyancesRules.append(contentsOf: safeExceptions)

// Convert to Safari JSON
print("=== Converting rules (SafariConverterLib) ===")
let adCount = convertAndWrite(rules: adRules, outputName: "adblock.json")
let trkCount = convertAndWrite(rules: trackerRules, outputName: "trackers.json")
let annCount = convertAndWrite(rules: annoyancesRules, outputName: "annoyances.json")

// Exceptions standalone file
let exceptionRules = (adRules + trackerRules + annoyancesRules).filter { $0.hasPrefix("@@") }
_ = convertAndWrite(rules: exceptionRules, outputName: "exceptions.json")

print("\n  Total rules compiled: \(adCount + trkCount + annCount)")

// Generate sidecar JSON files
print("\n=== Generating sidecar data files ===")
let siteScriptlets = extractSiteScriptlets(from: allTexts)
writeJSFiles(allTexts: allTexts, siteScriptlets: siteScriptlets)

// Write JS output files
print("\n=== Writing JS output files ===")

let cosmeticPath = outputDir.appendingPathComponent("cosmetic.js")
try? buildCosmeticJS().write(to: cosmeticPath, atomically: true, encoding: .utf8)
print("  Wrote output/cosmetic.js")

let scriptletsPath = outputDir.appendingPathComponent("scriptlets.js")
try? buildScriptletsJS(siteConfigs: siteScriptlets).write(to: scriptletsPath, atomically: true, encoding: .utf8)
print("  Wrote output/scriptlets.js (\(siteScriptlets.count) site configs embedded)")

let wsPath = outputDir.appendingPathComponent("websocket_block.js")
try? websocketBlockJS.write(to: wsPath, atomically: true, encoding: .utf8)
print("  Wrote output/websocket_block.js")

let stubsPath = outputDir.appendingPathComponent("tracker_stubs.js")
try? trackerStubsJS.write(to: stubsPath, atomically: true, encoding: .utf8)
print("  Wrote output/tracker_stubs.js")

print("\n=== Done ✓ ===")

// NOTE: WKContentRuleList compile verification removed from the build tool.
// It requires an active NSApplication run loop which isn't available in
// headless CI (GitHub Actions). Use the test browser to verify compilation locally.

print("""

  Output files:
    output/adblock.json          ← WKContentRuleList (ads)
    output/trackers.json         ← WKContentRuleList (trackers)
    output/annoyances.json       ← WKContentRuleList (annoyances / cookie banners)
    output/exceptions.json       ← WKContentRuleList (exceptions)
    output/cosmetic.js           ← WKUserScript (CSS hiding + anti-detection)
    output/scriptlets.js         ← WKUserScript (scriptlet engine + site configs)
    output/websocket_block.js    ← WKUserScript (WebSocket/WebRTC blocking)
    output/tracker_stubs.js      ← WKUserScript (tracker API stubs)
    output/cosmetic_domains.json ← per-domain CSS selectors
    output/scriptlet_rules.json  ← per-domain scriptlet configs
    output/removeparam_rules.json ← URL param stripping rules
    output/redirect_rules.json   ← $redirect surrogate mappings

""")

// MARK: - Helpers

func sha256(_ data: Data) -> String {
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes { bytes in
        _ = CC_SHA256(bytes.baseAddress, CC_LONG(data.count), &hash)
    }
    return hash.map { String(format: "%02x", $0) }.joined()
}
