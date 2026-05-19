/// Emerald Ad Blocker — Build Tool (Swift + SafariConverterLib)
///
/// Single-command build that generates ALL output files:
///   - adblock.json, trackers.json, exceptions.json (via SafariConverterLib)
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
    enum Category { case ads, trackers, removeparam }
}

let filterLists: [FilterList] = [
    .init(name: "easylist", url: "https://easylist.to/easylist/easylist.txt", category: .ads),
    .init(name: "easyprivacy", url: "https://easylist.to/easylist/easyprivacy.txt", category: .trackers),
    .init(name: "peter_lowe", url: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&mimetype=plaintext", category: .trackers),
    .init(name: "adguard_base", url: "https://filters.adtidy.org/extension/safari/filters/2.txt", category: .ads),
    .init(name: "adguard_tracking", url: "https://filters.adtidy.org/extension/safari/filters/3.txt", category: .trackers),
    .init(name: "adguard_social", url: "https://filters.adtidy.org/extension/safari/filters/4.txt", category: .ads),
    .init(name: "adguard_annoyances", url: "https://filters.adtidy.org/extension/safari/filters/14.txt", category: .ads),
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
        safariVersion: .safari15,
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

        // Append first-party exception at the end
        rulesArray.append([
            "trigger": ["url-filter": ".*", "load-type": ["first-party"]],
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
    case .removeparam:
        break // handled in writeJSFiles
    }
}

print("\n  Total: \(adRules.count) ad rules, \(trackerRules.count) tracker rules\n")

// Add safe-site exception rules for sites whose APIs match tracker patterns
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
    "@@||googletagmanager.com/gtm.js$domain=kahoot.it|kahoot.com",
    "@@||sentry.io^$domain=kahoot.it|kahoot.com",
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
]
print("  Adding \(safeExceptions.count) safe-site exception rules")
adRules.append(contentsOf: safeExceptions)
trackerRules.append(contentsOf: safeExceptions)

// Convert to Safari JSON
print("=== Converting rules (SafariConverterLib) ===")
let adCount = convertAndWrite(rules: adRules, outputName: "adblock.json")
let trkCount = convertAndWrite(rules: trackerRules, outputName: "trackers.json")

// Exceptions standalone file
let exceptionRules = (adRules + trackerRules).filter { $0.hasPrefix("@@") }
_ = convertAndWrite(rules: exceptionRules, outputName: "exceptions.json")

print("\n  Total rules compiled: \(adCount + trkCount)")

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
print("""

  Output files:
    output/adblock.json          ← WKContentRuleList (ads)
    output/trackers.json         ← WKContentRuleList (trackers)
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
