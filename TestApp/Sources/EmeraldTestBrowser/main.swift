/// Emerald Ad Blocker — minimal test browser
///
/// Build & run (no Xcode required — only Swift CLI tools):
///
///   cd TestApp
///   swift run
///
/// Or from the project root:
///
///   swift run --package-path TestApp
///
/// The browser loads adblock.json + trackers.json into WKContentRuleList and
/// injects scriptlets.js / cosmetic.js / websocket_block.js / ytadblock.js as
/// WKUserScripts, exactly as Emerald does.

import AppKit
import WebKit

// ---------------------------------------------------------------------------
// Locate the project root (output/ + test files live there)
// ---------------------------------------------------------------------------

func findProjectRoot() -> URL {
    let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    // Support running from TestApp/ or from the project root
    for candidate in [cwd, cwd.deletingLastPathComponent()] {
        if FileManager.default.fileExists(
            atPath: candidate.appendingPathComponent("output/adblock.json").path
        ) { return candidate }
    }
    return cwd
}

let ROOT = findProjectRoot()

// ---------------------------------------------------------------------------
// AppDelegate
// ---------------------------------------------------------------------------

class AppDelegate: NSObject, NSApplicationDelegate {
    var windowController: BrowserWindowController!

    func applicationDidFinishLaunching(_ note: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        buildMenu()
        windowController = BrowserWindowController()
        windowController.showWindow(nil)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }

    private func buildMenu() {
        let bar = NSMenu()
        let appItem = NSMenuItem()
        bar.addItem(appItem)
        let appMenu = NSMenu(title: "App")
        appItem.submenu = appMenu
        appMenu.addItem(withTitle: "Quit", action: #selector(NSApp.terminate(_:)), keyEquivalent: "q")

        let viewItem = NSMenuItem(title: "View", action: nil, keyEquivalent: "")
        bar.addItem(viewItem)
        let viewMenu = NSMenu(title: "View")
        viewItem.submenu = viewMenu
        viewMenu.addItem(withTitle: "Reload Page", action: #selector(BrowserWindowController.reload), keyEquivalent: "r")
        viewMenu.addItem(withTitle: "Go Home (Test Suite)", action: #selector(BrowserWindowController.goHome), keyEquivalent: "h")

        NSApp.mainMenu = bar
    }
}

// ---------------------------------------------------------------------------
// Browser window controller
// ---------------------------------------------------------------------------

class BrowserWindowController: NSWindowController, WKNavigationDelegate, WKUIDelegate {

    // Shared WKWebViewConfiguration — rules are added to this before first load
    private let wkConfig = WKWebViewConfiguration()

    private var webView: WKWebView!
    private var urlField: NSTextField!
    private var statusBar: NSTextField!
    private var spinner: NSProgressIndicator!

    private var rulesCompiled = 0
    private var rulesFailed  = 0
    private var pendingCompile = 0

    // ---------------------------------------------------------------------------
    init() {
        let win = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1200, height: 800),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        win.title = "Emerald Ad Blocker — Test Browser"
        win.center()
        super.init(window: win)
        buildUI()
        loadAdblocker()
    }
    required init?(coder: NSCoder) { fatalError() }

    // ---------------------------------------------------------------------------
    // MARK: UI layout
    // ---------------------------------------------------------------------------

    private func buildUI() {
        guard let cv = window?.contentView else { return }

        // Toolbar row
        let toolbar = NSView()
        toolbar.translatesAutoresizingMaskIntoConstraints = false
        cv.addSubview(toolbar)

        let backBtn   = navButton("◀",  #selector(goBack))
        let fwdBtn    = navButton("▶",  #selector(goForward))
        let reloadBtn = navButton("↺",   #selector(reload))
        let homeBtn   = navButton("⌂",   #selector(goHome))

        urlField = NSTextField()
        urlField.translatesAutoresizingMaskIntoConstraints = false
        urlField.font = .systemFont(ofSize: 13)
        urlField.placeholderString = "https://…"
        urlField.target = self
        urlField.action = #selector(navigateFromField)

        for v: NSView in [backBtn, fwdBtn, reloadBtn, homeBtn, urlField] {
            toolbar.addSubview(v)
        }

        // Separator
        let sep = NSBox(); sep.translatesAutoresizingMaskIntoConstraints = false
        sep.boxType = .separator
        cv.addSubview(sep)

        // Progress spinner (indeterminate) aligned to right of URL bar
        spinner = NSProgressIndicator()
        spinner.translatesAutoresizingMaskIntoConstraints = false
        spinner.style = .spinning
        spinner.isIndeterminate = true
        spinner.isHidden = true
        spinner.controlSize = .small
        toolbar.addSubview(spinner)

        // WebView
        webView = WKWebView(frame: .zero, configuration: wkConfig)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.translatesAutoresizingMaskIntoConstraints = false
        webView.allowsBackForwardNavigationGestures = true
        cv.addSubview(webView)

        // Status bar
        statusBar = NSTextField()
        statusBar.translatesAutoresizingMaskIntoConstraints = false
        statusBar.isEditable = false; statusBar.isBezeled = false
        statusBar.backgroundColor = .clear
        statusBar.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
        statusBar.textColor = .secondaryLabelColor
        statusBar.stringValue = "  Loading ad-blocking rules…"
        cv.addSubview(statusBar)

        let m: CGFloat = 8
        NSLayoutConstraint.activate([
            // Toolbar
            toolbar.topAnchor.constraint(equalTo: cv.topAnchor, constant: m),
            toolbar.leadingAnchor.constraint(equalTo: cv.leadingAnchor, constant: m),
            toolbar.trailingAnchor.constraint(equalTo: cv.trailingAnchor, constant: -m),
            toolbar.heightAnchor.constraint(equalToConstant: 30),

            backBtn.leadingAnchor.constraint(equalTo: toolbar.leadingAnchor),
            backBtn.centerYAnchor.constraint(equalTo: toolbar.centerYAnchor),
            backBtn.widthAnchor.constraint(equalToConstant: 28),

            fwdBtn.leadingAnchor.constraint(equalTo: backBtn.trailingAnchor, constant: 4),
            fwdBtn.centerYAnchor.constraint(equalTo: toolbar.centerYAnchor),
            fwdBtn.widthAnchor.constraint(equalToConstant: 28),

            reloadBtn.leadingAnchor.constraint(equalTo: fwdBtn.trailingAnchor, constant: 4),
            reloadBtn.centerYAnchor.constraint(equalTo: toolbar.centerYAnchor),
            reloadBtn.widthAnchor.constraint(equalToConstant: 28),

            homeBtn.leadingAnchor.constraint(equalTo: reloadBtn.trailingAnchor, constant: 4),
            homeBtn.centerYAnchor.constraint(equalTo: toolbar.centerYAnchor),
            homeBtn.widthAnchor.constraint(equalToConstant: 28),

            spinner.trailingAnchor.constraint(equalTo: toolbar.trailingAnchor, constant: -4),
            spinner.centerYAnchor.constraint(equalTo: toolbar.centerYAnchor),
            spinner.widthAnchor.constraint(equalToConstant: 16),
            spinner.heightAnchor.constraint(equalToConstant: 16),

            urlField.leadingAnchor.constraint(equalTo: homeBtn.trailingAnchor, constant: 8),
            urlField.trailingAnchor.constraint(equalTo: spinner.leadingAnchor, constant: -8),
            urlField.centerYAnchor.constraint(equalTo: toolbar.centerYAnchor),

            sep.topAnchor.constraint(equalTo: toolbar.bottomAnchor, constant: m),
            sep.leadingAnchor.constraint(equalTo: cv.leadingAnchor),
            sep.trailingAnchor.constraint(equalTo: cv.trailingAnchor),

            webView.topAnchor.constraint(equalTo: sep.bottomAnchor),
            webView.leadingAnchor.constraint(equalTo: cv.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: cv.trailingAnchor),
            webView.bottomAnchor.constraint(equalTo: statusBar.topAnchor, constant: -4),

            statusBar.bottomAnchor.constraint(equalTo: cv.bottomAnchor, constant: -4),
            statusBar.leadingAnchor.constraint(equalTo: cv.leadingAnchor),
            statusBar.trailingAnchor.constraint(equalTo: cv.trailingAnchor),
            statusBar.heightAnchor.constraint(equalToConstant: 16),
        ])
    }

    private func navButton(_ title: String, _ action: Selector) -> NSButton {
        let b = NSButton(title: title, target: self, action: action)
        b.translatesAutoresizingMaskIntoConstraints = false
        b.bezelStyle = .rounded
        b.font = .systemFont(ofSize: 13)
        return b
    }

    // ---------------------------------------------------------------------------
    // MARK: Load the adblocker (scripts + rule lists)
    // ---------------------------------------------------------------------------

    private func loadAdblocker() {
        let ucc = wkConfig.userContentController

        // ── 1. WKUserScripts (same order as Emerald injects them) ──────────────
        let jsFiles = ["scriptlets.js", "websocket_block.js", "cosmetic.js", "ytadblock.js"]
        var injected: [String] = []
        var totalJSKB = 0
        for name in jsFiles {
            let path = ROOT.appendingPathComponent("output/\(name)")
            guard let src = try? String(contentsOf: path, encoding: .utf8) else { continue }
            let script = WKUserScript(source: src, injectionTime: .atDocumentStart, forMainFrameOnly: false)
            ucc.addUserScript(script)
            injected.append(name)
            totalJSKB += src.utf8.count / 1024
        }
        print("[TestBrowser] Injected WKUserScripts: \(injected.joined(separator: ", ")) (\(totalJSKB) KB total)")

        // ── 2. WKContentRuleList compilation (network-level blocking) ──────────
        let ruleSets: [(id: String, file: String)] = [
            ("emerald.adblock",  "output/adblock.json"),
            ("emerald.trackers", "output/trackers.json"),
        ]

        pendingCompile = ruleSets.count
        var totalRules = 0
        var stats: [(name: String, count: Int, kb: Int)] = []

        for rs in ruleSets {
            let filePath = ROOT.appendingPathComponent(rs.file)
            guard let json = try? String(contentsOf: filePath, encoding: .utf8) else {
                print("[TestBrowser] ⚠ Could not read \(rs.file)")
                DispatchQueue.main.async { self.compileDone(stats: [], totalRules: 0) }
                continue
            }

            // Count for status display
            if let arr = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [[String: Any]] {
                let kb = filePath.fileSize / 1024
                stats.append((name: rs.id, count: arr.count, kb: kb))
                totalRules += arr.count
            }

            // Compile asynchronously — this is the same call Emerald makes
            WKContentRuleListStore.default().compileContentRuleList(
                forIdentifier: rs.id,
                encodedContentRuleList: json
            ) { [weak self] list, error in
                DispatchQueue.main.async {
                    guard let self else { return }
                    if let error {
                        print("[TestBrowser] ✗ \(rs.id): \(error.localizedDescription)")
                        self.rulesFailed += 1
                    } else if let list {
                        self.wkConfig.userContentController.add(list)
                        self.rulesCompiled += 1
                        print("[TestBrowser] ✓ \(rs.id)")
                    }
                    self.pendingCompile -= 1
                    if self.pendingCompile == 0 {
                        self.compileDone(stats: stats, totalRules: totalRules)
                    }
                }
            }
        }
    }

    private func compileDone(stats: [(name: String, count: Int, kb: Int)], totalRules: Int) {
        // Inject a stats variable so the test page can display rule counts
        // without needing a local server
        let statsJSON = stats.map { s in
            """
            "\(s.name)": { "count": \(s.count), "kb": \(s.kb) }
            """
        }.joined(separator: ", ")
        let statsScript = "window.__EMERALD_RULE_STATS__ = { \(statsJSON) };"
        let statsUserScript = WKUserScript(source: statsScript, injectionTime: .atDocumentStart, forMainFrameOnly: true)
        wkConfig.userContentController.addUserScript(statsUserScript)

        let totalFmt = NumberFormatter.decimal.string(from: NSNumber(value: totalRules)) ?? "\(totalRules)"

        if rulesFailed == 0 {
            statusBar.stringValue = "  ✅ \(rulesCompiled)/2 rule lists compiled  ·  \(totalFmt) rules active  ·  Ad blocking ON"
        } else {
            statusBar.stringValue = "  ⚠ \(rulesCompiled)/2 compiled, \(rulesFailed) failed — check Xcode/terminal console"
        }
        print("[TestBrowser] Rule compilation done: \(rulesCompiled) OK, \(rulesFailed) failed")

        goHome()
    }

    // ---------------------------------------------------------------------------
    // MARK: Navigation actions
    // ---------------------------------------------------------------------------

    @objc func navigateFromField() {
        var str = urlField.stringValue.trimmingCharacters(in: .whitespaces)
        guard !str.isEmpty else { return }
        if !str.contains("://") { str = "https://" + str }
        guard let url = URL(string: str) else { return }
        webView.load(URLRequest(url: url))
    }

    @objc func goBack()    { webView.goBack() }
    @objc func goForward() { webView.goForward() }
    @objc func reload()    { webView.reload() }

    @objc func goHome() {
        let testPage = ROOT.appendingPathComponent("TestApp/TestPage/index.html")
        if FileManager.default.fileExists(atPath: testPage.path) {
            webView.loadFileURL(testPage, allowingReadAccessTo: ROOT)
            urlField.stringValue = "  Test Suite (local)"
        } else {
            // Fallback: navigate to a real site
            let url = URL(string: "https://example.com")!
            webView.load(URLRequest(url: url))
            urlField.stringValue = url.absoluteString
        }
    }

    // ---------------------------------------------------------------------------
    // MARK: WKNavigationDelegate
    // ---------------------------------------------------------------------------

    func webView(_ webView: WKWebView, didStartProvisionalNavigation _: WKNavigation!) {
        spinner.isHidden = false; spinner.startAnimation(nil)
    }

    func webView(_ webView: WKWebView, didFinish _: WKNavigation!) {
        spinner.isHidden = true; spinner.stopAnimation(nil)
        if let url = webView.url, url.scheme != "file" {
            urlField.stringValue = url.absoluteString
        }
    }

    func webView(_ webView: WKWebView, didFail _: WKNavigation!, withError error: Error) {
        spinner.isHidden = true; spinner.stopAnimation(nil)
        let msg = (error as NSError).localizedDescription
        statusBar.stringValue = "  ✗ Navigation failed: \(msg)"
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation _: WKNavigation!, withError error: Error) {
        spinner.isHidden = true; spinner.stopAnimation(nil)
        let msg = (error as NSError).localizedDescription
        statusBar.stringValue = "  ✗ \(msg)"
    }

    // Allow WKWebView-created windows (target=_blank links etc.)
    func webView(_ webView: WKWebView, createWebViewWith config: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if action.targetFrame == nil { webView.load(action.request) }
        return nil
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

extension URL {
    var fileSize: Int {
        (try? resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
    }
}

extension NumberFormatter {
    static let decimal: NumberFormatter = {
        let f = NumberFormatter(); f.numberStyle = .decimal; return f
    }()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
