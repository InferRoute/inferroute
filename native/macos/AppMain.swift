// Small signed application shell: the bundled Python service draws the page, and this app shows it in a
// window of its own.
//
// It starts the bundled Python service (`probant home`, told not to open a browser) and, once the service prints
// its page address, shows that page in an Anteriora window (WebKit, the engine Safari uses). Closing the window
// keeps the service running; the Dock icon or File > New Window brings it back, never a second service. The
// page may load nothing but the service's own address: any other link opens in the default browser. WebKit
// keeps nothing on disk (a non-persistent data store): the person's notes and matter text never reach a cache.
// File > Open Anteriora in Browser stays for people who prefer a browser tab.
//
// Quitting (Anteriora > Quit, Cmd-Q, or the Dock menu) does what Ctrl-C does in a terminal: the service and every
// session it started get SIGINT (they share one process group, made here), and the app waits for them to end
// before it exits.
import AppKit
import Foundation
import WebKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var pid: pid_t = 0
    private var exited = false
    private var quitting = false
    private var homeURL: URL?
    private var pending = Data()
    private var output: FileHandle?
    private var exitWatch: DispatchSourceProcess?

    private var termWatch: DispatchSourceSignal?
    private var windows: [PageWindow] = []
    private var home: PageWindow?           // the window showing the home page; nil once closed

    func applicationDidFinishLaunching(_ notification: Notification) {
        installMenu()
        // SIGTERM (`kill`, `killall Anteriora`) takes the same path as Quit instead of leaving the service and
        // its sessions running with no app. The child gets the default disposition back (POSIX_SPAWN_SETSIGDEF).
        signal(SIGTERM, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        term.setEventHandler { AppDelegate.later { NSApplication.shared.terminate(nil) } }
        term.resume()
        termWatch = term
        guard #available(macOS 12.0, *), let resources = Bundle.main.resourceURL else {
            NSApplication.shared.terminate(nil); return
        }
        let python = resources.appendingPathComponent("python/bin/python3").path
        let entry = resources.appendingPathComponent("app_entry.py").path
        // Host credentials remain with the trusted host service. No Pi discovery. -B and
        // PYTHONDONTWRITEBYTECODE: nothing is written inside the signed bundle (it would break its seal).
        // IR_PROBANT_NO_BROWSER: the page is shown in this app's window, not in a browser tab.
        var env = ["HOME=" + NSHomeDirectory(), "PATH=/usr/bin:/bin",
                   "IR_ATTESTED_CONFINE=require", "PYTHONNOUSERSITE=1",
                   "PYTHONSAFEPATH=1", "PYTHONDONTWRITEBYTECODE=1", "IR_PROBANT_NO_BROWSER=1"]
        // The per-user temporary folder launchd gives every app; without it Python falls back to /tmp.
        if let tmp = ProcessInfo.processInfo.environment["TMPDIR"], tmp.hasPrefix("/") {
            env.append("TMPDIR=" + tmp)
        }
        guard start(argv: [python, "-I", "-B", entry], env: env) else {
            let alert = NSAlert()
            alert.messageText = "Anteriora could not start its bundled runtime."
            alert.informativeText = "No agent session was started."
            alert.runModal(); NSApplication.shared.terminate(nil); return
        }
    }

    // posix_spawn rather than Process: the child must lead its own process group, so that quitting can
    // signal the service and the sessions it started, and nothing else.
    private func start(argv: [String], env: [String]) -> Bool {
        var fds: [Int32] = [0, 0]
        guard pipe(&fds) == 0 else { return false }
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_adddup2(&actions, fds[1], 1)
        posix_spawn_file_actions_addinherit_np(&actions, 2)
        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        defer { posix_spawnattr_destroy(&attr) }
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT
                                              | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK))
        posix_spawnattr_setpgroup(&attr, 0)
        var defaults = sigset_t(), empty = sigset_t()
        sigemptyset(&defaults); sigemptyset(&empty)
        for sig in [SIGINT, SIGTERM, SIGHUP, SIGPIPE] { sigaddset(&defaults, sig) }
        posix_spawnattr_setsigdefault(&attr, &defaults)
        posix_spawnattr_setsigmask(&attr, &empty)
        let cArgv = argv.map { strdup($0) } + [nil]
        let cEnv = env.map { strdup($0) } + [nil]
        defer { (cArgv + cEnv).forEach { free($0) } }
        var child: pid_t = 0
        let rc = posix_spawn(&child, argv[0], &actions, &attr, cArgv, cEnv)
        close(fds[1])
        guard rc == 0 else { close(fds[0]); return false }
        pid = child
        let handle = FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)
        handle.readabilityHandler = { [weak self] h in
            let data = h.availableData
            if data.isEmpty { h.readabilityHandler = nil; return }      // end of output
            DispatchQueue.main.async { self?.read(data) }
        }
        output = handle
        let watch = DispatchSource.makeProcessSource(identifier: child, eventMask: .exit, queue: .main)
        watch.setEventHandler { [weak self] in self?.serviceExited() }
        watch.resume()
        exitWatch = watch
        return true
    }

    // The service prints its page address once ("Probant home:  http://127.0.0.1:PORT/#k=TOKEN"). It is kept
    // in memory only; the window loads it.
    private func read(_ data: Data) {
        pending.append(data)
        while let nl = pending.firstIndex(of: 0x0A) {
            let line = String(decoding: pending[pending.startIndex..<nl], as: UTF8.self)
            pending.removeSubrange(pending.startIndex...nl)
            if homeURL == nil, let r = line.range(of: "Probant home:") {
                let text = line[r.upperBound...].trimmingCharacters(in: .whitespaces)
                if text.hasPrefix("http://127.0.0.1:"), let url = URL(string: text) {
                    homeURL = url
                    showWindow(nil)
                }
            }
        }
        if pending.count > 65536 { pending.removeAll() }
    }

    private func serviceExited() {
        reap()
        exitWatch?.cancel()
        if quitting { return }           // the group wait in applicationShouldTerminate answers
        AppDelegate.later { [weak self] in
            if self?.homeURL == nil {
                let alert = NSAlert()
                alert.messageText = "Anteriora stopped before its page was ready."
                alert.informativeText = "No agent session was started."
                alert.runModal()
            }
            NSApplication.shared.terminate(nil)
        }
    }

    // terminate(_:) and runModal() spin a nested run loop. Called from inside a main-queue (GCD) callout,
    // that loop can never service the main queue again, so nothing else queued there runs: measured on
    // 15 Oct, a SIGTERM left the app waiting forever on an exited service it could no longer reap. They are
    // therefore run as run-loop blocks, outside any GCD callout.
    static func later(_ body: @escaping () -> Void) {
        RunLoop.main.perform(inModes: [.common, .modalPanel], block: body)
    }

    private func reap() {
        guard !exited else { return }
        var status: Int32 = 0
        if waitpid(pid, &status, WNOHANG) == pid { exited = true }
    }

    @objc func openHome(_ sender: Any?) {
        if let url = homeURL { NSWorkspace.shared.open(url) }
    }

    // The Dock icon and File > New Window: bring back the home window on the running service (never start
    // another). A record window (opened by the page) is not the home window and does not stand in for it.
    @objc func showWindow(_ sender: Any?) {
        guard let url = homeURL, !quitting else { return }
        if let open = home {
            if open.window.isMiniaturized { open.window.deminiaturize(nil) }
            open.window.makeKeyAndOrderFront(nil)
        } else {
            let w = PageWindow(home: url, app: self, configuration: nil, main: true)
            w.webView.load(URLRequest(url: url))
            windows.append(w); home = w
        }
        NSApp.activate(ignoringOtherApps: true)
    }

    // A page asked for a window (window.open): same service, same WebKit process, so it shares the opener's
    // session storage (and with it the per-launch key).
    func openChild(configuration: WKWebViewConfiguration, home url: URL) -> WKWebView {
        let w = PageWindow(home: url, app: self, configuration: configuration, main: false)
        windows.append(w)
        return w.webView
    }

    func closed(_ w: PageWindow) {
        windows.removeAll { $0 === w }
        if home === w { home = nil }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { showWindow(nil) }
        return flag
    }

    // The service keeps running with no window, as it did with no browser tab: Quit is how it ends.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard pid > 0, !quitting, groupAlive() else { return .terminateNow }
        quitting = true
        kill(-pid, SIGINT)                // what Ctrl-C does to `probant home` in a terminal
        let started = Date()
        // In the run loop's common AND modal-panel modes: while termination is pending AppKit runs the loop
        // in the modal-panel mode, where a default-mode timer never fires.
        let poll = Timer(timeInterval: 0.5, repeats: true) { [weak self] timer in
            guard let self = self else { timer.invalidate(); return }
            let waited = Date().timeIntervalSince(started)
            // Sessions get time to end cleanly: files the assistant wrote reach the matter folder only then.
            if !self.groupAlive() || waited > 90 {
                if waited > 90 { kill(-self.pid, SIGTERM) }
                timer.invalidate()
                NSApplication.shared.reply(toApplicationShouldTerminate: true)
            }
        }
        RunLoop.main.add(poll, forMode: .common)
        RunLoop.main.add(poll, forMode: .modalPanel)
        return .terminateLater
    }

    private func groupAlive() -> Bool {
        reap()
        if !exited { return true }
        return kill(-pid, 0) == 0 || errno == EPERM
    }

    private func installMenu() {
        let main = NSMenu()
        func top(_ title: String, _ items: [NSMenuItem]) -> NSMenu {
            let holder = NSMenuItem(), menu = NSMenu(title: title)
            items.forEach { menu.addItem($0) }
            holder.submenu = menu; main.addItem(holder)
            return menu
        }
        func item(_ title: String, _ action: Selector, _ key: String, _ mods: NSEvent.ModifierFlags = .command,
                  target: AnyObject? = nil) -> NSMenuItem {
            let i = NSMenuItem(title: title, action: action, keyEquivalent: key)
            i.keyEquivalentModifierMask = mods; i.target = target
            return i
        }
        _ = top("Anteriora", [
            item("Hide Anteriora", #selector(NSApplication.hide(_:)), "h"),
            item("Hide Others", #selector(NSApplication.hideOtherApplications(_:)), "h", [.command, .option]),
            item("Show All", #selector(NSApplication.unhideAllApplications(_:)), ""),
            .separator(),
            item("Quit Anteriora", #selector(NSApplication.terminate(_:)), "q")])
        _ = top("File", [
            item("New Window", #selector(showWindow(_:)), "n", target: self),
            item("Open Anteriora in Browser", #selector(openHome(_:)), "o", target: self),
            .separator(),
            item("Close Window", #selector(NSWindow.performClose(_:)), "w")])
        // Without an Edit menu, Cmd-C / Cmd-V / Cmd-A do nothing inside a web view.
        _ = top("Edit", [
            item("Undo", Selector(("undo:")), "z"),
            item("Redo", Selector(("redo:")), "z", [.command, .shift]),
            .separator(),
            item("Cut", #selector(NSText.cut(_:)), "x"),
            item("Copy", #selector(NSText.copy(_:)), "c"),
            item("Paste", #selector(NSText.paste(_:)), "v"),
            item("Select All", #selector(NSText.selectAll(_:)), "a")])
        _ = top("View", [
            item("Reload Page", #selector(WKWebView.reload(_:)), "r"),
            .separator(),
            item("Actual Size", #selector(PageWindow.actualSize(_:)), "0"),
            item("Zoom In", #selector(PageWindow.zoomIn(_:)), "="),
            item("Zoom Out", #selector(PageWindow.zoomOut(_:)), "-")])
        let windowMenu = top("Window", [
            item("Minimize", #selector(NSWindow.performMiniaturize(_:)), "m"),
            item("Zoom", #selector(NSWindow.performZoom(_:)), "")])
        NSApplication.shared.windowsMenu = windowMenu
        NSApplication.shared.mainMenu = main
    }
}

// One Anteriora window: a web view that may show the service's own pages and nothing else.
final class PageWindow: NSObject, NSWindowDelegate, WKNavigationDelegate, WKUIDelegate {
    let window: NSWindow
    let webView: WKWebView
    private let home: URL
    private weak var app: AppDelegate?

    init(home: URL, app: AppDelegate, configuration: WKWebViewConfiguration?, main: Bool) {
        self.home = home; self.app = app
        let config: WKWebViewConfiguration
        if let given = configuration {
            config = given                         // from window.open: WebKit requires this exact configuration
        } else {
            config = WKWebViewConfiguration()
            config.websiteDataStore = .nonPersistent()   // nothing the person types reaches a disk cache
        }
        webView = WKWebView(frame: .zero, configuration: config)
        let size = NSScreen.main.map { NSSize(width: min(1280, $0.visibleFrame.width * 0.85),
                                              height: min(900, $0.visibleFrame.height * 0.9)) }
                   ?? NSSize(width: 1180, height: 820)
        window = NSWindow(contentRect: NSRect(origin: .zero, size: size),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        super.init()
        window.title = "Anteriora"
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 720, height: 480)
        window.contentView = webView
        window.delegate = self
        webView.navigationDelegate = self
        webView.uiDelegate = self
        // Only the home window remembers its place; a record window opens offset from the window in front.
        if main {
            window.center()
            window.setFrameAutosaveName("ProbantWindow")
        } else if let front = NSApp.keyWindow ?? NSApp.mainWindow {
            window.setFrameTopLeftPoint(front.cascadeTopLeft(from: NSPoint(x: front.frame.minX, y: front.frame.maxY)))
        }
        window.makeKeyAndOrderFront(nil)
    }

    // The service's own address: same scheme, host and port as the page address it printed.
    private func isHome(_ url: URL?) -> Bool {
        guard let u = url else { return false }
        return u.scheme == "http" && u.host == "127.0.0.1" && u.port == home.port
    }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        let url = action.request.url
        if isHome(url) || url?.absoluteString == "about:blank" { decisionHandler(.allow); return }
        decisionHandler(.cancel)
        // A link the person followed (or a page's window.open) to anywhere else: the default browser.
        if let u = url, ["http", "https", "mailto"].contains(u.scheme ?? ""),
           action.targetFrame?.isMainFrame ?? true {
            NSWorkspace.shared.open(u)
        }
    }

    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        guard isHome(action.request.url), let app = app else {
            if let u = action.request.url, ["http", "https", "mailto"].contains(u.scheme ?? "") {
                NSWorkspace.shared.open(u)
            }
            return nil
        }
        return app.openChild(configuration: configuration, home: home)
    }

    func webViewDidClose(_ webView: WKWebView) { window.close() }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        if let t = webView.title, !t.isEmpty { window.title = t }
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) { webView.reload() }

    // window.alert / confirm / prompt, as sheets on this window.
    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let a = NSAlert(); a.messageText = message; a.addButton(withTitle: "OK")
        a.beginSheetModal(for: window) { _ in completionHandler() }
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let a = NSAlert(); a.messageText = message
        a.addButton(withTitle: "OK"); a.addButton(withTitle: "Cancel")
        a.beginSheetModal(for: window) { r in completionHandler(r == .alertFirstButtonReturn) }
    }

    func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String,
                 defaultText: String?, initiatedByFrame frame: WKFrameInfo,
                 completionHandler: @escaping (String?) -> Void) {
        let a = NSAlert(); a.messageText = prompt
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        field.stringValue = defaultText ?? ""; a.accessoryView = field
        a.addButton(withTitle: "OK"); a.addButton(withTitle: "Cancel")
        a.beginSheetModal(for: window) { r in completionHandler(r == .alertFirstButtonReturn ? field.stringValue : nil) }
    }

    // <input type="file">
    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = parameters.allowsDirectories
        panel.allowsMultipleSelection = parameters.allowsMultipleSelection
        panel.beginSheetModal(for: window) { r in completionHandler(r == .OK ? panel.urls : nil) }
    }

    @objc func actualSize(_ sender: Any?) { webView.pageZoom = 1.0 }
    @objc func zoomIn(_ sender: Any?) { webView.pageZoom = min(3.0, webView.pageZoom + 0.1) }
    @objc func zoomOut(_ sender: Any?) { webView.pageZoom = max(0.5, webView.pageZoom - 0.1) }

    func windowWillClose(_ notification: Notification) {
        webView.navigationDelegate = nil; webView.uiDelegate = nil
        app?.closed(self)
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
