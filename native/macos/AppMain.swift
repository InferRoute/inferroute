// Small signed application shell; the existing browser remains the UI.
//
// It starts the bundled Python service (`probant home`, which opens the page in the default browser once it
// listens), shows a Dock icon while that runs, and gives the person two things a shell with no window must
// still give: a way back to the page (click the Dock icon, or File > Open Probant in Browser) and a way to
// quit (Probant > Quit, Cmd-Q, or the Dock menu). Quitting does what Ctrl-C does in a terminal: the service
// and every session it started get SIGINT (they share one process group, made here), and the app waits for
// them to end before it exits.
import AppKit
import Foundation

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var pid: pid_t = 0
    private var exited = false
    private var quitting = false
    private var homeURL: URL?
    private var pending = Data()
    private var output: FileHandle?
    private var exitWatch: DispatchSourceProcess?

    private var termWatch: DispatchSourceSignal?

    func applicationDidFinishLaunching(_ notification: Notification) {
        installMenu()
        // SIGTERM (`kill`, `killall Probant`) takes the same path as Quit instead of leaving the service and
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
        var env = ["HOME=" + NSHomeDirectory(), "PATH=/usr/bin:/bin",
                   "IR_ATTESTED_CONFINE=require", "PYTHONNOUSERSITE=1",
                   "PYTHONSAFEPATH=1", "PYTHONDONTWRITEBYTECODE=1"]
        // The per-user temporary folder launchd gives every app; without it Python falls back to /tmp.
        if let tmp = ProcessInfo.processInfo.environment["TMPDIR"], tmp.hasPrefix("/") {
            env.append("TMPDIR=" + tmp)
        }
        guard start(argv: [python, "-I", "-B", entry], env: env) else {
            let alert = NSAlert()
            alert.messageText = "Probant could not start its bundled runtime."
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
    // in memory only, to reopen the page; the service itself opens it the first time.
    private func read(_ data: Data) {
        pending.append(data)
        while let nl = pending.firstIndex(of: 0x0A) {
            let line = String(decoding: pending[pending.startIndex..<nl], as: UTF8.self)
            pending.removeSubrange(pending.startIndex...nl)
            if homeURL == nil, let r = line.range(of: "Probant home:") {
                let text = line[r.upperBound...].trimmingCharacters(in: .whitespaces)
                if text.hasPrefix("http://127.0.0.1:"), let url = URL(string: text) { homeURL = url }
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
                alert.messageText = "Probant stopped before its page was ready."
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

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openHome(nil)
        return false
    }

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
        let appItem = NSMenuItem(), fileItem = NSMenuItem()
        main.addItem(appItem); main.addItem(fileItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Quit Probant", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        let fileMenu = NSMenu(title: "File")
        let open = NSMenuItem(title: "Open Probant in Browser", action: #selector(openHome(_:)), keyEquivalent: "o")
        open.target = self
        fileMenu.addItem(open)
        fileItem.submenu = fileMenu
        NSApplication.shared.mainMenu = main
    }
}
let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
