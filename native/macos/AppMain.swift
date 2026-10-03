// Small signed application shell; the existing browser remains the UI.
import AppKit
import Foundation

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var service: Process?
    func applicationDidFinishLaunching(_ notification: Notification) {
        guard #available(macOS 12.0, *), let resources = Bundle.main.resourceURL else {
            NSApplication.shared.terminate(nil); return
        }
        let python = resources.appendingPathComponent("python/bin/python3")
        let entry = resources.appendingPathComponent("app_entry.py")
        let child = Process()
        child.executableURL = python
        child.arguments = ["-I", entry.path]
        // Host credentials remain with the trusted host service. No Pi discovery.
        child.environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin",
                             "IR_ATTESTED_CONFINE": "require", "PYTHONNOUSERSITE": "1",
                             "PYTHONSAFEPATH": "1"]
        child.terminationHandler = { _ in
            DispatchQueue.main.async { NSApplication.shared.terminate(nil) }
        }
        do { try child.run(); service = child }
        catch {
            let alert = NSAlert()
            alert.messageText = "Probant could not start its bundled runtime."
            alert.informativeText = "No agent session was started."
            alert.runModal(); NSApplication.shared.terminate(nil)
        }
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if let child = service, child.isRunning { child.terminate() }
        return .terminateNow
    }
}
let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
