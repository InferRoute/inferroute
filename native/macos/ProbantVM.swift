// Internal launcher. Python authenticates/codesign-verifies and privately stages
// the complete vendor runtime before this executable starts. Never boots host shares.
import Foundation
import Virtualization
import CryptoKit
import CoreFoundation
import Darwin

enum Refusal: Error { case invalid, eof }
let brokerPort: UInt32 = 40501
let rpcPort: UInt32 = 40504
let maxFrame = 65536
let bridgeFD = CommandLine.arguments.count > 4 ? Int32(CommandLine.arguments[4]) ?? -1 : -1
let statusFD = CommandLine.arguments.count > 6 ? Int32(CommandLine.arguments[6]) ?? -1 : -1
let statusPort: UInt32 = 40505

func integerNumber(_ value: NSNumber) -> Bool {
    return CFGetTypeID(value) != CFBooleanGetTypeID() &&
        ["c", "s", "i", "l", "q", "C", "S", "I", "L", "Q"].contains(String(cString: value.objCType))
}

func refuse(_ reason: String) -> Never {
    // Fixed categories only; never print guest frames, payload bytes, or secrets.
    fputs("Probant VM refused: \(reason)\n", stderr)
    exit(78)
}

func exactRead(_ fd: Int32, _ size: Int) throws -> Data {
    var data = Data(count: size)
    var offset = 0
    while offset < size {
        let got = data.withUnsafeMutableBytes { ptr in
            Darwin.read(fd, ptr.baseAddress!.advanced(by: offset), size - offset)
        }
        if got < 0 && errno == EINTR { continue }
        if got == 0 { throw Refusal.eof }
        guard got > 0 else { throw Refusal.invalid }
        offset += got
    }
    return data
}

func writeAll(_ fd: Int32, _ data: Data) throws {
    var offset = 0
    while offset < data.count {
        let sent = data.withUnsafeBytes { ptr in
            Darwin.write(fd, ptr.baseAddress!.advanced(by: offset), data.count - offset)
        }
        if sent < 0 && errno == EINTR { continue }
        guard sent > 0 else { throw Refusal.invalid }
        offset += sent
    }
}

func verifiedArtifact(_ root: URL, _ record: Any?) throws -> URL {
    guard let record = record as? [String: Any], Set(record.keys) == Set(["file", "bytes", "sha256"]),
          let name = record["file"] as? String, !name.isEmpty,
          name != ".", name != "..", !name.contains("/"),
          let size = record["bytes"] as? NSNumber,
          integerNumber(size), size.int64Value > 0,
          size.doubleValue == Double(size.int64Value), size.int64Value <= 512 * 1024 * 1024,
          let expected = record["sha256"] as? String,
          expected.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    else { throw Refusal.invalid }
    let url = root.appendingPathComponent(name)
    let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
    guard fd >= 0 else { throw Refusal.invalid }
    defer { Darwin.close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_size == size.int64Value
    else { throw Refusal.invalid }
    var hash = SHA256()
    while true {
        var bytes = [UInt8](repeating: 0, count: 1024 * 1024)
        let count = Darwin.read(fd, &bytes, bytes.count)
        if count < 0 && errno == EINTR { continue }
        guard count >= 0 else { throw Refusal.invalid }
        if count == 0 { break }
        hash.update(data: Data(bytes.prefix(count)))
    }
    guard hash.finalize().map({ String(format: "%02x", $0) }).joined() == expected
    else { throw Refusal.invalid }
    // Python copied and authenticated these private staging files before invocation;
    // this second integrity check is not a substitute for vendor authentication.
    return url
}

@available(macOS 12.0, *)
final class Supervisor: NSObject, VZVirtioSocketListenerDelegate, VZVirtualMachineDelegate {
    let session = UUID().uuidString.lowercased()
    var vm: VZVirtualMachine!
    let listener = VZVirtioSocketListener()
    var connection: VZVirtioSocketConnection?
    var rpcConnection: VZVirtioSocketConnection?
    var statusConnection: VZVirtioSocketConnection?
    var parentMonitor: DispatchSourceProcess?
    var stopping = false
    var signals = [DispatchSourceSignal]()
    let worker = DispatchGroup()
    var syntheticConsole: FileHandle?
    var successCount = 0
    let started = Date()

    func finish(_ reason: String) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard !stopping else { return }
        stopping = true
        if let connection = connection { _ = Darwin.shutdown(connection.fileDescriptor, SHUT_RDWR); _ = Darwin.shutdown(bridgeFD, SHUT_RDWR) }
        if let rpc = rpcConnection { _ = Darwin.shutdown(rpc.fileDescriptor, SHUT_RDWR) }
        if let status = statusConnection { _ = Darwin.shutdown(status.fileDescriptor, SHUT_RDWR) }; _ = Darwin.shutdown(statusFD, SHUT_RDWR)
        guard vm.canStop else { refuse("stop state unavailable") }
        // Force-stop the VM, not a polite guest shutdown request.
        vm.stop { error in
            guard error == nil else { refuse("VM force-stop failed") }
            guard self.vm.state == .stopped else { refuse("VM did not enter stopped state") }
            self.worker.notify(queue: .main) {
            self.connection?.close()
            self.syntheticConsole?.closeFile()
            fputs("PROBANT_VM_STOPPED state=stopped reason=\(reason) completion_proved=\(self.successCount) elapsed_seconds=\(Date().timeIntervalSince(self.started))\n", stderr)
            exit(self.successCount == 1 && reason == "broker EOF" ? 0 : 78)
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { refuse("VM stop deadline") }
    }

    func listener(_ listener: VZVirtioSocketListener, shouldAcceptNewConnection new: VZVirtioSocketConnection,
                  from device: VZVirtioSocketDevice) -> Bool {
        // Exactly one of each channel, bound to this VM's socket device.
        guard !stopping, vm.socketDevices.contains(where: { $0 === device }) else { return false }
        if new.destinationPort == rpcPort {
            guard rpcConnection == nil else { return false }
            rpcConnection = new
            let fd = new.fileDescriptor
            var noSignal: Int32 = 1
            guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else { return false }
            // stdout is exclusively Pi RPC, never VM diagnostics or matter content logs.
            DispatchQueue.global().async {
                var bytes = [UInt8](repeating: 0, count: 65536)
                var lineBytes = 0
                var totalBytes = 0
                while true {
                    let n = Darwin.read(fd, &bytes, bytes.count)
                    if n < 0 && errno == EINTR { continue }
                    if n <= 0 { break }
                    totalBytes += n
                    for byte in bytes.prefix(n) {
                        lineBytes = byte == 10 ? 0 : lineBytes + 1
                        if lineBytes > 8 * 1024 * 1024 {
                            DispatchQueue.main.async { self.finish("RPC event quota") }
                            return
                        }
                    }
                    guard totalBytes <= 1024 * 1024 * 1024 else {
                        DispatchQueue.main.async { self.finish("RPC session quota") }; return
                    }
                    do { try writeAll(STDOUT_FILENO, Data(bytes.prefix(n))) }
                    catch { DispatchQueue.main.async { self.finish("RPC output closed") }; break }
                }
            }
            DispatchQueue.global().async {
                var bytes = [UInt8](repeating: 0, count: 65536)
                while true {
                    let n = Darwin.read(STDIN_FILENO, &bytes, bytes.count)
                    if n < 0 && errno == EINTR { continue }
                    if n <= 0 { _ = Darwin.shutdown(fd, SHUT_WR); break }
                    do { try writeAll(fd, Data(bytes.prefix(n))) }
                    catch { break }
                }
            }
            return true
        }
        let hostFD: Int32
        if new.destinationPort == statusPort {
            guard statusConnection == nil else { return false }
            statusConnection = new; hostFD = statusFD
        } else {
            guard connection == nil, new.destinationPort == brokerPort else { return false }
            connection = new; hostFD = bridgeFD
        }
        let fd = new.fileDescriptor
        var timeout = timeval(tv_sec: 600, tv_usec: 0)
        var noSignal: Int32 = 1
        for socket in [fd, hostFD] {
            guard setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
                  setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
                  setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else { return false }
        }
        do {
            let binding: [String: Any] = ["v": 1, "session": self.session, "op": "host.bind"]
            let bind = try JSONSerialization.data(withJSONObject: binding)
            var size = UInt32(bind.count).bigEndian
            try writeAll(hostFD, withUnsafeBytes(of: &size) { Data($0) } + bind)
        } catch { DispatchQueue.main.async { self.finish("host binding failed") }; return false }
        // Duplex framing supports request-body chunks, responses and ACK backpressure.
        for (source, target, fromHost) in [(fd, hostFD, false), (hostFD, fd, true)] {
            worker.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { self.worker.leave() }
                var reason = "broker failure"
                do {
                    var total = 0
                    for _ in 0..<1_000_000 {
                        let header = try exactRead(source, 4)
                        let size = header.reduce(0) { ($0 << 8) | Int($1) }
                        guard size > 0, size <= maxFrame else { throw Refusal.invalid }
                        total += size
                        guard total <= 1024 * 1024 * 1024 else { throw Refusal.invalid }
                        let body = try exactRead(source, size)
                        if fromHost {
                            guard let object = try JSONSerialization.jsonObject(with: body) as? [String: Any] else { throw Refusal.invalid }
                            if object["end"] as? Bool == true && object["vm_complete"] as? Bool == true && object["ok"] as? Bool == true {
                                DispatchQueue.main.async { self.successCount = 1 }
                            }
                        }
                        try writeAll(target, header + body)
                    }
                    reason = "frame quota"
                } catch Refusal.eof { reason = "broker EOF" }
                  catch { }
                DispatchQueue.main.async { self.finish(reason) }
            }
        }
        return true
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        // A guest that stops ITSELF is a failure. Once the host has begun its own teardown the stop is the
        // host's, and finish() is the one place that decides the outcome: it requires the force-stop to
        // succeed and the machine to be in .stopped before anything is reported. Refusing here as well would
        // turn every clean session into exit 78 if the framework delivers this callback for a host stop.
        if stopping { return }
        refuse("guest stopped before host teardown proof")
    }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        refuse("VM runtime error")
    }

    func start(manifest: URL) throws {
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: manifest))
        guard let value = object as? [String: Any],
              Set(value.keys) == Set(["schema", "development_only", "architecture", "artifacts"]),
              let schema = value["schema"] as? NSNumber, integerNumber(schema), schema == 1,
              let development = value["development_only"] as? NSNumber,
              CFGetTypeID(development) == CFBooleanGetTypeID(), !development.boolValue,
              value["architecture"] as? String == "arm64",
              let artifacts = value["artifacts"] as? [String: Any], Set(artifacts.keys) == Set(["kernel", "initrd"])
        else { throw Refusal.invalid }
        #if !arch(arm64)
        throw Refusal.invalid
        #endif
        let root = manifest.deletingLastPathComponent().resolvingSymlinksInPath()
        let kernel = try verifiedArtifact(root, artifacts["kernel"])
        let initrd = try verifiedArtifact(root, artifacts["initrd"])
        let loader = VZLinuxBootLoader(kernelURL: kernel)
        loader.initialRamdiskURL = initrd
        loader.commandLine = "console=hvc0 rdinit=/init panic=0 probant.session=\(session)"
        let config = VZVirtualMachineConfiguration()
        config.bootLoader = loader
        config.cpuCount = 2
        config.memorySize = 1024 * 1024 * 1024
        config.networkDevices = []
        config.directorySharingDevices = []
        config.storageDevices = []
        config.socketDevices = [VZVirtioSocketDeviceConfiguration()]
        config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        // The guest's console is discarded: stdout is Pi's RPC stream and nothing else, and a console that
        // went anywhere would be a place for matter text to end up. A DEVELOPMENT build compiled with
        // -D PROBANT_DEV_CONSOLE sends it to stderr instead, because a guest that fails to boot says so only
        // there. It is a compile-time switch on purpose: no flag, file or environment variable can turn it on
        // in a binary that was built without it, and the release build's hash is the one the manifest pins.
        #if PROBANT_DEV_CONSOLE
        let consoleOutput: FileHandle? = FileHandle.standardError
        #else
        let consoleOutput = FileHandle(forWritingAtPath: "/dev/null")
        #endif
        // No reading handle at all: the guest's console has no input. (/dev/null would also give it none,
        // but it is permanently "readable", which is an invitation to spin.)
        console.attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: nil,
            fileHandleForWriting: consoleOutput)
        config.serialPorts = [console]
        try config.validate()
        vm = VZVirtualMachine(configuration: config)
        vm.delegate = self
        guard let socketDevice = vm.socketDevices.first as? VZVirtioSocketDevice else { throw Refusal.invalid }
        listener.delegate = self
        socketDevice.setSocketListener(listener, forPort: brokerPort)
        socketDevice.setSocketListener(listener, forPort: rpcPort)
        socketDevice.setSocketListener(listener, forPort: statusPort)
        let parent = DispatchSource.makeProcessSource(identifier: getppid(), eventMask: .exit, queue: .main)
        parent.setEventHandler { self.finish("host parent exited") }; parent.resume(); parentMonitor = parent
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { self.finish("host signal") }
            source.resume()
            signals.append(source)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 8 * 3600) { self.finish("session deadline") }
        vm.start { result in
            if case .failure = result { refuse("VM start failed") }
            fputs("PROBANT_VM_STARTED nic=none host_share=none ram_mib=1024 cpus=2\n", stderr)
        }
    }
}

guard CommandLine.arguments.count == 7, CommandLine.arguments[1] == "--owned-runtime",
      CommandLine.arguments[3] == "--bridge-fd", bridgeFD >= 3,
      CommandLine.arguments[5] == "--status-fd", statusFD >= 3, bridgeFD != statusFD else {
    refuse("verified owned runtime and bridge required")
}
guard #available(macOS 12.0, *) else { refuse("macOS 12 or later required by prototype") }
var bridgeInfo = stat()
guard fstat(bridgeFD, &bridgeInfo) == 0, (bridgeInfo.st_mode & S_IFMT) == S_IFSOCK,
      fstat(statusFD, &bridgeInfo) == 0, (bridgeInfo.st_mode & S_IFMT) == S_IFSOCK else { refuse("owned host bridge required") }
let supervisor = Supervisor()
do { try supervisor.start(manifest: URL(fileURLWithPath: CommandLine.arguments[2])) }
catch { refuse("payload verification or VM setup failed") }
dispatchMain()
