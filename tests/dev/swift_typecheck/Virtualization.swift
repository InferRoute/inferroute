// A STUB of the parts of Apple's Virtualization framework the runner uses, written from the SDK's documented
// signatures. It can find Swift-language errors in the runner. It cannot confirm the runner uses the REAL
// framework correctly: it encodes the same understanding of the API the runner was written from.
import Foundation
open class VZBootLoader: NSObject {}
public class VZLinuxBootLoader: VZBootLoader {
    public init(kernelURL: URL) {}
    public var initialRamdiskURL: URL?
    public var commandLine: String = ""
}
open class VZNetworkDeviceConfiguration: NSObject {}
open class VZDirectorySharingDeviceConfiguration: NSObject {}
open class VZStorageDeviceConfiguration: NSObject {}
open class VZSocketDeviceConfiguration: NSObject {}
public class VZVirtioSocketDeviceConfiguration: VZSocketDeviceConfiguration { public override init() {} }
open class VZEntropyDeviceConfiguration: NSObject {}
public class VZVirtioEntropyDeviceConfiguration: VZEntropyDeviceConfiguration { public override init() {} }
open class VZSerialPortAttachment: NSObject {}
public class VZFileHandleSerialPortAttachment: VZSerialPortAttachment {
    public init(fileHandleForReading: FileHandle?, fileHandleForWriting: FileHandle?) {}
}
open class VZSerialPortConfiguration: NSObject { public var attachment: VZSerialPortAttachment? }
public class VZVirtioConsoleDeviceSerialPortConfiguration: VZSerialPortConfiguration { public override init() {} }
public class VZVirtualMachineConfiguration: NSObject {
    public override init() {}
    public var bootLoader: VZBootLoader?
    public var cpuCount: Int = 1
    public var memorySize: UInt64 = 0
    public var networkDevices: [VZNetworkDeviceConfiguration] = []
    public var directorySharingDevices: [VZDirectorySharingDeviceConfiguration] = []
    public var storageDevices: [VZStorageDeviceConfiguration] = []
    public var socketDevices: [VZSocketDeviceConfiguration] = []
    public var entropyDevices: [VZEntropyDeviceConfiguration] = []
    public var serialPorts: [VZSerialPortConfiguration] = []
    public func validate() throws {}
}
open class VZSocketDevice: NSObject {}
public class VZVirtioSocketConnection: NSObject {
    public var destinationPort: UInt32 { 0 }
    public var sourcePort: UInt32 { 0 }
    public var fileDescriptor: Int32 { 0 }
    public func close() {}
}
public protocol VZVirtioSocketListenerDelegate: NSObjectProtocol {
    func listener(_ listener: VZVirtioSocketListener, shouldAcceptNewConnection connection: VZVirtioSocketConnection,
                  from socketDevice: VZVirtioSocketDevice) -> Bool
}
public class VZVirtioSocketListener: NSObject {
    public override init() {}
    public weak var delegate: VZVirtioSocketListenerDelegate?
}
public class VZVirtioSocketDevice: VZSocketDevice {
    public func setSocketListener(_ listener: VZVirtioSocketListener, forPort port: UInt32) {}
}
public protocol VZVirtualMachineDelegate: NSObjectProtocol {
    func guestDidStop(_ virtualMachine: VZVirtualMachine)
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error)
}
public class VZVirtualMachine: NSObject {
    public enum State: Int { case stopped, running, paused, error, starting, pausing, resuming, stopping }
    public init(configuration: VZVirtualMachineConfiguration) {}
    public weak var delegate: VZVirtualMachineDelegate?
    public var socketDevices: [VZSocketDevice] { [] }
    public var canStop: Bool { true }
    public var state: State { .stopped }
    public func stop(completionHandler: @escaping (Error?) -> Void) {}
    public func start(completionHandler: @escaping (Result<Void, Error>) -> Void) {}
}
