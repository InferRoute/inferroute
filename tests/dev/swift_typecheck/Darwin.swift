// Stand-ins for what Darwin has and Glibc does not, so that what is LEFT in the compiler's output is about
// the runner and not about the platform this check runs on.
@_exported import Glibc
import Dispatch
public let SO_NOSIGPIPE: Int32 = 0x1022
public let SHUT_RDWR: Int32 = 2
public let SHUT_WR: Int32 = 1
public protocol DispatchSourceProcess: DispatchSourceProtocol {}
public struct ProcessEvent: OptionSet { public let rawValue: UInt; public init(rawValue: UInt) { self.rawValue = rawValue }
    public static let exit = ProcessEvent(rawValue: 1) }
extension DispatchSource {
    public class func makeProcessSource(identifier: pid_t, eventMask: ProcessEvent, queue: DispatchQueue? = nil) -> DispatchSourceProcess { fatalError() }
}
