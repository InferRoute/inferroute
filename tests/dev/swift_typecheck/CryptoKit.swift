import Foundation
public struct SHA256Digest: Sequence {
    public func makeIterator() -> IndexingIterator<[UInt8]> { [UInt8]().makeIterator() }
}
public struct SHA256 {
    public init() {}
    public mutating func update(data: Data) {}
    public func finalize() -> SHA256Digest { SHA256Digest() }
}
