// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//
// Swift API for SeyLock: reach your own servers from networks that block them.
// A thin layer over the C ABI in include/seylock.h; see README.md and
// PROTOCOL.md for what the calls do.

import Foundation
import SeyLockFFI

/// Why a SeyLock call failed. Raw codes follow include/seylock.h.
public enum SeyLockError: Error, Equatable, CustomStringConvertible {
    /// The endpoint list was rejected; the code (1 to 11) names the rule it
    /// broke (PROTOCOL.md, "Acceptance").
    case listRejected(code: Int32)
    /// `start` was called while a proxy is running.
    case alreadyRunning
    /// The call needs a running proxy and there is none.
    case notRunning
    /// The loopback port could not be bound.
    case bindFailed
    /// The policy JSON is invalid.
    case invalidPolicy
    /// An internal error or an invalid argument.
    case internalError(code: Int32)

    init(code: Int32) {
        switch code {
        case 1...99: self = .listRejected(code: code)
        case 101: self = .alreadyRunning
        case 102: self = .notRunning
        case 103: self = .bindFailed
        case 104: self = .invalidPolicy
        default: self = .internalError(code: code)
        }
    }

    public var description: String {
        switch self {
        case .listRejected(let code): return "endpoint list rejected (code \(code))"
        case .alreadyRunning: return "a proxy is already running"
        case .notRunning: return "no proxy is running"
        case .bindFailed: return "the loopback port could not be bound"
        case .invalidPolicy: return "the policy JSON is invalid"
        case .internalError(let code): return "internal error (code \(code))"
        }
    }
}

/// A running SeyLock proxy: where it listens and the token it requires.
public struct Proxy: Equatable, Sendable {
    /// Port on 127.0.0.1.
    public let port: UInt16
    /// Value for the `x-transport-token` header.
    public let token: String

    /// The same request, sent through SeyLock to `service` (a service name
    /// from the list). The scheme, host and port are replaced by the local
    /// proxy; the path, query, method, body and other headers are kept.
    public func request(for original: URLRequest, service: String) -> URLRequest {
        var request = original
        if let url = original.url,
           var parts = URLComponents(url: url, resolvingAgainstBaseURL: false) {
            parts.scheme = "http"
            parts.host = "127.0.0.1"
            parts.port = Int(port)
            parts.user = nil
            parts.password = nil
            request.url = parts.url
        }
        request.setValue(token, forHTTPHeaderField: "x-transport-token")
        request.setValue(service, forHTTPHeaderField: "x-transport-service")
        return request
    }
}

/// The SeyLock library. All calls are safe from any thread.
public enum SeyLock {
    /// Library version, for example "0.2.0".
    public static var version: String {
        takeString(seylock_version()) ?? ""
    }

    /// Verifies a signed endpoint list against the pinned Ed25519 public key
    /// and returns the accepted list as JSON, ready for the policy.
    ///
    /// - Parameters:
    ///   - signedJSON: The signed envelope `{"doc": ..., "sig_b64": ...}`.
    ///   - publicKeyBase64: Standard base64 of the 32-byte public key.
    ///   - currentIssuedAtMs: `issued_at_ms` of the list already accepted, or
    ///     0; only a newer list is accepted.
    ///   - now: The device clock.
    public static func verifyList(
        signedJSON: String,
        publicKeyBase64: String,
        currentIssuedAtMs: Int64 = 0,
        now: Date = Date()
    ) throws -> String {
        var doc: UnsafeMutablePointer<CChar>?
        let nowMs = Int64((now.timeIntervalSince1970 * 1000).rounded())
        let code = seylock_endpoints_verify(signedJSON, publicKeyBase64, nowMs, currentIssuedAtMs, &doc)
        // Taken (and freed) whatever the outcome.
        let json = takeString(doc)
        guard code == 0, let json else {
            throw SeyLockError(code: code == 0 ? 100 : code)
        }
        return json
    }

    /// Starts the process-wide proxy with a policy:
    /// `{"list": <accepted list>, "network_id": "...", "race": {}, ...}`.
    @discardableResult
    public static func start(policyJSON: String) throws -> Proxy {
        var port: UInt16 = 0
        var token: UnsafeMutablePointer<CChar>?
        let code = seylock_start(policyJSON, &port, &token)
        // Taken (and freed) whatever the outcome.
        let tokenString = takeString(token)
        guard code == 0, let tokenString else {
            throw SeyLockError(code: code == 0 ? 100 : code)
        }
        return Proxy(port: port, token: tokenString)
    }

    /// Replaces the list, network and permissions of the running proxy.
    public static func update(policyJSON: String) throws {
        try check(seylock_update(policyJSON))
    }

    /// Tells the proxy the device changed networks. Pass an opaque id, for
    /// example a salted hash of the Wi-Fi name, never the name itself.
    public static func setNetwork(_ networkID: String) throws {
        try check(seylock_set_network(networkID))
    }

    /// The running proxy's state as JSON, or nil if none is running. Persist
    /// its `memory` and pass it back in the next policy.
    public static func statusJSON() -> String? {
        takeString(seylock_status_json())
    }

    /// Stops the proxy. Returns whether one was running.
    @discardableResult
    public static func stop() -> Bool {
        seylock_stop() == 0
    }

    private static func check(_ code: Int32) throws {
        if code != 0 { throw SeyLockError(code: code) }
    }

    /// Copies a string returned by the library and frees the original.
    private static func takeString(_ pointer: UnsafeMutablePointer<CChar>?) -> String? {
        guard let pointer else { return nil }
        defer { seylock_string_free(pointer) }
        return String(cString: pointer)
    }
}
