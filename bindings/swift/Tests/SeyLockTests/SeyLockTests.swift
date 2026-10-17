// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi

import Foundation
import Network
import XCTest
@testable import SeyLock

/// The proxy is process-wide, so every test that starts it runs inside this
/// one class, serially, and stops it at the end.
final class SeyLockTests: XCTestCase {
    func testVersion() {
        XCTAssertTrue(SeyLock.version.hasPrefix("0."), SeyLock.version)
    }

    func testRejectedListsAreTypedErrors() {
        XCTAssertThrowsError(try SeyLock.verifyList(signedJSON: "not json", publicKeyBase64: "AAAA")) {
            XCTAssertEqual($0 as? SeyLockError, .listRejected(code: 1))
        }
    }

    /// A signed list from the test vectors verifies through the Swift API,
    /// so signatures and the clock parameter travel correctly.
    func testAcceptsASignedVector() throws {
        let vectors = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()      // SeyLockTests.swift
            .deletingLastPathComponent()      // SeyLockTests
            .deletingLastPathComponent()      // Tests
            .deletingLastPathComponent()      // swift
            .deletingLastPathComponent()      // bindings
            .appendingPathComponent("test-vectors/endpoints.json")
        let file = try JSONSerialization.jsonObject(with: Data(contentsOf: vectors)) as! [String: Any]
        let key = file["public_key_b64"] as! String
        let vector = (file["vectors"] as! [[String: Any]]).first { $0["name"] as? String == "v2 accepted" }!
        let nowMs = (vector["now_ms"] as! NSNumber).doubleValue
        let json = try SeyLock.verifyList(
            signedJSON: vector["signed"] as! String,
            publicKeyBase64: key,
            now: Date(timeIntervalSince1970: nowMs / 1000)
        )
        XCTAssertTrue(json.contains("\"v\":2"), json)
    }

    func testRequestRewriting() {
        let proxy = Proxy(port: 4567, token: "t0k")
        var original = URLRequest(url: URL(string: "https://user:pw@api.example.org/v1/send?x=1")!)
        original.httpMethod = "POST"
        original.setValue("keep", forHTTPHeaderField: "x-app")
        let r = proxy.request(for: original, service: "api")
        XCTAssertEqual(r.url?.absoluteString, "http://127.0.0.1:4567/v1/send?x=1")
        XCTAssertEqual(r.httpMethod, "POST")
        XCTAssertEqual(r.value(forHTTPHeaderField: "x-app"), "keep")
        XCTAssertEqual(r.value(forHTTPHeaderField: "x-transport-token"), "t0k")
        XCTAssertEqual(r.value(forHTTPHeaderField: "x-transport-service"), "api")
    }

    /// URLSession -> SeyLock proxy -> a local HTTP server, and the whole
    /// lifecycle of the proxy.
    func testEndToEndThroughTheProxy() async throws {
        let server = try LocalHTTPServer()
        defer { server.stop() }
        let port = try await server.ready()
        let policy = """
        {"list":{"v":2,"issued_at_ms":1,"expires_at_ms":9000000000000,
         "services":{"api":"http://127.0.0.1:\(port)"},"paths":[{"kind":"direct"}]},
         "network_id":"test","race":{}}
        """
        XCTAssertNil(SeyLock.statusJSON())
        XCTAssertThrowsError(try SeyLock.update(policyJSON: policy)) {
            XCTAssertEqual($0 as? SeyLockError, .notRunning)
        }
        let proxy = try SeyLock.start(policyJSON: policy)
        defer { SeyLock.stop() }
        XCTAssertThrowsError(try SeyLock.start(policyJSON: policy)) {
            XCTAssertEqual($0 as? SeyLockError, .alreadyRunning)
        }

        let request = proxy.request(for: URLRequest(url: URL(string: "https://api.example.org/hello")!), service: "api")
        let (body, response) = try await URLSession.shared.data(for: request)
        let http = response as! HTTPURLResponse
        XCTAssertEqual(http.statusCode, 200)
        XCTAssertEqual(http.value(forHTTPHeaderField: "x-transport-path"), "direct")
        XCTAssertEqual(String(decoding: body, as: UTF8.self), "path=/hello")

        try SeyLock.setNetwork("cell:1")
        XCTAssertTrue(SeyLock.statusJSON()?.contains("\"network_id\":\"cell:1\"") ?? false)
        try SeyLock.update(policyJSON: policy)
        XCTAssertTrue(SeyLock.stop())
        XCTAssertFalse(SeyLock.stop())
    }
}

/// A minimal HTTP server on loopback that answers every request with the
/// request path, enough to see a request arrive through the proxy.
final class LocalHTTPServer {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "local-http")

    init() throws {
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: params)
        listener.newConnectionHandler = { [queue] connection in
            connection.start(queue: queue)
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, _, _ in
                let head = data.map { String(decoding: $0, as: UTF8.self) } ?? ""
                let path = head.split(separator: " ").dropFirst().first.map(String.init) ?? "?"
                let body = "path=\(path)"
                let reply = "HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
                connection.send(content: Data(reply.utf8), completion: .contentProcessed { _ in connection.cancel() })
            }
        }
    }

    func ready() async throws -> UInt16 {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<UInt16, Error>) in
            var resumed = false
            listener.stateUpdateHandler = { [listener] state in
                guard !resumed else { return }
                switch state {
                case .ready:
                    resumed = true
                    c.resume(returning: listener.port?.rawValue ?? 0)
                case .failed(let error):
                    resumed = true
                    c.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: queue)
        }
    }

    func stop() { listener.cancel() }
}
