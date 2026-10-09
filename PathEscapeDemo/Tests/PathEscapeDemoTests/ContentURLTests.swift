import XCTest
@testable import PathEscapeDemo

final class ContentURLTests: XCTestCase {
    func testTraversalEscapesDocumentRoot() throws {
        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("itransfer-dig-\(UUID().uuidString)", isDirectory: true)
        let docs = base.appendingPathComponent("Documents", isDirectory: true)
        let secretDir = base.appendingPathComponent("Library", isDirectory: true)
        let secretFile = secretDir.appendingPathComponent("secret.txt")

        try fm.createDirectory(at: docs, withIntermediateDirectories: true)
        try fm.createDirectory(at: secretDir, withIntermediateDirectories: true)
        try "TOKEN-OUTSIDE-DOCS".write(to: secretFile, atomically: true, encoding: .utf8)
        defer { try? fm.removeItem(at: base) }

        // HTTP GET /../Library/secret.txt after percent-decode (sibling of Documents)
        let attack = "/../Library/secret.txt"
        let resolved = ContentURL.resolve(documentRoot: docs, path: attack).standardizedFileURL

        XCTAssertFalse(
            resolved.path.hasPrefix(docs.standardizedFileURL.path + "/") || resolved.path == docs.standardizedFileURL.path,
            "vulnerable resolve must escape Documents; got \(resolved.path)"
        )
        XCTAssertEqual(resolved.standardizedFileURL, secretFile.standardizedFileURL)
        let body = try String(contentsOf: resolved, encoding: .utf8)
        XCTAssertEqual(body, "TOKEN-OUTSIDE-DOCS")
    }

    func testSafeResolverRejectsEscape() {
        let docs = URL(fileURLWithPath: "/var/tmp/Documents", isDirectory: true)
        XCTAssertNil(ContentURL.resolveSafe(documentRoot: docs, path: "/../Library/secret.txt"))
        let ok = ContentURL.resolveSafe(documentRoot: docs, path: "/notes/a.txt")
        XCTAssertEqual(ok?.lastPathComponent, "a.txt")
    }

    func testAbsolutePathPrefixBypass() throws {
        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("itransfer-abs-\(UUID().uuidString)", isDirectory: true)
        let docs = base.appendingPathComponent("Documents", isDirectory: true)
        let outside = base.appendingPathComponent("outside.txt")
        try fm.createDirectory(at: docs, withIntermediateDirectories: true)
        try "ABS-BYPASS".write(to: outside, atomically: true, encoding: .utf8)
        defer { try? fm.removeItem(at: base) }

        // If request path is absolute and hasPrefix(documentRoot.path) is false,
        // appendingPathComponent still used — but if attacker knows full docs path
        // and appends /../outside via string that still hasPrefix docs.path incorrectly...
        // Absolute docs.path + "/../outside.txt" hasPrefix docs.path → true → fileURLWithPath
        let crafted = docs.path + "/../outside.txt"
        let resolved = ContentURL.resolve(documentRoot: docs, path: crafted).standardizedFileURL
        XCTAssertEqual(try String(contentsOf: resolved, encoding: .utf8), "ABS-BYPASS")
        XCTAssertNil(ContentURL.resolveSafe(documentRoot: docs, path: crafted))
    }
}
