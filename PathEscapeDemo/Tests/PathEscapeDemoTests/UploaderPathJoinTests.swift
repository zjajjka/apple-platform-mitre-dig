import XCTest
@testable import PathEscapeDemo

final class UploaderPathJoinTests: XCTestCase {
    func testSwiftyUploaderUploadFilenameTraversalWritesOutsideDocuments() throws {
        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("swifty-up-\(UUID().uuidString)", isDirectory: true)
        let docs = base.appendingPathComponent("Documents", isDirectory: true)
        let outsideDir = base.appendingPathComponent("Library", isDirectory: true)
        try fm.createDirectory(at: docs, withIntermediateDirectories: true)
        try fm.createDirectory(at: outsideDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: base) }

        let tmp = base.appendingPathComponent("upload-tmp.bin")
        try Data("PWNED".utf8).write(to: tmp)

        let toPath = UploaderPathJoin.swiftyUploaderUpload(
            documentPath: docs.path,
            destPath: "/",
            fileName: "../Library/pwned.txt"
        )
        XCTAssertFalse(
            UploaderPathJoin.isContained(candidate: toPath, root: docs.path),
            "expected escape; toPath=\(toPath)"
        )

        try fm.moveItem(atPath: tmp.path, toPath: toPath)
        let escaped = outsideDir.appendingPathComponent("pwned.txt")
        XCTAssertEqual(try String(contentsOf: escaped, encoding: .utf8), "PWNED")
    }

    func testSwiftyUploaderDeletePathTraversal() throws {
        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("swifty-del-\(UUID().uuidString)", isDirectory: true)
        let docs = base.appendingPathComponent("Documents", isDirectory: true)
        let victim = base.appendingPathComponent("Library/victim.txt")
        try fm.createDirectory(at: docs, withIntermediateDirectories: true)
        try fm.createDirectory(at: victim.deletingLastPathComponent(), withIntermediateDirectories: true)
        try "KEEP".write(to: victim, atomically: true, encoding: .utf8)
        defer { try? fm.removeItem(at: base) }

        let target = UploaderPathJoin.swiftyUploaderRootConcat(
            documentPath: docs.path,
            relative: "/../Library/victim.txt"
        )
        XCTAssertFalse(UploaderPathJoin.isContained(candidate: target, root: docs.path))
        try fm.removeItem(atPath: target)
        XCTAssertFalse(fm.fileExists(atPath: victim.path))
    }

    func testGcdWebUploaderRawFilenameTraversal() throws {
        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("gcd-up-\(UUID().uuidString)", isDirectory: true)
        let upload = base.appendingPathComponent("Documents", isDirectory: true)
        let outside = base.appendingPathComponent("Library", isDirectory: true)
        try fm.createDirectory(at: upload, withIntermediateDirectories: true)
        try fm.createDirectory(at: outside, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: base) }

        let tmp = base.appendingPathComponent("part.bin")
        try Data("GCD".utf8).write(to: tmp)

        // path query is normalized; Content-Disposition filename is not
        let toPath = UploaderPathJoin.gcdWebUploaderUpload(
            uploadDirectory: upload.path,
            relativePath: "/",
            fileName: "../Library/gcd-pwn.txt"
        )
        XCTAssertFalse(
            UploaderPathJoin.isContained(candidate: toPath, root: upload.path),
            "GCDWebUploader-style join must escape; toPath=\(toPath)"
        )

        try fm.moveItem(atPath: tmp.path, toPath: toPath)
        XCTAssertEqual(
            try String(contentsOf: outside.appendingPathComponent("gcd-pwn.txt"), encoding: .utf8),
            "GCD"
        )
    }

    func testGcdNormalizePathCollapsesDotDotInQueryPath() {
        // Issue #57 fix: query `path` is normalized so bare `../` cannot climb as path components.
        XCTAssertEqual(UploaderPathJoin.gcdNormalizePath("/../../etc/passwd"), "/etc/passwd")
        XCTAssertEqual(UploaderPathJoin.gcdNormalizePath("/a/../b"), "/b")
        // Filename channel remains unnormalized (see testGcdWebUploaderRawFilenameTraversal).
    }
}

