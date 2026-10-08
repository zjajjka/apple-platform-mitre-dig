import Foundation

/// Mirrors iTransfer `FileManagerService.contentURL(for:)` (isaveall/iFTPServer).
/// Used to prove path confinement failure on Apple Foundation (same API as iOS).
public enum ContentURL {
    public static func resolve(documentRoot: URL, path: String) -> URL {
        if path.hasPrefix(documentRoot.path) {
            return URL(fileURLWithPath: path)
        }
        let relative = path.hasPrefix("/") ? String(path.dropFirst()) : path
        return documentRoot.appendingPathComponent(relative)
    }

    /// Secure alternative: reject anything that escapes documentRoot after standardization.
    public static func resolveSafe(documentRoot: URL, path: String) -> URL? {
        let candidate = resolve(documentRoot: documentRoot, path: path).standardizedFileURL
        let root = documentRoot.standardizedFileURL.path
        let cand = candidate.path
        guard cand == root || cand.hasPrefix(root + "/") else { return nil }
        return candidate
    }
}
