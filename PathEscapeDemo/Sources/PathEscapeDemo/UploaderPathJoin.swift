import Foundation

/// Mirrors vulnerable path joins used by Wi‑Fi upload libraries on Apple platforms.

public enum UploaderPathJoin {
    /// kejinlu/SwiftyUploader `MultipartFormDataParser` (main):
    /// `documentPath + (destPath ?? "/") + fileName` — no normalization.
    public static func swiftyUploaderUpload(documentPath: String, destPath: String?, fileName: String) -> String {
        documentPath + (destPath ?? "/") + fileName
    }

    /// kejinlu/SwiftyUploader create/delete: `documentPath + path`
    public static func swiftyUploaderRootConcat(documentPath: String, relative: String) -> String {
        documentPath + relative
    }

    /// swisspol/GCDWebServer `GCDWebUploader.uploadFile`:
    /// `uploadDirectory` + NormalizePath(path) + **raw** `file.fileName` via `stringByAppendingPathComponent`.
    /// Relative `path` is normalized; multipart filename is not.
    public static func gcdWebUploaderUpload(uploadDirectory: String, relativePath: String, fileName: String) -> String {
        let normalized = gcdNormalizePath(relativePath)
        let dir = (uploadDirectory as NSString).appendingPathComponent(normalized)
        return (dir as NSString).appendingPathComponent(fileName)
    }

    /// Subset of `GCDWebServerNormalizePath` (same `..` / `.` rules).
    public static func gcdNormalizePath(_ path: String) -> String {
        var components: [String] = []
        for component in path.split(separator: "/", omittingEmptySubsequences: false).map(String.init) {
            if component == ".." {
                if !components.isEmpty { components.removeLast() }
            } else if !component.isEmpty && component != "." {
                components.append(component)
            }
        }
        if path.first == "/" {
            return "/" + components.joined(separator: "/")
        }
        return components.joined(separator: "/")
    }

    public static func isContained(candidate: String, root: String) -> Bool {
        let c = URL(fileURLWithPath: candidate).standardizedFileURL.path
        let r = URL(fileURLWithPath: root).standardizedFileURL.path
        return c == r || c.hasPrefix(r + "/")
    }
}
