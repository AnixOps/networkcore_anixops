import CryptoKit
import Foundation

/// A plugin script the user allowed: the exact copy downloaded when they agreed. The tunnel runs this copy and
/// nothing else; a newer version at the same address needs a new agreement.
public struct MitmScript: Codable, Equatable {
    /// Largest script accepted.
    public static let maxBytes = 1024 * 1024

    /// The `script-path` as written in the plugin.
    public var path: String
    public var url: URL
    public var source: String
    /// SHA-256 of `source`, lower-case hex.
    public var sha256: String
    public var allowedAt: Date

    public init(path: String, url: URL, data: Data, allowedAt: Date = Date()) throws {
        if data.count > Self.maxBytes {
            throw MitmScriptError.tooLarge
        }
        guard let source = String(data: data, encoding: .utf8),
              !source.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            throw MitmScriptError.notText
        }
        self.path = path
        self.url = url
        self.source = source
        sha256 = Self.digest(data)
        self.allowedAt = allowedAt
    }

    public static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

public enum MitmScriptError: Error, Equatable {
    case tooLarge
    case notText
    case notHTTPS
    /// The allowed scripts of the enabled plugins together would exceed what the profile carries.
    case libraryFull
}

/// The scripts the user allowed, by `script-path`, saved next to the plugin list. Only the containing app reads
/// this file; the tunnel gets the allowed sources of the enabled plugins through the tunnel profile.
public struct MitmScriptLibrary: Codable, Equatable {
    /// Allowed scripts handed to one tunnel, in bytes.
    public static let maxActiveBytes = 2 * 1024 * 1024

    public private(set) var scripts: [String: MitmScript] = [:]

    public init() {}

    public mutating func allow(_ script: MitmScript) {
        scripts[script.path] = script
    }

    public mutating func revoke(_ path: String) {
        scripts.removeValue(forKey: path)
    }

    /// `script-path` to source for the allowed scripts among `references`; scripts not allowed are left out
    /// and their dispatches do nothing.
    public func sources(for references: [MitmScriptReference]) throws -> [String: String] {
        var sources: [String: String] = [:]
        for reference in references {
            if let script = scripts[reference.path] {
                sources[reference.path] = script.source
            }
        }
        if sources.values.reduce(0, { $0 + $1.utf8.count }) > Self.maxActiveBytes {
            throw MitmScriptError.libraryFull
        }
        return sources
    }

    public static var defaultURL: URL {
        get throws {
            try FileManager.default
                .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
                .appendingPathComponent("mitm-scripts.json")
        }
    }

    public static func load(from url: URL) throws -> MitmScriptLibrary {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return MitmScriptLibrary()
        }
        return try JSONDecoder().decode(MitmScriptLibrary.self, from: Data(contentsOf: url))
    }

    public func save(to url: URL) throws {
        try JSONEncoder().encode(self).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    /// The tunnel profile value under `TunnelProfileKeys.mitmScripts`.
    public static func profileValue(_ sources: [String: String]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(sources)
    }

    public static func sources(fromProfileValue value: Data?) -> [String: String] {
        value.flatMap { try? JSONDecoder().decode([String: String].self, from: $0) } ?? [:]
    }

    /// Writes `sources` into `directory` as one file per script, named by its digest, and returns the
    /// `script_assets` map the runtime expects. Files no longer listed are removed.
    public static func writeAssets(_ sources: [String: String], to directory: URL) throws -> [String: String] {
        let manager = FileManager.default
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        var assets: [String: String] = [:]
        var keep: Set<String> = []
        for (path, source) in sources {
            let data = Data(source.utf8)
            let name = "\(MitmScript.digest(data)).js"
            let file = directory.appendingPathComponent(name)
            if !manager.fileExists(atPath: file.path) {
                try data.write(to: file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            }
            assets[path] = file.path
            keep.insert(name)
        }
        for name in try manager.contentsOfDirectory(atPath: directory.path) where !keep.contains(name) {
            try? manager.removeItem(at: directory.appendingPathComponent(name))
        }
        return assets
    }
}

extension MitmPluginLibrary {
    /// Script references of the plugins handed to the tunnel.
    public var activeScriptReferences: [MitmScriptReference] {
        guard isEnabled else {
            return []
        }
        return plugins.filter(\.isEnabled).flatMap(\.scriptReferences)
    }
}

/// Downloads a plugin or script the user asked for by address: `https` only, no cookies or cache, and stopped
/// as soon as it grows past `maxBytes`.
public enum MitmDownload {
    public enum Failure: Error, Equatable {
        case notHTTPS
        case tooLarge
        case status(Int)
    }

    public static func fetch(_ url: URL, maxBytes: Int, session: URLSession = MitmDownload.session) async throws -> Data {
        guard url.scheme?.lowercased() == "https" else {
            throw Failure.notHTTPS
        }
        let (bytes, response) = try await session.bytes(from: url)
        if response.url?.scheme?.lowercased() != "https" {
            throw Failure.notHTTPS
        }
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw Failure.status(http.statusCode)
        }
        if response.expectedContentLength > Int64(maxBytes) {
            throw Failure.tooLarge
        }
        var data = Data()
        for try await byte in bytes {
            if data.count == maxBytes {
                throw Failure.tooLarge
            }
            data.append(byte)
        }
        return data
    }

    public static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.timeoutIntervalForRequest = 20
        return URLSession(configuration: configuration)
    }()
}
