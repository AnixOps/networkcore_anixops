import Foundation

/// One imported Loon plugin. The text is kept as imported; the packet tunnel's runtime translates and merges
/// the enabled plugins (`mitm_policy::loon_plugin` in Rust). The summary here is only for the list in the app.
public struct MitmPlugin: Codable, Equatable, Identifiable {
    /// Largest plugin text accepted from a file or the clipboard.
    public static let maxBytes = 256 * 1024

    public var id: UUID
    public var name: String
    public var text: String
    public var isEnabled: Bool
    /// Where a remote plugin was downloaded from; relative `script-path`s resolve against it.
    public var sourceURL: URL?

    public init(text: String, fallbackName: String = "未命名插件", sourceURL: URL? = nil, id: UUID = UUID()) throws {
        if text.utf8.count > Self.maxBytes {
            throw MitmPluginError.tooLarge
        }
        let summary = Self.summarize(text)
        if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw MitmPluginError.empty
        }
        if summary.rewriteLines + summary.scriptLines == 0, summary.hostnames.isEmpty {
            throw MitmPluginError.nothingToApply
        }
        self.id = id
        name = summary.name ?? fallbackName
        self.text = text
        isEnabled = true
        self.sourceURL = sourceURL
    }

    /// The `script-path` of every `[Script]` line, in order and without repeats.
    public var scriptReferences: [MitmScriptReference] {
        var references: [MitmScriptReference] = []
        var inScript = false
        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("["), line.hasSuffix("]") {
                inScript = line.dropFirst().dropLast().trimmingCharacters(in: .whitespaces).lowercased() == "script"
                continue
            }
            guard inScript, !line.hasPrefix("#"), let path = Self.attribute("script-path", in: line) else {
                continue
            }
            if !references.contains(where: { $0.path == path }) {
                references.append(
                    MitmScriptReference(path: path, tag: Self.attribute("tag", in: line), base: sourceURL)
                )
            }
        }
        return references
    }

    /// The value of `name=value` (or `name = value`) in a comma-separated script line. The first item also holds
    /// the type and pattern, so the attribute may start at any word of an item.
    static func attribute(_ name: String, in line: String) -> String? {
        for item in line.split(separator: ",") {
            let words = item.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            for (index, word) in words.enumerated() {
                let candidate = words[index...].joined(separator: " ")
                guard word.lowercased().hasPrefix(name) else {
                    continue
                }
                let rest = candidate.dropFirst(name.count).trimmingCharacters(in: .whitespaces)
                guard rest.hasPrefix("=") else {
                    continue
                }
                let value = rest.dropFirst().trimmingCharacters(in: CharacterSet(charactersIn: " \"'"))
                return value.isEmpty ? nil : value
            }
        }
        return nil
    }

    public var summary: MitmPluginSummary {
        Self.summarize(text)
    }

    /// Reads `#!name`, the `[MITM] hostname` list and how many lines each kind of section holds.
    public static func summarize(_ text: String) -> MitmPluginSummary {
        var summary = MitmPluginSummary()
        var section = ""
        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty {
                continue
            }
            if line.hasPrefix("#!") {
                let meta = line.dropFirst(2)
                if let equals = meta.firstIndex(of: "="),
                   meta[..<equals].trimmingCharacters(in: .whitespaces).lowercased() == "name"
                {
                    let value = meta[meta.index(after: equals)...].trimmingCharacters(in: .whitespaces)
                    if !value.isEmpty {
                        summary.name = value
                    }
                }
                continue
            }
            if line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("//") {
                continue
            }
            if line.hasPrefix("["), line.hasSuffix("]") {
                section = line.dropFirst().dropLast().trimmingCharacters(in: .whitespaces).lowercased()
                continue
            }
            switch section {
            case "rewrite", "url rewrite", "remote rewrite", "header rewrite", "remote header rewrite",
                 "body rewrite", "remote body rewrite", "map local":
                summary.rewriteLines += 1
            case "script":
                summary.scriptLines += 1
            case "rule":
                summary.ruleLines += 1
            case "mitm":
                guard let equals = line.firstIndex(of: "="),
                      line[..<equals].trimmingCharacters(in: .whitespaces).lowercased() == "hostname"
                else {
                    continue
                }
                for item in line[line.index(after: equals)...].split(separator: ",") {
                    var host = item.trimmingCharacters(in: .whitespaces)
                    for marker in ["%APPEND%", "%INSERT%"] where host.uppercased().hasPrefix(marker) {
                        host = String(host.dropFirst(marker.count)).trimmingCharacters(in: .whitespaces)
                    }
                    if !host.isEmpty, !host.hasPrefix("-"), !host.hasPrefix("!"),
                       !summary.hostnames.contains(host.lowercased())
                    {
                        summary.hostnames.append(host.lowercased())
                    }
                }
            case "plugin" where summary.name == nil:
                if let equals = line.firstIndex(of: "="),
                   line[..<equals].trimmingCharacters(in: .whitespaces).lowercased() == "name"
                {
                    let value = line[line.index(after: equals)...].trimmingCharacters(in: .whitespaces)
                    summary.name = value.isEmpty ? nil : value
                }
            default:
                continue
            }
        }
        return summary
    }
}

public struct MitmPluginSummary: Equatable {
    public var name: String?
    /// Hosts the plugin decrypts, lower-cased, without exclusions.
    public var hostnames: [String] = []
    /// URL, header and body rewrites and Map Local lines.
    public var rewriteLines = 0
    /// `[Script]` lines. A script runs only after the user allows it (`MitmScriptLibrary`).
    public var scriptLines = 0
    /// `[Rule]` lines. Routing rules from plugins are not applied on iOS yet.
    public var ruleLines = 0
}

public enum MitmPluginError: Error, Equatable {
    case empty
    case tooLarge
    case nothingToApply
    /// The enabled plugins together would exceed what the tunnel accepts.
    case libraryFull
}

/// The plugins the user imported and the master switch, saved as JSON in the app's Application Support folder.
/// Only the containing app reads this file; the tunnel gets the enabled texts through the tunnel profile.
public struct MitmPluginLibrary: Codable, Equatable {
    /// Matches `MAX_POLICY_BYTES` in crates/engine-embedded/src/mitm.
    public static let maxActiveBytes = 512 * 1024

    public var isEnabled = false
    public private(set) var plugins: [MitmPlugin] = []

    public init() {}

    /// Texts handed to the tunnel: nothing while the master switch is off.
    public var activeTexts: [String] {
        isEnabled ? plugins.filter(\.isEnabled).map(\.text) : []
    }

    public mutating func add(_ plugin: MitmPlugin) throws {
        var next = self
        next.plugins.append(plugin)
        try next.checkSize()
        self = next
    }

    public mutating func setEnabled(_ enabled: Bool, for id: UUID) throws {
        guard let index = plugins.firstIndex(where: { $0.id == id }) else {
            return
        }
        var next = self
        next.plugins[index].isEnabled = enabled
        try next.checkSize()
        self = next
    }

    public mutating func remove(_ id: UUID) {
        plugins.removeAll { $0.id == id }
    }

    private func checkSize() throws {
        if plugins.filter(\.isEnabled).reduce(0, { $0 + $1.text.utf8.count }) > Self.maxActiveBytes {
            throw MitmPluginError.libraryFull
        }
    }

    public static var defaultURL: URL {
        get throws {
            try FileManager.default
                .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
                .appendingPathComponent("mitm-plugins.json")
        }
    }

    public static func load(from url: URL) throws -> MitmPluginLibrary {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return MitmPluginLibrary()
        }
        return try JSONDecoder().decode(MitmPluginLibrary.self, from: Data(contentsOf: url))
    }

    public func save(to url: URL) throws {
        try JSONEncoder().encode(self).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    /// The tunnel profile value under `TunnelProfileKeys.mitmPlugins`.
    public static func profileValue(_ texts: [String]) throws -> Data {
        try JSONEncoder().encode(texts)
    }

    public static func texts(fromProfileValue value: Data?) -> [String] {
        value.flatMap { try? JSONDecoder().decode([String].self, from: $0) } ?? []
    }
}

/// A `script-path` in a plugin. `path` is the text as written, which is how the runtime looks the script up;
/// `url` is where the app downloads it from, `nil` when it is not an `https` URL (or a path relative to a
/// remote plugin's address).
public struct MitmScriptReference: Equatable, Hashable {
    public var path: String
    public var tag: String?
    public var url: URL?

    public init(path: String, tag: String?, base: URL?) {
        self.path = path
        self.tag = tag
        let resolved = URL(string: path, relativeTo: base)?.absoluteURL
        url = resolved?.scheme?.lowercased() == "https" ? resolved : nil
    }
}
