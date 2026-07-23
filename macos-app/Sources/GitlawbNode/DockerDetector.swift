import Foundation

/// Detects available Docker runtimes on macOS.
struct DockerDetector {
    struct DockerRuntime {
        let path: String
        let name: String
        let version: String
    }

    /// Well-known locations for docker binaries on macOS.
    private static let searchPaths: [String] = [
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker",
        "/Applications/Docker.app/Contents/Resources/bin/docker",
        "\(NSHomeDirectory())/.orbstack/bin/docker",
        "/Applications/OrbStack.app/Contents/MacOS/xbin/docker",
    ]

    /// Finds the first available Docker binary and verifies the daemon is running.
    static func detect() -> DockerRuntime? {
        // Check PATH first, then well-known locations
        let pathResult = run(command: "/usr/bin/which", arguments: ["docker"])
        var candidates = [String]()
        if let found = pathResult, !found.isEmpty {
            candidates.append(found.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        candidates.append(contentsOf: searchPaths)

        for path in candidates {
            guard FileManager.default.isExecutableFile(atPath: path) else { continue }
            // Verify daemon is responding
            if let version = dockerVersion(at: path) {
                let name = runtimeName(for: path)
                return DockerRuntime(path: path, name: name, version: version)
            }
        }
        return nil
    }

    /// Returns the docker binary path or nil if unavailable.
    static func dockerPath() -> String? {
        detect()?.path
    }

    // MARK: - Private

    private static func dockerVersion(at path: String) -> String? {
        guard let output = run(command: path, arguments: ["version", "--format", "{{.Server.Version}}"]) else {
            return nil
        }
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private static func runtimeName(for path: String) -> String {
        if path.contains("OrbStack") || path.contains(".orbstack") {
            return "OrbStack"
        } else if path.contains("Docker.app") || path == "/usr/local/bin/docker" {
            return "Docker Desktop"
        } else if path.contains("colima") {
            return "Colima"
        } else {
            return "Docker"
        }
    }

    private static func run(command: String, arguments: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: command)
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return nil }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8)
        } catch {
            return nil
        }
    }
}
