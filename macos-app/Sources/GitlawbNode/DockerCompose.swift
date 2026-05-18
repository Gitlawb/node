import Foundation

/// Represents the aggregate state of the Docker Compose stack.
enum NodeStatus: Equatable {
    case stopped
    case starting
    case running
    case unhealthy
    case error(String)

    var label: String {
        switch self {
        case .stopped: return "Stopped"
        case .starting: return "Starting…"
        case .running: return "Running"
        case .unhealthy: return "Unhealthy"
        case .error(let msg): return "Error: \(msg)"
        }
    }
}

/// Manages the Docker Compose lifecycle for the gitlawb node stack.
class DockerCompose {
    /// Current status, updated by polling.
    private(set) var status: NodeStatus = .stopped {
        didSet {
            if oldValue != status {
                onStatusChange?(status)
            }
        }
    }

    /// Called whenever status changes.
    var onStatusChange: ((NodeStatus) -> Void)?

    private var pollTimer: Timer?
    private let pollInterval: TimeInterval = 5.0

    /// Path to the docker-compose.yml — uses the repo's file if available, otherwise generates one.
    var composeFilePath: String {
        // Prefer the repo's own docker-compose.yml (supports `build: .`)
        let repoCompose = Config.shared.repoPath.appendingPathComponent("docker-compose.yml")
        if FileManager.default.fileExists(atPath: repoCompose.path) {
            return repoCompose.path
        }
        // Fallback: generate a compose file with pre-built image
        let userPath = Config.shared.dataDirectory.appendingPathComponent("docker-compose.yml").path
        try? FileManager.default.createDirectory(at: Config.shared.dataDirectory, withIntermediateDirectories: true)
        let content = Self.generateComposeFile()
        try? content.write(toFile: userPath, atomically: true, encoding: .utf8)
        return userPath
    }

    /// Project directory for docker compose (needed for `build: .` context).
    var projectDirectory: String {
        let repoCompose = Config.shared.repoPath.appendingPathComponent("docker-compose.yml")
        if FileManager.default.fileExists(atPath: repoCompose.path) {
            return Config.shared.repoPath.path
        }
        return Config.shared.dataDirectory.path
    }

    /// Path to the .env file with user configuration.
    var envFilePath: String {
        Config.shared.dataDirectory.appendingPathComponent(".env").path
    }

    // MARK: - Lifecycle

    func start() {
        guard let docker = DockerDetector.dockerPath() else {
            status = .error("Docker not found")
            return
        }

        status = .starting
        Config.shared.writeEnvFile()

        runAsync(docker: docker, arguments: [
            "compose",
            "--project-directory", projectDirectory,
            "-f", composeFilePath,
            "--env-file", envFilePath,
            "up", "-d",
        ]) { [weak self] success, output in
            DispatchQueue.main.async {
                if success {
                    self?.refreshStatus()
                } else {
                    self?.status = .error(output ?? "Failed to start")
                }
            }
        }
    }

    func stop() {
        guard let docker = DockerDetector.dockerPath() else {
            status = .error("Docker not found")
            return
        }

        runAsync(docker: docker, arguments: [
            "compose",
            "--project-directory", projectDirectory,
            "-f", composeFilePath,
            "--env-file", envFilePath,
            "down",
        ]) { [weak self] _, _ in
            DispatchQueue.main.async {
                self?.status = .stopped
            }
        }
    }

    func refreshStatus() {
        guard let docker = DockerDetector.dockerPath() else {
            status = .error("Docker not found")
            return
        }

        let output = runSync(docker: docker, arguments: [
            "compose",
            "--project-directory", projectDirectory,
            "-f", composeFilePath,
            "--env-file", envFilePath,
            "ps", "--format", "json",
        ])

        guard let output = output, !output.isEmpty else {
            status = .stopped
            return
        }

        // docker compose ps --format json outputs one JSON object per line
        let lines = output.components(separatedBy: .newlines).filter { !$0.isEmpty }
        if lines.isEmpty {
            status = .stopped
            return
        }

        var allHealthy = true
        var anyRunning = false

        for line in lines {
            guard let data = line.data(using: .utf8),
                  let container = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                continue
            }
            let state = (container["State"] as? String) ?? ""
            let health = (container["Health"] as? String) ?? ""

            if state == "running" {
                anyRunning = true
                if health == "unhealthy" {
                    allHealthy = false
                }
            }
        }

        if anyRunning && allHealthy {
            status = .running
        } else if anyRunning {
            status = .unhealthy
        } else {
            status = .stopped
        }
    }

    // MARK: - Polling

    func startPolling() {
        refreshStatus()
        pollTimer = Timer.scheduledTimer(withTimeInterval: pollInterval, repeats: true) { [weak self] _ in
            self?.refreshStatus()
        }
    }

    func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    // MARK: - Process Helpers

    private func runSync(docker: String, arguments: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: docker)
        process.arguments = arguments
        process.environment = processEnvironment()

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            // Read concurrently to avoid pipe buffer deadlock
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let output = String(data: data, encoding: .utf8)
            guard process.terminationStatus == 0 else {
                return output // Return stderr output even on failure
            }
            return output
        } catch {
            return nil
        }
    }

    private func runAsync(docker: String, arguments: [String], completion: @escaping (Bool, String?) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: docker)
            process.arguments = arguments
            process.environment = self.processEnvironment()

            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe

            do {
                try process.run()
                // Read all output first to prevent pipe buffer deadlock
                // (docker compose build can produce >64KB of output)
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                let output = String(data: data, encoding: .utf8)
                completion(process.terminationStatus == 0, output)
            } catch {
                completion(false, error.localizedDescription)
            }
        }
    }

    private func processEnvironment() -> [String: String] {
        var env = ProcessInfo.processInfo.environment
        // Ensure common Docker paths are in PATH
        let extraPaths = "/usr/local/bin:/opt/homebrew/bin"
        if let existing = env["PATH"] {
            env["PATH"] = "\(extraPaths):\(existing)"
        } else {
            env["PATH"] = extraPaths
        }
        return env
    }

    // MARK: - Logs

    /// Returns recent logs from the Docker Compose stack.
    func logs(tail: Int = 200) -> String? {
        guard let docker = DockerDetector.dockerPath() else { return nil }
        return runSync(docker: docker, arguments: [
            "compose",
            "--project-directory", projectDirectory,
            "-f", composeFilePath,
            "--env-file", envFilePath,
            "logs", "--tail", "\(tail)", "--no-color",
        ])
    }

    // MARK: - Compose File Generation

    private static func generateComposeFile() -> String {
        return """
# Generated by Gitlawb Node macOS app
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: gitlawb
      POSTGRES_USER: gitlawb
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
    volumes:
      - pg-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U gitlawb"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  node:
    image: ghcr.io/gitlawb/node:latest
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "${GITLAWB_HTTP_PORT:-7545}:7545"
      - "${GITLAWB_P2P_PORT:-7546}:7546"
    volumes:
      - gitlawb-data:/data
    environment:
      DATABASE_URL: postgresql://gitlawb:${POSTGRES_PASSWORD:-changeme}@postgres:5432/gitlawb
      GITLAWB_HOST: 0.0.0.0
      GITLAWB_PUBLIC_URL: ${GITLAWB_PUBLIC_URL:-http://localhost:7545}
      GITLAWB_P2P_PORT: 7546
      GITLAWB_CHAIN_RPC_URL: ${GITLAWB_CHAIN_RPC_URL:-}
      GITLAWB_CONTRACT_NODE_STAKING: ${GITLAWB_CONTRACT_NODE_STAKING:-}
      GITLAWB_OPERATOR_PRIVATE_KEY: ${GITLAWB_OPERATOR_PRIVATE_KEY:-}
      GITLAWB_TIGRIS_BUCKET: ${GITLAWB_TIGRIS_BUCKET:-}
      AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:-}
      AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY:-}
      AWS_ENDPOINT_URL_S3: ${AWS_ENDPOINT_URL_S3:-}
    restart: unless-stopped

volumes:
  pg-data:
  gitlawb-data:
"""
    }
}
