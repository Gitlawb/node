import AppKit
import ServiceManagement

class StatusBarController: NSObject {
    private var statusItem: NSStatusItem
    private var menu: NSMenu
    private let dockerCompose: DockerCompose

    private var startStopItem: NSMenuItem!
    private var statusMenuItem: NSMenuItem!
    private var settingsWindow: SettingsWindowController?
    private var logsWindow: NSWindow?

    init(dockerCompose: DockerCompose) {
        self.dockerCompose = dockerCompose

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        menu = NSMenu()

        super.init()

        setupMenu()
        updateIcon(for: .stopped)

        statusItem.menu = menu

        // Listen for status changes
        dockerCompose.onStatusChange = { [weak self] status in
            self?.updateIcon(for: status)
            self?.updateMenuItems(for: status)
        }
    }

    // MARK: - Menu Setup

    private func setupMenu() {
        statusMenuItem = NSMenuItem(title: "Status: Stopped", action: nil, keyEquivalent: "")
        statusMenuItem.isEnabled = false
        menu.addItem(statusMenuItem)

        menu.addItem(.separator())

        startStopItem = NSMenuItem(title: "Start Node", action: #selector(toggleNode), keyEquivalent: "s")
        startStopItem.target = self
        menu.addItem(startStopItem)

        menu.addItem(.separator())

        let openWebUI = NSMenuItem(title: "Open Web UI", action: #selector(openWebUI), keyEquivalent: "w")
        openWebUI.target = self
        menu.addItem(openWebUI)

        let viewLogs = NSMenuItem(title: "View Logs…", action: #selector(viewLogs), keyEquivalent: "l")
        viewLogs.target = self
        menu.addItem(viewLogs)

        let settingsItem = NSMenuItem(title: "Settings…", action: #selector(openSettings), keyEquivalent: ",")
        settingsItem.target = self
        menu.addItem(settingsItem)

        menu.addItem(.separator())

        let autoStartItem = NSMenuItem(title: "Start on Login", action: #selector(toggleAutoStart), keyEquivalent: "")
        autoStartItem.target = self
        autoStartItem.state = Config.shared.autoStartOnLogin ? .on : .off
        menu.addItem(autoStartItem)

        menu.addItem(.separator())

        let quitItem = NSMenuItem(title: "Quit Gitlawb Node", action: #selector(quit), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)
    }

    // MARK: - Status Updates

    private func updateIcon(for status: NodeStatus) {
        guard let button = statusItem.button else { return }

        let dotColor: NSColor
        switch status {
        case .running:
            dotColor = .systemGreen
        case .starting, .unhealthy:
            dotColor = .systemYellow
        case .stopped:
            dotColor = .clear
        case .error:
            dotColor = .systemRed
        }

        // Load template image from bundle resources
        let iconImage: NSImage
        if let bundlePath = Bundle.main.path(forResource: "MenuBarIcon", ofType: "png"),
           let img = NSImage(contentsOfFile: bundlePath) {
            iconImage = img
        } else {
            // Fallback: try to load from @2x
            if let bundlePath = Bundle.main.path(forResource: "MenuBarIcon@2x", ofType: "png"),
               let img = NSImage(contentsOfFile: bundlePath) {
                img.size = NSSize(width: 18, height: 18)
                iconImage = img
            } else {
                // Last resort fallback to SF Symbol
                iconImage = NSImage(systemSymbolName: "network", accessibilityDescription: "Gitlawb Node") ?? NSImage()
            }
        }

        // Compose icon with status dot
        let size = NSSize(width: 18, height: 18)
        let composedImage = NSImage(size: size, flipped: false) { rect in
            iconImage.draw(in: rect)
            if dotColor != .clear {
                let dotSize: CGFloat = 6
                let dotRect = NSRect(x: rect.width - dotSize, y: 0, width: dotSize, height: dotSize)
                dotColor.setFill()
                NSBezierPath(ovalIn: dotRect).fill()
            }
            return true
        }
        composedImage.isTemplate = false // We handle tinting via the dot ourselves
        button.image = composedImage
        // Use template rendering for the base icon to adapt to light/dark menu bar
        // But since we composite with a colored dot, disable template mode on final image
    }

    private func updateMenuItems(for status: NodeStatus) {
        statusMenuItem.title = "Status: \(status.label)"

        switch status {
        case .running, .unhealthy:
            startStopItem.title = "Stop Node"
        case .starting:
            startStopItem.title = "Starting…"
            startStopItem.isEnabled = false
            return
        default:
            startStopItem.title = "Start Node"
        }
        startStopItem.isEnabled = true
    }

    // MARK: - Actions

    @objc private func toggleNode() {
        switch dockerCompose.status {
        case .running, .unhealthy:
            dockerCompose.stop()
        case .stopped, .error:
            // Verify Docker is available before starting
            guard DockerDetector.detect() != nil else {
                showNoDockerAlert()
                return
            }
            dockerCompose.start()
        default:
            break
        }
    }

    @objc private func openWebUI() {
        let port = Config.shared.httpPort
        if let url = URL(string: "http://localhost:\(port)") {
            NSWorkspace.shared.open(url)
        }
    }

    @objc private func openSettings() {
        if settingsWindow == nil {
            settingsWindow = SettingsWindowController()
        }
        settingsWindow?.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func viewLogs() {
        let logs = dockerCompose.logs() ?? "No logs available. Is the node running?"
        let panel = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 700, height: 500),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        panel.title = "Gitlawb Node Logs"
        panel.isReleasedWhenClosed = false
        panel.center()
        self.logsWindow = panel

        let scrollView = NSScrollView(frame: panel.contentView!.bounds)
        scrollView.autoresizingMask = [.width, .height]
        scrollView.hasVerticalScroller = true

        let textView = NSTextView(frame: scrollView.bounds)
        textView.autoresizingMask = [.width]
        textView.isEditable = false
        textView.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        textView.string = logs
        textView.textContainerInset = NSSize(width: 8, height: 8)

        scrollView.documentView = textView
        panel.contentView = scrollView

        // Scroll to bottom
        textView.scrollToEndOfDocument(nil)

        panel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func toggleAutoStart(_ sender: NSMenuItem) {
        let newState = !Config.shared.autoStartOnLogin
        Config.shared.autoStartOnLogin = newState
        sender.state = newState ? .on : .off

        // Register/unregister with macOS login items
        let service = SMAppService.mainApp
        do {
            if newState {
                try service.register()
            } else {
                try service.unregister()
            }
        } catch {
            // Silently fail — user can manage via System Settings
        }
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }

    // MARK: - Alerts

    private func showNoDockerAlert() {
        let alert = NSAlert()
        alert.messageText = "Docker Not Found"
        alert.informativeText = """
            Gitlawb Node requires a Docker runtime to run.

            Install one of the following:
            • Docker Desktop (docker.com)
            • OrbStack (orbstack.dev) — lightweight alternative
            • Colima (github.com/abiosoft/colima) — free CLI-based
            """
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}
