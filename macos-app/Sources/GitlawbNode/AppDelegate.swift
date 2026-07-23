import AppKit
import ServiceManagement

class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusBarController: StatusBarController?
    private let dockerCompose = DockerCompose()

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Hide from Dock — menu bar only
        NSApp.setActivationPolicy(.accessory)

        statusBarController = StatusBarController(dockerCompose: dockerCompose)

        // Auto-start node if preference is set
        if Config.shared.autoStartOnLaunch {
            dockerCompose.start()
        }

        // Begin polling status
        dockerCompose.startPolling()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    func applicationWillTerminate(_ notification: Notification) {
        dockerCompose.stopPolling()
    }
}
