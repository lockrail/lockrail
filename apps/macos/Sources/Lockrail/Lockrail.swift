import AppKit
import SwiftUI

/// Runs the `lockrail` binary. Before setup that is the copy inside the app bundle; after setup
/// it is the helper `lockrail install` placed in Application Support, so the menu and the
/// background service always agree on the version.
struct LockrailCLI: Sendable {
    let bundled: URL
    let helper: URL

    init() {
        bundled = Bundle.main.url(forResource: "lockrail", withExtension: nil)
            ?? URL(fileURLWithPath: "/usr/local/bin/lockrail")
        helper = FileManager.default.homeDirectoryForCurrentUser
            .appending(path: "Library/Application Support/Lockrail/bin/lockrail")
    }

    var executable: URL {
        FileManager.default.isExecutableFile(atPath: helper.path) ? helper : bundled
    }

    struct Result: Sendable {
        let status: Int32
        let stdout: Data
        let stderr: String
    }

    /// Run to completion off the main thread.
    func run(_ arguments: [String], using binary: URL? = nil) async -> Result {
        let url = binary ?? executable
        return await Task.detached {
            let process = Process()
            process.executableURL = url
            process.arguments = arguments
            let out = Pipe()
            let err = Pipe()
            process.standardOutput = out
            process.standardError = err
            do {
                try process.run()
            } catch {
                return Result(status: -1, stdout: Data(), stderr: error.localizedDescription)
            }
            let stdout = out.fileHandleForReading.readDataToEndOfFile()
            let stderr = err.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return Result(
                status: process.terminationStatus,
                stdout: stdout,
                stderr: String(decoding: stderr, as: UTF8.self)
            )
        }.value
    }

    func json<T: Decodable>(_ type: T.Type, _ arguments: [String]) async -> T? {
        let result = await run(["--json"] + arguments)
        return try? JSONDecoder().decode(T.self, from: result.stdout)
    }
}

struct ProtectionReport: Decodable {
    struct Check: Decodable, Identifiable {
        let name: String
        let ok: Bool
        let fix: String?
        var id: String { name }
    }
    let protected: Bool
    let checks: [Check]
}

struct LedgerSummary: Decodable {
    let total_stops: Int
    let prompts_blocked: Int
    let credentials: [Credential]
    struct Credential: Decodable {
        let found_in_transcripts: Bool
    }
}

struct SweepSummary: Decodable {
    let files_scanned: Int
    let secrets_by_kind: [String: Int]
    let phi_by_kind: [String: Int]
}

@MainActor
final class Model: ObservableObject {
    @Published var report: ProtectionReport?
    @Published var ledger: LedgerSummary?
    @Published var busy: String?
    @Published var lastMessage: String?

    private let cli = LockrailCLI()
    private var dashboard: Process?

    var title: String {
        guard let report else { return "Checking…" }
        return report.protected ? "Protected" : "Needs setup"
    }

    func refresh() async {
        report = await cli.json(ProtectionReport.self, ["protection"])
        ledger = await cli.json(LedgerSummary.self, ["ledger"])
    }

    /// One step: macOS asks for the login password once, to trust the local certificate.
    func setUp() async {
        busy = "Setting up…"
        let result = await cli.run(["install"], using: cli.bundled)
        busy = nil
        lastMessage = result.status == 0
            ? "Lockrail is protecting Claude Code. Start a new Claude Code session."
            : "Setup did not finish: \(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
        await refresh()
    }

    func sweep() async {
        busy = "Scanning old AI transcripts…"
        let summary = await cli.json(SweepSummary.self, ["sweep"])
        busy = nil
        if let summary {
            let secrets = summary.secrets_by_kind.values.reduce(0, +)
            let phi = summary.phi_by_kind.values.reduce(0, +)
            lastMessage = "Scanned \(summary.files_scanned) transcript files: \(secrets) secret-shaped values, \(phi) patient identifiers. Values are never shown; open the dashboard for details."
        } else {
            lastMessage = "The scan did not finish."
        }
        await refresh()
    }

    /// Starts the token-protected local dashboard once and opens it in the default browser.
    func openDashboard() async {
        if let dashboard, dashboard.isRunning {
            dashboard.terminate()
        }
        let process = Process()
        process.executableURL = cli.executable
        process.arguments = ["--json", "ui"]
        let out = Pipe()
        process.standardOutput = out
        do { try process.run() } catch {
            lastMessage = "Could not start the dashboard: \(error.localizedDescription)"
            return
        }
        dashboard = process
        let handle = out.fileHandleForReading
        struct Started: Decodable { let url: String }
        // `ui --json` prints one JSON object (possibly over several writes) and keeps serving:
        // read until it parses, for at most 3 seconds.
        let started: Started? = await Task.detached {
            var buffer = Data()
            let deadline = Date().addingTimeInterval(3)
            while Date() < deadline {
                let chunk = handle.availableData
                if chunk.isEmpty { break }
                buffer.append(chunk)
                if let parsed = try? JSONDecoder().decode(Started.self, from: buffer) {
                    return parsed
                }
            }
            return nil
        }.value
        if let started,
           let url = URL(string: started.url.replacingOccurrences(of: "/?token=", with: "/exposure?token=")) {
            NSWorkspace.shared.open(url)
        } else {
            lastMessage = "The dashboard did not start."
        }
    }

    func uninstall() async {
        let alert = NSAlert()
        alert.messageText = "Remove Lockrail protection?"
        alert.informativeText = "This removes the background sealer, the local certificate, and the Claude Code hooks and proxy settings, and restores your previous settings. Your vault and audit log are kept."
        alert.addButton(withTitle: "Remove")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        busy = "Removing…"
        let result = await cli.run(["uninstall", "--all"])
        busy = nil
        lastMessage = result.status == 0 ? "Lockrail protection removed." : result.stderr
        await refresh()
    }

    func quit() {
        dashboard?.terminate()
        NSApp.terminate(nil)
    }
}

struct MenuContent: View {
    @ObservedObject var model: Model

    var body: some View {
        Text(model.title).font(.headline)
        if let busy = model.busy {
            Text(busy)
        }
        if let report = model.report, !report.protected {
            ForEach(report.checks.filter { !$0.ok }) { check in
                Text("• \(check.name.replacingOccurrences(of: "_", with: " "))")
            }
            Button("Set Up Protection…") { Task { await model.setUp() } }
        }
        if let ledger = model.ledger {
            let leaked = ledger.credentials.filter(\.found_in_transcripts).count
            Text("\(ledger.total_stops) secrets kept from models")
            if leaked > 0 {
                Text("\(leaked) credentials leaked before Lockrail: rotate them")
            }
        }
        if let message = model.lastMessage {
            Divider()
            Text(message).fixedSize(horizontal: false, vertical: true)
        }
        Divider()
        Button("Open Dashboard") { Task { await model.openDashboard() } }
        Button("Scan Old AI Transcripts") { Task { await model.sweep() } }
        Button("Refresh") { Task { await model.refresh() } }
        Divider()
        Button("Remove Protection…") { Task { await model.uninstall() } }
        Button("Quit Lockrail") { model.quit() }.keyboardShortcut("q")
    }
}

@main
struct LockrailApp: App {
    @StateObject private var model = Model()

    var body: some Scene {
        MenuBarExtra {
            MenuContent(model: model)
                .task { await model.refresh() }
        } label: {
            Image(systemName: model.report?.protected == true ? "lock.shield.fill" : "lock.shield")
        }
    }
}
