import AppKit
import Foundation
import SwiftUI

func quoted(_ value: String) -> String {
    "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
}
func appleQuoted(_ value: String) -> String {
    "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
}

@MainActor final class ValidationModel: ObservableObject {
    @Published var running = false
    @Published var status = "准备就绪"
    func start() {
        guard let template=Bundle.main.resourceURL?.appendingPathComponent("validation-root",isDirectory:true),
              let resultPath=Bundle.main.object(forInfoDictionaryKey: "ResultPath") as? String,
              let source=Bundle.main.object(forInfoDictionaryKey: "WiFiDevice") as? String else { status="测试组件缺失"; return }
        running=true; status="等待授权并验证中…"
        DispatchQueue.global(qos: .userInitiated).async {
            let workspace=URL(fileURLWithPath:"/private/tmp",isDirectory:true)
                .appendingPathComponent("networksharer-validation-"+UUID().uuidString,isDirectory:true)
            defer { try? FileManager.default.removeItem(at:workspace) }
            do {
                try FileManager.default.createDirectory(at:workspace,withIntermediateDirectories:false,
                                                        attributes:[.posixPermissions:0o700])
                let copy=workspace.appendingPathComponent("root",isDirectory:true)
                try FileManager.default.copyItem(at:template,to:copy)
                let script=copy.appendingPathComponent("Tests/test_feth_sessions.py").path
                let command=["/usr/bin/python3",script,String(getuid()),source].map(quoted).joined(separator:" ")+" 2>&1 || true"
                let applescript="with timeout of 600 seconds\ndo shell script "+appleQuoted(command)+" with administrator privileges\nend timeout"
                let task=Process(); let out=Pipe(); let err=Pipe()
                task.executableURL=URL(fileURLWithPath:"/usr/bin/osascript"); task.arguments=["-e",applescript]
                task.standardOutput=out; task.standardError=err
                try task.run()
                let data=out.fileHandleForReading.readDataToEndOfFile()
                let errors=err.fileHandleForReading.readDataToEndOfFile()
                task.waitUntilExit()
                if task.terminationStatus==0 {
                    try data.write(to:URL(fileURLWithPath:resultPath),options:.atomic)
                    let parsed=(try? JSONSerialization.jsonObject(with:data)) as? [String:Any]
                    DispatchQueue.main.async { self.running=false; self.status=parsed?["result"] as? String == "passed" ? "验证完成" : "验证未通过，请查看结果" }
                } else {
                    let message=String(decoding:errors,as:UTF8.self)
                    DispatchQueue.main.async { self.running=false; self.status=message.isEmpty ? "授权未完成" : String(message.prefix(110)) }
                }
            } catch {
                DispatchQueue.main.async { self.running=false; self.status="无法启动验证" }
            }
        }
    }
}

struct ValidationView: View {
    @ObservedObject var model: ValidationModel
    var body: some View {
        VStack(alignment: .leading, spacing: 15) {
            Text("网络共享器本地验证").font(.title2.bold())
            Text("将创建并清理一对临时虚拟网络端口，检查地址分配、重复启停和异常退出。不需要连接手机。")
                .fixedSize(horizontal: false, vertical: true)
            Text("测试需要管理员授权，预计几分钟。请等待结果后再关闭此窗口。")
                .font(.callout).foregroundStyle(.secondary)
            HStack {
                Text(model.status).foregroundStyle(.secondary)
                Spacer()
                Button("开始验证", action: model.start).disabled(model.running)
            }
        }.padding(24).frame(width: 540)
    }
}

final class ValidationDelegate: NSObject,NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender:NSApplication)->Bool { true }
}
@main struct ValidationApp: App {
    @NSApplicationDelegateAdaptor(ValidationDelegate.self) var delegate
    @StateObject private var model=ValidationModel()
    var body: some Scene { WindowGroup { ValidationView(model:model) }.windowResizability(.contentSize) }
}
