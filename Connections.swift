import SwiftUI

struct ConnectionRow:Decodable, Identifiable {
    let App,Domain,Route:String
    let Count:Int
    var id: [String] { [App, Domain, Route] }
    var routeTitle: String {
        switch Route {
        case "guard": return "Через Guard"
        case "outside": return "Возможен прямой выход"
        default: return "Подключено к Guard"
        }
    }

}

struct ConnectionSnapshot:Decodable {
    let Rows:[ConnectionRow]
    let Registry,DNS:Bool
}

final class ConnectionList:ObservableObject {
    @Published var result:ConnectionSnapshot?
    @Published var updated:Date?
    @Published var failed=false
    private var busy=false

    func refresh(socket:String?) {
        guard !busy else{return}
        busy=true
        let executable=Bundle.main.resourceURL?.appendingPathComponent("guard")
        DispatchQueue.global(qos:.utility).async {
            var snapshot:ConnectionSnapshot?
            if let executable {
                let p=Process(),output=Pipe()
                p.executableURL=executable;p.arguments=["activity"]
                var env=ProcessInfo.processInfo.environment
                env["AI_GUARD_ACTIVITY_SOCKET"]=socket
                p.environment=env;p.standardOutput=output;p.standardError=FileHandle.nullDevice
                if (try? p.run()) != nil {
                    let data=output.fileHandleForReading.readDataToEndOfFile()
                    p.waitUntilExit()
                    if p.terminationStatus==0 {snapshot=try? JSONDecoder().decode(ConnectionSnapshot.self,from:data)}
                }
            }
            let captured=snapshot
            DispatchQueue.main.async {
                if let captured { self.result=captured; self.updated=Date() }
                self.failed=captured==nil;self.busy=false
            }
        }
    }
}

struct ConnectionReport: View {
    let report: ConnectionSnapshot
    let height: CGFloat
    var body: some View {
        let groups = Dictionary(grouping: report.Rows, by: \.App)
        VStack(alignment: .leading, spacing: 8) {
            Text("Приложений · \(groups.count)     Соединений · \(report.Rows.reduce(0) { $0 + $1.Count })")
                .font(.subheadline).foregroundStyle(.secondary)
            if groups.isEmpty {
                Text("Сейчас соединений с ИИ не видно.").frame(maxWidth: .infinity, alignment: .leading)
                    .frame(height: height)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        ForEach(groups.keys.sorted(), id: \.self) { app in
                            VStack(alignment: .leading, spacing: 7) {
                                Text(app).font(.headline).fixedSize(horizontal: false, vertical: true)
                                ForEach(groups[app] ?? []) { row in
                                    HStack(alignment: .top, spacing: 8) {
                                        Image(systemName: row.Route == "outside" ? "exclamationmark.triangle" : "link")
                                            .foregroundStyle(row.Route == "outside" ? Color.orange : .secondary)
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(row.routeTitle).font(.callout)
                                            Text(row.Domain.isEmpty ? "Домен пока неизвестен" : row.Domain)
                                                .font(.caption).foregroundStyle(.secondary)
                                        }.fixedSize(horizontal: false, vertical: true)
                                        Spacer(minLength: 4)
                                        Text("×\(row.Count)").font(.caption).monospacedDigit().fixedSize()
                                    }
                                }
                            }
                            Divider()
                        }
                    }.padding(.vertical, 4).padding(.trailing, 12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }.scrollIndicators(.visible).frame(height: height)
            }
        }
    }
}

struct ConnectionsPanel: View {
    @ObservedObject var list: ConnectionList
    @ObservedObject var proxy: ProxyClient
    let height: CGFloat
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Подключения приложений").font(.title2.bold())
            if let report = list.result {
                ConnectionReport(report: report, height: height)
                if list.failed { Text("Не удалось обновить. Показан предыдущий список.") }
                if !report.DNS { Text("Часть адресов ИИ пока не удалось сверить.") }
                if !report.Registry && proxy.ready { Text("Guard пока не передал домены соединений.") }
                Text("Прямой выход определяется по совпадению IP. Один IP могут использовать разные сайты.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                if let time = list.updated {
                    Text("Обновлено в \(time, style: .time)").font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Text(list.failed ? "Не удалось получить список. Повторим автоматически." : "Ищем открытые соединения…")
                    .frame(height: height)
            }
        }.onAppear { list.refresh(socket: proxy.activitySocket) }
        .onReceive(Timer.publish(every: 5, on: .main, in: .common).autoconnect()) { _ in
            list.refresh(socket: proxy.activitySocket)
        }
    }
}
