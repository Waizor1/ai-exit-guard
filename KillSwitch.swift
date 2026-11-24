import SwiftUI

final class KillSwitch:ObservableObject {
    @Published private(set) var state=DirectRouteLock.read()
    @Published private(set) var busy=false
    @Published private(set) var message=""
    @Published private(set) var verified=false
    @Published private(set) var checking=false
    private var revision=0
    func refresh() {
        revision += 1
        let version=revision
        state=DirectRouteLock.read()
        checking = state == .on
        guard checking else {verified=false;return}
        DispatchQueue.global(qos:.utility).async {
            let valid=DirectRouteLock.hosts.allSatisfy(DirectRouteLock.resolvesLocally)
            DispatchQueue.main.async {
                guard self.revision==version else {return}
                self.verified=valid;self.checking=false
            }
        }
    }
    private var request = UUID()
    func set(_ enabled:Bool) {
        guard !busy else{return}
        busy=true;message=""
        let connectionID = UUID()
        request = connectionID
        let connection = NSXPCConnection(machServiceName: guardServiceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: GuardRuleControl.self)
        func finish(_ error: String) {
            DispatchQueue.main.async {
                guard self.busy, self.request == connectionID else { return }
                connection.invalidate()
                self.busy = false
                self.refresh()
                self.message = error
            }
        }
        let missing = "Откройте установщик Guard из DMG и разрешите установку помощника."
        connection.invalidationHandler = { finish(missing) }
        connection.interruptionHandler = { finish("Связь с помощником прервалась. Попробуйте ещё раз.") }
        connection.resume()
        let remote = connection.remoteObjectProxyWithErrorHandler { _ in finish(missing) } as? GuardRuleControl
        remote?.setProtection(enabled) { ok in
            finish(ok ? "" : "Помощник не смог применить правило. Проверьте записи в hosts.")
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 12) {
            finish("Помощник не ответил вовремя. Откройте панель ещё раз, чтобы проверить правило.")
        }
    }
}

struct KillSwitchCard:View {
    @ObservedObject var lock:KillSwitch
    @ObservedObject var proxy:ProxyClient
    private var title:String {
        if lock.busy {return "Применяем…"}
        switch lock.state {
        case .on:return lock.verified ? (proxy.ready ? "Включён" : "Прямой выход закрыт") : (lock.checking ? "Проверяем адреса" : "DNS обходит защиту")
        case .off:return "Выключен"
        case .conflict,.unknown:return "Проверьте настройку"
        }
    }
    private var detail:String {
        if !lock.message.isEmpty {return lock.message}
        switch lock.state {
        case .on:
            if !lock.verified && !lock.checking {return "Система вернула внешний адрес. Пока отложите вход."}
            return "Защищены основные адреса ИИ в системном DNS."
        case .off:return "Приложения могут подключаться к ИИ напрямую."
        case .conflict,.unknown:return "Guard не смог подтвердить системное правило."
        }
    }
    var body:some View {
        VStack(alignment:.leading,spacing:5) {
            HStack {
                Label("Защита от обхода",systemImage:"shield.lefthalf.filled").font(.headline)
                Spacer()
                Text(title).font(.caption.weight(.semibold))
                Toggle("Запретить прямой выход к ИИ",isOn:Binding(get:{lock.state == .on},set:lock.set))
                    .labelsHidden().toggleStyle(.switch).controlSize(.small)
                    .disabled(lock.busy || lock.state == .conflict || lock.state == .unknown)
            }
            Text(detail)
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal:false,vertical:true)
        }.padding(12).background(Color.primary.opacity(0.055),in:RoundedRectangle(cornerRadius:12))
    }
}
