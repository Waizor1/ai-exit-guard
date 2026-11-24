import AppKit
import SwiftUI
import Combine
import Network
import CFNetwork
import UserNotifications
import ServiceManagement

struct Reading: Decodable, Equatable {
    let Host, IP, AssessmentIP, Status, Detail, RiskDetail, Checked: String
    let Trust, Risk: Double?
    let Country, Network, InfoDetail: String
    let Signals: [String]?
    let TraceCountry: String?
    let InfoChecked, InfoUnavailable: Bool?
    var infoFinished:Bool {InfoChecked == true || InfoUnavailable == true}
    var ipRisk: Double? {
        guard !IP.isEmpty, let risk=Risk, (0...100).contains(risk) else {return nil}
        return risk
    }
    func finding(now:Date) -> Finding {
        if Host=="accounts.google.com", RegionPolicy.issue(host:Host,country:TraceCountry,now:now) == .unsupportedCountry {return .unsupportedCountry}
        guard !IP.isEmpty else {return .domainUnavailable}
        let region = RegionPolicy.issue(host:Host, country:TraceCountry, now:now)
        if region == .unsupportedCountry {return .unsupportedCountry}
        if Status == "measuring" {return .waiting}
        let trust = IP == AssessmentIP ? Trust.flatMap { (0...100).contains($0) ? $0 : nil } : nil
        if let trust, trust <= 100.0/3 {return .riskyAI}
        if let risk=ipRisk, risk>66 {return .riskyIP}
        if let trust, trust <= 200.0/3 {return .moderateAI}
        if let risk=ipRisk, risk>33 {return .moderateIP}
        if let region {return region}
        guard ipRisk != nil else {return .riskUnavailable}
        if RegionPolicy.isKnown(Country), Country != TraceCountry {return .regionConflict}
        if !infoFinished {return InfoDetail.isEmpty ? .waiting : .infoUnavailable}
        if Host=="accounts.google.com" && Status=="google" {return .clear}
        if trust != nil {return .clear}
        if Status == "split", !AssessmentIP.isEmpty, AssessmentIP != IP {return .reputationOnly}
        return .trustUnavailable
    }
}

final class Monitor: NSObject, ObservableObject {
    @Published var rows = [String:Reading]()
    @Published var running = false
    @Published var note = ""
    @Published var fresh = Set<String>()
    @Published var online = false
    @Published var selectedService: String?
    @Published var technical = false
    @Published var showHistory = false
    let proxy=ProxyClient()
    let killSwitch=KillSwitch()
    @Published var t3RuntimeMessage="Проверяем запуск…"
    @Published var proxySettings=false
    @Published var showConnections=false
    @Published var connectionHeight:CGFloat=300
    let connections=ConnectionList()
    var history=ExitHistory()
    @Published var permissions = false
    @Published var notificationState = "Проверяем"
    @Published var loginState = "Проверяем"
    var policyDate: () -> Date = Date.init
    var changed: (() -> Void)?
    static let hosts = ["claude.ai", "api.anthropic.com", "chatgpt.com", "api.openai.com"]
    static let googleHost="accounts.google.com"
    static func service(_ host:String)->String {
        if host==googleHost {return "Antigravity"}
        return hosts.prefix(2).contains(host) ? "Claude":"ChatGPT"
    }
    static func serviceHosts(_ service:String)->[String] {
        if service=="Antigravity" {return [googleHost]}
        return hosts.filter{Self.service($0)==service}
    }
    var monitoredHosts:[String] {proxy.plan == nil ? Self.hosts : Self.hosts+[Self.googleHost]}
    static let refreshInterval: TimeInterval = 120
    static let maxAge: TimeInterval = 180
    private let iso = ISO8601DateFormatter()
    private var lastAttempt = Date.distantPast
    private var retryAt:Date?
    private var recoveryDelay:TimeInterval=5
    @Published private(set) var received = Set<String>()
    // This helper opens direct connections. A system proxy can give clients another exit.
    static func proxyEnabled(_ settings: [String: Any]) -> Bool {
        let keys = ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"]
        if keys.contains(where: { (settings[$0] as? NSNumber)?.boolValue == true }) { return true }
        return settings.values.contains { value in
            if let nested = value as? [String: Any] { return proxyEnabled(nested) }
            if let group = value as? [[String: Any]] { return group.contains(where: proxyEnabled) }
            return false
        }
    }
    var proxyAllowsProbe: () -> Bool = {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else { return false }
        return !Monitor.proxyEnabled(settings)
    }
    @Published private(set) var directProbeAllowed = true
    @Published private(set) var guardOnly = false
    private func updateProxy() {
        let allowed:Bool
        var scoped=false
        if proxy.expected.isEmpty {allowed=proxyAllowsProbe()} else {
            let settings=CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String:Any] ?? [:]
            scoped = !SystemRoute.owns(settings) || !SystemRoute.compatible(settings)
            allowed=proxy.ready
            proxy.applyTunnelRoute()
        }
        guard allowed != directProbeAllowed || scoped != guardOnly else { return }
        guardOnly=scoped
        directProbeAllowed = allowed
        invalidate("")
        lastAttempt = .distantPast
    }
    func finding(_ host:String) -> Finding {
        guard online && directProbeAllowed else {return .incomplete}
        guard fresh.contains(host), let row=rows[host] else {return running ? .waiting : .incomplete}
        if !proxy.expected.isEmpty, !row.IP.isEmpty, row.IP != proxy.expectedIP(Self.service(host)) {return .differentExit}
        let result=row.finding(now:policyDate())
        if running && !received.contains(host) && result.verdict != .avoid {return .waiting}
        let time=Date()
        if !row.IP.isEmpty, history.restricted(host,now:time) {
            if !history.known(host,ip:row.IP,now:time) && result.verdict != .avoid {return .frequentSwitch}
            return result
        }
        if (result.verdict == .clear || result == .waiting),
           history.awaitingConfirmation(host,ip:row.IP,now:time,interval:Self.refreshInterval) {
            return .changingIP
        }
        return result
    }
    func route(_ host:String) -> Recommendation {finding(host).verdict}
    private var previous = [String:(Finding,Date)]()
    // Presentation only. A diagnostic timeout cannot grant or extend a relay lease.
    private var verifiedExit = [String:(ip:String, expires:Date)]()
    func displayedFinding(_ host:String, now:Date = Date()) -> Finding {
        let current=finding(host)
        let service=Self.service(host)
        if current.missingEvidence, online, directProbeAllowed,
           let last=verifiedExit[host], now < last.expires,
           last.ip == proxy.expectedIP(service), proxy.isOpen(service,at:now) {
            return .rechecking
        }
        guard running, online, directProbeAllowed, let (old,stamp)=previous[host],
              (0..<Self.maxAge).contains(now.timeIntervalSince(stamp)) else {return current}
        if current == .waiting {return old}
        return current.verdict.rawValue > old.verdict.rawValue ? current : old
    }
    func displayed(_ hosts:[String], now:Date = Date()) -> Recommendation {
        let verdict = Recommendation.summarize(hosts.map {displayedFinding($0,now:now).verdict})
        if verdict == .clear && !proxy.expected.isEmpty && hosts.contains(where:{!proxy.isOpen(Self.service($0),at:now)}) {return .caution}
        return verdict
    }
    func explanation(for selectedHosts:[String])->String {
        if proxy.proxyOnly && proxy.ready {return "Автоматическая блокировка выключена. Вы можете проверить IP вручную."}
        if !online {return "Подключитесь к интернету. Проверка начнётся автоматически."}
        if !directProbeAllowed && !proxy.expected.isEmpty {return "Маршрут прокси не подтверждён. Проверьте подключение в настройках Guard."}
        if !directProbeAllowed {return "Системный прокси мешает проверить подключение. Отложите вход."}

        if let region=rows[Monitor.googleHost]?.TraceCountry,
           selectedHosts.contains(Monitor.googleHost),fresh.contains(Monitor.googleHost),finding(Monitor.googleHost) == .unsupportedCountry {
            return "Google видит "+(Locale(identifier:"ru").localizedString(forRegionCode:region) ?? region)+". Выберите другой прокси для Antigravity."
        }
        let worst=selectedHosts.map {displayedFinding($0)}.max { $0.rawValue < $1.rawValue } ?? .waiting
        if worst == .clear && displayed(selectedHosts) == .caution {
            return "Guard ждёт подтверждения прокси. Доступ откроется после проверки."
        }
        if worst.missingEvidence, !proxy.expected.isEmpty, selectedHosts.contains(where:{!proxy.isOpen(Self.service($0))}) {
            return "Ждём подтверждения адреса. Guard сам откроет доступ к сервису после успешной проверки."
        }
        return worst.explanation
    }
    var overall:Recommendation {Recommendation.summarize(monitoredHosts.map(route))}
    static func label(_ host:String) -> String {
        switch host {
        case googleHost: return "Antigravity"
        case "claude.ai": return "Сайт Claude"
        case "api.anthropic.com": return "API Claude"
        case "chatgpt.com": return "Сайт ChatGPT"
        default: return "API ChatGPT"
        }
    }
    var advice:String {
        if !online {return "Нет интернета. Проверка продолжится после подключения."}
        if !directProbeAllowed {return "Включён системный прокси. Его маршрут проверить не удалось."}
        if !note.isEmpty && fresh.isEmpty {return note}
        let findings=monitoredHosts.map { ($0, finding($0)) }
        guard let worst=findings.max(by:{ $0.1.rawValue < $1.1.rawValue }) else {return ""}
        if overall == .clear {
            if !proxy.expected.isEmpty && !proxy.allowsTraffic() {return "Доступ через Guard закрыт. Ждём подтверждения проверки."}
            return "IP123 подтвердил хорошую репутацию и доверие для всех четырёх выходов."
        }
        if worst.1 == .waiting && running {return "Дождитесь окончания проверки перед входом."}
        if findings.allSatisfy({$0.1 == worst.1}) {return worst.1.explanation}
        return Self.label(worst.0)+" · "+worst.1.explanation
    }
    private var lastOpenServices=Set<String>()
    func tick(now:Date = Date()) {
        updateProxy()
        let openServices=Set(ProxyClient.services.filter {proxy.isOpen($0,at:now)})
        if lastOpenServices != openServices {
            lastOpenServices=openServices
            objectWillChange.send()
            changed?()
        }
        guard directProbeAllowed, !proxy.proxyOnly else {return}
        let current=fresh.filter { host in
            guard let raw=rows[host]?.Checked,let time=iso.date(from:raw) else{return false}
            return (0..<Self.maxAge).contains(now.timeIntervalSince(time))
        }
        if current != fresh {fresh=current;changed?()}
        let elapsed=now.timeIntervalSince(lastAttempt)
        // A stalled monitor provides no new evidence. Existing relay leases
        // retain their original expiry and the next check runs automatically.
        if running && elapsed>110 {invalidate("Проверяем соединение повторно.",closeAll:false)}
        if running && elapsed<0 {invalidate("Время системы изменилось.")}
        // Start earlier for pinned routes to leave room for a timeout and retry.
        let interval = proxy.expected.isEmpty ? Self.refreshInterval : 90
        guard online, !running else {return}
        if let retryAt, now >= retryAt {startCheck()}
        else if elapsed>=interval || elapsed<0 {check()}
    }
    private var process: Process?
    private var generation = 0
    private var notified = Set<String>()
    private let legacy = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/local.aiexitguard.menu.plist")
    func invalidate(_ message:String, closeAll:Bool=true) {
        retryAt=nil
        if closeAll {verifiedExit.removeAll();proxy.setLease(0)}
        generation += 1
        if let p=process,p.isRunning {p.terminate()}
        process=nil;previous.removeAll();fresh.removeAll();received.removeAll();running=false;note=message;changed?()
    }
    func check() {recoveryDelay=5;startCheck()}
    private func startCheck() {
        updateProxy()
        guard online, directProbeAllowed, !running else{return}
        retryAt=nil
        previous.removeAll()
        for host in fresh {
            if let row=rows[host], let stamp=iso.date(from:row.Checked) {previous[host]=(finding(host),stamp)}
        }
        generation += 1; received.removeAll();note="";lastAttempt=Date();running=true;changed?()
        let token=generation
        let p=Process(), output=Pipe()
        p.executableURL=Bundle.main.resourceURL!.appendingPathComponent("guard")
        p.standardOutput=output
        do {
            let input = try proxy.expected.isEmpty ? nil : proxy.monitorInput(for:p)
            try p.run()
            if let (pipe, data) = input {
                defer { try? pipe.fileHandleForWriting.close() }
                try pipe.fileHandleForWriting.write(contentsOf:data + Data([10]))
            }
        } catch {if p.isRunning {p.terminate()};proxy.setLease(0);fresh.removeAll();running=false;note="Не удалось запустить проверку";changed?();return}
        process=p
        DispatchQueue.global(qos:.utility).async { [weak self] in
            var buffer=Data()
            while true {
                let part=output.fileHandleForReading.availableData
                if part.isEmpty {break}
                buffer.append(part)
                while let end=buffer.firstIndex(of:10) {
                    let line=Data(buffer[..<end]);buffer.removeSubrange(...end)
                    if let r=try? JSONDecoder().decode(Reading.self,from:line) {
                        DispatchQueue.main.async { [weak self] in
                            guard let self=self, self.generation==token else{return}
                            guard self.monitoredHosts.contains(r.Host) else{return}
                            let firstReading = !self.received.contains(r.Host)
                            self.rows[r.Host]=r;self.received.insert(r.Host)
                            if let date=self.iso.date(from:r.Checked),(0..<Self.maxAge).contains(Date().timeIntervalSince(date)) {self.fresh.insert(r.Host)} else {self.fresh.remove(r.Host)}
                            if firstReading, self.fresh.contains(r.Host), !r.IP.isEmpty, let stamp=self.iso.date(from:r.Checked) {
                                self.history.observe(r.Host,ip:r.IP,at:stamp)
                            }
                            let reason = self.finding(r.Host)
                            if reason != .clear && !reason.missingEvidence {
                                self.verifiedExit.removeValue(forKey:r.Host)
                            }
                            let highRisk = reason.verdict == .avoid
                            if highRisk {if self.proxy.plan != nil {self.proxy.setServiceLease(Self.service(r.Host),0)} else {self.proxy.setLease(0)}}
                            // Every member of this group must have a final, fresh reading
                            // in this generation. Slow checks for other providers are independent.
                            if self.proxy.plan != nil, reason == .clear, r.infoFinished {
                                let service=Self.service(r.Host)
                                let deadline=self.serviceDeadline(group:Self.serviceHosts(service),success:true)
                                if deadline>0 {self.proxy.setServiceLease(service,deadline)}
                            }
                            self.changed?()
                            if self.fresh.contains(r.Host),highRisk,self.notified.insert(r.Host).inserted {
                                self.notify(Self.label(r.Host)+" · "+reason.explanation)
                            } else if !highRisk && r.infoFinished { self.notified.remove(r.Host) }
                        }
                    }
                }
            }
            p.waitUntilExit()
            DispatchQueue.main.async { [weak self] in
                guard let self=self,self.generation==token else{return}
                self.running=false;self.process=nil
                self.fresh.formIntersection(self.received)
                if p.terminationStatus == 0 {
                    for host in self.fresh {
                        if self.finding(host).verdict == .clear, let row=self.rows[host] {
                            self.history.approve(host,ip:row.IP,at:Date())
                            if row.infoFinished, row.IP == self.proxy.expectedIP(Self.service(host)),
                               let stamp=self.iso.date(from:row.Checked) {
                                self.verifiedExit[host]=(row.IP,stamp.addingTimeInterval(Self.maxAge))
                            }
                        }
                    }
                }
                // Only a complete, current assessment may reopen access after a red result.
                if self.proxy.plan != nil {
                    for service in ProxyClient.services {
                        let group=Self.serviceHosts(service)
                        let deadline=self.serviceDeadline(group:group,success:p.terminationStatus==0)
                        if deadline>0 || group.contains(where:{self.finding($0).verdict == .avoid}) {self.proxy.setServiceLease(service,deadline)}
                    }
                } else if !self.proxy.expected.isEmpty {
                    let deadline = self.leaseDeadline(success:p.terminationStatus == 0)
                    if deadline > 0 || self.overall == .avoid { self.proxy.setLease(deadline) }
                }
                if self.received.count != self.monitoredHosts.count || p.terminationStatus != 0 {self.note="Часть результатов недоступна"}
                let missing = self.monitoredHosts.contains { self.finding($0).missingEvidence }
                if missing || p.terminationStatus != 0 {
                    self.retryAt=Date().addingTimeInterval(self.recoveryDelay)
                    self.recoveryDelay=min(30,self.recoveryDelay*2)
                } else {self.recoveryDelay=5}
                self.changed?()
            }
        }
    }
    func serviceDeadline(group:[String],success:Bool)->Int64 {
        guard success,online,directProbeAllowed else{return 0}
        let stamps=group.compactMap { h -> Date? in
            guard fresh.contains(h),received.contains(h),finding(h).verdict == .clear, let r=rows[h],
                  r.IP==proxy.expectedIP(Self.service(h)),r.infoFinished else{return nil}
            return iso.date(from:r.Checked)
        }
        guard stamps.count==group.count,let first=stamps.min() else{return 0}
        let end=first.addingTimeInterval(Self.maxAge)
        return end>Date() ? Int64(end.timeIntervalSince1970) : 0
    }
    func leaseDeadline(success:Bool) -> Int64 {
        guard success, online, directProbeAllowed, !proxy.expected.isEmpty,
              fresh == Set(Self.hosts), received == fresh, overall == .clear else { return 0 }
        let stamps = Self.hosts.compactMap { host -> Date? in
            guard let row=rows[host], row.IP == proxy.expected, row.infoFinished else { return nil }
            return iso.date(from:row.Checked)
        }
        guard stamps.count==Self.hosts.count, let oldest=stamps.min() else { return 0 }
        let end=oldest.addingTimeInterval(Self.maxAge)
        return end > Date() ? Int64(end.timeIntervalSince1970) : 0
    }
    func notify(_ text:String) {
        let n=UNMutableNotificationContent();n.title="AI Exit Guard";n.body=text
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier:text,content:n,trigger:nil))
    }
    func readPermissions() {
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            DispatchQueue.main.async {
                switch settings.authorizationStatus {
                case .authorized,.provisional:self.notificationState="Разрешены"
                case .denied:self.notificationState="Выключены"
                default:self.notificationState="Можно включить"
                }
            }
        }
        if FileManager.default.fileExists(atPath:legacy.path) {loginState="Включён";return}
        switch SMAppService.mainApp.status {
        case .enabled:loginState="Включён"
        case .requiresApproval:loginState="Нужно разрешение"
        default:loginState="Выключен"
        }
    }
    func notifications() {
        if notificationState=="Выключены" {
            NSWorkspace.shared.open(URL(string:"x-apple.systempreferences:com.apple.Notifications-Settings.extension")!)
        } else if notificationState=="Разрешены" {notify("Проверочное уведомление")}
        else { UNUserNotificationCenter.current().requestAuthorization(options:[.alert,.sound]) {_,_ in DispatchQueue.main.async {self.readPermissions()}} }
    }
    func login() {
        if loginState=="Выключен" {
            do {try SMAppService.mainApp.register()} catch {note="Скопируйте приложение в Программы и включите автозапуск в настройках macOS"}
            readPermissions()
        } else {SMAppService.openSystemSettingsLoginItems()}
    }
}
final class MenuSpinner:NSProgressIndicator {
    override func hitTest(_ point:NSPoint)->NSView? {nil}
}
// SwiftUI disclosure and child view updates can change the ideal size without
// publishing anything on Monitor. Measure after AppKit finishes that layout pass.
final class PanelHost: NSHostingView<GuardPanel> {
    var sizeInvalidated: (() -> Void)?
    private var pendingMeasurement=false

    override func invalidateIntrinsicContentSize() {
        super.invalidateIntrinsicContentSize()
        scheduleMeasurement()
    }

    override func layout() {
        super.layout()
        scheduleMeasurement()
    }

    private func scheduleMeasurement() {
        guard !pendingMeasurement, window?.isVisible == true else { return }
        pendingMeasurement=true
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.pendingMeasurement=false
            if self.window?.isVisible == true { self.sizeInvalidated?() }
        }
    }
}

final class TopAlignedClip: NSClipView {
    override var isFlipped: Bool { true }
}

final class StatusPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override func cancelOperation(_ sender: Any?) { orderOut(sender) }
}
final class GuardDelegate: NSObject, NSApplicationDelegate {
    let model = Monitor()
    let path = NWPathMonitor()
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let panel = StatusPanel(contentRect:.zero, styleMask:[.borderless,.nonactivatingPanel], backing:.buffered, defer:false)
    let scroll = NSScrollView()
    lazy var host: PanelHost = {
        let view=PanelHost(rootView:GuardPanel(model:model))
        view.sizeInvalidated={ [weak self] in self?.position() }
        return view
    }()
    var signature: String?
    var periodic: Timer?
    var pending: DispatchWorkItem?
    var observation: AnyCancellable?
    var connectionObservation: AnyCancellable?
    private var proxyReadiness:AnyCancellable?
    private var monitoringActivity:NSObjectProtocol?
    private func maintainMonitoring(_ ready:Bool) {
        if ready && monitoringActivity == nil {
            monitoringActivity=ProcessInfo.processInfo.beginActivity(options:.userInitiatedAllowingIdleSystemSleep,
                reason:"Проверка активных маршрутов Guard")
        } else if !ready, let token=monitoringActivity {
            ProcessInfo.processInfo.endActivity(token)
            monitoringActivity=nil
        }
    }
    var outside: Any?
    var local: Any?
    var anchor = NSRect.zero
    var display: NSScreen?

    func applicationDidFinishLaunching(_ n:Notification) {
        // Repair only the previous Guard-managed Antigravity path on upgrade.
        if let helper=Bundle.main.url(forResource:"guard",withExtension:nil) {
            let migration=Process()
            migration.executableURL=helper
            migration.arguments=["t3-migrate"]
            migration.standardOutput=FileHandle.nullDevice
            try? migration.run()
        }
        NSApp.setActivationPolicy(.accessory)
        model.proxy.routeChanged={ [weak self] in self?.recheck() }
        model.proxy.profileChanged={ [weak self] _ in
            guard let m=self?.model else{return}
            m.invalidate("",closeAll:false);m.check()
        }
        proxyReadiness=model.proxy.$ready.removeDuplicates().sink { [weak self] ready in self?.maintainMonitoring(ready) }
        model.proxy.restore()
        panel.title = "AI Exit Guard"
        panel.isFloatingPanel = true
        panel.level = .popUpMenu
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.transient,.moveToActiveSpace,.fullScreenAuxiliary]
        panel.hasShadow=true
        panel.isOpaque=false
        panel.backgroundColor = .clear
        scroll.contentView=TopAlignedClip()
        scroll.wantsLayer=true
        scroll.layer?.cornerRadius=15
        scroll.layer?.masksToBounds=true
        scroll.backgroundColor = .windowBackgroundColor
        scroll.hasVerticalScroller=true
        scroll.autohidesScrollers=true
        scroll.scrollerStyle = .overlay
        scroll.documentView=host
        panel.contentView=scroll
        item.button?.target=self;item.button?.action=#selector(toggle)
        observation=model.objectWillChange.sink { [weak self] _ in
            DispatchQueue.main.async { if let self=self,self.panel.isVisible {self.position()} }
        }
        connectionObservation=model.connections.objectWillChange.sink { [weak self] _ in
            DispatchQueue.main.async { if let self, self.model.showConnections, self.panel.isVisible { self.position() } }
        }
        model.changed={ [weak self] in self?.draw() };draw()
        path.pathUpdateHandler={ [weak self] p in
            let links=p.availableInterfaces.map{"\($0.index):\($0.name)"}.sorted().joined(separator:",")
            let used:[NWInterface.InterfaceType]=[.wiredEthernet,.wifi,.cellular,.other,.loopback]
            let key="\(p.status)|\(links)|\(used.filter{p.usesInterfaceType($0)})|\(p.gateways.map{String(describing:$0)}.sorted())|\(p.supportsIPv4)|\(p.supportsIPv6)"
            DispatchQueue.main.async {
                guard let self=self,self.signature != key else{return}
                self.signature=key;self.model.online=p.status == .satisfied
                self.model.killSwitch.refresh()
                self.recheck()
            }
        }
        let timer=Timer(timeInterval:5,repeats:true){[weak self] _ in self?.model.tick()}
        RunLoop.main.add(timer,forMode:.common)
        periodic=timer
        path.start(queue:DispatchQueue(label:"guard.network"))
        NSWorkspace.shared.notificationCenter.addObserver(self,selector:#selector(wake),name:NSWorkspace.didWakeNotification,object:nil)
        NotificationCenter.default.addObserver(self,selector:#selector(screenChanged),name:NSApplication.didChangeScreenParametersNotification,object:nil)
        outside=NSEvent.addGlobalMonitorForEvents(matching:[.leftMouseDown,.rightMouseDown]) { [weak self] _ in
            guard let self=self,self.panel.isVisible else{return}
            let mouse=NSEvent.mouseLocation
            if !self.anchor.insetBy(dx:-3,dy:-4).contains(mouse) && !self.panel.frame.contains(mouse) {self.closePanel()}
        }
        local=NSEvent.addLocalMonitorForEvents(matching:[.leftMouseDown,.rightMouseDown,.keyDown]) { [weak self] event in
            guard let self=self,self.panel.isVisible else{return event}
            if event.type == .keyDown {
                if event.keyCode==53 {self.closePanel();return nil}
            } else if event.window !== self.panel && event.window !== self.item.button?.window {self.closePanel()}
            return event
        }
    }
    func recheck() {
        pending?.cancel()
        model.invalidate("")
        guard model.online else{return}
        let work=DispatchWorkItem{[weak self] in self?.model.check()}
        pending=work
        DispatchQueue.main.asyncAfter(deadline:.now()+0.7,execute:work)
    }
    @objc func wake(){recheck()}
    @objc func screenChanged(){
        guard panel.isVisible else{return}
        guard let id=display?.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber,
              let current=NSScreen.screens.first(where:{($0.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber)==id}) else {closePanel();return}
        display=current
        position()
    }
    @objc func closePanel(){model.showConnections=false;panel.orderOut(nil)}
    let spinner: NSProgressIndicator = {
        let indicator=MenuSpinner()
        indicator.style = .spinning
        indicator.controlSize = .small
        indicator.isDisplayedWhenStopped=false
        indicator.setAccessibilityLabel("Идёт проверка")
        return indicator
    }()
    private var drawnState:Recommendation?
    private var animating=false
    func draw(){
        let state=model.displayed(model.monitoredHosts)
        let label="AI Exit Guard · "+(model.proxy.proxyOnly && model.proxy.ready ? "Только прокси" : state.title)+(model.running ? " · идёт проверка" : "")
        if let button=item.button {
            if spinner.superview == nil {
                button.addSubview(spinner)
                spinner.translatesAutoresizingMaskIntoConstraints=false
                NSLayoutConstraint.activate([spinner.trailingAnchor.constraint(equalTo:button.trailingAnchor,constant:-4),
                    spinner.centerYAnchor.constraint(equalTo:button.centerYAnchor),
                    spinner.widthAnchor.constraint(equalToConstant:14),spinner.heightAnchor.constraint(equalToConstant:14)])
            }
            if drawnState != state {
                let shield=state.trayIcon
                let image=NSImage(size:NSSize(width:38,height:18),flipped:false){_ in
                    shield.draw(at:.zero,from:.zero,operation:.sourceOver,fraction:1)
                    return true
                }
                image.isTemplate=false
                button.image=image
                drawnState=state
            }
            if animating != model.running {
                if model.running {spinner.startAnimation(nil)} else {spinner.stopAnimation(nil)}
                animating=model.running
            }
        }
        item.button?.setAccessibilityLabel(label)
        item.button?.toolTip=[label,model.explanation(for:model.monitoredHosts)].filter{!$0.isEmpty}.joined(separator:"\n")

    }
    func position(){
        guard let screen=display else{return}
        host.layoutSubtreeIfNeeded()
        let size=host.fittingSize
        guard size.width > 0, size.height > 0 else {return}
        let bounds=screen.visibleFrame.insetBy(dx:6,dy:6)
        let top=min(anchor.minY-4,bounds.maxY,screen.frame.maxY-NSStatusBar.system.thickness-4)
        let height=min(ceil(size.height),max(1,top-bounds.minY))
        let width=min(ceil(size.width),bounds.width)
        let x=min(max(bounds.minX,anchor.midX-width/2),bounds.maxX-width)
        let frame=NSRect(x:round(x),y:floor(top-height),width:width,height:height)
        if panel.frame != frame {panel.setFrame(frame,display:true)}
        let document=NSSize(width:width,height:ceil(size.height))
        if host.frame.size != document {host.setFrameSize(document)}
        if height >= document.height && scroll.contentView.bounds.origin != .zero {
            scroll.contentView.scroll(to:.zero)
            scroll.reflectScrolledClipView(scroll.contentView)
        }
    }
    @objc func toggle(){
        if panel.isVisible {closePanel();return}
        guard let button=item.button,let window=button.window else{return}
        anchor=window.convertToScreen(button.convert(button.bounds,to:nil))
        let mouse=NSEvent.mouseLocation
        if NSApp.currentEvent?.type == .leftMouseUp,let screen=NSScreen.screens.first(where:{ $0.frame.contains(mouse) && mouse.y >= $0.frame.maxY-NSStatusBar.system.thickness-3 }){
            display=screen
            if !screen.frame.intersects(anchor) || abs(mouse.x-anchor.midX)>button.bounds.width {
                anchor=NSRect(x:mouse.x,y:screen.frame.maxY-NSStatusBar.system.thickness,width:1,height:1)
            }
        } else {display=window.screen ?? NSScreen.main}
        if let screen=display {
            model.connectionHeight=min(420,max(90,anchor.minY-screen.visibleFrame.minY-210))
        }
        model.selectedService=nil;model.technical=false;model.showHistory=false;model.permissions=false;model.proxySettings=false;model.showConnections=false
        model.readPermissions()
        model.killSwitch.refresh()
        position()
        panel.makeKeyAndOrderFront(nil)
    }
    func applicationShouldTerminate(_ sender:NSApplication)->NSApplication.TerminateReply {
        model.proxy.prepareForQuit() ? .terminateNow : .terminateCancel
    }
    func applicationWillTerminate(_ n:Notification){
        maintainMonitoring(false)
        periodic?.invalidate();pending?.cancel();path.cancel();model.invalidate("");model.proxy.shutdown()
        if let outside=outside{NSEvent.removeMonitor(outside)}
        if let local=local{NSEvent.removeMonitor(local)}
    }
}
let app=NSApplication.shared
signal(SIGPIPE, SIG_IGN)
// An updater can check the new signature's Keychain access before stopping
// the working relay. Only the exit status leaves this process.
if CommandLine.arguments.dropFirst().elementsEqual(["--check-saved-proxy"]) {
    guard let data=ProxyVault.read(),
          (try? ProxyPlan.load(data)) != nil else {exit(1)}
    exit(0)
}
if CommandLine.arguments.dropFirst().elementsEqual(["--check-rule-helper"]) {
    let connection = NSXPCConnection(machServiceName: guardServiceName, options: .privileged)
    connection.remoteObjectInterface = NSXPCInterface(with: GuardRuleControl.self)
    connection.resume()
    let remote = connection.remoteObjectProxyWithErrorHandler { _ in exit(1) } as? GuardRuleControl
    remote?.ping { ok in exit(ok ? 0 : 1) }
    DispatchQueue.main.asyncAfter(deadline: .now() + 5) { exit(1) }
    RunLoop.main.run()
}
let delegate=GuardDelegate()
app.delegate=delegate
app.run()
