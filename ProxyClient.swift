import AppKit
import SwiftUI
import SystemConfiguration
import Security

struct ProxyEndpoint: Codable {
    var Scheme:String, Host:String, Port:Int, User:String, Password:String

    init(_ line:String, scheme:String) throws {
        let raw=line.trimmingCharacters(in:.whitespacesAndNewlines)
        var value=raw
        if !raw.contains("://") && !raw.contains("@") {
            let parts=raw.split(separator:":",maxSplits:3,omittingEmptySubsequences:false)
            if parts.count==4,let port=Int(parts[1]), (1...65535).contains(port), !parts[0].contains("[") {
                var c=URLComponents()
                c.scheme=scheme;c.host=String(parts[0]);c.port=port;c.user=String(parts[2]);c.password=String(parts[3])
                value=c.string ?? ""
            }
        }
        if !value.contains("://"){value=scheme+"://"+value}
        guard raw.utf8.count<=4096, let c=URLComponents(string:value),let h=c.host,!h.isEmpty,
              let p=c.port,(1...65535).contains(p),let proto=c.scheme?.lowercased(),
              ["http","https","socks5","socks5h"].contains(proto),c.path.isEmpty || c.path=="/",
              c.query==nil,c.fragment==nil else {throw ProxyIssue("Вставьте строку логин:пароль@адрес:порт или адрес:порт:логин:пароль.")}
        Scheme=proto=="socks5h" ? "socks5":proto;Host=h.trimmingCharacters(in:CharacterSet(charactersIn:"[]"));Port=p;User=c.user ?? "";Password=c.password ?? ""
    }
}
struct ProxyIssue:LocalizedError {
    let message:String
    init(_ message:String){self.message=message}
    var errorDescription:String? {message}
}

struct IndividualProxy: Codable {
    let Endpoint: ProxyEndpoint
    let Expected: String
}
struct ProxyPlan: Codable {
    let Common: ProxyEndpoint
    var Profiles: [String:IndividualProxy]
    static func load(_ data:Data)throws -> ProxyPlan {
        let decoder=JSONDecoder()
        if let legacy=try? decoder.decode(ProxyEndpoint.self,from:data) {return ProxyPlan(Common:legacy,Profiles:[:])}
        return try decoder.decode(ProxyPlan.self,from:data)
    }
}

enum SystemRoute {
    static let pac="http://127.0.0.1:39178/guard.pac"
    static func owns(_ d:[String:Any])->Bool {
        (d["ProxyAutoConfigEnable"] as? NSNumber)?.boolValue==true && (d["ProxyAutoConfigURLString"] as? String)==pac
    }
    static func compatible(_ d:[String:Any]) -> Bool {
        if d["HTTPSProxy"] as? String=="127.0.0.1", d["HTTPSPort"] as? Int==39178,
           d["HTTPProxy"] as? String=="127.0.0.1", d["HTTPPort"] as? Int==39178,
           d["SupplementalMatchDomain"] != nil || d["__MATCH_DOMAIN__"] != nil {return true}
        for key in ["HTTPEnable","HTTPSEnable","SOCKSEnable","ProxyAutoDiscoveryEnable"] where (d[key] as? NSNumber)?.boolValue==true {return false}
        if (d["ProxyAutoConfigEnable"] as? NSNumber)?.boolValue==true && !owns(d){return false}
        for value in d.values {
            if let scoped=value as? [String:Any], !compatible(scoped){return false}
            if let group=value as? [[String:Any]],group.contains(where:{!compatible($0)}){return false}
        }
        return true
    }
    static func change(enable:Bool)throws {
        var auth:AuthorizationRef?
        guard AuthorizationCreate(nil,nil,[],&auth)==errAuthorizationSuccess,let auth else {throw ProxyIssue("macOS не выдала разрешение.")}
        defer{AuthorizationFree(auth,[])}
        guard let prefs=SCPreferencesCreateWithAuthorization(nil,"AI Exit Guard" as CFString,nil,auth),
              SCPreferencesLock(prefs,false) else {throw ProxyIssue("Не удалось получить доступ к настройкам сети.")}
        defer{SCPreferencesUnlock(prefs)}
        guard let set=SCNetworkSetCopyCurrent(prefs),let services=SCNetworkSetCopyServices(set) as? [SCNetworkService] else {throw ProxyIssue("Сетевые подключения не найдены.")}
        var originals=[(SCNetworkProtocol,CFDictionary?)]()
        for service in services {
            guard let iface=SCNetworkServiceGetInterface(service), let kind=SCNetworkInterfaceGetInterfaceType(iface) as String?,
                  let proto=SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeProxies) else {continue}
            let original=SCNetworkProtocolGetConfiguration(proto)
            var cfg=original as? [String:Any] ?? [:]
            if enable {
                guard SCNetworkServiceGetEnabled(service), ["Ethernet","IEEE80211","USB","Thunderbolt","VLAN","Bond"].contains(kind) else {continue}
                guard compatible(cfg), (cfg["ProxyAutoConfigURLString"] as? String ?? pac)==pac, cfg["ProxyAutoConfigJavaScript"]==nil else {throw ProxyIssue("В настройках сети уже задан другой прокси. Сохраните его настройки и выключите перед подключением Guard.")}
                cfg["ProxyAutoConfigURLString"]=pac;cfg["ProxyAutoConfigEnable"]=1
            } else {
                guard (cfg["ProxyAutoConfigURLString"] as? String)==pac else{continue}
                cfg.removeValue(forKey:"ProxyAutoConfigURLString");cfg.removeValue(forKey:"ProxyAutoConfigEnable")
            }
            guard SCNetworkProtocolSetConfiguration(proto,cfg as CFDictionary) else {throw ProxyIssue("macOS отклонила изменение маршрута.")}
            originals.append((proto,original))
        }
        if originals.isEmpty {if enable {throw ProxyIssue("Не найдено подключение Wi-Fi или Ethernet.")};return}
        guard SCPreferencesCommitChanges(prefs) else {throw ProxyIssue("macOS не сохранила настройки сети.")}
        if !SCPreferencesApplyChanges(prefs) {
            var restored=true
            for (proto,original) in originals {
                if !SCNetworkProtocolSetConfiguration(proto,original) {restored=false}
            }
            if !restored || !SCPreferencesCommitChanges(prefs) || !SCPreferencesApplyChanges(prefs) {
                throw ProxyIssue("Не удалось восстановить настройки. Проверьте автоматический прокси в настройках сети macOS.")
            }
            throw ProxyIssue("macOS отклонила новый маршрут. Предыдущие настройки восстановлены.")
        }
    }
}

enum ProxyVault {
    static var query:[String:Any]{[kSecClass as String:kSecClassGenericPassword,kSecAttrService as String:"local.aiexitguard.proxy",kSecAttrAccount as String:"current"]}
    static func save(_ data:Data)throws {
        let attrs=[kSecValueData as String:data]
        var status=SecItemUpdate(query as CFDictionary,attrs as CFDictionary)
        if status==errSecItemNotFound {var q=query;q[kSecValueData as String]=data;q[kSecAttrAccessible as String]=kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;status=SecItemAdd(q as CFDictionary,nil)}
        guard status==errSecSuccess else {throw ProxyIssue("Связка ключей не сохранила прокси.")}
    }
    static func read()->Data? {var q=query;q[kSecReturnData as String]=true;var value:CFTypeRef?;return SecItemCopyMatching(q as CFDictionary,&value)==errSecSuccess ? value as? Data : nil}
    static func clear(){SecItemDelete(query as CFDictionary)}
}

final class ProxyClient:ObservableObject {
    static let services=["Claude","ChatGPT","Antigravity"]
    @Published private(set) var plan:ProxyPlan?
    @Published private(set) var leases=[String:Int64]()
    @Published var profileMessage=""
    var profileChanged:((String)->Void)?
    func expectedIP(_ service:String)->String {plan?.Profiles[service]?.Expected ?? expected}
    @Published private(set) var proxyOnly=false
    func setProxyOnly(_ enabled:Bool) {
        guard ready, plan != nil, command(enabled ? "mode proxy-only":"mode guarded",expect:"READY") else{return}
        proxyOnly=enabled
        leases.removeAll();allowedUntil=0
        UserDefaults.standard.set(enabled,forKey:"proxyOnly")
        routeChanged?()
    }
    func isOpen(_ service:String,at now:Date=Date())->Bool {
        if proxyOnly {return ready}
        guard plan != nil else{return allowsTraffic(at:now)}
        return ready && Double(leases[service] ?? 0)>now.timeIntervalSince1970
    }
    let domainRoutes=KillSwitch()
    private let defaults=UserDefaults.standard
    var managesDomains:Bool {defaults.bool(forKey:"manageModelDomains")}
    var shouldReleaseDomainsOnQuit:Bool {
        managesDomains && defaults.bool(forKey:"proxyOnly") && DirectRouteLock.read() == .on
    }
    func releaseDomainsForQuit(_ completion:@escaping(Bool)->Void) {
        busy=true
        domainRoutes.apply(false) { ok in
            self.busy=false
            if !ok {self.message=self.domainRoutes.message}
            completion(ok)
        }
    }
    @Published var draft=""
    @Published var scheme="socks5"
    @Published private(set) var routeWarning=""
    @Published var busy=false
    @Published var ready=false
    @Published var message=""
    @Published var expected=UserDefaults.standard.string(forKey:"proxyExpected") ?? ""
    private var overlayRequested=false
    private var overlayStarting=false
    private var overlayStarted=false
    func applyTunnelRoute() {
        guard !managesDomains,!overlayStarting,!overlayStarted,ready,let server,server.isRunning,!overlayRequested,RuntimePAC.isTunnelPrimary() else{return}
        overlayRequested=true;overlayStarting=true
        RuntimePAC.activate(relay:server.processIdentifier){ [weak self] ok in
            guard let self=self, self.server===server else{return}
            self.overlayStarting=false;self.overlayStarted=ok
            if !ok {self.message="Разрешите настройку маршрута для Happ."}
            self.routeChanged?()
        }
    }
    @Published private(set) var allowedUntil: Int64 = 0
    func allowsTraffic(at date:Date = Date()) -> Bool {
        ready && (proxyOnly || Double(allowedUntil) > date.timeIntervalSince1970)
    }
    private var response: FileHandle?
    private var assessmentSpec: Data?

    func monitorInput(for process: Process) throws -> (Pipe, Data) {
        guard let assessmentSpec, ready else { throw ProxyIssue("Прокси недоступен.") }
        let pipe = Pipe()
        process.arguments = ["proxy-monitor"]
        process.standardInput = pipe
        return (pipe, assessmentSpec)
    }

    // Wait for the relay to close its live sockets before publishing a red verdict.
    func setLease(_ deadline: Int64) {
        guard !proxyOnly else{return}
        if plan != nil {
            guard deadline==0 else{return}
            if leases.values.contains(where:{$0 != 0}) { _ = command("0", expect:"CLOSED") }
            leases.removeAll();allowedUntil=0;return
        }
        guard deadline != allowedUntil else { return }
        if let reply=leaseReply(String(deadline), deadline:deadline) {
            allowedUntil = reply == "OPEN" ? deadline : 0
        }
    }

    private func command(_ line:String,expect:String)->Bool {
        acknowledgment(line,accept:[expect]) != nil
    }

    private func leaseReply(_ line:String,deadline:Int64)->String? {
        // The deadline can expire between computing the assessment and the
        // relay applying it. CLOSED is an authoritative reply for this route.
        acknowledgment(line,accept:deadline>0 ? ["OPEN","CLOSED"] : ["CLOSED"])
    }

    private func acknowledgment(_ line:String,accept:Set<String>)->String? {
        guard let lifetime,let response,let server,server.isRunning else{return nil}
        do {
            try lifetime.fileHandleForWriting.write(contentsOf:Data((line+"\n").utf8))
            var fd=pollfd(fd:response.fileDescriptor,events:Int16(POLLIN),revents:0)
            guard poll(&fd,1,1500)>0,
                  let reply=String(data:response.availableData,encoding:.utf8),
                  reply.hasSuffix("\n"),accept.contains(String(reply.dropLast())) else {
                throw ProxyIssue("Прокси не подтвердил маршрут.")
            }
            return String(reply.dropLast())
        } catch {
            if server.isRunning {Darwin.kill(server.processIdentifier,SIGKILL);server.waitUntilExit()}
            ready=false;leases.removeAll();allowedUntil=0;message="Связь с локальным прокси прервалась."
            return nil
        }
    }
    func setServiceLease(_ service:String,_ deadline:Int64){
        guard !proxyOnly, (leases[service] ?? 0) != deadline else{return}
        if let reply=leaseReply(service+" "+String(deadline),deadline:deadline){
            leases[service]=reply=="OPEN" ? deadline : 0
            allowedUntil=leases.values.max() ?? 0
        }
    }
    func useCommon(_ service:String){
        guard !busy,var next=plan else{return}
        next.Profiles.removeValue(forKey:service);apply(next,service:service)
    }
    func useIndividual(_ service:String,line:String,scheme:String){
        guard !busy,let current=plan,Self.services.contains(service) else{return}
        do{
            let ep=try ProxyEndpoint(line,scheme:scheme)
            var request=try JSONSerialization.jsonObject(with:JSONEncoder().encode(ep)) as! [String:Any]
            request["CheckService"]=service
            let (proc,_,output)=try start("proxy-check",JSONSerialization.data(withJSONObject:request))
            busy=true;profileMessage="Проверяем адрес для "+service+"…"
            DispatchQueue.global(qos:.utility).async {
                let answer=String(data:output.fileHandleForReading.readDataToEndOfFile(),encoding:.utf8)?.trimmingCharacters(in:.whitespacesAndNewlines) ?? ""
                proc.waitUntilExit()
                DispatchQueue.main.async {
                    self.busy=false
                    guard self.ready,proc.terminationStatus==0,!answer.isEmpty else{self.profileMessage=answer.isEmpty ? "Не удалось проверить прокси.":answer;return}
                    var next=current;next.Profiles[service]=IndividualProxy(Endpoint:ep,Expected:answer)
                    self.apply(next,service:service)
                }
            }
        }catch{profileMessage=error.localizedDescription}
    }
    private func apply(_ next:ProxyPlan,service:String){
        do{
            guard ready else{throw ProxyIssue("Подключите общий прокси.")}
            let data=try JSONEncoder().encode(next)
            setServiceLease(service,0)
            try ProxyVault.save(data)
            assessmentSpec=data
            guard command("config "+String(decoding:data,as:UTF8.self),expect:"READY") else{throw ProxyIssue("Настройки сохранены. Guard восстановит подключение.")}
            assessmentSpec=data;plan=next;profileMessage="Маршрут сохранён.";profileChanged?(service)
        }catch{profileMessage=error.localizedDescription}
    }
    private var server:Process?
    private var reconnect:DispatchWorkItem?
    private var reconnectDelay:TimeInterval=1
    private var lastRelayStart=Date.distantPast
    private func retryRelay(_ data:Data) {
        guard reconnect==nil,server==nil,!expected.isEmpty else{return}
        let wait=reconnectDelay
        reconnectDelay=min(60,wait*2)
        message="Прокси остановился. Повторяем подключение через "+String(Int(wait))+" с."
        let work=DispatchWorkItem { [weak self] in
            guard let self=self else{return}
            self.reconnect=nil
            guard self.server==nil,!self.expected.isEmpty else{return}
            do {
                try self.relay(data)
                self.finishRestore()
            } catch {self.retryRelay(data)}
        }
        reconnect=work
        DispatchQueue.main.asyncAfter(deadline:.now()+wait,execute:work)
    }
    private var lifetime:Pipe?
    private var activityFolder:URL?
    var activitySocket:String? { activityFolder?.appendingPathComponent("flows").path }
    private func clearActivityFolder(){
        if let dir=activityFolder {try? FileManager.default.removeItem(at:dir)}
        activityFolder=nil
    }
    var routeChanged:(()->Void)?
    private func start(_ mode:String,_ payload:Data)throws ->(Process,Pipe,Pipe) {
        let p=Process(),input=Pipe(),output=Pipe()
        p.executableURL=Bundle.main.resourceURL!.appendingPathComponent("guard");p.arguments=[mode]
        if mode=="proxy-serve",let path=activitySocket {
            var env=ProcessInfo.processInfo.environment;env["AI_GUARD_ACTIVITY_SOCKET"]=path;p.environment=env
        }
        p.standardInput=input;p.standardOutput=output;p.standardError=FileHandle.nullDevice
        try p.run();input.fileHandleForWriting.write(payload+Data([10]))
        if mode != "proxy-serve"{try? input.fileHandleForWriting.close()}
        return (p,input,output)
    }
    func relay(_ data:Data)throws {
        plan=try? JSONDecoder().decode(ProxyPlan.self,from:data); leases.removeAll()
        clearActivityFolder()
        let dir=URL(fileURLWithPath:"/private/tmp",isDirectory:true).appendingPathComponent("aeg-"+UUID().uuidString)
        if (try? FileManager.default.createDirectory(at:dir,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])) != nil {activityFolder=dir}
        var started=false
        defer {if !started {clearActivityFolder()}}
        let (p,input,output)=try start("proxy-serve",data)
        var readyFD=pollfd(fd:output.fileHandleForReading.fileDescriptor,events:Int16(POLLIN),revents:0)
        guard poll(&readyFD,1,3000)>0,
              String(data:output.fileHandleForReading.availableData,encoding:.utf8)=="READY\n" else {
            try? input.fileHandleForWriting.close()
            if p.isRunning {p.terminate()}
            throw ProxyIssue("Локальный прокси не запустился.")
        }
        lifetime=input;response=output.fileHandleForReading;assessmentSpec=data;allowedUntil=0;server=p;started=true
        proxyOnly=false
        if plan != nil && UserDefaults.standard.bool(forKey:"proxyOnly") {
            guard command("mode proxy-only",expect:"READY") else {stop();throw ProxyIssue("Режим прокси не подтверждён.")}
            proxyOnly=true
        }
        lastRelayStart=Date()
        p.terminationHandler={ [weak self] proc in DispatchQueue.main.async {
            guard let self=self,self.server===proc else{return}
            let saved=self.assessmentSpec ?? data
            if Date().timeIntervalSince(self.lastRelayStart)>90 {self.reconnectDelay=1}
            self.stop()
            self.routeChanged?()
            self.retryRelay(saved)
        }}
    }
    private func stop() {
        reconnect?.cancel();reconnect=nil
        setLease(0)
        allowedUntil=0;leases.removeAll();proxyOnly=false
        assessmentSpec=nil;response=nil
        overlayRequested=false;overlayStarting=false;overlayStarted=false
        let running=server;server=nil
        try? lifetime?.fileHandleForWriting.close();lifetime=nil
        if let running,running.isRunning {running.terminate()}
        clearActivityFolder()
        ready=false
    }
    func restore(){
        guard !expected.isEmpty else{return}
        do {guard let stored=ProxyVault.read() else{throw ProxyIssue("Откройте связку ключей и переподключите прокси.")}
            let data=try JSONEncoder().encode(ProxyPlan.load(stored))
            do {try relay(data)} catch {retryRelay(data);return}
            finishRestore()
        }
        catch {message=error.localizedDescription}
    }
    private func syncFilter(connected:Bool)throws {
        let home=FileManager.default.homeDirectoryForCurrentUser
        let managed=home.appendingPathComponent("Library/LaunchAgents/local.aiexitguard.filter.plist")
        let paused=home.appendingPathComponent("Library/Application Support/AI Exit Guard/paused-filter.plist")
        guard FileManager.default.fileExists(atPath:managed.path) || FileManager.default.fileExists(atPath:paused.path) else{return}
        let build=Bundle.main.object(forInfoDictionaryKey:"CFBundleVersion") as? String ?? ""
        let update=connected && defaults.string(forKey:"filterProfileBuild") != build
        let task=Process()
        task.executableURL=Bundle.main.resourceURL!.appendingPathComponent("guard")
        task.arguments=[connected ? (update ? "filter-refresh" : "filter-resume") : "filter-pause"]
        task.standardOutput=FileHandle.nullDevice;task.standardError=FileHandle.nullDevice
        try task.run();task.waitUntilExit()
        guard task.terminationStatus==0 else {throw ProxyIssue("Не удалось переключить системный фильтр Guard.")}
        if update {defaults.set(build,forKey:"filterProfileBuild")}
    }
    private func finishRestore() {
        ready=true;routeWarning="";message=""
        restoreSavedPAC()
        do {try syncFilter(connected:true)} catch {routeWarning=error.localizedDescription}
        if managesDomains && DirectRouteLock.read() != .on {
            busy=true
            domainRoutes.apply(true) { ok in
                self.busy=false
                if !ok {self.routeWarning=self.domainRoutes.message}
                self.routeChanged?()
            }
        } else {routeChanged?()}
    }
    private func restoreSavedPAC() {
        guard UserDefaults.standard.bool(forKey:"restoreGuardPAC") else{return}
        do {try SystemRoute.change(enable:true);UserDefaults.standard.removeObject(forKey:"restoreGuardPAC")}
        catch {message=error.localizedDescription}
    }
    func connect(_ line:String,_ scheme:String) {
        guard !busy,expected.isEmpty else{return}
        routeWarning=""
        do {
            let data=try JSONEncoder().encode(ProxyEndpoint(line,scheme:scheme))
            let (p,_,out)=try start("proxy-check",data)
            busy=true;message="Проверяем выход Claude и ChatGPT…"
            DispatchQueue.global(qos:.userInitiated).async {
                let result=String(data:out.fileHandleForReading.readDataToEndOfFile(),encoding:.utf8)?.trimmingCharacters(in:.whitespacesAndNewlines) ?? ""
                p.waitUntilExit()
                DispatchQueue.main.async {
                    guard p.terminationStatus==0,!result.isEmpty else {self.busy=false;self.message=result.isEmpty ? "Проверка не завершилась.":result;return}
                    do {
                        let saved=try JSONEncoder().encode(ProxyPlan.load(data))
                        if self.defaults.object(forKey:"proxyOnly") == nil {self.defaults.set(true,forKey:"proxyOnly")}
                        try self.relay(saved);try ProxyVault.save(saved)
                        try SystemRoute.change(enable:true)
                        self.expected=result;UserDefaults.standard.set(result,forKey:"proxyExpected")
                        let alreadyOn=DirectRouteLock.read() == .on
                        self.domainRoutes.apply(true) { ok in
                            self.busy=false
                            guard ok else {
                                let reason=self.domainRoutes.message
                                self.finishDisconnect()
                                self.routeWarning=reason
                                return
                            }
                            if !alreadyOn {self.defaults.set(true,forKey:"manageModelDomains")}
                            self.draft="";self.routeWarning=""
                            do {try self.syncFilter(connected:true)} catch {self.routeWarning=error.localizedDescription}
                            self.ready=self.server?.isRunning == true
                            self.message=self.ready ? "Прокси подключён." : "Восстанавливаем подключение…"
                            self.routeChanged?()
                        }
                    } catch {self.busy=false;self.stop();ProxyVault.clear();self.message=error.localizedDescription}
                }
            }
        } catch {message=error.localizedDescription}
    }
    func disconnect(){
        guard !busy else{return}
        if managesDomains && DirectRouteLock.read() != .off {
            busy=true
            domainRoutes.apply(false) { ok in
                self.busy=false
                if ok {self.finishDisconnect()} else {self.message=self.domainRoutes.message}
            }
        } else {finishDisconnect()}
    }
    private func finishDisconnect() {
        do {try syncFilter(connected:false);try SystemRoute.change(enable:false);defaults.removeObject(forKey:"manageModelDomains");stop();plan=nil;routeWarning="";ProxyVault.clear();UserDefaults.standard.removeObject(forKey:"restoreGuardPAC");expected="";UserDefaults.standard.removeObject(forKey:"proxyExpected");message="Прокси отключён.";routeChanged?()}
        catch {message=error.localizedDescription}
    }
    func prepareForQuit() -> Bool {
        guard !expected.isEmpty, DirectRouteLock.read() == .off else { return true }
        do {
            if defaults.bool(forKey:"proxyOnly") {try syncFilter(connected:false)}
            try SystemRoute.change(enable:false)
            UserDefaults.standard.set(true, forKey:"restoreGuardPAC")
            return true
        } catch { message=error.localizedDescription; return false }
    }
    func shutdown(){stop()}
}

struct ProxyEditor: View {
    @ObservedObject var proxy:ProxyClient
    var body:some View {
        VStack(alignment:.leading,spacing:12) {
            Text("Прокси для ИИ").font(.title2.bold())
            if proxy.expected.isEmpty {
                Text("Вставьте строку из кабинета провайдера. Guard проверит, что Claude и ChatGPT видят один IP.").font(.callout)
                Picker("Протокол",selection:$proxy.scheme) {
                    Text("HTTP").tag("http");Text("HTTPS").tag("https");Text("SOCKS5").tag("socks5")
                }.pickerStyle(.segmented)
                SecureField("логин:пароль@адрес:порт",text:$proxy.draft).textFieldStyle(.roundedBorder)
                HStack {
                    Button("Вставить"){proxy.draft=NSPasteboard.general.string(forType:.string) ?? ""}
                    Spacer()
                    Button("Подключить"){proxy.connect(proxy.draft,proxy.scheme)}.buttonStyle(.borderedProminent).disabled(proxy.draft.isEmpty || proxy.busy)
                }.disabled(proxy.busy)
                Text("macOS запросит разрешение на настройку сети. Пароль хранится в Связке ключей.").font(.caption).foregroundStyle(.secondary)
            } else {
                Text("Выбранный выход   "+proxy.expected).textSelection(.enabled)
                Button("Отключить прокси",action:proxy.disconnect)
            }
            if !proxy.routeWarning.isEmpty {Text(proxy.routeWarning).font(.callout).foregroundStyle(.orange)}
            if proxy.busy {ProgressView().controlSize(.small)}
            if !proxy.message.isEmpty {Text(proxy.message).font(.callout).fixedSize(horizontal:false,vertical:true)}
        }
    }
}
