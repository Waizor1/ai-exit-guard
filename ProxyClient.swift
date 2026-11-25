import AppKit
import SwiftUI
import SystemConfiguration
import Security

struct ProxyEndpoint: Codable,Equatable {
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
    var CommonPaused:Bool?=nil
    static func load(_ data:Data)throws -> ProxyPlan {
        let decoder=JSONDecoder()
        if let book=try? decoder.decode(ProxyLibrary.self,from:data) {
            guard let current=book.entries.first(where:{$0.id==book.current}) else{throw ProxyIssue("Не найден выбранный профиль.")}
            return current.plan
        }
        if let legacy=try? decoder.decode(ProxyEndpoint.self,from:data) {return ProxyPlan(Common:legacy,Profiles:[:])}
        return try decoder.decode(ProxyPlan.self,from:data)
    }
}

struct SavedProxy:Codable,Identifiable {
    let id:UUID
    var plan:ProxyPlan
    var ip:String
    var title:String {let ep=plan.Common;return ep.Host+":"+String(ep.Port)}
}
struct ProxyLibrary:Codable {
    var entries:[SavedProxy]
    var current:UUID?
    mutating func select(_ plan:ProxyPlan,ip:String,id:UUID?) {
        let index=id.flatMap{key in entries.firstIndex{$0.id==key}}
        if let index {entries[index].plan=plan;entries[index].ip=ip;current=entries[index].id}
        else {
            let entry=SavedProxy(id:UUID(),plan:plan,ip:ip)
            entries.append(entry);current=entry.id
        }
    }
}
private struct ProxyMeasurement:Decodable {
    let IP:String,Country:String,Status:String
    var title:String {
        let country=Locale(identifier:"ru").localizedString(forRegionCode:Country) ?? Country
        switch Status {
        case "ok":return country.isEmpty ? IP : country+" · "+IP
        case "changed":return "IP изменился · "+IP
        case "inconsistent":return "Выходы различаются"
        default:return "Нет ответа"
        }
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
    static func readForUpdate()throws -> Data? {
        var q=query;q[kSecReturnData as String]=true
        var item:CFTypeRef?
        let status=SecItemCopyMatching(q as CFDictionary,&item)
        if status==errSecItemNotFound{return nil}
        guard status==errSecSuccess,let data=item as? Data else{throw ProxyIssue("Связка ключей недоступна. Откройте её и повторите попытку.")}
        return data
    }
    static func read()->Data? {try? readForUpdate()}
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
    func setProxyOnly(_ enabled:Bool,deadlines:[String:Int64])->Bool {
        guard ready, plan != nil, enabled != proxyOnly else{return false}
        var line="mode proxy-only"
        if !enabled {
            guard let data=try? JSONEncoder().encode(deadlines),
                  let payload=String(data:data,encoding:.utf8) else{return false}
            line="mode guarded "+payload
        }
        guard command(line,expect:"READY") else{return false}
        proxyOnly=enabled
        leases=enabled ? [:] : deadlines
        allowedUntil=leases.values.max() ?? 0
        UserDefaults.standard.set(enabled,forKey:"proxyOnly")
        return true
    }
    func isOpen(_ service:String,at now:Date=Date())->Bool {
        if plan?.CommonPaused==true && plan?.Profiles[service]==nil{return false}
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
    @Published private(set) var library=ProxyLibrary(entries:[],current:nil)
    @Published private(set) var observations=[UUID:String]()
    @Published private(set) var measuring=false
    private func loadLibrary()throws -> ProxyLibrary {
        guard let raw=try ProxyVault.readForUpdate() else {
            guard savedIP.isEmpty else{throw ProxyIssue("Не удалось прочитать сохранённый прокси.")}
            return ProxyLibrary(entries:[],current:nil)
        }
        if let book=try? JSONDecoder().decode(ProxyLibrary.self,from:raw){
            guard book.entries.contains(where:{$0.id==book.current}) else{throw ProxyIssue("Не найден выбранный профиль.")}
            return book
        }
        var book=ProxyLibrary(entries:[],current:nil)
        book.select(try ProxyPlan.load(raw),ip:savedIP,id:nil)
        try ProxyVault.save(JSONEncoder().encode(book))
        return book
    }
    func refreshLibrary(){
        do { library=try loadLibrary() }catch{message=error.localizedDescription}
    }
    private func saveLibrary(_ book:ProxyLibrary)throws {
        try ProxyVault.save(JSONEncoder().encode(book))
        library=book
    }
    private func persist(_ profile:ProxyPlan,ip:String,id:UUID?)throws {
        var book=try loadLibrary()
        book.select(profile,ip:ip,id:id)
        try saveLibrary(book)
    }
    private func measure(_ ep:ProxyEndpoint,service:String,pin:String)throws -> ProxyMeasurement {
        struct Request:Encodable {let Endpoint:ProxyEndpoint,Service:String,Expected:String}
        let (proc,_,out)=try start("proxy-profile-check",JSONEncoder().encode(Request(Endpoint:ep,Service:service,Expected:pin)))
        let data=out.fileHandleForReading.readDataToEndOfFile();proc.waitUntilExit()
        guard proc.terminationStatus==0 else{throw ProxyIssue("Прокси не ответил на проверку.")}
        return try JSONDecoder().decode(ProxyMeasurement.self,from:data)
    }
    func checkLibrary(){
        guard !measuring,!library.entries.isEmpty else{return}
        let entries=library.entries
        measuring=true
        DispatchQueue.global(qos:.utility).async {
            for entry in entries {
                var lines=[String]()
                if entry.plan.Profiles.isEmpty {
                    lines.append((try? self.measure(entry.plan.Common,service:"",pin:entry.ip))?.title ?? "Нет ответа")
                }else{
                    for service in Self.services {
                        let route=entry.plan.Profiles[service]
                        if route==nil && entry.plan.CommonPaused==true {lines.append(service+" · общий на паузе");continue}
                        let value=(try? self.measure(route?.Endpoint ?? entry.plan.Common,service:service,pin:route?.Expected ?? entry.ip))?.title ?? "Нет ответа"
                        lines.append(service+" · "+value)
                    }
                }
                let answer=lines.joined(separator:"\n")+" · "+Date().formatted(date:.omitted,time:.shortened)
                DispatchQueue.main.async {self.observations[entry.id]=answer}
            }
            DispatchQueue.main.async {self.measuring=false}
        }
    }
    func selectSaved(_ entry:SavedProxy){
        do {try activate(entry.plan,pin:entry.ip,id:entry.id)}catch{message=error.localizedDescription}
    }
    @Published var replacing=false
    @Published var draft=""
    @Published var scheme="socks5"
    @Published private(set) var routeWarning=""
    @Published var busy=false
    @Published var ready=false
    @Published var message=""
    @Published private(set) var paused=UserDefaults.standard.bool(forKey:"proxyPaused")
    var savedIP:String {defaults.string(forKey:"proxyExpected") ?? ""}
    @Published var expected=UserDefaults.standard.bool(forKey:"proxyPaused") ? "" : UserDefaults.standard.string(forKey:"proxyExpected") ?? ""
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
            try persist(next,ip:expected,id:try loadLibrary().current)
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
        do {try activate(ProxyPlan(Common:ProxyEndpoint(line,scheme:scheme),Profiles:[:]),pin:nil)}
        catch {message=error.localizedDescription}
    }
    func resumeSaved(){
        guard paused,!busy else{return}
        do {
            guard let data=ProxyVault.read(),!savedIP.isEmpty else {throw ProxyIssue("Не удалось открыть сохранённый прокси в Связке ключей.")}
            try activate(ProxyPlan.load(data),pin:savedIP,id:try loadLibrary().current)
        }catch{message=error.localizedDescription}
    }
    private func activate(_ profile:ProxyPlan,pin:String?,id:UUID?=nil)throws {
        guard !busy,(ready || expected.isEmpty) else{return}
        routeWarning=""
        let switching=ready
        do {
            let saved=try JSONEncoder().encode(profile)
            busy=true;message="Проверяем выбранный прокси…"
            DispatchQueue.global(qos:.userInitiated).async {
                var measured=pin ?? ""
                do {
                    if profile.CommonPaused != true {
                        if profile.Profiles.isEmpty {
                            let (p,_,out)=try self.start("proxy-check",JSONEncoder().encode(profile.Common))
                            let value=String(data:out.fileHandleForReading.readDataToEndOfFile(),encoding:.utf8)?.trimmingCharacters(in:.whitespacesAndNewlines) ?? ""
                            p.waitUntilExit()
                            guard p.terminationStatus==0,!value.isEmpty else{throw ProxyIssue(value.isEmpty ? "Проверка не завершилась." : value)}
                            measured=value
                        } else {
                            for service in Self.services where profile.Profiles[service]==nil {
                                let r=try self.measure(profile.Common,service:service,pin:measured)
                                guard r.Status=="ok",!r.IP.isEmpty else{throw ProxyIssue("Не подтверждён общий выход для "+service+".")}
                                measured=r.IP
                            }
                        }
                    }
                    for (service,route) in profile.Profiles {
                        guard try self.measure(route.Endpoint,service:service,pin:route.Expected).Status=="ok" else{throw ProxyIssue("Не подтверждён отдельный выход для "+service+".")}
                    }
                    guard !measured.isEmpty else{throw ProxyIssue("Профиль не содержит закреплённого выхода.")}
                }catch{
                    let reason=error.localizedDescription
                    DispatchQueue.main.async{self.busy=false;self.message=reason}
                    return
                }
                let result=measured
                DispatchQueue.main.async {
                    do {
                        if let pin,pin != result {
                            self.busy=false;self.message="Выходной IP изменился. Для подключения нового адреса настройте прокси заново.";return
                        }
                        if switching {
                            guard self.ready else{throw ProxyIssue("Текущий прокси восстанавливается. Повторите переключение.")}
                            try self.switchRunning(profile,data:saved,ip:result,id:id)
                            self.busy=false;self.replacing=false;self.draft="";self.message="Прокси переключён."
                            self.profileChanged?("Common");return
                        }
                        if self.defaults.object(forKey:"proxyOnly") == nil {self.defaults.set(true,forKey:"proxyOnly")}
                        try self.persist(profile,ip:result,id:id)
                        self.defaults.set(result,forKey:"proxyExpected")
                        self.paused=true;self.defaults.set(true,forKey:"proxyPaused")
                        try self.relay(saved)
                        try SystemRoute.change(enable:true)
                        self.expected=result
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
                            self.replacing=false;self.paused=false;self.defaults.removeObject(forKey:"proxyPaused");self.draft="";self.routeWarning=""
                            do {try self.syncFilter(connected:true)} catch {self.routeWarning=error.localizedDescription}
                            self.ready=self.server?.isRunning == true
                            self.message=self.ready ? "Прокси подключён." : "Восстанавливаем подключение…"
                            self.routeChanged?()
                        }
                    } catch {self.busy=false;if !switching {self.stop();self.plan=nil;self.expected=""};self.message=error.localizedDescription}
                }
            }
        } catch {message=error.localizedDescription}
    }
    private func switchRunning(_ next:ProxyPlan,data:Data,ip:String,id:UUID?)throws {
        guard let previous=assessmentSpec,let old=plan else{throw ProxyIssue("Текущий прокси восстанавливается.")}
        var book=try loadLibrary()
        book.select(next,ip:ip,id:id)
        guard command("config "+String(decoding:data,as:UTF8.self),expect:"READY") else {
            stop();retryRelay(previous);throw ProxyIssue("Guard восстанавливает предыдущий маршрут.")
        }
        do {try saveLibrary(book)}
        catch {
            if !command("config "+String(decoding:previous,as:UTF8.self),expect:"READY"){stop();retryRelay(previous)}
            throw error
        }
        for service in Self.services {
            let before=old.Profiles[service],after=next.Profiles[service]
            let changed = (before?.Endpoint ?? old.Common) != (after?.Endpoint ?? next.Common)
                || (before?.Expected ?? expected) != (after?.Expected ?? ip)
                || (before==nil && old.CommonPaused==true) != (after==nil && next.CommonPaused==true)
            if changed {setServiceLease(service,0);leases.removeValue(forKey:service)}
        }
        allowedUntil=leases.values.max() ?? 0
        plan=next;assessmentSpec=data;expected=ip;defaults.set(ip,forKey:"proxyExpected")
    }
    func setCommonPaused(_ value:Bool){
        guard !busy,ready,var next=plan,!next.Profiles.isEmpty else{return}
        next.CommonPaused=value
        if !value {
            do {try activate(next,pin:expected,id:try loadLibrary().current)}
            catch {message=error.localizedDescription}
            return
        }
        do {
            let data=try JSONEncoder().encode(next)
            try switchRunning(next,data:data,ip:expected,id:try loadLibrary().current)
            message="Общий прокси на паузе. Отдельные маршруты подключены.";profileChanged?("Common")
        }catch{message=error.localizedDescription}
    }
    func disconnect(){
        guard !busy else{return}
        if let plan,!plan.Profiles.isEmpty {setCommonPaused(true);return}
        disconnectAll()
    }
    func disconnectAll(){
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
        do {try syncFilter(connected:false);try SystemRoute.change(enable:false);defaults.removeObject(forKey:"manageModelDomains");stop();plan=nil;routeWarning="";paused = !savedIP.isEmpty;defaults.set(paused,forKey:"proxyPaused");defaults.removeObject(forKey:"restoreGuardPAC");expected="";message="Прокси отключён.";routeChanged?()}
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
            Text("Общий прокси").font(.title2.bold())
            if !proxy.library.entries.isEmpty {
                Text("Сохранённые прокси").font(.headline)
                ScrollView { VStack(alignment:.leading,spacing:8){ ForEach(proxy.library.entries) { entry in
                    HStack {
                        VStack(alignment:.leading) {
                            Text(entry.title).font(.headline)
                            Text(proxy.observations[entry.id] ?? (proxy.measuring ? "Проверяем выход…" : "Выход ещё не проверен")).font(.caption)
                        }
                        Spacer()
                        if proxy.ready && proxy.library.current==entry.id {Text(proxy.plan?.CommonPaused==true ? "Общий на паузе":"Подключён").foregroundStyle(.green)}
                        else { Button("Подключить"){proxy.selectSaved(entry)}.disabled(proxy.busy) }
                    }
                }
                }}.frame(maxHeight:160)
                HStack {
                    Button(proxy.measuring ? "Проверяем…" : "Проверить выходы"){proxy.checkLibrary()}.disabled(proxy.measuring)
                    if !proxy.replacing {Button("Добавить прокси"){proxy.replacing=true}}
                }
            }
            if proxy.paused && !proxy.replacing && proxy.library.entries.isEmpty {
                Text("Сохранённый выход   "+proxy.savedIP)
                HStack {
                    Button("Подключить снова",action:proxy.resumeSaved).buttonStyle(.borderedProminent)
                    Button("Другой прокси"){proxy.replacing=true}
                }.disabled(proxy.busy)
            } else if proxy.replacing || (proxy.expected.isEmpty && proxy.library.entries.isEmpty) {
                if proxy.replacing && (proxy.paused || proxy.ready || !proxy.library.entries.isEmpty) {Button("Отменить добавление"){proxy.replacing=false}}
                Text("Вставьте строку из кабинета провайдера. Guard проверит, что Claude и ChatGPT видят один IP.").font(.callout)
                Picker("Протокол",selection:$proxy.scheme) {
                    Text("HTTP").tag("http");Text("HTTPS").tag("https");Text("SOCKS5").tag("socks5")
                }.pickerStyle(.segmented)
                VStack(alignment:.leading,spacing:4) {
                    Text("Адрес прокси").font(.subheadline.weight(.semibold))
                    SecureField("логин:пароль@адрес:порт",text:$proxy.draft).textFieldStyle(.roundedBorder).accessibilityLabel("Адрес прокси")
                }
                HStack {
                    Button("Вставить"){proxy.draft=NSPasteboard.general.string(forType:.string) ?? ""}
                    Spacer()
                    Button("Подключить"){proxy.connect(proxy.draft,proxy.scheme)}.buttonStyle(.borderedProminent).disabled(proxy.draft.isEmpty || proxy.busy)
                }.disabled(proxy.busy)
                Text("macOS запросит разрешение на настройку сети. Пароль хранится в Связке ключей.").font(.caption).foregroundStyle(.secondary)
            } else if proxy.ready {
                Text("Выбранный выход   "+proxy.expected).textSelection(.enabled)
                if let plan=proxy.plan,!plan.Profiles.isEmpty {
                    Button(plan.CommonPaused==true ? "Подключить общий":"Отключить общий"){proxy.setCommonPaused(plan.CommonPaused != true)}.disabled(proxy.busy)
                    Button("Отключить все прокси"){proxy.replacing=false;proxy.disconnectAll()}.disabled(proxy.busy)
                }else{Button("Отключить прокси"){proxy.replacing=false;proxy.disconnect()}.disabled(proxy.busy)}
            }
            if !proxy.routeWarning.isEmpty {Text(proxy.routeWarning).font(.callout).foregroundStyle(.orange)}
            if proxy.busy {ProgressView().controlSize(.small)}
            if !proxy.message.isEmpty {Text(proxy.message).font(.callout).fixedSize(horizontal:false,vertical:true)}
        }.onAppear{proxy.refreshLibrary();proxy.checkLibrary()}
    }
}
