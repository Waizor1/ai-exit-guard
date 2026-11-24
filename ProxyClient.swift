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
    func isOpen(_ service:String,at now:Date=Date())->Bool {
        guard plan != nil else{return allowsTraffic(at:now)}
        return ready && Double(leases[service] ?? 0)>now.timeIntervalSince1970
    }
    @Published var draft=""
    @Published var scheme="socks5"
    @Published var busy=false
    @Published var ready=false
    @Published var message=""
    @Published var expected=UserDefaults.standard.string(forKey:"proxyExpected") ?? ""
    private var overlayRequested=false
    private var overlayStarting=false
    private var overlayStarted=false
    func applyTunnelRoute(force:Bool=false) {
        guard !overlayStarting,!overlayStarted,ready,let server,server.isRunning,RuntimePAC.isTunnelPrimary(),force || !overlayRequested else{return}
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
        ready && Double(allowedUntil) > date.timeIntervalSince1970
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
        if plan != nil {
            guard deadline==0 else{return}
            if leases.values.contains(where:{$0 != 0}) { _ = command("0", expect:"CLOSED") }
            leases.removeAll();allowedUntil=0;return
        }
        guard deadline != allowedUntil, let server, let lifetime, let response else { return }
        do {
            try lifetime.fileHandleForWriting.write(contentsOf: Data("\(deadline)\n".utf8))
            var descriptor = pollfd(fd: response.fileDescriptor, events: Int16(POLLIN), revents: 0)
            guard poll(&descriptor, 1, 1000) > 0,
                  let reply = String(data: response.availableData, encoding: .utf8),
                  reply == (deadline > 0 ? "OPEN\n" : "CLOSED\n") else {
                throw ProxyIssue("Прокси не подтвердил правило.")
            }
            allowedUntil = deadline
        } catch {
            if server.isRunning { Darwin.kill(server.processIdentifier, SIGKILL); server.waitUntilExit() }
            allowedUntil = 0
            ready = false
            message = "Прокси остановлен: не удалось подтвердить защиту."
        }
    }

    private func command(_ line:String,expect:String)->Bool {
        guard let lifetime,let response,let server,server.isRunning else{return false}
        do {
            try lifetime.fileHandleForWriting.write(contentsOf:Data((line+"\n").utf8))
            var fd=pollfd(fd:response.fileDescriptor,events:Int16(POLLIN),revents:0)
            guard poll(&fd,1,1500)>0,String(data:response.availableData,encoding:.utf8)==expect+"\n" else{throw ProxyIssue("Прокси не подтвердил маршрут.")}
            return true
        } catch {
            if server.isRunning {Darwin.kill(server.processIdentifier,SIGKILL);server.waitUntilExit()}
            ready=false;leases.removeAll();allowedUntil=0;message="Guard остановил прокси после ошибки маршрутизации.";return false
        }
    }
    func setServiceLease(_ service:String,_ deadline:Int64){
        guard (leases[service] ?? 0) != deadline else{return}
        if command(service+" "+String(deadline),expect:deadline>0 ? "OPEN":"CLOSED"){
            leases[service]=deadline;allowedUntil=leases.values.max() ?? 0
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
            guard command("config "+String(decoding:data,as:UTF8.self),expect:"READY") else{throw ProxyIssue("Настройки сохранены. Перезапустите Guard.")}
            assessmentSpec=data;plan=next;profileMessage="Маршрут сохранён.";profileChanged?(service)
        }catch{profileMessage=error.localizedDescription}
    }
    @Published private(set) var antigravityMessage = ""
    private var launchedAntigravity: NSRunningApplication?
    private var server:Process?
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
        guard String(data:output.fileHandleForReading.availableData,encoding:.utf8)?.trimmingCharacters(in:.whitespacesAndNewlines)=="READY" else {throw ProxyIssue("Не удалось запустить локальный прокси. Возможно, порт уже занят.")}
        lifetime=input;response=output.fileHandleForReading;assessmentSpec=data;allowedUntil=0;server=p;started=true
        p.terminationHandler={ [weak self] proc in DispatchQueue.main.async {
            guard let self=self,self.server===proc else{return}
            self.allowedUntil=0;self.leases.removeAll();self.assessmentSpec=nil;self.clearActivityFolder();self.ready=false;self.message="Прокси остановлен. Переподключите его.";self.routeChanged?()
        }}
    }
    private func stop(){setLease(0);allowedUntil=0;assessmentSpec=nil;response=nil;overlayRequested=false;overlayStarting=false;overlayStarted=false;let p=server;server=nil;try? lifetime?.fileHandleForWriting.close();lifetime=nil;if let p,p.isRunning {p.terminate()};clearActivityFolder();ready=false}
    func restore(){
        guard !expected.isEmpty else{return}
        do {guard let data=ProxyVault.read() else{throw ProxyIssue("Откройте связку ключей и переподключите прокси.")};try relay(JSONEncoder().encode(ProxyPlan.load(data)));ready=true
            if UserDefaults.standard.bool(forKey:"restoreGuardPAC") {
                try SystemRoute.change(enable:true)
                UserDefaults.standard.removeObject(forKey:"restoreGuardPAC")
            }
        }
        catch {message=error.localizedDescription}
    }
    func connect(_ line:String,_ scheme:String) {
        guard !busy,expected.isEmpty else{return}
        do {
            let data=try JSONEncoder().encode(ProxyEndpoint(line,scheme:scheme))
            let (p,_,out)=try start("proxy-check",data)
            busy=true;message="Проверяем выход Claude и ChatGPT…"
            DispatchQueue.global(qos:.userInitiated).async {
                let result=String(data:out.fileHandleForReading.readDataToEndOfFile(),encoding:.utf8)?.trimmingCharacters(in:.whitespacesAndNewlines) ?? ""
                p.waitUntilExit()
                DispatchQueue.main.async {
                    defer{self.busy=false}
                    guard p.terminationStatus==0,!result.isEmpty else {self.message=result.isEmpty ? "Проверка не завершилась.":result;return}
                    do {
                        let saved=try JSONEncoder().encode(ProxyPlan.load(data));try self.relay(saved);try ProxyVault.save(saved)
                        try SystemRoute.change(enable:true)
                        self.expected=result;UserDefaults.standard.set(result,forKey:"proxyExpected")
                        self.draft="";self.ready=true;self.message="Прокси подключён.";self.routeChanged?()
                    } catch {self.stop();ProxyVault.clear();self.message=error.localizedDescription}
                }
            }
        } catch {message=error.localizedDescription}
    }
    func disconnect(){
        guard !busy else{return}
        do {try SystemRoute.change(enable:false);stop();plan=nil;ProxyVault.clear();UserDefaults.standard.removeObject(forKey:"restoreGuardPAC");expected="";UserDefaults.standard.removeObject(forKey:"proxyExpected");message="Прокси отключён.";routeChanged?()}
        catch {message=error.localizedDescription}
    }
    func prepareForQuit() -> Bool {
        guard !expected.isEmpty, DirectRouteLock.read() == .off else { return true }
        do {
            try SystemRoute.change(enable:false)
            UserDefaults.standard.set(true, forKey:"restoreGuardPAC")
            return true
        } catch { message=error.localizedDescription; return false }
    }
    func shutdown(){stop()}
}

struct ProxyEditor: View {
    @ObservedObject var proxy:ProxyClient
    var guardOnly:Bool
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
                if guardOnly {Button("Настроить для Happ"){proxy.applyTunnelRoute(force:true)}}
                DisclosureGroup("Открыть приложение через Guard") {
                    VStack(alignment:.leading,spacing:8) {
                        Text("Для терминала запустите новую сессию здесь. Открытая сессия сохраняет прежние настройки.").font(.callout)
                        HStack{Button("Claude"){proxy.openService("Claude")};Button("ChatGPT"){proxy.openService("ChatGPT")}}.disabled(!proxy.ready)
                        HStack{Button("Claude Code"){terminal("claude")};Button("Codex"){terminal("codex")}}.disabled(!proxy.ready)
                    }.padding(.top,6)
                }
                Button("Отключить прокси",action:proxy.disconnect)
            }
            if proxy.busy {ProgressView().controlSize(.small)}
            if !proxy.message.isEmpty {Text(proxy.message).font(.callout).fixedSize(horizontal:false,vertical:true)}
        }
    }
    private func terminal(_ command:String) {
        let file=command=="claude" ? "Claude Code" : "Codex"
        guard let script=Bundle.main.url(forResource:file,withExtension:"command") else{return}
        let app=URL(fileURLWithPath:"/System/Applications/Utilities/Terminal.app")
        NSWorkspace.shared.open([script],withApplicationAt:app,configuration:NSWorkspace.OpenConfiguration()) {_,error in
            if error != nil {DispatchQueue.main.async{proxy.message="Не удалось открыть Терминал."}}
        }
    }
}

extension ProxyClient {
    func openAntigravity() {
        guard isOpen("Antigravity") else {antigravityMessage="Дождитесь проверки прокси."; return}
        let id = "com.google.antigravity"
        guard let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier:id) else {
            antigravityMessage="Antigravity не найден в Программах."; return
        }
        if let running = NSRunningApplication.runningApplications(withBundleIdentifier:id).first {
            if running == launchedAntigravity {
                running.activate(options: [.activateAllWindows])
                antigravityMessage=""
            } else {antigravityMessage="Завершите Antigravity через ⌘Q и откройте его здесь ещё раз."}
            return
        }
        let configuration = NSWorkspace.OpenConfiguration()
        let relay = "http://127.0.0.1:39178"
        configuration.arguments = ["--proxy-server=" + relay, "--disable-quic"]
        configuration.environment = ["HTTPS_PROXY":relay, "https_proxy":relay,
                                     "HTTP_PROXY":relay, "http_proxy":relay,
                                     "NO_PROXY":"localhost,127.0.0.1,::1", "no_proxy":"localhost,127.0.0.1,::1"]
        NSWorkspace.shared.openApplication(at:app, configuration:configuration) { opened, error in
            DispatchQueue.main.async {
                self.launchedAntigravity = opened
                self.antigravityMessage = error == nil ? "" : "Не удалось открыть Antigravity."
            }
        }
    }

    func openService(_ service:String) {
        guard ready else {message="Подключите прокси перед открытием.";return}
        let browsers=[("com.google.Chrome","Google Chrome"),("com.microsoft.edgemac","Microsoft Edge")]
        guard let executable=browsers.compactMap({pair -> URL? in
            guard let app=NSWorkspace.shared.urlForApplication(withBundleIdentifier:pair.0) else{return nil}
            return app.appendingPathComponent("Contents/MacOS/"+pair.1)
        }).first else {message="Для окна Guard нужен Google Chrome или Microsoft Edge.";return}
        do {
            let dir=try FileManager.default.url(for:.applicationSupportDirectory,in:.userDomainMask,appropriateFor:nil,create:true)
                .appendingPathComponent("AI Exit Guard/Browser")
            try FileManager.default.createDirectory(at:dir,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
            let p=Process();p.executableURL=executable
            p.arguments=["--user-data-dir="+dir.path,"--no-first-run","--no-default-browser-check","--disable-quic",
                         "--proxy-pac-url="+SystemRoute.pac,"--app=https://"+(service=="Claude" ? "claude.ai" : "chatgpt.com")]
            p.standardInput=FileHandle.nullDevice;p.standardOutput=FileHandle.nullDevice;p.standardError=FileHandle.nullDevice
            try p.run()
        } catch {message="Не удалось открыть окно браузера через Guard."}
    }
}
