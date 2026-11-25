"""Exercise the app's recommendation, status-item rendering and refresh lifecycle offline."""
import pathlib
import plistlib
import subprocess
import tempfile
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as stage:
    contents = pathlib.Path(stage) / 'Fixture.app/Contents'
    resources = contents / 'Resources'
    resources.mkdir(parents=True)
    executable = contents / 'MacOS/StatusCheck'
    executable.parent.mkdir()
    (contents / 'Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier':'local.aiexitguard.status-test.'+uuid.uuid4().hex,
        'CFBundleExecutable':'StatusCheck','CFBundlePackageType':'APPL'}))
    helper = resources / 'guard'
    # The private relay pipe can acknowledge an expired positive deadline with CLOSED.
    helper.write_text("""#!/bin/sh
if [ "$1" = proxy-serve ]; then
    IFS= read -r config || exit 2
    echo $$ >> "$(dirname "$0")/relay-pids"
    echo READY
    while IFS= read -r line; do
        case "$line" in "config "*|"mode proxy-only"|"mode guarded") echo READY;; *" 1"|*" 0"|0) echo CLOSED;; *) echo OPEN;; esac
    done
elif [ "$1" = proxy-profile-check ]; then
    IFS= read -r config
    case "$config" in *192.0.2.99*) status=changed;; *) status=ok;; esac
    case "$config" in *3129*) ip=192.0.2.11;; *) ip=192.0.2.10;; esac
    printf '{"Status":"%s","Country":"DE","IP":"%s"}\n' "$status" "$ip"
elif [ "$1" = proxy-check ]; then
    cat >/dev/null; echo 192.0.2.10
else
    cat "$(dirname "$0")/fixture"
fi
""")
    helper.chmod(0o755)
    # Exercise Quit with a memory-only vault and network preferences. Never modify the host.
    mock_proxy = pathlib.Path(stage) / 'ProxyClient.swift'
    proxy_source = (ROOT/'ProxyClient.swift').read_text()
    route_start = proxy_source.index('    static func change(enable:Bool)throws {')
    route_end = proxy_source.index('final class ProxyClient:',route_start)
    # Never consult the console user's launch agent in the UI fixture.
    filter_start = proxy_source.index('    private func syncFilter(connected:Bool)throws {')
    filter_end = proxy_source.index('    private func finishRestore()', filter_start)
    proxy_source = proxy_source[:filter_start] + '    private func syncFilter(connected:Bool)throws {}\n' + proxy_source[filter_end:]
    mock_proxy.write_text(proxy_source[:route_start] + """
    static var routeEnabled=true
    static func change(enable:Bool)throws { routeEnabled=enable }
}
enum ProxyVault {
    static var value:Data?
    static func save(_ data:Data)throws {value=data}
    static var unreadable=false
    static func readForUpdate()throws -> Data? {
        if unreadable{throw ProxyIssue("keychain unavailable")}
        return value
    }
    static func read()->Data? {value}
    static func clear(){value=nil}
}
""" + proxy_source[route_end:] + """
extension ProxyClient {
    func fixtureAdvisory() {proxyOnly=true}
    func fixtureLease(_ ip:String, until:Int64) {
        expected=ip;ready=true;assessmentSpec=Data();allowedUntil=until
    }
}
""")
    mock_rules = pathlib.Path(stage) / 'GuardRules.swift'
    rules = (ROOT/'GuardRules.swift').read_text()
    start = rules.index('    static func read() -> State {')
    end = rules.index('    // The helper edits',start)
    mock_rules.write_text(rules[:start]+'    static var fixtureState:State = .off\n    static func read() -> State { fixtureState }\n'+rules[end:])
    # Model the helper reply at the XPC boundary; the real hosts editor has its own test.
    rules_client = (ROOT/'KillSwitch.swift').read_text()
    start = rules_client.index('        let connectionID = UUID()')
    end = rules_client.index('\n    }\n}', start)
    mock_client = pathlib.Path(stage) / 'KillSwitch.swift'
    mock_client.write_text(rules_client[:start] + """
        DirectRouteLock.fixtureState = enabled ? .on : .off
        busy=false
        refresh()
        completion(true)
""" + rules_client[end:])
    entry = (ROOT / 'main.swift').read_text().split('let app=NSApplication.shared')[0]
    driver = pathlib.Path(stage) / 'main.swift'
    driver.write_text(entry + r"""
let parsed=try! ProxyEndpoint("demo:p%40ss@127.0.0.1:8080",scheme:"http")
precondition(parsed.Password=="p@ss" && parsed.Host=="127.0.0.1")
let alternate=try! ProxyEndpoint("127.0.0.1:1080:demo:local",scheme:"socks5")
precondition(alternate.User=="demo" && alternate.Scheme=="socks5")
precondition((try? ProxyEndpoint("http://host.example:65536",scheme:"http"))==nil)
precondition(!SystemRoute.compatible(["HTTPEnable":1]))
precondition(!SystemRoute.compatible(["ProxyAutoConfigEnable":1,"ProxyAutoConfigURLString":"https://example.com/other.pac"]))
precondition(SystemRoute.owns(["ProxyAutoConfigEnable":1,"ProxyAutoConfigURLString":SystemRoute.pac]))
let app=NSApplication.shared
defer {UserDefaults.standard.removePersistentDomain(forName:Bundle.main.bundleIdentifier!)}
let d=GuardDelegate()
let m=d.model
let isolated=UserDefaults(suiteName:UUID().uuidString)!
m.proxy.expected=""
m.history=ExitHistory(store:isolated)
var images=Set<Data>()
func waitUntil(_ test:()->Bool){
    let deadline=Date().addingTimeInterval(4)
    while !test() && Date()<deadline{RunLoop.main.run(until:Date().addingTimeInterval(0.01))}
    precondition(test())
}
// A nested ProxyClient update changes the SwiftUI page without publishing a Monitor update.
if let screen=NSScreen.main {
    d.display=screen
    d.anchor=NSRect(x:screen.visibleFrame.midX,y:screen.visibleFrame.maxY-8,width:20,height:16)
    d.scroll.contentView=TopAlignedClip()
    d.scroll.documentView=d.host
    d.panel.contentView=d.scroll
    m.proxySettings=true
    d.position()
    d.panel.orderFront(nil)
    RunLoop.main.run(until:Date().addingTimeInterval(0.35))
    let before=d.panel.frame
    m.proxy.expected="192.0.2.10"
    waitUntil { abs(d.panel.frame.height-before.height)>15 }
    precondition(abs(d.panel.frame.maxY-before.maxY)<2)
    m.proxy.expected=""
    waitUntil { abs(d.panel.frame.height-before.height)<2 }
    precondition(d.scroll.contentView.bounds.origin.y==0)
    var measures=0
    let resize=d.host.sizeInvalidated
    d.host.sizeInvalidated={ measures+=1;resize?() }
    RunLoop.main.run(until:Date().addingTimeInterval(0.3))
    precondition(measures<12, "idle panel repeatedly measured itself")
    d.host.sizeInvalidated=resize
    d.panel.orderOut(nil)
    m.proxySettings=false
}
func fixture(_ statuses:[String],age:Double=0){
    let stamp=ISO8601DateFormatter().string(from:Date().addingTimeInterval(-age))
    var data=Data()
    for (host,status) in zip(Monitor.hosts,statuses){
        var rec:[String:Any]=["Host":host,"Status":status,"Detail":"fixture","Checked":stamp,"IP":"","AssessmentIP":"",
                 "RiskDetail":"","InfoDetail":"","Country":"","Network":"","TraceCountry":"DE","InfoChecked":true]
        if ["green","amber","red"].contains(status) {
            rec["IP"]="1.1.1.1";rec["AssessmentIP"]="1.1.1.1"
            rec["Risk"]=2;rec["Trust"]=["green":90,"amber":50,"red":10][status]!
        }
        if status=="info-timeout" {
            rec["IP"]="1.1.1.1";rec["AssessmentIP"]="1.1.1.1"
            rec["Risk"]=2;rec["Trust"]=90;rec["Status"]="green";rec["InfoChecked"]=false
            rec["InfoUnavailable"]=true;rec["InfoDetail"]="тайм-аут"
        }
        if status=="confirmed-high-risk" {rec["Status"]="green";rec["Trust"]=95;rec["Risk"]=90;rec["IP"]="1.1.1.1";rec["AssessmentIP"]="1.1.1.1"}
        if status.hasPrefix("split-") {rec["Status"]="split";rec["Risk"]=Int(status.dropFirst(6))!;rec["IP"]="1.1.1.1";rec["AssessmentIP"]="8.8.8.8"}
        if status=="other-exit" {rec["Status"]="green";rec["Risk"]=5;rec["Trust"]=90;rec["IP"]="9.9.9.9";rec["AssessmentIP"]="9.9.9.9"}
        if status=="conflicting-country" || status=="pending-info" {
            rec["IP"]="1.1.1.1";rec["AssessmentIP"]="8.8.8.8";rec["Risk"]=2;rec["Status"]="split"
            if status=="conflicting-country" {rec["Country"]="RU"} else {rec["InfoChecked"]=false}
        }
        if status.hasPrefix("visit-") {
            let ip=String(status.dropFirst(6))
            rec["IP"]=ip;rec["AssessmentIP"]=ip;rec["Status"]="green";rec["Risk"]=2;rec["Trust"]=90
        }
        if ["unsupported","exception","missing-country"].contains(status) {
            rec["IP"]="1.1.1.1";rec["Risk"]=2;rec["TraceCountry"]=["unsupported":"CN","exception":"UA","missing-country":"XX"][status]!
        }
        data.append(try! JSONSerialization.data(withJSONObject:rec));data.append(10)
    }
    try! data.write(to:Bundle.main.resourceURL!.appendingPathComponent("fixture"))
}
func result(_ statuses:[String],_ expected:Recommendation,_ age:Double=0){
    fixture(statuses,age:age);m.check();waitUntil{!m.running}
    precondition(m.overall==expected,"unexpected result for "+statuses.joined(separator:",")+" expected "+expected.title+" got "+m.overall.title+" "+m.advice)
    d.draw()
    let button=d.item.button!
    precondition(button.toolTip!.contains(expected.title))
    precondition(button.image != nil && !button.image!.isTemplate)
    images.insert(button.image!.tiffRepresentation!)
}
m.online=true
m.policyDate={RegionPolicy.reviewed.addingTimeInterval(86400)}
m.proxyAllowsProbe={true}
func repeated(_ status:String)->[String]{Array(repeating:status,count:4)}
result(repeated("green"),.clear)
// A missing answer starts bounded backoff until fresh evidence recovers the route.
result(repeated("unknown"),.caution)
m.tick(now:Date().addingTimeInterval(7));precondition(m.running)
waitUntil{!m.running}
m.tick(now:Date().addingTimeInterval(7));precondition(!m.running)
fixture(repeated("green"));m.tick(now:Date().addingTimeInterval(16))
precondition(m.running);waitUntil{!m.running};precondition(m.overall == .clear)
result(repeated("unknown"),.caution)
fixture(repeated("green"));m.tick(now:Date().addingTimeInterval(7))
precondition(m.running);waitUntil{!m.running};precondition(m.overall == .clear)
result(repeated("amber"),.caution)
result(repeated("red"),.avoid)
result(["green","green","green","red"],.avoid)
precondition(m.advice.contains("API ChatGPT"))
result(repeated("split-33"),.caution)
precondition(m.advice.contains("другой выход"))
result(repeated("split-34"),.caution)
result(repeated("split-66"),.caution)
result(repeated("split-67"),.avoid)
result(repeated("confirmed-high-risk"),.avoid)
result(repeated("unsupported"),.avoid)
result(repeated("exception"),.caution)
result(repeated("missing-country"),.caution)
result(repeated("conflicting-country"),.caution)
precondition(m.advice.contains("разные страны"))
result(repeated("pending-info"),.caution)
result(repeated("unknown"),.caution)
result(["green","green"],.caution)
precondition(m.fresh.count==2)
result(repeated("green"),.clear)
result(repeated("other-exit"),.caution)
precondition(m.advice.contains("изменился"))
result(repeated("other-exit"),.caution)
// A fresh installation has no prior switches.
m.invalidate("");m.history=ExitHistory(store:UserDefaults(suiteName:UUID().uuidString)!)
result(repeated("other-exit"),.clear)
let steadyIcon=d.item.button!.image!
fixture(repeated("other-exit"));m.check()
precondition(m.running && m.overall == .caution && m.displayed(Monitor.hosts) == .clear)
precondition(m.displayed(Monitor.hosts,now:Date().addingTimeInterval(181)) == .caution)
d.draw();precondition(d.item.button!.image === steadyIcon)
precondition(m.displayedFinding("claude.ai").verdict == .clear)
waitUntil{!m.running};d.draw();precondition(d.item.button!.image === steadyIcon)
m.invalidate("route changed");precondition(m.fresh.isEmpty && m.overall == .caution)
result(repeated("green"),.caution)
precondition(m.finding("claude.ai") == .changingIP)
result(repeated("green"),.caution,190)
m.online=false;precondition(m.overall == .caution && m.advice.contains("интернета"))
m.online=true;fixture(repeated("amber"));m.tick(now:Date().addingTimeInterval(181))
precondition(m.running && m.fresh.isEmpty)
waitUntil{!m.running};precondition(m.overall == .caution)
precondition(Monitor.proxyEnabled(["__SCOPED__":["en0":["ProxyAutoConfigEnable":1]]]))
m.proxyAllowsProbe={false};m.tick();m.check()
precondition(m.overall == .caution && m.fresh.isEmpty && !m.running && m.advice.contains("прокси"))
m.proxyAllowsProbe={true};m.tick();waitUntil{!m.running}
let day=m.policyDate()
precondition(RegionPolicy.issue(host:"claude.ai",country:"PR",now:day)==nil)
precondition(RegionPolicy.issue(host:"api.openai.com",country:"AF",now:day)==nil)
precondition(RegionPolicy.issue(host:"api.anthropic.com",country:"AF",now:day) == .unsupportedCountry)
m.policyDate={day.addingTimeInterval(91*86400)}
result(repeated("green"),.caution)
precondition(m.advice.contains("устарел"))
precondition(images.count==3)
m.policyDate={day}
m.invalidate("")
m.history=ExitHistory(store:UserDefaults(suiteName:UUID().uuidString)!)
result(repeated("visit-1.1.1.1"),.clear)
result(repeated("visit-8.8.8.8"),.caution)
result(repeated("visit-9.9.9.9"),.avoid)
precondition(m.finding("claude.ai") == .frequentSwitch)
result(repeated("visit-9.9.9.9"),.avoid)
result(repeated("visit-1.1.1.1"),.clear)
result(repeated("confirmed-high-risk"),.avoid)
let defaults=UserDefaults(suiteName:UUID().uuidString)!
let journal=ExitHistory(store:defaults)
let now=Date()
func record(_ address:String,_ seconds:Double) {journal.observe("claude.ai",ip:address,at:now.addingTimeInterval(seconds))}
record("A",0);journal.approve("claude.ai",ip:"A",at:now)
record("B",60);record("B",179)
func awaiting(_ ip:String, _ seconds:Double)->Bool {
    journal.awaitingConfirmation("claude.ai",ip:ip,now:now.addingTimeInterval(seconds),interval:Monitor.refreshInterval)
}
precondition(awaiting("B",190)) // Wall time alone cannot confirm an address.
record("B",180);precondition(!awaiting("B",180))
record("C",181)
let later=now.addingTimeInterval(181)
precondition(journal.restricted("claude.ai",now:later))
journal.approve("claude.ai",ip:"C",at:later)
precondition(!journal.known("claude.ai",ip:"C",now:later))
precondition(ExitHistory(store:defaults).known("claude.ai",ip:"A",now:later))
precondition(!journal.restricted("api.anthropic.com",now:later))
precondition(!journal.restricted("claude.ai",now:now.addingTimeInterval(961)))
record("C",1050);record("A",1082)
precondition(!journal.restricted("claude.ai",now:now.addingTimeInterval(1082)))
precondition(!awaiting("A",1082))
record("D",2100)
precondition(!journal.restricted("claude.ai",now:now.addingTimeInterval(2100)))
precondition(awaiting("D",2100))
record("D",2220);precondition(!awaiting("D",2220))
// A manual advisory check retries temporary failures without closing the relay or enabling periodic polling.
let advisory=Monitor()
advisory.online=true;advisory.policyDate={day}
advisory.proxy.fixtureLease("1.1.1.1",until:0);advisory.proxy.fixtureAdvisory()
fixture(repeated("green"));advisory.check();waitUntil{!advisory.running}
fixture(repeated("unknown"));advisory.check();waitUntil{!advisory.running}
for wait:TimeInterval in [7,16] {
    advisory.tick(now:Date().addingTimeInterval(wait))
    precondition(advisory.running && advisory.proxy.isOpen("Claude"))
    waitUntil{!advisory.running}
}
advisory.tick(now:Date().addingTimeInterval(300))
precondition(!advisory.running && advisory.explanation(for:Monitor.hosts).contains("недоступна"))
advisory.check();waitUntil{!advisory.running}
fixture(repeated("green"));advisory.tick(now:Date().addingTimeInterval(7))
precondition(advisory.running);waitUntil{!advisory.running}
precondition(advisory.overall == .clear)
advisory.tick(now:Date().addingTimeInterval(91));precondition(!advisory.running)
let googleEvidence = Reading(Host:Monitor.googleHost,IP:"1.1.1.1",AssessmentIP:"",Status:"google",Detail:"",RiskDetail:"",Checked:"",Trust:nil,Risk:2,Country:"DE",Network:"",InfoDetail:"",Signals:nil,TraceCountry:"DE",InfoChecked:true,InfoUnavailable:false)
precondition(googleEvidence.finding(now:day) == .trustUnavailable)
// A short diagnostic outage is visible without downgrading a still-verified route.
let pinned=Monitor()
pinned.history=ExitHistory(store:UserDefaults(suiteName:UUID().uuidString)!)
pinned.policyDate={day};pinned.online=true
let deadline=Int64(Date().timeIntervalSince1970)+120
pinned.proxy.fixtureLease("1.1.1.1",until:deadline)
func checkPinned(_ status:String) {
    fixture(repeated(status));pinned.check();waitUntil{!pinned.running}
}
checkPinned("info-timeout")
precondition(pinned.leaseDeadline(success:true)>0)
precondition(pinned.serviceDeadline(group:Monitor.serviceHosts("Claude"),success:true)>0)
checkPinned("green")
checkPinned("unknown")
precondition(pinned.finding("claude.ai") == .domainUnavailable)
precondition(pinned.displayedFinding("claude.ai") == .rechecking)
precondition(pinned.displayed(Monitor.hosts) == .clear)
precondition(pinned.explanation(for:Monitor.hosts) == Finding.rechecking.explanation)
precondition(pinned.proxy.allowedUntil == deadline)
precondition(pinned.displayed(Monitor.hosts,now:Date(timeIntervalSince1970:Double(deadline))) == .caution)
var leaseRedraws=0
pinned.changed={leaseRedraws+=1}
pinned.tick()
precondition(leaseRedraws>0)
leaseRedraws=0
pinned.tick()
precondition(leaseRedraws==0)
pinned.proxy.fixtureLease("1.1.1.1",until:0)
pinned.tick()
precondition(leaseRedraws>0 && pinned.displayed(Monitor.hosts) == .caution)
pinned.proxy.fixtureLease("1.1.1.1",until:deadline)
checkPinned("amber");checkPinned("unknown")
precondition(pinned.displayed(Monitor.hosts) == .caution)
checkPinned("green");checkPinned("red")
precondition(pinned.displayed(Monitor.hosts) == .avoid)
pinned.online=false
precondition(pinned.displayed(Monitor.hosts) == .caution)
let recovered=ProxyClient()
recovered.expected="192.0.2.55"
let fakePlan=try! JSONEncoder().encode(ProxyPlan(Common:try! ProxyEndpoint("http://127.0.0.1:1",scheme:"http"),Profiles:[:]))
try! recovered.relay(fakePlan)
recovered.ready=true
let validUntil=Int64(Date().timeIntervalSince1970)+90
recovered.setServiceLease("Claude",validUntil)
recovered.setServiceLease("ChatGPT",1)
precondition(recovered.ready && recovered.isOpen("Claude") && !recovered.isOpen("ChatGPT"))
let pidFile=Bundle.main.resourceURL!.appendingPathComponent("relay-pids")
func fixturePIDs()->[Int32] {((try? String(contentsOf:pidFile,encoding:.utf8)) ?? "").split(separator:"\n").compactMap{Int32($0)}}
let count=fixturePIDs().count
Darwin.kill(fixturePIDs().last!,SIGTERM)
waitUntil{fixturePIDs().count==count+1 && recovered.ready}
precondition(!recovered.isOpen("Claude"))
recovered.shutdown()
RunLoop.main.run(until:Date().addingTimeInterval(1.3))
precondition(!recovered.ready && fixturePIDs().count==count+1)
let dummy=Data("fixture-secret".utf8)
try! ProxyVault.save(dummy)
m.proxy.expected="192.0.2.1"
UserDefaults.standard.set(m.proxy.expected,forKey:"proxyExpected")
defer {UserDefaults.standard.removeObject(forKey:"restoreGuardPAC");UserDefaults.standard.removeObject(forKey:"proxyExpected")}
precondition(d.applicationShouldTerminate(app) == .terminateNow)
precondition(!SystemRoute.routeEnabled && ProxyVault.read()==dummy)
precondition(ProxyClient().expected=="192.0.2.1")
precondition(UserDefaults.standard.bool(forKey:"restoreGuardPAC"))
m.proxy.disconnect()
precondition(ProxyVault.read()==dummy && ProxyClient().paused && ProxyClient().expected.isEmpty)
// A fresh connect, ordinary quit, restore and explicit disconnect share ownership.
ProxyVault.clear(); UserDefaults.standard.removeObject(forKey:"proxyExpected")
let client=ProxyClient()
client.expected=""
let connectedDefaults=UserDefaults.standard
connectedDefaults.removeObject(forKey:"manageModelDomains")
connectedDefaults.removeObject(forKey:"proxyOnly")
client.connect("http://127.0.0.1:3128","http")
waitUntil{!client.busy}
precondition(client.ready && client.proxyOnly && client.managesDomains && DirectRouteLock.read() == .on)
precondition(client.shouldReleaseDomainsOnQuit)
client.releaseDomainsForQuit{ok in precondition(ok)}
precondition(client.prepareForQuit() && DirectRouteLock.read() == .off)
client.shutdown()
client.restore()
precondition(client.ready && DirectRouteLock.read() == .on)
client.disconnect()
precondition(!client.ready && !client.proxyOnly && !client.managesDomains && DirectRouteLock.read() == .off)
let restarted=ProxyClient()
var savedPlan=try! ProxyPlan.load(ProxyVault.read()!)
savedPlan.Profiles["Antigravity"]=IndividualProxy(Endpoint:try! ProxyEndpoint("127.0.0.1:3129",scheme:"http"),Expected:"192.0.2.11")
let storedPlan=try! JSONEncoder().encode(savedPlan)
try! ProxyVault.save(storedPlan)
restarted.restore()
precondition(restarted.paused && !restarted.ready && restarted.savedIP=="192.0.2.10" && !SystemRoute.routeEnabled)
connectedDefaults.set("192.0.2.99",forKey:"proxyExpected")
restarted.resumeSaved()
waitUntil{!restarted.busy}
precondition(restarted.paused && !restarted.ready && !SystemRoute.routeEnabled && (try! ProxyPlan.load(ProxyVault.read()!)).Profiles["Antigravity"]?.Expected=="192.0.2.11")
connectedDefaults.set("192.0.2.10",forKey:"proxyExpected")
restarted.resumeSaved()
waitUntil{!restarted.busy}
precondition(restarted.expectedIP("Antigravity")=="192.0.2.11")
precondition(restarted.ready && !restarted.paused && (try! ProxyPlan.load(ProxyVault.read()!)).Profiles["Antigravity"]?.Expected=="192.0.2.11")
let first=restarted.library.entries[0]
let archived=ProxyVault.read()
ProxyVault.unreadable=true
restarted.connect("http://127.0.0.1:3130","http")
waitUntil{!restarted.busy}
precondition(restarted.ready && restarted.library.current==first.id && ProxyVault.read()==archived && restarted.plan?.Common.Port==3128)
ProxyVault.unreadable=false
restarted.connect("http://127.0.0.1:3130","http")
waitUntil{!restarted.busy}
precondition(restarted.library.entries.count==2 && restarted.library.current != first.id)
restarted.selectSaved(first)
waitUntil{!restarted.busy}
precondition(restarted.library.current==first.id && restarted.expectedIP("Antigravity")=="192.0.2.11")
restarted.checkLibrary()
waitUntil{!restarted.measuring}
precondition(restarted.observations[first.id]?.contains("Германия")==true)
restarted.disconnect()
precondition(restarted.ready && restarted.plan?.CommonPaused==true && !restarted.isOpen("Claude") && restarted.isOpen("Antigravity"))
restarted.shutdown()
let individualOnly=ProxyClient();individualOnly.restore()
precondition(individualOnly.ready && individualOnly.plan?.CommonPaused==true && !individualOnly.isOpen("ChatGPT") && individualOnly.isOpen("Antigravity"))
individualOnly.setCommonPaused(false);waitUntil{!individualOnly.busy}
precondition(individualOnly.ready && individualOnly.isOpen("Claude"))
individualOnly.disconnectAll()
DirectRouteLock.fixtureState = .on
client.connect("http://127.0.0.1:3128","http")
waitUntil{!client.busy}
precondition(client.ready && !client.managesDomains)
client.disconnect()
precondition(DirectRouteLock.read() == .on)
DirectRouteLock.fixtureState = .conflict
client.connect("http://127.0.0.1:3128","http")
waitUntil{!client.busy}
precondition(!client.ready && client.expected.isEmpty && !client.routeWarning.isEmpty && !SystemRoute.routeEnabled)
print("PASS: fresh proxy-only connect, domain ownership, quit, restore, disconnect and conflict rollback")
print("PASS: three tray verdicts, thresholds, mixed routes, region eligibility and expiry, split exits, address rotation, stale data, refresh, network and proxy recovery")
""")
    subprocess.run(['xcrun','swiftc',str(driver),str(ROOT/'MCPDNS.swift'),str(mock_rules),str(mock_client),str(ROOT/'Panel.swift'),str(mock_proxy),str(ROOT/'RuntimePAC.swift'),str(ROOT/'Connections.swift'),
                    str(ROOT/'Recommendation.swift'),str(ROOT/'ExitHistory.swift'),'-o',str(executable)],check=True)
    subprocess.run([str(executable)],check=True)
