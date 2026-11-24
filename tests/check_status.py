"""Exercise the app's recommendation, status-item rendering and refresh lifecycle offline."""
import pathlib
import plistlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as stage:
    contents = pathlib.Path(stage) / 'Fixture.app/Contents'
    resources = contents / 'Resources'
    resources.mkdir(parents=True)
    executable = contents / 'MacOS/StatusCheck'
    executable.parent.mkdir()
    (contents / 'Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier':'local.aiexitguard.status-test',
        'CFBundleExecutable':'StatusCheck','CFBundlePackageType':'APPL'}))
    helper = resources / 'guard'
    helper.write_text('#!/bin/sh\ncat "$(dirname "$0")/fixture"\n')
    helper.chmod(0o755)
    # Exercise Quit with a memory-only vault and network preferences. Never modify the host.
    mock_proxy = pathlib.Path(stage) / 'ProxyClient.swift'
    proxy_source = (ROOT/'ProxyClient.swift').read_text()
    route_start = proxy_source.index('    static func change(enable:Bool)throws {')
    route_end = proxy_source.index('final class ProxyClient:',route_start)
    mock_proxy.write_text(proxy_source[:route_start] + """
    static var routeEnabled=true
    static func change(enable:Bool)throws { routeEnabled=enable }
}
enum ProxyVault {
    static var value:Data?
    static func save(_ data:Data)throws {value=data}
    static func read()->Data? {value}
    static func clear(){value=nil}
}
""" + proxy_source[route_end:])
    mock_rules = pathlib.Path(stage) / 'GuardRules.swift'
    rules = (ROOT/'GuardRules.swift').read_text()
    start = rules.index('    static func read() -> State {')
    end = rules.index('    // The helper edits',start)
    mock_rules.write_text(rules[:start]+'    static func read() -> State { .off }\n'+rules[end:])
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
precondition(ProxyVault.read()==nil && ProxyClient().expected.isEmpty)
print("PASS: three tray verdicts, thresholds, mixed routes, region eligibility and expiry, split exits, address rotation, stale data, refresh, network and proxy recovery")
""")
    subprocess.run(['xcrun','swiftc',str(driver),str(mock_rules),str(ROOT/'KillSwitch.swift'),str(ROOT/'Panel.swift'),str(mock_proxy),str(ROOT/'RuntimePAC.swift'),str(ROOT/'Connections.swift'),
                    str(ROOT/'Recommendation.swift'),str(ROOT/'ExitHistory.swift'),'-o',str(executable)],check=True)
    subprocess.run([str(executable)],check=True)
