import Foundation

struct ExitVisit: Codable {
    let ip:String
    let first:Date
    var last:Date
    let switched:Bool
    var approved:Bool
}

// All observations are scoped to the precise destination. Two hostnames may legitimately use different exits.
final class ExitHistory {
    static let window:TimeInterval = 15*60
    static let retention:TimeInterval = 30*86400
    private let store:UserDefaults
    private let key="exitVisits.v1"
    private var routes:[String:[ExitVisit]]

    init(store:UserDefaults = .standard) {
        self.store=store
        routes=store.data(forKey:key).flatMap{try? JSONDecoder().decode([String:[ExitVisit]].self,from:$0)} ?? [:]
        prune(at:Date())
    }
    private func save() {
        if let data=try? JSONEncoder().encode(routes) {store.set(data,forKey:key)}
    }
    private func prune(at now:Date) {
        for host in Array(routes.keys) {
            routes[host]?.removeAll{now.timeIntervalSince($0.last)>Self.retention}
        }
    }
    func visits(_ host:String, now:Date = Date()) -> [ExitVisit] {
        (routes[host] ?? []).filter{now.timeIntervalSince($0.last)<=Self.retention}
    }
    func known(_ host:String, ip:String, now:Date)->Bool {
        visits(host,now:now).contains{$0.ip==ip && $0.approved}
    }
    func awaitingConfirmation(_ host:String, ip:String, now:Date, interval:TimeInterval)->Bool {
        guard let visits=routes[host], visits.count>1, let visit=visits.last, visit.ip==ip,
              !known(host,ip:ip,now:now) else {return false}
        return visit.last.timeIntervalSince(visit.first)<interval
    }
    func restricted(_ host:String, now:Date)->Bool {
        let switches=visits(host,now:now).filter{$0.switched && (0..<Self.window).contains(now.timeIntervalSince($0.first))}
        return switches.count>=2
    }
    func observe(_ host:String, ip:String, at now:Date) {
        guard !ip.isEmpty else{return}
        prune(at:now)
        var records=routes[host] ?? []
        if let prior=records.last, prior.ip==ip {
            records[records.count-1].last=now
        } else {
            let switched=records.last.map{(0..<Self.window).contains(now.timeIntervalSince($0.last))} ?? false
            records.append(ExitVisit(ip:ip,first:now,last:now,switched:switched,approved:false))
        }
        routes[host]=records
        save()
    }
    func approve(_ host:String, ip:String, at now:Date) {
        guard var records=routes[host], let last=records.last, last.ip==ip, !last.approved,
              !restricted(host,now:now) || known(host,ip:ip,now:now) else{return}
        records[records.count-1].approved=true
        routes[host]=records
        save()
    }
}
