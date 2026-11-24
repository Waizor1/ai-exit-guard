import Foundation
import SystemConfiguration

// Configurations supplied by a running packet tunnel take priority over Wi-Fi preferences.
// Only the active tunnel's proxy dictionary is edited. No routes, DNS or VPN profiles are replaced.
enum RuntimePAC {
    static func isTunnelPrimary()->Bool {
        guard let store=SCDynamicStoreCreate(nil,"AI Exit Guard" as CFString,nil,nil),
              let global=SCDynamicStoreCopyValue(store,"State:/Network/Global/IPv4" as CFString) as? [String:Any],
              let name=global["PrimaryInterface"] as? String else{return false}
        guard name.hasPrefix("utun") else{return false}
        let list=scutil(["--nc","list"])
        guard let entry=list.split(separator:"\n").first(where:{$0.contains("(Connected)") && $0.contains("[VPN:su.ffg.happ]")}),
              let id=entry.split(whereSeparator:{$0.isWhitespace}).first(where:{UUID(uuidString:String($0)) != nil}) else{return false}
        return scutil(["--nc","status",String(id)]).split(separator:"\n").contains{line in
            line.trimmingCharacters(in:.whitespaces)=="InterfaceName : "+name
        }
    }
    private static func scutil(_ args:[String])->String {
        let p=Process(),out=Pipe();p.executableURL=URL(fileURLWithPath:"/usr/sbin/scutil");p.arguments=args
        p.standardOutput=out;p.standardError=FileHandle.nullDevice
        guard (try? p.run()) != nil else{return ""}
        let data=out.fileHandleForReading.readDataToEndOfFile();p.waitUntilExit()
        return String(data:data,encoding:.utf8) ?? ""
    }
    private static func applied(_ token:String)->Bool {
        guard let store=SCDynamicStoreCreate(nil,"AI Exit Guard" as CFString,nil,nil),
              let global=SCDynamicStoreCopyValue(store,"State:/Network/Global/IPv4" as CFString) as? [String:Any],
              let id=global["PrimaryService"] as? String,UUID(uuidString:id) != nil,
              let config=SCDynamicStoreCopyValue(store,("State:/Network/Service/"+id+"/Proxies") as CFString) as? [String:Any] else{return false}
        return config["AIExitGuardOwner"] as? String==token && SystemRoute.owns(config)
    }
    static func activate(relay:Int32, completion:@escaping(Bool)->Void) {
        guard relay>1 else {completion(false);return}
        // Supply the immutable program as data. Neither credentials nor user-entered shell text enter it.
        let program=#"""
        set -f
        PATH=/usr/bin:/bin:/usr/sbin:/sbin
        export PATH
        pac=http://127.0.0.1:39178/guard.pac
        held=''
        owned() { printf '%s\n' "$d" | /usr/bin/awk -v p="$pac" -v t="$token" '$1=="ProxyAutoConfigURLString" && $3==p {u=1} $1=="AIExitGuardOwner" && $3==t {m=1} END{exit !(u && m)}'; }
        token="$3"
        scoped="State:/Network/Service/local.aiexitguard.$token/Proxies"
        domains="claude.ai claude.com anthropic.com claudeusercontent.com claudemcpcontent.com openai.com chatgpt.com oaistatic.com oaiusercontent.com oaistatsig.com openaimerge.com generativelanguage.googleapis.com antigravity.google antigravity.google.com aicode.googleapis.com cloudcode-pa.googleapis.com daily-cloudcode-pa.googleapis.com jetski-webchannel.googleapis.com businessaicode.googleapis.com businessaicode.us.rep.googleapis.com businessaicode.eu.rep.googleapis.com businessaicode.mtls.googleapis.com antigravity-hub-auto-updater-974169037036.us-central1.run.app antigravity-ide-auto-updater-974169037036.us-central1.run.app"
        scopeLive=''
        scope_on() {
          [ -z "$scopeLive" ] || return 0
          printf 'd.init\nd.add HTTPEnable # 1\nd.add HTTPProxy 127.0.0.1\nd.add HTTPPort # 39178\nd.add HTTPSEnable # 1\nd.add HTTPSProxy 127.0.0.1\nd.add HTTPSPort # 39178\nd.add SupplementalMatchDomains * %s\nset %s\n' "$domains" "$scoped" | /usr/sbin/scutil >/dev/null
          scopeLive=yes
        }
        hadZero=''
        release() {
          if [ -n "$scopeLive" ];then printf 'remove %s\n' "$scoped" | /usr/sbin/scutil >/dev/null;scopeLive='';fi
          [ -n "$held" ] || return 0
          d=$(printf 'show %s\n' "$held" | /usr/sbin/scutil)
          if owned; then
            { printf 'get %s\nd.remove AIExitGuardOwner\nd.remove ProxyAutoConfigURLString\n' "$held"
              if [ "$hadZero" = yes ]; then printf 'd.add ProxyAutoConfigEnable # 0\n'; else printf 'd.remove ProxyAutoConfigEnable\n'; fi
              printf 'set %s\n' "$held"; } | /usr/sbin/scutil >/dev/null
          fi
          held=''
        }
        trap 'release' EXIT
        while /bin/kill -0 "$1" 2>/dev/null && /bin/kill -0 "$2" 2>/dev/null; do
          g=$(printf 'show State:/Network/Global/IPv4\n' | /usr/sbin/scutil)
          id=$(printf '%s\n' "$g" | /usr/bin/awk '$1=="PrimaryService" {print $3}')
          interface=$(printf '%s\n' "$g" | /usr/bin/awk '$1=="PrimaryInterface" {print $3}')
          next=''
          if [[ "$interface" =~ ^utun[0-9]+$ && "$id" =~ ^[A-Fa-f0-9-]{36}$ ]]; then
            happ=$(/usr/sbin/scutil --nc list | /usr/bin/awk '/\(Connected\)/ && /\[VPN:su\.ffg\.happ\]/ {print $3;exit}')
            if [[ "$happ" =~ ^[A-Fa-f0-9-]{36}$ ]] && /usr/sbin/scutil --nc status "$happ" | /usr/bin/awk -v i="$interface" '$1=="InterfaceName" && $3==i {ok=1} END {exit !ok}'; then next="State:/Network/Service/$id/Proxies";fi
          fi
          if [ "$held" != "$next" ]; then release; fi
          if [ -n "$next" ]; then
            d=$(printf 'show %s\n' "$next" | /usr/sbin/scutil)
            if owned; then held="$next"
            elif printf '%s\n' "$d" | /usr/bin/grep -q '^<dictionary>' &&
                 printf '%s\n' "$d" | /usr/bin/awk -v p="$pac" '$1=="AIExitGuardOwner" || $1=="ProxyAutoConfigJavaScript" || ($1=="ProxyAutoConfigURLString" && $3!=p) || ($1~/^(HTTP|HTTPS|SOCKS|ProxyAutoDiscovery)Enable$/ && $3==1){bad=1} END {exit bad}'; then
              hadZero=''; if printf '%s\n' "$d" | /usr/bin/grep -q 'ProxyAutoConfigEnable : 0'; then hadZero=yes;fi
              printf 'get %s\nd.add ProxyAutoConfigEnable # 1\nd.add ProxyAutoConfigURLString %s\nd.add AIExitGuardOwner %s\nset %s\n' "$next" "$pac" "$token" "$next" | /usr/sbin/scutil >/dev/null
              held="$next"
            fi
          fi
          # A denied/conflicting initial write should leave the retry button usable.
          if [ -z "$held" ] && [ -z "$everOwned" ]; then exit 1;fi
          if [ -n "$held" ]; then
            d=$(printf 'show %s\n' "$held" | /usr/sbin/scutil)
            if owned; then everOwned=yes;scope_on;elif [ -z "$everOwned" ]; then exit 1;fi
          fi
          /bin/sleep 3
        done
        """#
        let quote:(String)->String={"'"+$0.replacingOccurrences(of:"'",with:"'\\''")+"'"}
        let token=UUID().uuidString
        let command="/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash --noprofile --norc -c "+quote(program)+" guard "+String(relay)+" "+String(ProcessInfo.processInfo.processIdentifier)+" "+token+" </dev/null >/dev/null 2>&1 &"
        DispatchQueue.global(qos:.utility).async {
            let p=Process();p.executableURL=URL(fileURLWithPath:"/usr/bin/osascript")
            p.arguments=["-e","on run argv","-e","do shell script (item 1 of argv) with administrator privileges","-e","end run",command]
            p.standardOutput=FileHandle.nullDevice;p.standardError=FileHandle.nullDevice
            var ok=false
            do {try p.run();p.waitUntilExit();ok=p.terminationStatus==0} catch {}
            if ok {
                for _ in 0..<15 {if applied(token){break};Thread.sleep(forTimeInterval:0.4)}
            }
            let success=ok && applied(token)
            DispatchQueue.main.async{completion(success)}
        }
    }
}
