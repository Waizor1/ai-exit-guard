import Foundation
import Darwin

// Explicit proxy clients send the destination name to Guard. The upstream
// resolves it remotely; a direct lookup on this Mac must lead to loopback.
enum DirectRouteLock {
    static let legacyHosts = [
        "claude.ai", "www.claude.ai", "api.claude.ai", "claude.com",
        "anthropic.com", "api.anthropic.com", "platform.claude.com",
        "console.anthropic.com", "platform.claude.ai",
        "chatgpt.com", "www.chatgpt.com", "ab.chatgpt.com", "ws.chatgpt.com",
        "chat.openai.com", "api.openai.com", "auth.openai.com",
        "auth0.openai.com", "platform.openai.com", "auth.chatgpt.com"
    ]
    static let hosts = [
        "claude.ai", "claude.com", "anthropic.com",
        "claudeusercontent.com", "claudemcpcontent.com", "openai.com",
        "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
        "oaistatsig.com", "openaimerge.com", "antigravity.google",
        "antigravity.google.com", "aicode.googleapis.com", "cloudcode-pa.googleapis.com",
        "daily-cloudcode-pa.googleapis.com", "jetski-webchannel.googleapis.com", "businessaicode.googleapis.com",
        "businessaicode.us.rep.googleapis.com", "businessaicode.eu.rep.googleapis.com", "businessaicode.mtls.googleapis.com",
        "antigravity-hub-auto-updater-974169037036.us-central1.run.app", "antigravity-ide-auto-updater-974169037036.us-central1.run.app", "www.claude.ai",
        "api.claude.ai", "api.anthropic.com", "platform.claude.com",
        "console.anthropic.com", "platform.claude.ai", "www.chatgpt.com",
        "ab.chatgpt.com", "ws.chatgpt.com", "chat.openai.com",
        "api.openai.com", "auth.openai.com", "auth0.openai.com",
        "platform.openai.com", "auth.chatgpt.com", "cdn.oaistatic.com",
        "files.oaiusercontent.com", "generativelanguage.googleapis.com"
    ]
    static let begin = "# BEGIN AI Exit Guard model hosts"
    static let end = "# END AI Exit Guard model hosts"
    static let legacyBlock = ([begin] + legacyHosts.map { "127.0.0.2 " + $0 } + legacyHosts.map { "::1 " + $0 } + [end]).joined(separator:"\n") + "\n"
    static let block = ([begin] + hosts.map { "127.0.0.2 " + $0 } + hosts.map { "::ffff:127.0.0.2 " + $0 } + [end]).joined(separator:"\n") + "\n"
    enum State { case off, on, conflict, unknown }
    static func state(_ data:String) -> State {
        let lines=data.components(separatedBy:"\n")
        let marks=lines.filter { $0 == begin || $0 == end }
        if marks.isEmpty {return .off}
        guard marks == [begin,end], ("\n" + data).contains("\n" + block) else {return .conflict}
        return .on
    }
    static func resolvesLocally(_ host:String) -> Bool {
        var info:UnsafeMutablePointer<addrinfo>?
        var hints=addrinfo()
        hints.ai_family=AF_UNSPEC
        hints.ai_socktype=SOCK_STREAM
        guard getaddrinfo(host,nil,&hints,&info)==0, let first=info else {return false}
        defer {freeaddrinfo(first)}
        var node:UnsafeMutablePointer<addrinfo>?=first
        while let current=node {
            let address=current.pointee
            var name=[CChar](repeating:0,count:Int(NI_MAXHOST))
            guard getnameinfo(address.ai_addr,address.ai_addrlen,&name,socklen_t(name.count),nil,0,NI_NUMERICHOST)==0,
                  ["127.0.0.2","::ffff:127.0.0.2"].contains(String(cString:name)) else {return false}
            node=address.ai_next
        }
        return true
    }
    static func read() -> State {
        guard let data=try? String(contentsOfFile:"/private/etc/hosts",encoding:.utf8) else {return .unknown}
        return state(data)
    }
    // The helper edits only a
    // marked block, preserves other bytes and metadata, and serializes writers.
    static let editor = #"""
use strict; use warnings;
use Fcntl qw(:flock);
use File::Temp qw(tempfile);
my ($dir,$enable,$block,$legacy)=@ARGV;
open(my $lock, "<", $dir) or die "open directory";
flock($lock, LOCK_EX) or die "lock";
my $path="$dir/hosts";
die "unexpected hosts file" unless -f $path && !-l $path;
sub readfile { open(my $f,'<:raw',$path) or die "read hosts"; local $/; return <$f>; }
my $old=readfile(); my $new=$old;
my ($begin,@lines)=split(/\n/,$block); my $end=pop @lines;
my @marks=($old =~ /^(\Q$begin\E|\Q$end\E)$/mg);
if ($enable eq 'upgrade') {
    exit 0 unless defined $legacy && index("\n".$old, "\n".$legacy) >= 0;
    $enable='on';
}
if (@marks) {
    die "modified block" unless @marks==2 && $marks[0] eq $begin && $marks[1] eq $end && ($new =~ s/^\Q$block\E//m || (defined $legacy && $new =~ s/^\Q$legacy\E//m));
}
if ($enable eq 'on') {
    my %hosts=map { (split / /)[1] => 1 } @lines;
    for (split /\n/, $new) {
        s/#.*//; my ($ip,@names)=split;
        die "conflicting host" if grep { $hosts{lc($_)} } @names;
    }
    die "missing newline" if length($new) && $new !~ /\n\z/;
    $new.=$block;
}
exit 0 if $old eq $new;
my ($temp,$name)=tempfile('.aiexitguard.XXXXXXXX', DIR=>$dir, UNLINK=>1);
close $temp or die "close";
system('/bin/cp','-p',$path,$name)==0 or die "metadata";
open(my $out,'>:raw',$name) or die "open replacement";
print {$out} $new or die "write"; close $out or die "close replacement";
die "hosts changed" unless readfile() eq $old;
rename($name,$path) or die "replace";
print "changed\n";
"""#
}

@objc(GuardRuleControl) protocol GuardRuleControl {
    func setProtection(_ enabled: Bool, withReply reply: @escaping (Bool) -> Void)
    func setSystemProxy(_ enabled: Bool, withReply reply: @escaping (Bool, String) -> Void)
    func publishDNS(_ hosts: [String], udp: FileHandle, tcp: FileHandle, withReply reply: @escaping (Bool) -> Void)
    func renewDNS(withReply reply: @escaping (Bool) -> Void)
    func clearDNS(withReply reply: @escaping (Bool) -> Void)
    func publishSystemDNS(_ udp: FileHandle, tcp: FileHandle, withReply reply: @escaping (Bool) -> Void)
    func renewSystemDNS(withReply reply: @escaping (Bool) -> Void)
    func clearSystemDNS(withReply reply: @escaping (Bool) -> Void)
    func ping(withReply reply: @escaping (Bool) -> Void)
}

func guardRuleInterface() -> NSXPCInterface {
    let interface = NSXPCInterface(with: GuardRuleControl.self)
    let classes = NSSet(objects: NSArray.self, NSString.self) as! Set<AnyHashable>
    interface.setClasses(classes, for: #selector(GuardRuleControl.publishDNS(_:udp:tcp:withReply:)),
                         argumentIndex: 0, ofReply: false)
    return interface
}

let guardServiceName = "local.aiexitguard.rules"
