import Foundation
import Darwin

// Explicit proxy clients send the destination name to Guard. The upstream
// resolves it remotely; a direct lookup on this Mac must lead to loopback.
enum DirectRouteLock {
    static let hosts = [
        "claude.ai", "www.claude.ai", "api.claude.ai", "claude.com",
        "anthropic.com", "api.anthropic.com", "platform.claude.com",
        "console.anthropic.com", "platform.claude.ai",
        "chatgpt.com", "www.chatgpt.com", "ab.chatgpt.com", "ws.chatgpt.com",
        "chat.openai.com", "api.openai.com", "auth.openai.com",
        "auth0.openai.com", "platform.openai.com", "auth.chatgpt.com"
    ]
    static let begin = "# BEGIN AI Exit Guard model hosts"
    static let end = "# END AI Exit Guard model hosts"
    static let block = ([begin] + hosts.map { "127.0.0.2 " + $0 } + hosts.map { "::1 " + $0 } + [end]).joined(separator:"\n") + "\n"
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
                  ["127.0.0.2","::1"].contains(String(cString:name)) else {return false}
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
my ($dir,$enable,$block)=@ARGV;
open(my $lock, "<", $dir) or die "open directory";
flock($lock, LOCK_EX) or die "lock";
my $path="$dir/hosts";
die "unexpected hosts file" unless -f $path && !-l $path;
sub readfile { open(my $f,'<:raw',$path) or die "read hosts"; local $/; return <$f>; }
my $old=readfile(); my $new=$old;
my ($begin,@lines)=split(/\n/,$block); my $end=pop @lines;
my @marks=($old =~ /^(\Q$begin\E|\Q$end\E)$/mg);
if (@marks) {
    die "modified block" unless @marks==2 && $marks[0] eq $begin && $marks[1] eq $end && $new =~ s/^\Q$block\E//m;
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
"""#
}

@objc(GuardRuleControl) protocol GuardRuleControl {
    func setProtection(_ enabled: Bool, withReply reply: @escaping (Bool) -> Void)
    func ping(withReply reply: @escaping (Bool) -> Void)
}

let guardServiceName = "local.aiexitguard.rules"
