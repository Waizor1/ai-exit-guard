using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

static class ClientLock {
    const string Group="AI Exit Guard";
    static string Prefix(string path){
        string file=Path.GetFileName(path).ToLowerInvariant();
        if(!Path.IsPathRooted(path) || !new[]{"codex.exe","claude.exe","antigravity.exe","language_server_windows_x64.exe","language_server_windows_arm64.exe"}.Contains(file))throw new ArgumentException("Выберите отдельный исполняемый файл Codex, Claude или Antigravity.");
        using(var hash=SHA256.Create())return Group+" "+BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(Path.GetFullPath(path).ToLowerInvariant()))).Replace("-","").Substring(0,24);
    }
    static dynamic Policy(){return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2",true));}
    static dynamic Owned(dynamic policy,string name,string path){
        foreach(dynamic rule in policy.Rules){
            if(!String.Equals((string)rule.Name,name,StringComparison.Ordinal))continue;
            if((string)rule.Grouping!=Group || !String.Equals((string)rule.ApplicationName,path,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Конфликт имён правил Windows Firewall.");
            return rule;
        }
        return null;
    }
    public static bool Active(string path){
        string prefix=Prefix(path);dynamic policy=Policy();
        return Owned(policy,prefix+" external",path)!=null;
    }
    public static void Apply(string path,bool enabled){
        string prefix=Prefix(path);dynamic policy=Policy();dynamic rules=policy.Rules;
        if(enabled){
            if(!File.Exists(path))throw new FileNotFoundException();
            foreach(int profile in new[]{1,2,4})if(!policy.FirewallEnabled[profile])throw new InvalidOperationException("Включите брандмауэр Windows во всех профилях.");
        }
        var specs=new[]{
            new {Name="external",Protocol=256,Addresses="0.0.0.0-127.0.0.0,127.0.0.2-255.255.255.255,::/0",Ports=""},
            new {Name="other TCP",Protocol=6,Addresses="127.0.0.1",Ports="1-39177,39179-65535"},
            new {Name="local UDP",Protocol=17,Addresses="127.0.0.1",Ports=""}
        };
        foreach(var spec in specs) {
            string name=prefix+" "+spec.Name;dynamic existing=Owned(policy,name,path);
            if(!enabled){if(existing!=null)rules.Remove(name);continue;}
            if(existing!=null)continue;
            dynamic r=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule",true));
            r.Name=name;r.Grouping=Group;r.ApplicationName=path;r.Protocol=spec.Protocol;
            r.RemoteAddresses=spec.Addresses;if(spec.Ports!="")r.RemotePorts=spec.Ports;
            r.Direction=2;r.Action=0;r.Profiles=7;r.Enabled=true;rules.Add(r);
        }
    }
}
