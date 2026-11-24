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
        string name=prefix+" external";
        dynamic existing=Owned(policy,name,path);
        if(!enabled){if(existing!=null)rules.Remove(name);return;}
        if(existing!=null) {
            if(!(bool)existing.Enabled || (int)existing.Direction!=2 || (int)existing.Action!=0 || (int)existing.Protocol!=256 || (int)existing.Profiles!=7 || (string)existing.RemoteAddresses!="*")
                throw new InvalidDataException("Существующее правило брандмауэра было изменено.");
            return;
        }
        // Defender treats local loopback separately for ordinary desktop apps.
        // Block all external addresses; the signed redirector handles local port rules.
        dynamic r=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule",true));
        r.Name=name;r.Grouping=Group;r.ApplicationName=path;r.Direction=2;r.Action=0;
        r.Profiles=7;r.Enabled=true;rules.Add(r);
    }
}
