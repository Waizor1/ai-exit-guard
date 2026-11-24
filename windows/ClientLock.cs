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
    // Remove only unchanged process-wide rules created by older Guard releases.
    // Group names alone are not proof of ownership.
    public static List<string> LegacyNames(){
        var names=new List<string>();
        dynamic policy=Policy();
        foreach(dynamic rule in policy.Rules){
            if((string)rule.Grouping!=Group)continue;
            string path=(string)rule.ApplicationName;
            if(String.IsNullOrEmpty(path))continue;
            string expected;
            try{expected=Prefix(path)+" external";}catch(ArgumentException){continue;}
            if(!String.Equals((string)rule.Name,expected,StringComparison.Ordinal))continue;
            if((int)rule.Direction==2 && (int)rule.Action==0 && (int)rule.Protocol==256 &&
               (int)rule.Profiles==7 && (string)rule.RemoteAddresses=="*")names.Add(expected);
        }
        return names;
    }
    public static void RemoveLegacy(){
        dynamic policy=Policy();
        foreach(string name in LegacyNames())policy.Rules.Remove(name);
    }
}
