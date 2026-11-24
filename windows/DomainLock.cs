using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;

static class DomainLock {
    const string Begin="# BEGIN AI Exit Guard model hosts", End="# END AI Exit Guard model hosts";
    // Latin-1 provides byte-for-byte preservation for unrelated lines, including an existing UTF-8 BOM.
    static readonly Encoding Raw=Encoding.GetEncoding(28591);
    static string[] Names(){
        using(var reader=new StreamReader(Assembly.GetExecutingAssembly().GetManifestResourceStream("guard-hosts"))){
            return reader.ReadToEnd().Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries);
        }
    }
    static string Block(string nl){
        var rows=new List<string>();rows.Add(Begin);
        foreach(var h in Names())rows.Add("127.0.0.2 "+h);
        foreach(var h in Names())rows.Add("::ffff:127.0.0.2 "+h);
        rows.Add(End);return String.Join(nl,rows)+nl;
    }
    internal static string Edit(string old,bool enable){
        string nl=old.Contains("\r\n")?"\r\n":"\n", block=Block(nl);
        int i=old.IndexOf(Begin,StringComparison.Ordinal);
        if(i>=0 || old.Contains(End)){
            if(i<0 || (i>0 && old[i-1]!='\n') || !old.Substring(i).StartsWith(block,StringComparison.Ordinal))throw new InvalidDataException("Изменена секция Guard в hosts.");
            old=old.Remove(i,block.Length);
            if(old.Contains(Begin) || old.Contains(End))throw new InvalidDataException("Повтор секции Guard.");
        }
        if(!enable)return old;
        var names=new HashSet<string>(Names(),StringComparer.OrdinalIgnoreCase);
        foreach(string line in old.Split('\n')){
            var fields=line.Split('#')[0].Split((char[])null,StringSplitOptions.RemoveEmptyEntries);
            for(int k=1;k<fields.Length;k++)if(names.Contains(fields[k].TrimEnd('.')))throw new InvalidDataException("Домен уже настроен вручную в hosts.");
        }
        if(old.Length>0 && !old.EndsWith("\n"))throw new InvalidDataException("Добавьте перенос строки в конце файла hosts.");
        return old+block;
    }
    internal static string PathName{get{return Path.Combine(Environment.SystemDirectory,@"drivers\etc\hosts");}}
    internal static bool Enabled(){string s=Raw.GetString(File.ReadAllBytes(PathName));return Edit(s,false)!=s;}
    internal static void Apply(bool enabled){
        string path=PathName;
        using(var mutex=new Mutex(false,@"Global\AIExitGuardHosts")){
            if(!mutex.WaitOne(5000))throw new IOException("Файл hosts занят.");
            try{
                if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("Файл hosts перенаправлен.");
                var old=Raw.GetString(File.ReadAllBytes(path));
                string next=Edit(old,enabled);if(next==old)return;
                string temp=Path.Combine(Path.GetDirectoryName(path),Guid.NewGuid()+".tmp");
                try{
                    using(var file=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None)){byte[] b=Raw.GetBytes(next);file.Write(b,0,b.Length);file.Flush(true);}
                    if(Raw.GetString(File.ReadAllBytes(path))!=old)throw new IOException("Файл hosts изменился.");
                    File.Replace(temp,path,null);
                }finally{if(File.Exists(temp))File.Delete(temp);}
            }finally{mutex.ReleaseMutex();}
        }
        using(var flush=System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"ipconfig.exe"),"/flushdns"){UseShellExecute=false,CreateNoWindow=true})){
            flush.WaitForExit();if(flush.ExitCode!=0)throw new IOException("Не удалось обновить кэш DNS.");
        }
    }
}
