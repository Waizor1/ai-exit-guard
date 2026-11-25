using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

sealed class ConnectionPane {
    internal sealed class Flow {
        public string Domain {get;set;}
        public string Status {get;set;}
        public long At {get;set;}
    }
    sealed class DnsEntry {
        public string Name {get;set;}
        public string Data {get;set;}
    }
    readonly ListView list;
    readonly Label note;
    readonly Dictionary<string,string> labels=new Dictionary<string,string>{
        {"active","Через Guard"},{"finished","Завершено"},{"blocked","Заблокировано"},{"failed","Ошибка прокси"}
    };
    Flow[] recent=new Flow[0];
    string[] outside=new string[0];
    string last;
    string dnsState="Сверяем прямые TCP-соединения с DNS Windows…";
    bool scanning, online;
    DateTime nextScan;

    public ConnectionPane(TableLayoutPanel panel,Color surface,Color ink){
        note=new Label{AutoSize=true,Dock=DockStyle.Top,ForeColor=ink};
        list=new ListView{View=View.Details,FullRowSelect=true,HeaderStyle=ColumnHeaderStyle.Nonclickable,
            Dock=DockStyle.Top,Height=300,BackColor=surface,ForeColor=ink,BorderStyle=BorderStyle.None,
            AccessibleName="Активные соединения и последние попытки"};
        list.Columns.Add("Состояние",128);list.Columns.Add("Адрес",175);list.Columns.Add("Время",62);
        list.Resize+=(s,e)=>list.Columns[1].Width=Math.Max(100,list.ClientSize.Width-211);
        panel.Controls.Add(note);panel.Controls.Add(list);
    }
    public void Update(Flow[] rows,bool connected){
        recent=rows??new Flow[0];online=connected;Render();
    }
    public async void CheckOutside(){
        if(scanning || DateTime.UtcNow<nextScan)return;
        scanning=true;
        try{
            outside=await Task.Run(()=>FindOutside());
            dnsState=outside.Length==0?"Совпадений по IP вне Guard не найдено.":"«Возможный обход» — адрес совпал по DNS. IP может быть общим.";
        }catch{outside=new string[0];dnsState="Windows не дала проверить прямые соединения.";}
        finally{nextScan=DateTime.UtcNow.AddSeconds(10);scanning=false;if(!list.IsDisposed)Render();}
    }
    static string[] FindOutside(){
        // Read the local DNS cache without sending any DNS or HTTP probes.
        const string query="$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $r=@(Get-DnsClientCache | Where-Object { $_.Type -in 1,28 } | Select-Object Name,Data); ConvertTo-Json -InputObject $r -Compress";
        var info=new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,@"WindowsPowerShell\v1.0\powershell.exe"),
            "-NoLogo -NoProfile -NonInteractive -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(query))){
            UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,StandardOutputEncoding=Encoding.UTF8};
        using(var p=Process.Start(info)){
            var output=p.StandardOutput.ReadToEndAsync();
            if(!p.WaitForExit(6000)){p.Kill();throw new IOException();}
            if(p.ExitCode!=0)throw new IOException();
            var dns=new JavaScriptSerializer().Deserialize<DnsEntry[]>(output.GetAwaiter().GetResult());
            var sockets=IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            var peers=new HashSet<IPAddress>(sockets.Where(t=>t.State==TcpState.Established && t.RemoteEndPoint.Port==443)
                .Select(t=>t.RemoteEndPoint.Address.MapToIPv6()));
            var hosts=new HashSet<string>(DomainLock.Names(),StringComparer.OrdinalIgnoreCase);
            var matches=new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(var rr in dns){
                string host=(rr.Name??"").TrimEnd('.');
                IPAddress ip;
                if(!IPAddress.TryParse(rr.Data,out ip) || IPAddress.IsLoopback(ip.IsIPv4MappedToIPv6?ip.MapToIPv4():ip) || !peers.Contains(ip.MapToIPv6()))continue;
                for(string suffix=host;suffix.Length>0;){
                    if(hosts.Contains(suffix)){matches.Add(host);break;}
                    int dot=suffix.IndexOf('.');if(dot<0)break;suffix=suffix.Substring(dot+1);
                }
            }
            return matches.ToArray();
        }
    }
    void Render(){
        var rows=new List<string[]>();
        foreach(var g in recent.Where(r=>r.Status=="active").GroupBy(r=>r.Domain))
            rows.Add(new[]{"Через Guard",g.Key+(g.Count()>1?" ×"+g.Count():""),"Сейчас"});
        foreach(string h in outside)rows.Add(new[]{"Возможный обход",h,"Сейчас"});
        foreach(var f in recent.Where(r=>r.Status!="active" && labels.ContainsKey(r.Status)))
            rows.Add(new[]{labels[f.Status],f.Domain,DateTimeOffset.FromUnixTimeSeconds(f.At).LocalDateTime.ToString("HH:mm:ss")});
        note.Text=(online?(recent.Any(f=>f.Status=="active")?"Активные туннели и последние попытки.":"Активных туннелей через Guard сейчас нет."):"Прокси отключён.")+" "+dnsState;
        string key=String.Join("\n",rows.Select(r=>String.Join("\t",r)));if(key==last)return;last=key;
        list.BeginUpdate();
        try{list.Items.Clear();foreach(var r in rows)list.Items.Add(new ListViewItem(r));}
        finally{list.EndUpdate();}
    }
}
