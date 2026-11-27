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
        list.OwnerDraw=true;
        list.DrawColumnHeader+=(sender,e)=>{
            using(var brush=new SolidBrush(Color.FromArgb(66,65,65)))e.Graphics.FillRectangle(brush,e.Bounds);
            TextRenderer.DrawText(e.Graphics,e.Header.Text,list.Font,Rectangle.Inflate(e.Bounds,-4,0),ink,TextFormatFlags.Left|TextFormatFlags.VerticalCenter);
        };
        list.DrawItem+=(sender,e)=>{if(list.View!=View.Details)e.DrawDefault=true;};
        list.DrawSubItem+=(sender,e)=>{
            Color text=ink;
            if(e.ColumnIndex==0){
                switch(e.SubItem.Text){
                    case "Через Guard":text=Color.LightGreen;break;
                    case "Ошибка прокси":case "Заблокировано":text=Color.LightSalmon;break;
                    case "Возможный обход":text=Color.FromArgb(255,195,111);break;
                }
            }
            if(e.Item.Selected)text=SystemColors.HighlightText;
            using(var brush=new SolidBrush(e.Item.Selected?SystemColors.Highlight:surface))e.Graphics.FillRectangle(brush,e.Bounds);
            TextRenderer.DrawText(e.Graphics,e.SubItem.Text,list.Font,Rectangle.Inflate(e.Bounds,-3,0),text,TextFormatFlags.Left|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
        };
        list.Columns.Add("Состояние",128);list.Columns.Add("Адрес",175);list.Columns.Add("Время",62);
        Action fitColumns=()=>{
            int stateWidth=TextRenderer.MeasureText("Возможный обход  ",list.Font).Width;
            int timeWidth=TextRenderer.MeasureText("00:00:00  ",list.Font).Width;
            list.Columns[0].Width=stateWidth;
            list.Columns[2].Width=timeWidth;
            list.Columns[1].Width=Math.Max(60,list.ClientSize.Width-stateWidth-timeWidth-SystemInformation.VerticalScrollBarWidth);
        };
        list.Resize+=(s,e)=>fitColumns();list.FontChanged+=(s,e)=>fitColumns();
        panel.Controls.Add(note);panel.Controls.Add(list);Render();
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
    internal static string[] FindOutside(){
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
            return MatchOutside(dns,peers);
        }
    }
    internal static bool CheckMatching(){
        var dns=new[]{new DnsEntry{Name="api.openai.com",Data="192.0.2.9"},new DnsEntry{Name="notopenai.com",Data="192.0.2.9"},new DnsEntry{Name="claude.ai",Data="127.0.0.2"}};
        var peers=new HashSet<IPAddress>(new[]{IPAddress.Parse("192.0.2.9").MapToIPv6(),IPAddress.Parse("127.0.0.2").MapToIPv6()});
        return MatchOutside(dns,peers).SequenceEqual(new[]{"api.openai.com"});
    }
    static string[] MatchOutside(DnsEntry[] dns,HashSet<IPAddress> peers){
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
    public string NoteText { get { return note.Text; } }
    public List<Dictionary<string,string>> SnapshotRows(){
        var result=new List<Dictionary<string,string>>();
        foreach(ListViewItem item in list.Items){
            string st=item.SubItems.Count>0?item.SubItems[0].Text:"";
            string dom=item.SubItems.Count>1?item.SubItems[1].Text:"";
            string tm=item.SubItems.Count>2?item.SubItems[2].Text:"";
            string tone="muted";
            if(st=="Через Guard")tone="ok";
            else if(st=="Ошибка прокси" || st=="Заблокировано")tone="bad";
            else if(st=="Возможный обход")tone="warn";
            result.Add(new Dictionary<string,string>{{"state",st},{"domain",dom},{"time",tm},{"tone",tone}});
        }
        return result;
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
