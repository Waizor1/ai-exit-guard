using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

sealed class GuardWindow : Form {
    sealed class Route {
        public string Address {get; set;}
        public string IP {get; set;}
    }
    readonly string[] names = {"Общий", "Claude", "ChatGPT", "Antigravity"};
    readonly TextBox[] urls = new TextBox[4], ips = new TextBox[4];
    readonly Label status = new Label();
    readonly Button start = new Button();
    readonly NotifyIcon tray = new NotifyIcon();
    readonly Timer timer = new Timer();
    readonly JavaScriptSerializer json = new JavaScriptSerializer();
    readonly string saved = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"AI Exit Guard","routes.bin");
    readonly string dir = AppDomain.CurrentDomain.BaseDirectory;
    Process relay;
    Task<string> next;
    bool quitting;
    DateTime lastReport;
    public GuardWindow() {
        Text="AI Exit Guard"; ClientSize=new Size(640,330); AutoScaleMode=AutoScaleMode.Font;
        Font=SystemFonts.MessageBoxFont; FormBorderStyle=FormBorderStyle.FixedDialog; MaximizeBox=false;
        AddLabel("Прокси для ИИ",16,14,480);
        AddLabel("Сервис",16,52,95); AddLabel("Прокси (http, https или socks5)",120,52,300); AddLabel("Ожидаемый выходной IP",436,52,195);
        for(int i=0;i<4;i++) {
            int y=82+33*i; AddLabel(names[i],16,y,97);
            urls[i]=new TextBox{AccessibleName=names[i]+" — прокси",Left=120,Top=y,Width=305,UseSystemPasswordChar=true};
            ips[i]=new TextBox{AccessibleName=names[i]+" — выходной IP",Left=436,Top=y,Width=181}; Controls.Add(urls[i]); Controls.Add(ips[i]);
        }
        AddLabel("Пустая строка сервиса использует общий прокси.",16,218,590);
        start.Text="Подключить"; start.SetBounds(16,247,132,31);
        start.Click+=(s,e)=>{if(relay==null) Connect();else Stop();};Controls.Add(start);
        var filter=new Button{Text="Системные правила…"};filter.SetBounds(161,247,180,31);
        filter.Click+=(s,e)=>SystemRules();Controls.Add(filter);
        status.SetBounds(16,292,610,32);Controls.Add(status);
        tray.Icon=SystemIcons.Shield;tray.Visible=true; tray.DoubleClick+=(s,e)=>ShowWindow();
        var menu=new ContextMenuStrip();menu.Items.Add("Открыть",null,(s,e)=>ShowWindow());
        menu.Items.Add("Выход",null,(s,e)=>{quitting=true;Close();});tray.ContextMenuStrip=menu;
        FormClosing+=(s,e)=>{if(!quitting && e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();}};
        FormClosed+=(s,e)=>{timer.Stop();Stop();tray.Dispose();};
        timer.Interval=350;timer.Tick+=(s,e)=>Poll();timer.Start();
        State("Прокси выключен",false);
        if(File.Exists(saved)) {
            try {
                byte[] bytes=ProtectedData.Unprotect(File.ReadAllBytes(saved),null,DataProtectionScope.CurrentUser);
                var r=json.Deserialize<Route[]>(Encoding.UTF8.GetString(bytes));
                if(r.Length!=4)throw new InvalidDataException();
                for(int i=0;i<4;i++){urls[i].Text=r[i].Address;ips[i].Text=r[i].IP;}
                Shown+=(s,e)=>Connect();
            }catch{State("Не удалось прочитать сохранённые прокси.",false);}
        }
    }
    void ShowWindow(){Show();WindowState=FormWindowState.Normal;Activate();}
    void AddLabel(string text,int x,int y,int w){Controls.Add(new Label{Text=text,Left=x,Top=y,Width=w,Height=25});}
    void State(string text,bool open){status.Text=text;tray.Text=open?"Guard: маршруты открыты":"Guard: проверьте статус";tray.Icon=open?SystemIcons.Information:SystemIcons.Warning;}
    object Endpoint(string text) {
        Uri u;
        if(!text.Contains("://"))text="http://"+text;
        if(!Uri.TryCreate(text,UriKind.Absolute,out u) || (u.Scheme!="http" && u.Scheme!="https" && u.Scheme!="socks5") || u.Port<1 || u.AbsolutePath.Trim('/').Length>0 || u.Query!="" || u.Fragment!="") throw new FormatException();
        string[] auth=u.UserInfo.Split(new[]{':'},2);
        return new {Scheme=u.Scheme, Host=u.DnsSafeHost, Port=u.Port, User=Uri.UnescapeDataString(auth[0]),Password=auth.Length>1?Uri.UnescapeDataString(auth[1]):""};
    }
    void Connect() {
        try {
            var profiles=new Dictionary<string,object>();var routes=new List<Route>();object common=null;
            for(int i=0;i<4;i++) {
                string url=urls[i].Text.Trim(), ip=ips[i].Text.Trim();
                routes.Add(new Route{Address=url,IP=ip});
                if(url=="" && ip=="" && i>0)continue;
                System.Net.IPAddress parsed;
                if(url=="" || !System.Net.IPAddress.TryParse(ip,out parsed) || parsed.ToString()!=ip)throw new FormatException();
                var endpoint=Endpoint(url);if(i==0)common=endpoint;else profiles[names[i]]=new {Endpoint=endpoint,Expected=ip};
            }
            var cfg=new {Common=common,Expected=routes[0].IP,Profiles=profiles};
            var psi=new ProcessStartInfo(Path.Combine(dir,"guard-core.exe"),"desktop-relay"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true};
            relay=Process.Start(psi); relay.StandardInput.WriteLine(json.Serialize(cfg));relay.StandardInput.Flush();
            next=relay.StandardOutput.ReadLineAsync();lastReport=DateTime.UtcNow;
            Directory.CreateDirectory(Path.GetDirectoryName(saved));
            byte[] data=ProtectedData.Protect(Encoding.UTF8.GetBytes(json.Serialize(routes)),null,DataProtectionScope.CurrentUser);
            string temp=Path.Combine(Path.GetDirectoryName(saved),Guid.NewGuid().ToString()+".tmp");
            try{File.WriteAllBytes(temp,data);if(File.Exists(saved))File.Replace(temp,saved,null);else File.Move(temp,saved);}
            finally{if(File.Exists(temp))File.Delete(temp);}
            Inputs(false);start.Text="Отключить";State("Проверяем адреса. Доступ через Guard закрыт.",false);
        }catch(FormatException){State("Введите прокси и его фактический выходной IP.",false);}
         catch{Stop();State("Не удалось запустить Guard или сохранить настройки.",false);}
    }
    void Inputs(bool enabled){foreach(var t in urls)t.Enabled=enabled;foreach(var t in ips)t.Enabled=enabled;}
    void Stop(){
        if(relay!=null){
            try{relay.StandardInput.Close();if(!relay.WaitForExit(1200))relay.Kill();}catch(InvalidOperationException){}
            relay.Dispose();relay=null;
        }
        next=null;Inputs(true);start.Text="Подключить";State("Прокси выключен",false);
    }
    void Poll(){
        if(relay==null)return;
        try{
            if(relay.HasExited){Stop();State("Прокси остановлен. Проверьте адрес и свободен ли порт 39178.",false);return;}
            if(next!=null && next.IsCompleted){
                string line=next.Result;if(line==null){Stop();return;}
                next=relay.StandardOutput.ReadLineAsync();
                if(line=="READY")return;
                var rows=json.Deserialize<Dictionary<string,bool>>(line);
                var labels=new List<string>();bool all=true;
                foreach(string n in new[]{"Claude","ChatGPT","Antigravity"}){bool ok=rows[n];all&=ok;labels.Add(n+(ok?" — открыт":" — закрыт"));}
                lastReport=DateTime.UtcNow;State(String.Join("   ",labels),all);
            }else if((DateTime.UtcNow-lastReport).TotalSeconds>180) State("Проверка устарела. Обновляем статус.",false);
        }catch{Stop();State("Связь с Guard потеряна.",false);}
    }
    void SystemRules(){
        try{
            string engine=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ProxyBridge","ProxyBridge_CLI.exe");
            if(!File.Exists(engine)){
                MessageBox.Show("Установите ProxyBridge для Windows, затем нажмите кнопку снова.","Системный фильтр");
                Process.Start("https://github.com/InterceptSuite/ProxyBridge/releases/tag/v4.3.0_Windows");return;
            }
            Process.Start(new ProcessStartInfo(engine,"--profile \""+Path.Combine(dir,"AI Exit Guard.pbprofile")+"\" --verbose 1"){UseShellExecute=true,Verb="runas",WorkingDirectory=Path.GetDirectoryName(engine)});
        }catch{MessageBox.Show("Системный фильтр не запущен. Проверьте разрешение администратора.");}
    }
    [STAThread] static void Main(){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.Run(new GuardWindow());}
}
