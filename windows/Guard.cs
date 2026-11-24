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
        public bool AllowGoogleCountryMismatch {get; set;}
    }
    readonly string[] names = {"Общий", "Claude", "ChatGPT", "Antigravity"};
    readonly TextBox[] urls = new TextBox[4], ips = new TextBox[4];
    readonly Label status = new Label { AutoSize=true };
    readonly Label[] outcomes = new Label[3];
    readonly CheckBox allowMismatch = new CheckBox { Dock=DockStyle.Fill,AutoSize=true, Text="Разрешить разные страны Google и IPinfo для Antigravity" };
    sealed class Reading {
        public long Until {get;set;}
        public string Reason {get;set;}
    }
    readonly Color ink=Color.FromArgb(31,44,56), muted=Color.FromArgb(77,93,104);
    readonly TabControl pages=new TabControl { Dock=DockStyle.Fill };
    TableLayoutPanel Page(string title) {
        var tab=new TabPage(title){BackColor=Color.White,AutoScroll=true};
        var grid=new TableLayoutPanel {AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Dock=DockStyle.Top,ColumnCount=1,Padding=new Padding(18,10,18,18)};
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        tab.Controls.Add(grid);pages.TabPages.Add(tab);
        return grid;
    }
    Label Copy(string text,bool heading) {
        return new Label {Text=text,AutoSize=true,Dock=DockStyle.Fill,ForeColor=heading?ink:muted,
            Font=heading?new Font(Font,FontStyle.Bold):Font,Margin=new Padding(2,heading?12:4,2,4)};
    }
    void ProxyInputs(TableLayoutPanel grid,int i) {
        var fields=new TableLayoutPanel {AutoSize=true,Dock=DockStyle.Fill,ColumnCount=2};
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,62));fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,38));
        fields.Controls.Add(Copy("Адрес прокси",false),0,0);fields.Controls.Add(Copy("Закреплённый IP",false),1,0);
        urls[i]=new TextBox{AccessibleName=names[i]+" — прокси",Dock=DockStyle.Fill,UseSystemPasswordChar=true};
        ips[i]=new TextBox{AccessibleName=names[i]+" — выходной IP",Dock=DockStyle.Fill};
        fields.Controls.Add(urls[i],0,1);fields.Controls.Add(ips[i],1,1);
        grid.Controls.Add(fields);
    }
    void ShowIdle(string message) {
        foreach(var label in outcomes){label.Text=message;label.ForeColor=muted;}
    }
    readonly Button dns=new Button();
    readonly Button start = new Button();
    readonly NotifyIcon tray = new NotifyIcon();
    readonly Timer timer = new Timer();
    readonly JavaScriptSerializer json = new JavaScriptSerializer();
    readonly string saved;
    readonly string dir = AppDomain.CurrentDomain.BaseDirectory;
    Process relay;
    Task<string> next;
    bool quitting;
    Dictionary<string,Reading> leases;
    public GuardWindow(string dataDirectory) {
        saved=Path.Combine(dataDirectory,"routes.bin");
        Text="AI Exit Guard"; AutoScaleMode=AutoScaleMode.Font;Font=SystemFonts.MessageBoxFont;
        ClientSize=new Size(650,520);MinimumSize=new Size(430,360);
        Controls.Add(pages);
        var home=Page("Главная");var settings=Page("Настройки");
        var title=Copy("Доступ через Guard",true);title.Font=new Font(Font.FontFamily,16,FontStyle.Bold);home.Controls.Add(title);
        status.Dock=DockStyle.Fill;status.ForeColor=muted;status.Margin=new Padding(2,0,2,12);home.Controls.Add(status);
        var results=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=2,BackColor=Color.FromArgb(242,246,247),Padding=new Padding(8)};
        results.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));results.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        for(int i=0;i<3;i++){
            var name=Copy(names[i+1],true);name.Margin=new Padding(4,6,18,6);results.Controls.Add(name,0,i);
            outcomes[i]=Copy("",false);outcomes[i].AccessibleName=names[i+1]+" — статус";outcomes[i].Margin=new Padding(2,6,2,6);
            results.Controls.Add(outcomes[i],1,i);
        }
        home.Controls.Add(results);home.Controls.Add(Copy("Общий прокси",true));
        home.Controls.Add(Copy("Вставьте адрес от провайдера и IP, через который должны выходить сервисы.",false));ProxyInputs(home,0);
        start.Text="Подключить";start.AutoSize=true;start.Padding=new Padding(14,4,14,4);start.Margin=new Padding(2,10,2,4);
        start.BackColor=Color.FromArgb(19,92,102);start.ForeColor=Color.White;start.FlatStyle=FlatStyle.Flat;
        start.Click+=(s,e)=>{if(relay==null) Connect();else Stop();};home.Controls.Add(start);
        settings.Controls.Add(Copy("Отдельные прокси",true));settings.Controls.Add(Copy("Оставьте поля пустыми, чтобы использовать общий прокси.",false));
        for(int i=1;i<4;i++){settings.Controls.Add(Copy(names[i],true));ProxyInputs(settings,i);}
        settings.Controls.Add(allowMismatch);
        settings.Controls.Add(Copy("Обе страны должны поддерживаться. Проверки IP и риска обязательны. Чтобы изменить прокси или это правило, отключите Guard на главной.",false));
        settings.Controls.Add(Copy("Системная защита",true));
        var filter=new Button{Text="Системные правила…",AutoSize=true};
        filter.Click+=(s,e)=>SystemRules();settings.Controls.Add(filter);
        dns.AutoSize=true;dns.AccessibleName="Защита известных доменов через системный DNS";
        Action refresh=()=>{try{dns.Text=DomainLock.Enabled()?"Отключить защиту доменов":"Включить защиту доменов";}catch{dns.Text="Проверьте файл hosts";dns.Enabled=false;}};
        dns.Click+=(s,e)=>{try{
            string arg=DomainLock.Enabled()?"--domains-off":"--domains-on";
            using(var helper=Process.Start(new ProcessStartInfo(Application.ExecutablePath,arg){UseShellExecute=true,Verb="runas"})){helper.WaitForExit();}
            refresh();
        }catch{State("Защита доменов не изменена.",false);}};
        settings.Controls.Add(dns);refresh();
        var strict=new Button{Text="Строгий режим для клиента…"};strict.AutoSize=true;settings.Controls.Add(strict);
        strict.Click+=(s,e)=>{
            using(var picker=new OpenFileDialog{Title="Выберите Codex, Claude или Antigravity",Filter="Приложения (*.exe)|*.exe"}){
                if(picker.ShowDialog()!=DialogResult.OK)return;
                try {
                    string target=picker.FileName;bool active=ClientLock.Active(target);
                    string detail=active?"Снять запрет прямого выхода для этого файла?":"Закрыть этому файлу прямой интернет? Для работы задайте HTTP-прокси 127.0.0.1:39178. Правила действуют, пока включён брандмауэр Windows.";
                    if(MessageBox.Show(detail,target,MessageBoxButtons.OKCancel)!=DialogResult.OK)return;
                    var selected=new ProcessStartInfo(Application.ExecutablePath,(active?"--client-off ":"--client-on ")+Convert.ToBase64String(Encoding.UTF8.GetBytes(target))){UseShellExecute=true,Verb="runas"};
                    using(var helper=Process.Start(selected)){helper.WaitForExit();if(helper.ExitCode==0)MessageBox.Show(active?"Запрет снят.":"Запрет прямого выхода установлен.");}
                }catch(Exception ex){MessageBox.Show(ex.Message,"Строгий режим");}
            }
        };
        ShowIdle("Выключен");
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
                allowMismatch.Checked=r[0].AllowGoogleCountryMismatch;
                Shown+=(s,e)=>Connect();
            }catch{State("Не удалось прочитать сохранённые прокси.",false);}
        }
    }
    void ShowWindow(){Show();WindowState=FormWindowState.Normal;Activate();}
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
                routes.Add(new Route{Address=url,IP=ip,AllowGoogleCountryMismatch=i==0 && allowMismatch.Checked});
                if(url=="" && ip=="" && i>0)continue;
                System.Net.IPAddress parsed;
                if(url=="" || !System.Net.IPAddress.TryParse(ip,out parsed) || parsed.ToString()!=ip)throw new FormatException();
                var endpoint=Endpoint(url);if(i==0)common=endpoint;else profiles[names[i]]=new {Endpoint=endpoint,Expected=ip};
            }
            var cfg=new {Common=common,Expected=routes[0].IP,Profiles=profiles,DetailedStatus=true,AllowGoogleCountryMismatch=allowMismatch.Checked};
            var psi=new ProcessStartInfo(Path.Combine(dir,"guard-core.exe"),"desktop-relay"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,StandardOutputEncoding=Encoding.UTF8};
            relay=Process.Start(psi); relay.StandardInput.WriteLine(json.Serialize(cfg));relay.StandardInput.Flush();
            next=relay.StandardOutput.ReadLineAsync();leases=null;
            Directory.CreateDirectory(Path.GetDirectoryName(saved));
            byte[] data=ProtectedData.Protect(Encoding.UTF8.GetBytes(json.Serialize(routes)),null,DataProtectionScope.CurrentUser);
            string temp=Path.Combine(Path.GetDirectoryName(saved),Guid.NewGuid().ToString()+".tmp");
            try{File.WriteAllBytes(temp,data);if(File.Exists(saved))File.Replace(temp,saved,null);else File.Move(temp,saved);}
            finally{if(File.Exists(temp))File.Delete(temp);}
            ShowIdle("Проверяем…");Inputs(false);start.Text="Отключить";State("Проверяем адреса. Доступ через Guard закрыт.",false);
        }catch(FormatException){State("Введите прокси и его фактический выходной IP.",false);}
         catch{Stop();State("Не удалось запустить Guard или сохранить настройки.",false);}
    }
    void Inputs(bool enabled){allowMismatch.Enabled=enabled;foreach(var t in urls)t.Enabled=enabled;foreach(var t in ips)t.Enabled=enabled;}
    void Stop(){
        if(relay!=null){
            try{relay.StandardInput.Close();if(!relay.WaitForExit(1200))relay.Kill();}catch(InvalidOperationException){}
            relay.Dispose();relay=null;
        }
        next=null;leases=null;ShowIdle("Выключен");Inputs(true);start.Text="Подключить";State("Прокси выключен",false);
    }
    void Poll(){
        if(relay==null)return;
        try{
            if(relay.HasExited){Stop();State("Прокси остановлен. Проверьте адрес и свободен ли порт 39178.",false);return;}
            if(next!=null && next.IsCompleted){
                string line=next.Result;if(line==null){Stop();return;}
                next=relay.StandardOutput.ReadLineAsync();
                if(line=="READY")return;
                leases=json.Deserialize<Dictionary<string,Reading>>(line);
            }
            if(leases!=null) RenderReadings((long)(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalSeconds);
        }catch{Stop();State("Связь с Guard потеряна.",false);}
    }
    void RenderReadings(long now){
        int open=0, waiting=0;
        for(int i=0;i<outcomes.Length;i++){
            Reading r;string caption;Color color;
            if(!leases.TryGetValue(names[i+1],out r)){caption="Проверяем…";color=muted;waiting++;}
            else if(r.Until>now){caption="Можно пользоваться";color=Color.DarkGreen;open++;}
            else{caption="Закрыт · "+(String.IsNullOrWhiteSpace(r.Reason)?"Ожидаем свежую проверку.":r.Reason);color=Color.Maroon;}
            if(outcomes[i].Text!=caption){outcomes[i].Text=caption;outcomes[i].ForeColor=color;}
        }
        string current=waiting>0?"Идёт проверка…":open==3?"Все три сервиса доступны":"Доступно сервисов: "+open+" из 3";
        if(status.Text!=current)State(current,open==3);
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
    int ExerciseForm(){
        string original="127.0.0.1 localhost\r\n";string on=DomainLock.Edit(original,true);
        if(DomainLock.Edit(on,false)!=original || DomainLock.Edit(on,true)!=on || !on.Contains("127.0.0.2 daily-cloudcode-pa.googleapis.com"))return 18;
        if(!Visible || !IsHandleCreated || !tray.Visible || urls.Length!=4 || ips.Length!=4)return 11;
        var initialSize=ClientSize;
        foreach(int width in new[]{650,460}){
            ClientSize=new Size(width,520);PerformLayout();pages.SelectedIndex=0;pages.SelectedTab.PerformLayout();
            foreach(var control in new Control[]{status,urls[0],ips[0],start,outcomes[0],outcomes[1],outcomes[2]}){
                var rect=pages.SelectedTab.RectangleToClient(control.RectangleToScreen(control.ClientRectangle));
                if(rect.Width<=0 || rect.Left<0 || rect.Right>pages.SelectedTab.ClientSize.Width || rect.Bottom>pages.SelectedTab.ClientSize.Height)return 21;
            }
        }
        ClientSize=initialSize;
        for(int i=0;i<4;i++){
            pages.SelectedIndex=i==0?0:1;pages.Update();
            if(!urls[i].Created || !ips[i].Created || ips[i].Width<60 || urls[i].Width<80)return 12;
        }
        pages.SelectedIndex=0;
        leases=json.Deserialize<Dictionary<string,Reading>>("{\"Antigravity\":{\"Until\":0,\"Reason\":\"Google: NL, IPinfo: DE\"},\"Claude\":{\"Until\":201}}");
        RenderReadings(200);
        if(!outcomes[2].Text.Contains("Google: NL, IPinfo: DE") || !outcomes[0].Text.Contains("Можно") || !outcomes[1].Text.Contains("Проверяем"))return 19;
        RenderReadings(201);if(!outcomes[0].Text.Contains("Закрыт"))return 20;
        allowMismatch.Checked=true;
        urls[0].Text="http://127.0.0.1:1";ips[0].Text="invalid";start.PerformClick();
        if(relay!=null || !status.Text.Contains("IP"))return 13;
        ips[0].Text="192.0.2.1"; start.PerformClick();
        if(relay==null || relay.HasExited || !File.Exists(saved) || urls[0].Enabled)return 14;
        byte[] plain=ProtectedData.Unprotect(File.ReadAllBytes(saved),null,DataProtectionScope.CurrentUser);
        if(!json.Deserialize<Route[]>(Encoding.UTF8.GetString(plain))[0].AllowGoogleCountryMismatch)return 15;
        start.PerformClick();if(relay!=null || !urls[0].Enabled)return 16;
        return 0;
    }
    [STAThread] static int Main(string[] args){
        if(args.Length==2 && (args[0]=="--client-on" || args[0]=="--client-off")){
            try{ClientLock.Apply(Encoding.UTF8.GetString(Convert.FromBase64String(args[1])),args[0]=="--client-on");return 0;}
            catch(Exception ex){if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")=="true")Console.Error.WriteLine(ex.GetType().Name+" "+ex.Message);else MessageBox.Show(ex.Message,"Брандмауэр Windows");return 1;}
        }
        if(args.Length==1 && (args[0]=="--domains-on" || args[0]=="--domains-off")){
            try{DomainLock.Apply(args[0]=="--domains-on");return 0;}catch(Exception ex){if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true")MessageBox.Show(ex.Message,"Защита доменов");return 1;}
        }
        bool smoke=args.Length==1 && args[0]=="--smoke-test";
        string data=smoke?Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString()):Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"AI Exit Guard");
        int result=smoke?10:0;
        Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
        using(var form=new GuardWindow(data)){
            if(smoke)form.Shown+=(s,e)=>form.BeginInvoke(new Action(()=>{
                try{result=form.ExerciseForm();}catch{result=17;}
                form.quitting=true;form.Close();
            }));
            Application.Run(form);
        }
        if(smoke && Directory.Exists(data))Directory.Delete(data,true);
        return result;
    }
}
