using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
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
    readonly Color ink=Color.FromArgb(246,245,244), muted=Color.FromArgb(198,196,194);
    readonly Color surface=Color.FromArgb(42,42,44), card=Color.FromArgb(56,56,59), accent=Color.FromArgb(46,121,221);
    readonly Label proxyBadge=new Label{AutoSize=true};
    readonly Label verdict=new Label{AutoSize=true,Dock=DockStyle.Fill};
    TableLayoutPanel summary;
    Button ActionButton(string title, EventHandler click) {
        var button=new Button{Text=title,AutoSize=true,FlatStyle=FlatStyle.Flat,ForeColor=ink,BackColor=card,Padding=new Padding(8,3,8,3)};
        button.FlatAppearance.BorderSize=0;button.Click+=click;return button;
    }
    sealed class RoundedCard : TableLayoutPanel {
        protected override void OnSizeChanged(EventArgs e) {
            base.OnSizeChanged(e);
            if(Width<20 || Height<20)return;
            using(var path=new GraphicsPath()){
                const int d=18;
                path.AddArc(0,0,d,d,180,90);path.AddArc(Width-d,0,d,d,270,90);
                path.AddArc(Width-d,Height-d,d,d,0,90);path.AddArc(0,Height-d,d,d,90,90);path.CloseFigure();
                Region old=Region;Region=new Region(path);if(old!=null)old.Dispose();
            }
        }
    }
    TableLayoutPanel Card() {
        var panel=new RoundedCard {AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Dock=DockStyle.Top,ColumnCount=1,BackColor=card,Padding=new Padding(12,8,12,8),Margin=new Padding(0,4,0,4)};
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));return panel;
    }
    readonly TabControl pages=new TabControl { Dock=DockStyle.Fill };
    TableLayoutPanel Page(string title) {
        var tab=new TabPage(title){ForeColor=ink,BackColor=surface,AutoScroll=true};
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
    readonly ToolTip detail=new ToolTip();
    readonly Timer timer = new Timer();
    readonly JavaScriptSerializer json = new JavaScriptSerializer();
    readonly string saved;
    readonly string dir = AppDomain.CurrentDomain.BaseDirectory;
    Process relay;
    Task<string> next;
    bool quitting, relayReady;
    Dictionary<string,Reading> leases;
    public GuardWindow(string dataDirectory) {
        saved=Path.Combine(dataDirectory,"routes.bin");
        Text="AI Exit Guard"; AutoScaleMode=AutoScaleMode.Font;Font=SystemFonts.MessageBoxFont;
        ClientSize=new Size(460,570);MinimumSize=new Size(390,400);BackColor=surface;ForeColor=ink;
        pages.Appearance=TabAppearance.FlatButtons;pages.SizeMode=TabSizeMode.Fixed;pages.ItemSize=new Size(0,1);pages.TabStop=false;
        Controls.Add(pages);
        var home=Page("Главная");var settings=Page("Настройки");
        var header=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=2};
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.Controls.Add(Copy("AI Exit Guard",true),0,0);
        header.Controls.Add(ActionButton("Настройки",(s,e)=>pages.SelectedIndex=1),1,0);home.Controls.Add(header);
        summary=Card();
        summary.Controls.Add(Copy("Доступ к ИИ",false));
        verdict.Font=new Font(Font.FontFamily,18,FontStyle.Bold);summary.Controls.Add(verdict);
        status.Dock=DockStyle.Fill;status.ForeColor=ink;summary.Controls.Add(status);home.Controls.Add(summary);
        var results=Card();results.ColumnCount=2;
        results.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,60));results.ColumnStyles[0].Width=40;
        for(int i=0;i<3;i++){
            var name=Copy(names[i+1],true);name.Margin=new Padding(2,8,8,8);results.Controls.Add(name,0,i);
            outcomes[i]=Copy("",false);outcomes[i].AccessibleName=names[i+1]+" — статус";outcomes[i].Margin=new Padding(2,8,2,8);
            results.Controls.Add(outcomes[i],1,i);
        }
        home.Controls.Add(results);
        var proxyCard=Card();proxyCard.ColumnCount=2;proxyCard.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        proxyCard.Controls.Add(Copy("Прокси",true),0,0);proxyBadge.ForeColor=muted;proxyBadge.Anchor=AnchorStyles.Left;
        proxyCard.Controls.Add(proxyBadge,1,0);home.Controls.Add(proxyCard);
        var protect=Card();protect.Controls.Add(Copy("Защита от обхода",true));protect.Controls.Add(dns);home.Controls.Add(protect);
        start.Text="Подключить прокси";start.AutoSize=true;start.Padding=new Padding(12,4,12,4);start.Margin=new Padding(0,8,0,4);
        start.BackColor=accent;start.ForeColor=Color.White;start.FlatStyle=FlatStyle.Flat;start.FlatAppearance.BorderSize=0;
        start.Click+=(s,e)=>{if(relay!=null) Stop();else if(String.IsNullOrWhiteSpace(urls[0].Text)){pages.SelectedIndex=1;urls[0].Focus();}else Connect();};home.Controls.Add(start);
        settings.Controls.Add(ActionButton("←  Назад",(s,e)=>pages.SelectedIndex=0));
        settings.Controls.Add(Copy("Общий прокси",true));ProxyInputs(settings,0);
        settings.Controls.Add(ActionButton("Подключить",(s,e)=>{if(relay==null)Connect();if(relay!=null)pages.SelectedIndex=0;else MessageBox.Show(status.Text,Text);}));
        settings.Controls.Add(Copy("Отдельные прокси",true));settings.Controls.Add(Copy("Оставьте поля пустыми, чтобы использовать общий прокси.",false));
        for(int i=1;i<4;i++){settings.Controls.Add(Copy(names[i],true));ProxyInputs(settings,i);}
        settings.Controls.Add(allowMismatch);
        settings.Controls.Add(Copy("Обе страны должны поддерживаться. Проверки IP и риска обязательны. Чтобы изменить прокси или это правило, отключите Guard на главной.",false));
        settings.Controls.Add(Copy("Системная защита",true));
        var filter=new Button{Text="Системные правила…",AutoSize=true};
        filter.Click+=(s,e)=>SystemRules();filter.FlatStyle=FlatStyle.Flat;filter.ForeColor=ink;settings.Controls.Add(filter);
        dns.AutoSize=true;dns.AccessibleName="Защита известных доменов через системный DNS";
        Action refresh=()=>{try{dns.Text=DomainLock.Enabled()?"Включена · отключить":"Выключена · включить";}catch{dns.Text="Проверьте файл hosts";dns.Enabled=false;}};
        dns.Click+=(s,e)=>{try{
            string arg=DomainLock.Enabled()?"--domains-off":"--domains-on";
            using(var helper=Process.Start(new ProcessStartInfo(Application.ExecutablePath,arg){UseShellExecute=true,Verb="runas"})){helper.WaitForExit();}
            refresh();
        }catch{State("Защита доменов не изменена.",false);}};
        dns.FlatStyle=FlatStyle.Flat;dns.ForeColor=ink;dns.BackColor=card;refresh();
        var strict=new Button{Text="Строгий режим для клиента…"};strict.AutoSize=true;strict.FlatStyle=FlatStyle.Flat;strict.ForeColor=ink;settings.Controls.Add(strict);
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
        tray.Icon=SystemIcons.Shield;tray.Visible=true; tray.MouseClick+=(s,e)=>{if(e.Button==MouseButtons.Left)ShowWindow();};
        var menu=new ContextMenuStrip();menu.Items.Add("Открыть",null,(s,e)=>ShowWindow());
        menu.Items.Add("Выход",null,(s,e)=>{quitting=true;Close();});tray.ContextMenuStrip=menu;
        FormClosing+=(s,e)=>{if(!quitting && e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();}};
        FormClosed+=(s,e)=>{timer.Stop();Stop();tray.Dispose();detail.Dispose();};
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
    void State(string text,bool open){
        status.Text=text;proxyBadge.Text=relay==null?"Выключен":relayReady?"Подключён":"Подключаем…";
        verdict.Text=open?"Можно работать":relay==null?"Прокси выключен":leases==null?"Проверяем адреса":"Есть замечания";
        bool closed=relay!=null && leases!=null && text=="Доступно сервисов: 0 из 3";
        if(closed)verdict.Text="Доступ закрыт";
        verdict.ForeColor=open?Color.LightGreen:closed?Color.LightSalmon:Color.FromArgb(255,195,111);
        summary.BackColor=open?Color.FromArgb(37,58,49):closed?Color.FromArgb(65,44,45):Color.FromArgb(62,54,46);
        tray.Text="Guard · "+verdict.Text;tray.Icon=open?SystemIcons.Information:closed?SystemIcons.Error:SystemIcons.Warning;
    }
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
        relayReady=false;next=null;leases=null;ShowIdle("Выключен");Inputs(true);start.Text="Подключить";State("Прокси выключен",false);
    }
    void Poll(){
        if(relay==null)return;
        try{
            if(relay.HasExited){Stop();State("Прокси остановлен. Проверьте адрес и свободен ли порт 39178.",false);return;}
            if(next!=null && next.IsCompleted){
                string line=next.Result;if(line==null){Stop();return;}
                next=relay.StandardOutput.ReadLineAsync();
                if(line=="READY"){relayReady=true;proxyBadge.Text="Подключён";return;}
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
            else if(r.Until>now){caption="Можно пользоваться";color=Color.LightGreen;open++;}
            else{caption="Закрыт";color=Color.LightSalmon;}
            if(outcomes[i].Text!=caption){outcomes[i].Text=caption;outcomes[i].ForeColor=color;}
        }
        for(int i=0;i<outcomes.Length;i++){
            Reading item;
            outcomes[i].AccessibleDescription=leases.TryGetValue(names[i+1],out item)?item.Reason:"";
            if(detail.GetToolTip(outcomes[i])!=outcomes[i].AccessibleDescription)detail.SetToolTip(outcomes[i],outcomes[i].AccessibleDescription);
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
    void SaveSmokeImage(string file){
        string folder=Environment.GetEnvironmentVariable("GUARD_UI_SCREENSHOTS");
        if(String.IsNullOrEmpty(folder))return;
        Directory.CreateDirectory(folder);PerformLayout();Update();
        using(var image=new Bitmap(pages.Width,pages.Height)){
            pages.DrawToBitmap(image,new Rectangle(Point.Empty,pages.Size));
            image.Save(Path.Combine(folder,file),System.Drawing.Imaging.ImageFormat.Png);
        }
    }
    int ExerciseForm(){
        string original="127.0.0.1 localhost\r\n";string on=DomainLock.Edit(original,true);
        if(DomainLock.Edit(on,false)!=original || DomainLock.Edit(on,true)!=on || !on.Contains("127.0.0.2 daily-cloudcode-pa.googleapis.com"))return 18;
        if(!Visible || !IsHandleCreated || !tray.Visible || urls.Length!=4 || ips.Length!=4)return 11;
        var initialSize=ClientSize;
        foreach(int width in new[]{650,460}){
            ClientSize=new Size(width,570);PerformLayout();pages.SelectedIndex=0;pages.SelectedTab.PerformLayout();
            foreach(var control in new Control[]{verdict,status,proxyBadge,dns,start,outcomes[0],outcomes[1],outcomes[2]}){
                var rect=pages.SelectedTab.RectangleToClient(control.RectangleToScreen(control.ClientRectangle));
                if(rect.Width<=0 || rect.Left<0 || rect.Right>pages.SelectedTab.ClientSize.Width || rect.Bottom>pages.SelectedTab.ClientSize.Height)return 21;
            }
        }
        ClientSize=initialSize;
        for(int i=0;i<4;i++){
            pages.SelectedIndex=1;pages.Update();
            if(!urls[i].Created || !ips[i].Created || ips[i].Width<60 || urls[i].Width<80)return 12;
        }
        pages.SelectedIndex=0;
        leases=json.Deserialize<Dictionary<string,Reading>>("{\"Antigravity\":{\"Until\":0,\"Reason\":\"Google: NL, IPinfo: DE\"},\"Claude\":{\"Until\":201}}");
        RenderReadings(200);
        if(!outcomes[2].AccessibleDescription.Contains("Google: NL, IPinfo: DE") || !outcomes[0].Text.Contains("Можно") || !outcomes[1].Text.Contains("Проверяем"))return 19;
        RenderReadings(201);if(!outcomes[0].Text.Contains("Закрыт"))return 20;
        allowMismatch.Checked=true;
        urls[0].Text="http://127.0.0.1:1";ips[0].Text="invalid";start.PerformClick();
        if(relay!=null || !status.Text.Contains("IP"))return 13;
        ips[0].Text="192.0.2.1"; start.PerformClick();
        if(relay==null || relay.HasExited || !File.Exists(saved) || urls[0].Enabled)return 14;
        byte[] plain=ProtectedData.Unprotect(File.ReadAllBytes(saved),null,DataProtectionScope.CurrentUser);
        if(!json.Deserialize<Route[]>(Encoding.UTF8.GetString(plain))[0].AllowGoogleCountryMismatch)return 15;
        relayReady=true;
        leases=new Dictionary<string,Reading>();
        for(int i=1;i<names.Length;i++)leases[names[i]]=new Reading{Until=201};
        RenderReadings(200);SaveSmokeImage("01-access-open.png");
        leases["Antigravity"]=new Reading{Until=0,Reason="Google не подтвердил страну выхода."};
        RenderReadings(200);SaveSmokeImage("02-one-service-closed.png");
        pages.SelectedIndex=1;pages.SelectedTab.PerformLayout();SaveSmokeImage("03-settings.png");
        pages.SelectedIndex=0;
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
