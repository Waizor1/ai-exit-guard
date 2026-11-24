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
        public bool ProxyOnly {get;set;}
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
    readonly Color surface=Color.FromArgb(32,33,36), card=Color.FromArgb(44,46,50), accent=Color.FromArgb(36,99,195);
    readonly Label routeReason=new Label {AutoSize=true,Dock=DockStyle.Fill};
    Button routeOptions;
    TableLayoutPanel optionalRoutes;
    int selectedRoute=-1;
    readonly Label proxyBadge=new Label{AutoSize=true};
    readonly Label verdict=new Label{AutoSize=true,Dock=DockStyle.Fill};
    TableLayoutPanel summary;
    Button ActionButton(string title, EventHandler click) {
        var button=new Button{Text=title,AutoSize=true,FlatStyle=FlatStyle.Flat,ForeColor=ink,BackColor=card,Padding=new Padding(8,3,8,3)};
        button.Cursor=Cursors.Hand;button.FlatAppearance.BorderSize=0;button.Click+=click;return button;
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
        fields.Controls.Add(Copy("Адрес прокси",false),0,0);fields.Controls.Add(Copy("IP · авто",false),1,0);
        urls[i]=new TextBox{AccessibleName=names[i]+" — прокси",Dock=DockStyle.Fill,UseSystemPasswordChar=true};
        ips[i]=new TextBox{AccessibleName=names[i]+" — выходной IP",Dock=DockStyle.Fill};
        fields.Controls.Add(urls[i],0,1);fields.Controls.Add(ips[i],1,1);
        grid.Controls.Add(fields);
    }
    void ShowIdle(string message) {
        foreach(var label in outcomes){label.Text=message;label.ForeColor=muted;label.AccessibleDescription="";detail.SetToolTip(label,"");}UpdateReason();
    }
    readonly CheckBox proxyOnly=new CheckBox{AutoSize=true,Text="Только прокси (килл-свитч выключен)"};
    readonly Button dns=new Button();
    readonly bool smokeMode;
    readonly string ownedDomains;
    bool routingSetup, checkingProxy, retrying;
    int retryDelay=1;
    DateTime retryAt, readySince;
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
    public GuardWindow(string dataDirectory,bool smoke) {
        smokeMode=smoke;
        ownedDomains=Path.Combine(dataDirectory,"managed-domains");
        proxyOnly.Checked=true;
        saved=Path.Combine(dataDirectory,"routes.bin");
        Text="AI Exit Guard"; AutoScaleMode=AutoScaleMode.Font;Font=new Font("Segoe UI",10F);
        ClientSize=new Size(442,500);MinimumSize=new Size(370,410);BackColor=surface;ForeColor=ink;
        pages.Appearance=TabAppearance.FlatButtons;pages.SizeMode=TabSizeMode.Fixed;pages.ItemSize=new Size(0,1);pages.TabStop=false;
        Controls.Add(pages);
        var home=Page("Главная");var settings=Page("Настройки");
        var header=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=2};
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.Controls.Add(Copy("AI Exit Guard",true),0,0);
        header.Controls.Add(ActionButton("Настройки",(s,e)=>pages.SelectedIndex=1),1,0);home.Controls.Add(header);
        summary=Card();
        verdict.Font=new Font(Font.FontFamily,19,FontStyle.Bold);verdict.Margin=new Padding(2,7,2,3);summary.Controls.Add(verdict);
        status.Dock=DockStyle.Fill;status.Margin=new Padding(2,2,2,8);status.ForeColor=muted;summary.Controls.Add(status);home.Controls.Add(summary);
        var results=Card();results.ColumnCount=2;
        results.ColumnStyles[0].Width=45;results.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,55));
        for(int i=0;i<3;i++){
            int row=i;
            var name=ActionButton(names[i+1],(sender,e)=>SelectRoute(row));
            name.TextAlign=ContentAlignment.MiddleLeft;name.Dock=DockStyle.Fill;name.Font=new Font(Font,FontStyle.Bold);
            name.Margin=new Padding(0,3,3,3);results.Controls.Add(name,0,i);
            outcomes[i]=Copy("",false);outcomes[i].AccessibleName=names[i+1]+" — статус";
            outcomes[i].TextAlign=ContentAlignment.MiddleRight;outcomes[i].Margin=new Padding(2,6,4,6);
            outcomes[i].Cursor=Cursors.Hand;outcomes[i].Click+=(sender,e)=>SelectRoute(row);
            results.Controls.Add(outcomes[i],1,i);
        }
        routeReason.ForeColor=muted;routeReason.Margin=new Padding(8,6,8,8);routeReason.Visible=false;
        results.Controls.Add(routeReason,0,3);results.SetColumnSpan(routeReason,2);
        home.Controls.Add(results);
        var proxyCard=Card();proxyCard.ColumnCount=2;proxyCard.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var edit=ActionButton("Прокси", (sender,e)=>pages.SelectedIndex=1);edit.TextAlign=ContentAlignment.MiddleLeft;
        proxyCard.Controls.Add(edit,0,0);proxyBadge.ForeColor=muted;proxyBadge.Anchor=AnchorStyles.Right;
        proxyCard.Controls.Add(proxyBadge,1,0);home.Controls.Add(proxyCard);
        start.Text="Подключить прокси";start.AutoSize=true;start.Padding=new Padding(12,4,12,4);start.Margin=new Padding(0,8,0,4);
        start.BackColor=accent;start.ForeColor=Color.White;start.FlatStyle=FlatStyle.Flat;start.FlatAppearance.BorderSize=0;
        start.Click+=(s,e)=>{if(relay!=null || retrying) Disconnect();else if(String.IsNullOrWhiteSpace(urls[0].Text)){pages.SelectedIndex=1;urls[0].Focus();}else Connect();};home.Controls.Add(start);
        settings.Controls.Add(ActionButton("←  Назад",(s,e)=>pages.SelectedIndex=0));
        settings.Controls.Add(Copy("Общий прокси",true));ProxyInputs(settings,0);settings.Controls.Add(proxyOnly);
        settings.Controls.Add(ActionButton("Подключить",(s,e)=>{if(relay==null)Connect();if(relay!=null || checkingProxy)pages.SelectedIndex=0;else MessageBox.Show(status.Text,Text);}));
        routeOptions=ActionButton("Отдельные прокси  ▸",(sender,e)=>ShowRouteOptions(!optionalRoutes.Visible));
        settings.Controls.Add(routeOptions);
        optionalRoutes=Card();settings.Controls.Add(optionalRoutes);
        for(int i=1;i<4;i++){optionalRoutes.Controls.Add(Copy(names[i],true));ProxyInputs(optionalRoutes,i);}
        optionalRoutes.Controls.Add(allowMismatch);optionalRoutes.Visible=false;
        dns.Text="Убрать прежнее правило доменов";dns.AutoSize=true;
        dns.Visible=!smoke && DomainRulesPresent() && !File.Exists(ownedDomains);
        dns.Click+=(sender,e)=>{try{SetDomains(false);dns.Visible=false;}catch{State("Windows не сняла правило доменов.",false);}};
        settings.Controls.Add(dns);
        ShowIdle("Выключен");
        tray.Icon=SystemIcons.Shield;tray.Visible=true; tray.MouseClick+=(s,e)=>{if(e.Button==MouseButtons.Left)ShowWindow();};
        var menu=new ContextMenuStrip();menu.Items.Add("Открыть",null,(s,e)=>ShowWindow());
        menu.Items.Add("Выход",null,(s,e)=>{quitting=true;Close();});tray.ContextMenuStrip=menu;
        FormClosing+=(s,e)=>{if(!quitting && e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();return;}
            if(proxyOnly.Checked && !ReleaseDomains()){quitting=false;e.Cancel=true;ShowWindow();}};
        FormClosed+=(s,e)=>{timer.Stop();Stop();tray.Dispose();detail.Dispose();};
        timer.Interval=350;timer.Tick+=(s,e)=>Poll();timer.Start();
        State("Откройте настройки, чтобы подключить прокси.",false);
        if(File.Exists(saved)) {
            try {
                byte[] bytes=ProtectedData.Unprotect(File.ReadAllBytes(saved),null,DataProtectionScope.CurrentUser);
                var r=json.Deserialize<Route[]>(Encoding.UTF8.GetString(bytes));
                if(r.Length!=4)throw new InvalidDataException();
                for(int i=0;i<4;i++){urls[i].Text=r[i].Address;ips[i].Text=r[i].IP;}
                allowMismatch.Checked=r[0].AllowGoogleCountryMismatch;proxyOnly.Checked=r[0].ProxyOnly;
                if(!File.Exists(Path.Combine(dataDirectory,"paused")))Shown+=(s,e)=>Connect();
            }catch{State("Не удалось прочитать сохранённые прокси.",false);}
        }
    }
    void ShowRouteOptions(bool show){
        optionalRoutes.Visible=show;routeOptions.Text=show?"Отдельные прокси  ▾":"Отдельные прокси  ▸";
        pages.SelectedTab.PerformLayout();
    }
    void SelectRoute(int i){
        selectedRoute=selectedRoute==i?-1:i;
        UpdateReason();
    }
    void UpdateReason(){
        routeReason.Visible=selectedRoute>=0;
        if(selectedRoute<0)return;
        string why=outcomes[selectedRoute].AccessibleDescription;
        if(String.IsNullOrEmpty(why))why=outcomes[selectedRoute].Text;
        routeReason.Text=names[selectedRoute+1]+" · "+why;
    }
    void ShowWindow(){Show();WindowState=FormWindowState.Normal;Activate();}
    void State(string text,bool open){
        status.Text=text;proxyBadge.Text=relay==null?"Выключен":relayReady?"Подключён":"Подключаем…";
        verdict.Text=open?"Можно работать":relay==null?"Прокси отключён":leases==null?"Проверяем подключение":"Доступ ограничен";
        bool closed=relay!=null && leases!=null && text=="Доступно сервисов: 0 из 3";
        if(closed)verdict.Text="Доступ закрыт";
        verdict.ForeColor=open?Color.LightGreen:closed?Color.LightSalmon:Color.FromArgb(255,195,111);
        summary.BackColor=relay==null?card:open?Color.FromArgb(35,54,46):closed?Color.FromArgb(66,42,44):Color.FromArgb(60,53,42);
        if(relay==null)verdict.ForeColor=ink;
        bool routing=proxyOnly.Checked && relayReady;
        if(routing){verdict.Text="Прокси настроен";verdict.ForeColor=ink;summary.BackColor=card;proxyBadge.Text="Готов";}
        tray.Text="Guard · "+verdict.Text;tray.Icon=routing?SystemIcons.Shield:open?SystemIcons.Information:closed?SystemIcons.Error:SystemIcons.Warning;
    }
    object Endpoint(string text) {
        Uri u;
        if(!text.Contains("://"))text="http://"+text;
        if(!Uri.TryCreate(text,UriKind.Absolute,out u) || (u.Scheme!="http" && u.Scheme!="https" && u.Scheme!="socks5") || u.Port<1 || u.AbsolutePath.Trim('/').Length>0 || u.Query!="" || u.Fragment!="") throw new FormatException();
        string[] auth=u.UserInfo.Split(new[]{':'},2);
        return new {Scheme=u.Scheme, Host=u.DnsSafeHost, Port=u.Port, User=Uri.UnescapeDataString(auth[0]),Password=auth.Length>1?Uri.UnescapeDataString(auth[1]):""};
    }
    async Task<string> MeasureExit(object endpoint,int index){
        var request=json.Deserialize<Dictionary<string,object>>(json.Serialize(endpoint));
        if(index>0)request["CheckService"]=names[index];
        var info=new ProcessStartInfo(Path.Combine(dir,"guard-core.exe"),"proxy-check"){
            UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,
            StandardOutputEncoding=Encoding.UTF8};
        using(var p=Process.Start(info)){
            p.StandardInput.WriteLine(json.Serialize(request));p.StandardInput.Close();
            string value=(await p.StandardOutput.ReadToEndAsync()).Trim();
            p.WaitForExit();
            System.Net.IPAddress ip;
            if(p.ExitCode!=0 || !System.Net.IPAddress.TryParse(value,out ip))throw new IOException();
            return ip.ToString();
        }
    }
    async void Connect() {
        if(checkingProxy || relay!=null)return;
        checkingProxy=true;Inputs(false);start.Enabled=false;
        try {
            var profiles=new Dictionary<string,object>();var routes=new List<Route>();object common=null;
            for(int i=0;i<4;i++) {
                string url=urls[i].Text.Trim(), ip=ips[i].Text.Trim();
                var route=new Route{Address=url,IP=ip,ProxyOnly=i==0 && proxyOnly.Checked,AllowGoogleCountryMismatch=i==0 && allowMismatch.Checked};
                routes.Add(route);
                if(url=="" && ip=="" && i>0)continue;
                System.Net.IPAddress parsed;
                if(url=="" || (ip!="" && (!System.Net.IPAddress.TryParse(ip,out parsed) || parsed.ToString()!=ip)))throw new FormatException();
                var endpoint=Endpoint(url);
                if(ip==""){
                    State("Проверяем выход через прокси…",false);
                    try{ip=await MeasureExit(endpoint,i);}catch{
                        if(!IsDisposed)State("Прокси не подтвердил выход. Проверьте адрес и пароль.",false);
                        return;
                    }
                    if(IsDisposed || Disposing)return;
                    route.IP=ip;ips[i].Text=ip;
                }
                if(i==0)common=endpoint;else profiles[names[i]]=new {Endpoint=endpoint,Expected=ip};
            }
            var cfg=new {Common=common,Expected=routes[0].IP,Profiles=profiles,DetailedStatus=true,ProxyOnly=proxyOnly.Checked,AllowGoogleCountryMismatch=allowMismatch.Checked};
            var psi=new ProcessStartInfo(Path.Combine(dir,"guard-core.exe"),"desktop-relay"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,StandardOutputEncoding=Encoding.UTF8};
            relay=Process.Start(psi); relay.StandardInput.WriteLine(json.Serialize(cfg));relay.StandardInput.Flush();
            next=relay.StandardOutput.ReadLineAsync();leases=null;
            Directory.CreateDirectory(Path.GetDirectoryName(saved));
            byte[] data=ProtectedData.Protect(Encoding.UTF8.GetBytes(json.Serialize(routes)),null,DataProtectionScope.CurrentUser);
            string temp=Path.Combine(Path.GetDirectoryName(saved),Guid.NewGuid().ToString()+".tmp");
            try{File.WriteAllBytes(temp,data);if(File.Exists(saved))File.Replace(temp,saved,null);else File.Move(temp,saved);}
            finally{if(File.Exists(temp))File.Delete(temp);}
            ShowIdle("Подключаем…");Inputs(false);start.Text="Отключить прокси";State(proxyOnly.Checked?"Запускаем прокси…":"Проверяем адреса перед подключением.",false);
        }catch(FormatException){State("Введите прокси и его фактический выходной IP.",false);}
         catch{Stop();State("Не удалось запустить Guard или сохранить настройки.",false);}
        finally{
            checkingProxy=false;
            if(!IsDisposed && !Disposing){start.Enabled=true;Inputs(relay==null);}
        }
    }
    void Inputs(bool enabled){proxyOnly.Enabled=enabled;allowMismatch.Enabled=enabled;foreach(var t in urls)t.Enabled=enabled;foreach(var t in ips)t.Enabled=enabled;}
    bool DomainRulesPresent(){
        try{return DomainLock.Enabled();}catch{return false;}
    }
    void SetDomains(bool on,bool migrate=false){
        using(var child=Process.Start(new ProcessStartInfo(Application.ExecutablePath,migrate?"--connect-routes":on?"--domains-on":"--domains-off"){UseShellExecute=true,Verb="runas"})){
            child.WaitForExit();
            if(child.ExitCode!=0 || DomainLock.Enabled()!=on)throw new IOException();
        }
    }
    void AcquireDomains(){
        if(smokeMode)return;
        if(DomainLock.Enabled()){
            if(!File.Exists(ownedDomains) && ClientLock.LegacyNames().Count>0)SetDomains(true,true);
            return;
        }
        // Record ownership before UAC so a crash after applying the rule is recoverable.
        File.WriteAllText(ownedDomains,"1");
        try{SetDomains(true,true);}
        catch{if(!DomainLock.Enabled())File.Delete(ownedDomains);throw;}
    }
    bool ReleaseDomains(){
        if(smokeMode || !File.Exists(ownedDomains))return true;
        try{
            if(DomainLock.Enabled())SetDomains(false);
            File.Delete(ownedDomains);return true;
        }catch{State("Windows не сняла маршрут. Прокси продолжает работать.",false);return false;}
    }
    void Disconnect(){
        if(!ReleaseDomains())return;
        retrying=false;retryDelay=1;Stop();
        // Keep the saved credentials, but respect a manual disconnect after restart.
        try{File.WriteAllText(Path.Combine(Path.GetDirectoryName(saved),"paused"),"1");}
        catch{State("Прокси отключён. Не удалось сохранить выбор для следующего запуска.",false);}
    }
    void Stop(){
        if(relay!=null){
            try{relay.StandardInput.Close();if(!relay.WaitForExit(1200))relay.Kill();}catch(InvalidOperationException){}
            relay.Dispose();relay=null;
        }
        relayReady=false;next=null;leases=null;ShowIdle("Выключен");Inputs(true);start.Text="Подключить";State("Откройте настройки, чтобы подключить прокси.",false);
    }
    void RelayEnded(){
        bool recover=relayReady || retrying;
        if(relayReady && (DateTime.UtcNow-readySince).TotalSeconds>90)retryDelay=1;
        Stop();
        if(!recover){State("Прокси не запустился. Проверьте, свободен ли его порт.",false);return;}
        retrying=true;retryAt=DateTime.UtcNow.AddSeconds(retryDelay);
        State("Повторим подключение через "+retryDelay+" с.",false);
        retryDelay=Math.Min(60,retryDelay*2);
        Inputs(false);start.Text="Отключить прокси";
    }
    void Poll(){
        if(routingSetup || checkingProxy)return;
        if(relay==null){
            if(retrying && DateTime.UtcNow>=retryAt){
                retryAt=DateTime.UtcNow.AddSeconds(retryDelay);Connect();
            }
            return;
        }
        try{
            if(relay.HasExited){RelayEnded();return;}
            if(next!=null && next.IsCompleted){
                string line=next.Result;if(line==null){RelayEnded();return;}
                next=relay.StandardOutput.ReadLineAsync();
                if(line=="READY"){
                    routingSetup=true;
                    try{
                        AcquireDomains();
                        File.Delete(Path.Combine(Path.GetDirectoryName(saved),"paused"));
                    }catch{
                        retrying=false;Stop();State("Windows не применила маршрут. При подключении разрешите изменение адресов ИИ.",false);return;
                    }finally{routingSetup=false;}
                    retrying=false;readySince=DateTime.UtcNow;relayReady=true;proxyBadge.Text="Готов";
                    if(proxyOnly.Checked){
                        State("Автоматическая блокировка выключена.",false);
                        for(int i=0;i<outcomes.Length;i++)outcomes[i].Text=String.IsNullOrWhiteSpace(urls[i+1].Text)?"Общий прокси":"Свой прокси";
                    }else ShowIdle("Проверяем…");
                    return;
                }
                leases=json.Deserialize<Dictionary<string,Reading>>(line);
            }
            if(leases!=null) RenderReadings((long)(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalSeconds);
        }catch{RelayEnded();}
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
        UpdateReason();
        if(status.Text!=current)State(current,open==3);
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
        proxyOnly.Checked=false;
        string original="127.0.0.1 localhost\r\n";string on=DomainLock.Edit(original,true);
        if(DomainLock.Edit(on,false)!=original || DomainLock.Edit(on,true)!=on || !on.Contains("127.0.0.2 daily-cloudcode-pa.googleapis.com"))return 18;
        if(!Visible || !IsHandleCreated || !tray.Visible || urls.Length!=4 || ips.Length!=4)return 11;
        var initialSize=ClientSize;
        foreach(int width in new[]{650,460}){
            ClientSize=new Size(width,570);PerformLayout();pages.SelectedIndex=0;pages.SelectedTab.PerformLayout();
            foreach(var control in new Control[]{verdict,status,proxyBadge,start,outcomes[0],outcomes[1],outcomes[2]}){
                var rect=pages.SelectedTab.RectangleToClient(control.RectangleToScreen(control.ClientRectangle));
                if(rect.Width<=0 || rect.Left<0 || rect.Right>pages.SelectedTab.ClientSize.Width || rect.Bottom>pages.SelectedTab.ClientSize.Height)return 21;
            }
        }
        ClientSize=initialSize;
        pages.SelectedIndex=1;ShowRouteOptions(true);
        for(int i=0;i<4;i++){
            pages.Update();
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
        pages.SelectedIndex=1;ShowRouteOptions(false);pages.SelectedTab.PerformLayout();SaveSmokeImage("03-settings.png");
        pages.SelectedIndex=0;
        start.PerformClick();if(relay!=null || !urls[0].Enabled)return 16;
        return 0;
    }
    [STAThread] static int Main(string[] args){
        if(args.Length==1 && args[0]=="--remove-legacy-rules"){
            try{ClientLock.RemoveLegacy();return 0;}catch{return 1;}
        }
        if(args.Length==1 && (args[0]=="--domains-on" || args[0]=="--domains-off" || args[0]=="--connect-routes")){
            try{
                if(args[0]=="--connect-routes")ClientLock.RemoveLegacy();
                DomainLock.Apply(args[0]!="--domains-off");return 0;
            }catch(Exception ex){if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true")MessageBox.Show(ex.Message,"Защита доменов");return 1;}
        }
        bool smoke=args.Length==1 && args[0]=="--smoke-test";
        string data=smoke?Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString()):Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"AI Exit Guard");
        int result=smoke?10:0;
        Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
        using(var form=new GuardWindow(data,smoke)){
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
