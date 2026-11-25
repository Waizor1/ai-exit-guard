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
    readonly TextBox[] urls = new TextBox[4];
    readonly ComboBox[] schemes = new ComboBox[4];
    readonly Button[] paste = new Button[4];
    readonly string[] pins = new string[4];
    readonly Label status = new Label { AutoSize=true };
    readonly Label[] outcomes = new Label[3];
    readonly CheckBox allowMismatch = new CheckBox { Dock=DockStyle.Fill,AutoSize=true, Text="Разрешить разные страны Google и IPinfo для Antigravity" };
    sealed class Reading {
        public long Until {get;set;}
        public string Reason {get;set;}
    }
    readonly Color ink=Color.FromArgb(246,245,244), muted=Color.FromArgb(198,196,194);
    readonly Color surface=Color.FromArgb(32,33,36), card=Color.FromArgb(44,46,50), accent=Color.FromArgb(36,99,195);
    readonly Label[] reasons=new Label[3];
    readonly Button checkAddress=new Button();
    readonly Label modeHint=new Label {AutoSize=true,Dock=DockStyle.Fill};
    Button routeOptions;
    TableLayoutPanel optionalRoutes;
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
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        fields.Controls.Add(Copy("Протокол",false),0,0);
        schemes[i]=new ComboBox{AccessibleName=names[i]+" — протокол",DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Fill};
        schemes[i].Items.AddRange(new object[]{"HTTP","HTTPS","SOCKS5"});
        schemes[i].SelectedIndex=0;
        fields.Controls.Add(schemes[i],0,1);
        var hint=Copy("Строка прокси · логин:пароль@адрес:порт",false);
        fields.Controls.Add(hint,0,2);fields.SetColumnSpan(hint,2);
        urls[i]=new TextBox{AccessibleName=names[i]+" — строка прокси",Anchor=AnchorStyles.Left|AnchorStyles.Right,UseSystemPasswordChar=true};
        fields.Controls.Add(urls[i],0,3);
        paste[i]=ActionButton("Вставить",(sender,e)=>{
            try{
                string line=Clipboard.GetText().Trim();
                if(line.Length>0)urls[i].Text=line;
                urls[i].Focus();
            }catch(System.Runtime.InteropServices.ExternalException){MessageBox.Show(this,"Буфер обмена занят. Попробуйте ещё раз.");}
        });
        paste[i].AccessibleName="Вставить прокси — "+names[i];
        fields.Controls.Add(paste[i],1,3);
        schemes[i].SelectedIndexChanged+=(sender,e)=>pins[i]=null;
        urls[i].TextChanged+=(sender,e)=>{
            pins[i]=null;
            string raw=urls[i].Text.Trim();
            int separator=raw.IndexOf("://",StringComparison.Ordinal);
            if(separator<1)return;
            string scheme=raw.Substring(0,separator).ToUpperInvariant();
            if(scheme=="SOCKS5H")scheme="SOCKS5";
            if(!schemes[i].Items.Contains(scheme))return;
            schemes[i].SelectedItem=scheme;
            urls[i].Text=raw.Substring(separator+3);
            urls[i].SelectionStart=urls[i].TextLength;
        };
        grid.Controls.Add(fields);
    }
    void ShowIdle(string message) {
        for(int i=0;i<outcomes.Length;i++){
            outcomes[i].Text=message;outcomes[i].ForeColor=muted;
            ShowReason(i,"");
        }
    }
    // Keep the native CheckBox semantics for keyboard and screen readers.
    sealed class ModeSwitch : CheckBox {
        public ModeSwitch(){
            Text="Защита по IP";AccessibleName=Text;Dock=DockStyle.Fill;
            AutoSize=false;Height=32;Margin=new Padding(4,3,4,0);Cursor=Cursors.Hand;
            SetStyle(ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw,true);
        }
        protected override void OnPaint(PaintEventArgs e){
            e.Graphics.Clear(BackColor);
            int h=Math.Max(16,Font.Height),w=2*h;
            var track=new Rectangle(Width-w-2,(Height-h)/2,w,h);
            Color trackColor=Checked?Color.FromArgb(55,119,217):Color.FromArgb(95,98,104);
            e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
            using(var path=new GraphicsPath()){
                path.AddArc(track.Left,track.Top,h,h,90,180);
                path.AddArc(track.Right-h,track.Top,h,h,270,180);path.CloseFigure();
                using(var brush=new SolidBrush(trackColor))e.Graphics.FillPath(brush,path);
            }
            int thumb=h-4;
            e.Graphics.FillEllipse(Brushes.White,Checked?track.Right-thumb-2:track.Left+2,track.Top+2,thumb,thumb);
            var label=new Rectangle(0,0,Math.Max(0,track.Left-8),Height);
            TextRenderer.DrawText(e.Graphics,Text,Font,label,ForeColor,TextFormatFlags.VerticalCenter | TextFormatFlags.Left);
            if(Focused && ShowFocusCues)ControlPaint.DrawFocusRectangle(e.Graphics,ClientRectangle,ForeColor,BackColor);
        }
    }
    readonly ModeSwitch protection=new ModeSwitch();
    bool ProxyOnly {get{return !protection.Checked;}}
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
        protection.Checked=false;
        saved=Path.Combine(dataDirectory,"routes.bin");
        Text="AI Exit Guard"; AutoScaleMode=AutoScaleMode.Font;Font=new Font("Segoe UI",10F);
        ClientSize=new Size(450,580);MinimumSize=new Size(390,440);BackColor=surface;ForeColor=ink;
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
            var name=Copy(names[i+1],true);
            name.Margin=new Padding(4,8,2,4);results.Controls.Add(name,0,2*i);
            outcomes[i]=Copy("",false);outcomes[i].AccessibleName=names[i+1]+" — статус";
            outcomes[i].TextAlign=ContentAlignment.MiddleRight;outcomes[i].Margin=new Padding(2,8,4,4);
            results.Controls.Add(outcomes[i],1,2*i);
            reasons[i]=Copy("",false);reasons[i].Margin=new Padding(4,0,4,6);
            results.Controls.Add(reasons[i],0,2*i+1);results.SetColumnSpan(reasons[i],2);
        }
        home.Controls.Add(results);
        var proxyCard=Card();proxyCard.ColumnCount=2;proxyCard.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var edit=ActionButton("Прокси", (sender,e)=>pages.SelectedIndex=1);edit.TextAlign=ContentAlignment.MiddleLeft;
        proxyCard.Controls.Add(edit,0,0);proxyBadge.ForeColor=muted;proxyBadge.Anchor=AnchorStyles.Right;
        proxyCard.Controls.Add(proxyBadge,1,0);
        protection.ForeColor=ink;protection.BackColor=card;protection.Font=new Font(Font,FontStyle.Bold);proxyCard.Controls.Add(protection,0,1);proxyCard.SetColumnSpan(protection,2);
        modeHint.ForeColor=muted;modeHint.Margin=new Padding(4,1,2,6);
        proxyCard.Controls.Add(modeHint,0,2);proxyCard.SetColumnSpan(modeHint,2);home.Controls.Add(proxyCard);
        protection.CheckedChanged+=(sender,e)=>{
            UpdateModeHint();
            if(relayReady){Stop();Connect();}
        };
        UpdateModeHint();
        start.Text="Подключить прокси";start.AutoSize=true;start.Padding=new Padding(12,4,12,4);start.Margin=new Padding(0,8,0,4);
        start.BackColor=accent;start.ForeColor=Color.White;start.FlatStyle=FlatStyle.Flat;start.FlatAppearance.BorderSize=0;
        start.Click+=(s,e)=>{if(relay!=null || retrying) Disconnect();else if(String.IsNullOrWhiteSpace(urls[0].Text)){pages.SelectedIndex=1;urls[0].Focus();}else Connect();};
        var actions=new FlowLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,FlowDirection=FlowDirection.RightToLeft,WrapContents=true};
        checkAddress.Text="Проверить адрес";checkAddress.AutoSize=true;checkAddress.FlatStyle=FlatStyle.Flat;
        checkAddress.BackColor=accent;checkAddress.ForeColor=ink;checkAddress.FlatAppearance.BorderSize=0;checkAddress.Padding=new Padding(8,4,8,4);
        checkAddress.Margin=new Padding(6,8,0,4);checkAddress.Visible=false;
        checkAddress.Click+=(sender,e)=>{
            if(!relayReady || !ProxyOnly || !checkAddress.Enabled)return;
            try{relay.StandardInput.WriteLine("check");relay.StandardInput.Flush();checkAddress.Enabled=false;checkAddress.Text="Проверяем…";}
            catch(IOException){RelayEnded();}
        };
        actions.Controls.Add(checkAddress);actions.Controls.Add(start);home.Controls.Add(actions);
        settings.Controls.Add(ActionButton("←  Назад",(s,e)=>pages.SelectedIndex=0));
        settings.Controls.Add(Copy("Общий прокси",true));ProxyInputs(settings,0);
        settings.Controls.Add(ActionButton("Подключить",(s,e)=>{if(relay==null){pages.SelectedIndex=0;Connect();}else pages.SelectedIndex=0;else MessageBox.Show(status.Text,Text);}));
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
            if(ProxyOnly && !ReleaseDomains()){quitting=false;e.Cancel=true;ShowWindow();}};
        FormClosed+=(s,e)=>{timer.Stop();Stop();tray.Dispose();detail.Dispose();};
        timer.Interval=350;timer.Tick+=(s,e)=>Poll();timer.Start();
        State("Откройте настройки, чтобы подключить прокси.",false);
        if(File.Exists(saved)) {
            try {
                byte[] bytes=ProtectedData.Unprotect(File.ReadAllBytes(saved),null,DataProtectionScope.CurrentUser);
                var r=json.Deserialize<Route[]>(Encoding.UTF8.GetString(bytes));
                if(r.Length!=4)throw new InvalidDataException();
                for(int i=0;i<4;i++){urls[i].Text=r[i].Address;pins[i]=r[i].IP;}
                allowMismatch.Checked=r[0].AllowGoogleCountryMismatch;protection.Checked=!r[0].ProxyOnly;
                if(!File.Exists(Path.Combine(dataDirectory,"paused")))Shown+=(s,e)=>Connect();
            }catch{State("Не удалось прочитать сохранённые прокси.",false);}
        }
    }
    void ShowRouteOptions(bool show){
        optionalRoutes.Visible=show;routeOptions.Text=show?"Отдельные прокси  ▾":"Отдельные прокси  ▸";
        pages.SelectedTab.PerformLayout();
    }
    void UpdateModeHint(){
        modeHint.Text=ProxyOnly?"Guard только предупреждает о риске.":"При опасном IP Guard блокирует запросы к ИИ через прокси.";
    }
    void ShowReason(int i,string reason){
        reason=reason??"";
        reasons[i].Text=reason;reasons[i].Visible=reason.Length>0;
        outcomes[i].AccessibleDescription=reason;detail.SetToolTip(outcomes[i],reason);
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
        bool routing=ProxyOnly && relayReady;
        if(routing){verdict.Text="Только прокси";verdict.ForeColor=ink;summary.BackColor=card;}
        checkAddress.Visible=routing;start.BackColor=routing?card:accent;
        tray.Text="Guard · "+verdict.Text;tray.Icon=routing?SystemIcons.Shield:open?SystemIcons.Information:closed?SystemIcons.Error:SystemIcons.Warning;
    }
    object Endpoint(string text) {
        Uri u;
        int split=text.IndexOf("://",StringComparison.Ordinal);
        if(split<1)throw new FormatException();
        string body=text.Substring(split+3);
        if(body.Contains("://"))throw new FormatException();
        if(!body.Contains("@") && !body.StartsWith("[")){
            var parts=body.Split(new[]{':'},4);
            int port;
            if(parts.Length==4 && int.TryParse(parts[1],out port) && port>=1 && port<=65535)
                text=text.Substring(0,split+3)+Uri.EscapeDataString(parts[2])+":"+Uri.EscapeDataString(parts[3])+"@"+parts[0]+":"+parts[1];
        }
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
                string url=urls[i].Text.Trim(), ip=pins[i] ?? "";
                var route=new Route{Address=url==""?"":schemes[i].Text.ToLowerInvariant()+"://"+url,IP=ip,ProxyOnly=i==0 && ProxyOnly,AllowGoogleCountryMismatch=i==0 && allowMismatch.Checked};
                routes.Add(route);
                if(url=="" && ip=="" && i>0)continue;
                System.Net.IPAddress parsed;
                if(url=="" || (ip!="" && (!System.Net.IPAddress.TryParse(ip,out parsed) || parsed.ToString()!=ip)))throw new FormatException();
                var endpoint=Endpoint(route.Address);
                if(ip==""){
                    State("Проверяем выход через прокси…",false);
                    try{ip=await MeasureExit(endpoint,i);}catch{
                        if(!IsDisposed)State("Прокси не подтвердил выход. Проверьте адрес и пароль.",false);
                        return;
                    }
                    if(IsDisposed || Disposing)return;
                    route.IP=ip;pins[i]=ip;
                }
                if(i==0)common=endpoint;else profiles[names[i]]=new {Endpoint=endpoint,Expected=ip};
            }
            var cfg=new {Common=common,Expected=routes[0].IP,Profiles=profiles,DetailedStatus=true,ProxyOnly=ProxyOnly,AllowGoogleCountryMismatch=allowMismatch.Checked};
            var psi=new ProcessStartInfo(Path.Combine(dir,"guard-core.exe"),"desktop-relay"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,StandardOutputEncoding=Encoding.UTF8};
            relay=Process.Start(psi); relay.StandardInput.WriteLine(json.Serialize(cfg));relay.StandardInput.Flush();
            next=relay.StandardOutput.ReadLineAsync();leases=null;
            Directory.CreateDirectory(Path.GetDirectoryName(saved));
            byte[] data=ProtectedData.Protect(Encoding.UTF8.GetBytes(json.Serialize(routes)),null,DataProtectionScope.CurrentUser);
            string temp=Path.Combine(Path.GetDirectoryName(saved),Guid.NewGuid().ToString()+".tmp");
            try{File.WriteAllBytes(temp,data);if(File.Exists(saved))File.Replace(temp,saved,null);else File.Move(temp,saved);}
            finally{if(File.Exists(temp))File.Delete(temp);}
            ShowIdle("Подключаем…");Inputs(false);start.Text="Отключить прокси";State(ProxyOnly?"Запускаем прокси…":"Проверяем адреса перед подключением.",false);
        }catch(FormatException){State("Проверьте строку прокси. Пример: логин:пароль@адрес:порт.",false);}
         catch{Stop();State("Не удалось запустить Guard или сохранить настройки.",false);}
        finally{
            checkingProxy=false;
            if(!IsDisposed && !Disposing){start.Enabled=true;Inputs(relay==null);}
        }
    }
    void Inputs(bool enabled){protection.Enabled=enabled || relayReady;allowMismatch.Enabled=enabled;foreach(var t in urls)t.Enabled=enabled;foreach(var t in schemes)t.Enabled=enabled;foreach(var t in paste)t.Enabled=enabled;}
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
        relayReady=false;checkAddress.Enabled=true;checkAddress.Text="Проверить адрес";next=null;leases=null;ShowIdle("Выключен");Inputs(true);start.Text="Подключить";State("Откройте настройки, чтобы подключить прокси.",false);
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
                    retrying=false;readySince=DateTime.UtcNow;relayReady=true;protection.Enabled=true;proxyBadge.Text="Подключён";
                    if(ProxyOnly){
                        State("Адрес можно проверить вручную.",false);
                        for(int i=0;i<outcomes.Length;i++)outcomes[i].Text=String.IsNullOrWhiteSpace(urls[i+1].Text)?"Общий прокси":"Свой прокси";
                    }else ShowIdle("Проверяем…");
                    return;
                }
                if(line=="CHECKED"){checkAddress.Enabled=true;checkAddress.Text="Проверить адрес";return;}
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
            else if(r.Until>now){caption=ProxyOnly?"Низкий риск":"Можно пользоваться";color=Color.LightGreen;open++;}
            else{caption=ProxyOnly?"Есть замечание":"Закрыт";color=ProxyOnly?Color.FromArgb(255,195,111):Color.LightSalmon;}
            if(outcomes[i].Text!=caption){outcomes[i].Text=caption;outcomes[i].ForeColor=color;}
            string reason=r==null || r.Until>now?"":r.Reason;
            if(r!=null && r.Until<=now && String.IsNullOrEmpty(reason))reason="Срок проверки истёк.";
            if(reasons[i].Text!=reason)ShowReason(i,reason);
        }
        string current=ProxyOnly?(waiting>0?"Проверяем адреса…":open==3?"Замечаний по адресу нет.":"Есть замечания к выходному IP."):waiting>0?"Идёт проверка…":open==3?"Все три сервиса доступны":"Доступно сервисов: "+open+" из 3";
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
        protection.Checked=true;
        string original="127.0.0.1 localhost\r\n";string on=DomainLock.Edit(original,true);
        if(DomainLock.Edit(on,false)!=original || DomainLock.Edit(on,true)!=on || !on.Contains("127.0.0.2 daily-cloudcode-pa.googleapis.com"))return 18;
        if(!Visible || !IsHandleCreated || !tray.Visible || urls.Length!=4 || schemes.Length!=4)return 11;
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
            if(!urls[i].Created || !paste[i].Created || !schemes[i].Created || paste[i].Width<60 || urls[i].Width<80)return 12;
        }
        Clipboard.SetText("socks5://demo:pass@proxy.example:8000");paste[1].PerformClick();
        if(schemes[1].Text!="SOCKS5" || urls[1].Text!="demo:pass@proxy.example:8000")return 24;
        if(json.Serialize(Endpoint("https://proxy.example:8000:demo:p:a"))!=json.Serialize(Endpoint("https://demo:p%3Aa@proxy.example:8000")))return 25;
        pins[1]="192.0.2.1";schemes[1].SelectedItem="HTTPS";
        if(pins[1]!=null)return 26;
        urls[1].Text="";
        pages.SelectedIndex=1;ShowRouteOptions(false);
        pages.SelectedTab.PerformLayout();SaveSmokeImage("03-settings.png");
        pages.SelectedIndex=0;
        leases=json.Deserialize<Dictionary<string,Reading>>("{\"Antigravity\":{\"Until\":0,\"Reason\":\"Google: NL, IPinfo: DE\"},\"Claude\":{\"Until\":201}}");
        RenderReadings(200);
        if(!outcomes[2].AccessibleDescription.Contains("Google: NL, IPinfo: DE") || !outcomes[0].Text.Contains("Можно") || !outcomes[1].Text.Contains("Проверяем"))return 19;
        RenderReadings(201);if(!outcomes[0].Text.Contains("Закрыт"))return 20;
        allowMismatch.Checked=true;
        urls[0].Text="http://example.org:invalid";start.PerformClick();
        if(relay!=null || !status.Text.Contains("строку прокси"))return 13;
        urls[0].Text="http://127.0.0.1:1";pins[0]="192.0.2.1"; start.PerformClick();
        if(relay==null || relay.HasExited || !File.Exists(saved) || urls[0].Enabled)return 14;
        byte[] plain=ProtectedData.Unprotect(File.ReadAllBytes(saved),null,DataProtectionScope.CurrentUser);
        if(!json.Deserialize<Route[]>(Encoding.UTF8.GetString(plain))[0].AllowGoogleCountryMismatch)return 15;
        relayReady=true;
        leases=new Dictionary<string,Reading>();
        for(int i=1;i<names.Length;i++)leases[names[i]]=new Reading{Until=201};
        RenderReadings(200);SaveSmokeImage("01-access-open.png");
        leases["Antigravity"]=new Reading{Until=0,Reason="Google не подтвердил страну выхода."};
        RenderReadings(200);SaveSmokeImage("02-one-service-closed.png");
        if(!reasons[2].Visible || !reasons[2].Text.Contains("страну"))return 22;
        relayReady=false;protection.Checked=false;relayReady=true;RenderReadings(200);
        if(outcomes[2].Text!="Есть замечание" || !checkAddress.Visible || !reasons[2].Visible)return 23;
        SaveSmokeImage("04-proxy-only-warning.png");
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
