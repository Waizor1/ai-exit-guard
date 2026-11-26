using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
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
    sealed class SavedProxyItem {
        public string Id {get;set;}
        public string Country {get;set;}
        public string Scheme {get;set;}
        public string Line {get;set;}
    }
    readonly string[] names = {"Общий", "Claude", "ChatGPT", "Antigravity"};
    readonly TextBox[] urls = new TextBox[4];
    readonly ProtocolPicker[] schemes = new ProtocolPicker[4];
    readonly Button[] paste = new Button[4];
    readonly CheckBox[] byField=new CheckBox[4];
    readonly TextBox[] addresses=new TextBox[4], logins=new TextBox[4], passwords=new TextBox[4];
    readonly CheckBox[] reveal=new CheckBox[4];
    ConnectionPane connections;
    DateTime nextFlows;
    readonly string[] pins = new string[4];
    readonly Label status = new Label { AutoSize=true };
    readonly Label[] outcomes = new Label[3];
    readonly CheckBox allowMismatch = new CheckBox { Dock=DockStyle.Fill,AutoSize=true, Text="Разрешить разные страны Google и IPinfo для Antigravity" };
    sealed class Reading {
        public long Until {get;set;}
        public string Reason {get;set;}
        public bool HighRisk {get;set;}
    }
    readonly Color ink=Color.FromArgb(246,245,244), muted=Color.FromArgb(198,196,194);
    readonly Color surface=Color.FromArgb(43,42,42), card=Color.FromArgb(55,54,54), accent=Color.FromArgb(0,112,232);
    readonly Label inputFeedback = new Label{AutoSize=true,Visible=false,Dock=DockStyle.Fill};
    readonly Label[] reasons=new Label[3];
    readonly Button checkAddress=new SoftButton();
    readonly Label lastResult=new Label{Text="Адрес ещё не проверен",AutoSize=true,Anchor=AnchorStyles.Left};
    readonly Label modeHint=new Label {AutoSize=true,Dock=DockStyle.Fill};
    readonly Label patchState=new Label{AutoSize=true,Dock=DockStyle.Fill,ForeColor=Color.FromArgb(198,196,194)};
    readonly Label patchError=new Label{AutoSize=true,Dock=DockStyle.Fill,ForeColor=Color.FromArgb(255,140,130),Visible=false,Margin=new Padding(4,0,4,2)};
    Button patchButton;
    bool patchBusy;
    readonly Label updateState=new Label{AutoSize=true,Dock=DockStyle.Fill,ForeColor=Color.FromArgb(198,196,194)};
    Button updateButton;
    TableLayoutPanel updateBanner;
    Label updateBannerText;
    Button updateBannerButton;
    bool updateBusy;
    string availableVersion="";
    readonly string savedLibrary;
    readonly List<SavedProxyItem> savedProxies=new List<SavedProxyItem>();
    TableLayoutPanel savedProxiesCard;
    TableLayoutPanel savedProxiesList;
    ComboBox buyCountryBox;
    Button routeOptions;
    TableLayoutPanel optionalRoutes;
    readonly Label proxyBadge=new Label{AutoSize=true};
    readonly Label verdict=new Label{AutoSize=true,Dock=DockStyle.Fill};
    TableLayoutPanel summary;
    Button ActionButton(string title, EventHandler click) {
        var button=new SoftButton{Text=title,AutoSize=true,FlatStyle=FlatStyle.Flat,ForeColor=ink,BackColor=card,Padding=new Padding(8,3,8,3)};
        button.Cursor=Cursors.Hand;button.FlatAppearance.BorderSize=0;button.Click+=click;return button;
    }
    static void PaintSurface(Control control,Graphics g,Color fill,int radius){
        int w=control.Width-1,h=control.Height-1;
        if(w<1 || h<1)return;
        g.Clear(control.Parent==null?fill:control.Parent.BackColor);
        int d=Math.Min(Math.Min(w,h),radius*2);
        g.SmoothingMode=SmoothingMode.AntiAlias;
        using(var path=new GraphicsPath()){
            path.AddArc(0,0,d,d,180,90);path.AddArc(w-d,0,d,d,270,90);
            path.AddArc(w-d,h-d,d,d,0,90);path.AddArc(0,h-d,d,d,90,90);path.CloseFigure();
            using(var brush=new SolidBrush(fill))g.FillPath(brush,path);
        }
    }
    sealed class RoundedCard : TableLayoutPanel {
        protected override void OnPaintBackground(PaintEventArgs e){PaintSurface(this,e.Graphics,BackColor,14);}
    }
    enum Mark { Shield, Sun, Chat, Stars }
    sealed class Glyph : Control {
        readonly Mark mark;
        public Glyph(Mark mark,Color color){
            this.mark=mark;ForeColor=color;Size=new Size(23,23);Margin=new Padding(2,6,7,0);
            TabStop=false;AccessibleRole=AccessibleRole.None;
        }
        protected override void OnPaint(PaintEventArgs e){
            base.OnPaint(e);
            Graphics g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;
            float scale=Math.Min(ClientSize.Width,ClientSize.Height)/24f;g.ScaleTransform(scale,scale);
            using(var pen=new Pen(ForeColor,1.7f))
            using(var brush=new SolidBrush(ForeColor)){
                if(mark==Mark.Shield){
                    g.DrawPolygon(pen,new[]{new Point(12,2),new Point(21,6),new Point(20,14),new Point(17,18),new Point(12,22),new Point(7,18),new Point(4,14),new Point(3,6)});
                    g.DrawLines(pen,new[]{new Point(7,11),new Point(11,15),new Point(17,8)});
                }else if(mark==Mark.Sun){
                    g.FillEllipse(brush,7,7,10,10);
                    for(int i=0;i<8;i++){
                        double a=i*Math.PI/4;float x=(float)Math.Cos(a),y=(float)Math.Sin(a);
                        g.DrawLine(pen,12+7*x,12+7*y,12+10*x,12+10*y);
                    }
                }else if(mark==Mark.Chat){
                    g.DrawEllipse(pen,2,3,15,11);g.DrawLine(pen,6,13,4,17);
                    g.FillEllipse(brush,8,9,14,10);
                    g.FillPolygon(brush,new[]{new Point(15,17),new Point(21,21),new Point(20,16)});
                }else{
                    g.FillPolygon(brush,new[]{new Point(10,4),new Point(12,11),new Point(19,13),new Point(12,15),new Point(10,22),new Point(8,15),new Point(1,13),new Point(8,11)});
                    g.FillPolygon(brush,new[]{new Point(18,1),new Point(19,4),new Point(23,6),new Point(19,7),new Point(18,11),new Point(17,7),new Point(14,6),new Point(17,4)});
                }
            }
        }
    }
    sealed class SoftButton : Button {
        protected override void OnPaint(PaintEventArgs e){
            bool hover=Enabled && ClientRectangle.Contains(PointToClient(MousePosition));
            Color fill=Enabled?BackColor:Color.FromArgb(64,63,63);
            PaintSurface(this,e.Graphics,hover?ControlPaint.Light(fill,.12f):fill,8);
            var alignment=TextAlign==ContentAlignment.MiddleLeft?TextFormatFlags.Left:TextFormatFlags.HorizontalCenter;
            TextRenderer.DrawText(e.Graphics,Text,Font,Rectangle.Inflate(ClientRectangle,-Padding.Left,0),Enabled?ForeColor:Color.Silver,alignment|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
            if(Focused && ShowFocusCues)ControlPaint.DrawFocusRectangle(e.Graphics,Rectangle.Inflate(ClientRectangle,-4,-4),ForeColor,BackColor);
        }
    }
    sealed class ProtocolPicker : TableLayoutPanel {
        public static readonly string[] Choices={"HTTP","HTTPS","SOCKS5"};
        public event EventHandler Changed;
        public string Selected {
            get{foreach(RadioButton b in Controls)if(b.Checked)return b.Text;return Choices[0];}
            set{foreach(RadioButton b in Controls)if(b.Text==value)b.Checked=true;}
        }
        public ProtocolPicker(){
            AutoSize=true;Dock=DockStyle.Fill;ColumnCount=3;Margin=new Padding(0,3,0,8);
            foreach(string choice in Choices){
                ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100f/3));
                var b=new RadioButton{Appearance=Appearance.Button,Text=choice,AutoSize=true,TextAlign=ContentAlignment.MiddleCenter,Dock=DockStyle.Fill,FlatStyle=FlatStyle.Flat,Margin=new Padding(0),Padding=new Padding(1,3,1,3)};
                b.BackColor=Color.FromArgb(63,62,62);b.ForeColor=Color.White;b.FlatAppearance.BorderSize=0;
                b.FlatAppearance.CheckedBackColor=Color.FromArgb(100,99,98);
                b.CheckedChanged+=(sender,e)=>{if(b.Checked && Changed!=null)Changed(this,e);};
                Controls.Add(b);
            }
            Selected=Choices[0];
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
        var header=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=3,Margin=Padding.Empty};
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        if(pages.TabCount>1)header.Controls.Add(ActionButton("←  Назад",(s,e)=>pages.SelectedIndex=0),0,0);
        var identity=new FlowLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,Margin=Padding.Empty,WrapContents=true};
        var name=Copy("AI Exit Guard",true);
        name.Margin=new Padding(2,8,4,4);
        if(pages.TabCount==1)identity.Controls.Add(new Glyph(Mark.Shield,ink));
        identity.Controls.Add(name);
        var version=Copy(Application.ProductVersion,false);version.Name="ProductVersion";
        version.AccessibleName="Версия "+version.Text;version.Margin=new Padding(2,8,2,4);
        identity.Controls.Add(version);header.Controls.Add(identity,1,0);
        if(pages.TabCount==1){
            var settingsMenu=new ContextMenuStrip();
            settingsMenu.Items.Add("Прокси",null,(s,e)=>pages.SelectedIndex=1);
            settingsMenu.Items.Add("Активные подключения",null,(s,e)=>pages.SelectedIndex=2);
            settingsMenu.Items.Add("Завершить Guard",null,(s,e)=>{quitting=true;Close();});
            header.Controls.Add(ActionButton("Настройки",(sender,e)=>{var button=(Button)sender;settingsMenu.Show(button,0,button.Height);}),2,0);
            Disposed+=(s,e)=>settingsMenu.Dispose();
        }
        grid.Controls.Add(header);
        return grid;
    }
    Label Copy(string text,bool heading) {
        return new Label {Text=text,AutoSize=true,Dock=DockStyle.Fill,ForeColor=heading?ink:muted,
            Font=heading?new Font(Font,FontStyle.Bold):Font,Margin=new Padding(2,heading?12:4,2,4)};
    }
    RoundedCard EntryBox(TextBox input){
        var box=new RoundedCard{Dock=DockStyle.Fill,AutoSize=true,ColumnCount=1,BackColor=Color.FromArgb(28,28,28),Padding=new Padding(8,6,8,6),Margin=new Padding(0,4,0,5)};
        box.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        input.Anchor=AnchorStyles.Left|AnchorStyles.Right;input.BackColor=box.BackColor;input.ForeColor=ink;input.BorderStyle=BorderStyle.None;
        box.Controls.Add(input);return box;
    }
    TextBox AddEntry(TableLayoutPanel panel,string label,int i){
        var entry=new TextBox{AccessibleName=names[i]+" — "+label};
        panel.Controls.Add(Copy(label,false));panel.Controls.Add(EntryBox(entry));
        return entry;
    }
    string FieldLine(int i){
        string host=addresses[i].Text.Trim(),user=logins[i].Text,password=passwords[i].Text;
        if(user=="" && password=="")return host;
        return Uri.EscapeDataString(user)+":"+Uri.EscapeDataString(password)+"@"+host;
    }
    bool ValidFields(int i){
        string host=addresses[i].Text.Trim();
        if(host=="")return logins[i].Text=="" && passwords[i].Text=="";
        int port;Uri uri;
        int colon=host.LastIndexOf(':');
        return colon>0 && int.TryParse(host.Substring(colon+1),out port) && port>0 && port<=65535 &&
            host.IndexOfAny(new[]{'@','/','?','#','\\',' '})<0 && Uri.TryCreate("http://"+host,UriKind.Absolute,out uri) &&
            uri.Port==port && (passwords[i].Text=="" || logins[i].Text!="");
    }
    void ProxyInputs(TableLayoutPanel grid,int i) {
        var fields=Card();fields.ColumnCount=2;fields.ColumnStyles.Clear();
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        fields.Controls.Add(Copy("Протокол",false),0,0);
        schemes[i]=new ProtocolPicker{AccessibleName=names[i]+" — протокол"};
        fields.Controls.Add(schemes[i],0,1);fields.SetColumnSpan(schemes[i],2);
        var hint=Copy("Строка прокси · логин:пароль@адрес:порт",false);
        fields.Controls.Add(hint,0,2);fields.SetColumnSpan(hint,2);
        urls[i]=new TextBox{AccessibleName=names[i]+" — строка прокси",Anchor=AnchorStyles.Left|AnchorStyles.Right,UseSystemPasswordChar=false};
        var slot=new TableLayoutPanel{ColumnCount=1,Dock=DockStyle.Fill,AutoSize=true,Margin=Padding.Empty};slot.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        fields.Controls.Add(slot,0,3);fields.SetColumnSpan(slot,2);
        var input=EntryBox(urls[i]);slot.Controls.Add(input);
        paste[i]=ActionButton("Вставить",(sender,e)=>{
            try{
                string line=Clipboard.GetText().Trim();
                if(line.Length>0)urls[i].Text=line;
                urls[i].Focus();
            }catch(System.Runtime.InteropServices.ExternalException){MessageBox.Show(this,"Буфер обмена занят. Попробуйте ещё раз.");}
        });
        paste[i].BackColor=Color.FromArgb(77,76,76);paste[i].AccessibleName="Вставить прокси — "+names[i];
        fields.Controls.Add(paste[i],0,4);
        schemes[i].Changed+=(sender,e)=>pins[i]=null;
        urls[i].TextChanged+=(sender,e)=>{
            pins[i]=null;
            string raw=urls[i].Text.Trim();
            int separator=raw.IndexOf("://",StringComparison.Ordinal);
            if(separator<1)return;
            string scheme=raw.Substring(0,separator).ToUpperInvariant();
            if(scheme=="SOCKS5H")scheme="SOCKS5";
            if(Array.IndexOf(ProtocolPicker.Choices,scheme)<0)return;
            schemes[i].Selected=scheme;
            urls[i].Text=raw.Substring(separator+3);
            urls[i].SelectionStart=urls[i].TextLength;
        };
        reveal[i]=new CheckBox{Text="Показывать строку",Checked=true,AutoSize=true,ForeColor=ink,Dock=DockStyle.Fill};
        var parts=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Top,ColumnCount=1,Margin=Padding.Empty,Visible=false};
        parts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        addresses[i]=AddEntry(parts,"Адрес и порт",i);
        logins[i]=AddEntry(parts,"Логин",i);passwords[i]=AddEntry(parts,"Пароль",i);
        slot.Controls.Add(parts);
        byField[i]=new CheckBox{Text="Ввести по полям",AutoSize=true,ForeColor=ink};
        fields.Controls.Add(byField[i],1,0);
        bool filling=false;
        byField[i].CheckedChanged+=(sender,e)=>{
            bool split=byField[i].Checked;
            if(split){
                filling=true;
                try{
                    string raw=urls[i].Text.Trim();
                    if(raw.Length==0){addresses[i].Clear();logins[i].Clear();passwords[i].Clear();}
                    else{
                        var ep=Endpoint(schemes[i].Selected.ToLowerInvariant()+"://"+raw);
                        addresses[i].Text=(ep.Host.Contains(":")?"["+ep.Host.Trim('[',']')+"]":ep.Host)+":"+ep.Port;
                        logins[i].Text=ep.User;passwords[i].Text=ep.Password;
                    }
                }catch(FormatException){addresses[i].Text=urls[i].Text;logins[i].Clear();passwords[i].Clear();}
                finally{filling=false;}
            }
            input.Visible=hint.Visible=paste[i].Visible=!split;parts.Visible=split;
            reveal[i].Text=split?"Показывать пароль":"Показывать строку";
        };
        foreach(var part in new[]{addresses[i],logins[i],passwords[i]})
            part.TextChanged+=(sender,e)=>{if(byField[i].Checked && !filling)urls[i].Text=FieldLine(i);};
        reveal[i].CheckedChanged+=(sender,e)=>{urls[i].UseSystemPasswordChar=passwords[i].UseSystemPasswordChar=!reveal[i].Checked;};
        fields.Controls.Add(reveal[i],0,5);fields.SetColumnSpan(reveal[i],2);
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
    readonly Button start = new SoftButton();
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
        SuspendLayout();
        smokeMode=smoke;
        ownedDomains=Path.Combine(dataDirectory,"managed-domains");
        protection.Checked=false;
        saved=Path.Combine(dataDirectory,"routes.bin");
        savedLibrary=Path.Combine(dataDirectory,"proxy-library.bin");
        Text="AI Exit Guard"; Font=new Font("Segoe UI",11F);
        AutoScaleDimensions=new SizeF(96,96);AutoScaleMode=AutoScaleMode.Dpi;
        ClientSize=new Size(480,Math.Min(730,Screen.FromControl(this).WorkingArea.Height-70));MinimumSize=new Size(390,440);BackColor=surface;ForeColor=ink;
        pages.Appearance=TabAppearance.FlatButtons;pages.SizeMode=TabSizeMode.Fixed;pages.ItemSize=new Size(0,1);pages.TabStop=false;
        Controls.Add(pages);
        var home=Page("Главная");var settings=Page("Настройки");
        summary=Card();
        verdict.Font=new Font(Font.FontFamily,19,FontStyle.Bold);verdict.Margin=new Padding(2,7,2,3);summary.Controls.Add(verdict);
        status.AccessibleName="Причина текущего состояния";status.Dock=DockStyle.Fill;status.Margin=new Padding(2,2,2,8);status.ForeColor=muted;summary.Controls.Add(status);home.Controls.Add(summary);
        var results=Card();results.ColumnCount=3;results.ColumnStyles.Clear();
        results.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));results.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,46));results.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,54));
        var services=Copy("Сервисы",true);services.Margin=new Padding(4,2,4,4);services.ForeColor=muted;
        results.Controls.Add(services,0,0);results.SetColumnSpan(services,3);
        var marks=new[]{Mark.Sun,Mark.Chat,Mark.Stars};
        var colors=new[]{Color.SandyBrown,Color.Turquoise,Color.FromArgb(178,167,255)};
        for(int i=0;i<3;i++){
            int row=1+3*i;
            var name=Copy(names[i+1],true);
            results.Controls.Add(new Glyph(marks[i],colors[i]),0,row);
            name.Margin=new Padding(0,8,2,4);results.Controls.Add(name,1,row);
            outcomes[i]=Copy("",false);outcomes[i].AccessibleName=names[i+1]+" — статус";
            outcomes[i].TextAlign=ContentAlignment.MiddleRight;outcomes[i].Margin=new Padding(2,8,4,4);
            results.Controls.Add(outcomes[i],2,row);
            reasons[i]=Copy("",false);reasons[i].Margin=new Padding(0,0,4,7);
            results.Controls.Add(reasons[i],1,row+1);results.SetColumnSpan(reasons[i],2);
            if(i<2){
                var divider=new Panel{Height=1,Dock=DockStyle.Top,Margin=new Padding(4,1,4,1),BackColor=ControlPaint.Light(card,.12f)};
                results.Controls.Add(divider,0,row+2);results.SetColumnSpan(divider,3);
            }
        }
        home.Controls.Add(results);
        var proxyCard=Card();proxyCard.ColumnCount=2;proxyCard.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var edit=ActionButton("Добавить прокси", (sender,e)=>pages.SelectedIndex=1);edit.TextAlign=ContentAlignment.MiddleLeft;edit.Font=new Font(Font,FontStyle.Bold);
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
        start.Click+=(s,e)=>{
            if(relay!=null || retrying){Disconnect();if(relay!=null)pages.SelectedIndex=0;return;}
            Connect();
        };
        var activity=Page("Подключения");
        var connectionsTitle=Copy("Активные подключения",true);connectionsTitle.Font=new Font(Font.FontFamily,18,FontStyle.Bold);activity.Controls.Add(connectionsTitle);
        var feed=Card();activity.Controls.Add(feed);connections=new ConnectionPane(feed,card,ink);
        EventHandler openFlows=(s,e)=>{pages.SelectedIndex=2;nextFlows=DateTime.MinValue;};
        var activityLink=ActionButton("Активные подключения",openFlows);activityLink.Dock=DockStyle.Fill;
        activityLink.TextAlign=ContentAlignment.MiddleLeft;activityLink.Font=new Font(Font,FontStyle.Bold);home.Controls.Add(activityLink);
        var actions=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=2};
        actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));actions.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        lastResult.ForeColor=muted;actions.Controls.Add(lastResult,0,0);
        checkAddress.Text="Проверить адрес";checkAddress.AutoSize=true;checkAddress.FlatStyle=FlatStyle.Flat;
        checkAddress.BackColor=accent;checkAddress.ForeColor=ink;checkAddress.FlatAppearance.BorderSize=0;checkAddress.Padding=new Padding(8,4,8,4);
        checkAddress.Margin=new Padding(6,8,0,4);checkAddress.Enabled=false;
        checkAddress.Click+=(sender,e)=>{
            if(!relayReady || !checkAddress.Enabled)return;
            try{relay.StandardInput.WriteLine("check");relay.StandardInput.Flush();checkAddress.Enabled=false;checkAddress.Text="Проверяем…";}
            catch(IOException){RelayEnded();}
        };
        actions.Controls.Add(checkAddress,1,0);home.Controls.Add(actions);
        updateBanner=Card();updateBanner.BackColor=Color.FromArgb(38,52,72);updateBanner.ColumnCount=2;updateBanner.ColumnStyles.Clear();
        updateBanner.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));updateBanner.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        updateBannerText=Copy("Доступно обновление",true);updateBannerText.Margin=new Padding(2,4,6,4);
        updateBanner.Controls.Add(updateBannerText,0,0);
        updateBannerButton=ActionButton("Обновить",(sender,e)=>RunAppUpdate("install"));
        updateBannerButton.BackColor=accent;updateBannerButton.ForeColor=Color.White;
        updateBanner.Controls.Add(updateBannerButton,1,0);
        updateBanner.Visible=false;home.Controls.Add(updateBanner);
        var vectraCard=Card();vectraCard.BackColor=Color.FromArgb(40,50,66);vectraCard.ColumnCount=2;vectraCard.ColumnStyles.Clear();
        vectraCard.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));vectraCard.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var vectraTitle=Copy("Vectra Connect",true);vectraTitle.Margin=new Padding(2,2,4,1);
        var vectraSub=Copy("Лучший VPN-сервис для быстрой и стабильной работы",false);vectraSub.Margin=new Padding(2,0,4,2);
        var vectraText=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=1,Margin=Padding.Empty,BackColor=Color.Transparent};
        vectraText.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        vectraText.Controls.Add(vectraTitle);vectraText.Controls.Add(vectraSub);
        vectraCard.Controls.Add(vectraText,0,0);
        var vectraOpen=ActionButton("Открыть",(sender,e)=>{try{Process.Start(new ProcessStartInfo("https://pay.vectra-pro.net/store"){UseShellExecute=true});}catch{}});
        vectraOpen.BackColor=Color.FromArgb(62,76,98);vectraOpen.Anchor=AnchorStyles.Right;
        vectraCard.Controls.Add(vectraOpen,1,0);
        home.Controls.Add(vectraCard);
        var heading=Copy("Общий прокси",true);heading.Font=new Font(Font.FontFamily,18,FontStyle.Bold);settings.Controls.Add(heading);inputFeedback.ForeColor=Color.FromArgb(255,195,111);settings.Controls.Add(inputFeedback);ProxyInputs(settings,0);
        savedProxiesCard=Card();
        savedProxiesCard.Controls.Add(Copy("Сохранённые прокси",true));
        savedProxiesList=new TableLayoutPanel{AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Dock=DockStyle.Top,ColumnCount=1,Margin=Padding.Empty};
        savedProxiesList.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        savedProxiesCard.Controls.Add(savedProxiesList);
        savedProxiesCard.Visible=false;
        settings.Controls.Add(savedProxiesCard);
        var buyCard=Card();
        buyCard.Controls.Add(Copy("Купить прокси",true));
        var buyRow=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=2,Margin=new Padding(0,4,0,4)};
        buyRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));buyRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        buyCountryBox=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Fill,BackColor=Color.FromArgb(28,28,28),ForeColor=ink,FlatStyle=FlatStyle.Flat};
        buyCountryBox.Items.AddRange(new object[]{"Нидерланды","Германия","США","Финляндия","Великобритания","Сингапур","Япония"});
        buyCountryBox.SelectedIndex=0;
        var buyPay=ActionButton("Оплатить",(sender,e)=>{});
        buyPay.Enabled=false;buyPay.Margin=new Padding(8,0,0,0);
        buyRow.Controls.Add(buyCountryBox,0,0);buyRow.Controls.Add(buyPay,1,0);
        buyCard.Controls.Add(buyRow);
        buyCard.Controls.Add(Copy("Скоро: после оплаты прокси сам сохранится в список и подключится.",false));
        settings.Controls.Add(buyCard);
        urls[0].TextChanged+=(s,e)=>edit.Text=String.IsNullOrWhiteSpace(urls[0].Text)?"Добавить прокси":"Прокси";
        start.Anchor=AnchorStyles.Right;
        var fields=(TableLayoutPanel)paste[0].Parent;
        fields.Controls.Add(start,1,4);
        routeOptions=ActionButton("Отдельные прокси  ▸",(sender,e)=>ShowRouteOptions(!optionalRoutes.Visible));
        settings.Controls.Add(routeOptions);
        optionalRoutes=Card();settings.Controls.Add(optionalRoutes);
        for(int i=1;i<4;i++){optionalRoutes.Controls.Add(Copy(names[i],true));ProxyInputs(optionalRoutes,i);}
        optionalRoutes.Controls.Add(allowMismatch);optionalRoutes.Visible=false;
        dns.Text="Убрать прежнее правило доменов";dns.AutoSize=true;
        dns.Visible=!smoke && DomainRulesPresent() && !File.Exists(ownedDomains);
        dns.Click+=(sender,e)=>{try{SetDomains(false);dns.Visible=false;}catch{State("Windows не сняла правило доменов.",false);}};
        settings.Controls.Add(dns);
        var patchCard=Card();
        patchCard.Controls.Add(Copy("Патч Antigravity",true));
        patchState.Margin=new Padding(4,1,4,2);
        patchCard.Controls.Add(patchState);
        patchCard.Controls.Add(patchError);
        patchButton=ActionButton("Проверить",(sender,e)=>{});
        patchButton.TextAlign=ContentAlignment.MiddleLeft;patchButton.Enabled=false;
        patchButton.Click+=(sender,e)=>{if(!patchBusy)RunAntigravity(patchButton.Text=="Восстановить"?"restore":"patch");};
        patchCard.Controls.Add(patchButton);
        settings.Controls.Add(patchCard);
        var updateCard=Card();
        updateCard.Controls.Add(Copy("Обновления Guard",true));
        updateState.Text="Версия "+Application.ProductVersion;updateState.Margin=new Padding(4,1,4,2);
        updateCard.Controls.Add(updateState);
        updateButton=ActionButton("Проверить",(sender,e)=>RunAppUpdate(String.IsNullOrEmpty(availableVersion)?"check":"install"));
        updateButton.TextAlign=ContentAlignment.MiddleLeft;
        updateCard.Controls.Add(updateButton);
        settings.Controls.Add(updateCard);
        LoadSavedProxies();
        Shown+=(sender,e)=>{if(!smokeMode)RunAppUpdate("check");};
        pages.SelectedIndexChanged+=(sender,e)=>{if(pages.SelectedIndex==1 && !patchBusy)RunAntigravity("status");};
        ShowIdle("Выключен");
        tray.Icon=SystemIcons.Shield;tray.Visible=true; tray.MouseClick+=(s,e)=>{if(e.Button==MouseButtons.Left)ShowWindow();};
        var menu=new ContextMenuStrip();menu.Items.Add("Открыть",null,(s,e)=>ShowWindow());
        menu.Items.Add("Активные подключения",(Image)null,(s,e)=>{ShowWindow();openFlows(s,e);});menu.Items.Add("Выход",null,(s,e)=>{quitting=true;Close();});tray.ContextMenuStrip=menu;
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
                for(int i=0;i<4;i++){urls[i].Text=r[i].Address;pins[i]=r[i].IP;reveal[i].Checked=String.IsNullOrEmpty(r[i].Address);}
                allowMismatch.Checked=r[0].AllowGoogleCountryMismatch;protection.Checked=!r[0].ProxyOnly;
                if(!File.Exists(Path.Combine(dataDirectory,"paused")))Shown+=(s,e)=>Connect();
            }catch{State("Не удалось прочитать сохранённые прокси.",false);}
        }
        ResumeLayout(true);
    }
    void UpdatePatchUi(string state,string detail,string version,int rc,string action){
        string suffix=String.IsNullOrEmpty(version)?"":" · Antigravity "+version;
        bool showError=(action=="patch" || action=="restore") && rc!=0 && (state=="patched" || state=="unpatched");
        patchError.Text=showError?(String.IsNullOrEmpty(detail)?"Не удалось выполнить операцию":detail):"";
        patchError.Visible=showError;
        switch(state){
            case "patched":
                patchState.Text="Пропатчен"+suffix;patchState.ForeColor=Color.FromArgb(120,200,140);
                patchButton.Text="Восстановить";patchButton.Enabled=true;break;
            case "unpatched":
                patchState.Text="Не пропатчен"+suffix;patchState.ForeColor=muted;
                patchButton.Text="Пропатчить";patchButton.Enabled=true;break;
            case "missing":
                patchState.Text="Antigravity не найдена";patchState.ForeColor=muted;
                patchButton.Text="Пропатчить";patchButton.Enabled=false;break;
            case "unsupported":
                patchState.Text=String.IsNullOrEmpty(detail)?"Версия не поддерживается":detail;
                patchState.ForeColor=Color.FromArgb(255,195,111);patchButton.Text="Пропатчить";patchButton.Enabled=false;break;
            default:
                patchState.Text=String.IsNullOrEmpty(detail)?"Ошибка патчера":detail;
                patchState.ForeColor=Color.FromArgb(255,195,111);
                patchButton.Text="Повторить";patchButton.Enabled=true;break;
        }
    }
    async void RunAntigravity(string action){
        if(patchBusy)return;
        patchBusy=true;patchButton.Enabled=false;
        patchError.Visible=false;patchError.Text="";
        if(action=="status"){patchState.Text="Проверяем…";patchState.ForeColor=muted;}
        else{patchState.Text=action=="restore"?"Восстанавливаем…":"Патчим…";patchState.ForeColor=muted;}
        string output;
        try{
            output=await Task.Run(()=>{
                var psi=new ProcessStartInfo(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"guard-core.exe"),"antigravity-"+action){
                    UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8};
                using(var process=Process.Start(psi)){
                    string text=process.StandardOutput.ReadToEnd();
                    process.WaitForExit(900000);
                    return text;
                }
            });
        }catch(Exception ex){
            output=json.Serialize(new Dictionary<string,object>{{"state","error"},{"detail",ex.Message},{"rc",1}});
        }
        string state="error",detail="Не удалось разобрать ответ патчера",version="";
        int rc=1;
        try{
            var report=json.Deserialize<Dictionary<string,object>>(output);
            if(report!=null){
                state=report.ContainsKey("state")?Convert.ToString(report["state"]):"error";
                detail=report.ContainsKey("detail")?Convert.ToString(report["detail"]):"";
                version=report.ContainsKey("version")?Convert.ToString(report["version"]):"";
                rc=report.ContainsKey("rc")?Convert.ToInt32(report["rc"]):0;
            }
        }catch{}
        patchBusy=false;
        UpdatePatchUi(state,detail,version,rc,action);
    }
    void LoadSavedProxies(){
        savedProxies.Clear();
        try{
            if(!File.Exists(savedLibrary))return;
            byte[] plain=ProtectedData.Unprotect(File.ReadAllBytes(savedLibrary),null,DataProtectionScope.CurrentUser);
            var items=json.Deserialize<List<SavedProxyItem>>(Encoding.UTF8.GetString(plain));
            if(items!=null)savedProxies.AddRange(items);
        }catch{}
        RenderSavedProxies();
    }
    void PersistSavedProxies(){
        try{
            Directory.CreateDirectory(Path.GetDirectoryName(savedLibrary));
            byte[] data=ProtectedData.Protect(Encoding.UTF8.GetBytes(json.Serialize(savedProxies)),null,DataProtectionScope.CurrentUser);
            File.WriteAllBytes(savedLibrary,data);
        }catch{}
    }
    void SaveProxyToLibrary(string scheme,string line,string country){
        if(String.IsNullOrWhiteSpace(line))return;
        string normScheme=(scheme??"HTTP").ToUpperInvariant();
        string normLine=line.Trim();
        var existing=savedProxies.FirstOrDefault(p=>String.Equals(p.Scheme,normScheme,StringComparison.OrdinalIgnoreCase) && p.Line==normLine);
        if(existing!=null){
            if(!String.IsNullOrEmpty(country))existing.Country=country;
        }else{
            savedProxies.Add(new SavedProxyItem{Id=Guid.NewGuid().ToString("N"),Country=country??"",Scheme=normScheme,Line=normLine});
        }
        PersistSavedProxies();
        RenderSavedProxies();
    }
    public void AddPurchasedProxy(string country,string connectionLine){
        try{
            var ep=Endpoint(connectionLine);
            string line=ep.User=="" && ep.Password==""?ep.Host+":"+ep.Port:Uri.EscapeDataString(ep.User)+":"+Uri.EscapeDataString(ep.Password)+"@"+ep.Host+":"+ep.Port;
            SaveProxyToLibrary(ep.Scheme.ToUpperInvariant(),line,country);
            schemes[0].Selected=ep.Scheme.ToUpperInvariant();
            urls[0].Text=line;
            if(relay!=null)Disconnect();
            Connect();
        }catch{}
    }
    static string SavedProxyTitle(SavedProxyItem item){
        string host=item.Line??"";
        int at=host.LastIndexOf('@');
        if(at>=0 && at+1<host.Length)host=host.Substring(at+1);
        return String.IsNullOrEmpty(item.Country)?host:item.Country+" · "+host;
    }
    void RenderSavedProxies(){
        if(savedProxiesList==null)return;
        savedProxiesList.SuspendLayout();
        savedProxiesList.Controls.Clear();
        foreach(var entry in savedProxies){
            var item=entry;
            var row=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=4,Margin=new Padding(0,2,0,2)};
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            var title=Copy(SavedProxyTitle(item),false);title.ForeColor=ink;title.Margin=new Padding(2,6,4,2);
            var use=ActionButton("Выбрать",(s,e)=>{
                if(relay!=null)Disconnect();
                schemes[0].Selected=item.Scheme;urls[0].Text=item.Line;
            });
            var copy=ActionButton("Копировать",(s,e)=>{
                try{
                    Clipboard.SetText(item.Scheme.ToLowerInvariant()+"://"+item.Line);
                    var btn=(Button)s;btn.Text="Скопировано";
                    var t=new Timer{Interval=1500};t.Tick+=(ts,te)=>{t.Stop();t.Dispose();if(!btn.IsDisposed)btn.Text="Копировать";};t.Start();
                }catch{}
            });
            var del=ActionButton("×",(s,e)=>{savedProxies.RemoveAll(p=>p.Id==item.Id);PersistSavedProxies();RenderSavedProxies();});
            row.Controls.Add(title,0,0);row.Controls.Add(use,1,0);row.Controls.Add(copy,2,0);row.Controls.Add(del,3,0);
            savedProxiesList.Controls.Add(row);
        }
        savedProxiesList.ResumeLayout(true);
        savedProxiesCard.Visible=savedProxies.Count>0;
    }
    async void RunAppUpdate(string action){
        if(updateBusy)return;
        updateBusy=true;updateButton.Enabled=false;updateBannerButton.Enabled=false;
        updateState.Text=action=="install"?"Скачиваем обновление…":"Проверяем обновления…";
        updateState.ForeColor=muted;
        string output;
        try{
            output=await Task.Run(()=>{
                var psi=new ProcessStartInfo(Path.Combine(dir,"guard-core.exe"),"app-update-"+action+" "+Application.ProductVersion){
                    UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8};
                using(var process=Process.Start(psi)){
                    string text=process.StandardOutput.ReadToEnd();
                    process.WaitForExit(300000);
                    return text;
                }
            });
        }catch(Exception ex){
            output=json.Serialize(new Dictionary<string,object>{{"state","error"},{"detail",ex.Message}});
        }
        string state="error",latest="",detail="Не удалось проверить обновления";
        try{
            var report=json.Deserialize<Dictionary<string,object>>(output);
            if(report!=null){
                state=report.ContainsKey("state")?Convert.ToString(report["state"]):"error";
                latest=report.ContainsKey("latest")?Convert.ToString(report["latest"]):"";
                detail=report.ContainsKey("detail")?Convert.ToString(report["detail"]):"";
            }
        }catch{}
        updateBusy=false;
        if(state=="available" && !String.IsNullOrEmpty(latest)){
            availableVersion=latest;
            updateState.Text="Доступна версия "+latest;updateState.ForeColor=Color.FromArgb(130,190,255);
            updateButton.Text="Обновить";updateButton.BackColor=accent;updateButton.Enabled=true;
            updateBannerText.Text="Доступно обновление "+latest;updateBanner.Visible=true;updateBannerButton.Enabled=true;
        }else if(state=="installing"){
            updateState.Text=String.IsNullOrEmpty(detail)?"Устанавливаем обновление…":detail;
            updateState.ForeColor=Color.FromArgb(120,200,140);
            quitting=true;Close();
        }else if(state=="current"){
            availableVersion="";
            updateState.Text="Установлена последняя версия ("+Application.ProductVersion+")";updateState.ForeColor=muted;
            updateButton.Text="Проверить";updateButton.BackColor=card;updateButton.Enabled=true;
            updateBanner.Visible=false;
        }else{
            updateState.Text=String.IsNullOrEmpty(detail)?"Не удалось проверить обновления":detail;
            updateState.ForeColor=Color.FromArgb(255,140,130);
            updateButton.Text="Проверить";updateButton.Enabled=true;updateBannerButton.Enabled=true;
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
        if(checkingProxy && pages.SelectedIndex==1 && relay==null){inputFeedback.Text=text;inputFeedback.Visible=true;}
        status.Text=text;status.AccessibleDescription=text;proxyBadge.Text=relay==null?"Выключен":relayReady?"Подключён":"Подключаем…";
        verdict.Text=open?"Можно работать":relay==null?"Прокси отключён":leases==null?"Проверяем подключение":"Доступ ограничен";
        bool closed=relay!=null && leases!=null && text.StartsWith("Доступно сервисов: 0 из 3",StringComparison.Ordinal);
        if(closed)verdict.Text="Доступ закрыт";
        verdict.ForeColor=open?Color.LightGreen:closed?Color.LightSalmon:Color.FromArgb(255,195,111);
        summary.BackColor=relay==null?card:open?Color.FromArgb(35,54,46):closed?Color.FromArgb(66,42,44):Color.FromArgb(60,53,42);
        if(relay==null)verdict.ForeColor=ink;
        bool routing=ProxyOnly && relayReady;
        if(routing){verdict.Text="Только прокси";verdict.ForeColor=ink;summary.BackColor=leases==null?card:open?Color.FromArgb(48,60,48):Color.FromArgb(66,54,44);}
        bool danger=leases!=null && leases.Values.Any(r=>r.HighRisk && r.Until==0);
        if(routing && danger){verdict.Text="Высокий риск";verdict.ForeColor=Color.LightSalmon;summary.BackColor=Color.FromArgb(66,42,44);}
        if(retrying && relay==null){verdict.Text="Восстанавливаем соединение";proxyBadge.Text="Переподключение";verdict.ForeColor=Color.FromArgb(255,195,111);}
        if(!relayReady)checkAddress.Enabled=false;
        else if(checkAddress.Text!="Проверяем…")checkAddress.Enabled=true;
        start.BackColor=relay!=null || retrying?ControlPaint.Light(card,.17f):accent;
        tray.Text="Guard · "+verdict.Text;tray.Icon=routing && danger?SystemIcons.Error:routing && open?SystemIcons.Shield:routing?SystemIcons.Warning:open?SystemIcons.Information:closed?SystemIcons.Error:SystemIcons.Warning;
    }
    sealed class ProxyEndpoint {
        public string Scheme,Host,User,Password;
        public int Port;
    }
    ProxyEndpoint Endpoint(string text) {
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
        return new ProxyEndpoint {Scheme=u.Scheme, Host=u.DnsSafeHost, Port=u.Port, User=Uri.UnescapeDataString(auth[0]),Password=auth.Length>1?Uri.UnescapeDataString(auth[1]):""};
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
        checkingProxy=true;inputFeedback.Visible=false;Inputs(false);start.Enabled=false;
        try {
            var profiles=new Dictionary<string,object>();var routes=new List<Route>();object common=null;
            for(int i=0;i<4;i++) {
                if(byField[i].Checked && !ValidFields(i)){State("Проверьте адрес и порт прокси. Если указан пароль, заполните логин.",false);return;}
                string url=urls[i].Text.Trim(), ip=pins[i] ?? "";
                var route=new Route{Address=url==""?"":schemes[i].Selected.ToLowerInvariant()+"://"+url,IP=ip,ProxyOnly=i==0 && ProxyOnly,AllowGoogleCountryMismatch=i==0 && allowMismatch.Checked};
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
            SaveProxyToLibrary(schemes[0].Selected,urls[0].Text.Trim(),"");
            pages.SelectedIndex=0;inputFeedback.Visible=false;ShowIdle("Подключаем…");Inputs(false);start.Text="Отключить прокси";State(ProxyOnly?"Запускаем прокси…":"Проверяем адреса перед подключением.",false);
        }catch(FormatException){State("Проверьте строку прокси. Пример: логин:пароль@адрес:порт.",false);}
         catch{Stop();State("Не удалось запустить Guard или сохранить настройки.",false);}
        finally{
            checkingProxy=false;
            if(!IsDisposed && !Disposing){start.Enabled=true;Inputs(relay==null && !retrying);}
        }
    }
    void Inputs(bool enabled){protection.Enabled=enabled || relayReady;allowMismatch.Enabled=enabled;foreach(var t in urls)t.Enabled=enabled;foreach(var t in schemes)t.Enabled=enabled;foreach(var t in paste)t.Enabled=enabled;foreach(var t in byField)t.Enabled=enabled;foreach(var group in new[]{addresses,logins,passwords})foreach(var field in group)field.Enabled=enabled;}
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
        connections.Update(null,false);lastResult.Text="Адрес ещё не проверен";relayReady=false;checkAddress.Enabled=true;checkAddress.Text="Проверить адрес";next=null;leases=null;ShowIdle("Выключен");Inputs(true);start.Text="Подключить прокси";State("Откройте настройки, чтобы подключить прокси.",false);
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
        if(pages.SelectedIndex==2 && !smokeMode){
            connections.CheckOutside();
            if(relayReady && DateTime.UtcNow>=nextFlows){
                nextFlows=DateTime.UtcNow.AddSeconds(2);
                try{relay.StandardInput.WriteLine("activity");relay.StandardInput.Flush();}
                catch(IOException){nextFlows=DateTime.UtcNow.AddSeconds(5);}
            }else if(!relayReady)connections.Update(null,false);
        }
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
                    }else {ShowIdle("Проверяем…");State("Ожидаем результаты по трём сервисам.",false);}
                    return;
                }
                if(line.StartsWith("FLOWS ",StringComparison.Ordinal)){
                    try{connections.Update(json.Deserialize<ConnectionPane.Flow[]>(line.Substring(6)),true);}
                    catch(ArgumentException){connections.Update(null,relayReady);}
                    return;
                }
                if(line=="CHECKED"){checkAddress.Enabled=true;checkAddress.Text="Проверить адрес";return;}
                leases=json.Deserialize<Dictionary<string,Reading>>(line);
                lastResult.Text="Результат в "+DateTime.Now.ToString("HH:mm");
                if(!ProxyOnly){checkAddress.Enabled=relayReady;checkAddress.Text="Проверить адрес";}
            }
            if(leases!=null) RenderReadings((long)(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalSeconds);
        }catch{RelayEnded();}
    }
    void RenderReadings(long now){
        int open=0, waiting=0;
        string firstIssue=null;bool highIssue=false;
        for(int i=0;i<outcomes.Length;i++){
            Reading r;string caption;Color color;
            if(!leases.TryGetValue(names[i+1],out r)){caption="Проверяем…";color=muted;waiting++;}
            else if(r.Until>now){caption=ProxyOnly?"✓  Низкий риск":"✓  Можно работать";color=Color.LightGreen;open++;}
            else{caption=ProxyOnly?(r.HighRisk?"×  Высокий риск":"!  Есть замечание"):"×  Закрыт";color=ProxyOnly && !r.HighRisk?Color.FromArgb(255,195,111):Color.LightSalmon;}
            if(outcomes[i].Text!=caption){outcomes[i].Text=caption;outcomes[i].ForeColor=color;}
            string reason=r==null || r.Until>now?"":r.Reason;
            if(r!=null && r.Until<=now && String.IsNullOrEmpty(reason))reason="Срок проверки истёк.";
            if(!String.IsNullOrEmpty(reason) && (firstIssue==null || (r!=null && r.HighRisk && !highIssue))){firstIssue=names[i+1]+": "+reason;highIssue=r!=null && r.HighRisk;}
            if(r==null)reason="Ожидаем результат проверки.";
            else if(r.Until>now)reason=(String.IsNullOrWhiteSpace(urls[i+1].Text)?"Общий прокси":"Свой прокси")+" · оценка до "+DateTimeOffset.FromUnixTimeSeconds(r.Until).LocalDateTime.ToString("HH:mm");
            if(reasons[i].Text!=reason)ShowReason(i,reason);
        }
        string current=ProxyOnly?(waiting>0?"Проверяем адреса…":open==3?"Замечаний по адресу нет.":"Есть замечания к выходному IP."):waiting>0?"Идёт проверка…":open==3?"Все три сервиса доступны":"Доступно сервисов: "+open+" из 3";
        if(ProxyOnly && highIssue)current="Guard предупреждает о риске. Блокировка по IP выключена.";
        if(firstIssue!=null)current=current.TrimEnd('.','…')+". "+firstIssue;
        if(status.Text!=current)State(current,open==3);
    }
    void SaveSmokeImage(string file){
        string folder=Environment.GetEnvironmentVariable("GUARD_UI_SCREENSHOTS");
        if(String.IsNullOrEmpty(folder))return;
        Directory.CreateDirectory(folder);PerformLayout();Update();
        using(var image=new Bitmap(pages.SelectedTab.Width,pages.SelectedTab.Height)){
            pages.SelectedTab.DrawToBitmap(image,new Rectangle(Point.Empty,pages.SelectedTab.Size));
            image.Save(Path.Combine(folder,file),System.Drawing.Imaging.ImageFormat.Png);
        }
    }
    int ExerciseForm(){
        if(!ConnectionPane.CheckMatching())return 29;
        ConnectionPane.FindOutside();
        protection.Checked=true;
        string original="127.0.0.1 localhost\r\n";string on=DomainLock.Edit(original,true);
        if(DomainLock.Edit(on,false)!=original || DomainLock.Edit(on,true)!=on || !on.Contains("127.0.0.2 daily-cloudcode-pa.googleapis.com"))return 18;
        if(!Visible || !IsHandleCreated || !tray.Visible || urls.Length!=4 || schemes.Length!=4)return 11;
        foreach(TabPage page in pages.TabPages){
            var labels=page.Controls.Find("ProductVersion",true);
            if(labels.Length!=1 || labels[0].Text!=Application.ProductVersion)return 33;
        }
        var initialSize=ClientSize;
        foreach(int width in new[]{650,460}){
            ClientSize=new Size(width,570);PerformLayout();pages.SelectedIndex=0;pages.SelectedTab.PerformLayout();
            foreach(var control in new Control[]{verdict,status,proxyBadge,checkAddress,outcomes[0],outcomes[1],outcomes[2]}){
                pages.SelectedTab.ScrollControlIntoView(control);
                var rect=pages.SelectedTab.RectangleToClient(control.RectangleToScreen(control.ClientRectangle));
                if(rect.Width<=0 || rect.Left<0 || rect.Right>pages.SelectedTab.ClientSize.Width || rect.Bottom>pages.SelectedTab.ClientSize.Height)return 21;
            }
        }
        ClientSize=initialSize;pages.SelectedTab.AutoScrollPosition=Point.Empty;
        pages.SelectedIndex=1;ShowRouteOptions(true);
        for(int i=0;i<4;i++){
            pages.Update();
            if(!urls[i].Created || !paste[i].Created || !schemes[i].Created || paste[i].Width<60 || urls[i].Width<80)return 12;
        }
        Clipboard.SetText("socks5://demo:pass@proxy.example:8000");paste[1].PerformClick();
        if(schemes[1].Selected!="SOCKS5" || urls[1].Text!="demo:pass@proxy.example:8000")return 24;
        if(json.Serialize(Endpoint("https://proxy.example:8000:demo:p:a"))!=json.Serialize(Endpoint("https://demo:p%3Aa@proxy.example:8000")))return 25;
        pins[1]="192.0.2.1";schemes[1].Selected="HTTPS";
        if(pins[1]!=null)return 26;
        urls[1].Text="";
        pages.SelectedIndex=1;ShowRouteOptions(false);
        urls[0].Text="demo:example@proxy.example:8000";
        if(urls[0].UseSystemPasswordChar)return 27;
        reveal[0].Checked=false;if(!urls[0].UseSystemPasswordChar)return 28;reveal[0].Checked=true;
        pages.SelectedTab.PerformLayout();SaveSmokeImage("03-settings.png");
        byField[0].Checked=true;
        if(addresses[0].Text!="proxy.example:8000" || logins[0].Text!="demo" || passwords[0].Text!="example")return 30;
        passwords[0].Text="pass@:/#";var parsed=Endpoint("http://"+urls[0].Text);
        if(!ValidFields(0) || parsed.Password!="pass@:/#" || parsed.User!="demo")return 31;
        addresses[0].Text="proxy.example";if(ValidFields(0))return 32;
        addresses[0].Text="proxy.example:8000";passwords[0].Text="example";
        pages.SelectedTab.PerformLayout();SaveSmokeImage("06-separate-fields.png");byField[0].Checked=false;
        pages.SelectedIndex=2;
        connections.Update(new[]{new ConnectionPane.Flow{Domain="api.openai.com",Status="active"},new ConnectionPane.Flow{Domain="api.anthropic.com",Status="blocked",At=DateTimeOffset.UtcNow.ToUnixTimeSeconds()}},true);
        pages.SelectedTab.PerformLayout();SaveSmokeImage("05-connections.png");
        pages.SelectedIndex=0;
        leases=json.Deserialize<Dictionary<string,Reading>>("{\"Antigravity\":{\"Until\":0,\"Reason\":\"Google: NL, IPinfo: DE\"},\"Claude\":{\"Until\":201}}");
        RenderReadings(200);
        if(!outcomes[2].AccessibleDescription.Contains("Google: NL, IPinfo: DE") || !outcomes[0].Text.Contains("Можно") || !outcomes[1].Text.Contains("Проверяем"))return 19;
        RenderReadings(201);if(!outcomes[0].Text.Contains("Закрыт"))return 20;
        allowMismatch.Checked=true;
        pages.SelectedIndex=1;urls[0].Text="http://example.org:invalid";start.PerformClick();
        if(relay!=null || !status.Text.Contains("строку прокси"))return 13;
        pages.SelectedIndex=1;urls[0].Text="http://127.0.0.1:1";pins[0]="192.0.2.1"; start.PerformClick();
        if(relay==null || relay.HasExited || !File.Exists(saved) || urls[0].Enabled)return 14;
        byte[] plain=ProtectedData.Unprotect(File.ReadAllBytes(saved),null,DataProtectionScope.CurrentUser);
        if(!json.Deserialize<Route[]>(Encoding.UTF8.GetString(plain))[0].AllowGoogleCountryMismatch)return 15;
        relayReady=true;
        leases=new Dictionary<string,Reading>();
        long demoTime=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        for(int i=1;i<names.Length;i++)leases[names[i]]=new Reading{Until=demoTime+120};
        lastResult.Text="Результат в "+DateTime.Now.ToString("HH:mm");
        RenderReadings(demoTime);SaveSmokeImage("01-access-open.png");
        leases["Antigravity"]=new Reading{Until=0,Reason="Google не подтвердил страну выхода."};
        RenderReadings(demoTime);SaveSmokeImage("02-one-service-closed.png");
        if(!reasons[2].Visible || !reasons[2].Text.Contains("страну") || !status.Text.Contains("Antigravity: Google"))return 22;
        relayReady=false;protection.Checked=false;relayReady=true;RenderReadings(demoTime);
        if(!outcomes[2].Text.Contains("Есть замечание") || !checkAddress.Visible || !reasons[2].Visible)return 23;
        SaveSmokeImage("04-proxy-only-warning.png");
        leases["Antigravity"]=new Reading{Until=0,HighRisk=true,Reason="IP123 отметил высокий риск для сервиса."};RenderReadings(demoTime);
        if(!outcomes[2].Text.Contains("Высокий риск") || verdict.Text!="Высокий риск")return 37;
        SaveSmokeImage("07-proxy-only-high-risk.png");
        pages.SelectedIndex=1;
        if(byField[0].Enabled || !start.Enabled || !start.Text.Contains("Отключить"))return 34;
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
