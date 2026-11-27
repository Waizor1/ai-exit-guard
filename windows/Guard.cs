using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

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
    sealed class StorePurchaseItem {
        public string Id {get;set;}
        public string Kind {get;set;}
        public string Title {get;set;}
        public string Country {get;set;}
        public string ExpiresAt {get;set;}
        public string ProxyLine {get;set;}
        public string CardNumber {get;set;}
        public string CardExp {get;set;}
        public string CardCvc {get;set;}
        public string BillingAddress {get;set;}
        public string AccountEmail {get;set;}
        public string AccountPass {get;set;}
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
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int val, int size);
    [DllImport("uxtheme.dll", CharSet=CharSet.Unicode)] static extern int SetWindowTheme(IntPtr hwnd, string appName, string idList);
    [DllImport("user32.dll")] static extern bool DestroyIcon(IntPtr hIcon);
    WebView2 webView;
    bool webReady;
    readonly TaskCompletionSource<bool> webInitDone=new TaskCompletionSource<bool>();
    string currentStoreDetail="proxy";
    string lastWebPayload="";
    string currentTrayMood="";
    Icon customTrayIcon;
    Icon customAppIcon;
    static GraphicsPath ShieldContourPath(float cx,float topY,float w,float h){
        var p=new GraphicsPath();
        float half=w*0.5f;
        float shY=topY+h*0.16f;
        float midY=topY+h*0.48f;
        float botY=topY+h;
        p.AddLine(cx,topY,cx+half,shY);
        p.AddLine(cx+half,shY,cx+half,midY);
        p.AddBezier(cx+half,midY,cx+half,topY+h*0.76f,cx+w*0.26f,topY+h*0.92f,cx,botY);
        p.AddBezier(cx,botY,cx-w*0.26f,topY+h*0.92f,cx-half,topY+h*0.76f,cx-half,midY);
        p.AddLine(cx-half,midY,cx-half,shY);
        p.CloseFigure();
        return p;
    }
    static Icon IconFromBitmap(Bitmap bmp){
        IntPtr h=bmp.GetHicon();
        try{return (Icon)Icon.FromHandle(h).Clone();}
        finally{DestroyIcon(h);}
    }
    static Icon CreateAppIcon(){
        using(var bmp=new Bitmap(64,64))
        using(var g=Graphics.FromImage(bmp)){
            g.SmoothingMode=SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            using(var tile=RoundRect(4,4,56,56,14))
            using(var bg=new LinearGradientBrush(new Rectangle(4,4,56,56),Color.FromArgb(28,33,46),Color.FromArgb(13,15,23),90f))
            using(var rim=new Pen(Color.FromArgb(34,255,255,255),1.2f)){
                g.FillPath(bg,tile);
                g.DrawPath(rim,tile);
            }
            using(var shield=ShieldContourPath(32f,14f,30f,35f))
            using(var pen=new Pen(Color.FromArgb(238,242,248),4.2f){LineJoin=LineJoin.Round,StartCap=LineCap.Round,EndCap=LineCap.Round}){
                g.DrawPath(pen,shield);
            }
            using(var core=new SolidBrush(Color.FromArgb(56,217,158)))
                g.FillEllipse(core,26.2f,26.5f,11.6f,11.6f);
            return IconFromBitmap(bmp);
        }
    }
    static Icon CreateTrayIcon(string mood){
        using(var bmp=new Bitmap(32,32))
        using(var g=Graphics.FromImage(bmp)){
            g.SmoothingMode=SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            bool off=mood=="off";
            Color stroke=off?Color.FromArgb(145,235,238,245):Color.FromArgb(245,247,250);
            using(var shield=ShieldContourPath(16f,3.5f,21f,25f))
            using(var pen=new Pen(stroke,2.9f){LineJoin=LineJoin.Round,StartCap=LineCap.Round,EndCap=LineCap.Round}){
                g.DrawPath(pen,shield);
            }
            if(off){
                using(var p=new Pen(stroke,2.6f){StartCap=LineCap.Round,EndCap=LineCap.Round}){
                    g.DrawLine(p,13.2f,12.5f,13.2f,19.5f);
                    g.DrawLine(p,18.8f,12.5f,18.8f,19.5f);
                }
            }else{
                Color dot=Color.FromArgb(245,247,250);
                if(mood=="ok")dot=Color.FromArgb(56,217,158);
                else if(mood=="warn")dot=Color.FromArgb(250,184,36);
                else if(mood=="danger")dot=Color.FromArgb(250,86,86);
                float r=mood=="warn" || mood=="danger"?4.2f:3.7f;
                using(var b=new SolidBrush(dot))
                    g.FillEllipse(b,16f-r,15.8f-r,r*2f,r*2f);
            }
            return IconFromBitmap(bmp);
        }
    }
    void SetTrayMood(string mood){
        if(currentTrayMood==mood && customTrayIcon!=null)return;
        currentTrayMood=mood;
        Icon nextIcon=CreateTrayIcon(mood);
        tray.Icon=nextIcon;
        if(customTrayIcon!=null)customTrayIcon.Dispose();
        customTrayIcon=nextIcon;
    }
    protected override void OnHandleCreated(EventArgs e){
        base.OnHandleCreated(e);
        try{int dark=1;if(DwmSetWindowAttribute(Handle,20,ref dark,4)!=0)DwmSetWindowAttribute(Handle,19,ref dark,4);}catch{}
    }
    readonly CheckBox allowMismatch = new DarkCheckBox { Dock=DockStyle.Fill,AutoSize=true, Text="Разрешить разные страны Google и IPinfo для Antigravity" };
    sealed class Reading {
        public long Until {get;set;}
        public string Reason {get;set;}
        public bool HighRisk {get;set;}
    }
    readonly Color ink=Color.FromArgb(242,244,248), muted=Color.FromArgb(148,154,176);
    readonly Color surface=Color.FromArgb(22,23,27), card=Color.FromArgb(31,33,39), cardBorder=Color.FromArgb(45,48,57);
    readonly Color inset=Color.FromArgb(19,20,24), btnFill=Color.FromArgb(42,45,53), btnBorder=Color.FromArgb(58,62,73);
    readonly Color accent=Color.FromArgb(10,132,255);
    Font captionFont, headingFont;
    readonly Label inputFeedback = new Label{AutoSize=true,Visible=false,Dock=DockStyle.Fill};
    readonly Label[] reasons=new Label[3];
    readonly Button checkAddress=new SoftButton();
    readonly Label lastResult=new Label{Text="Адрес ещё не проверен",AutoSize=true,Anchor=AnchorStyles.Left};
    readonly Label modeHint=new Label {AutoSize=true,Dock=DockStyle.Fill};
    readonly Label patchState=new Label{AutoSize=true,Dock=DockStyle.Fill,ForeColor=Color.FromArgb(148,154,176)};
    readonly Label patchError=new Label{AutoSize=true,Dock=DockStyle.Fill,ForeColor=Color.FromArgb(255,110,105),Visible=false,Margin=new Padding(2,2,2,2)};
    Button patchButton;
    bool patchBusy;
    readonly Label updateState=new Label{AutoSize=true,Dock=DockStyle.Fill,ForeColor=Color.FromArgb(148,154,176)};
    Button updateButton;
    RoundedCard updateBanner;
    Label updateBannerText;
    Button updateBannerButton;
    bool updateBusy;
    string availableVersion="";
    readonly string savedLibrary;
    readonly List<SavedProxyItem> savedProxies=new List<SavedProxyItem>();
    RoundedCard savedProxiesCard;
    TableLayoutPanel savedProxiesList;
    readonly string savedPurchasesFile;
    readonly List<StorePurchaseItem> storePurchases=new List<StorePurchaseItem>();
    TableLayoutPanel storeDetailHost;
    Label storePurchasesCount;
    Button routeOptions;
    RoundedCard optionalRoutes;
    readonly Label proxyBadge=new Label{AutoSize=true};
    readonly Label verdict=new Label{AutoSize=true,Dock=DockStyle.Fill};
    Glyph verdictGlyph;
    RoundedCard summary;
    Button ActionButton(string title, EventHandler click) {
        var button=new SoftButton{Text=title,AutoSize=true,FlatStyle=FlatStyle.Flat,ForeColor=ink,BackColor=btnFill,BorderColor=btnBorder,Padding=new Padding(11,4,11,4)};
        button.MinimumSize=new Size(0,30);
        button.Cursor=Cursors.Hand;button.FlatAppearance.BorderSize=0;button.Click+=click;return button;
    }
    sealed class DarkMenuTable : ProfessionalColorTable {
        public override Color ToolStripDropDownBackground { get { return Color.FromArgb(26,28,34); } }
        public override Color MenuBorder { get { return Color.FromArgb(48,52,64); } }
        public override Color MenuItemBorder { get { return Color.FromArgb(10,132,255); } }
        public override Color MenuItemSelected { get { return Color.FromArgb(10,132,255); } }
        public override Color ImageMarginGradientBegin { get { return Color.FromArgb(26,28,34); } }
        public override Color ImageMarginGradientMiddle { get { return Color.FromArgb(26,28,34); } }
        public override Color ImageMarginGradientEnd { get { return Color.FromArgb(26,28,34); } }
    }
    static ContextMenuStrip DarkMenu() {
        var m=new ContextMenuStrip{BackColor=Color.FromArgb(26,28,34),ForeColor=Color.FromArgb(242,244,248),ShowImageMargin=false};
        m.Renderer=new ToolStripProfessionalRenderer(new DarkMenuTable());
        return m;
    }
    sealed class CountryPicker : SoftButton {
        readonly ContextMenuStrip menu=DarkMenu();
        public string SelectedCountry { get { return Text; } }
        public CountryPicker(string[] items){
            BackColor=Color.FromArgb(19,20,24);ForeColor=Color.FromArgb(242,244,248);
            BorderColor=Color.FromArgb(50,54,66);TextAlign=ContentAlignment.MiddleLeft;
            FlatStyle=FlatStyle.Flat;FlatAppearance.BorderSize=0;Cursor=Cursors.Hand;
            Padding=new Padding(11,4,28,4);MinimumSize=new Size(0,32);Height=32;
            foreach(string item in items){
                string label=item;
                var mi=new ToolStripMenuItem(label){ForeColor=Color.FromArgb(242,244,248)};
                mi.Click+=(s,e)=>{Text=label;Invalidate();};
                menu.Items.Add(mi);
            }
            if(items.Length>0)Text=items[0];
            Click+=(s,e)=>menu.Show(this,0,Height+2);
            Disposed+=(s,e)=>menu.Dispose();
        }
        protected override void OnPaint(PaintEventArgs e){
            base.OnPaint(e);
            int cx=Width-15,cy=Height/2;
            e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
            using(var pen=new Pen(Color.FromArgb(148,154,176),1.6f){StartCap=LineCap.Round,EndCap=LineCap.Round,LineJoin=LineJoin.Round})
                e.Graphics.DrawLines(pen,new[]{new Point(cx-4,cy-2),new Point(cx,cy+2),new Point(cx+4,cy-2)});
        }
    }
    static GraphicsPath RoundRect(int x,int y,int w,int h,int radius){
        var path=new GraphicsPath();
        int d=Math.Min(Math.Min(w,h),radius*2);
        if(d<1){path.AddRectangle(new Rectangle(x,y,w,h));return path;}
        path.AddArc(x,y,d,d,180,90);path.AddArc(x+w-d,y,d,d,270,90);
        path.AddArc(x+w-d,y+h-d,d,d,0,90);path.AddArc(x,y+h-d,d,d,90,90);path.CloseFigure();
        return path;
    }
    static Color EffectiveBackColor(Control control,Color fallback){
        for(var p=control;p!=null;p=p.Parent)if(p.BackColor.A>0)return p.BackColor;
        return fallback;
    }
    static void PaintSurface(Control control,Graphics g,Color fill,Color border,int radius){
        int w=control.Width-1,h=control.Height-1;
        if(w<1 || h<1)return;
        g.Clear(EffectiveBackColor(control.Parent,fill));
        g.SmoothingMode=SmoothingMode.AntiAlias;
        using(var path=RoundRect(0,0,w,h,radius)){
            using(var brush=new SolidBrush(fill))g.FillPath(brush,path);
            if(border.A>0){using(var pen=new Pen(border,1f))g.DrawPath(pen,path);}
        }
    }
    sealed class RoundedCard : TableLayoutPanel {
        public Color BorderColor=Color.FromArgb(45,48,57);
        public int Radius=12;
        public RoundedCard(){DoubleBuffered=true;}
        protected override void OnPaintBackground(PaintEventArgs e){PaintSurface(this,e.Graphics,BackColor,BorderColor,Radius);}
    }
    enum Mark { Shield, Sun, Chat, Stars, Bolt, Globe, Arrows, CheckCircle, Warn }
    sealed class Glyph : Control {
        public Mark CurrentMark;
        public Glyph(Mark mark,Color color){
            CurrentMark=mark;ForeColor=color;Size=new Size(20,20);Margin=new Padding(0,4,8,0);
            TabStop=false;AccessibleRole=AccessibleRole.None;
            SetStyle(ControlStyles.OptimizedDoubleBuffer|ControlStyles.AllPaintingInWmPaint|ControlStyles.UserPaint,true);
        }
        protected override void OnPaint(PaintEventArgs e){
            e.Graphics.Clear(EffectiveBackColor(Parent,BackColor));
            Graphics g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;
            float scale=Math.Min(ClientSize.Width,ClientSize.Height)/24f;g.ScaleTransform(scale,scale);
            using(var pen=new Pen(ForeColor,1.8f){StartCap=LineCap.Round,EndCap=LineCap.Round,LineJoin=LineJoin.Round})
            using(var brush=new SolidBrush(ForeColor)){
                if(CurrentMark==Mark.Shield){
                    g.DrawPolygon(pen,new[]{new Point(12,2),new Point(21,6),new Point(20,14),new Point(17,18),new Point(12,22),new Point(7,18),new Point(4,14),new Point(3,6)});
                    g.DrawLines(pen,new[]{new Point(7,11),new Point(11,15),new Point(17,8)});
                }else if(CurrentMark==Mark.CheckCircle){
                    g.FillEllipse(brush,2,2,20,20);
                    using(var chk=new Pen(Color.FromArgb(18,30,22),2.3f){StartCap=LineCap.Round,EndCap=LineCap.Round,LineJoin=LineJoin.Round})
                        g.DrawLines(chk,new[]{new PointF(7.5f,12.2f),new PointF(10.6f,15.3f),new PointF(16.6f,9.0f)});
                }else if(CurrentMark==Mark.Warn){
                    g.FillPolygon(brush,new[]{new PointF(12,2.5f),new PointF(22,20.5f),new PointF(2,20.5f)});
                    using(var ex=new Pen(Color.FromArgb(30,24,14),2.1f){StartCap=LineCap.Round})
                        g.DrawLine(ex,12,9,12,14.5f);
                    using(var dot=new SolidBrush(Color.FromArgb(30,24,14)))
                        g.FillEllipse(dot,10.8f,16.5f,2.4f,2.4f);
                }else if(CurrentMark==Mark.Bolt){
                    g.DrawPolygon(pen,new[]{new Point(12,2),new Point(21,6),new Point(20,14),new Point(17,18),new Point(12,22),new Point(7,18),new Point(4,14),new Point(3,6)});
                    g.FillPolygon(brush,new[]{new Point(13,6),new Point(8,13),new Point(12,13),new Point(11,18),new Point(16,11),new Point(12,11)});
                }else if(CurrentMark==Mark.Globe){
                    g.DrawEllipse(pen,3,3,18,18);
                    g.DrawEllipse(pen,8,3,8,18);
                    g.DrawLine(pen,3,12,21,12);
                }else if(CurrentMark==Mark.Arrows){
                    g.DrawLine(pen,5,9,19,9);g.DrawLines(pen,new[]{new Point(15,5),new Point(19,9),new Point(15,13)});
                    g.DrawLine(pen,19,15,5,15);g.DrawLines(pen,new[]{new Point(9,11),new Point(5,15),new Point(9,19)});
                }else if(CurrentMark==Mark.Sun){
                    g.FillEllipse(brush,7,7,10,10);
                    for(int i=0;i<8;i++){
                        double a=i*Math.PI/4;float x=(float)Math.Cos(a),y=(float)Math.Sin(a);
                        g.DrawLine(pen,12+7*x,12+7*y,12+10*x,12+10*y);
                    }
                }else if(CurrentMark==Mark.Chat){
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
    class SoftButton : Button {
        public Color BorderColor=Color.Transparent;
        public SoftButton(){DoubleBuffered=true;}
        protected override void OnPaint(PaintEventArgs e){
            bool hover=Enabled && ClientRectangle.Contains(PointToClient(MousePosition));
            Color fill=Enabled?BackColor:Color.FromArgb(30,32,39);
            Color border=Enabled?BorderColor:Color.FromArgb(42,45,55);
            PaintSurface(this,e.Graphics,hover?ControlPaint.Light(fill,.14f):fill,border,7);
            var alignment=TextAlign==ContentAlignment.MiddleLeft?TextFormatFlags.Left:TextFormatFlags.HorizontalCenter;
            var rect=new Rectangle(Padding.Left,0,Math.Max(0,Width-Padding.Left-Padding.Right),Height);
            TextRenderer.DrawText(e.Graphics,Text,Font,rect,Enabled?ForeColor:Color.FromArgb(95,101,119),alignment|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis|TextFormatFlags.NoPadding);
            if(Focused && ShowFocusCues)ControlPaint.DrawFocusRectangle(e.Graphics,Rectangle.Inflate(ClientRectangle,-4,-4),ForeColor,BackColor);
        }
    }
    sealed class DarkCheckBox : CheckBox {
        public DarkCheckBox(){
            AutoSize=true;Cursor=Cursors.Hand;ForeColor=Color.FromArgb(220,224,232);
            SetStyle(ControlStyles.UserPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.AllPaintingInWmPaint|ControlStyles.ResizeRedraw,true);
        }
        public override Size GetPreferredSize(Size proposedSize){
            var sz=TextRenderer.MeasureText(Text,Font);
            return new Size(sz.Width+26,Math.Max(22,sz.Height+4));
        }
        protected override void OnPaint(PaintEventArgs e){
            Color bg=EffectiveBackColor(Parent,Color.FromArgb(31,33,39));
            e.Graphics.Clear(bg);
            e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
            int box=15,y=(Height-box)/2;
            Color fill=Checked?Color.FromArgb(10,132,255):Color.FromArgb(19,20,24);
            Color border=Checked?Color.FromArgb(10,132,255):Color.FromArgb(68,73,88);
            if(!Enabled){fill=Color.FromArgb(37,39,46);border=Color.FromArgb(52,55,65);}
            using(var path=RoundRect(1,y,box,box,4)){
                using(var brush=new SolidBrush(fill))e.Graphics.FillPath(brush,path);
                using(var pen=new Pen(border,1f))e.Graphics.DrawPath(pen,path);
            }
            if(Checked){
                using(var pen=new Pen(Color.White,1.9f){StartCap=LineCap.Round,EndCap=LineCap.Round,LineJoin=LineJoin.Round})
                    e.Graphics.DrawLines(pen,new[]{new PointF(4.5f,y+7.8f),new PointF(7.2f,y+10.5f),new PointF(12.2f,y+4.8f)});
            }
            var textRect=new Rectangle(23,0,Math.Max(0,Width-23),Height);
            TextRenderer.DrawText(e.Graphics,Text,Font,textRect,Enabled?ForeColor:Color.FromArgb(108,114,128),TextFormatFlags.Left|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
        }
    }
    sealed class ProtocolPicker : TableLayoutPanel {
        public static readonly string[] Choices={"HTTP","HTTPS","SOCKS5"};
        public event EventHandler Changed;
        public string Selected {
            get{foreach(RadioButton b in Controls)if(b.Checked)return b.Text;return Choices[0];}
            set{foreach(RadioButton b in Controls)if(b.Text==value)b.Checked=true;}
        }
        sealed class Segment : RadioButton {
            public Segment(){
                Appearance=Appearance.Button;AutoSize=true;Dock=DockStyle.Fill;FlatStyle=FlatStyle.Flat;
                Margin=new Padding(2);Padding=new Padding(4,5,4,5);Cursor=Cursors.Hand;
                SetStyle(ControlStyles.UserPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.AllPaintingInWmPaint|ControlStyles.ResizeRedraw,true);
            }
            protected override void OnPaint(PaintEventArgs e){
                e.Graphics.Clear(Color.FromArgb(19,20,24));
                e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
                if(Checked){
                    using(var path=RoundRect(0,0,Width-1,Height-1,6)){
                        using(var brush=new SolidBrush(Color.FromArgb(52,56,68)))e.Graphics.FillPath(brush,path);
                        using(var pen=new Pen(Color.FromArgb(72,77,92),1f))e.Graphics.DrawPath(pen,path);
                    }
                }
                TextRenderer.DrawText(e.Graphics,Text,Font,ClientRectangle,Checked?Color.White:Color.FromArgb(148,154,176),TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter);
            }
        }
        protected override void OnPaintBackground(PaintEventArgs e){
            PaintSurface(this,e.Graphics,Color.FromArgb(19,20,24),Color.FromArgb(45,48,57),8);
        }
        public ProtocolPicker(){
            DoubleBuffered=true;AutoSize=true;Dock=DockStyle.Fill;ColumnCount=3;Padding=new Padding(2);Margin=new Padding(0,3,0,8);
            foreach(string choice in Choices){
                ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100f/3));
                var b=new Segment{Text=choice};
                b.CheckedChanged+=(sender,e)=>{b.Invalidate();if(b.Checked && Changed!=null)Changed(this,e);};
                Controls.Add(b);
            }
            Selected=Choices[0];
        }
    }
    RoundedCard Card() {
        var panel=new RoundedCard {AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Dock=DockStyle.Top,ColumnCount=1,BackColor=card,BorderColor=cardBorder,Padding=new Padding(14,10,14,10),Margin=new Padding(0,5,0,5)};
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));return panel;
    }
    readonly TabControl pages=new TabControl { Dock=DockStyle.Fill };
    TableLayoutPanel Page(string title) {
        var tab=new TabPage(title){ForeColor=ink,BackColor=surface,AutoScroll=true};
        tab.HandleCreated+=(s,e)=>{try{SetWindowTheme(tab.Handle,"DarkMode_Explorer",null);}catch{}};
        var grid=new TableLayoutPanel {AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Dock=DockStyle.Top,ColumnCount=1,Padding=new Padding(16,10,16,16)};
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        tab.Controls.Add(grid);pages.TabPages.Add(tab);
        var header=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=3,Margin=new Padding(0,0,0,6)};
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        if(pages.TabCount>1)header.Controls.Add(ActionButton("←  Назад",(s,e)=>pages.SelectedIndex=0),0,0);
        var identity=new FlowLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,Margin=Padding.Empty,WrapContents=true};
        var name=Copy("AI Exit Guard",true);
        name.Margin=new Padding(2,6,4,4);
        if(pages.TabCount==1)identity.Controls.Add(new Glyph(Mark.Shield,ink));
        identity.Controls.Add(name);
        var version=Copy(Application.ProductVersion,false);version.Name="ProductVersion";
        version.Font=captionFont;
        version.AccessibleName="Версия "+version.Text;version.Margin=new Padding(2,8,2,4);
        identity.Controls.Add(version);header.Controls.Add(identity,1,0);
        if(pages.TabCount==1){
            var topBtns=new FlowLayoutPanel{AutoSize=true,Margin=Padding.Empty,WrapContents=false,Anchor=AnchorStyles.Right,BackColor=Color.Transparent};
            var shopBtn=ActionButton("Магазин",(sender,e)=>pages.SelectedIndex=4);
            shopBtn.BackColor=Color.FromArgb(24,42,68);((SoftButton)shopBtn).BorderColor=Color.FromArgb(46,84,136);shopBtn.ForeColor=Color.FromArgb(115,184,255);
            shopBtn.Margin=new Padding(0,0,6,0);
            var gear=ActionButton("Настройки",(sender,e)=>pages.SelectedIndex=3);
            gear.Margin=Padding.Empty;
            topBtns.Controls.Add(shopBtn);topBtns.Controls.Add(gear);
            header.Controls.Add(topBtns,2,0);
        }
        grid.Controls.Add(header);
        return grid;
    }
    Label Copy(string text,bool heading) {
        return new Label {Text=text,AutoSize=true,Dock=DockStyle.Fill,ForeColor=heading?ink:muted,
            Font=heading?(headingFont??Font):(captionFont??Font),Margin=new Padding(2,heading?6:2,2,2)};
    }
    RoundedCard EntryBox(TextBox input){
        var box=new RoundedCard{Dock=DockStyle.Fill,AutoSize=true,ColumnCount=1,BackColor=inset,BorderColor=Color.FromArgb(50,54,66),Radius=8,Padding=new Padding(10,7,10,7),Margin=new Padding(0,4,0,6)};
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
        paste[i].BackColor=btnFill;paste[i].AccessibleName="Вставить прокси — "+names[i];
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
        reveal[i]=new DarkCheckBox{Text="Показывать строку",Checked=true,Dock=DockStyle.Fill,Margin=new Padding(0,4,0,0)};
        var parts=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Top,ColumnCount=1,Margin=Padding.Empty,Visible=false};
        parts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        addresses[i]=AddEntry(parts,"Адрес и порт",i);
        logins[i]=AddEntry(parts,"Логин",i);passwords[i]=AddEntry(parts,"Пароль",i);
        slot.Controls.Add(parts);
        byField[i]=new DarkCheckBox{Text="Ввести по полям",Anchor=AnchorStyles.Right};
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
        savedPurchasesFile=Path.Combine(dataDirectory,"store-purchases.bin");
        Text="AI Exit Guard"; Font=new Font("Segoe UI",9.5F);
        captionFont=new Font("Segoe UI",8.5F);
        headingFont=new Font("Segoe UI Semibold",10F);
        AutoScaleDimensions=new SizeF(96,96);AutoScaleMode=AutoScaleMode.Dpi;
        ClientSize=new Size(450,Math.Min(785,Screen.FromControl(this).WorkingArea.Height-40));MinimumSize=new Size(390,440);BackColor=surface;ForeColor=ink;
        pages.Appearance=TabAppearance.FlatButtons;pages.SizeMode=TabSizeMode.Fixed;pages.ItemSize=new Size(0,1);pages.TabStop=false;
        Controls.Add(pages);
        var home=Page("Главная");var settings=Page("Прокси");
        summary=Card();summary.Padding=new Padding(14,10,14,10);
        var heroRow=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=2,Margin=Padding.Empty,BackColor=Color.Transparent};
        heroRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));heroRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        verdictGlyph=new Glyph(Mark.Shield,ink);verdictGlyph.Size=new Size(22,22);verdictGlyph.Anchor=AnchorStyles.Left;verdictGlyph.Margin=new Padding(0,2,9,0);
        heroRow.Controls.Add(verdictGlyph,0,0);
        verdict.Font=new Font("Segoe UI Semibold",15.5F);verdict.Margin=new Padding(0,0,0,1);heroRow.Controls.Add(verdict,1,0);
        summary.Controls.Add(heroRow);
        status.AccessibleName="Причина текущего состояния";status.Dock=DockStyle.Fill;status.Margin=new Padding(0,2,0,1);status.ForeColor=muted;status.Font=captionFont;summary.Controls.Add(status);home.Controls.Add(summary);
        var results=Card();results.ColumnCount=3;results.ColumnStyles.Clear();results.Padding=new Padding(14,9,14,9);
        results.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));results.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,44));results.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,56));
        var services=Copy("Сервисы",true);services.Font=captionFont;services.Margin=new Padding(0,0,0,5);services.ForeColor=muted;
        results.Controls.Add(services,0,0);results.SetColumnSpan(services,3);
        var marks=new[]{Mark.Sun,Mark.Chat,Mark.Stars};
        var colors=new[]{Color.FromArgb(255,159,10),Color.FromArgb(48,209,176),Color.FromArgb(165,148,255)};
        for(int i=0;i<3;i++){
            int row=1+3*i;
            var name=Copy(names[i+1],true);
            results.Controls.Add(new Glyph(marks[i],colors[i]),0,row);
            name.Margin=new Padding(0,4,2,1);results.Controls.Add(name,1,row);
            outcomes[i]=Copy("",false);outcomes[i].AccessibleName=names[i+1]+" — статус";
            outcomes[i].Font=new Font("Segoe UI Semibold",9F);
            outcomes[i].TextAlign=ContentAlignment.MiddleRight;outcomes[i].Margin=new Padding(2,4,0,1);
            results.Controls.Add(outcomes[i],2,row);
            reasons[i]=Copy("",false);reasons[i].Margin=new Padding(0,0,0,5);
            results.Controls.Add(reasons[i],1,row+1);results.SetColumnSpan(reasons[i],2);
            if(i<2){
                var divider=new Panel{Height=1,Dock=DockStyle.Top,Margin=new Padding(0,1,0,2),BackColor=cardBorder};
                results.Controls.Add(divider,0,row+2);results.SetColumnSpan(divider,3);
            }
        }
        home.Controls.Add(results);
        var proxyCard=Card();proxyCard.Padding=new Padding(14,9,14,9);
        var proxyHeader=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=4,Margin=new Padding(0,0,0,4),Cursor=Cursors.Hand,BackColor=Color.Transparent};
        proxyHeader.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        proxyHeader.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        proxyHeader.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        proxyHeader.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var proxyIcon=new Glyph(Mark.Globe,muted);proxyIcon.Size=new Size(18,18);proxyIcon.Margin=new Padding(0,3,8,0);
        var edit=Copy("Добавить прокси",true);edit.Margin=new Padding(0,2,4,2);edit.Cursor=Cursors.Hand;
        proxyBadge.ForeColor=muted;proxyBadge.Font=captionFont;proxyBadge.Margin=new Padding(4,3,4,2);proxyBadge.Cursor=Cursors.Hand;
        var proxyChev=Copy("›",false);proxyChev.Font=new Font("Segoe UI",11F);proxyChev.Anchor=AnchorStyles.Right;proxyChev.Margin=new Padding(0,1,0,2);proxyChev.Cursor=Cursors.Hand;
        EventHandler openProxy=(sender,e)=>pages.SelectedIndex=1;
        proxyHeader.Click+=openProxy;proxyIcon.Click+=openProxy;edit.Click+=openProxy;proxyBadge.Click+=openProxy;proxyChev.Click+=openProxy;
        proxyHeader.Controls.Add(proxyIcon,0,0);proxyHeader.Controls.Add(edit,1,0);proxyHeader.Controls.Add(proxyBadge,2,0);proxyHeader.Controls.Add(proxyChev,3,0);
        proxyCard.Controls.Add(proxyHeader);
        proxyCard.Controls.Add(new Panel{Height=1,Dock=DockStyle.Top,Margin=new Padding(0,2,0,4),BackColor=cardBorder});
        protection.ForeColor=ink;protection.BackColor=card;protection.Font=headingFont;protection.Margin=new Padding(0,0,0,0);proxyCard.Controls.Add(protection);
        modeHint.ForeColor=muted;modeHint.Font=captionFont;modeHint.Margin=new Padding(0,0,0,2);
        proxyCard.Controls.Add(modeHint);home.Controls.Add(proxyCard);
        protection.CheckedChanged+=(sender,e)=>{
            UpdateModeHint();
            if(relayReady){Stop();Connect();}
        };
        UpdateModeHint();
        start.Text="Подключить прокси";start.AutoSize=true;start.Padding=new Padding(14,5,14,5);start.MinimumSize=new Size(0,32);start.Margin=new Padding(0,6,0,4);
        start.BackColor=accent;start.ForeColor=Color.White;start.Font=headingFont;start.FlatStyle=FlatStyle.Flat;start.FlatAppearance.BorderSize=0;
        start.Click+=(s,e)=>{
            if(relay!=null || retrying){Disconnect();if(relay!=null)pages.SelectedIndex=0;return;}
            Connect();
        };
        var activity=Page("Подключения");
        var connectionsTitle=Copy("Активные подключения",true);connectionsTitle.Font=new Font("Segoe UI Semibold",14.5F);activity.Controls.Add(connectionsTitle);
        var feed=Card();activity.Controls.Add(feed);connections=new ConnectionPane(feed,card,ink);
        EventHandler openFlows=(s,e)=>{pages.SelectedIndex=2;nextFlows=DateTime.MinValue;};
        var activityCard=Card();activityCard.Padding=new Padding(14,8,14,8);activityCard.ColumnCount=3;activityCard.ColumnStyles.Clear();activityCard.Cursor=Cursors.Hand;
        activityCard.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));activityCard.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));activityCard.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var actIcon=new Glyph(Mark.Arrows,muted);actIcon.Size=new Size(18,18);actIcon.Margin=new Padding(0,3,8,0);
        var actTitle=Copy("Активные подключения",true);actTitle.Margin=new Padding(0,2,4,2);actTitle.Cursor=Cursors.Hand;
        var actChev=Copy("›",false);actChev.Font=new Font("Segoe UI",11F);actChev.Anchor=AnchorStyles.Right;actChev.Margin=new Padding(0,1,0,2);actChev.Cursor=Cursors.Hand;
        activityCard.Click+=openFlows;actIcon.Click+=openFlows;actTitle.Click+=openFlows;actChev.Click+=openFlows;
        activityCard.Controls.Add(actIcon,0,0);activityCard.Controls.Add(actTitle,1,0);activityCard.Controls.Add(actChev,2,0);
        home.Controls.Add(activityCard);
        var vectraCard=Card();vectraCard.Padding=new Padding(14,9,14,9);vectraCard.BackColor=Color.FromArgb(20,30,46);vectraCard.BorderColor=Color.FromArgb(38,60,92);vectraCard.ColumnCount=3;vectraCard.ColumnStyles.Clear();
        vectraCard.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));vectraCard.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));vectraCard.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var vectraGlyph=new Glyph(Mark.Bolt,Color.FromArgb(56,152,255));vectraGlyph.Size=new Size(22,22);vectraGlyph.Anchor=AnchorStyles.None;vectraGlyph.Margin=new Padding(0,0,10,0);
        vectraCard.Controls.Add(vectraGlyph,0,0);
        var vectraTitle=Copy("Vectra Connect",true);vectraTitle.Margin=new Padding(0,0,4,1);
        var vectraSub=Copy("Лучший VPN-сервис для быстрой и стабильной работы",false);vectraSub.Margin=new Padding(0,0,4,0);
        var vectraText=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=1,Margin=Padding.Empty,BackColor=Color.Transparent};
        vectraText.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        vectraText.Controls.Add(vectraTitle);vectraText.Controls.Add(vectraSub);
        vectraCard.Controls.Add(vectraText,1,0);
        var vectraOpen=ActionButton("Открыть",(sender,e)=>{try{Process.Start(new ProcessStartInfo("https://pay.vectra-pro.net/store"){UseShellExecute=true});}catch{}});
        vectraOpen.BackColor=Color.FromArgb(34,52,78);((SoftButton)vectraOpen).BorderColor=Color.FromArgb(58,86,128);vectraOpen.Anchor=AnchorStyles.Right;
        vectraCard.Controls.Add(vectraOpen,2,0);
        home.Controls.Add(vectraCard);
        updateBanner=Card();updateBanner.BackColor=Color.FromArgb(23,36,56);updateBanner.BorderColor=Color.FromArgb(40,68,108);updateBanner.ColumnCount=2;updateBanner.ColumnStyles.Clear();
        updateBanner.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));updateBanner.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        updateBannerText=Copy("Доступно обновление",true);updateBannerText.Margin=new Padding(2,4,6,4);
        updateBanner.Controls.Add(updateBannerText,0,0);
        updateBannerButton=ActionButton("Обновить",(sender,e)=>RunAppUpdate("install"));
        updateBannerButton.BackColor=accent;updateBannerButton.ForeColor=Color.White;((SoftButton)updateBannerButton).BorderColor=Color.Transparent;
        updateBanner.Controls.Add(updateBannerButton,1,0);
        updateBanner.Visible=false;home.Controls.Add(updateBanner);
        var actions=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=2,Margin=new Padding(0,4,0,0)};
        actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));actions.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        lastResult.ForeColor=muted;lastResult.Font=captionFont;actions.Controls.Add(lastResult,0,0);
        checkAddress.Text="Проверить адрес";checkAddress.AutoSize=true;checkAddress.FlatStyle=FlatStyle.Flat;
        checkAddress.BackColor=accent;checkAddress.ForeColor=Color.White;checkAddress.Font=headingFont;checkAddress.FlatAppearance.BorderSize=0;checkAddress.Padding=new Padding(13,5,13,5);checkAddress.MinimumSize=new Size(0,32);
        checkAddress.Margin=new Padding(6,2,0,2);checkAddress.Enabled=false;
        checkAddress.Click+=(sender,e)=>{
            if(!relayReady || !checkAddress.Enabled)return;
            try{relay.StandardInput.WriteLine("check");relay.StandardInput.Flush();checkAddress.Enabled=false;checkAddress.Text="Проверяем…";}
            catch(IOException){RelayEnded();}
        };
        actions.Controls.Add(checkAddress,1,0);home.Controls.Add(actions);
        var heading=Copy("Общий прокси",true);heading.Font=new Font("Segoe UI Semibold",14.5F);heading.Margin=new Padding(2,2,2,4);settings.Controls.Add(heading);inputFeedback.ForeColor=Color.FromArgb(255,159,10);settings.Controls.Add(inputFeedback);ProxyInputs(settings,0);
        savedProxiesCard=Card();
        savedProxiesCard.Controls.Add(Copy("Сохранённые прокси",true));
        savedProxiesList=new TableLayoutPanel{AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Dock=DockStyle.Top,ColumnCount=1,Margin=Padding.Empty};
        savedProxiesList.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        savedProxiesCard.Controls.Add(savedProxiesList);
        savedProxiesCard.Visible=false;
        settings.Controls.Add(savedProxiesCard);
        var buyLinkCard=Card();buyLinkCard.Padding=new Padding(14,8,14,8);buyLinkCard.ColumnCount=3;buyLinkCard.ColumnStyles.Clear();buyLinkCard.Cursor=Cursors.Hand;
        buyLinkCard.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));buyLinkCard.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));buyLinkCard.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var buyIcon=new Glyph(Mark.Globe,Color.FromArgb(77,163,255));buyIcon.Size=new Size(18,18);buyIcon.Margin=new Padding(0,3,8,0);
        var buyLbl=Copy("Купить чистый прокси",true);buyLbl.Margin=new Padding(0,2,4,2);buyLbl.Cursor=Cursors.Hand;
        var buyChev=Copy("›",false);buyChev.Font=new Font("Segoe UI",11F);buyChev.Anchor=AnchorStyles.Right;buyChev.Margin=new Padding(0,1,0,2);buyChev.Cursor=Cursors.Hand;
        EventHandler openBuy=(s,e)=>OpenStoreDetail("proxy");
        buyLinkCard.Click+=openBuy;buyIcon.Click+=openBuy;buyLbl.Click+=openBuy;buyChev.Click+=openBuy;
        buyLinkCard.Controls.Add(buyIcon,0,0);buyLinkCard.Controls.Add(buyLbl,1,0);buyLinkCard.Controls.Add(buyChev,2,0);
        settings.Controls.Add(buyLinkCard);
        urls[0].TextChanged+=(s,e)=>edit.Text=String.IsNullOrWhiteSpace(urls[0].Text)?"Добавить прокси":"Прокси";
        start.Anchor=AnchorStyles.Right;
        var fields=(TableLayoutPanel)paste[0].Parent;
        fields.Controls.Add(start,1,4);
        routeOptions=ActionButton("Отдельные прокси  ▸",(sender,e)=>ShowRouteOptions(!optionalRoutes.Visible));
        routeOptions.Margin=new Padding(0,4,0,4);
        settings.Controls.Add(routeOptions);
        optionalRoutes=Card();settings.Controls.Add(optionalRoutes);
        for(int i=1;i<4;i++){optionalRoutes.Controls.Add(Copy(names[i],true));ProxyInputs(optionalRoutes,i);}
        optionalRoutes.Controls.Add(allowMismatch);optionalRoutes.Visible=false;
        var appSettings=Page("Настройки");
        var appSettingsTitle=Copy("Настройки",true);appSettingsTitle.Font=new Font("Segoe UI Semibold",14.5F);appSettingsTitle.Margin=new Padding(2,2,2,6);appSettings.Controls.Add(appSettingsTitle);
        dns.Text="Убрать прежнее правило доменов";dns.AutoSize=true;
        dns.Visible=!smoke && DomainRulesPresent() && !File.Exists(ownedDomains);
        dns.Click+=(sender,e)=>{try{SetDomains(false);dns.Visible=false;}catch{State("Windows не сняла правило доменов.",false);}};
        appSettings.Controls.Add(dns);
        var patchCard=Card();patchCard.ColumnCount=2;patchCard.ColumnStyles.Clear();
        patchCard.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));patchCard.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var patchLeft=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=1,Margin=Padding.Empty,BackColor=Color.Transparent};
        patchLeft.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        patchLeft.Controls.Add(Copy("Патч Antigravity",true));
        patchState.Font=captionFont;patchState.Margin=new Padding(2,1,2,2);
        patchLeft.Controls.Add(patchState);
        patchError.Font=captionFont;
        patchLeft.Controls.Add(patchError);
        patchCard.Controls.Add(patchLeft,0,0);
        patchButton=ActionButton("Проверить",(sender,e)=>{});
        patchButton.Anchor=AnchorStyles.Right;patchButton.Enabled=false;
        patchButton.Click+=(sender,e)=>{if(!patchBusy)RunAntigravity(patchButton.Text=="Восстановить"?"restore":"patch");};
        patchCard.Controls.Add(patchButton,1,0);
        appSettings.Controls.Add(patchCard);
        var updateCard=Card();updateCard.ColumnCount=2;updateCard.ColumnStyles.Clear();
        updateCard.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));updateCard.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var updateLeft=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=1,Margin=Padding.Empty,BackColor=Color.Transparent};
        updateLeft.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        updateLeft.Controls.Add(Copy("Обновления Guard",true));
        updateState.Font=captionFont;updateState.Text="Версия "+Application.ProductVersion;updateState.Margin=new Padding(2,1,2,2);
        updateLeft.Controls.Add(updateState);
        updateCard.Controls.Add(updateLeft,0,0);
        updateButton=ActionButton("Проверить",(sender,e)=>RunAppUpdate(String.IsNullOrEmpty(availableVersion)?"check":"install"));
        updateButton.Anchor=AnchorStyles.Right;
        updateCard.Controls.Add(updateButton,1,0);
        appSettings.Controls.Add(updateCard);
        var quitBtn=ActionButton("Завершить AI Exit Guard",(s,e)=>{quitting=true;Close();});
        quitBtn.Margin=new Padding(0,8,0,0);
        appSettings.Controls.Add(quitBtn);
        var storePage=Page("Магазин");
        var storeTitle=Copy("Магазин",true);storeTitle.Font=new Font("Segoe UI Semibold",15F);storeTitle.Margin=new Padding(2,2,2,6);
        storePage.Controls.Add(storeTitle);
        var storeGroup=Card();storeGroup.Padding=new Padding(14,4,14,4);
        storeGroup.Controls.Add(StoreMenuRow(Mark.Globe,Color.FromArgb(77,163,255),"Чистый прокси","Статический IP без скачков и банов",null,(s,e)=>OpenStoreDetail("proxy")));
        storeGroup.Controls.Add(new Panel{Height=1,Dock=DockStyle.Top,Margin=new Padding(0,2,0,2),BackColor=cardBorder});
        storeGroup.Controls.Add(StoreMenuRow(Mark.Bolt,Color.FromArgb(77,163,255),"Карта Vectra Pay","Для оплаты Claude, ChatGPT и Cursor",null,(s,e)=>OpenStoreDetail("card")));
        storeGroup.Controls.Add(new Panel{Height=1,Dock=DockStyle.Top,Margin=new Padding(0,2,0,2),BackColor=cardBorder});
        storeGroup.Controls.Add(StoreMenuRow(Mark.Stars,Color.FromArgb(255,179,64),"Аккаунт Claude","Верифицированный · можно сразу с IP",null,(s,e)=>OpenStoreDetail("claude")));
        storePage.Controls.Add(storeGroup);
        var purchasesGroup=Card();purchasesGroup.Padding=new Padding(14,4,14,4);
        storePurchasesCount=Copy("",false);storePurchasesCount.Anchor=AnchorStyles.Right;storePurchasesCount.Margin=new Padding(0,2,4,2);
        purchasesGroup.Controls.Add(StoreMenuRow(Mark.CheckCircle,Color.FromArgb(76,224,101),"Мои покупки","Карты, аккаунты и прокси",storePurchasesCount,(s,e)=>OpenStoreDetail("purchases")));
        storePage.Controls.Add(purchasesGroup);
        var storeDetailPage=Page("Детали");
        storeDetailHost=new TableLayoutPanel{AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Dock=DockStyle.Top,ColumnCount=1,Margin=Padding.Empty,BackColor=Color.Transparent};
        storeDetailHost.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        storeDetailPage.Controls.Add(storeDetailHost);
        LoadStorePurchases();
        LoadSavedProxies();
        Shown+=(sender,e)=>{if(!smokeMode)RunAppUpdate("check");};
        pages.SelectedIndexChanged+=(sender,e)=>{if(pages.SelectedIndex==3 && !patchBusy)RunAntigravity("status");};
        ShowIdle("Выключен");
        tray.Visible=true; tray.MouseClick+=(s,e)=>{if(e.Button==MouseButtons.Left)ShowWindow();};
        customAppIcon=CreateAppIcon();
        this.Icon=customAppIcon;
        SetTrayMood("off");
        var menu=new ContextMenuStrip();menu.Items.Add("Открыть",null,(s,e)=>ShowWindow());
        menu.Items.Add("Активные подключения",(Image)null,(s,e)=>{ShowWindow();openFlows(s,e);});menu.Items.Add("Выход",null,(s,e)=>{quitting=true;Close();});tray.ContextMenuStrip=menu;
        FormClosing+=(s,e)=>{if(!quitting && e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();return;}
            if(ProxyOnly && !ReleaseDomains()){quitting=false;e.Cancel=true;ShowWindow();}};
        FormClosed+=(s,e)=>{timer.Stop();Stop();if(webView!=null){try{webView.Dispose();}catch{}webView=null;}tray.Dispose();if(customTrayIcon!=null)customTrayIcon.Dispose();if(customAppIcon!=null)customAppIcon.Dispose();detail.Dispose();};
        timer.Interval=350;timer.Tick+=(s,e)=>{Poll();SyncWebUi(false);};timer.Start();
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
        InitWebUi(dataDirectory);
        ResumeLayout(true);
    }
    async void InitWebUi(string dataDirectory){
        try{
            webView=new WebView2{Dock=DockStyle.Fill,Visible=false,DefaultBackgroundColor=Color.FromArgb(28,28,30)};
            Controls.Add(webView);
            webView.BringToFront();
            string udfs=Path.Combine(dataDirectory,"webview2");
            var env=await CoreWebView2Environment.CreateAsync(null,udfs);
            await webView.EnsureCoreWebView2Async(env);
            if(IsDisposed || Disposing){webInitDone.TrySetResult(false);return;}
            var s=webView.CoreWebView2.Settings;
            s.AreDefaultContextMenusEnabled=false;
            s.AreDevToolsEnabled=false;
            s.IsStatusBarEnabled=false;
            s.IsZoomControlEnabled=false;
            webView.CoreWebView2.WebMessageReceived+=(sender,args)=>{
                try{HandleWebMessage(args.WebMessageAsJson);}catch{}
            };
            string html="";
            using(var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("guard-ui.html"))
            using(var reader=new StreamReader(stream,Encoding.UTF8))
                html=reader.ReadToEnd();
            webView.NavigateToString(html);
        }catch{
            if(webView!=null && !webView.IsDisposed)webView.Visible=false;
            webInitDone.TrySetResult(false);
        }
    }
    string CurrentPageKey(){
        switch(pages.SelectedIndex){
            case 1:return "proxy";
            case 2:return "connections";
            case 3:return "settings";
            case 4:return "store";
            case 5:return "store-detail";
            default:return "home";
        }
    }
    void SyncWebUi(bool force){
        if(!webReady || webView==null || webView.IsDisposed || webView.CoreWebView2==null)return;
        try{
            bool routing=ProxyOnly && relayReady;
            bool danger=leases!=null && leases.Values.Any(r=>r.HighRisk && r.Until==0);
            bool closed=relay!=null && leases!=null && status.Text.StartsWith("Доступно сервисов: 0 из 3",StringComparison.Ordinal);
            bool open=verdict.Text=="Можно работать";
            string tone="neutral";
            string icon="shield";
            if(routing && danger){tone="bad";icon="warn";}
            else if(routing){tone="neutral";icon="globe";}
            else if(relay==null && !retrying){tone="neutral";icon="shield";}
            else if(open){tone="ok";icon="check";}
            else if(closed){tone="bad";icon="warn";}
            else{tone="warn";icon="warn";}

            var svcList=new List<object>();
            for(int i=0;i<3;i++){
                string st=outcomes[i].Text;
                string stTone="muted";
                if(st.Contains("Можно") || st.Contains("Низкий"))stTone="ok";
                else if(st.Contains("замечание"))stTone="warn";
                else if(st.Contains("Закрыт") || st.Contains("Высокий"))stTone="bad";
                svcList.Add(new Dictionary<string,object>{
                    {"name",names[i+1]},{"status",st},{"tone",stTone},{"reason",reasons[i].Visible?reasons[i].Text:""}
                });
            }
            var slotList=new List<object>();
            for(int i=0;i<4;i++){
                slotList.Add(new Dictionary<string,object>{
                    {"name",names[i]},
                    {"scheme",schemes[i].Selected},
                    {"url",urls[i].Text},
                    {"byField",byField[i].Checked},
                    {"address",addresses[i].Text},
                    {"login",logins[i].Text},
                    {"password",passwords[i].Text},
                    {"reveal",reveal[i].Checked}
                });
            }
            var savedList=new List<object>();
            foreach(var sp in savedProxies){
                savedList.Add(new Dictionary<string,object>{{"id",sp.Id},{"title",SavedProxyTitle(sp)}});
            }
            var purchaseList=new List<object>();
            foreach(var pr in storePurchases){
                purchaseList.Add(new Dictionary<string,object>{
                    {"id",pr.Id??""},{"title",pr.Title??"Покупка"},
                    {"cardNumber",pr.CardNumber??""},{"proxyLine",pr.ProxyLine??""}
                });
            }
            string patchTone="muted";
            if(patchState.Text.StartsWith("Пропатчен",StringComparison.Ordinal))patchTone="ok";
            else if(patchState.ForeColor.R>200)patchTone="warn";

            var payload=new Dictionary<string,object>{
                {"page",CurrentPageKey()},
                {"storeDetail",currentStoreDetail},
                {"version",Application.ProductVersion},
                {"verdict",verdict.Text},
                {"verdictTone",tone},
                {"verdictIcon",icon},
                {"status",status.Text},
                {"proxyTitle",String.IsNullOrWhiteSpace(urls[0].Text)?"Добавить прокси":"Прокси"},
                {"proxyBadge",proxyBadge.Text},
                {"protection",protection.Checked},
                {"protectionEnabled",protection.Enabled},
                {"modeHint",modeHint.Text},
                {"lastResult",lastResult.Text},
                {"checkEnabled",checkAddress.Enabled},
                {"checkText",checkAddress.Text},
                {"services",svcList},
                {"proxySlots",slotList},
                {"inputsEnabled",urls[0].Enabled},
                {"startEnabled",start.Enabled},
                {"startText",start.Text},
                {"relayActive",relay!=null || retrying},
                {"inputFeedback",inputFeedback.Visible?inputFeedback.Text:""},
                {"savedProxies",savedList},
                {"showRouteOptions",optionalRoutes.Visible},
                {"allowMismatch",allowMismatch.Checked},
                {"flows",connections!=null?connections.SnapshotRows():new List<Dictionary<string,string>>()},
                {"dnsNote",connections!=null?connections.NoteText:""},
                {"dnsCleanupVisible",dns.Visible},
                {"patch",new Dictionary<string,object>{
                    {"status",patchState.Text},{"tone",patchTone},
                    {"error",patchError.Visible?patchError.Text:""},
                    {"button",patchButton.Text},{"enabled",patchButton.Enabled}
                }},
                {"update",new Dictionary<string,object>{
                    {"available",!String.IsNullOrEmpty(availableVersion)},
                    {"latest",availableVersion},
                    {"status",updateState.Text},
                    {"button",updateButton.Text},
                    {"busy",updateBusy}
                }},
                {"purchases",purchaseList}
            };
            string text=json.Serialize(payload);
            if(!force && text==lastWebPayload)return;
            lastWebPayload=text;
            webView.CoreWebView2.PostWebMessageAsJson(text);
        }catch{}
    }
    void HandleWebMessage(string raw){
        var msg=json.Deserialize<Dictionary<string,object>>(raw);
        if(msg==null || !msg.ContainsKey("type"))return;
        string type=Convert.ToString(msg["type"]);
        int idx=msg.ContainsKey("idx") && msg["idx"]!=null?Convert.ToInt32(msg["idx"]):0;
        switch(type){
            case "ready":
                webReady=true;
                if(webView!=null && !webView.IsDisposed)webView.Visible=true;
                SyncWebUi(true);
                webInitDone.TrySetResult(true);
                break;
            case "nav":{
                string p=msg.ContainsKey("page")?Convert.ToString(msg["page"]):"home";
                if(p=="proxy")pages.SelectedIndex=1;
                else if(p=="connections"){pages.SelectedIndex=2;nextFlows=DateTime.MinValue;}
                else if(p=="settings")pages.SelectedIndex=3;
                else if(p=="store")pages.SelectedIndex=4;
                else pages.SelectedIndex=0;
                SyncWebUi(true);
                break;
            }
            case "open-store":{
                string kind=msg.ContainsKey("kind")?Convert.ToString(msg["kind"]):"proxy";
                currentStoreDetail=kind;
                OpenStoreDetail(kind);
                SyncWebUi(true);
                break;
            }
            case "toggle-protection":
                if(protection.Enabled){protection.Checked=!protection.Checked;SyncWebUi(true);}
                break;
            case "open-vectra":
                try{Process.Start(new ProcessStartInfo("https://pay.vectra-pro.net/store"){UseShellExecute=true});}catch{}
                break;
            case "check-address":
                if(relayReady && checkAddress.Enabled){
                    try{relay.StandardInput.WriteLine("check");relay.StandardInput.Flush();checkAddress.Enabled=false;checkAddress.Text="Проверяем…";SyncWebUi(true);}
                    catch(IOException){RelayEnded();}
                }
                break;
            case "set-scheme":
                if(idx>=0 && idx<4 && msg.ContainsKey("scheme")){schemes[idx].Selected=Convert.ToString(msg["scheme"]);SyncWebUi(true);}
                break;
            case "set-byfield":
                if(idx>=0 && idx<4 && msg.ContainsKey("value")){byField[idx].Checked=Convert.ToBoolean(msg["value"]);SyncWebUi(true);}
                break;
            case "set-reveal":
                if(idx>=0 && idx<4 && msg.ContainsKey("value")){reveal[idx].Checked=Convert.ToBoolean(msg["value"]);SyncWebUi(true);}
                break;
            case "set-url":
                if(idx>=0 && idx<4 && msg.ContainsKey("value")){urls[idx].Text=Convert.ToString(msg["value"]);SyncWebUi(false);}
                break;
            case "set-field":
                if(idx>=0 && idx<4 && msg.ContainsKey("field") && msg.ContainsKey("value")){
                    string f=Convert.ToString(msg["field"]);
                    string v=Convert.ToString(msg["value"]);
                    if(f=="address")addresses[idx].Text=v;
                    else if(f=="login")logins[idx].Text=v;
                    else if(f=="password")passwords[idx].Text=v;
                }
                break;
            case "paste-proxy":
                if(idx>=0 && idx<4){paste[idx].PerformClick();SyncWebUi(true);}
                break;
            case "toggle-connect":
                start.PerformClick();SyncWebUi(true);
                break;
            case "use-saved":{
                string id=msg.ContainsKey("id")?Convert.ToString(msg["id"]):"";
                var item=savedProxies.FirstOrDefault(p=>p.Id==id);
                if(item!=null){if(relay!=null)Disconnect();schemes[0].Selected=item.Scheme;urls[0].Text=item.Line;SyncWebUi(true);}
                break;
            }
            case "copy-saved":{
                string id=msg.ContainsKey("id")?Convert.ToString(msg["id"]):"";
                var item=savedProxies.FirstOrDefault(p=>p.Id==id);
                if(item!=null){try{Clipboard.SetText(item.Scheme.ToLowerInvariant()+"://"+item.Line);}catch{}}
                break;
            }
            case "del-saved":{
                string id=msg.ContainsKey("id")?Convert.ToString(msg["id"]):"";
                savedProxies.RemoveAll(p=>p.Id==id);PersistSavedProxies();RenderSavedProxies();SyncWebUi(true);
                break;
            }
            case "toggle-routes":
                ShowRouteOptions(!optionalRoutes.Visible);SyncWebUi(true);
                break;
            case "set-mismatch":
                if(msg.ContainsKey("value")){allowMismatch.Checked=Convert.ToBoolean(msg["value"]);SyncWebUi(true);}
                break;
            case "clear-dns":
                dns.PerformClick();SyncWebUi(true);
                break;
            case "patch-run":
                if(!patchBusy && patchButton.Enabled)RunAntigravity(patchButton.Text=="Восстановить"?"restore":"patch");
                break;
            case "update-check":
                RunAppUpdate("check");
                break;
            case "update-install":
                RunAppUpdate("install");
                break;
            case "copy-text":
                if(msg.ContainsKey("text")){try{Clipboard.SetText(Convert.ToString(msg["text"]));}catch{}}
                break;
            case "quit":
                quitting=true;Close();
                break;
        }
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
    TableLayoutPanel StoreMenuRow(Mark mark,Color tint,string title,string subtitle,Label countLabel,EventHandler click){
        var row=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=4,Margin=new Padding(0,4,0,4),Cursor=Cursors.Hand,BackColor=Color.Transparent};
        row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var icon=new Glyph(mark,tint);icon.Size=new Size(20,20);icon.Anchor=AnchorStyles.None;icon.Margin=new Padding(0,0,10,0);
        var textCol=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=1,Margin=Padding.Empty,BackColor=Color.Transparent};
        textCol.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        var t=Copy(title,true);t.Margin=new Padding(0,1,4,0);t.Cursor=Cursors.Hand;
        var s=Copy(subtitle,false);s.Margin=new Padding(0,0,4,1);s.Cursor=Cursors.Hand;
        textCol.Controls.Add(t);textCol.Controls.Add(s);
        var chev=Copy("›",false);chev.Font=new Font("Segoe UI",11F);chev.Anchor=AnchorStyles.Right;chev.Margin=new Padding(2,1,0,2);chev.Cursor=Cursors.Hand;
        row.Click+=click;icon.Click+=click;textCol.Click+=click;t.Click+=click;s.Click+=click;chev.Click+=click;
        row.Controls.Add(icon,0,0);row.Controls.Add(textCol,1,0);
        if(countLabel!=null){countLabel.Click+=click;row.Controls.Add(countLabel,2,0);}
        row.Controls.Add(chev,3,0);
        return row;
    }
    void LoadStorePurchases(){
        storePurchases.Clear();
        try{
            if(File.Exists(savedPurchasesFile)){
                byte[] plain=ProtectedData.Unprotect(File.ReadAllBytes(savedPurchasesFile),null,DataProtectionScope.CurrentUser);
                var items=json.Deserialize<List<StorePurchaseItem>>(Encoding.UTF8.GetString(plain));
                if(items!=null)storePurchases.AddRange(items);
            }
        }catch{}
        if(storePurchasesCount!=null)storePurchasesCount.Text=storePurchases.Count>0?storePurchases.Count.ToString():"";
    }
    void OpenStoreDetail(string kind){
        currentStoreDetail=kind;
        storeDetailHost.SuspendLayout();
        storeDetailHost.Controls.Clear();
        var backToStore=ActionButton("←  Магазин",(s,e)=>pages.SelectedIndex=4);
        backToStore.Margin=new Padding(0,0,0,8);
        storeDetailHost.Controls.Add(backToStore);
        if(kind=="proxy"){
            var h=Copy("Чистый прокси",true);h.Font=new Font("Segoe UI Semibold",15F);storeDetailHost.Controls.Add(h);
            storeDetailHost.Controls.Add(Copy("Выделенный IP, проверенный для Claude, ChatGPT и Antigravity.",false));
            var c=Card();
            c.Controls.Add(Copy("Страна",false));
            var picker=new CountryPicker(new[]{"Нидерланды","Германия","США","Финляндия","Великобритания","Сингапур","Япония"}){Dock=DockStyle.Fill,Margin=new Padding(0,4,0,8)};
            c.Controls.Add(picker);
            c.Controls.Add(Copy("Срок",false));
            var termRow=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=2,Margin=new Padding(0,4,0,10)};
            termRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));termRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));
            var m1=ActionButton("1 месяц",(s,e)=>{});m1.Dock=DockStyle.Fill;m1.BackColor=Color.FromArgb(52,56,68);
            var m3=ActionButton("3 месяца",(s,e)=>{});m3.Dock=DockStyle.Fill;m3.Margin=new Padding(6,0,0,0);
            m1.Click+=(s,e)=>{m1.BackColor=Color.FromArgb(52,56,68);m3.BackColor=btnFill;m1.Invalidate();m3.Invalidate();};
            m3.Click+=(s,e)=>{m3.BackColor=Color.FromArgb(52,56,68);m1.BackColor=btnFill;m1.Invalidate();m3.Invalidate();};
            termRow.Controls.Add(m1,0,0);termRow.Controls.Add(m3,1,0);
            c.Controls.Add(termRow);
            var pay=ActionButton("Оплатить · Скоро",(s,e)=>{});pay.Dock=DockStyle.Fill;pay.Enabled=false;pay.MinimumSize=new Size(0,34);
            c.Controls.Add(pay);
            c.Controls.Add(Copy("После оплаты прокси сам добавится в Guard и подключится.",false));
            storeDetailHost.Controls.Add(c);
        }else if(kind=="card"){
            var h=Copy("Карта Vectra Pay",true);h.Font=new Font("Segoe UI Semibold",15F);storeDetailHost.Controls.Add(h);
            storeDetailHost.Controls.Add(Copy("Предоплаченная Visa с готовым Billing Address под оплату ИИ.",false));
            var c=Card();
            c.Controls.Add(Copy("Номинал",false));
            var amtRow=new TableLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,ColumnCount=3,Margin=new Padding(0,4,0,10)};
            amtRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,33.3f));amtRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,33.3f));amtRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,33.4f));
            var a20=ActionButton("$20",(s,e)=>{});a20.Dock=DockStyle.Fill;a20.BackColor=Color.FromArgb(52,56,68);
            var a100=ActionButton("$100",(s,e)=>{});a100.Dock=DockStyle.Fill;a100.Margin=new Padding(6,0,0,0);
            var a200=ActionButton("$200",(s,e)=>{});a200.Dock=DockStyle.Fill;a200.Margin=new Padding(6,0,0,0);
            Action<Button> pickAmt=sel=>{foreach(var b in new[]{a20,a100,a200}){b.BackColor=b==sel?Color.FromArgb(52,56,68):btnFill;b.Invalidate();}};
            a20.Click+=(s,e)=>pickAmt(a20);a100.Click+=(s,e)=>pickAmt(a100);a200.Click+=(s,e)=>pickAmt(a200);
            amtRow.Controls.Add(a20,0,0);amtRow.Controls.Add(a100,1,0);amtRow.Controls.Add(a200,2,0);
            c.Controls.Add(amtRow);
            var pay=ActionButton("Выпустить карту · Скоро",(s,e)=>{});pay.Dock=DockStyle.Fill;pay.Enabled=false;pay.MinimumSize=new Size(0,34);
            c.Controls.Add(pay);
            c.Controls.Add(Copy("Карта появится в «Мои покупки» с копированием в 1 клик.",false));
            storeDetailHost.Controls.Add(c);
        }else if(kind=="claude"){
            var h=Copy("Аккаунт Claude",true);h.Font=new Font("Segoe UI Semibold",15F);storeDetailHost.Controls.Add(h);
            storeDetailHost.Controls.Add(Copy("Верифицированный аккаунт с доступом к почте.",false));
            var c=Card();
            var withIp=new DarkCheckBox{Text="Добавить личный IP (привяжется к Claude автоматически)",Checked=true,Dock=DockStyle.Fill,Margin=new Padding(0,4,0,10)};
            c.Controls.Add(withIp);
            var pay=ActionButton("Оплатить · Скоро",(s,e)=>{});pay.Dock=DockStyle.Fill;pay.Enabled=false;pay.MinimumSize=new Size(0,34);
            c.Controls.Add(pay);
            c.Controls.Add(Copy("Логин, пароль и почта сохранятся в «Мои покупки».",false));
            storeDetailHost.Controls.Add(c);
        }else{
            var h=Copy("Мои покупки",true);h.Font=new Font("Segoe UI Semibold",15F);storeDetailHost.Controls.Add(h);
            if(storePurchases.Count==0){
                var empty=Card();
                empty.Controls.Add(Copy("Покупок пока нет",true));
                empty.Controls.Add(Copy("Купленные прокси, карты Vectra Pay и аккаунты появятся здесь и сохранятся зашифрованно.",false));
                storeDetailHost.Controls.Add(empty);
            }else{
                foreach(var entry in storePurchases){
                    var item=entry;
                    var c=Card();
                    c.Controls.Add(Copy(item.Title??"Покупка",true));
                    if(!String.IsNullOrEmpty(item.CardNumber)){
                        var copyNum=ActionButton("Копировать номер карты",(s,e)=>{try{Clipboard.SetText(item.CardNumber);}catch{}});
                        c.Controls.Add(copyNum);
                    }
                    if(!String.IsNullOrEmpty(item.ProxyLine)){
                        var copyProxy=ActionButton("Копировать прокси",(s,e)=>{try{Clipboard.SetText(item.ProxyLine);}catch{}});
                        c.Controls.Add(copyProxy);
                    }
                    storeDetailHost.Controls.Add(c);
                }
            }
        }
        storeDetailHost.ResumeLayout(true);
        pages.SelectedIndex=5;
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
        verdict.ForeColor=open?Color.FromArgb(50,215,75):closed?Color.FromArgb(255,69,58):Color.FromArgb(255,159,10);
        summary.BackColor=relay==null?card:open?Color.FromArgb(22,41,32):closed?Color.FromArgb(46,26,29):Color.FromArgb(42,34,22);
        summary.BorderColor=relay==null?cardBorder:open?Color.FromArgb(35,71,54):closed?Color.FromArgb(84,43,48):Color.FromArgb(74,58,32);
        if(relay==null)verdict.ForeColor=ink;
        bool routing=ProxyOnly && relayReady;
        if(routing){verdict.Text="Только прокси";verdict.ForeColor=ink;summary.BackColor=leases==null?card:open?Color.FromArgb(22,41,32):Color.FromArgb(42,34,22);summary.BorderColor=leases==null?cardBorder:open?Color.FromArgb(35,71,54):Color.FromArgb(74,58,32);}
        bool danger=leases!=null && leases.Values.Any(r=>r.HighRisk && r.Until==0);
        if(routing && danger){verdict.Text="Высокий риск";verdict.ForeColor=Color.FromArgb(255,69,58);summary.BackColor=Color.FromArgb(46,26,29);summary.BorderColor=Color.FromArgb(84,43,48);}
        if(retrying && relay==null){verdict.Text="Восстанавливаем соединение";proxyBadge.Text="Переподключение";verdict.ForeColor=Color.FromArgb(255,159,10);}
        if(verdictGlyph!=null){
            verdictGlyph.CurrentMark=relay==null?Mark.Shield:(open && !(routing && danger))?Mark.CheckCircle:Mark.Warn;
            verdictGlyph.ForeColor=verdict.ForeColor;
            verdictGlyph.Invalidate();
        }
        if(!relayReady)checkAddress.Enabled=false;
        else if(checkAddress.Text!="Проверяем…")checkAddress.Enabled=true;
        start.BackColor=relay!=null || retrying?ControlPaint.Light(card,.17f):accent;
        tray.Text="Guard · "+verdict.Text;
        string mood=relay==null?"off":(routing && danger) || closed?"danger":routing && open?"proxy":routing?"warn":open?"ok":"warn";
        SetTrayMood(mood);
        SyncWebUi(false);
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
    async Task SaveSmokeImageAsync(string file){
        string folder=Environment.GetEnvironmentVariable("GUARD_UI_SCREENSHOTS");
        if(String.IsNullOrEmpty(folder))return;
        Directory.CreateDirectory(folder);
        if(webReady && webView!=null && !webView.IsDisposed && webView.CoreWebView2!=null){
            SyncWebUi(true);
            await Task.Delay(140);
            using(var fs=File.Create(Path.Combine(folder,file)))
                await webView.CoreWebView2.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png,fs);
            return;
        }
        PerformLayout();Update();
        using(var image=new Bitmap(pages.SelectedTab.Width,pages.SelectedTab.Height)){
            pages.SelectedTab.DrawToBitmap(image,new Rectangle(Point.Empty,pages.SelectedTab.Size));
            image.Save(Path.Combine(folder,file),System.Drawing.Imaging.ImageFormat.Png);
        }
    }
    async Task<int> ExerciseFormAsync(){
        await Task.WhenAny(webInitDone.Task,Task.Delay(6000));
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
        pages.SelectedTab.PerformLayout();await SaveSmokeImageAsync("03-settings.png");
        byField[0].Checked=true;
        if(addresses[0].Text!="proxy.example:8000" || logins[0].Text!="demo" || passwords[0].Text!="example")return 30;
        passwords[0].Text="pass@:/#";var parsed=Endpoint("http://"+urls[0].Text);
        if(!ValidFields(0) || parsed.Password!="pass@:/#" || parsed.User!="demo")return 31;
        addresses[0].Text="proxy.example";if(ValidFields(0))return 32;
        addresses[0].Text="proxy.example:8000";passwords[0].Text="example";
        pages.SelectedTab.PerformLayout();await SaveSmokeImageAsync("06-separate-fields.png");byField[0].Checked=false;
        pages.SelectedIndex=2;
        connections.Update(new[]{new ConnectionPane.Flow{Domain="api.openai.com",Status="active"},new ConnectionPane.Flow{Domain="api.anthropic.com",Status="blocked",At=DateTimeOffset.UtcNow.ToUnixTimeSeconds()}},true);
        pages.SelectedTab.PerformLayout();await SaveSmokeImageAsync("05-connections.png");
        pages.SelectedIndex=3;
        pages.SelectedTab.PerformLayout();await SaveSmokeImageAsync("08-app-settings.png");
        pages.SelectedIndex=4;
        pages.SelectedTab.PerformLayout();await SaveSmokeImageAsync("09-store.png");
        OpenStoreDetail("card");
        pages.SelectedTab.PerformLayout();await SaveSmokeImageAsync("10-store-card.png");
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
        RenderReadings(demoTime);await SaveSmokeImageAsync("01-access-open.png");
        leases["Antigravity"]=new Reading{Until=0,Reason="Google не подтвердил страну выхода."};
        RenderReadings(demoTime);await SaveSmokeImageAsync("02-one-service-closed.png");
        if(!reasons[2].Visible || !reasons[2].Text.Contains("страну") || !status.Text.Contains("Antigravity: Google"))return 22;
        relayReady=false;protection.Checked=false;relayReady=true;RenderReadings(demoTime);
        if(!outcomes[2].Text.Contains("Есть замечание") || !checkAddress.Visible || !reasons[2].Visible)return 23;
        await SaveSmokeImageAsync("04-proxy-only-warning.png");
        leases["Antigravity"]=new Reading{Until=0,HighRisk=true,Reason="IP123 отметил высокий риск для сервиса."};RenderReadings(demoTime);
        if(!outcomes[2].Text.Contains("Высокий риск") || verdict.Text!="Высокий риск")return 37;
        await SaveSmokeImageAsync("07-proxy-only-high-risk.png");
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
            if(smoke)form.Shown+=(s,e)=>form.BeginInvoke(new Action(async ()=>{
                try{result=await form.ExerciseFormAsync();}catch{result=17;}
                form.quitting=true;form.Close();
            }));
            Application.Run(form);
        }
        if(smoke && Directory.Exists(data)){try{Directory.Delete(data,true);}catch{}}
        return result;
    }
}
