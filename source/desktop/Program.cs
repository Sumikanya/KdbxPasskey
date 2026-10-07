// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;
using Ui = Wpf.Ui.Controls;
using Wpf.Ui.Appearance;
using Wpf.Ui.Markup;
using Wpf.Ui.Abstractions;

namespace KdbxPasskeyDesktop;
public static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        using var guard = new Mutex(false, args.Contains("--ui-check") ? "Local\\KdbxPasskey-UI-check-" + Guid.NewGuid() : "Local\\KdbxPasskey-UI");
        bool owned;
        try { owned = guard.WaitOne(0); } catch (AbandonedMutexException) { owned = true; }
        if (!owned) { try { using var signal=EventWaitHandle.OpenExisting("Local\\KdbxPasskey-Show"); signal.Set(); } catch { MessageBox.Show("程序已运行，请点击任务栏通知区域图标。", "KDBX Passkey"); } return; }
        try
        {
            var app = new Application();
            app.Resources.MergedDictionaries.Add(new ThemesDictionary { Theme = ApplicationTheme.Light });
            app.Resources.MergedDictionaries.Add(new ControlsDictionary());
            Wpf.Ui.UiApplication.Current.ApplySystemAccentColor=false;
            Wpf.Ui.UiApplication.Current.Resources=app.Resources;
            var window = new MainWindow(args.Contains("--ui-check"), args.Length==2 && args[1].Contains("dark"),args.Length==2 ? args[1] : null);
            if (args.Length == 2 && args[0] == "--ui-check")
            {
                var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
                bool checkedUi = false;
                timer.Tick += (_,_) => {
                    if(!checkedUi) { window.CheckUi(); window.PreviewPage(args[1]); checkedUi=true; return; }
                    timer.Stop(); var rendered=window.PreviewWindow; rendered.UpdateLayout(); window.VerifyPreviewLayout(args[1]);
                    var bitmap = new RenderTargetBitmap((int)rendered.ActualWidth, (int)rendered.ActualHeight, 96, 96, PixelFormats.Pbgra32);
                    bitmap.Render(rendered);
                    var visual = new DrawingVisual();
                    using(var dc = visual.RenderOpen()) { byte shade=args[1].Contains("dark") ? (byte)32 : (byte)243; dc.DrawRectangle(new SolidColorBrush(Color.FromRgb(shade,shade,shade)), null, new Rect(0,0,rendered.ActualWidth,rendered.ActualHeight)); dc.DrawImage(bitmap, new Rect(0,0,rendered.ActualWidth,rendered.ActualHeight)); }
                    var composited = new RenderTargetBitmap((int)rendered.ActualWidth, (int)rendered.ActualHeight,96,96,PixelFormats.Pbgra32); composited.Render(visual);
                    var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(composited));
                    using var stream = File.Create(args[1]); encoder.Save(stream);
                    window.Close();
                };
                timer.Start(); app.Run(window); return;
            }
            using var showSignal=new EventWaitHandle(false,EventResetMode.AutoReset,"Local\\KdbxPasskey-Show");
            var registration=ThreadPool.RegisterWaitForSingleObject(showSignal,(_,_)=>window.Dispatcher.BeginInvoke(new Action(window.ShowMainWindow)),null,Timeout.Infinite,false);
            try { app.Run(window); } finally { registration.Unregister(null); }
        }
        catch (Exception ex) { if(args.Length == 2 && args[0] == "--ui-check") { File.WriteAllText(args[1] + ".error.txt", ex.ToString()); Environment.ExitCode = 1; } else MessageBox.Show($"界面启动失败 [{ex.GetType().Name}]", "KDBX Passkey"); }
        finally { guard.ReleaseMutex(); }
    }
}
public sealed partial class MainWindow : Ui.FluentWindow
{
    readonly TextBox database = new(), keyfile = new();
    readonly PasswordBox password = new();
    readonly TextBlock status = new() { Text = "数据库已锁定", TextWrapping = TextWrapping.Wrap };
    readonly TextBlock count = new() { Text = "解锁后显示通行密钥", TextWrapping = TextWrapping.Wrap };
    readonly TextBlock sync = new() { Text = "正在启动系统认证服务…", TextWrapping = TextWrapping.Wrap };
    readonly ItemsControl sites = new();
    readonly TextBlock diagnostics = new() { Text = "暂无诊断信息", TextWrapping = TextWrapping.Wrap };
    readonly Ui.Button unlock = new() { Content = "解锁数据库", Appearance=Ui.ControlAppearance.Primary };
    readonly Ui.CardExpander connection = new() { IsExpanded=true };
    readonly Ui.Button lockNow = new() { Content="锁定", IsEnabled=false };
    readonly TextBlock vaultName = new() { Text="尚未连接数据库", FontSize=13, Opacity=.65, TextTrimming=TextTrimming.CharacterEllipsis };
    readonly TextBlock keySummary = new() { Text="解锁数据库后，凭据会显示在这里。", Opacity=.65, TextWrapping=TextWrapping.Wrap };
    readonly Ui.SymbolIcon stateIcon = new() { Symbol=Ui.SymbolRegular.LockClosed24, FontSize=28 };
    readonly TextBlock connectionTitle = new() { Text="连接数据库",FontSize=15,FontWeight=FontWeights.SemiBold };
    readonly Dictionary<string, Window> approvals = [];
    Process? backend;
    readonly bool preview;
    readonly string? previewScenario;
    bool closing;
    bool shutdownComplete;
    int preferredTheme;
    int idleSeconds = 600;
    bool lockOnSession = true, requireConfirmation = true;
    readonly string preferencePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KdbxPasskey", "settings.json");
    readonly Ui.NavigationView navigation = new();
    readonly Type[] pageTypes = [typeof(HomePage),typeof(KeysPage),typeof(DiagnosticsPage),typeof(SettingsPage),typeof(AboutPage)];
    readonly List<UIElement> pages = [];
    readonly SemaphoreSlim sendGate = new(1, 1);
    public MainWindow(bool preview, bool darkPreview=false,string? scenario=null)
    {
        this.preview = preview;
        previewScenario=preview ? scenario : null;
        if(!preview) {
            try { using var saved=JsonDocument.Parse(File.ReadAllText(preferencePath));
                int t=saved.RootElement.GetProperty("theme").GetInt32(); int seconds=saved.RootElement.GetProperty("idleSeconds").GetInt32();
                if(saved.RootElement.TryGetProperty("lockOnSession", out var session) && session.ValueKind is JsonValueKind.True or JsonValueKind.False) lockOnSession=session.GetBoolean();
                if(saved.RootElement.TryGetProperty("requireConfirmation", out var confirm) && confirm.ValueKind is JsonValueKind.True or JsonValueKind.False) requireConfirmation=confirm.GetBoolean();
                if(saved.RootElement.TryGetProperty("databasePath",out var db) && db.ValueKind==JsonValueKind.String) database.Text=db.GetString()??"";
                if(saved.RootElement.TryGetProperty("keyfilePath",out var kf) && kf.ValueKind==JsonValueKind.String) keyfile.Text=kf.GetString()??"";
                if(t >= 0 && t <= 2) preferredTheme=t;
                if(new[]{300,600,900,1800}.Contains(seconds)) idleSeconds=seconds;
            } catch { }
        }
        if(preview) preferredTheme=previewScenario?.Contains("system-")==true ? 0 : darkPreview ? 2 : 1;
        SetResourceReference(ForegroundProperty,"TextFillColorPrimaryBrush");
        Title = "KDBX Passkey 0.2.8"; Width = 1080; Height = 800; MinWidth = 880; MinHeight = 620;
        if(previewScenario?.Contains("compact")==true) { Width=880; Height=620; }
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        ExtendsContentIntoTitleBar = true; WindowBackdropType = Wpf.Ui.Controls.WindowBackdropType.Mica; ApplyFluentTheme();
        SystemEvents.UserPreferenceChanged += OnSystemPreference;
        Closed += (_,_) => SystemEvents.UserPreferenceChanged -= OnSystemPreference;
        BuildInterface();
        Closing += async (_, e) => {
            if (shutdownComplete) return;
            e.Cancel = true;
            if (closing) return;
            if(!preview && tray is not null && !exitRequested) { HideToTray(); return; }
            await CloseBackendAsync();
            shutdownComplete = true;
            _ = Dispatcher.BeginInvoke(new Action(Close));
        };
        Loaded += (_,_) => { ApplyFluentTheme(); navigation.Navigate(pageTypes[0]); if (!preview) { InitializeTray(); StartBackend(); } };
    }
    public void PreviewPage(string path)
    {
        if(path.Contains("tray-check")) {
            InitializeTray();
            if(tray is null) throw new InvalidOperationException("Tray initialization failed");
            HideToTray(); if(IsVisible || ShowInTaskbar) throw new InvalidOperationException("Tray hide failed");
            ShowMainWindow(); if(!IsVisible || !ShowInTaskbar) throw new InvalidOperationException("Tray restore failed");
        }
        if(path.Contains("unlocked")) PreviewOpened();
        if(path.Contains("many")) {
            for(int i=0;i<30;i++) credentials.Add(new CredentialView($"site{i:D2}.example.test","account@example.test","临时测试账户",true,""));
            RenderCredentials();
        }
        if(path.Contains("about")) navigation.Navigate(pageTypes[4]);
        if(path.Contains("empty")) {
            using var empty=JsonDocument.Parse("{\"type\":\"opened\",\"total\":0,\"signable\":0,\"sites\":[],\"diagnostics\":[]}"); Receive(empty.RootElement);
        }
        if(path.Contains("settings")) navigation.Navigate(pageTypes[3]);
        if(path.Contains("keys")) navigation.Navigate(pageTypes[1]);
        if(path.Contains("details") && sites.Items.Count>0) ((Expander)sites.Items[0]).IsExpanded=true;
        if(path.Contains("search")) credentialSearch.Text="work@example";
        if(path.Contains("diagnostics")) navigation.Navigate(pageTypes[2]);
        if(path.Contains("session")) {
            pendingSecret=new SessionSecret("temporary-preview-secret"); pendingPath="Personal.kdbx"; AcceptSession();
            using var locked=JsonDocument.Parse("{\"type\":\"locked\",\"message\":\"数据库已锁定\"}"); Receive(locked.RootElement);
        }
        if(path.Contains("login-unlock")) {
            using var request=JsonDocument.Parse("{\"type\":\"unlock_required\",\"token\":\"preview\",\"rp\":\"example.com\"}");
            Receive(request.RootElement);
            if(unlockRequestPanel.Visibility != Visibility.Visible) throw new InvalidOperationException("Unlock request missing");
        }
        if(path.Contains("approval")) {
            using var fixture=JsonDocument.Parse("{\"token\":\"preview-approval\",\"rp\":\"example.com\",\"choices\":[{\"credentialId\":\"example-id\",\"userName\":\"hello@example.com\",\"title\":\"Personal account\"}]}");
            ShowApproval(fixture.RootElement);
        }
    }
    public Window PreviewWindow=>approvals.Values.FirstOrDefault() ?? this;
    public void VerifyPreviewLayout(string path)
    {
        if(!path.Contains("many") || !path.Contains("keys")) return;
        var report=new StringBuilder();
        for(DependencyObject? node=credentialScroll;node is not null;node=VisualTreeHelper.GetParent(node))
            if(node is FrameworkElement element) report.AppendLine($"{node.GetType().Name}: {element.ActualWidth} x {element.ActualHeight}");
        File.WriteAllText(path+".layout.txt",report.ToString());
        if(credentialScroll.ScrollableHeight<=0) throw new InvalidOperationException("Credential list has no bounded scroll viewport");
        var position=credentialSearch.TranslatePoint(new Point(),this);
        credentialScroll.ScrollToBottom(); UpdateLayout();
        if(credentialScroll.VerticalOffset<=0 || credentialSearch.TranslatePoint(new Point(),this)!=position)
            throw new InvalidOperationException("Credential scrolling moved fixed page controls");
        credentialScroll.ScrollToTop(); UpdateLayout();
    }
    void PreviewOpened()
    {
        database.Text=@"D:\Passwords\Personal.kdbx";
        using var opened=JsonDocument.Parse(JsonSerializer.Serialize(new {
            type="opened",total=4,signable=3,sites=new[]{"example.com","github.com","okx.com"},
            diagnostics=new[]{new {rpId="example.com",reason="私钥格式需要检查"}},
            credentials=new[]{
                new {rpId="example.com",userName="personal@example.com",title="个人账户",signable=true,reason=""},
                new {rpId="example.com",userName="work@example.com",title="工作账户",signable=false,reason="私钥格式需要检查"},
                new {rpId="github.com",userName="developer",title="代码托管",signable=true,reason=""},
                new {rpId="okx.com",userName="trader",title="交易账户",signable=true,reason=""}
            }
        }));
        Receive(opened.RootElement);
    }
    void ConfigureBackend() => Send(new { type="configure", idleSeconds, lockOnSession, requireConfirmation });
    void SavePreferences()
    {
        if(preview) { ShowSaved(true); return; }
        try {
            Directory.CreateDirectory(Path.GetDirectoryName(preferencePath)!);
            File.WriteAllText(preferencePath + ".tmp", JsonSerializer.Serialize(new { theme=preferredTheme, idleSeconds, lockOnSession, requireConfirmation, databasePath=database.Text.Trim(), keyfilePath=keyfile.Text.Trim() }));
            File.Move(preferencePath + ".tmp", preferencePath, true);
            ShowSaved(true);
        } catch { ShowSaved(false); }
    }
    void OnSystemPreference(object? sender, UserPreferenceChangedEventArgs e) => Dispatcher.InvokeAsync(ApplyFluentTheme);
    void ApplyFluentTheme()
    {
        bool light=true;
        try { light=(int?)Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize","AppsUseLightTheme",1)!=0; } catch { }
        if(previewScenario?.Contains("system-dark")==true) light=false;
        if(previewScenario?.Contains("system-light")==true) light=true;
        var current=SystemParameters.HighContrast ? ApplicationTheme.HighContrast : preferredTheme==2 || (preferredTheme==0 && !light) ? ApplicationTheme.Dark : ApplicationTheme.Light;
        ApplicationThemeManager.Apply(current);
        var resources=Application.Current.Resources;
        bool dark=current==ApplicationTheme.Dark, highContrast=current==ApplicationTheme.HighContrast;
        var accent=ApplicationAccentColorManager.GetColorizationColor();
        if(previewScenario?.Contains("accent-blue")==true) accent=Color.FromRgb(0,103,192);
        if(!highContrast) ApplicationAccentColorManager.Apply(accent,current,false,false);
        var fill=dark ? Blend(accent,Colors.White,.48) : accent;
        if(!dark) while(Contrast(fill,Colors.White)<4.5) fill=Blend(fill,Colors.Black,.08);
        if(dark) while(Contrast(fill,Colors.Black)<6) fill=Blend(fill,Colors.White,.05);
        var foreground=dark ? Colors.Black : Colors.White;
        void Brush(string name,string lightValue,string darkValue,Brush contrast)
            => resources[name]=highContrast ? contrast : new SolidColorBrush((Color)ColorConverter.ConvertFromString(dark ? darkValue : lightValue));
        resources["KdbxAccentFill"]=highContrast ? SystemColors.HighlightBrush : new SolidColorBrush(fill);
        resources["KdbxAccentHover"]=highContrast ? SystemColors.HighlightBrush : new SolidColorBrush(Blend(fill,dark ? Colors.White : Colors.Black,.08));
        resources["KdbxAccentPressed"]=highContrast ? SystemColors.HighlightBrush : new SolidColorBrush(Blend(fill,Colors.Black,dark ? .1 : .16));
        resources["KdbxAccentText"]=highContrast ? SystemColors.HighlightTextBrush : new SolidColorBrush(foreground);
        resources["KdbxAccentIcon"]=highContrast ? SystemColors.WindowTextBrush : new SolidColorBrush(fill);
        Brush("AppSurface","#FFFFFF","#2D2E33",SystemColors.WindowBrush);
        Brush("AppBorder","#E1E2E8","#3C3D43",SystemColors.WindowTextBrush);
        Brush("AppSecondary","#656772","#B3B4BF",SystemColors.WindowTextBrush);
        Brush("AppInset","#F3F4F7","#35363D",SystemColors.ControlBrush);
        Brush("AppInput","#FAFAFC","#25262C",SystemColors.WindowBrush);
        Brush("AppInputBorder","#D5D6DE","#50525B",SystemColors.WindowTextBrush);
        var surface=(Color)ColorConverter.ConvertFromString(dark ? "#2D2E33" : "#FFFFFF");
        resources["AppTint"]=highContrast ? SystemColors.ControlBrush : new SolidColorBrush(Blend(surface,accent,dark ? .18 : .09));
        resources["NavigationViewSelectionIndicatorForeground"]=resources["KdbxAccentFill"];
    }
    static Color Blend(Color a,Color b,double amount)=>Color.FromRgb((byte)(a.R+(b.R-a.R)*amount),(byte)(a.G+(b.G-a.G)*amount),(byte)(a.B+(b.B-a.B)*amount));
    static double Contrast(Color a,Color b)
    {
        static double L(Color c) { static double S(byte v) { double x=v/255d; return x<=.04045 ? x/12.92 : Math.Pow((x+.055)/1.055,2.4); } return .2126*S(c.R)+.7152*S(c.G)+.0722*S(c.B); }
        double x=L(a),y=L(b); return (Math.Max(x,y)+.05)/(Math.Min(x,y)+.05);
    }
    static void Primary(Ui.Button button)
    {
        button.SetResourceReference(Control.BackgroundProperty,"KdbxAccentFill");
        button.SetResourceReference(Control.ForegroundProperty,"KdbxAccentText");
        button.SetResourceReference(Control.BorderBrushProperty,"KdbxAccentFill");
        button.SetResourceReference(Ui.Button.MouseOverBackgroundProperty,"KdbxAccentHover");
        button.SetResourceReference(Ui.Button.PressedBackgroundProperty,"KdbxAccentPressed");
        button.SetResourceReference(Ui.Button.PressedForegroundProperty,"KdbxAccentText");
    }
    void Choose(TextBox input, string filter) { var dialog = new OpenFileDialog { Filter = filter }; if (dialog.ShowDialog(this) == true) input.Text = dialog.FileName; }
    void Unlock()
    {
        if (string.IsNullOrWhiteSpace(database.Text)) { status.Text = "请先选择数据库。"; return; }
        string secret = password.Password; password.Clear(); unlock.IsEnabled = false;
        ForgetSession(); pendingPath=database.Text.Trim(); pendingKeyfile=keyfile.Text.Trim();
        try { pendingSecret=new SessionSecret(secret); } catch { status.Text="本次无法记住密码，仍尝试解锁数据库。"; }
        Send(new { type = "unlock", path = pendingPath, keyfile = pendingKeyfile, password = secret });
    }
    void StartBackend()
    {
        try
        {
            backend = new Process { StartInfo = new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "Backend", "KdbxBackend.exe")) {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true,
                StandardInputEncoding = new UTF8Encoding(false), StandardOutputEncoding = Encoding.UTF8 } };
            backend.Start();
            ConfigureBackend();
            _ = Task.Run(async () => {
                try {
                    string? line;
                    while ((line = await backend.StandardOutput.ReadLineAsync()) != null) {
                        using var document = JsonDocument.Parse(line);
                        var message = document.RootElement.Clone();
                        await Dispatcher.InvokeAsync(() => { if (!closing) Receive(message); });
                    }
                } catch { }
                if (!closing) await Dispatcher.InvokeAsync(() => { ForgetSession(); credentials.Clear(); credentialSearch.Clear(); sites.Items.Clear(); diagnostics.Text="暂无诊断信息"; UpdateVisualState(false); status.Text = "认证后端已退出，请重新启动程序。"; unlock.IsEnabled = false; vaultOpened=false; SetSyncFeedback("认证后端已退出，请重新启动程序。"); foreach(var w in approvals.Values.ToArray()) w.Close(); });
            });
        }
        catch { status.Text = "认证后端启动失败，请检查安装包。"; unlock.IsEnabled = false; }
    }
    async void Send(object request)
    {
        if (closing) return;
        await sendGate.WaitAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try { if (!closing && backend != null && !backend.HasExited) { await backend.StandardInput.WriteLineAsync(JsonSerializer.Serialize(request).AsMemory(), timeout.Token); await backend.StandardInput.FlushAsync(timeout.Token); } }
        catch { if (!closing) { status.Text = "认证后端通信失败。"; SetSyncFeedback("通信失败，请重新启动程序。"); } }
        finally { sendGate.Release(); }
    }
    void Receive(JsonElement m)
    {
        string type = m.GetProperty("type").GetString()!;
        switch(type) {
            case "opened":
                status.Text = "数据库已解锁"; connection.IsExpanded=false; connectionTitle.Text="数据库连接"; lockNow.IsEnabled=true; stateIcon.Symbol=Ui.SymbolRegular.Shield24;
                vaultName.Text=Path.GetFileName(database.Text); keySummary.Text=$"{m.GetProperty("total").GetInt32()} 条凭据 · {m.GetProperty("signable").GetInt32()} 条可认证";
                count.Visibility = Visibility.Visible;
                count.Text = $"凭据元数据：{m.GetProperty("total").GetInt32()}  ·  可签名：{m.GetProperty("signable").GetInt32()}";
                var invalidSites=m.GetProperty("diagnostics").EnumerateArray().Select(d=>d.GetProperty("rpId").GetString()).ToHashSet();
                credentials.Clear();
                if(m.TryGetProperty("credentials",out var metadata)) {
                    foreach(var c in metadata.EnumerateArray()) credentials.Add(new CredentialView(c.GetProperty("rpId").GetString()!,c.GetProperty("userName").GetString()??"",c.GetProperty("title").GetString()??"",c.GetProperty("signable").GetBoolean(),c.GetProperty("reason").GetString()??"需要检查"));
                } else foreach(var site in m.GetProperty("sites").EnumerateArray()) credentials.Add(new CredentialView(site.GetString()!,"","",!invalidSites.Contains(site.GetString()),"需要检查"));
                credentialSearch.Clear();
                var lines = m.GetProperty("diagnostics").EnumerateArray().Select(d => d.GetProperty("rpId").GetString() + "：" + d.GetProperty("reason").GetString());
                diagnostics.Text = string.Join("\n\n", lines); if (diagnostics.Text.Length == 0) diagnostics.Text = m.GetProperty("total").GetInt32()==0 ? "未找到可识别的通行密钥，请检查条目是否使用兼容的通行密钥字段。" : "所有凭据均可签名。";
                fullDiagnostics=diagnostics.Text; diagnosticSite=null; diagnosticScope.Text=""; clearDiagnostic.Visibility=Visibility.Collapsed;
                UpdateVisualState(true,m.GetProperty("total").GetInt32(),m.GetProperty("signable").GetInt32());
                AcceptSession();
                break;
            case "locked":
                sessionEpoch++;
                status.Text = m.GetProperty("message").GetString(); connection.IsExpanded=true; connectionTitle.Text="连接数据库"; lockNow.IsEnabled=false; stateIcon.Symbol=Ui.SymbolRegular.LockClosed24; keySummary.Text="解锁数据库后，凭据会显示在这里。"; password.Clear(); count.Text = ""; count.Visibility = Visibility.Collapsed; sites.Items.Clear(); diagnostics.Text = "暂无诊断信息";
                credentials.Clear(); credentialSearch.Clear(); fullDiagnostics="暂无诊断信息"; diagnosticSite=null; diagnosticScope.Text=""; clearDiagnostic.Visibility=Visibility.Collapsed;
                UpdateVisualState(false);
                foreach(var w in approvals.Values.ToArray()) w.Close(); break;
            case "sync":
                sync.Text = m.GetProperty("message").GetString();
                var busy=m.TryGetProperty("busy",out var syncing) && syncing.GetBoolean();
                var success=m.TryGetProperty("success",out var ok) && ok.GetBoolean();
                SetSyncFeedback(success ? (vaultOpened ? "已同步到 Windows" : "Windows 凭据缓存已清除") : sync.Text ?? "",busy); break;
            case "error": case "cancelled": RejectPendingSession(); status.Text = m.GetProperty("message").GetString(); unlock.IsEnabled = true; break;
            case "busy": status.Text = "正在解锁数据库…"; unlock.IsEnabled = false; break;
            case "idle": unlock.IsEnabled = true; break;
            case "unlock_required": ShowUnlockRequest(m); break;
            case "unlock_request_closed":
                if (unlockRequestToken == m.GetProperty("token").GetString()) {
                    unlockRequestToken = null;
                    unlockRequestPanel.Visibility = Visibility.Collapsed;
                }
                break;
            case "approve": ShowApproval(m); break;
            case "approval_closed": if (approvals.TryGetValue(m.GetProperty("token").GetString()!, out var window)) window.Close(); break;
        }
    }
    void ShowApproval(JsonElement m)
    {
        if(!preview) ShowMainWindow();
        var token = m.GetProperty("token").GetString()!;
        var choices = m.GetProperty("choices").EnumerateArray().ToArray();
        if (choices.Length == 0) { Send(new { type="approval", token, credentialId=(string?)null }); return; }
        var dialog = new Ui.FluentWindow { Title = "确认通行密钥认证", Width = 520, SizeToContent=SizeToContent.Height, MaxHeight=720, MinHeight = 380, MinWidth=460, Owner = this, WindowStartupLocation = WindowStartupLocation.CenterOwner, Topmost = true,FontFamily=FontFamily,FontSize=14,UseLayoutRounding=true };
        dialog.SetResourceReference(Control.ForegroundProperty,"TextFillColorPrimaryBrush");
        dialog.SetResourceReference(Control.BackgroundProperty,"AppSurface");
        var panel = new StackPanel { Margin = new Thickness(28) };
        panel.Children.Add(Text("使用通行密钥登录",24,FontWeights.SemiBold));
        panel.Children.Add(BodyText("请确认登录站点，并选择本次使用的账户。",13,new Thickness(0,8,0,24)));
        var target=new DockPanel(); var targetIcon=Glyph(Ui.SymbolRegular.Globe24,22,"KdbxAccentIcon"); targetIcon.Margin=new Thickness(0,0,12,0); DockPanel.SetDock(targetIcon,Dock.Left); target.Children.Add(targetIcon);
        var targetText=Text(m.GetProperty("rp").GetString()!,16,FontWeights.SemiBold); targetText.VerticalAlignment=VerticalAlignment.Center; target.Children.Add(targetText); panel.Children.Add(Surface(target,16));
        panel.Children.Add(Label("登录账户",20));
        var accounts = new ListBox { MinHeight = 64, MaxHeight=176 };
        accounts.Padding=new Thickness(4);
        accounts.SetResourceReference(Control.BackgroundProperty,"AppInput");
        accounts.SetResourceReference(Control.BorderBrushProperty,"AppBorder");
        var accountStyle=new Style(typeof(ListBoxItem),TryFindResource(typeof(ListBoxItem)) as Style); accountStyle.Setters.Add(new Setter(Control.PaddingProperty,new Thickness(14,12,14,12))); accountStyle.Setters.Add(new Setter(Control.HorizontalContentAlignmentProperty,HorizontalAlignment.Stretch)); accounts.ItemContainerStyle=accountStyle;
        accountStyle.Setters.Add(new Setter(Control.TemplateProperty,System.Windows.Markup.XamlReader.Parse("""
            <ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" TargetType="{x:Type ListBoxItem}">
              <Border x:Name="Card" Background="Transparent" BorderBrush="Transparent" BorderThickness="1" CornerRadius="6" Padding="{TemplateBinding Padding}">
                <ContentPresenter HorizontalAlignment="Stretch" VerticalAlignment="Center"/>
              </Border>
              <ControlTemplate.Triggers>
                <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Card" Property="Background" Value="{DynamicResource AppInset}"/></Trigger>
                <Trigger Property="IsSelected" Value="True">
                  <Setter TargetName="Card" Property="Background" Value="{DynamicResource AppTint}"/>
                  <Setter TargetName="Card" Property="BorderBrush" Value="{DynamicResource KdbxAccentFill}"/>
                </Trigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
            """)));
        foreach(var c in choices) { var account=new StackPanel(); account.Children.Add(Text(c.GetProperty("userName").GetString()??"",14,FontWeights.SemiBold)); account.Children.Add(BodyText(c.GetProperty("title").GetString()??"",12,new Thickness(0,4,0,0))); accounts.Items.Add(account); }
        accounts.SelectedIndex = 0; panel.Children.Add(accounts);
        bool answered = false;
        void Finish(string? id) { if (answered) return; answered=true; Send(new { type="approval", token, credentialId=id }); dialog.Close(); }
        var row = new StackPanel { Orientation=Orientation.Horizontal, HorizontalAlignment=HorizontalAlignment.Right, Margin=new Thickness(0,24,0,0) };
        row.Children.Add(Button("取消", () => Finish(null)));
        var allow=Button("允许本次认证", () => { if(accounts.SelectedIndex >= 0) Finish(choices[accounts.SelectedIndex].GetProperty("credentialId").GetString()); });
        Primary(allow); allow.Margin=new Thickness(12,0,0,0); row.Children.Add(allow);
        panel.Children.Add(row); dialog.Content = panel;
        var timer = new DispatcherTimer { Interval=TimeSpan.FromSeconds(55) }; timer.Tick += (_,_) => Finish(null);
        dialog.Closed += (_,_) => { timer.Stop(); approvals.Remove(token); if(!answered) { answered=true; Send(new { type="approval", token, credentialId=(string?)null }); } };
        dialog.KeyDown += (_,e) => { if(e.Key == System.Windows.Input.Key.Escape) Finish(null); };
        approvals[token]=dialog; timer.Start(); dialog.Show(); dialog.Activate();
    }
    public void CheckUi()
    {
        CheckSessionUi();
        using(var empty=JsonDocument.Parse("{\"type\":\"opened\",\"total\":0,\"signable\":0,\"sites\":[],\"diagnostics\":[]}")) Receive(empty.RootElement);
        if(emptyTitle.Text!="未找到兼容的通行密钥" || emptyAction.Content.ToString()!="查看诊断" || emptyReload.Visibility!=Visibility.Visible) throw new InvalidOperationException("Empty unlocked state failed");
        using(var progress=JsonDocument.Parse("{\"type\":\"sync\",\"message\":\"正在同步\",\"busy\":true}")) Receive(progress.RootElement);
        if(refresh.IsEnabled) throw new InvalidOperationException("Sync progress failed");
        using(var finished=JsonDocument.Parse("{\"type\":\"sync\",\"message\":\"SYNC ok\",\"success\":true}")) Receive(finished.RootElement);
        if(!refresh.IsEnabled || syncFeedback.Text!="已同步到 Windows") throw new InvalidOperationException("Sync completion failed");
        using(var failed=JsonDocument.Parse("{\"type\":\"sync\",\"message\":\"同步失败测试\",\"success\":false}")) Receive(failed.RootElement);
        if(!refresh.IsEnabled || syncFeedback.Text!="同步失败测试") throw new InvalidOperationException("Sync failure failed");
        SetSyncFeedback("");
        if(securityToggles.Count != 2) throw new InvalidOperationException("Missing security controls");
        foreach(var toggle in securityToggles) toggle.IsChecked=false;
        if(lockOnSession || requireConfirmation) throw new InvalidOperationException("Security toggles did not disable");
        foreach(var toggle in securityToggles) toggle.IsChecked=true;
        if(!lockOnSession || !requireConfirmation) throw new InvalidOperationException("Security toggles did not enable");
        if(settingsFeedback.Text!="已保存") throw new InvalidOperationException("Save feedback failed");
        var expected=(SolidColorBrush)Application.Current.FindResource("TextFillColorPrimaryBrush");
        if(status.Foreground is not SolidColorBrush foreground || foreground.Color!=expected.Color)
            throw new InvalidOperationException("Initial theme foreground mismatch");
        ApplicationThemeManager.Apply(preferredTheme==2 ? ApplicationTheme.Light : ApplicationTheme.Dark);
        expected=(SolidColorBrush)Application.Current.FindResource("TextFillColorPrimaryBrush");
        if(status.Foreground is not SolidColorBrush changed || changed.Color!=expected.Color)
            throw new InvalidOperationException("Theme change foreground mismatch");
        ApplyFluentTheme();
        PreviewOpened();
        if(connection.IsExpanded || !lockNow.IsEnabled || sites.Items.Count!=3 || metrics.Visibility!=Visibility.Visible || loadedNumber.Text!="4")
            throw new InvalidOperationException("Unlocked layout failed");
        credentialSearch.Text="work@example";
        if(sites.Items.Count!=1) throw new InvalidOperationException("Account search failed");
        credentialSearch.Text="代码托管";
        if(sites.Items.Count!=1) throw new InvalidOperationException("Title search failed");
        credentialSearch.Text="no-match-fixture";
        if(sites.Items.Count!=0 || emptyTitle.Text!="没有匹配的凭据" || emptyAction.Content.ToString()!="清除搜索") throw new InvalidOperationException("Search empty state failed");
        credentialSearch.Clear();
        ShowSiteDiagnostics("example.com");
        if(!diagnostics.Text.Contains("work@example.com") || diagnosticScope.Text!="当前站点：example.com") throw new InvalidOperationException("Site diagnostics failed");
        using(var locked = JsonDocument.Parse("{\"type\":\"locked\",\"message\":\"数据库已锁定\"}")) Receive(locked.RootElement);
        if(count.Visibility != Visibility.Collapsed || !connection.IsExpanded || lockNow.IsEnabled || sites.Items.Count!=0 || metrics.Visibility!=Visibility.Collapsed)
            throw new InvalidOperationException("Locked layout failed");
        if(credentials.Count!=0 || credentialSearch.Text!="" || diagnosticScope.Text!="") throw new InvalidOperationException("Locked metadata retained");
        database.Clear(); currentDatabase.Text="尚未选择数据库"; vaultName.Text="选择一个密码库，开始使用通行密钥。";
        for(int i=1;i<pages.Count;i++) { if(!navigation.Navigate(pageTypes[i])) throw new InvalidOperationException("Navigation failed: " + pageTypes[i].Name); }
        navigation.Navigate(pageTypes[0]);
        using var fixture = JsonDocument.Parse("{\"token\":\"ui-fixture\",\"rp\":\"example.test\",\"choices\":[{\"credentialId\":\"fixture-one\",\"userName\":\"first\",\"title\":\"Test\"},{\"credentialId\":\"fixture-two\",\"userName\":\"second\",\"title\":\"Test\"}]}");
        ShowApproval(fixture.RootElement);
        var dialog = approvals["ui-fixture"];
        var panel = (StackPanel)dialog.Content;
        var accounts = panel.Children.OfType<ListBox>().Single();
        if(accounts.SelectedIndex != 0 || accounts.Items.Count != 2 || approvals.Count != 1)
            throw new InvalidOperationException("Native selection failed");
        var row = panel.Children.OfType<StackPanel>().Single();
        var allow = row.Children.OfType<Button>().Single(b => b.Content.ToString() == "允许本次认证");
        if(allow.IsDefault) throw new InvalidOperationException("Unexpected Enter approval");
        allow.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Button.ClickEvent));
        if(approvals.Count != 0) throw new InvalidOperationException("Confirmation did not close");
    }

    async Task CloseBackendAsync()
    {
        if (closing) return;
        closing = true; ForgetSession(); tray?.Dispose(); tray=null;
        try { if(helloProcess is not null && !helloProcess.HasExited) helloProcess.Kill(entireProcessTree:true); } catch { }
        password.Clear(); IsEnabled = false;
        status.Text = "正在锁定数据库并退出…";
        foreach (var w in approvals.Values.ToArray()) w.Close();
        try {
            if (backend != null && !backend.HasExited) {
                await sendGate.WaitAsync();
                try { backend.StandardInput.Close(); } finally { sendGate.Release(); }
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                try { await backend.WaitForExitAsync(timeout.Token); }
                catch (OperationCanceledException) { backend.Kill(entireProcessTree: true); }
            }
        } catch { }
        finally { backend?.Dispose(); }
    }

}

public sealed class HomePage : Page { }
public sealed class KeysPage : Page { }
public sealed class DiagnosticsPage : Page { }
public sealed class SettingsPage : Page { }
public sealed class AboutPage : Page { }
public sealed class PageProvider : INavigationViewPageProvider
{
    readonly Dictionary<Type,object> map=[];
    public PageProvider(Type[] types,List<UIElement> content) { for(int i=0;i<types.Length;i++) { var page=(Page)Activator.CreateInstance(types[i])!; page.SetResourceReference(Control.ForegroundProperty,"TextFillColorPrimaryBrush"); page.Background=Brushes.Transparent; page.Content=content[i];
            page.Loaded+=(_,_)=> {
                for(DependencyObject? parent=VisualTreeHelper.GetParent(page);parent is not null;parent=VisualTreeHelper.GetParent(parent))
                    if(parent is ScrollViewer scroll) {
                        scroll.VerticalScrollBarVisibility=ScrollBarVisibility.Disabled;
                        scroll.HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled;
                        break;
                    }
            };
            map[types[i]]=page; } }
    public object? GetPage(Type type)=>map.GetValueOrDefault(type);
}
public sealed record SearchEntry(string Title,string Keywords,Type Target) { public override string ToString()=>Title; }

