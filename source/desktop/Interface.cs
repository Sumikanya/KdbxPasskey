// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Ui = Wpf.Ui.Controls;

namespace KdbxPasskeyDesktop;

public sealed partial class MainWindow
{
    Border keysEmpty = null!, keysList = null!, readyGuide = null!;
    readonly TextBlock navigationStatus = new();
    readonly TextBlock loadedNumber = new(), readyNumber = new();
    readonly List<Ui.ToggleSwitch> securityToggles = [];
    FrameworkElement metrics = null!;
    Grid keysPageRoot=null!;
    ScrollViewer credentialScroll=null!;
    readonly TextBlock syncFeedback = new() { TextWrapping=TextWrapping.Wrap, Visibility=Visibility.Collapsed }, settingsFeedback = new() { TextWrapping=TextWrapping.Wrap };
    TextBlock emptyTitle = null!, emptyDescription = null!;
    Ui.Button refresh = null!, emptyAction = null!, emptyReload = null!;
    bool vaultOpened, syncBusy;
    readonly TextBlock currentDatabase = new() { Text="尚未选择数据库", TextTrimming=TextTrimming.CharacterEllipsis };
    readonly TextBox credentialSearch = new() { MinHeight=36, Padding=new Thickness(10,6,10,6), IsEnabled=false };
    readonly List<CredentialView> credentials = [];
    readonly List<StackPanel> pageBodies = [];
    readonly List<Grid> settingsRows = [];
    string? diagnosticSite;
    string fullDiagnostics="暂无诊断信息";
    readonly TextBlock diagnosticScope = new() { TextWrapping=TextWrapping.Wrap };
    Ui.Button clearDiagnostic = null!;

    readonly System.Windows.Threading.DispatcherTimer savedTimer = new() { Interval=TimeSpan.FromSeconds(3) };

    void SetSyncFeedback(string message,bool busy=false)
    {
        syncBusy=busy; syncFeedback.Text=message; syncFeedback.Visibility=string.IsNullOrEmpty(message) ? Visibility.Collapsed : Visibility.Visible;
        refresh.IsEnabled=vaultOpened && !busy;
        refresh.Content=busy ? "正在同步…" : "同步到 Windows";
    }
    void ShowSaved(bool success)
    {
        savedTimer.Stop(); settingsFeedback.Text=success ? "已保存" : "保存失败，仅本次运行生效。";
        if(success) savedTimer.Start();
    }

    void BuildInterface()
    {
        FontFamily = new FontFamily("Segoe UI Variable Text, Microsoft YaHei UI");
        FontSize = 14;
        UseLayoutRounding = true;
        SnapsToDevicePixels = true;
        TextOptions.SetTextFormattingMode(this, TextFormattingMode.Display);

        var shell = new Grid();
        shell.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        shell.RowDefinitions.Add(new RowDefinition());
        var title = new Ui.TitleBar { Title = "KDBX Passkey", Height = 52, Icon = Glyph(Ui.SymbolRegular.Key24, 18, "KdbxAccentIcon") };
        title.TrailingContent = new TextBlock { Text = "0.2.8", FontSize = 12, Opacity = .5, Margin = new Thickness(0,0,20,0), VerticalAlignment = VerticalAlignment.Center };
        shell.Children.Add(title);

        navigation.OpenPaneLength = 220;
        navigation.PaneDisplayMode = Ui.NavigationViewPaneDisplayMode.Left;
        navigation.IsPaneToggleVisible = false;
        navigation.IsBackButtonVisible = Ui.NavigationViewBackButtonVisible.Collapsed;
        navigation.IsTopSeparatorVisible = false;
        navigation.IsFooterSeparatorVisible = false;
        navigation.FrameMargin = new Thickness(8, 4, 12, 12);
        // Each page owns its scroll viewport; the navigation host must constrain it.
        navigation.Margin = new Thickness(8,0,0,0);
        var vaultHeader=new StackPanel { Margin=new Thickness(20,16,20,24) };
        vaultHeader.Children.Add(BodyText("当前数据库",12,new Thickness(0,0,0,6)));
        currentDatabase.SetResourceReference(TextBlock.ForegroundProperty,"TextFillColorPrimaryBrush");
        vaultHeader.Children.Add(currentDatabase);
        navigationStatus.Margin=new Thickness(0,6,0,0); vaultHeader.Children.Add(navigationStatus);
        navigation.PaneHeader=vaultHeader;
        var names = new[] { "数据库", "通行密钥", "诊断", "设置" };
        var icons = new[] { Ui.SymbolRegular.Folder24, Ui.SymbolRegular.Key24, Ui.SymbolRegular.Document24, Ui.SymbolRegular.Settings24 };
        for (int i=0; i<names.Length; i++) {
            var item = new Ui.NavigationViewItem { Content=names[i], Icon=Glyph(icons[i],20), TargetPageType=pageTypes[i], Margin=new Thickness(4,2,8,2) };
            if (i==3) navigation.FooterMenuItems.Add(item); else navigation.MenuItems.Add(item);
        }
        var about = new Ui.NavigationViewItem { Content="关于", Icon=Glyph(Ui.SymbolRegular.Info24,20), TargetPageType=pageTypes[4], Margin=new Thickness(4,2,8,12) };
        navigation.FooterMenuItems.Add(about);
        navigationStatus.Text="本地数据库 · 已锁定";
        navigationStatus.FontSize=12;
        navigationStatus.SetResourceReference(TextBlock.ForegroundProperty,"AppSecondary");

        Grid.SetRow(navigation,1); shell.Children.Add(navigation);

        BuildDatabasePage();
        BuildKeysPage();
        BuildDiagnosticsPage();
        BuildSettingsPage();
        BuildAboutPage();
        navigation.SetPageProviderService(new PageProvider(pageTypes, pages));
        Content=shell;
        SizeChanged += (_,_)=>ApplyDensity();
        ApplyDensity();
    }

    void BuildDatabasePage()
    {
        lockNow.Content="锁定数据库";
        lockNow.Icon=Glyph(Ui.SymbolRegular.LockClosed24,16);
        lockNow.Visibility=Visibility.Collapsed;
        lockNow.Padding=new Thickness(14,8,14,8);
        lockNow.Click += (_,_) => { password.Clear(); Send(new { type="lock" }); };
        var page=PageBody("数据库", "你的通行密钥，从这里连接到 Windows。",lockNow);

        status.FontSize=19; status.FontWeight=FontWeights.SemiBold;
        status.SetResourceReference(TextBlock.ForegroundProperty,"TextFillColorPrimaryBrush");
        vaultName.Text="选择一个密码库，开始使用通行密钥。";
        vaultName.Opacity=1; vaultName.SetResourceReference(TextBlock.ForegroundProperty,"AppSecondary");
        vaultName.Margin=new Thickness(0,6,0,0);
        var text=new StackPanel { VerticalAlignment=VerticalAlignment.Center };
        text.Children.Add(status); text.Children.Add(vaultName);
        var top=new Grid(); top.ColumnDefinitions.Add(new ColumnDefinition { Width=GridLength.Auto }); top.ColumnDefinitions.Add(new ColumnDefinition()); top.ColumnDefinitions.Add(new ColumnDefinition { Width=GridLength.Auto });
        stateIcon.FontSize=28; stateIcon.SetResourceReference(Control.ForegroundProperty,"KdbxAccentIcon");
        var emblem=Tile(stateIcon,56); emblem.Margin=new Thickness(0,0,20,0); top.Children.Add(emblem);
        Grid.SetColumn(text,1); top.Children.Add(text);
        var readOnly=Badge("只读访问"); readOnly.Margin=new Thickness(16,0,0,0); Grid.SetColumn(readOnly,2); top.Children.Add(readOnly);
        var hero=new StackPanel(); hero.Children.Add(top);
        count.Visibility=Visibility.Collapsed; count.FontSize=13; count.Margin=new Thickness(0,16,0,0); count.SetResourceReference(TextBlock.ForegroundProperty,"AppSecondary");
        System.Windows.Automation.AutomationProperties.SetLiveSetting(status,System.Windows.Automation.AutomationLiveSetting.Polite);
        var stats=new Grid { Margin=new Thickness(0,24,0,0) };
        stats.ColumnDefinitions.Add(new ColumnDefinition()); stats.ColumnDefinitions.Add(new ColumnDefinition()); stats.ColumnDefinitions.Add(new ColumnDefinition { Width=GridLength.Auto });
        stats.Children.Add(Metric(loadedNumber,"已加载的通行密钥"));
        var ready=Metric(readyNumber,"可用于认证"); Grid.SetColumn(ready,1); stats.Children.Add(ready);
        var view=Button("查看通行密钥",()=>navigation.Navigate(pageTypes[1])); view.VerticalAlignment=VerticalAlignment.Bottom; Grid.SetColumn(view,2); stats.Children.Add(view);
        metrics=stats; metrics.Visibility=Visibility.Collapsed; hero.Children.Add(stats);
        page.Children.Add(Surface(hero,24));

        BuildUnlockRequestPanel(page);
        BuildSessionPanel(page);
        var form=new StackPanel();
        form.Children.Add(Field("数据库文件",database,()=>Choose(database,"KeePass 数据库|*.kdbx")));
        form.Children.Add(Label("主密码",20));
        password.Height=40; password.Padding=new Thickness(12,8,12,8); password.VerticalContentAlignment=VerticalAlignment.Center;
        password.SetResourceReference(Control.BackgroundProperty,"AppInput");
        password.SetResourceReference(Control.BorderBrushProperty,"AppInputBorder");
        System.Windows.Automation.AutomationProperties.SetName(password,"数据库主密码");
        form.Children.Add(password);
        password.KeyDown += (_,e) => { if(e.Key==System.Windows.Input.Key.Enter) Unlock(); };
        var optionalBody=new StackPanel();
        optionalBody.Children.Add(Field("密钥文件",keyfile,()=>Choose(keyfile,"所有文件|*.*")));
        optionalBody.Children.Add(BodyText("仅使用密钥文件解锁时，主密码可以留空。",12,new Thickness(0,10,0,0)));
        optionalBody.Margin=new Thickness(0,12,0,0);
        var optional=new Expander { Header=Text("使用密钥文件（可选）",13), Content=optionalBody, Margin=new Thickness(0,16,0,0), Padding=new Thickness(12,10,12,10) };
        form.Children.Add(optional);
        var footer=new Grid { Margin=new Thickness(0,24,0,0) };
        footer.ColumnDefinitions.Add(new ColumnDefinition()); footer.ColumnDefinitions.Add(new ColumnDefinition { Width=GridLength.Auto });
        var note=BodyText("本次运行记住密码，退出后清除。",12); note.VerticalAlignment=VerticalAlignment.Center; note.Margin=new Thickness(0,0,16,0); footer.Children.Add(note);
        Primary(unlock); unlock.Icon=Glyph(Ui.SymbolRegular.Key24,16); unlock.Padding=new Thickness(20,10,20,10); unlock.MinHeight=40;
        unlock.Click += (_,_)=>Unlock(); Grid.SetColumn(unlock,1); footer.Children.Add(unlock); form.Children.Add(footer);
        connectionTitle.Text="解锁密码库"; connectionTitle.FontSize=16; connectionTitle.FontWeight=FontWeights.SemiBold;
        connectionTitle.Margin=new Thickness(12,10,0,10);
        connection.Header=connectionTitle; connection.Icon=null;
        connection.Padding=new Thickness(12,8,12,8);
        connection.ContentPadding=new Thickness(24,8,24,24);
        connection.Content=form; connection.Margin=new Thickness(0,20,0,0); connection.CornerRadius=new CornerRadius(10);
        connection.SetResourceReference(Control.BackgroundProperty,"AppSurface");
        connection.SetResourceReference(Control.BorderBrushProperty,"AppBorder");
        page.Children.Add(connection);

        var guide=new StackPanel(); guide.Children.Add(Text("准备好进行下一次登录",16,FontWeights.SemiBold));
        guide.Children.Add(BodyText("使用密码库中的账户完成 Windows Hello 验证，按安全设置确认本次认证。",13,new Thickness(0,10,0,0)));
        readyGuide=Surface(guide,24); readyGuide.Margin=new Thickness(0,20,0,0); readyGuide.Visibility=Visibility.Collapsed; page.Children.Add(readyGuide);
        var safety=new Grid { Margin=new Thickness(0,22,0,0) };
        safety.ColumnDefinitions.Add(new ColumnDefinition { Width=GridLength.Auto }); safety.ColumnDefinitions.Add(new ColumnDefinition()); safety.ColumnDefinitions.Add(new ColumnDefinition { Width=GridLength.Auto });
        var shield=Glyph(Ui.SymbolRegular.Shield24,18,"AppSecondary"); shield.Margin=new Thickness(0,0,10,0); safety.Children.Add(shield);
        var safetyText=BodyText("Windows Hello 保护 · 只读访问数据库",12); safetyText.VerticalAlignment=VerticalAlignment.Center; Grid.SetColumn(safetyText,1); safety.Children.Add(safetyText);
        var manage=Button("安全设置",()=>navigation.Navigate(pageTypes[3])); manage.Padding=new Thickness(12,6,12,6); Grid.SetColumn(manage,2); safety.Children.Add(manage);
        page.Children.Add(safety); pages.Add(Scrollable(page));
    }

    void BuildKeysPage()
    {
        refresh=Button("同步到 Windows",()=> { SetSyncFeedback("正在同步到 Windows…",true); Send(new { type="sync" }); }); refresh.IsEnabled=false; refresh.Icon=Glyph(Ui.SymbolRegular.ArrowSync24,16);
        var page=PageBody("通行密钥","当前密码库中可供 Windows 使用的凭据。",refresh);
        keySummary.FontSize=13; keySummary.Opacity=1; keySummary.Margin=new Thickness(0,0,0,8); keySummary.SetResourceReference(TextBlock.ForegroundProperty,"AppSecondary"); page.Children.Add(keySummary);
        syncFeedback.SetResourceReference(TextBlock.ForegroundProperty,"AppSecondary");
        syncFeedback.Margin=new Thickness(0,0,0,8);
        System.Windows.Automation.AutomationProperties.SetLiveSetting(syncFeedback,System.Windows.Automation.AutomationLiveSetting.Polite);
        page.Children.Add(syncFeedback);
        var searchRow=new Grid { Margin=new Thickness(0,0,0,12) };
        searchRow.ColumnDefinitions.Add(new ColumnDefinition()); searchRow.ColumnDefinitions.Add(new ColumnDefinition { Width=GridLength.Auto });
        credentialSearch.SetResourceReference(Control.BackgroundProperty,"AppInput");
        credentialSearch.SetResourceReference(Control.ForegroundProperty,"TextFillColorPrimaryBrush");
        System.Windows.Automation.AutomationProperties.SetName(credentialSearch,"搜索站点、账户或条目标题");
        credentialSearch.TextChanged += (_,_)=>RenderCredentials();
        page.Children.Add(BodyText("搜索站点、账户或条目标题",12,new Thickness(0,0,0,6)));
        searchRow.Children.Add(credentialSearch);
        var clear=Button("清除",()=>credentialSearch.Clear()); clear.Margin=new Thickness(8,0,0,0); Grid.SetColumn(clear,1); searchRow.Children.Add(clear);
        page.Children.Add(searchRow);
        sites.SetResourceReference(Control.ForegroundProperty,"TextFillColorPrimaryBrush");
        credentialScroll=new ScrollViewer { Content=sites,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled,Padding=new Thickness(0,0,14,0),PanningMode=PanningMode.VerticalOnly };
        var content=new Grid(); content.RowDefinitions.Add(new RowDefinition { Height=GridLength.Auto }); content.RowDefinitions.Add(new RowDefinition());
        var header=new DockPanel { Margin=new Thickness(12,2,12,8) };
        var right=BodyText("状态",12); DockPanel.SetDock(right,Dock.Right); header.Children.Add(right); header.Children.Add(BodyText("站点与账户",12)); content.Children.Add(header);
        Grid.SetRow(credentialScroll,1); content.Children.Add(credentialScroll);
        keysList=Surface(content,8); keysList.Visibility=Visibility.Collapsed;
        var empty=new StackPanel { Margin=new Thickness(24,28,24,28),HorizontalAlignment=HorizontalAlignment.Center };
        empty.Children.Add(Tile(Glyph(Ui.SymbolRegular.Key24,28,"KdbxAccentIcon"),64));
        emptyTitle=Text("通行密钥会显示在这里",18,FontWeights.SemiBold); emptyTitle.HorizontalAlignment=HorizontalAlignment.Center; emptyTitle.Margin=new Thickness(0,20,0,0); empty.Children.Add(emptyTitle);
        emptyDescription=BodyText("先解锁数据库，再查看和同步你的凭据。",13,new Thickness(0,8,0,20)); emptyDescription.TextAlignment=TextAlignment.Center; empty.Children.Add(emptyDescription);
        emptyAction=Button("前往解锁",()=> { if(vaultOpened && credentials.Count>0) credentialSearch.Clear(); else navigation.Navigate(pageTypes[vaultOpened ? 2 : 0]); });
        emptyReload=Button("重新解锁",()=> { connection.IsExpanded=true; navigation.Navigate(pageTypes[0]); });
        emptyReload.Margin=new Thickness(12,0,0,0); emptyReload.Visibility=Visibility.Collapsed;
        var actions=new StackPanel { Orientation=Orientation.Horizontal, HorizontalAlignment=HorizontalAlignment.Center };
        actions.Children.Add(emptyAction); actions.Children.Add(emptyReload); empty.Children.Add(actions);
        keysEmpty=Surface(empty,16); keysEmpty.VerticalAlignment=VerticalAlignment.Top;
        var results=new Grid(); results.Children.Add(keysList); results.Children.Add(keysEmpty);
        // Only the results viewport scrolls. Header, status and search stay fixed.
        pageBodies.Remove(page); page.Margin=new Thickness(0); page.MaxWidth=double.PositiveInfinity;
        if(page.Children[0] is FrameworkElement heading) heading.Margin=new Thickness(0,0,0,12);
        keysPageRoot=new Grid { Margin=new Thickness(24,20,24,16) };
        keysPageRoot.RowDefinitions.Add(new RowDefinition { Height=GridLength.Auto });
        keysPageRoot.RowDefinitions.Add(new RowDefinition());
        keysPageRoot.RowDefinitions.Add(new RowDefinition { Height=GridLength.Auto });
        keysPageRoot.Children.Add(page); Grid.SetRow(results,1); keysPageRoot.Children.Add(results);
        var note=BodyText("数据库有更新时，请重新解锁以加载最新凭据。",12,new Thickness(0,8,0,0));
        Grid.SetRow(note,2); keysPageRoot.Children.Add(note); pages.Add(keysPageRoot);
    }

    void BuildDiagnosticsPage()
    {
        var copy=Button("复制诊断",()=>Clipboard.SetText(sync.Text+"\n\n"+diagnostics.Text)); copy.Icon=Glyph(Ui.SymbolRegular.Copy24,16);
        var page=PageBody("诊断","检查 Windows 同步状态与凭据解析结果。",copy);
        var scope=new StackPanel { Margin=new Thickness(0,0,0,12) };
        diagnosticScope.SetResourceReference(TextBlock.ForegroundProperty,"AppSecondary"); scope.Children.Add(diagnosticScope);
        clearDiagnostic=Button("显示全部诊断",()=> { diagnosticSite=null; diagnostics.Text=fullDiagnostics; diagnosticScope.Text=""; clearDiagnostic.Visibility=Visibility.Collapsed; });
        clearDiagnostic.Visibility=Visibility.Collapsed; clearDiagnostic.HorizontalAlignment=HorizontalAlignment.Left; scope.Children.Add(clearDiagnostic); page.Children.Add(scope);
        sync.FontSize=13; sync.TextWrapping=TextWrapping.Wrap;
        diagnostics.FontSize=13; diagnostics.TextWrapping=TextWrapping.Wrap;
        page.Children.Add(DiagnosticCard("Windows 凭据同步","提供程序与系统缓存",Ui.SymbolRegular.ArrowSync24,sync));
        page.Children.Add(DiagnosticCard("凭据解析","密码库中的通行密钥",Ui.SymbolRegular.Document24,diagnostics));
        page.Children.Add(BodyText("诊断信息不包含主密码或私钥。",12,new Thickness(0,4,0,0)));
        pages.Add(Scrollable(page));
    }

    void BuildSettingsPage()
    {
        settingsFeedback.SetResourceReference(TextBlock.ForegroundProperty,"AppSecondary");
        settingsFeedback.MaxWidth=180;
        System.Windows.Automation.AutomationProperties.SetLiveSetting(settingsFeedback,System.Windows.Automation.AutomationLiveSetting.Polite);
        savedTimer.Tick += (_,_)=> { savedTimer.Stop(); settingsFeedback.Text=""; };
        var page=PageBody("设置","调整外观，以及密码库的保护方式。",settingsFeedback);
        var theme=new ComboBox { ItemsSource=new[]{"跟随系统","浅色","深色"},SelectedIndex=preferredTheme,Width=152,MinHeight=36,VerticalAlignment=VerticalAlignment.Center };
        theme.SelectionChanged += (_,_)=> { preferredTheme=theme.SelectedIndex; SavePreferences(); ApplyFluentTheme(); };
        page.Children.Add(SectionTitle("外观",0));
        page.Children.Add(SettingsGroup(SettingRow("应用主题","选择你喜欢的明暗外观。",Ui.SymbolRegular.Color24,theme)));
        var timeout=new ComboBox { ItemsSource=new[]{"5 分钟","10 分钟","15 分钟","30 分钟"},SelectedIndex=Array.IndexOf(new[]{300,600,900,1800},idleSeconds),Width=152,MinHeight=36,VerticalAlignment=VerticalAlignment.Center };
        timeout.SelectionChanged += (_,_)=> { idleSeconds=new[]{300,600,900,1800}[timeout.SelectedIndex]; SavePreferences(); ConfigureBackend(); };
        page.Children.Add(SectionTitle("安全"));
        page.Children.Add(SettingsGroup(
            SettingRow("闲置时自动锁定","从上次认证开始计时。",Ui.SymbolRegular.Clock24,timeout),
            SettingRow("锁屏与休眠","离开电脑时，立即锁定数据库。",Ui.SymbolRegular.LockClosed24,SecurityToggle("锁屏与休眠时锁定",lockOnSession,value=>lockOnSession=value)),
            SettingRow("每次手动确认","关闭后单个账户直接继续，多个账户仍需选择。",Ui.SymbolRegular.Shield24,SecurityToggle("每次手动确认",requireConfirmation,value=>requireConfirmation=value)),
            SettingRow("Windows Hello","PIN、指纹或人脸用于验证身份；手动确认用于确认本次登录。",Ui.SymbolRegular.Shield24,Badge("必须验证"))));
        page.Children.Add(SectionTitle("系统集成"));
        var open=Button("打开设置",()=>Process.Start(new ProcessStartInfo("ms-settings:passkeys-advancedoptions") { UseShellExecute=true }));
        page.Children.Add(SettingsGroup(SettingRow("Windows 通行密钥","管理 KDBX Passkey 提供程序。",Ui.SymbolRegular.Settings24,open)));
        pages.Add(Scrollable(page));
    }

    FrameworkElement SecurityToggle(string name,bool enabled,Action<bool> update)
    {
        var toggle=new Ui.ToggleSwitch { IsChecked=enabled, VerticalAlignment=VerticalAlignment.Center, MinWidth=76 };
        System.Windows.Automation.AutomationProperties.SetName(toggle,name);
        var state=BodyText(enabled ? "已开启" : "已关闭",12); state.VerticalAlignment=VerticalAlignment.Center; state.Margin=new Thickness(0,0,8,0);
        toggle.Checked += (_,_) => { state.Text="已开启"; update(true); SavePreferences(); ConfigureBackend(); };
        toggle.Unchecked += (_,_) => { state.Text="已关闭"; update(false); SavePreferences(); ConfigureBackend(); };
        securityToggles.Add(toggle);
        var row=new StackPanel { Orientation=Orientation.Horizontal }; row.Children.Add(state); row.Children.Add(toggle); return row;
    }

    void BuildAboutPage()
    {
        var page=PageBody("关于","KDBX Passkey · 本地通行密钥提供程序");
        var body=new StackPanel();
        body.Children.Add(Text("KDBX Passkey 0.2.8",24,FontWeights.SemiBold));
        body.Children.Add(BodyText("独立读取 KDBX 数据库中的通行密钥，为 Windows 提供认证。",14,new Thickness(0,12,0,24)));
        body.Children.Add(Text("界面：WPF UI / Fluent",14));
        body.Children.Add(Text("认证：基于 KeePassPasskey",14));
        body.Children.Add(BodyText("开源许可：GPL-3.0-or-later。第三方许可随安装包提供。",13,new Thickness(0,20,0,0)));
        page.Children.Add(Surface(body,24));
        pages.Add(Scrollable(page));
    }

    void ApplyDensity()
    {
        bool compact=ActualHeight>0 && ActualHeight<720;
        foreach(var body in pageBodies) {
            body.Margin=compact ? new Thickness(24,16,24,20) : new Thickness(32,28,32,32);
            if(body.Children[0] is FrameworkElement heading) heading.Margin=new Thickness(0,0,0,compact ? 16 : 28);
        }
        if(keysPageRoot is not null) keysPageRoot.Margin=compact ? new Thickness(18,12,18,12) : new Thickness(24,20,24,16);
        foreach(var row in settingsRows) row.Margin=compact ? new Thickness(18,12,18,12) : new Thickness(22,20,22,20);
    }

    void RenderCredentials()
    {
        if(emptyTitle is null) return;
        sites.Items.Clear();
        if(vaultOpened) {
            string query=credentialSearch.Text.Trim();
            foreach(var group in credentials.Where(c=> (c.Rp+" "+c.User+" "+c.Title).Contains(query,StringComparison.OrdinalIgnoreCase)).GroupBy(c=>c.Rp).OrderBy(g=>g.Key)) {
                var members=group.ToArray();
                var details=new StackPanel { Margin=new Thickness(12,6,12,6) };
                foreach(var account in members) {
                    var item=new StackPanel { Margin=new Thickness(0,0,0,8) };
                    item.Children.Add(Text(string.IsNullOrWhiteSpace(account.User) ? "未提供账户名称" : account.User,14,FontWeights.Medium));
                    item.Children.Add(BodyText(account.Signable ? account.Title+" · 可用于认证" : account.Title+" · "+account.Reason,12,new Thickness(0,2,0,0)));
                    details.Children.Add(item);
                }
                if(members.Any(c=>!c.Signable)) details.Children.Add(Button("查看此站点诊断",()=>ShowSiteDiagnostics(group.Key)));
                var expander=new Expander { Header=SiteRow(group.Key+" · "+members.Length+" 条凭据",members.Any(c=>!c.Signable),group.Key),Content=details,HorizontalContentAlignment=HorizontalAlignment.Stretch,Padding=new Thickness(0),Margin=new Thickness(0,0,0,4) };
                sites.Items.Add(expander);
            }
        }
        bool filtered=vaultOpened && credentials.Count>0 && sites.Items.Count==0;
        keysList.Visibility=sites.Items.Count>0 ? Visibility.Visible : Visibility.Collapsed;
        keysEmpty.Visibility=sites.Items.Count>0 ? Visibility.Collapsed : Visibility.Visible;
        emptyTitle.Text=filtered ? "没有匹配的凭据" : vaultOpened ? "未找到兼容的通行密钥" : "通行密钥会显示在这里";
        emptyDescription.Text=filtered ? "试试其他站点、账户名称或条目标题。" : vaultOpened ? "数据库已解锁，但没有找到可识别的通行密钥。可查看诊断，或更新数据库后重新解锁。" : "先解锁数据库，再查看和同步你的凭据。";
        emptyAction.Content=filtered ? "清除搜索" : vaultOpened ? "查看诊断" : "前往解锁";
        emptyReload.Visibility=vaultOpened && !filtered ? Visibility.Visible : Visibility.Collapsed;
    }
    void ShowSiteDiagnostics(string rp)
    {
        diagnosticSite=rp;
        diagnosticScope.Text="当前站点："+rp;
        diagnostics.Text=string.Join("\n\n",credentials.Where(c=>c.Rp==rp && !c.Signable).Select(c=>c.User+"："+c.Reason));
        clearDiagnostic.Visibility=Visibility.Visible;
        navigation.Navigate(pageTypes[2]);
    }

    static Ui.SymbolIcon Glyph(Ui.SymbolRegular symbol,double size,string? brush=null)
    {
        var icon=new Ui.SymbolIcon { Symbol=symbol,FontSize=size,VerticalAlignment=VerticalAlignment.Center,HorizontalAlignment=HorizontalAlignment.Center };
        if(brush!=null) icon.SetResourceReference(Control.ForegroundProperty,brush); return icon;
    }
    static TextBlock Text(string value,double size=14,FontWeight? weight=null)
    {
        var text=new TextBlock { Text=value,FontSize=size,FontWeight=weight??FontWeights.Normal,TextWrapping=TextWrapping.Wrap };
        text.SetResourceReference(TextBlock.ForegroundProperty,"TextFillColorPrimaryBrush"); return text;
    }
    static TextBlock BodyText(string value,double size=13,Thickness? margin=null)
    {
        var text=Text(value,size); text.SetResourceReference(TextBlock.ForegroundProperty,"AppSecondary"); if(margin.HasValue) text.Margin=margin.Value; return text;
    }
    static TextBlock Label(string value,int top=0) { var label=Text(value,13,FontWeights.Medium); label.Margin=new Thickness(0,top,0,8); return label; }
    StackPanel PageBody(string title,string subtitle,UIElement? action=null)
    {
        var body=new StackPanel { MaxWidth=820,Margin=new Thickness(32,28,32,32),HorizontalAlignment=HorizontalAlignment.Stretch };
        var header=new Grid { Margin=new Thickness(0,0,0,28) }; header.ColumnDefinitions.Add(new ColumnDefinition()); header.ColumnDefinitions.Add(new ColumnDefinition { Width=GridLength.Auto });
        var words=new StackPanel { Margin=new Thickness(0,0,16,0) }; words.Children.Add(Text(title,28,FontWeights.SemiBold)); words.Children.Add(BodyText(subtitle,13,new Thickness(0,8,0,0))); header.Children.Add(words);
        if(action is FrameworkElement element) { Grid.SetColumn(element,1); element.VerticalAlignment=VerticalAlignment.Top; element.Margin=new Thickness(0,4,0,0); header.Children.Add(element); }
        body.Children.Add(header); pageBodies.Add(body); return body;
    }
    static ScrollViewer Scrollable(UIElement content)=>new() { Content=content,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled,Padding=new Thickness(0),Focusable=false };
    static Border Surface(UIElement content,int padding)
    {
        var border=new Border { Child=content,Padding=new Thickness(padding),CornerRadius=new CornerRadius(10),BorderThickness=new Thickness(1) };
        border.SetResourceReference(Border.BackgroundProperty,"AppSurface"); border.SetResourceReference(Border.BorderBrushProperty,"AppBorder"); return border;
    }
    static Border Tile(UIElement icon,int size)
    {
        var tile=new Border { Child=icon,Width=size,Height=size,CornerRadius=new CornerRadius(12),VerticalAlignment=VerticalAlignment.Center,HorizontalAlignment=HorizontalAlignment.Center };
        tile.SetResourceReference(Border.BackgroundProperty,"AppTint"); return tile;
    }
    static Border Badge(string text)
    {
        var badge=new Border { Child=BodyText(text,12),Padding=new Thickness(10,5,10,5),CornerRadius=new CornerRadius(6),VerticalAlignment=VerticalAlignment.Center,HorizontalAlignment=HorizontalAlignment.Right };
        badge.SetResourceReference(Border.BackgroundProperty,"AppInset"); return badge;
    }
    static StackPanel Metric(TextBlock number,string label)
    {
        number.FontSize=26; number.FontWeight=FontWeights.SemiBold; number.SetResourceReference(TextBlock.ForegroundProperty,"TextFillColorPrimaryBrush");
        var panel=new StackPanel(); panel.Children.Add(number); panel.Children.Add(BodyText(label,12,new Thickness(0,4,0,0))); return panel;
    }
    static Ui.Button Button(string title,Action action)
    {
        var button=new Ui.Button { Content=title,Padding=new Thickness(14,8,14,8),MinHeight=36,VerticalAlignment=VerticalAlignment.Center };
        button.Click += (_,_)=>action(); return button;
    }
    static StackPanel Field(string label,TextBox input,Action choose)
    {
        var field=new StackPanel(); field.Children.Add(Label(label));
        var row=new Grid(); row.ColumnDefinitions.Add(new ColumnDefinition()); row.ColumnDefinitions.Add(new ColumnDefinition { Width=GridLength.Auto });
        input.MinHeight=40; input.Padding=new Thickness(12,8,12,8); input.VerticalContentAlignment=VerticalAlignment.Center;
        input.SetResourceReference(Control.BackgroundProperty,"AppInput"); input.SetResourceReference(Control.BorderBrushProperty,"AppInputBorder");
        System.Windows.Automation.AutomationProperties.SetName(input,label); row.Children.Add(input);
        var browse=Button("浏览",choose); browse.Margin=new Thickness(10,0,0,0); browse.MinHeight=40; browse.MinWidth=72; Grid.SetColumn(browse,1); row.Children.Add(browse); field.Children.Add(row); return field;
    }
    static TextBlock SectionTitle(string title,int top=24) { var text=Text(title,13,FontWeights.SemiBold); text.Margin=new Thickness(0,top,0,10); return text; }
    Grid SettingRow(string title,string description,Ui.SymbolRegular symbol,UIElement action)
    {
        var row=new Grid { Margin=new Thickness(22,20,22,20) };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width=new GridLength(36) }); row.ColumnDefinitions.Add(new ColumnDefinition()); row.ColumnDefinitions.Add(new ColumnDefinition { Width=GridLength.Auto });
        var icon=Glyph(symbol,22); icon.HorizontalAlignment=HorizontalAlignment.Left; row.Children.Add(icon);
        var words=new StackPanel { VerticalAlignment=VerticalAlignment.Center,Margin=new Thickness(8,0,24,0) }; words.Children.Add(Text(title,14,FontWeights.Medium)); words.Children.Add(BodyText(description,12,new Thickness(0,5,0,0))); Grid.SetColumn(words,1); row.Children.Add(words);
        Grid.SetColumn(action,2); row.Children.Add(action); settingsRows.Add(row); return row;
    }
    static Border SettingsGroup(params UIElement[] rows)
    {
        var group=new StackPanel(); for(int i=0;i<rows.Length;i++) {
            if(i>0) { var line=new Border { Height=1,Margin=new Thickness(22,0,22,0) }; line.SetResourceReference(Border.BackgroundProperty,"AppBorder"); group.Children.Add(line); }
            group.Children.Add(rows[i]);
        } return Surface(group,0);
    }
    static Border DiagnosticCard(string title,string subtitle,Ui.SymbolRegular symbol,TextBlock body)
    {
        var content=new StackPanel(); var heading=new DockPanel(); var icon=Glyph(symbol,22,"KdbxAccentIcon"); icon.Margin=new Thickness(0,0,12,0); DockPanel.SetDock(icon,Dock.Left); heading.Children.Add(icon);
        var words=new StackPanel(); words.Children.Add(Text(title,16,FontWeights.SemiBold)); words.Children.Add(BodyText(subtitle,12,new Thickness(0,4,0,0))); heading.Children.Add(words); content.Children.Add(heading);
        body.SetResourceReference(TextBlock.ForegroundProperty,"AppSecondary"); body.Margin=new Thickness(0,20,0,0); body.LineHeight=22; content.Children.Add(body);
        var card=Surface(content,24); card.Margin=new Thickness(0,0,0,16); return card;
    }
    Grid SiteRow(string site,bool needsAttention,string? rp=null)
    {
        var row=new Grid(); row.ColumnDefinitions.Add(new ColumnDefinition { Width=GridLength.Auto }); row.ColumnDefinitions.Add(new ColumnDefinition()); row.ColumnDefinitions.Add(new ColumnDefinition { Width=GridLength.Auto });
        var tile=Tile(Glyph(Ui.SymbolRegular.Globe24,16,"AppSecondary"),28); tile.Margin=new Thickness(0,0,10,0); row.Children.Add(tile);
        var text=Text(site,14,FontWeights.Medium); text.VerticalAlignment=VerticalAlignment.Center; Grid.SetColumn(text,1); row.Children.Add(text);
        FrameworkElement badge=needsAttention && rp!=null ? Button("需要检查",()=>ShowSiteDiagnostics(rp)) : Badge("可用于认证"); badge.Margin=new Thickness(12,0,0,0); Grid.SetColumn(badge,2); row.Children.Add(badge); return row;
    }
    void UpdateVisualState(bool opened,int total=0,int signable=0)
    {
        vaultOpened=opened;
        credentialSearch.IsEnabled=opened;
        currentDatabase.Text=string.IsNullOrEmpty(database.Text) ? "尚未选择数据库" : System.IO.Path.GetFileName(database.Text);
        currentDatabase.ToolTip=currentDatabase.Text;
        refresh.IsEnabled=opened && !syncBusy;
        emptyTitle.Text=opened ? "未找到兼容的通行密钥" : "通行密钥会显示在这里";
        emptyDescription.Text=opened ? "数据库已解锁，但没有找到可识别的通行密钥。可查看诊断，或在更新数据库后重新解锁。" : "先解锁数据库，再查看和同步你的凭据。";
        emptyAction.Content=opened ? "查看诊断" : "前往解锁";
        emptyReload.Visibility=opened ? Visibility.Visible : Visibility.Collapsed;
        lockNow.Visibility=opened ? Visibility.Visible : Visibility.Collapsed;
        metrics.Visibility=opened ? Visibility.Visible : Visibility.Collapsed;
        readyGuide.Visibility=opened ? Visibility.Visible : Visibility.Collapsed;
        keysList.Visibility=opened && sites.Items.Count>0 ? Visibility.Visible : Visibility.Collapsed;
        keysEmpty.Visibility=opened && sites.Items.Count>0 ? Visibility.Collapsed : Visibility.Visible;
        loadedNumber.Text=total.ToString(); readyNumber.Text=signable.ToString();
        navigationStatus.Text=opened ? "本地数据库 · 已解锁" : "本地数据库 · 已锁定";
        connectionTitle.Text=opened ? "更换或重新解锁密码库" : "解锁密码库";
        RenderCredentials();
        tray?.SetStatus(opened); UpdateSessionPanel();
    }
}

public sealed record CredentialView(string Rp,string User,string Title,bool Signable,string Reason);
