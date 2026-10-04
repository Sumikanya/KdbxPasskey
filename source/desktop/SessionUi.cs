// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using Ui = Wpf.Ui.Controls;

namespace KdbxPasskeyDesktop;

public sealed partial class MainWindow
{
    TrayIcon? tray;
    bool exitRequested, helloBusy;
    SessionSecret? rememberedSecret, pendingSecret;
    string rememberedPath="", rememberedKeyfile="", pendingPath="", pendingKeyfile="";
    int sessionEpoch;
    Process? helloProcess;
    Border sessionPanel=null!;
    readonly Ui.Button helloUnlock=new() { Content="Windows Hello 解锁", Appearance=Ui.ControlAppearance.Primary };
    readonly TextBlock sessionDescription=new() { TextWrapping=TextWrapping.Wrap };

    void InitializeTray()
    {
        try { tray=new TrayIcon(this,ShowMainWindow,()=>Send(new { type="lock" }),()=> { ForgetSession(); Send(new { type="lock" }); },()=> { exitRequested=true; Close(); }); }
        catch { if(preview) throw; status.Text="托盘初始化失败，关闭窗口将退出程序。"; }
        StateChanged+=(_,_)=> { if(WindowState==WindowState.Minimized && tray is not null && !closing) HideToTray(); };
        Application.Current.SessionEnding+=(_,_)=> { exitRequested=true; ForgetSession(); };
    }
    public void ShowMainWindow()
    {
        if(closing) return;
        ShowInTaskbar=true; Show(); WindowState=WindowState.Normal; Activate();
    }
    void HideToTray()
    {
        ShowInTaskbar=false; Hide();
    }
    void BuildSessionPanel(StackPanel page)
    {
        var body=new StackPanel();
        body.Children.Add(Text("本次运行已记住解锁信息",16,FontWeights.SemiBold));
        sessionDescription.SetResourceReference(TextBlock.ForegroundProperty,"AppSecondary");
        sessionDescription.Margin=new Thickness(0,8,0,16); body.Children.Add(sessionDescription);
        var buttons=new WrapPanel(); Primary(helloUnlock); helloUnlock.Click+=async (_,_)=>await ResumeWithHello();
        buttons.Children.Add(helloUnlock);
        var forget=Button("忘记本次密码",ForgetSession); forget.Margin=new Thickness(12,0,0,0); buttons.Children.Add(forget);
        body.Children.Add(buttons); sessionPanel=Surface(body,24); sessionPanel.Margin=new Thickness(0,16,0,0);
        sessionPanel.Visibility=Visibility.Collapsed; page.Children.Add(sessionPanel);
    }
    void UpdateSessionPanel()
    {
        if(sessionPanel is null) return;
        sessionPanel.Visibility=rememberedSecret is not null && !vaultOpened ? Visibility.Visible : Visibility.Collapsed;
        sessionDescription.Text=Path.GetFileName(rememberedPath)+"：通过 Windows Hello 恢复；退出程序后需重新输入主密码。";
        helloUnlock.IsEnabled=!helloBusy;
        if(rememberedSecret is not null && !vaultOpened) { connection.IsExpanded=false; connectionTitle.Text="使用主密码重新解锁"; }
    }
    void ForgetSession()
    {
        sessionEpoch++;
        rememberedSecret?.Dispose(); rememberedSecret=null; pendingSecret?.Dispose(); pendingSecret=null;
        rememberedPath=rememberedKeyfile=pendingPath=pendingKeyfile="";
        UpdateSessionPanel();
        if(!vaultOpened) { connection.IsExpanded=true; connectionTitle.Text="解锁密码库"; }
    }
    void AcceptSession()
    {
        if(pendingSecret is not null) {
            rememberedSecret?.Dispose(); rememberedSecret=pendingSecret; pendingSecret=null;
            rememberedPath=pendingPath; rememberedKeyfile=pendingKeyfile;
        }
        if(!preview) SavePreferences();
        UpdateSessionPanel();
    }
    void RejectPendingSession()
    {
        pendingSecret?.Dispose(); pendingSecret=null;
        UpdateSessionPanel();
    }
    void CheckSessionUi()
    {
        var secret=new SessionSecret("temporary-ui-test-password");
        if(secret.Reveal()!="temporary-ui-test-password") throw new InvalidOperationException("Session protection round trip failed");
        secret.Dispose();
        try { secret.Reveal(); throw new InvalidOperationException("Disposed session secret was readable"); }
        catch(ObjectDisposedException) { }
        pendingSecret=new SessionSecret("temporary-session"); pendingPath="fixture.kdbx";
        AcceptSession(); vaultOpened=false; UpdateSessionPanel();
        if(rememberedSecret is null || sessionPanel.Visibility!=Visibility.Visible || connection.IsExpanded)
            throw new InvalidOperationException("Session resume state failed");
        ForgetSession();
        if(rememberedSecret is not null || sessionPanel.Visibility!=Visibility.Collapsed || !connection.IsExpanded)
            throw new InvalidOperationException("Session forgetting failed");
    }
    async Task ResumeWithHello()
    {
        if(helloBusy || rememberedSecret is null || closing) return;
        helloBusy=true; helloUnlock.IsEnabled=false;
        int epoch=sessionEpoch;
        try {
            ShowMainWindow(); status.Text="请完成 Windows Hello 验证…";
            var start=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"Provider","KeePassPasskeyProvider.exe")) {
                UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true
            };
            start.ArgumentList.Add("/verify_session"); start.ArgumentList.Add(new WindowInteropHelper(this).Handle.ToInt64().ToString());
            using var process=new Process { StartInfo=start }; helloProcess=process;
            process.Start();
            var output=process.StandardOutput.ReadToEndAsync(); var errors=process.StandardError.ReadToEndAsync();
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(120));
            try { await process.WaitForExitAsync(timeout.Token); }
            catch(OperationCanceledException) { process.Kill(entireProcessTree:true); status.Text="Windows Hello 验证超时，请重试。"; return; }
            string result=(await output).Trim(); await errors;
            if(process.ExitCode!=0 || result!="HELLO verified") { status.Text="未完成 Windows Hello 验证，可重试或使用主密码解锁。"; return; }
            if(closing || epoch!=sessionEpoch || rememberedSecret is null) { status.Text="解锁状态已变化，请重新验证。"; return; }
            database.Text=rememberedPath; keyfile.Text=rememberedKeyfile;
            unlock.IsEnabled=false;
            Send(new { type="unlock", path=rememberedPath, keyfile=rememberedKeyfile, password=rememberedSecret.Reveal() });
        } catch { if(!closing) status.Text="Windows Hello 不可用，请使用主密码解锁。"; }
        finally { helloProcess=null; helloBusy=false; UpdateSessionPanel(); }
    }
}
