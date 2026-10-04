// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
using KeePassPasskeyProvider.Authenticator;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyProvider.Util;
using Windows.Security.Credentials.UI;
namespace KeePassPasskeyProvider;
internal static class Program
{
    [MTAThread]
    static int Main(string[] args)
    {
        KeePassPasskeySettings.Current=SettingsCache.TryLoad();
        if(args.Length>0 && args[0]=="/verify_session") return VerifySession(args).GetAwaiter().GetResult();
        if(args.Length>0 && args[0]=="/runtime_check") {
            var checks=new {
                helloRequired=KeePassPasskeySettings.Current.SignInVerification==UserVerificationMode.WindowsHello,
                lightLogo=LogoResources.LightThemeSvg.Length>0,darkLogo=LogoResources.DarkThemeSvg.Length>0,
                clsid=PluginConstants.KeePassPasskeyProviderClsid.ToString(),
                avalonia=AppDomain.CurrentDomain.GetAssemblies().Any(a=>a.GetName().Name!.StartsWith("Avalonia"))
            };
            Console.WriteLine(JsonSerializer.Serialize(checks));
            return checks.helloRequired && checks.lightLogo && checks.darkLogo && !checks.avalonia ? 0 : 1;
        }
        if(args.Any(a=>a.Equals("-ActivateAuthenticator",StringComparison.OrdinalIgnoreCase))) return ComServer.RunComServer();
        if(args.Length==0 || args[0]=="/settings") {
            Process.Start(new ProcessStartInfo(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"..","KdbxPasskey.exe"))) { UseShellExecute=false }); return 0;
        }
        if(args[0]=="/synccredential") {
            PluginRegistration.EnsureRegistered();
            bool ok=CredentialCache.SyncToWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);
            Console.WriteLine(CredentialCache.LastSyncStatus); return ok ? 0 : 1;
        }
        return RunManagementCommand(args);
    }
    static async Task<int> VerifySession(string[] args)
    {
        try {
            if(args.Length!=2 || !long.TryParse(args[1],out long handle) || handle==0 || !IsWindow((nint)handle)) return 2;
            if(await UserConsentVerifier.CheckAvailabilityAsync()!=UserConsentVerifierAvailability.Available) { Console.WriteLine("HELLO unavailable"); return 2; }
            var result=await UserConsentVerifierInterop.RequestVerificationForWindowAsync((nint)handle,"解锁 KDBX Passkey 中本次运行已记住的数据库");
            if(result==UserConsentVerificationResult.Verified) { Console.WriteLine("HELLO verified"); return 0; }
            Console.WriteLine("HELLO cancelled"); return 2;
        } catch { Console.WriteLine("HELLO unavailable"); return 2; }
    }
    [DllImport("user32.dll")] [return:MarshalAs(UnmanagedType.Bool)] static extern bool IsWindow(nint hwnd);
	private static int RunManagementCommand(string[] args)
	{
		string cmd = args.Length > 1 ? args[1] : (args.Length > 0 ? args[0] : string.Empty);

		switch (cmd.ToLowerInvariant())
		{
            case "/ensure_registered":
            {
                try
                {
                    int hr = PluginRegistration.GetState(out var state);
                    if (hr >= 0)
                    {
                        Console.WriteLine($"REGISTER ready state={state} hr=0x{hr:X8}");
                        return 0;
                    }
                    hr = PluginRegistration.Register();
                    Console.WriteLine($"REGISTER {(hr >= 0 ? "ready" : "failed")} stage=AddAuthenticator hr=0x{hr:X8}");
                    return hr >= 0 ? 0 : 1;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"REGISTER failed type={ex.GetType().Name} hr=0x{ex.HResult:X8}");
                    return 1;
                }
            }
			case "/register":
			{
				int hr = PluginRegistration.Register();
				if (hr >= HResults.S_OK)
					Console.WriteLine("KeePassPasskey Provider registered successfully.");
				else
					Console.WriteLine($"Registration failed: 0x{hr:X8}");
				return hr >= HResults.S_OK ? 0 : 1;
			}

			case "/unregister":
			{
				int hr = PluginRegistration.Unregister();
				if (hr >= HResults.S_OK)
					Console.WriteLine("KeePassPasskey Provider unregistered.");
				else
					Console.WriteLine($"Unregister failed: 0x{hr:X8}");
				return hr >= HResults.S_OK ? 0 : 1;
			}

			case "/status":
			{
				int hr = PluginRegistration.GetState(out var state);
				if (hr >= HResults.S_OK)
				{
					string stateStr = state == AuthenticatorState.AuthenticatorState_Enabled
						? "Enabled" : "Disabled";
					Console.WriteLine($"Plugin state: {stateStr}");
				}
				else
				{
					Console.WriteLine($"GetPluginState failed: 0x{hr:X8}");
				}
				return hr >= HResults.S_OK ? 0 : 1;
			}

			case "/dumpcredentials":
			{
				CredentialCache.DumpCredentials(
					PluginConstants.KeePassPasskeyProviderClsid, Console.WriteLine);
				return 0;
			}

			case "/clearcredentials":
			{
				bool cleared = CredentialCache.ClearWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);
				Console.WriteLine(cleared
					? "Windows credential cache cleared. It repopulates on the next database open or save."
					: "Could not clear the Windows credential cache; see the provider log.");
				return cleared ? 0 : 1;
			}

			default:
				Console.WriteLine("KeePassPasskey Provider");
				Console.WriteLine("Usage: KeePassPasskeyProvider.exe /register | /unregister | /status | /dumpcredentials | /clearcredentials");
				return 0;
		}
	}
}
