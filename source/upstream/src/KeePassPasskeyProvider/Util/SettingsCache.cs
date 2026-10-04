// Derived from KeePassPasskey, Copyright (C) 2026 Uwe Koegel.
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
namespace KeePassPasskeyProvider.Util;
internal static class SettingsCache
{
    internal const string SettingsFileName = "Settings.cached.json";
    internal static KeePassPasskeySettings TryLoad() => new()
    {
        SignInVerification = UserVerificationMode.WindowsHello,
        RegistrationVerification = UserVerificationMode.WindowsHello,
        LogLevel = LogLevel.Off,
        CheckForPluginUpdates = false,
        SaveToExistingEntry = false,
        IsCredentialSyncEnabled = true,
    };
    internal static void Save(KeePassPasskeySettings settings) { }
}
