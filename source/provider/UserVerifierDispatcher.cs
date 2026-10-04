// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyProvider.Authenticator.Native;
namespace KeePassPasskeyProvider.Authenticator.UserVerification;
internal static class UserVerifierDispatcher
{
    static readonly WindowsHelloUserVerifier verifier = new();
    public static int VerifyForSignIn(SignInVerification request, CancellationToken cancellation)
        => cancellation.IsCancellationRequested ? HResults.NTE_USER_CANCELLED : verifier.VerifyForSignIn(request,cancellation);
    public static (int hr, DatabaseInfo? selectedDatabase, EntryTargetInfo? selectedEntry) VerifyForRegistration(RegistrationVerification request,CancellationToken cancellation)
        => (unchecked((int)0x80004001),null,null);
}
