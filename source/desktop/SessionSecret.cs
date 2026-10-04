// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace KdbxPasskeyDesktop;

// Process-scoped encrypted memory only. No persistence or cross-process key export.
internal sealed class SessionSecret : IDisposable
{
    byte[]? protectedBytes;
    readonly int length;
    public SessionSecret(string value)
    {
        byte[] plain = Encoding.UTF8.GetBytes(value);
        length = plain.Length;
        protectedBytes = new byte[Math.Max(16, (length + 15) / 16 * 16)];
        plain.CopyTo(protectedBytes, 0);
        CryptographicOperations.ZeroMemory(plain);
        if (!CryptProtectMemory(protectedBytes, (uint)protectedBytes.Length, 0)) {
            Dispose();
            throw new CryptographicException("Session memory protection failed");
        }
    }
    public string Reveal()
    {
        ObjectDisposedException.ThrowIf(protectedBytes is null, this);
        byte[] copy = (byte[])protectedBytes!.Clone();
        try {
            if (!CryptUnprotectMemory(copy, (uint)copy.Length, 0)) throw new CryptographicException("Session memory unavailable");
            return Encoding.UTF8.GetString(copy, 0, length);
        } finally { CryptographicOperations.ZeroMemory(copy); }
    }
    public void Dispose()
    {
        if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
        protectedBytes = null;
    }
    [DllImport("crypt32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptProtectMemory([In, Out] byte[] memory, uint size, uint flags);
    [DllImport("crypt32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptUnprotectMemory([In, Out] byte[] memory, uint size, uint flags);
}
