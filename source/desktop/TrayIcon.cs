// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;

namespace KdbxPasskeyDesktop;

internal sealed class TrayIcon : IDisposable
{
    const int Callback = 0x8001;
    readonly HwndSource source;
    readonly Action show;
    readonly ContextMenu menu;
    NotifyData data;
    readonly uint taskbarCreated;
    bool disposed;
    IntPtr ownedIcon;
    public TrayIcon(Window owner, Action show, Action lockVault, Action forget, Action exit)
    {
        this.show = show;
        source = new HwndSource(new HwndSourceParameters("KdbxPasskeyTray") { Width=0, Height=0, WindowStyle=0 });
        source.AddHook(Hook);
        taskbarCreated=RegisterWindowMessage("TaskbarCreated");
        ownedIcon=LoadImage(IntPtr.Zero,System.IO.Path.Combine(AppContext.BaseDirectory,"Assets","AppIcon.ico"),1,0,0,0x10|0x40);
        data=new NotifyData { Size=Marshal.SizeOf<NotifyData>(), Window=source.Handle, Id=1, Flags=7, Callback=Callback,
            Icon=ownedIcon!=IntPtr.Zero ? ownedIcon : LoadIcon(IntPtr.Zero, (IntPtr)32512), Tip="KDBX Passkey", Info="", Title="" };
        menu=new ContextMenu { Placement=PlacementMode.MousePoint };
        void Item(string text, Action action) { var item=new MenuItem { Header=text }; item.Click+=(_,_)=>action(); menu.Items.Add(item); }
        Item("打开 KDBX Passkey", show); Item("锁定数据库", lockVault); Item("锁定并忘记本次密码", forget);
        menu.Items.Add(new Separator()); Item("退出", exit);
        if(!Shell_NotifyIcon(0,ref data)) { source.Dispose(); if(ownedIcon!=IntPtr.Zero) DestroyIcon(ownedIcon); throw new InvalidOperationException("Tray unavailable"); }
    }
    public void SetStatus(bool unlocked)
    {
        if(disposed) return;
        data.Tip=unlocked ? "KDBX Passkey · 已解锁" : "KDBX Passkey · 已锁定";
        Shell_NotifyIcon(1,ref data);
    }
    IntPtr Hook(IntPtr hwnd,int message,IntPtr wParam,IntPtr lParam,ref bool handled)
    {
        if((uint)message==taskbarCreated && !disposed) Shell_NotifyIcon(0,ref data);
        if(message==Callback) {
            if(lParam.ToInt64()==0x0202) show();
            if(lParam.ToInt64()==0x0205) { SetForegroundWindow(source.Handle); menu.IsOpen=true; }
            handled=true;
        }
        return IntPtr.Zero;
    }
    public void Dispose()
    {
        if(disposed) return;
        disposed=true; menu.IsOpen=false; Shell_NotifyIcon(2,ref data); source.Dispose(); if(ownedIcon!=IntPtr.Zero) DestroyIcon(ownedIcon);
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct NotifyData {
        public int Size; public IntPtr Window; public uint Id; public uint Flags; public uint Callback; public IntPtr Icon;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=128)] public string Tip;
        public uint State, StateMask;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)] public string Info;
        public uint Timeout;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=64)] public string Title;
        public uint InfoFlags; public Guid Guid; public IntPtr BalloonIcon;
    }
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern IntPtr LoadImage(IntPtr instance,string name,uint type,int width,int height,uint flags);
    [DllImport("user32.dll")] [return:MarshalAs(UnmanagedType.Bool)] static extern bool DestroyIcon(IntPtr icon);
    [DllImport("shell32.dll",CharSet=CharSet.Unicode)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool Shell_NotifyIcon(uint command,ref NotifyData data);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern uint RegisterWindowMessage(string name);
    [DllImport("user32.dll")] static extern IntPtr LoadIcon(IntPtr instance,IntPtr icon);
    [DllImport("user32.dll")] [return:MarshalAs(UnmanagedType.Bool)] static extern bool SetForegroundWindow(IntPtr window);
}
