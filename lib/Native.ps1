# Win32 calls that PowerShell has no cmdlet for. Compiled on first use, which takes a second or two.
#
# GetVisibleWindows: finds console windows. For a classic console window the owner PID reported by
#   GetWindowThreadProcessId is the program running inside it (cmd.exe, bash.exe...), not conhost.exe,
#   because conhost registers the client as the window's owner for compatibility.
# ResetTcp: SetTcpEntry with state DELETE_TCB. The TCP stack sends a RST and forgets the connection.
#   It is the only state SetTcpEntry accepts, it needs Administrator, and it is IPv4 only.

function Initialize-SusNative {
    if ('SusHunt.Native' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace SusHunt
{
    public class WindowInfo
    {
        public long Handle;
        public string ClassName;
        public string Title;
        public int ProcessId;
    }

    public static class Native
    {
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetClassName(IntPtr hWnd, StringBuilder name, int maxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int maxCount);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        public static List<WindowInfo> GetVisibleWindows(string[] classNames)
        {
            HashSet<string> wanted = new HashSet<string>(classNames, StringComparer.OrdinalIgnoreCase);
            List<WindowInfo> found = new List<WindowInfo>();
            EnumWindows(delegate (IntPtr hWnd, IntPtr lParam)
            {
                if (!IsWindowVisible(hWnd)) { return true; }
                StringBuilder cls = new StringBuilder(256);
                GetClassName(hWnd, cls, cls.Capacity);
                if (!wanted.Contains(cls.ToString())) { return true; }
                StringBuilder title = new StringBuilder(512);
                GetWindowText(hWnd, title, title.Capacity);
                uint pid;
                GetWindowThreadProcessId(hWnd, out pid);
                WindowInfo info = new WindowInfo();
                info.Handle = hWnd.ToInt64();
                info.ClassName = cls.ToString();
                info.Title = title.ToString();
                info.ProcessId = (int)pid;
                found.Add(info);
                return true;
            }, IntPtr.Zero);
            return found;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW
        {
            public uint State;
            public uint LocalAddr;
            public uint LocalPort;
            public uint RemoteAddr;
            public uint RemotePort;
        }

        [DllImport("iphlpapi.dll")]
        private static extern uint SetTcpEntry(ref MIB_TCPROW row);

        // Addresses and ports must already be in network byte order.
        public static uint ResetTcp(uint localAddr, uint localPort, uint remoteAddr, uint remotePort)
        {
            MIB_TCPROW row = new MIB_TCPROW();
            row.State = 12; // MIB_TCP_STATE_DELETE_TCB
            row.LocalAddr = localAddr;
            row.LocalPort = localPort;
            row.RemoteAddr = remoteAddr;
            row.RemotePort = remotePort;
            return SetTcpEntry(ref row);
        }
    }
}
'@
}
