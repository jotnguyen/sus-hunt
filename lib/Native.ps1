# Win32 calls that PowerShell has no cmdlet for, or only reaches through slow WMI.
# Compiled on first use, which takes a second or two.
#
# GetVisibleWindows: finds console windows. For a classic console window the owner PID reported by
#   GetWindowThreadProcessId is the program running inside it (cmd.exe, bash.exe...), not conhost.exe,
#   because conhost registers the client as the window's owner for compatibility.
# ListProcesses / DescribeProcess: Toolhelp snapshot plus PROCESS_QUERY_LIMITED_INFORMATION queries.
#   About 1 ms, where Get-CimInstance Win32_Process takes ~200 ms and loads the WMI service.
# GetTcpConnections: GetExtendedTcpTable, the API netstat -ano uses. About 1 ms, where
#   Get-NetTCPConnection takes ~800 ms.
# FindRecentFiles: recursive walk for the files command; a PowerShell loop is ~20x slower.
# ReadHeads: first 4 KB of many files in parallel (antivirus makes each first open slow).
# ShannonEntropy: byte histogram -> bits per byte, for spotting packed PE sections (lib/Files.ps1).
# ResetTcp: SetTcpEntry with state DELETE_TCB. The TCP stack sends a RST and forgets the connection.
#   It is the only state SetTcpEntry accepts, it needs Administrator, and it is IPv4 only.
#
# The namespace is versioned (SusHunt.V4) because a session cannot redefine an already-loaded type.

function Initialize-SusNative {
    if ('SusHunt.V4.Win32' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SusHunt.V4
{
    public class WindowInfo
    {
        public long Handle;
        public string ClassName;
        public string Title;
        public int ProcessId;
    }

    public class ProcessInfo
    {
        public int ProcessId;
        public int ParentProcessId;
        public string Name;
        public string ExecutablePath;
        public string CommandLine;
        public DateTime? CreationDate;
    }

    public class TcpInfo
    {
        public string State;
        public string LocalAddress;
        public int LocalPort;
        public string RemoteAddress;
        public int RemotePort;
        public int OwningProcess;
    }

    public static class Win32
    {
        // ---- Recent files (lib/Files.ps1) ------------------------------------------------------
        // Walks folders by hand: one unreadable folder must not end the walk, junctions (reparse
        // points) are skipped because AppData has loops, and cloud placeholders are skipped because
        // reading one downloads it. A PowerShell loop over 100k+ entries takes a minute; this, seconds.
        public static List<FileInfo> FindRecentFiles(string[] roots, DateTime sinceUtc, string[] skipDirPatterns)
        {
            const FileAttributes cloud = (FileAttributes)(0x1000 | 0x40000 | 0x400000); // OFFLINE, RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS
            var skip = new List<Regex>();
            foreach (string p in skipDirPatterns ?? new string[0]) skip.Add(new Regex(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var stack = new Stack<string>(roots);
            var found = new List<FileInfo>();
            while (stack.Count > 0)
            {
                string dir = stack.Pop();
                if (!seen.Add(dir)) continue;
                try
                {
                    foreach (FileSystemInfo item in new DirectoryInfo(dir).EnumerateFileSystemInfos())
                    {
                        FileAttributes a = item.Attributes;
                        if ((a & FileAttributes.ReparsePoint) != 0) continue;
                        if ((a & FileAttributes.Directory) != 0)
                        {
                            bool skipped = false;
                            foreach (Regex rx in skip) { if (rx.IsMatch(item.FullName)) { skipped = true; break; } }
                            if (!skipped) stack.Push(item.FullName);
                            continue;
                        }
                        if ((a & cloud) != 0) continue;
                        if (item.LastWriteTimeUtc >= sinceUtc || item.CreationTimeUtc >= sinceUtc) found.Add((FileInfo)item);
                    }
                }
                catch (Exception) { }   // access denied, or the folder vanished mid-walk
            }
            return found;
        }

        // First bytes of many files, 8 at a time. Antivirus scans a file the first time anything
        // opens it, so reading thousands of headers one by one is slow for reasons outside our code.
        // A null entry means the file could not be read (locked, gone, access denied).
        public static byte[][] ReadHeads(string[] paths, int count)
        {
            var heads = new byte[paths.Length][];
            Parallel.For(0, paths.Length, new ParallelOptions { MaxDegreeOfParallelism = 8 }, i =>
            {
                try
                {
                    using (var fs = new FileStream(paths[i], FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        var buf = new byte[(int)Math.Min((long)count, fs.Length)];
                        int read = 0, n;
                        while (read < buf.Length && (n = fs.Read(buf, read, buf.Length - read)) > 0) read += n;
                        if (read < buf.Length) Array.Resize(ref buf, read);
                        heads[i] = buf;
                    }
                }
                catch (Exception) { heads[i] = null; }
            });
            return heads;
        }

        // ---- Shannon entropy (lib/Files.ps1) ---------------------------------------------------
        // Bits per byte, 0..8. A PowerShell loop over a few MB of bytes takes seconds; this takes ms.
        public static double ShannonEntropy(byte[] data, int offset, int count)
        {
            if (data == null || count <= 0) return 0.0;
            long[] freq = new long[256];
            int end = offset + count;
            for (int i = offset; i < end; i++) freq[data[i]]++;
            double h = 0.0;
            for (int b = 0; b < 256; b++)
            {
                if (freq[b] == 0) continue;
                double p = (double)freq[b] / count;
                h -= p * Math.Log(p, 2.0);
            }
            return h;
        }

        // ---- Windows -------------------------------------------------------------------------
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

        // ---- Processes -----------------------------------------------------------------------
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROCESSENTRY32W
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Process32FirstW(IntPtr snapshot, ref PROCESSENTRY32W entry);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Process32NextW(IntPtr snapshot, ref PROCESSENTRY32W entry);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int processId);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageNameW(IntPtr process, int flags, StringBuilder name, ref int size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr process, int infoClass, IntPtr info, int length, out int returnLength);

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        // PID, parent PID and image name of every process. No handles opened, so it is cheap.
        public static List<ProcessInfo> ListProcesses()
        {
            List<ProcessInfo> list = new List<ProcessInfo>();
            IntPtr snapshot = CreateToolhelp32Snapshot(2, 0);   // TH32CS_SNAPPROCESS
            if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1)) { return list; }
            try
            {
                PROCESSENTRY32W entry = new PROCESSENTRY32W();
                entry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W));
                if (Process32FirstW(snapshot, ref entry))
                {
                    do
                    {
                        ProcessInfo p = new ProcessInfo();
                        p.ProcessId = (int)entry.th32ProcessID;
                        p.ParentProcessId = (int)entry.th32ParentProcessID;
                        p.Name = entry.szExeFile;
                        list.Add(p);
                    } while (Process32NextW(snapshot, ref entry));
                }
            }
            finally { CloseHandle(snapshot); }
            return list;
        }

        // Fills in path, command line and start time (and the parent PID if it is unknown).
        // Protected processes refuse even limited access; their fields stay null.
        public static void DescribeProcess(ProcessInfo p)
        {
            IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, p.ProcessId);
            if (h == IntPtr.Zero) { return; }
            try
            {
                StringBuilder path = new StringBuilder(1024);
                int size = path.Capacity;
                if (QueryFullProcessImageNameW(h, 0, path, ref size)) { p.ExecutablePath = path.ToString(0, size); }
                long creation, exit, kernel, user;
                if (GetProcessTimes(h, out creation, out exit, out kernel, out user)) { p.CreationDate = DateTime.FromFileTime(creation); }
                p.CommandLine = ReadCommandLine(h);
                if (p.ParentProcessId == 0) { p.ParentProcessId = ReadParentId(h); }
                if (string.IsNullOrEmpty(p.Name) && p.ExecutablePath != null) { p.Name = System.IO.Path.GetFileName(p.ExecutablePath); }
            }
            finally { CloseHandle(h); }
        }

        public static ProcessInfo DescribePid(int processId)
        {
            ProcessInfo p = new ProcessInfo();
            p.ProcessId = processId;
            DescribeProcess(p);
            return p;
        }

        private static string ReadCommandLine(IntPtr h)
        {
            // ProcessCommandLineInformation (60) returns a UNICODE_STRING followed by the text.
            int length;
            NtQueryInformationProcess(h, 60, IntPtr.Zero, 0, out length);
            if (length <= 0) { return null; }
            IntPtr buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (NtQueryInformationProcess(h, 60, buffer, length, out length) != 0) { return null; }
                int bytes = Marshal.ReadInt16(buffer) & 0xFFFF;
                IntPtr text = Marshal.ReadIntPtr(buffer, IntPtr.Size);   // Buffer field follows Length, MaximumLength and padding
                return bytes > 0 ? Marshal.PtrToStringUni(text, bytes / 2) : null;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static int ReadParentId(IntPtr h)
        {
            // ProcessBasicInformation (0): six pointer-sized fields; the last is the parent PID.
            int size = IntPtr.Size * 6;
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                int returned;
                if (NtQueryInformationProcess(h, 0, buffer, size, out returned) != 0) { return 0; }
                return (int)Marshal.ReadIntPtr(buffer, IntPtr.Size * 5).ToInt64();
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        // ---- New-process polling -------------------------------------------------------------
        // SystemProcessInformation (5) returns every process in one buffer, start time included.
        // The watcher keeps PID -> start time here and only hands PowerShell the new ones, so a
        // quiet tick costs a single system call and no PowerShell work.
        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int infoClass, IntPtr info, int length, out int returnLength);

        private static Dictionary<int, long> knownStarts = null;

        public static List<ProcessInfo> PollNewProcesses()
        {
            List<ProcessInfo> fresh = new List<ProcessInfo>();
            if (IntPtr.Size != 8) { return PollNewProcessesToolhelp(); }   // offsets below are for 64-bit
            int size = 1 << 20;
            IntPtr buffer = IntPtr.Zero;
            try
            {
                for (int attempt = 0; attempt < 5; attempt++)
                {
                    buffer = Marshal.AllocHGlobal(size);
                    int needed;
                    int status = NtQuerySystemInformation(5, buffer, size, out needed);
                    if (status == 0) { break; }
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                    if (status != unchecked((int)0xC0000004)) { return fresh; }   // not STATUS_INFO_LENGTH_MISMATCH
                    size = Math.Max(size * 2, needed + 65536);
                }
                if (buffer == IntPtr.Zero) { return fresh; }

                Dictionary<int, long> now = new Dictionary<int, long>();
                IntPtr entry = buffer;
                while (true)
                {
                    // SYSTEM_PROCESS_INFORMATION (x64): CreateTime @32, ImageName @56,
                    // UniqueProcessId @80, InheritedFromUniqueProcessId @88.
                    int next = Marshal.ReadInt32(entry, 0);
                    long created = Marshal.ReadInt64(entry, 32);
                    int pid = (int)Marshal.ReadIntPtr(entry, 80).ToInt64();
                    now[pid] = created;
                    long before;
                    bool isNew = knownStarts != null && (!knownStarts.TryGetValue(pid, out before) || before != created);
                    if (isNew)
                    {
                        ProcessInfo p = new ProcessInfo();
                        p.ProcessId = pid;
                        p.ParentProcessId = (int)Marshal.ReadIntPtr(entry, 88).ToInt64();
                        int nameBytes = Marshal.ReadInt16(entry, 56) & 0xFFFF;
                        IntPtr namePtr = Marshal.ReadIntPtr(entry, 64);
                        p.Name = nameBytes > 0 && namePtr != IntPtr.Zero ? Marshal.PtrToStringUni(namePtr, nameBytes / 2) : null;
                        if (created > 0) { p.CreationDate = DateTime.FromFileTime(created); }
                        fresh.Add(p);
                    }
                    if (next == 0) { break; }
                    entry = IntPtr.Add(entry, next);
                }
                knownStarts = now;
            }
            finally { if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); } }
            return fresh;
        }

        // Same contract on 32-bit PowerShell, using the Toolhelp list (slower, no start time).
        private static Dictionary<int, string> knownNames = null;
        private static List<ProcessInfo> PollNewProcessesToolhelp()
        {
            List<ProcessInfo> fresh = new List<ProcessInfo>();
            Dictionary<int, string> now = new Dictionary<int, string>();
            foreach (ProcessInfo p in ListProcesses())
            {
                now[p.ProcessId] = p.Name;
                string before;
                if (knownNames != null && (!knownNames.TryGetValue(p.ProcessId, out before) || before != p.Name)) { fresh.Add(p); }
            }
            knownNames = now;
            return fresh;
        }

        // Forget what we have seen, so the next poll only primes the list (returns nothing).
        public static void ResetProcessPolling() { knownStarts = null; knownNames = null; }

        // ---- TCP -----------------------------------------------------------------------------
        [DllImport("iphlpapi.dll")]
        private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int addressFamily, int tableClass, uint reserved);

        private static readonly string[] TcpStates = { "Unknown", "Closed", "Listen", "SynSent", "SynReceived",
            "Established", "FinWait1", "FinWait2", "CloseWait", "Closing", "LastAck", "TimeWait", "DeleteTCB" };

        private static int Port(int raw) { return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF); }
        private static string State(int raw) { return raw >= 0 && raw < TcpStates.Length ? TcpStates[raw] : raw.ToString(); }

        public static List<TcpInfo> GetTcpConnections()
        {
            List<TcpInfo> list = new List<TcpInfo>();
            ReadTcpTable(2, list);    // AF_INET
            ReadTcpTable(23, list);   // AF_INET6
            return list;
        }

        private static void ReadTcpTable(int family, List<TcpInfo> list)
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, 5, 0);   // TCP_TABLE_OWNER_PID_ALL
            for (int attempt = 0; attempt < 3 && size > 0; attempt++)
            {
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint rc = GetExtendedTcpTable(buffer, ref size, false, family, 5, 0);
                    if (rc == 122) { continue; }   // ERROR_INSUFFICIENT_BUFFER: the table grew, try again
                    if (rc != 0) { return; }
                    int count = Marshal.ReadInt32(buffer);
                    IntPtr row = IntPtr.Add(buffer, 4);
                    for (int i = 0; i < count; i++)
                    {
                        TcpInfo t = new TcpInfo();
                        if (family == 2)
                        {
                            // MIB_TCPROW_OWNER_PID: state, local addr, local port, remote addr, remote port, pid
                            t.State = State(Marshal.ReadInt32(row, 0));
                            t.LocalAddress = new IPAddress((uint)Marshal.ReadInt32(row, 4)).ToString();
                            t.LocalPort = Port(Marshal.ReadInt32(row, 8));
                            t.RemoteAddress = new IPAddress((uint)Marshal.ReadInt32(row, 12)).ToString();
                            t.RemotePort = Port(Marshal.ReadInt32(row, 16));
                            t.OwningProcess = Marshal.ReadInt32(row, 20);
                            row = IntPtr.Add(row, 24);
                        }
                        else
                        {
                            // MIB_TCP6ROW_OWNER_PID: local addr[16], scope, port, remote addr[16], scope, port, state, pid
                            byte[] local = new byte[16];
                            byte[] remote = new byte[16];
                            Marshal.Copy(row, local, 0, 16);
                            Marshal.Copy(IntPtr.Add(row, 24), remote, 0, 16);
                            t.LocalAddress = new IPAddress(local).ToString();
                            t.LocalPort = Port(Marshal.ReadInt32(row, 20));
                            t.RemoteAddress = new IPAddress(remote).ToString();
                            t.RemotePort = Port(Marshal.ReadInt32(row, 44));
                            t.State = State(Marshal.ReadInt32(row, 48));
                            t.OwningProcess = Marshal.ReadInt32(row, 52);
                            row = IntPtr.Add(row, 56);
                        }
                        list.Add(t);
                    }
                    return;
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
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

function Get-NativeProcess {
    # Win32_Process-shaped object from the fast native queries, so the rest of the code does not care.
    param([int]$ProcessId, [int]$ParentProcessId = 0, [string]$Name)
    Initialize-SusNative
    $info = New-Object SusHunt.V4.ProcessInfo
    $info.ProcessId = $ProcessId
    $info.ParentProcessId = $ParentProcessId
    $info.Name = $Name
    [SusHunt.V4.Win32]::DescribeProcess($info)
    ConvertFrom-NativeProcess $info
}

function ConvertFrom-NativeProcess {
    param($Info)
    [pscustomobject]@{
        Name            = $Info.Name
        ProcessId       = [int]$Info.ProcessId
        ParentProcessId = [int]$Info.ParentProcessId
        CommandLine     = $Info.CommandLine
        ExecutablePath  = $Info.ExecutablePath
        CreationDate    = if ($Info.CreationDate) { [datetime]$Info.CreationDate } else { $null }
    }
}
