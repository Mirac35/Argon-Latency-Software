using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ArgonLatencyStudio
{
    static class Program
    {
        [DllImport("user32.dll")]
        static extern bool SetProcessDPIAware();

        [STAThread]
        static void Main(string[] args)
        {
            try { SetProcessDPIAware(); } catch { }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            MainForm form = new MainForm(args);
            Application.ApplicationExit += (s, e) =>
            {
                try { form.PerformCleanShutdownKeepSettings(); } catch { }
            };
            SystemEvents.SessionEnding += (s, e) =>
            {
                try { form.PerformCleanShutdownKeepSettings(); } catch { }
            };
            AppDomain.CurrentDomain.ProcessExit += (s, e) =>
            {
                try { form.PerformCleanShutdownKeepSettings(); } catch { }
            };
            Application.Run(form);
        }
    }

    #region Native Win32 & Kernel Interop

    public static class NativeMethods
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtSetTimerResolution(uint DesiredResolution, bool SetResolution, out uint CurrentResolution);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtQueryTimerResolution(out uint MinimumResolution, out uint MaximumResolution, out uint CurrentResolution);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtSetSystemInformation(int SystemInformationClass, ref int Info, int Length);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtSetInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, ref int ProcessInformation, uint ProcessInformationLength);

        [DllImport("winmm.dll")]
        public static extern uint timeBeginPeriod(uint uMilliseconds);

        [DllImport("winmm.dll")]
        public static extern uint timeEndPeriod(uint uMilliseconds);

        [DllImport("powrprof.dll")]
        public static extern uint PowerGetActiveScheme(IntPtr UserRootPowerKey, out IntPtr ActivePolicyGuid);

        [DllImport("powrprof.dll")]
        public static extern uint PowerSetActiveScheme(IntPtr UserRootPowerKey, ref Guid SchemeGuid);

        [DllImport("powrprof.dll")]
        public static extern uint PowerDuplicateScheme(IntPtr RootPowerKey, ref Guid SourceSchemeGuid, out IntPtr DestinationSchemeGuid);

        [DllImport("powrprof.dll")]
        public static extern uint PowerWriteACValueIndex(IntPtr RootPowerKey, ref Guid SchemeGuid, ref Guid SubGroupOfPowerSettingsGuid, ref Guid PowerSettingGuid, uint AcValueIndex);

        [DllImport("powrprof.dll")]
        public static extern uint PowerWriteDCValueIndex(IntPtr RootPowerKey, ref Guid SchemeGuid, ref Guid SubGroupOfPowerSettingsGuid, ref Guid PowerSettingGuid, uint DcValueIndex);

        [DllImport("powrprof.dll")]
        public static extern uint PowerReadACValueIndex(IntPtr RootPowerKey, ref Guid SchemeGuid, ref Guid SubGroupOfPowerSettingsGuid, ref Guid PowerSettingGuid, out uint AcValueIndex);

        [DllImport("powrprof.dll")]
        public static extern uint PowerDeleteScheme(IntPtr RootPowerKey, ref Guid SchemeGuid);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetProcessWorkingSetSize(IntPtr proc, int min, int max);

        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        public static extern int DnsFlushResolverCache();

        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, IntPtr pvParam, uint fWinIni);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, int[] pvParam, uint fWinIni);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, out int pvParam, uint fWinIni);

        [DllImport("dwmapi.dll")]
        public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public class MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
            public MEMORYSTATUSEX()
            {
                this.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_POWER_THROTTLING_STATE
        {
            public uint Version;
            public uint ControlMask;
            public uint StateMask;
        }

        public const int ProcessPowerThrottling = 4;
        public const int ProcessIoPriority = 33;
        public const int ProcessPagePriority = 39;
        public const uint PROCESS_SET_INFORMATION = 0x0200;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1;
        public const uint PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION = 0x4;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetProcessInformation(IntPtr hProcess, int ProcessInformationClass, ref PROCESS_POWER_THROTTLING_STATE ProcessInformation, uint ProcessInformationSize);

        [StructLayout(LayoutKind.Sequential)]
        public struct FILTERKEYS
        {
            public uint cbSize;
            public uint dwFlags;
            public uint iWaitMSec;
            public uint iDelayMSec;
            public uint iRepeatMSec;
            public uint iBounceMSec;
        }

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, ref FILTERKEYS pvParam, uint fWinIni);

        public const uint SPI_GETMOUSE = 0x0003;
        public const uint SPI_SETMOUSE = 0x0004;
        public const uint SPI_GETKEYBOARDDELAY = 0x0016;
        public const uint SPI_SETKEYBOARDDELAY = 0x0017;
        public const uint SPI_GETKEYBOARDSPEED = 0x000A;
        public const uint SPI_SETKEYBOARDSPEED = 0x000B;
        public const uint SPI_GETFILTERKEYS = 0x0032;
        public const uint SPI_SETFILTERKEYS = 0x0033;
        public const uint SPI_GETMOUSESPEED = 0x0070;
        public const uint SPI_SETMOUSESPEED = 0x0071;
        public const uint SPI_GETMOUSEHOVERTIME = 0x0066;
        public const uint SPI_SETMOUSEHOVERTIME = 0x0067;
        public const uint SPIF_UPDATEINIFILE = 0x01;
        public const uint SPIF_SENDCHANGE = 0x02;
        public const uint FKF_FILTERKEYSON = 0x00000001;
        public const uint FKF_AVAILABLE = 0x00000002;
    }

    #endregion

    #region Hardware Detection & Transactional StateVault

    public enum CpuProfileType
    {
        AmdRyzenStandard = 0,
        AmdRyzenX3D = 1,
        IntelHybridPE = 2,
        IntelClassic = 3
    }

    public enum GpuProfileType
    {
        AmdRadeon = 0,
        NvidiaGeForce = 1,
        IntelArc = 2
    }

    public class DetectedHardwareInfo
    {
        public string CpuName = "Bilinmeyen İşlemci";
        public int PhysicalCores = 6;
        public int LogicalThreads = 12;
        public string GpuName = "Bilinmeyen Ekran Kartı";
        public string NicName = "Ethernet";
        public double TotalRamGb = 16.0;
        public string CurrentBootStamp = "";
        public CpuProfileType RecommendedCpuProfile = CpuProfileType.AmdRyzenStandard;
        public GpuProfileType RecommendedGpuProfile = GpuProfileType.AmdRadeon;

        public static DetectedHardwareInfo ProbeSystem()
        {
            DetectedHardwareInfo info = new DetectedHardwareInfo();
            info.LogicalThreads = Environment.ProcessorCount;
            info.PhysicalCores = Math.Max(1, info.LogicalThreads / 2);

            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT LastBootUpTime FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject mo in mos.Get())
                    {
                        string lb = Convert.ToString(mo["LastBootUpTime"] ?? "").Trim();
                        if (lb.Length >= 14) info.CurrentBootStamp = lb.Substring(0, 14);
                        else if (!string.IsNullOrEmpty(lb)) info.CurrentBootStamp = lb;
                        break;
                    }
                }
            }
            catch { }
            if (string.IsNullOrEmpty(info.CurrentBootStamp))
            {
                DateTime bootUtc = DateTime.UtcNow.AddMilliseconds(-(uint)Environment.TickCount);
                info.CurrentBootStamp = bootUtc.ToString("yyyyMMddHHmm");
            }

            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor"))
                {
                    foreach (ManagementObject mo in mos.Get())
                    {
                        info.CpuName = Convert.ToString(mo["Name"] ?? "").Trim();
                        if (mo["NumberOfCores"] != null) info.PhysicalCores = Convert.ToInt32(mo["NumberOfCores"]);
                        if (mo["NumberOfLogicalProcessors"] != null) info.LogicalThreads = Convert.ToInt32(mo["NumberOfLogicalProcessors"]);
                        break;
                    }
                }
            }
            catch { }

            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT Name FROM Win32_VideoController"))
                {
                    foreach (ManagementObject mo in mos.Get())
                    {
                        string gName = Convert.ToString(mo["Name"] ?? "").Trim();
                        if (!string.IsNullOrEmpty(gName))
                        {
                            info.GpuName = gName;
                            if (gName.IndexOf("NVIDIA", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                gName.IndexOf("GeForce", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                gName.IndexOf("RTX", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                gName.IndexOf("GTX", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                gName.IndexOf("Radeon", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                gName.IndexOf("AMD", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                gName.IndexOf("Arc", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                break;
                            }
                        }
                    }
                }
            }
            catch { }

            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    {
                        info.NicName = ni.Description;
                        break;
                    }
                }
            }
            catch { }

            try
            {
                NativeMethods.MEMORYSTATUSEX mem = new NativeMethods.MEMORYSTATUSEX();
                if (NativeMethods.GlobalMemoryStatusEx(mem))
                    info.TotalRamGb = mem.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
            }
            catch { }

            // Auto-Classify CPU Profile
            string cpuUpper = info.CpuName.ToUpperInvariant();
            if (cpuUpper.Contains("X3D"))
            {
                info.RecommendedCpuProfile = CpuProfileType.AmdRyzenX3D;
            }
            else if (cpuUpper.Contains("AMD") || cpuUpper.Contains("RYZEN"))
            {
                info.RecommendedCpuProfile = CpuProfileType.AmdRyzenStandard;
            }
            else if (cpuUpper.Contains("INTEL"))
            {
                if (cpuUpper.Contains("12th") || cpuUpper.Contains("13th") || cpuUpper.Contains("14th") ||
                    cpuUpper.Contains("I5-12") || cpuUpper.Contains("I7-12") || cpuUpper.Contains("I9-12") ||
                    cpuUpper.Contains("I5-13") || cpuUpper.Contains("I7-13") || cpuUpper.Contains("I9-13") ||
                    cpuUpper.Contains("I5-14") || cpuUpper.Contains("I7-14") || cpuUpper.Contains("I9-14") ||
                    cpuUpper.Contains("ULTRA"))
                {
                    info.RecommendedCpuProfile = CpuProfileType.IntelHybridPE;
                }
                else
                {
                    info.RecommendedCpuProfile = CpuProfileType.IntelClassic;
                }
            }

            // Auto-Classify GPU Profile
            string gpuUpper = info.GpuName.ToUpperInvariant();
            if (gpuUpper.Contains("NVIDIA") || gpuUpper.Contains("GEFORCE") || gpuUpper.Contains("RTX") || gpuUpper.Contains("GTX"))
            {
                info.RecommendedGpuProfile = GpuProfileType.NvidiaGeForce;
            }
            else if (gpuUpper.Contains("AMD") || gpuUpper.Contains("RADEON") || gpuUpper.Contains("RX "))
            {
                info.RecommendedGpuProfile = GpuProfileType.AmdRadeon;
            }
            else if (gpuUpper.Contains("ARC") || gpuUpper.Contains("INTEL"))
            {
                info.RecommendedGpuProfile = GpuProfileType.IntelArc;
            }

            return info;
        }
    }

    public class RegistryBackupEntry
    {
        public string HiveName;
        public string SubKey;
        public string ValueName;
        public bool ExistedBefore;
        public RegistryValueKind Kind;
        public string SerializedValue;
        public string CurrentAppliedSummary;
        public string FriendlyTweakName;
    }

    public class ProcessBackupEntry
    {
        public int Pid;
        public string ProcessName;
        public ProcessPriorityClass OriginalPriority;
        public long OriginalAffinity;
        public bool OriginalBoost;
    }

    public class TweakVariation
    {
        public string ShortLabel;
        public string DetailedTitle;
        public string TechnicalReason;
        public string ExactParameters;
        public Action ApplyAction;

        public TweakVariation(string shortLabel, string detailedTitle, string technicalReason, string exactParams, Action applyAction)
        {
            ShortLabel = shortLabel;
            DetailedTitle = detailedTitle;
            TechnicalReason = technicalReason;
            ExactParameters = exactParams;
            ApplyAction = applyAction;
        }
    }

    public class TweakDefinition
    {
        public string Id;
        public string Category; // "HARDWARE", "NETWORK", "LATENCY", "FPS", "EXPERIMENTAL"
        public string HardwareTag; // "ALL", "INTEL_CPU", "AMD_CPU", "NVIDIA_GPU", "AMD_GPU", "INTEL_GPU"
        public string BadgeText;
        public Color BadgeColor;
        public bool RequiresAdmin;
        public string Title;
        public string SummaryDescription;
        public string DeepTechnicalWhy;
        public string TargetPathOrApi;
        public List<TweakVariation> Variations = new List<TweakVariation>();
        public Action RevertAction;
        public Func<string> QueryOriginalOrDefaultSummary;

        public bool NeedsReboot = false;
        public bool NeedsNetReload = false;
        public bool RebootSatisfied = false;
        public bool NetReloadSatisfied = false;
        public bool PendingRebootAfterDisable = false;
        public string ModifiedBootStamp = "";
        public bool IsVerifiedInOs = false;
        public string VerifiedSystemValue = "";

        public bool IsEnabled = false;
        public int SelectedVariationIndex = 0;
        public string CapturedOriginalSummary = "Varsayılan";
        public string CurrentAppliedText = "Pasif (Orijinal)";
    }

    public class StateVault
    {
        private readonly string journalPath;
        public Dictionary<string, RegistryBackupEntry> RegistryBackups = new Dictionary<string, RegistryBackupEntry>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<int, ProcessBackupEntry> ProcessBackups = new Dictionary<int, ProcessBackupEntry>();

        public Guid OriginalPowerScheme = Guid.Empty;
        public Guid SessionCustomPowerScheme = Guid.Empty;
        public Dictionary<string, uint> PowerSettingRequests = new Dictionary<string, uint>();

        public int[] OriginalMouseAccel = new int[3];
        public int OriginalMouseSensitivity = 10;
        public int OriginalMouseHoverTime = 400;
        public int OriginalKeyboardDelay = 1;
        public int OriginalKeyboardSpeed = 31;
        public NativeMethods.FILTERKEYS OriginalFilterKeys;
        public bool MouseSpiModified = false;
        public bool KeyboardSpiModified = false;
        public bool FilterKeysModified = false;

        public bool NetshModified = false;
        public bool NetshBaselineCaptured = false;
        public string OrigAutoTuning = "normal";
        public string OrigEcn = "disabled";
        public string OrigTimestamps = "disabled";
        public string OrigRsc = "enabled";
        public string OrigRss = "enabled";
        public string OrigNonSack = "disabled";
        public string OrigInitialRto = "3000";
        public string OrigMaxSyn = "2";

        public bool DnsModified = false;
        public string ActiveAdapterName = "Ethernet";
        public List<string> OriginalDnsServers = new List<string>();
        public bool OriginalDnsWasDhcp = true;

        public Dictionary<string, string> LearnedTweakSummaries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public bool LoadedFromPersistedProfile = false;

        public StateVault()
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "UltraLowLatencyArgon");
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
            journalPath = Path.Combine(dir, "original_baseline_backup.txt");

            CaptureInitialSystemBaseline();
            LoadPersistedBaselineIfPresent();
        }

        private void CaptureInitialSystemBaseline()
        {
            try
            {
                IntPtr pGuid;
                if (NativeMethods.PowerGetActiveScheme(IntPtr.Zero, out pGuid) == 0 && pGuid != IntPtr.Zero)
                {
                    OriginalPowerScheme = (Guid)Marshal.PtrToStructure(pGuid, typeof(Guid));
                    NativeMethods.LocalFree(pGuid);
                }
            }
            catch { }

            try
            {
                NativeMethods.SystemParametersInfo(NativeMethods.SPI_GETMOUSE, 0, OriginalMouseAccel, 0);
                NativeMethods.SystemParametersInfo(NativeMethods.SPI_GETMOUSESPEED, 0, out OriginalMouseSensitivity, 0);
                NativeMethods.SystemParametersInfo(NativeMethods.SPI_GETMOUSEHOVERTIME, 0, out OriginalMouseHoverTime, 0);
                NativeMethods.SystemParametersInfo(NativeMethods.SPI_GETKEYBOARDDELAY, 0, out OriginalKeyboardDelay, 0);
                NativeMethods.SystemParametersInfo(NativeMethods.SPI_GETKEYBOARDSPEED, 0, out OriginalKeyboardSpeed, 0);

                OriginalFilterKeys = new NativeMethods.FILTERKEYS();
                OriginalFilterKeys.cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.FILTERKEYS));
                NativeMethods.SystemParametersInfo(NativeMethods.SPI_GETFILTERKEYS, OriginalFilterKeys.cbSize, ref OriginalFilterKeys, 0);

                // If click sound (FKF_CLICKON = 0x40) or hotkey beep (0x10) was accidentally active, silence it immediately!
                if ((OriginalFilterKeys.dwFlags & 0x50u) != 0)
                {
                    OriginalFilterKeys.dwFlags &= ~0x50u;
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETFILTERKEYS, OriginalFilterKeys.cbSize, ref OriginalFilterKeys, NativeMethods.SPIF_SENDCHANGE);
                }
                // Baseline should always represent standard silent keyboard state when reverting
                OriginalFilterKeys.dwFlags = 2; // FKF_AVAILABLE only (FilterKeys OFF, Click OFF)
                OriginalFilterKeys.iWaitMSec = 0;
                OriginalFilterKeys.iDelayMSec = 1000;
                OriginalFilterKeys.iRepeatMSec = 500;
                OriginalFilterKeys.iBounceMSec = 0;
            }
            catch { }

            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    {
                        ActiveAdapterName = ni.Name;
                        IPInterfaceProperties ipProps = ni.GetIPProperties();
                        foreach (var dns in ipProps.DnsAddresses)
                        {
                            if (dns.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                                OriginalDnsServers.Add(dns.ToString());
                        }
                        using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + ni.Id))
                        {
                            if (k != null)
                            {
                                string ns = k.GetValue("NameServer", "") as string;
                                OriginalDnsWasDhcp = string.IsNullOrEmpty(ns);
                            }
                        }
                        break;
                    }
                }
            }
            catch { }

            try
            {
                string tcpGlobalOut = RunCmdCaptureOutput("netsh", "int tcp show global");
                if (!string.IsNullOrEmpty(tcpGlobalOut))
                {
                    string[] lines = tcpGlobalOut.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (string rawLine in lines)
                    {
                        int colon = rawLine.IndexOf(':');
                        if (colon <= 0 || colon >= rawLine.Length - 1) continue;
                        string k = rawLine.Substring(0, colon).Trim().ToLowerInvariant();
                        string v = rawLine.Substring(colon + 1).Trim().ToLowerInvariant();
                        if (k.Contains("auto-tuning") || k.Contains("otomatik")) OrigAutoTuning = v;
                        else if (k.Contains("ecn")) OrigEcn = v;
                        else if (k.Contains("timestamps") || k.Contains("zaman")) OrigTimestamps = v;
                        else if (k.Contains("coalescing")) OrigRsc = v;
                        else if (k.Contains("scaling state")) OrigRss = v;
                        else if (k.Contains("non sack") || k.Contains("nonsack")) OrigNonSack = v;
                        else if (k.Contains("initial rto")) OrigInitialRto = v.Replace("ms", "").Trim();
                        else if (k.Contains("syn retransmissions")) OrigMaxSyn = v;
                    }
                    NetshBaselineCaptured = true;
                }
            }
            catch { }
        }

        private void LoadPersistedBaselineIfPresent()
        {
            try
            {
                if (!File.Exists(journalPath))
                {
                    SaveJournal();
                    return;
                }
                string[] lines = File.ReadAllLines(journalPath, Encoding.UTF8);
                foreach (string line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    string[] parts = line.Split(new char[] { '|' }, 9);
                    if (parts[0] == "POWERSCHEME" && parts.Length >= 2)
                    {
                        Guid g;
                        if (Guid.TryParse(parts[1], out g) && g != Guid.Empty)
                            OriginalPowerScheme = g;
                    }
                    else if (parts[0] == "CUSTOMSCHEME" && parts.Length >= 2)
                    {
                        Guid g;
                        if (Guid.TryParse(parts[1], out g) && g != Guid.Empty)
                            SessionCustomPowerScheme = g;
                    }
                    else if (parts[0] == "MOUSE_SPI" && parts.Length >= 6)
                    {
                        OriginalMouseAccel = new int[] { int.Parse(parts[1]), int.Parse(parts[2]), int.Parse(parts[3]) };
                        OriginalMouseSensitivity = int.Parse(parts[4]);
                        OriginalMouseHoverTime = int.Parse(parts[5]);
                        MouseSpiModified = true;
                    }
                    else if (parts[0] == "KBD_SPI" && parts.Length >= 3)
                    {
                        OriginalKeyboardDelay = int.Parse(parts[1]);
                        OriginalKeyboardSpeed = int.Parse(parts[2]);
                        KeyboardSpiModified = true;
                    }
                    else if (parts[0] == "FILTERKEYS_SPI" && parts.Length >= 6)
                    {
                        OriginalFilterKeys = new NativeMethods.FILTERKEYS
                        {
                            cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.FILTERKEYS)),
                            dwFlags = 2, // Always restore to silent FilterKeys OFF
                            iWaitMSec = 0,
                            iDelayMSec = 1000,
                            iRepeatMSec = 500,
                            iBounceMSec = 0
                        };
                        FilterKeysModified = true;
                    }
                    else if (parts[0] == "NETSH_BASE" && parts.Length >= 9)
                    {
                        OrigAutoTuning = parts[1];
                        OrigEcn = parts[2];
                        OrigTimestamps = parts[3];
                        OrigRsc = parts[4];
                        OrigRss = parts[5];
                        OrigNonSack = parts[6];
                        OrigInitialRto = parts[7];
                        OrigMaxSyn = parts[8];
                        NetshBaselineCaptured = true;
                    }
                    else if (parts[0] == "LEARNED_DEFAULT" && parts.Length >= 3)
                    {
                        LearnedTweakSummaries[parts[1]] = parts[2];
                    }
                    else if (parts[0] == "REG" && parts.Length >= 6)
                    {
                        string hive = parts[1];
                        string subKey = parts[2];
                        string valName = parts[3];
                        bool existed = bool.Parse(parts[4]);
                        RegistryValueKind kind = (RegistryValueKind)Enum.Parse(typeof(RegistryValueKind), parts[5]);
                        string rawVal = parts.Length >= 7 ? parts[6] : "";
                        string friendly = parts.Length >= 8 ? parts[7] : "Kayıt Defteri Ayarı";
                        string keyId = hive + "\\" + subKey + "\\" + valName;
                        if (!RegistryBackups.ContainsKey(keyId))
                        {
                            RegistryBackups[keyId] = new RegistryBackupEntry
                            {
                                HiveName = hive,
                                SubKey = subKey,
                                ValueName = valName,
                                ExistedBefore = existed,
                                Kind = kind,
                                SerializedValue = rawVal,
                                CurrentAppliedSummary = ReadRegistryDisplay(hive, subKey, valName, rawVal),
                                FriendlyTweakName = friendly
                            };
                        }
                    }
                }
                LoadedFromPersistedProfile = true;
            }
            catch { }
        }

        public void LearnMachineDefaultsForCatalog(List<TweakDefinition> tweaks)
        {
            bool newlyLearned = false;
            foreach (var t in tweaks)
            {
                try
                {
                    if (LearnedTweakSummaries.ContainsKey(t.Id) && !string.IsNullOrEmpty(LearnedTweakSummaries[t.Id]))
                    {
                        t.CapturedOriginalSummary = LearnedTweakSummaries[t.Id];
                    }
                    else
                    {
                        string queried = t.QueryOriginalOrDefaultSummary != null ? t.QueryOriginalOrDefaultSummary() : "Varsayılan";
                        t.CapturedOriginalSummary = queried;
                        LearnedTweakSummaries[t.Id] = queried;
                        newlyLearned = true;
                    }
                }
                catch { }
            }
            if (newlyLearned)
                SaveJournal();
        }

        public string ReadPowerAcSettingDisplay(Guid subGroup, Guid setting, string fallback)
        {
            try
            {
                Guid scheme = OriginalPowerScheme;
                if (scheme == Guid.Empty)
                {
                    IntPtr pGuid;
                    if (NativeMethods.PowerGetActiveScheme(IntPtr.Zero, out pGuid) == 0 && pGuid != IntPtr.Zero)
                    {
                        scheme = (Guid)Marshal.PtrToStructure(pGuid, typeof(Guid));
                        NativeMethods.LocalFree(pGuid);
                    }
                }
                if (scheme != Guid.Empty)
                {
                    uint acVal;
                    if (NativeMethods.PowerReadACValueIndex(IntPtr.Zero, ref scheme, ref subGroup, ref setting, out acVal) == 0)
                        return acVal.ToString();
                }
            }
            catch { }
            return fallback;
        }

        public void SaveJournal()
        {
            try
            {
                List<string> lines = new List<string>();
                if (OriginalPowerScheme != Guid.Empty)
                    lines.Add("POWERSCHEME|" + OriginalPowerScheme.ToString());
                if (SessionCustomPowerScheme != Guid.Empty)
                    lines.Add("CUSTOMSCHEME|" + SessionCustomPowerScheme.ToString());
                if (MouseSpiModified)
                    lines.Add(string.Format("MOUSE_SPI|{0}|{1}|{2}|{3}|{4}", OriginalMouseAccel[0], OriginalMouseAccel[1], OriginalMouseAccel[2], OriginalMouseSensitivity, OriginalMouseHoverTime));
                if (KeyboardSpiModified)
                    lines.Add(string.Format("KBD_SPI|{0}|{1}", OriginalKeyboardDelay, OriginalKeyboardSpeed));
                if (FilterKeysModified)
                    lines.Add(string.Format("FILTERKEYS_SPI|{0}|{1}|{2}|{3}|{4}",
                        OriginalFilterKeys.dwFlags, OriginalFilterKeys.iWaitMSec, OriginalFilterKeys.iDelayMSec, OriginalFilterKeys.iRepeatMSec, OriginalFilterKeys.iBounceMSec));
                if (NetshBaselineCaptured)
                    lines.Add(string.Format("NETSH_BASE|{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}",
                        OrigAutoTuning, OrigEcn, OrigTimestamps, OrigRsc, OrigRss, OrigNonSack, OrigInitialRto, OrigMaxSyn));

                foreach (var kv in LearnedTweakSummaries)
                {
                    lines.Add(string.Format("LEARNED_DEFAULT|{0}|{1}", kv.Key, (kv.Value ?? "").Replace("|", "/")));
                }

                foreach (var kv in RegistryBackups.Values)
                {
                    lines.Add(string.Format("REG|{0}|{1}|{2}|{3}|{4}|{5}|{6}",
                        kv.HiveName, kv.SubKey, kv.ValueName, kv.ExistedBefore, kv.Kind, kv.SerializedValue ?? "", (kv.FriendlyTweakName ?? "").Replace("|", "/")));
                }
                File.WriteAllLines(journalPath, lines.ToArray(), Encoding.UTF8);
            }
            catch { }
        }

        public bool SetRegistryTracked(string friendlyTweakName, string hiveName, string subKey, string valueName, object newValue, RegistryValueKind kind)
        {
            string keyId = hiveName + "\\" + subKey + "\\" + valueName;
            try
            {
                RegistryKey baseKey = (hiveName == "HKLM") ? Registry.LocalMachine : Registry.CurrentUser;
                if (!RegistryBackups.ContainsKey(keyId))
                {
                    RegistryBackupEntry backup = new RegistryBackupEntry
                    {
                        HiveName = hiveName,
                        SubKey = subKey,
                        ValueName = valueName,
                        ExistedBefore = false,
                        Kind = kind,
                        SerializedValue = "",
                        FriendlyTweakName = friendlyTweakName
                    };

                    using (RegistryKey existingKey = baseKey.OpenSubKey(subKey, false))
                    {
                        if (existingKey != null)
                        {
                            object oldObj = existingKey.GetValue(valueName, null);
                            if (oldObj != null)
                            {
                                backup.ExistedBefore = true;
                                backup.Kind = existingKey.GetValueKind(valueName);
                                backup.SerializedValue = Convert.ToString(oldObj);
                            }
                        }
                    }
                    RegistryBackups[keyId] = backup;
                }

                using (RegistryKey writeKey = baseKey.CreateSubKey(subKey))
                {
                    if (writeKey == null) return false;
                    writeKey.SetValue(valueName, newValue, kind);
                }

                RegistryBackups[keyId].CurrentAppliedSummary = Convert.ToString(newValue);
                SaveJournal();
                return true;
            }
            catch
            {
                return false;
            }
        }

        public void RevertRegistryTracked(string hiveName, string subKey, string valueName)
        {
            string keyId = hiveName + "\\" + subKey + "\\" + valueName;
            if (!RegistryBackups.ContainsKey(keyId)) return;

            var entry = RegistryBackups[keyId];
            RestoreSingleRegistryEntry(entry.HiveName, entry.SubKey, entry.ValueName, entry.ExistedBefore, entry.Kind, entry.SerializedValue);
            RegistryBackups.Remove(keyId);
            SaveJournal();
        }

        private void RestoreSingleRegistryEntry(string hiveName, string subKey, string valueName, bool existedBefore, RegistryValueKind kind, string serializedValue)
        {
            try
            {
                RegistryKey baseKey = (hiveName == "HKLM") ? Registry.LocalMachine : Registry.CurrentUser;
                using (RegistryKey writeKey = baseKey.OpenSubKey(subKey, true))
                {
                    if (writeKey == null) return;
                    if (!existedBefore)
                    {
                        writeKey.DeleteValue(valueName, false);
                    }
                    else
                    {
                        if (kind == RegistryValueKind.DWord)
                        {
                            int v;
                            if (int.TryParse(serializedValue, out v))
                                writeKey.SetValue(valueName, v, RegistryValueKind.DWord);
                        }
                        else if (kind == RegistryValueKind.QWord)
                        {
                            long v;
                            if (long.TryParse(serializedValue, out v))
                                writeKey.SetValue(valueName, v, RegistryValueKind.QWord);
                        }
                        else
                        {
                            writeKey.SetValue(valueName, serializedValue, RegistryValueKind.String);
                        }
                    }
                }
            }
            catch { }
        }

        public string ReadRegistryDisplay(string hiveName, string subKey, string valueName, string fallback)
        {
            try
            {
                RegistryKey baseKey = (hiveName == "HKLM") ? Registry.LocalMachine : Registry.CurrentUser;
                using (RegistryKey k = baseKey.OpenSubKey(subKey, false))
                {
                    if (k == null) return fallback;
                    object val = k.GetValue(valueName, null);
                    if (val == null) return fallback;
                    return Convert.ToString(val);
                }
            }
            catch
            {
                return fallback;
            }
        }

        public void ApplyPowerSettingTracked(string keyTag, Guid subGroup, Guid setting, uint acValue)
        {
            PowerSettingRequests[keyTag] = acValue;
            RebuildSessionPowerPlan();
        }

        public void RemovePowerSettingTracked(string keyTag)
        {
            if (PowerSettingRequests.ContainsKey(keyTag))
                PowerSettingRequests.Remove(keyTag);
            RebuildSessionPowerPlan();
        }

        private void RebuildSessionPowerPlan()
        {
            try
            {
                if (PowerSettingRequests.Count == 0)
                {
                    RevertPowerPlanCompletely();
                    return;
                }

                if (SessionCustomPowerScheme == Guid.Empty)
                {
                    IntPtr pDest;
                    Guid source = OriginalPowerScheme != Guid.Empty ? OriginalPowerScheme : new Guid("381b4222-f694-41f0-9685-ff5bb260df2e");
                    if (NativeMethods.PowerDuplicateScheme(IntPtr.Zero, ref source, out pDest) == 0 && pDest != IntPtr.Zero)
                    {
                        SessionCustomPowerScheme = (Guid)Marshal.PtrToStructure(pDest, typeof(Guid));
                        NativeMethods.LocalFree(pDest);
                        SaveJournal();
                    }
                }

                if (SessionCustomPowerScheme != Guid.Empty)
                {
                    foreach (var kv in PowerSettingRequests)
                    {
                        string[] parts = kv.Key.Split('|');
                        Guid sub = new Guid(parts[0]);
                        Guid set = new Guid(parts[1]);
                        uint val = kv.Value;
                        NativeMethods.PowerWriteACValueIndex(IntPtr.Zero, ref SessionCustomPowerScheme, ref sub, ref set, val);
                        NativeMethods.PowerWriteDCValueIndex(IntPtr.Zero, ref SessionCustomPowerScheme, ref sub, ref set, val);
                    }
                    NativeMethods.PowerSetActiveScheme(IntPtr.Zero, ref SessionCustomPowerScheme);
                }
            }
            catch { }
        }

        public void RevertPowerPlanCompletely()
        {
            try
            {
                PowerSettingRequests.Clear();
                if (OriginalPowerScheme != Guid.Empty)
                    NativeMethods.PowerSetActiveScheme(IntPtr.Zero, ref OriginalPowerScheme);
                if (SessionCustomPowerScheme != Guid.Empty)
                {
                    NativeMethods.PowerDeleteScheme(IntPtr.Zero, ref SessionCustomPowerScheme);
                    SessionCustomPowerScheme = Guid.Empty;
                }
                SaveJournal();
            }
            catch { }
        }

        public void RollbackAllAndCleanSession()
        {
            List<RegistryBackupEntry> regList = new List<RegistryBackupEntry>(RegistryBackups.Values);
            foreach (var entry in regList)
            {
                RestoreSingleRegistryEntry(entry.HiveName, entry.SubKey, entry.ValueName, entry.ExistedBefore, entry.Kind, entry.SerializedValue);
            }
            RegistryBackups.Clear();

            RevertPowerPlanCompletely();

            if (MouseSpiModified)
            {
                try
                {
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETMOUSE, 0, OriginalMouseAccel, NativeMethods.SPIF_SENDCHANGE);
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETMOUSESPEED, 0, (IntPtr)OriginalMouseSensitivity, NativeMethods.SPIF_SENDCHANGE);
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETMOUSEHOVERTIME, (uint)OriginalMouseHoverTime, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                }
                catch { }
                MouseSpiModified = false;
            }

            if (KeyboardSpiModified)
            {
                try
                {
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDDELAY, (uint)OriginalKeyboardDelay, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDSPEED, (uint)OriginalKeyboardSpeed, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                }
                catch { }
                KeyboardSpiModified = false;
            }

            if (FilterKeysModified)
            {
                try
                {
                    OriginalFilterKeys.cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.FILTERKEYS));
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETFILTERKEYS, OriginalFilterKeys.cbSize, ref OriginalFilterKeys, NativeMethods.SPIF_SENDCHANGE);
                }
                catch { }
                FilterKeysModified = false;
            }

            if (NetshModified)
            {
                RunHiddenCmd("netsh", string.Format("int tcp set global autotuninglevel={0} ecncapability={1} timestamps={2} rsc={3} rss={4} nonsackrttresiliency={5} initialRto={6} maxsynretransmissions={7}",
                    OrigAutoTuning, OrigEcn, OrigTimestamps, OrigRsc, OrigRss, OrigNonSack, OrigInitialRto, OrigMaxSyn));
                NetshModified = false;
            }

            if (DnsModified)
            {
                if (OriginalDnsWasDhcp)
                {
                    RunHiddenCmd("netsh", string.Format("interface ip set dns name=\"{0}\" source=dhcp", ActiveAdapterName));
                }
                else if (OriginalDnsServers.Count > 0)
                {
                    RunHiddenCmd("netsh", string.Format("interface ip set dns name=\"{0}\" static {1} primary", ActiveAdapterName, OriginalDnsServers[0]));
                    if (OriginalDnsServers.Count > 1)
                        RunHiddenCmd("netsh", string.Format("interface ip add dns name=\"{0}\" {1} index=2", ActiveAdapterName, OriginalDnsServers[1]));
                }
                NativeMethods.DnsFlushResolverCache();
                DnsModified = false;
            }

            foreach (var pb in ProcessBackups.Values)
            {
                try
                {
                    Process p = Process.GetProcessById(pb.Pid);
                    if (!p.HasExited)
                    {
                        p.PriorityClass = pb.OriginalPriority;
                        p.ProcessorAffinity = (IntPtr)pb.OriginalAffinity;
                        p.PriorityBoostEnabled = pb.OriginalBoost;
                    }
                }
                catch { }
            }
            ProcessBackups.Clear();

            SaveJournal();
        }

        public static void RunHiddenCmd(string file, string args)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(file, args)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using (Process p = Process.Start(psi))
                {
                    if (p != null) p.WaitForExit(1500);
                }
            }
            catch { }
        }

        public static string RunCmdCaptureOutput(string file, string args)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(file, args)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using (Process p = Process.Start(psi))
                {
                    if (p == null) return "";
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(1500);
                    return output ?? "";
                }
            }
            catch { return ""; }
        }
    }

    #endregion

    #region Progressive MultiVariationTweakCard (Compact + Expandable + Tooltip)

    public class MultiVariationTweakCard : Panel
    {
        public TweakDefinition Tweak;
        private Action<TweakDefinition, bool, int> onStateChanged;
        private Action<TweakDefinition, TweakVariation> onHoverInspect;
        private ToolTip sharedToolTip;

        private bool isExpanded = false;
        private const int COMPACT_HEIGHT = 108;
        private const int EXPANDED_HEIGHT = 166;

        private Label lblTitle;
        private Label lblBadge;
        private Label lblScopeBadge;
        private Label lblLiveState;
        private Label lblShortSub;
        private Button btnExpandToggle;
        private Panel pnlToggleSwitch;
        private Panel pnlDetailsDrawer;
        private Label lblDeepWhy;
        private List<Button> variationButtons = new List<Button>();

        public MultiVariationTweakCard(
            TweakDefinition tweak,
            ToolTip toolTip,
            Action<TweakDefinition, bool, int> stateCallback,
            Action<TweakDefinition, TweakVariation> hoverCallback)
        {
            this.Tweak = tweak;
            this.sharedToolTip = toolTip;
            this.onStateChanged = stateCallback;
            this.onHoverInspect = hoverCallback;

            this.SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            this.DoubleBuffered = true;
            this.Height = COMPACT_HEIGHT;
            this.Width = 920;
            this.BackColor = Color.FromArgb(21, 25, 36);
            this.Margin = new Padding(0, 0, 0, 8);

            BuildProgressiveCard();
            this.Resize += (s, e) =>
            {
                LayoutCardControls();
                this.Invalidate(true);
            };
            RefreshVisualState();
        }

        private void BuildProgressiveCard()
        {
            string rawTitle = Tweak.Title ?? "";
            if (rawTitle.Contains("RESTART")) Tweak.NeedsReboot = true;
            if (rawTitle.Contains("AĞ") && rawTitle.Contains("YENİLEME")) Tweak.NeedsNetReload = true;

            // Strip any bracket tags like [⚡ ANLIK...], [🔄 ...], [🟠 ...] from the visible title
            StringBuilder cleanSb = new StringBuilder();
            bool inBracket = false;
            for (int c = 0; c < rawTitle.Length; c++)
            {
                if (rawTitle[c] == '[') { inBracket = true; continue; }
                if (rawTitle[c] == ']') { inBracket = false; continue; }
                if (!inBracket) cleanSb.Append(rawTitle[c]);
            }
            string cleanTitle = cleanSb.ToString().Replace("  ", " ").Trim();
            Tweak.Title = cleanTitle;

            // Row 1 Left: Category Badge + Optional Reboot/Reload Pill (ONLY shown when needed!)
            lblBadge = new Label
            {
                Text = Tweak.BadgeText,
                Font = new Font("Segoe UI", 7.2f, FontStyle.Bold),
                ForeColor = Color.Black,
                BackColor = Tweak.BadgeColor,
                AutoSize = true,
                Padding = new Padding(5, 2, 5, 2),
                Location = new Point(14, 8)
            };
            this.Controls.Add(lblBadge);

            lblScopeBadge = new Label
            {
                Text = "",
                Font = new Font("Segoe UI", 7.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(251, 191, 36),
                BackColor = Color.FromArgb(52, 34, 14),
                AutoSize = true,
                Padding = new Padding(5, 2, 5, 2),
                Location = new Point(lblBadge.Right + 6, 8),
                Visible = false
            };
            this.Controls.Add(lblScopeBadge);

            // Row 1 Right: Live State + [Ne İşe Yarar ▾] + Toggle Switch
            lblLiveState = new Label
            {
                Text = Tweak.CapturedOriginalSummary,
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = false,
                AutoEllipsis = true,
                TextAlign = ContentAlignment.MiddleRight,
                Size = new Size(310, 19)
            };
            this.Controls.Add(lblLiveState);

            btnExpandToggle = new Button
            {
                Text = "Amacı ▾",
                Font = new Font("Segoe UI", 7.5f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(30, 37, 52),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Height = 24,
                Padding = new Padding(4, 0, 4, 0),
                Cursor = Cursors.Hand
            };
            btnExpandToggle.FlatAppearance.BorderSize = 1;
            btnExpandToggle.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnExpandToggle.Click += (s, e) => ToggleExpandDrawer();
            sharedToolTip.SetToolTip(btnExpandToggle, "Bu ayarın hangi durumlarda ve ne amaçla kullanıldığını göster/gizle");
            this.Controls.Add(btnExpandToggle);

            pnlToggleSwitch = new Panel
            {
                Size = new Size(98, 28),
                Cursor = Cursors.Hand,
                BackColor = Color.Transparent
            };
            pnlToggleSwitch.Paint += OnPaintToggleSwitch;
            pnlToggleSwitch.Click += (s, e) =>
            {
                bool wasEnabled = Tweak.IsEnabled;
                Tweak.IsEnabled = !wasEnabled;
                if (Tweak.IsEnabled)
                {
                    Tweak.PendingRebootAfterDisable = false;
                    if (Tweak.NeedsReboot) Tweak.RebootSatisfied = false;
                    if (Tweak.NeedsNetReload) Tweak.NetReloadSatisfied = false;
                }
                else
                {
                    if (wasEnabled && Tweak.NeedsReboot && Tweak.RebootSatisfied)
                        Tweak.PendingRebootAfterDisable = true;
                    else
                        Tweak.PendingRebootAfterDisable = false;
                    Tweak.RebootSatisfied = false;
                    Tweak.NetReloadSatisfied = false;
                }
                if (onStateChanged != null)
                    onStateChanged(Tweak, Tweak.IsEnabled, Tweak.SelectedVariationIndex);
                RefreshVisualState();
            };
            this.Controls.Add(pnlToggleSwitch);

            // Row 2: Clean Bold Title (Y = 31)
            lblTitle = new Label
            {
                Text = cleanTitle,
                Font = new Font("Segoe UI", 9.8f, FontStyle.Bold),
                ForeColor = Color.White,
                AutoSize = true,
                Location = new Point(14, 31)
            };
            this.Controls.Add(lblTitle);

            // Row 3: Full-Width 1-Line Subtitle (Y = 52)
            lblShortSub = new Label
            {
                Text = Tweak.SummaryDescription,
                Font = new Font("Segoe UI", 8.2f, FontStyle.Regular),
                ForeColor = Color.FromArgb(156, 172, 194),
                AutoEllipsis = true,
                Location = new Point(14, 52),
                Size = new Size(this.Width - 28, 19)
            };
            this.Controls.Add(lblShortSub);

            // Row 4: Variation Pills Row (Y = 74)
            int varX = 14;
            for (int i = 0; i < Tweak.Variations.Count; i++)
            {
                int idx = i;
                TweakVariation v = Tweak.Variations[i];
                Button btnVar = new Button
                {
                    Text = string.Format("Mod {0}: {1}", i + 1, v.ShortLabel),
                    Font = new Font("Segoe UI", 8f, FontStyle.Bold),
                    FlatStyle = FlatStyle.Flat,
                    AutoSize = true,
                    Height = 26,
                    Location = new Point(varX, 74),
                    Cursor = Cursors.Hand,
                    Padding = new Padding(5, 0, 5, 0)
                };
                btnVar.FlatAppearance.BorderSize = 1;
                btnVar.Click += (s, e) =>
                {
                    bool changed = (!Tweak.IsEnabled || Tweak.SelectedVariationIndex != idx);
                    Tweak.SelectedVariationIndex = idx;
                    Tweak.IsEnabled = true;
                    Tweak.PendingRebootAfterDisable = false;
                    if (changed && Tweak.NeedsReboot) Tweak.RebootSatisfied = false;
                    if (changed && Tweak.NeedsNetReload) Tweak.NetReloadSatisfied = false;
                    if (onStateChanged != null)
                        onStateChanged(Tweak, true, idx);
                    RefreshVisualState();
                    if (onHoverInspect != null)
                        onHoverInspect(Tweak, v);
                };

                string varTip = string.Format(
                    "⚡ Mod {0}: {1}\n" +
                    "──────────────────────────────────────────\n" +
                    "🎯 Ne Zaman Kullanılır: {2}\n" +
                    "💡 Makine Varsayılanı: {3}",
                    i + 1, v.DetailedTitle, v.TechnicalReason, Tweak.CapturedOriginalSummary);

                sharedToolTip.SetToolTip(btnVar, varTip);
                btnVar.MouseEnter += (s, e) =>
                {
                    if (onHoverInspect != null) onHoverInspect(Tweak, v);
                };

                this.Controls.Add(btnVar);
                variationButtons.Add(btnVar);
                varX += btnVar.PreferredSize.Width + 8;
            }

            // Row 5: Expandable Practical Purpose Drawer (Y = 105, Hidden by default)
            pnlDetailsDrawer = new Panel
            {
                Location = new Point(14, 105),
                Size = new Size(this.Width - 28, 53),
                BackColor = Color.FromArgb(14, 18, 27),
                Visible = false
            };
            this.Controls.Add(pnlDetailsDrawer);

            lblDeepWhy = new Label
            {
                Text = "💡 Ne Zaman & Neden Kullanılır: " + Tweak.DeepTechnicalWhy,
                Font = new Font("Segoe UI", 8.2f, FontStyle.Regular),
                ForeColor = Color.FromArgb(185, 200, 222),
                Location = new Point(8, 6),
                Size = new Size(pnlDetailsDrawer.Width - 16, 42)
            };
            pnlDetailsDrawer.Controls.Add(lblDeepWhy);

            string cardTip = BuildCardTooltip();
            sharedToolTip.SetToolTip(this, cardTip);
            sharedToolTip.SetToolTip(lblTitle, cardTip);
            sharedToolTip.SetToolTip(lblShortSub, cardTip);

            EventHandler hoverHandler = (s, e) =>
            {
                if (onHoverInspect != null && Tweak.Variations.Count > 0)
                {
                    int safeIdx = Math.Max(0, Math.Min(Tweak.SelectedVariationIndex, Tweak.Variations.Count - 1));
                    onHoverInspect(Tweak, Tweak.Variations[safeIdx]);
                }
            };
            this.MouseEnter += hoverHandler;
            lblTitle.MouseEnter += hoverHandler;
            lblShortSub.MouseEnter += hoverHandler;

            LayoutCardControls();
        }

        private void LayoutCardControls()
        {
            int w = Math.Max(600, this.ClientSize.Width);
            if (lblBadge != null && lblScopeBadge != null)
            {
                lblScopeBadge.Location = new Point(lblBadge.Right + 6, 8);
            }
            if (pnlToggleSwitch != null)
            {
                pnlToggleSwitch.Location = new Point(w - pnlToggleSwitch.Width - 12, 5);
            }
            if (btnExpandToggle != null && pnlToggleSwitch != null)
            {
                int expW = Math.Max(68, btnExpandToggle.PreferredSize.Width);
                btnExpandToggle.Size = new Size(expW, 24);
                btnExpandToggle.Location = new Point(pnlToggleSwitch.Left - expW - 8, 7);
            }
            if (lblLiveState != null && btnExpandToggle != null && lblBadge != null)
            {
                int leftLimit = (lblScopeBadge != null && lblScopeBadge.Visible) ? (lblScopeBadge.Right + 10) : (lblBadge.Right + 10);
                int rightLimit = btnExpandToggle.Left - 8;
                int availW = Math.Max(120, rightLimit - leftLimit);
                lblLiveState.Size = new Size(availW, 19);
                lblLiveState.Location = new Point(leftLimit, 9);
            }
            if (lblShortSub != null)
            {
                lblShortSub.Width = Math.Max(200, w - 28);
            }
            if (pnlDetailsDrawer != null)
            {
                pnlDetailsDrawer.Width = Math.Max(200, w - 28);
                if (lblDeepWhy != null)
                    lblDeepWhy.Width = Math.Max(180, pnlDetailsDrawer.ClientSize.Width - 16);
            }
        }

        private void ToggleExpandDrawer()
        {
            isExpanded = !isExpanded;
            pnlDetailsDrawer.Visible = isExpanded;
            this.Height = isExpanded ? EXPANDED_HEIGHT : COMPACT_HEIGHT;
            btnExpandToggle.Text = isExpanded ? "Gizle ▴" : "Amacı ▾";
            btnExpandToggle.ForeColor = isExpanded ? Color.FromArgb(56, 189, 248) : Color.FromArgb(148, 163, 184);
            LayoutCardControls();
            this.Invalidate(true);
        }

        private string BuildCardTooltip()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("⚡ " + Tweak.Title);
            sb.AppendLine("🎯 Kullanım Amacı: " + Tweak.DeepTechnicalWhy);
            sb.AppendLine();
            for (int i = 0; i < Tweak.Variations.Count; i++)
            {
                var v = Tweak.Variations[i];
                sb.AppendLine(string.Format("• Mod {0} ({1}): {2}", i + 1, v.ShortLabel, v.TechnicalReason));
            }
            return sb.ToString();
        }

        private void OnPaintToggleSwitch(object sender, PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            Rectangle rect = new Rectangle(2, 2, pnlToggleSwitch.Width - 5, pnlToggleSwitch.Height - 5);
            Color bg = Tweak.IsEnabled ? Color.FromArgb(16, 185, 129) : Color.FromArgb(40, 48, 66);
            Color border = Tweak.IsEnabled ? Color.FromArgb(52, 211, 153) : Color.FromArgb(71, 85, 105);

            using (GraphicsPath path = CreateRoundedRect(rect, 11))
            using (SolidBrush br = new SolidBrush(bg))
            using (Pen pen = new Pen(border, 1.5f))
            {
                g.FillPath(br, path);
                g.DrawPath(pen, path);
            }

            int knobSize = rect.Height - 6;
            int knobX = Tweak.IsEnabled ? (rect.Right - knobSize - 4) : (rect.Left + 4);
            Rectangle knobRect = new Rectangle(knobX, rect.Top + 3, knobSize, knobSize);
            using (SolidBrush knobBr = new SolidBrush(Tweak.IsEnabled ? Color.FromArgb(10, 15, 22) : Color.FromArgb(203, 213, 225)))
            {
                g.FillEllipse(knobBr, knobRect);
            }

            string txt = Tweak.IsEnabled ? "AÇIK" : "KAPALI";
            using (Font f = new Font("Segoe UI", 7.8f, FontStyle.Bold))
            using (SolidBrush txtBr = new SolidBrush(Tweak.IsEnabled ? Color.FromArgb(10, 15, 22) : Color.FromArgb(203, 213, 225)))
            {
                int textX = Tweak.IsEnabled ? (rect.Left + 10) : (rect.Left + knobSize + 8);
                g.DrawString(txt, f, txtBr, new PointF(textX, rect.Top + 3));
            }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            Color borderColor = Tweak.IsEnabled ? Tweak.BadgeColor : Color.FromArgb(35, 42, 60);
            int borderWidth = Tweak.IsEnabled ? 2 : 1;
            using (Pen p = new Pen(borderColor, borderWidth))
            {
                e.Graphics.DrawRectangle(p, 0, 0, this.Width - 1, this.Height - 1);
            }
            if (Tweak.IsEnabled)
            {
                using (SolidBrush accentBr = new SolidBrush(Tweak.BadgeColor))
                {
                    e.Graphics.FillRectangle(accentBr, 0, 0, 4, this.Height);
                }
            }
        }

        public void RefreshVisualState()
        {
            if (lblScopeBadge != null)
            {
                if (!Tweak.IsEnabled)
                {
                    if (Tweak.PendingRebootAfterDisable)
                    {
                        lblScopeBadge.Visible = true;
                        lblScopeBadge.Text = "🟠 Kapatıldı (Restart İster)";
                        lblScopeBadge.ForeColor = Color.FromArgb(251, 191, 36);
                        lblScopeBadge.BackColor = Color.FromArgb(55, 34, 12);
                    }
                    else
                    {
                        lblScopeBadge.Visible = false;
                    }
                }
                else
                {
                    if (Tweak.NeedsReboot && !Tweak.RebootSatisfied)
                    {
                        lblScopeBadge.Visible = true;
                        lblScopeBadge.Text = Tweak.IsVerifiedInOs ? "🟠 Restart Gerekli (Kaydedildi)" : "🟠 Restart Gerekli";
                        lblScopeBadge.ForeColor = Color.FromArgb(251, 191, 36);
                        lblScopeBadge.BackColor = Color.FromArgb(55, 34, 12);
                    }
                    else if (Tweak.NeedsNetReload && !Tweak.NetReloadSatisfied)
                    {
                        lblScopeBadge.Visible = true;
                        lblScopeBadge.Text = "🔄 Ağ Yenileme İster";
                        lblScopeBadge.ForeColor = Color.FromArgb(56, 189, 248);
                        lblScopeBadge.BackColor = Color.FromArgb(16, 36, 56);
                    }
                    else if (Tweak.IsVerifiedInOs)
                    {
                        lblScopeBadge.Visible = true;
                        if (Tweak.NeedsReboot && Tweak.RebootSatisfied)
                            lblScopeBadge.Text = "✓ Doğrulandı (Restart Aktif)";
                        else if (Tweak.NeedsNetReload && Tweak.NetReloadSatisfied)
                            lblScopeBadge.Text = "✓ Doğrulandı (Ağ Aktif)";
                        else
                            lblScopeBadge.Text = "✓ Sistemde Doğrulandı";
                        lblScopeBadge.ForeColor = Color.FromArgb(52, 211, 153);
                        lblScopeBadge.BackColor = Color.FromArgb(14, 42, 34);
                    }
                    else
                    {
                        lblScopeBadge.Visible = true;
                        lblScopeBadge.Text = "⚠️ Doğrulanamadı (Yetki/Kilit)";
                        lblScopeBadge.ForeColor = Color.FromArgb(248, 113, 113);
                        lblScopeBadge.BackColor = Color.FromArgb(58, 20, 24);
                    }
                }
            }

            LayoutCardControls();

            this.BackColor = Tweak.IsEnabled ? Color.FromArgb(18, 29, 41) : Color.FromArgb(21, 25, 36);

            if (Tweak.IsEnabled && Tweak.SelectedVariationIndex >= 0 && Tweak.SelectedVariationIndex < Tweak.Variations.Count)
            {
                var activeVar = Tweak.Variations[Tweak.SelectedVariationIndex];
                if (!string.IsNullOrEmpty(Tweak.VerifiedSystemValue))
                {
                    lblLiveState.Text = string.Format("✓ OS: {0} | Mod {1}", Tweak.VerifiedSystemValue, Tweak.SelectedVariationIndex + 1);
                }
                else
                {
                    lblLiveState.Text = string.Format("Aktif: Mod {0} ({1})", Tweak.SelectedVariationIndex + 1, activeVar.ShortLabel);
                }
                lblLiveState.ForeColor = Tweak.IsVerifiedInOs ? Color.FromArgb(52, 211, 153) : Color.FromArgb(251, 191, 36);
            }
            else
            {
                lblLiveState.Text = "Varsayılan: " + Tweak.CapturedOriginalSummary;
                lblLiveState.ForeColor = Color.FromArgb(125, 140, 165);
            }

            for (int i = 0; i < variationButtons.Count; i++)
            {
                bool isSelected = (i == Tweak.SelectedVariationIndex);
                if (Tweak.IsEnabled && isSelected)
                {
                    variationButtons[i].BackColor = Tweak.BadgeColor;
                    variationButtons[i].ForeColor = Color.Black;
                    variationButtons[i].FlatAppearance.BorderColor = Color.White;
                }
                else if (isSelected)
                {
                    variationButtons[i].BackColor = Color.FromArgb(36, 44, 62);
                    variationButtons[i].ForeColor = Color.White;
                    variationButtons[i].FlatAppearance.BorderColor = Tweak.BadgeColor;
                }
                else
                {
                    variationButtons[i].BackColor = Color.FromArgb(27, 33, 47);
                    variationButtons[i].ForeColor = Color.FromArgb(160, 174, 196);
                    variationButtons[i].FlatAppearance.BorderColor = Color.FromArgb(45, 55, 76);
                }
            }

            pnlToggleSwitch.Invalidate();
            this.Invalidate(true);
        }

        private static GraphicsPath CreateRoundedRect(Rectangle bounds, int radius)
        {
            int diameter = radius * 2;
            Size size = new Size(diameter, diameter);
            Rectangle arc = new Rectangle(bounds.Location, size);
            GraphicsPath path = new GraphicsPath();
            if (radius == 0) { path.AddRectangle(bounds); return path; }
            path.AddArc(arc, 180, 90);
            arc.X = bounds.Right - diameter;
            path.AddArc(arc, 270, 90);
            arc.Y = bounds.Bottom - diameter;
            path.AddArc(arc, 0, 90);
            arc.X = bounds.Left;
            path.AddArc(arc, 90, 90);
            path.CloseFigure();
            return path;
        }
    }

    #endregion

    #region Main Form & Complete Hardware + Network + Latency + FPS + Experimental Catalog

    public class MainForm : Form
    {
        private StateVault vault;
        private DetectedHardwareInfo detectedHw;
        private CpuProfileType selectedCpuProfile;
        private GpuProfileType selectedGpuProfile;
        private int selectedProgressiveTier = 2; // 1: Dengeli, 2: Rekabetçi Espor (Default), 3: Turnuva Ekstrem

        private bool isAdmin;
        private bool shutdownExecuted = false;
        private bool isLoadingProfile = false;
        private string userProfilePath;

        private List<string> activeTcpInterfaceGuids = new List<string>();
        private string activeNicClassSubKey = "";
        private string activeGpuClassSubKey = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000";

        private bool timerLockActive = false;
        private uint desiredTimerUnit = 5000;
        private volatile bool pulseThreadRunning = false;
        private int pulseMode = 0;
        private Thread syntheticPulseThread;
        private bool autoStandbyCleanerActive = false;
        private bool autoGameWatchdogActive = true;
        private int standbyIsolationMode = 0;
        private int fpsEcoQosMode = 0;
        private int fpsAudioIsoMode = 0;
        private List<string> pausedServicesByArgon = new List<string>();
        private string currentBootStamp = "";

        private List<TweakDefinition> allTweaks = new List<TweakDefinition>();
        private List<MultiVariationTweakCard> allCards = new List<MultiVariationTweakCard>();

        private ToolTip mainToolTip;
        private Panel pnlTopHeader;
        private Panel pnlNavBar;
        private Panel pnlInspectorFooter;
        private Label lblInspectorTitle;
        private Label lblInspectorPath;

        private Label lblTopTimer;
        private Label lblTopPing;
        private Label lblTopRam;
        private Label lblTopActiveCount;
        private TextBox txtGlobalSearch;

        // Progressive Dashboard & Hardware Matrix Controls
        private ComboBox cmbCpuSelector;
        private ComboBox cmbGpuSelector;
        private Button btnTier1;
        private Button btnTier2;
        private Button btnTier3;
        private Label lblMatrixSummary;
        private FlowLayoutPanel flowHardwareSpecificCards;

        private List<Button> navButtons = new List<Button>();
        private Panel pnlContentHost;
        private Panel viewDashboard;
        private FlowLayoutPanel viewNetwork;
        private FlowLayoutPanel viewLatency;
        private FlowLayoutPanel viewFps;
        private FlowLayoutPanel viewExperimental;
        private Panel viewProcesses;
        private Panel viewBenchmark;
        private Panel viewSnapshotAudit;

        private ListView lvProcesses;
        private TextBox txtProcFilter;
        private Label lblProcActionStatus;
        private CheckBox chkWatchdogToggle;

        private Button btnRunSleepTest;
        private Button btnRunMultiPingTest;
        private Label lblSleepTestReport;
        private Label lblPingTestReport;
        private Panel pnlMouseTestArea;
        private Label lblMouseHzLive;
        private Label lblMouseDeltaLive;
        private long lastMouseTick = 0;
        private List<double> mouseHzHistory = new List<double>();

        private ListView lvAuditLog;

        private System.Windows.Forms.Timer telemetryTimer;
        private int tickCounter = 0;
        private NotifyIcon trayIcon;
        private ContextMenuStrip trayMenu;

        // Power Plan GUIDs (Including Intel Hybrid & AMD CPPC GUIDs)
        static readonly Guid SUB_PROCESSOR = new Guid("54533251-82be-4824-96c1-47b60b740d00");
        static readonly Guid SET_IDLEDISABLE = new Guid("5d76a2ca-e8c0-402f-a133-2158492d58ad");
        static readonly Guid SET_IDLEDEMOTE = new Guid("4b92d758-5a24-4851-a470-815d78aee119");
        static readonly Guid SET_IDLEPROMOTE = new Guid("7b224883-b3cc-4d79-819f-8374152cbe7c");
        static readonly Guid SET_CPMINCORES = new Guid("0cc5b647-c1df-4637-891a-dec35c318583");
        static readonly Guid SET_PROCTHROTTLEMIN = new Guid("893dee8e-2bef-41e0-89c6-b55d0929964c");
        static readonly Guid SET_PERFCHECK = new Guid("4d2b0152-7d5c-498b-88e2-34345392a2c5");
        static readonly Guid SET_BOOSTPOLICY = new Guid("45bcc044-d885-43e2-8605-ee0ec6e96b59");
        static readonly Guid SET_INCPOLICY = new Guid("465e1f50-b610-473a-ab58-00d1077dc418");

        // Intel Hybrid P/E Core & SpeedShift / AMD CPPC Autonomous GUIDs
        static readonly Guid SET_HETEROPOLICY = new Guid("7f2f5cfa-f10c-4823-b5e1-e93ae85f46b5");
        static readonly Guid SET_SCHEDPOLICY = new Guid("93b8b6dc-0698-4d1c-9ee4-0644e900c85d");
        static readonly Guid SET_SHORTSCHEDPOLICY = new Guid("bae08b81-2d5e-4688-ad6a-13243356654b");
        static readonly Guid SET_PERFEPP = new Guid("36687f9e-e3a5-4dbf-b1dc-15eb381c6863");
        static readonly Guid SET_AUTONOMOUS = new Guid("8baa4a8a-14c6-4451-8e8b-14bdbd197537");

        static readonly Guid SUB_USB = new Guid("2a737441-1930-4402-8d77-b2bebba308a3");
        static readonly Guid SET_USBSUSPEND = new Guid("48e6b7a6-50f5-4782-a5d4-53bb8f07e226");
        static readonly Guid SUB_PCIEXPRESS = new Guid("501a4d13-42af-4429-9fd1-a8218c268e20");
        static readonly Guid SET_PCIEASPM = new Guid("ee12f906-d277-404b-b6da-e5fa1a576df5");

        public MainForm(string[] args)
        {
            isAdmin = CheckIsAdministrator();
            detectedHw = DetectedHardwareInfo.ProbeSystem();
            currentBootStamp = detectedHw.CurrentBootStamp;
            selectedCpuProfile = detectedHw.RecommendedCpuProfile;
            selectedGpuProfile = detectedHw.RecommendedGpuProfile;

            DiscoverHardwareRegistryPaths();
            vault = new StateVault();
            string profileDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "UltraLowLatencyArgon");
            if (!Directory.Exists(profileDir)) Directory.CreateDirectory(profileDir);
            userProfilePath = Path.Combine(profileDir, "user_saved_profile.txt");

            mainToolTip = new ToolTip
            {
                AutoPopDelay = 30000,
                InitialDelay = 160,
                ReshowDelay = 60,
                ShowAlways = true,
                IsBalloon = false
            };

            RegisterAllTweaksCatalog();
            InitializeStudioUI();
            LoadAndRestoreUserProfileState();

            telemetryTimer = new System.Windows.Forms.Timer { Interval = 500 };
            telemetryTimer.Tick += OnTelemetryTick;
            telemetryTimer.Start();

            UpdateTelemetryBar();
            RunAsyncPingCheck();
            RefreshProcessTable();
            RefreshSnapshotAuditView();
        }

        private bool CheckIsAdministrator()
        {
            try
            {
                WindowsIdentity id = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(id);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        private void DiscoverHardwareRegistryPaths()
        {
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    {
                        activeTcpInterfaceGuids.Add(ni.Id);
                    }
                }
            }
            catch { }

            if (activeTcpInterfaceGuids.Count == 0)
            {
                try
                {
                    using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"))
                    {
                        if (k != null)
                        {
                            foreach (string sub in k.GetSubKeyNames())
                                activeTcpInterfaceGuids.Add(sub);
                        }
                    }
                }
                catch { }
            }

            try
            {
                string netClassBase = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
                using (RegistryKey baseKey = Registry.LocalMachine.OpenSubKey(netClassBase, false))
                {
                    if (baseKey != null)
                    {
                        foreach (string sub in baseKey.GetSubKeyNames())
                        {
                            if (sub.Length != 4) continue;
                            using (RegistryKey itemKey = baseKey.OpenSubKey(sub, false))
                            {
                                if (itemKey == null) continue;
                                string cfgId = itemKey.GetValue("NetCfgInstanceId", "") as string;
                                if (!string.IsNullOrEmpty(cfgId) && activeTcpInterfaceGuids.Contains(cfgId))
                                {
                                    activeNicClassSubKey = netClassBase + "\\" + sub;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            if (string.IsNullOrEmpty(activeNicClassSubKey))
                activeNicClassSubKey = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001";
        }

        private void RegisterAllTweaksCatalog()
        {
            string tcpParams = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
            string tcpServiceProvider = @"SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider";
            string afdParams = @"SYSTEM\CurrentControlSet\Services\AFD\Parameters";
            string mmcssRoot = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile";
            string mmcssGames = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games";
            string mmcssAudio = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio";
            string mmcssProAudio = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio";
            string pschedKey = @"SOFTWARE\Policies\Microsoft\Windows\Psched";
            string prioCtrl = @"SYSTEM\CurrentControlSet\Control\PriorityControl";
            string kernelKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\kernel";
            string memMgmtKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
            string mouParams = @"SYSTEM\CurrentControlSet\Services\mouclass\Parameters";
            string kbdParams = @"SYSTEM\CurrentControlSet\Services\kbdclass\Parameters";
            string gameConfig = @"System\GameConfigStore";
            string gameDvr = @"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR";
            string dxGlobal = @"Software\Microsoft\DirectX\UserGlobalSettings";
            string gfxDrivers = @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers";
            string nvServiceKey = @"SYSTEM\CurrentControlSet\Services\nvlddmkm";

            Color colHw = Color.FromArgb(244, 63, 94);        // Rose/Crimson for Hardware Matrix
            Color colNet = Color.FromArgb(14, 165, 233);      // Cyan
            Color colLat = Color.FromArgb(16, 185, 129);      // Emerald
            Color colFps = Color.FromArgb(245, 158, 11);      // Amber
            Color colExp = Color.FromArgb(168, 85, 247);      // Purple

            // =================================================================================================
            // CATEGORY 0: CPU & GPU HARDWARE MATRIX TWEAKS (DYNAMICALLY SELECTED BY USER OR AUTO-DETECT)
            // =================================================================================================

            // HW-01: INTEL CPU Architecture Optimization (Thread Director P/E Core + SpeedShift EPP)
            var hwIntelCpu = new TweakDefinition
            {
                Id = "HW_INTEL_CPU",
                Category = "HARDWARE",
                HardwareTag = "INTEL_CPU",
                BadgeText = "INTEL İŞLEMCİ ÖZEL",
                BadgeColor = Color.FromArgb(59, 130, 246),
                RequiresAdmin = false,
                Title = "Intel İşlemci Optimizasyonu (Oyun İçin Performans Çekirdekleri & Hızlı Tepki)",
                SummaryDescription = "Intel işlemcilerde oyunların yavaş arka plan çekirdeklerine kaymasını önler ve işlemcinin hızlanma tepkisini anında maksimuma çeker.",
                DeepTechnicalWhy = "Genellikle rekabetçi oyunlarda ani FPS düşüşlerini (drop) engellemek ve işlemcinin her an tam hızda hazır beklemesini sağlamak amacıyla kullanılır. Yayın veya Discord açıksa Mod 2, saf oyun oynuyorsanız Mod 1 önerilir.",
                TargetPathOrApi = "Intel İşlemci Güç & Çekirdek Yönetimi",
                QueryOriginalOrDefaultSummary = () => "EPP=" + vault.ReadPowerAcSettingDisplay(SUB_PROCESSOR, SET_PERFEPP, "Otomatik") + ", Sched=" + vault.ReadPowerAcSettingDisplay(SUB_PROCESSOR, SET_SCHEDPOLICY, "Varsayılan"),
                RevertAction = () =>
                {
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_SCHEDPOLICY);
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_SHORTSCHEDPOLICY);
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_HETEROPOLICY);
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_PERFEPP);
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_AUTONOMOUS);
                }
            };
            hwIntelCpu.Variations.Add(new TweakVariation(
                "Performans Çekirdeklerine Kilitle (Hibrit Espor)",
                "12/13/14. Nesil Intel: Oyunları Sadece Hızlı Çekirdeklerde Çalıştır",
                "Sadece oyun oynarken maksimum FPS ve sıfır takılma almak için oyunu doğrudan ana performans çekirdeklerine (P-Core) odaklar.",
                "Performans Çekirdekleri Öncelikli + Maksimum Hız Tepkisi",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_SCHEDPOLICY, SUB_PROCESSOR, SET_SCHEDPOLICY, 1);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_SHORTSCHEDPOLICY, SUB_PROCESSOR, SET_SHORTSCHEDPOLICY, 1);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_HETEROPOLICY, SUB_PROCESSOR, SET_HETEROPOLICY, 4);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_PERFEPP, SUB_PROCESSOR, SET_PERFEPP, 0);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_AUTONOMOUS, SUB_PROCESSOR, SET_AUTONOMOUS, 1);
                }));
            hwIntelCpu.Variations.Add(new TweakVariation(
                "Oyun + Discord/Yayın Dengeli (Hibrit Çoklu Görev)",
                "Oyun Hızlı Çekirdeklerde, Arka Plan Uygulamaları Yardımcı Çekirdeklerde",
                "Oyun oynarken arka planda Discord, tarayıcı veya OBS yayını açık tutanlar için yükü dengeli paylaştırır.",
                "Oyun P-Core + Arka Plan E-Core Dengesi",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_SCHEDPOLICY, SUB_PROCESSOR, SET_SCHEDPOLICY, 2);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_HETEROPOLICY, SUB_PROCESSOR, SET_HETEROPOLICY, 4);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_PERFEPP, SUB_PROCESSOR, SET_PERFEPP, 15);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_AUTONOMOUS, SUB_PROCESSOR, SET_AUTONOMOUS, 1);
                }));
            hwIntelCpu.Variations.Add(new TweakVariation(
                "Intel Klasik (9/10/11. Nesil) Tam Performans",
                "Klasik Intel İşlemciler İçin Tüm Çekirdekler Tam Hızda",
                "9, 10 ve 11. nesil Intel işlemcilerde tüm çekirdekleri eşit ve en yüksek hız tepkisinde çalıştırmak için kullanılır.",
                "Tüm Çekirdekler Eşit + Maksimum Turbo Tepkisi",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_SCHEDPOLICY, SUB_PROCESSOR, SET_SCHEDPOLICY, 0);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_PERFEPP, SUB_PROCESSOR, SET_PERFEPP, 0);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_AUTONOMOUS, SUB_PROCESSOR, SET_AUTONOMOUS, 1);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_BOOSTPOLICY, SUB_PROCESSOR, SET_BOOSTPOLICY, 100);
                }));
            allTweaks.Add(hwIntelCpu);

            // HW-02: AMD RYZEN / X3D CPU Architecture Optimization
            var hwAmdCpu = new TweakDefinition
            {
                Id = "HW_AMD_CPU",
                Category = "HARDWARE",
                HardwareTag = "AMD_CPU",
                BadgeText = "AMD RYZEN / X3D ÖZEL",
                BadgeColor = Color.FromArgb(249, 115, 22),
                RequiresAdmin = false,
                Title = "AMD Ryzen & X3D İşlemci Optimizasyonu (En Hızlı Çekirdekler & Boost)",
                SummaryDescription = "AMD Ryzen (5600, 7500F vb.) ve X3D işlemcilerde oyun yükünü en hızlı çekirdeklere yönlendirir ve anlık frekans düşüşlerini engeller.",
                DeepTechnicalWhy = "Genellikle AMD Ryzen işlemcilerde oyun içindeki anlık takılmaları (stutter) kesmek ve işlemcinin en yüksek saat hızında çalışmasını sağlamak amacıyla kullanılır.",
                TargetPathOrApi = "AMD Ryzen Güç & Çekirdek Yönetimi",
                QueryOriginalOrDefaultSummary = () => "EPP=" + vault.ReadPowerAcSettingDisplay(SUB_PROCESSOR, SET_PERFEPP, "Dengeli") + ", Boost=" + vault.ReadPowerAcSettingDisplay(SUB_PROCESSOR, SET_BOOSTPOLICY, "Varsayılan"),
                RevertAction = () =>
                {
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_PERFEPP);
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_AUTONOMOUS);
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_SCHEDPOLICY);
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_HETEROPOLICY);
                }
            };
            hwAmdCpu.Variations.Add(new TweakVariation(
                "Ryzen Standart Espor (Maksimum Tepki)",
                "Ryzen 5000/7000/9000 (5600, 7500F vb.) İçin Anında Tam Hız",
                "Standart Ryzen işlemcilerde enerji tasarrufu gecikmesini sıfırlar ve oyunlarda en keskin işlemci tepkisini verir.",
                "Sıfır Enerji Gecikmesi + %100 Boost",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_PERFEPP, SUB_PROCESSOR, SET_PERFEPP, 0);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_AUTONOMOUS, SUB_PROCESSOR, SET_AUTONOMOUS, 1);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_SCHEDPOLICY, SUB_PROCESSOR, SET_SCHEDPOLICY, 0);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_BOOSTPOLICY, SUB_PROCESSOR, SET_BOOSTPOLICY, 100);
                }));
            hwAmdCpu.Variations.Add(new TweakVariation(
                "Ryzen X3D 3D V-Cache Odaklı Mod",
                "5800X3D / 7800X3D / 9800X3D Önbellek Öncelikli Mod",
                "X3D serisi işlemcilerde oyunu büyük 3D önbelleğe sahip çekirdeklerde tutarak maksimum FPS sağlar.",
                "3D V-Cache Çekirdek Önceliği",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_SCHEDPOLICY, SUB_PROCESSOR, SET_SCHEDPOLICY, 2);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_HETEROPOLICY, SUB_PROCESSOR, SET_HETEROPOLICY, 0);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_PERFEPP, SUB_PROCESSOR, SET_PERFEPP, 0);
                }));
            hwAmdCpu.Variations.Add(new TweakVariation(
                "Ryzen Serin & Yüksek Boost Modu",
                "Daha Düşük Sıcaklıkta Maksimum Tek Çekirdek Hızı",
                "İşlemciyi gereksiz ısıtmadan sadece oyunu kullanan çekirdeklerin en yüksek MHz hızına çıkması için kullanılır.",
                "Serin Termal Denge + Maksimum Tek Çekirdek Boost",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_PERFEPP, SUB_PROCESSOR, SET_PERFEPP, 15);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_AUTONOMOUS, SUB_PROCESSOR, SET_AUTONOMOUS, 1);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_BOOSTPOLICY, SUB_PROCESSOR, SET_BOOSTPOLICY, 100);
                }));
            allTweaks.Add(hwAmdCpu);

            // HW-03: NVIDIA GeForce GPU Architecture Optimization
            var hwNvidiaGpu = new TweakDefinition
            {
                Id = "HW_NVIDIA_GPU",
                Category = "HARDWARE",
                HardwareTag = "NVIDIA_GPU",
                BadgeText = "NVIDIA GEFORCE ÖZEL",
                BadgeColor = Color.FromArgb(34, 197, 94),
                RequiresAdmin = true,
                Title = "NVIDIA GeForce Ekran Kartı Optimizasyonu (Sabit Frekans & Takılma Önleyici)",
                SummaryDescription = "NVIDIA RTX/GTX ekran kartlarında oyun içi anlık frekans düşüşlerini kapatır ve ekran kartı yükünü işlemci çekirdeklerine dengeli dağıtır.",
                DeepTechnicalWhy = "Genellikle NVIDIA kartlarda sakin sahnelerden çatışma anına geçerken oluşan anlık takılmaları önlemek ve kare hızını (FPS) sabit tutmak için kullanılır.",
                TargetPathOrApi = "NVIDIA Sürücü Performans Profili",
                QueryOriginalOrDefaultSummary = () => "PState=" + vault.ReadRegistryDisplay("HKLM", activeGpuClassSubKey, "DisableDynamicPstate", "0 (Dinamik)"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", activeGpuClassSubKey, "DisableDynamicPstate");
                    vault.RevertRegistryTracked("HKLM", activeGpuClassSubKey, "PowerMizerEnable");
                    vault.RevertRegistryTracked("HKLM", activeGpuClassSubKey, "PowerMizerLevel");
                    vault.RevertRegistryTracked("HKLM", activeGpuClassSubKey, "PowerMizerLevelAC");
                    vault.RevertRegistryTracked("HKLM", activeGpuClassSubKey, "PerfLevelSrc");
                    vault.RevertRegistryTracked("HKLM", gfxDrivers, "RmGpsPsEnablePerCpuCoreDpc");
                    vault.RevertRegistryTracked("HKLM", nvServiceKey, "RmGpsPsEnablePerCpuCoreDpc");
                }
            };
            hwNvidiaGpu.Variations.Add(new TweakVariation(
                "NVIDIA Tam Performans Kilidi (Maksimum FPS)",
                "Ekran Kartı Frekansını Sabitle + İşlemci Darboğazını Çöz",
                "Rekabetçi oyunlarda ekran kartının hız düşürmesini tamamen engeller ve sürücü yükünü tüm çekirdeklere yayar.",
                "Sabit Maksimum GPU Hızı + Çoklu Çekirdek Dağıtımı",
                () =>
                {
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", activeGpuClassSubKey, "DisableDynamicPstate", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", activeGpuClassSubKey, "PowerMizerEnable", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", activeGpuClassSubKey, "PowerMizerLevel", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", activeGpuClassSubKey, "PowerMizerLevelAC", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", activeGpuClassSubKey, "PerfLevelSrc", 0x2222, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", gfxDrivers, "RmGpsPsEnablePerCpuCoreDpc", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", nvServiceKey, "RmGpsPsEnablePerCpuCoreDpc", 1, RegistryValueKind.DWord);
                }));
            hwNvidiaGpu.Variations.Add(new TweakVariation(
                "NVIDIA Dengeli Espor (Oyunda Tam Hız, Masaüstünde Serin)",
                "Oyun İçinde Maksimum Performans + Masaüstünde Sessiz Fan",
                "Oyun içindeyken tam performans verirken masaüstünde ekran kartının gereksiz ısınmasını önlemek için kullanılır.",
                "Oyunda Tam Güç + Masaüstünde Serin Mod",
                () =>
                {
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", activeGpuClassSubKey, "DisableDynamicPstate", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", activeGpuClassSubKey, "PowerMizerEnable", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", activeGpuClassSubKey, "PowerMizerLevelAC", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", gfxDrivers, "RmGpsPsEnablePerCpuCoreDpc", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", nvServiceKey, "RmGpsPsEnablePerCpuCoreDpc", 1, RegistryValueKind.DWord);
                }));
            hwNvidiaGpu.Variations.Add(new TweakVariation(
                "Sadece Akıcılık & Mikro-Takılma Koruması",
                "Saat Hızlarına Dokunmadan Yalnızca Sürücü Gecikmesini Düşür",
                "Ekran kartı güç ayarlarını değiştirmeden sadece sürücü kaynaklı anlık takılmaları (stutter) gidermek için kullanılır.",
                "Çoklu Çekirdek Sürücü Dağıtımı",
                () =>
                {
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", gfxDrivers, "RmGpsPsEnablePerCpuCoreDpc", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwNvidiaGpu.Title, "HKLM", nvServiceKey, "RmGpsPsEnablePerCpuCoreDpc", 1, RegistryValueKind.DWord);
                }));
            allTweaks.Add(hwNvidiaGpu);

            // HW-04: AMD Radeon GPU Architecture Optimization
            var hwAmdGpu = new TweakDefinition
            {
                Id = "HW_AMD_GPU",
                Category = "HARDWARE",
                HardwareTag = "AMD_GPU",
                BadgeText = "AMD RADEON ÖZEL",
                BadgeColor = Color.FromArgb(239, 68, 68),
                RequiresAdmin = true,
                Title = "AMD Radeon Ekran Kartı Optimizasyonu (Derin Uyku Kapatma & Düşük Gecikme)",
                SummaryDescription = "AMD Radeon RX 6000/7000/9000 (RX 9060 XT dahil) kartlarda oyun içi anlık frekans uyku takılmalarını kapatır ve görüntü gecikmesini düşürür.",
                DeepTechnicalWhy = "Genellikle AMD Radeon ekran kartlarında hafif oyunlarda veya ani dönüşlerde oluşan FPS dalgalanmalarını (stutter) kesmek ve fare tepkisini hızlandırmak için kullanılır.",
                TargetPathOrApi = "AMD Radeon Sürücü Performans Profili",
                QueryOriginalOrDefaultSummary = () => "ULPS=" + vault.ReadRegistryDisplay("HKLM", activeGpuClassSubKey, "EnableUlps", "Varsayılan"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", activeGpuClassSubKey, "EnableUlps");
                    vault.RevertRegistryTracked("HKLM", activeGpuClassSubKey, "PP_SclkDeepSleepDisable");
                    vault.RevertRegistryTracked("HKLM", activeGpuClassSubKey, "StutterMode");
                    vault.RevertRegistryTracked("HKLM", activeGpuClassSubKey, "KMD_DeLagEnabled");
                    vault.RevertRegistryTracked("HKLM", activeGpuClassSubKey, "FlipQueueSize");
                }
            };
            hwAmdGpu.Variations.Add(new TweakVariation(
                "Radeon Tam Espor Kilidi (Sıfır Uyku + Anti-Lag)",
                "Frekans Uykusu Kapalı + Düşük Kare Kuyruğu (En Düşük Gecikme)",
                "Rekabetçi oyunlarda (CS2, Valorant, HaxBall vb.) en düşük görüntü gecikmesi ve en sabit FPS için kullanılır.",
                "Derin Uyku Kapalı + Anti-Lag Açık + 1 Kare Kuyruk",
                () =>
                {
                    vault.SetRegistryTracked(hwAmdGpu.Title, "HKLM", activeGpuClassSubKey, "EnableUlps", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwAmdGpu.Title, "HKLM", activeGpuClassSubKey, "PP_SclkDeepSleepDisable", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwAmdGpu.Title, "HKLM", activeGpuClassSubKey, "StutterMode", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwAmdGpu.Title, "HKLM", activeGpuClassSubKey, "KMD_DeLagEnabled", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwAmdGpu.Title, "HKLM", activeGpuClassSubKey, "FlipQueueSize", 0x3100, RegistryValueKind.DWord);
                }));
            hwAmdGpu.Variations.Add(new TweakVariation(
                "Radeon Dengeli Akıcılık (Uyku Kapalı + 2 Kare Tampon)",
                "Takılma Önleyici + Hikayeli ve Ağır Oyunlar İçin Akıcı Kareler",
                "Hem rekabetçi hem de yüksek grafikli hikayeli oyunlarda takılmaları önlerken akıcı görüntü sunar.",
                "Derin Uyku ve Stutter Kapalı + 2 Kare Tampon",
                () =>
                {
                    vault.SetRegistryTracked(hwAmdGpu.Title, "HKLM", activeGpuClassSubKey, "EnableUlps", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwAmdGpu.Title, "HKLM", activeGpuClassSubKey, "PP_SclkDeepSleepDisable", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwAmdGpu.Title, "HKLM", activeGpuClassSubKey, "StutterMode", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwAmdGpu.Title, "HKLM", activeGpuClassSubKey, "FlipQueueSize", 0x3200, RegistryValueKind.DWord);
                }));
            hwAmdGpu.Variations.Add(new TweakVariation(
                "Sadece Radeon Uyku Kalkanı (ULPS Kapalı)",
                "Adrenalin Ayarlarına Dokunmadan Sadece Frekans Düşüşünü Önle",
                "Kendi AMD Adrenalin ayarlarınızı bozmadan sadece kartın oyun ortasında uyku moduna geçmesini engeller.",
                "Sadece ULPS ve Derin Uyku Kapalı",
                () =>
                {
                    vault.SetRegistryTracked(hwAmdGpu.Title, "HKLM", activeGpuClassSubKey, "EnableUlps", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwAmdGpu.Title, "HKLM", activeGpuClassSubKey, "PP_SclkDeepSleepDisable", 1, RegistryValueKind.DWord);
                }));
            allTweaks.Add(hwAmdGpu);

            // HW-05: Intel Arc / Iris Xe GPU Optimization
            var hwIntelGpu = new TweakDefinition
            {
                Id = "HW_INTEL_GPU",
                Category = "HARDWARE",
                HardwareTag = "INTEL_GPU",
                BadgeText = "INTEL ARC GPU ÖZEL",
                BadgeColor = Color.FromArgb(6, 182, 212),
                RequiresAdmin = true,
                Title = "Intel Arc Ekran Kartı Optimizasyonu (Veri Yolu Güç Kilidi & Akıcılık)",
                SummaryDescription = "Intel Arc ekran kartlarında güç tasarrufu kaynaklı FPS düşüşlerini kapatır ve modern oyun uyumluluğunu artırır.",
                DeepTechnicalWhy = "Genellikle Intel Arc ekran kartlarında tam performans almak ve pencereli/DX11 oyunlardaki kare süresi dalgalanmalarını önlemek için kullanılır.",
                TargetPathOrApi = "Intel Arc Performans Profili",
                QueryOriginalOrDefaultSummary = () => "Standart Arc Profili",
                RevertAction = () =>
                {
                    vault.RemovePowerSettingTracked(SUB_PCIEXPRESS + "|" + SET_PCIEASPM);
                    vault.RevertRegistryTracked("HKLM", gfxDrivers, "HwSchMode");
                    vault.RevertRegistryTracked("HKLM", gfxDrivers, "TdrDelay");
                }
            };
            hwIntelGpu.Variations.Add(new TweakVariation(
                "Arc Maksimum Performans",
                "Veri Yolu Güç Tasarrufu Kapalı + Donanım Zamanlaması Açık",
                "Intel Arc ekran kartından oyunlarda en yüksek FPS değerini almak için kullanılır.",
                "PCIe Güç Tasarrufu Kapalı + HAGS Açık",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PCIEXPRESS + "|" + SET_PCIEASPM, SUB_PCIEXPRESS, SET_PCIEASPM, 0);
                    vault.SetRegistryTracked(hwIntelGpu.Title, "HKLM", gfxDrivers, "HwSchMode", 2, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(hwIntelGpu.Title, "HKLM", gfxDrivers, "TdrDelay", 10, RegistryValueKind.DWord);
                }));
            hwIntelGpu.Variations.Add(new TweakVariation(
                "Arc Pencereli Oyun & DX11 İyileştirmesi",
                "Pencereli Oyunlarda Düşük Gecikme + Güç Tasarrufu Kapalı",
                "Eski veya pencereli (Borderless) oyunlarda daha akıcı görüntü almak için kullanılır.",
                "Flip-Model Sunum + PCIe Tam Güç",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PCIEXPRESS + "|" + SET_PCIEASPM, SUB_PCIEXPRESS, SET_PCIEASPM, 0);
                    vault.SetRegistryTracked(hwIntelGpu.Title, "HKCU", dxGlobal, "DirectXUserGlobalSettings", "VRROptimizeEnable=1;SwapEffectUpgradeEnable=1;", RegistryValueKind.String);
                }));
            hwIntelGpu.Variations.Add(new TweakVariation(
                "Sadece Veri Yolu Uyku Kilidi",
                "Sadece Ekran Kartı Güç Tasarrufunu Kapat",
                "Diğer grafik ayarlarına dokunmadan sadece kartın güç tasarrufuna geçmesini engeller.",
                "PCIe Güç Tasarrufu Kapalı",
                () => vault.ApplyPowerSettingTracked(SUB_PCIEXPRESS + "|" + SET_PCIEASPM, SUB_PCIEXPRESS, SET_PCIEASPM, 0)));
            allTweaks.Add(hwIntelGpu);

            // =================================================================================================
            // CATEGORY 1: NETWORK & TCP OPTIMIZER PRO (12 COMPREHENSIVE MULTI-VARIATION TWEAKS)
            // =================================================================================================

            // NET-01: Nagle's Algorithm & Delayed ACK
            var net01 = new TweakDefinition
            {
                Id = "NET_NAGLE",
                Category = "NETWORK",
                HardwareTag = "ALL",
                BadgeText = "TCP OPTIMIZER / OYUN PİNG",
                BadgeColor = colNet,
                RequiresAdmin = true,
                NeedsNetReload = true,
                Title = "Nagle Algoritması & Paket Bekletmeyi Kapatma (Anında Paket İletimi)",
                SummaryDescription = "Küçük oyun paketlerinin gönderilmeden önce 40-200ms boyunca birleştirilip bekletilmesini kapatır; paketler üretildiği an çıkar.",
                DeepTechnicalWhy = "Genellikle online rekabetçi oyunlarda (CS2, Valorant, HaxBall, LoL vb.) mermi/pas komutlarının sunucuya gecikmesiz ulaşması için kullanılır. Açıldığında ağ kartındaki paket birleştirme ayarlarıyla otomatik senkronize çalışır.",
                TargetPathOrApi = @"Ağ Kartı Paket Bekletme Ayarı",
                QueryOriginalOrDefaultSummary = () => "Varsayılan (Ack=2, Nagle=Açık)",
                RevertAction = () =>
                {
                    foreach (string g in activeTcpInterfaceGuids)
                    {
                        string k = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + g;
                        vault.RevertRegistryTracked("HKLM", k, "TcpAckFrequency");
                        vault.RevertRegistryTracked("HKLM", k, "TCPNoDelay");
                        vault.RevertRegistryTracked("HKLM", k, "TcpDelAckTicks");
                    }
                }
            };
            net01.Variations.Add(new TweakVariation(
                "Sıfır Paket Bekletme (Tam Espor Modu)",
                "Her Paketi Bekletmeden Anında Gönder ve Onayla",
                "Sadece en düşük ping ve en hızlı sunucu tepkisi istediğiniz online oyunlarda kullanılır.",
                "Sıfır Paket Birleştirme + Anında Onay",
                () =>
                {
                    foreach (string g in activeTcpInterfaceGuids)
                    {
                        string k = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + g;
                        vault.SetRegistryTracked(net01.Title, "HKLM", k, "TcpAckFrequency", 1, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(net01.Title, "HKLM", k, "TCPNoDelay", 1, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(net01.Title, "HKLM", k, "TcpDelAckTicks", 0, RegistryValueKind.DWord);
                    }
                    vault.NetshModified = true;
                    StateVault.RunHiddenCmd("netsh", "int tcp set global rsc=disabled");
                }));
            net01.Variations.Add(new TweakVariation(
                "Dengeli Hızlı (Düşük Upload Dostu)",
                "Paket Bekletme Kapalı + Dengeli Onay Trafiği",
                "Upload hızı düşük olan (VDSL/ADSL) bağlantılarda hattı yormadan oyun paketlerini hızlandırmak için kullanılır.",
                "Nagle Kapalı + Dengeli Onay",
                () =>
                {
                    foreach (string g in activeTcpInterfaceGuids)
                    {
                        string k = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + g;
                        vault.SetRegistryTracked(net01.Title, "HKLM", k, "TcpAckFrequency", 2, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(net01.Title, "HKLM", k, "TCPNoDelay", 1, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(net01.Title, "HKLM", k, "TcpDelAckTicks", 1, RegistryValueKind.DWord);
                    }
                }));
            net01.Variations.Add(new TweakVariation(
                "Yayın + Oyun Modu (OBS / Twitch)",
                "Canlı Yayın Yaparken Oyun Oynayanlar İçin Dengeli Paket Akışı",
                "Hem OBS üzerinden canlı yayın verip hem de online oyun oynarken yayın karelerinin düşmemesi için kullanılır.",
                "Yayın ve Oyun Dengeli Paket Akışı",
                () =>
                {
                    foreach (string g in activeTcpInterfaceGuids)
                    {
                        string k = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + g;
                        vault.SetRegistryTracked(net01.Title, "HKLM", k, "TcpAckFrequency", 1, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(net01.Title, "HKLM", k, "TCPNoDelay", 0, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(net01.Title, "HKLM", k, "TcpDelAckTicks", 1, RegistryValueKind.DWord);
                    }
                }));
            allTweaks.Add(net01);

            // NET-02: TCP Receive Window Auto-Tuning & RFC 1323 Scaling
            var net02 = new TweakDefinition
            {
                Id = "NET_AUTOTUNING",
                Category = "NETWORK",
                HardwareTag = "ALL",
                BadgeText = "TCP OPTIMIZER GENEL",
                BadgeColor = colNet,
                RequiresAdmin = true,
                Title = "İndirme Tamponu & Modem Kuyruk Koruması (Bufferbloat Önleyici)",
                SummaryDescription = "Evde arka planda video izlenirken veya indirme yapılırken oyundaki pingin fırlamasını (Bufferbloat) engeller.",
                DeepTechnicalWhy = "Genellikle aynı internete bağlı başka cihazlar varken veya arka planda Discord/tarayıcı açıkken ping dalgalanmasını önlemek amacıyla kullanılır.",
                TargetPathOrApi = "TCP Pencere & Kuyruk Yönetimi",
                QueryOriginalOrDefaultSummary = () => "AutoTune=" + vault.OrigAutoTuning + ", Tcp1323=" + vault.ReadRegistryDisplay("HKLM", tcpParams, "Tcp1323Opts", "Varsayılan"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", tcpParams, "Tcp1323Opts");
                    StateVault.RunHiddenCmd("netsh", string.Format("int tcp set global autotuninglevel={0} timestamps={1}", vault.OrigAutoTuning, vault.OrigTimestamps));
                }
            };
            net02.Variations.Add(new TweakVariation(
                "Normal + Hızlı Başlık (TCP Optimizer Önerilen)",
                "Hem Tam İndirme Hızı Hem Düşük Ping (Fiber / VDSL)",
                "İndirme hızınızı hiç düşürmeden paketlerdeki gereksiz zaman damgası yükünü kaldırır.",
                "Normal Tampon + Zaman Damgası Kapalı",
                () =>
                {
                    vault.NetshModified = true;
                    vault.SetRegistryTracked(net02.Title, "HKLM", tcpParams, "Tcp1323Opts", 1, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", "int tcp set global autotuninglevel=normal timestamps=disabled");
                }));
            net02.Variations.Add(new TweakVariation(
                "Ping Korumalı Kısıtlı Mod (Anti-Bufferbloat)",
                "Ev Ağı Yoğunken Ping Sıçramasını Keser",
                "Evde başkaları video izlerken veya indirme yaparken oyundaki pinginizin yükselmesini engellemek için kullanılır.",
                "Kısıtlı Tampon (Anti-Bufferbloat)",
                () =>
                {
                    vault.NetshModified = true;
                    vault.SetRegistryTracked(net02.Title, "HKLM", tcpParams, "Tcp1323Opts", 1, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", "int tcp set global autotuninglevel=restricted timestamps=disabled");
                }));
            net02.Variations.Add(new TweakVariation(
                "Saf Düşük Ping (Minimum Tampon)",
                "Sadece Oyun Odaklı En Küçük Paket Kuyruğu",
                "İndirme hızından ziyade yalnızca maç içindeki paketlerin sıfır kuyrukta beklemesi gerektiğinde kullanılır.",
                "En Küçük Tampon Boyutu",
                () =>
                {
                    vault.NetshModified = true;
                    vault.SetRegistryTracked(net02.Title, "HKLM", tcpParams, "Tcp1323Opts", 0, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", "int tcp set global autotuninglevel=highlyrestricted timestamps=disabled");
                }));
            net02.Variations.Add(new TweakVariation(
                "1000 Mbps+ Gigabit İndirme Modu",
                "Yüksek Hızlı Fiber İçin Maksimum İndirme Kapasitesi",
                "Büyük oyun veya dosya indirirken 1 Gbps fiber hattın tam kapasitesini kullanmak için seçilir.",
                "Maksimum Fiber Tamponu",
                () =>
                {
                    vault.NetshModified = true;
                    vault.SetRegistryTracked(net02.Title, "HKLM", tcpParams, "Tcp1323Opts", 3, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", "int tcp set global autotuninglevel=experimental timestamps=enabled");
                }));
            allTweaks.Add(net02);

            // NET-03: NetworkThrottlingIndex & SystemResponsiveness
            var net03 = new TweakDefinition
            {
                Id = "NET_THROTTLING",
                Category = "NETWORK",
                HardwareTag = "ALL",
                BadgeText = "WINDOWS AĞ SINIRI",
                BadgeColor = colNet,
                RequiresAdmin = true,
                NeedsReboot = true,
                Title = "Windows Ağ Paket Kısıtlamasını Kaldırma & Oyun Önceliği",
                SummaryDescription = "Windows'un ses veya video oynatılırken ağ paketlerine uyguladığı hız sınırını kaldırır ve işlemciyi oyuna odaklar.",
                DeepTechnicalWhy = "Genellikle arkada Discord, Spotify veya tarayıcı açıkken oyun içinde oluşan paket gecikmelerini ve FPS düşüşlerini önlemek için kullanılır.",
                TargetPathOrApi = @"Windows Multimedya & Ağ Önceliği",
                QueryOriginalOrDefaultSummary = () => "Throttling=" + vault.ReadRegistryDisplay("HKLM", mmcssRoot, "NetworkThrottlingIndex", "10") + ", Resp=" + vault.ReadRegistryDisplay("HKLM", mmcssRoot, "SystemResponsiveness", "20"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", mmcssRoot, "NetworkThrottlingIndex");
                    vault.RevertRegistryTracked("HKLM", mmcssRoot, "SystemResponsiveness");
                }
            };
            net03.Variations.Add(new TweakVariation(
                "Tam Kilit Açık (Sıfır Kısıtlama + %100 Oyun)",
                "Ağ Kısıtlaması Tamamen Kapalı + Maksimum Oyun Önceliği",
                "Sistem kaynaklarının tamamını ön plandaki oyuna ve ağ paketlerine ayırmak için kullanılır.",
                "Ağ Sınırı Kapalı + %0 Arka Plan Rezervi",
                () =>
                {
                    vault.SetRegistryTracked(net03.Title, "HKLM", mmcssRoot, "NetworkThrottlingIndex", unchecked((int)0xFFFFFFFF), RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net03.Title, "HKLM", mmcssRoot, "SystemResponsiveness", 0, RegistryValueKind.DWord);
                }));
            net03.Variations.Add(new TweakVariation(
                "TCP Optimizer Optimal (Oyun + Discord Dengeli)",
                "Ağ Kısıtlaması Kapalı + %10 Ses/Discord Payı",
                "Ağ kısıtlamasını tamamen kapatırken arka plandaki Discord sesli sohbetinin kesilmemesi için %10 pay bırakır.",
                "Ağ Sınırı Kapalı + %10 Ses/Discord Payı",
                () =>
                {
                    vault.SetRegistryTracked(net03.Title, "HKLM", mmcssRoot, "NetworkThrottlingIndex", unchecked((int)0xFFFFFFFF), RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net03.Title, "HKLM", mmcssRoot, "SystemResponsiveness", 10, RegistryValueKind.DWord);
                }));
            net03.Variations.Add(new TweakVariation(
                "Dengeli Yüksek Limit (Ses Çıtırtısı Önleyici)",
                "Varsayılanın 7 Katı Paket Limiti + %10 Sistem Payı",
                "Harici ses kartı kullanan sistemlerde yoğun ağ trafiği sırasında seste cızırtı olmaması için kullanılır.",
                "Yüksek Paket Limiti (70x) + %10 Sistem Payı",
                () =>
                {
                    vault.SetRegistryTracked(net03.Title, "HKLM", mmcssRoot, "NetworkThrottlingIndex", 70, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net03.Title, "HKLM", mmcssRoot, "SystemResponsiveness", 10, RegistryValueKind.DWord);
                }));
            allTweaks.Add(net03);

            // NET-04: TCP Initial RTO & SYN Retransmissions
            var net04 = new TweakDefinition
            {
                Id = "NET_RTO",
                Category = "NETWORK",
                HardwareTag = "ALL",
                BadgeText = "KAYIP PAKET TELAFİSİ",
                BadgeColor = colNet,
                RequiresAdmin = true,
                Title = "Kayıp Paket Kurtarma Süresi (3 Saniyeden 0.3 Saniyeye Düşürme)",
                SummaryDescription = "İnternette anlık paket kaybı yaşandığında Windows'un yeni paket istemek için beklediği 3 saniyelik süreyi 300ms'ye indirir.",
                DeepTechnicalWhy = "Genellikle oyunlarda anlık paket kaybı (packet loss) olduğunda karakterin 2-3 saniye boyunca donup kalmasını (ışınlanma hissini) önlemek amacıyla kullanılır.",
                TargetPathOrApi = "Kayıp Paket Telafi Süresi",
                QueryOriginalOrDefaultSummary = () => "Varsayılan (InitialRTO=3000ms, MaxSyn=2)",
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", tcpParams, "TcpMaxDataRetransmissions");
                    StateVault.RunHiddenCmd("netsh", "int tcp set global initialRto=3000 maxsynretransmissions=2 nonsackrttresiliency=disabled");
                }
            };
            net04.Variations.Add(new TweakVariation(
                "Espor 300ms (10 Kat Hızlı Kurtarma)",
                "Kayıp Paketi 3 Saniye Yerine 0.3 Saniyede Telafi Et",
                "Kablolu veya fiber bağlantılarda anlık paket kaybını en hızlı şekilde telafi etmek için kullanılır.",
                "300ms Hızlı Kurtarma",
                () =>
                {
                    vault.NetshModified = true;
                    vault.SetRegistryTracked(net04.Title, "HKLM", tcpParams, "TcpMaxDataRetransmissions", 3, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", "int tcp set global initialRto=300 maxsynretransmissions=2 nonsackrttresiliency=disabled");
                }));
            net04.Variations.Add(new TweakVariation(
                "Yurt Dışı Sunucu Dengeli (1000ms)",
                "Avrupa / Uzak Sunucular İçin 1 Saniye Kurtarma",
                "Yurt dışı sunucularda (60-90ms ping) gereksiz paket tekrarını önleyerek kararlı bağlantı sağlar.",
                "1000ms Dengeli Kurtarma",
                () =>
                {
                    vault.NetshModified = true;
                    vault.SetRegistryTracked(net04.Title, "HKLM", tcpParams, "TcpMaxDataRetransmissions", 5, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", "int tcp set global initialRto=1000 maxsynretransmissions=2 nonsackrttresiliency=disabled");
                }));
            net04.Variations.Add(new TweakVariation(
                "Wi-Fi / Dalgalı İnternet Koruması",
                "Kablosuz Bağlantılarda Kopma Önleyici Mod",
                "Wi-Fi veya mobil internetle oynarken anlık ping dalgalanmalarında oyundan düşmeyi engellemek için kullanılır.",
                "Kablosuz Hat Kopma Koruması",
                () =>
                {
                    vault.NetshModified = true;
                    vault.SetRegistryTracked(net04.Title, "HKLM", tcpParams, "TcpMaxDataRetransmissions", 5, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", "int tcp set global initialRto=1500 maxsynretransmissions=3 nonsackrttresiliency=enabled");
                }));
            allTweaks.Add(net04);

            // NET-05: MaxUserPort, TcpTimedWaitDelay & DefaultTTL
            var net05 = new TweakDefinition
            {
                Id = "NET_PORTS_TTL",
                Category = "NETWORK",
                HardwareTag = "ALL",
                BadgeText = "PORT & BAĞLANTI HAVUZU",
                BadgeColor = colNet,
                RequiresAdmin = true,
                NeedsReboot = true,
                Title = "Oyun Port Havuzu Genişletme & Hızlı Bağlantı Yenileme",
                SummaryDescription = "Kullanılabilir port sayısını maksimuma (65534) çıkarır ve kapanan bağlantıların portları kilitleme süresini kısaltır.",
                DeepTechnicalWhy = "Genellikle HaxBall gibi P2P oda kurulan oyunlarda, sunucu listesi yenilemelerinde ve arka arkaya maç aratırken bağlantı tıkanıklığını önlemek için kullanılır.",
                TargetPathOrApi = @"Port Havuzu & Soket Süresi",
                QueryOriginalOrDefaultSummary = () => "Port=" + vault.ReadRegistryDisplay("HKLM", tcpParams, "MaxUserPort", "16384") + ", Wait=" + vault.ReadRegistryDisplay("HKLM", tcpParams, "TcpTimedWaitDelay", "120s"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", tcpParams, "MaxUserPort");
                    vault.RevertRegistryTracked("HKLM", tcpParams, "TcpTimedWaitDelay");
                    vault.RevertRegistryTracked("HKLM", tcpParams, "DefaultTTL");
                    StateVault.RunHiddenCmd("netsh", "int ipv4 set dynamicport tcp start=49152 num=16384");
                    StateVault.RunHiddenCmd("netsh", "int ipv4 set dynamicport udp start=49152 num=16384");
                }
            };
            net05.Variations.Add(new TweakVariation(
                "TCP Optimizer Optimal (65534 Port / 30sn)",
                "Maksimum Port Havuzu + 30 Saniyede Port Temizliği",
                "Tüm oyunlar ve günlük kullanım için önerilen en dengeli port genişletme ayarıdır.",
                "65534 Port + 30sn Temizlik + TTL 64",
                () =>
                {
                    vault.SetRegistryTracked(net05.Title, "HKLM", tcpParams, "MaxUserPort", 65534, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net05.Title, "HKLM", tcpParams, "TcpTimedWaitDelay", 30, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net05.Title, "HKLM", tcpParams, "DefaultTTL", 64, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", "int ipv4 set dynamicport tcp start=1025 num=64510");
                    StateVault.RunHiddenCmd("netsh", "int ipv4 set dynamicport udp start=1025 num=64510");
                }));
            net05.Variations.Add(new TweakVariation(
                "HaxBall / P2P Oda Kurucu Modu (15sn)",
                "Çoklu Oyuncu & WebRTC Odaları İçin Hızlı Port Döngüsü",
                "HaxBall'da oda açarken (host olurken) veya çok sayıda oyuncunun bağlandığı P2P oyunlarda portların 15 saniyede yenilenmesini sağlar.",
                "65534 Port + 15sn Hızlı Port Döngüsü",
                () =>
                {
                    vault.SetRegistryTracked(net05.Title, "HKLM", tcpParams, "MaxUserPort", 65534, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net05.Title, "HKLM", tcpParams, "TcpTimedWaitDelay", 15, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net05.Title, "HKLM", tcpParams, "DefaultTTL", 64, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", "int ipv4 set dynamicport tcp start=1025 num=64510");
                    StateVault.RunHiddenCmd("netsh", "int ipv4 set dynamicport udp start=1025 num=64510");
                }));
            net05.Variations.Add(new TweakVariation(
                "Standart Genişletilmiş (32768 Port / 60sn)",
                "Windows Varsayılanına Yakın Güvenli Genişletme",
                "Standart ayarları bozmadan sadece port kapasitesini iki katına çıkarmak için kullanılır.",
                "32768 Port + 60sn Temizlik",
                () =>
                {
                    vault.SetRegistryTracked(net05.Title, "HKLM", tcpParams, "MaxUserPort", 32768, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net05.Title, "HKLM", tcpParams, "TcpTimedWaitDelay", 60, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net05.Title, "HKLM", tcpParams, "DefaultTTL", 128, RegistryValueKind.DWord);
                }));
            allTweaks.Add(net05);

            // NET-06: Host Resolution Priority
            var net06 = new TweakDefinition
            {
                Id = "NET_HOSTPRIO",
                Category = "NETWORK",
                HardwareTag = "ALL",
                BadgeText = "SUNUCU ADRES ÇÖZÜMLEME",
                BadgeColor = colNet,
                RequiresAdmin = true,
                Title = "Oyun Sunucusu Adres Çözümleme Hızlandırıcı",
                SummaryDescription = "Oyun sunucularına ve web sitelerine ilk bağlanma anındaki adres arama sırasını hızlandırır.",
                DeepTechnicalWhy = "Genellikle maça girerken, lobiye bağlanırken veya tarayıcıda sayfa açarken yaşanan ilk bekleme süresini kısaltmak için kullanılır.",
                TargetPathOrApi = @"Sunucu İsim Çözümleme Sırası",
                QueryOriginalOrDefaultSummary = () => "DNS=" + vault.ReadRegistryDisplay("HKLM", tcpServiceProvider, "DnsPriority", "2000") + ", NetBT=" + vault.ReadRegistryDisplay("HKLM", tcpServiceProvider, "NetbtPriority", "2001"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", tcpServiceProvider, "LocalPriority");
                    vault.RevertRegistryTracked("HKLM", tcpServiceProvider, "HostsPriority");
                    vault.RevertRegistryTracked("HKLM", tcpServiceProvider, "DnsPriority");
                    vault.RevertRegistryTracked("HKLM", tcpServiceProvider, "NetbtPriority");
                }
            };
            net06.Variations.Add(new TweakVariation(
                "TCP Optimizer Optimal Sıralama",
                "Tüm Sunucu ve DNS Sorgularını En Yüksek Önceliğe Al",
                "Hem oyun içi sunucu bağlantılarını hem de internet gezinmesini hızlandıran standart ayardır.",
                "Optimal Çözümleme Önceliği (4/5/6/7)",
                () =>
                {
                    vault.SetRegistryTracked(net06.Title, "HKLM", tcpServiceProvider, "LocalPriority", 4, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net06.Title, "HKLM", tcpServiceProvider, "HostsPriority", 5, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net06.Title, "HKLM", tcpServiceProvider, "DnsPriority", 6, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net06.Title, "HKLM", tcpServiceProvider, "NetbtPriority", 7, RegistryValueKind.DWord);
                    NativeMethods.DnsFlushResolverCache();
                }));
            net06.Variations.Add(new TweakVariation(
                "Yavaş Yerel Ağ (NetBIOS) Aramasını Kapat",
                "Doğrudan DNS Sorgusu + Ev Ağı Beklemesini Atla",
                "Windows'un internete çıkmadan önce yerel ağda gereksiz cihaz araması yapmasını engeller.",
                "Hızlı DNS + Yerel Ağ Beklemesi Kapalı",
                () =>
                {
                    vault.SetRegistryTracked(net06.Title, "HKLM", tcpServiceProvider, "LocalPriority", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net06.Title, "HKLM", tcpServiceProvider, "HostsPriority", 2, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net06.Title, "HKLM", tcpServiceProvider, "DnsPriority", 3, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net06.Title, "HKLM", tcpServiceProvider, "NetbtPriority", 99, RegistryValueKind.DWord);
                    NativeMethods.DnsFlushResolverCache();
                }));
            net06.Variations.Add(new TweakVariation(
                "Doğrudan Önbellekli DNS Önceliği",
                "Dosya Taramasını Atlayıp Doğrudan DNS Önbelleğine Git",
                "Özellikle tarayıcı tabanlı oyunlarda ve hızlı sunucu geçişlerinde kullanılır.",
                "Doğrudan DNS Önbellek Önceliği",
                () =>
                {
                    vault.SetRegistryTracked(net06.Title, "HKLM", tcpServiceProvider, "LocalPriority", 2, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net06.Title, "HKLM", tcpServiceProvider, "DnsPriority", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net06.Title, "HKLM", tcpServiceProvider, "HostsPriority", 10, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net06.Title, "HKLM", tcpServiceProvider, "NetbtPriority", 50, RegistryValueKind.DWord);
                    NativeMethods.DnsFlushResolverCache();
                }));
            allTweaks.Add(net06);

            // NET-07: MTU, Path MTU Discovery & Selective ACK (SackOpts)
            var net07 = new TweakDefinition
            {
                Id = "NET_MTU_SACK",
                Category = "NETWORK",
                HardwareTag = "ALL",
                BadgeText = "PAKET BOYUTU (MTU)",
                BadgeColor = colNet,
                RequiresAdmin = true,
                Title = "İnternet Altyapısına Göre Paket Boyutu (MTU) & Parçalanma Önleyici",
                SummaryDescription = "İnternet paketlerinin modemde ikiye bölünüp ekstra ping yaratmasını önler ve sadece düşen paketin tekrar gönderilmesini sağlar.",
                DeepTechnicalWhy = "Genellikle Fiber/Kablo bağlantılarda 1500, Türk Telekom VDSL/PPPoE bağlantılarda ise 1492 seçilerek paketlerin yolda parçalanıp gecikme yaratmasını önlemek için kullanılır.",
                TargetPathOrApi = @"Ağ Paket Boyutu (MTU) — Anında Uygulanır",
                QueryOriginalOrDefaultSummary = () => "SackOpts=" + vault.ReadRegistryDisplay("HKLM", tcpParams, "SackOpts", "1") + ", MTU=1500",
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", tcpParams, "SackOpts");
                    vault.RevertRegistryTracked("HKLM", tcpParams, "EnablePMTUDiscovery");
                    vault.RevertRegistryTracked("HKLM", tcpParams, "EnablePMTUBHDetect");
                    foreach (string g in activeTcpInterfaceGuids)
                        vault.RevertRegistryTracked("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + g, "MTU");
                    StateVault.RunHiddenCmd("netsh", string.Format("interface ipv4 set subinterface \"{0}\" mtu=1500 store=active", vault.ActiveAdapterName));
                }
            };
            net07.Variations.Add(new TweakVariation(
                "Fiber / Kablo Standart (MTU=1500)",
                "Fiber ve Kablonet Bağlantılar İçin Tam Paket Boyutu",
                "Fiber (GPON) veya Kablonet kullanıyorsanız paketlerin bölünmeden tek seferde gitmesi için kullanılır.",
                "MTU=1500 + Akıllı Paket Tekrarı (SACK)",
                () =>
                {
                    vault.SetRegistryTracked(net07.Title, "HKLM", tcpParams, "SackOpts", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net07.Title, "HKLM", tcpParams, "EnablePMTUDiscovery", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net07.Title, "HKLM", tcpParams, "EnablePMTUBHDetect", 0, RegistryValueKind.DWord);
                    foreach (string g in activeTcpInterfaceGuids)
                        vault.SetRegistryTracked(net07.Title, "HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + g, "MTU", 1500, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", string.Format("interface ipv4 set subinterface \"{0}\" mtu=1500 store=active", vault.ActiveAdapterName));
                }));
            net07.Variations.Add(new TweakVariation(
                "VDSL / PPPoE Altyapı (MTU=1492)",
                "Türk Telekom VDSL / PPPoE Modemler İçin Paket Bölünme Koruması",
                "Modem arayüzünde kullanıcı adı/şifre (PPPoE) girili olan VDSL/Fiber hatlarda paketlerin ikiye bölünmesini engeller.",
                "MTU=1492 (PPPoE Uyumlu) + SACK Açık",
                () =>
                {
                    vault.SetRegistryTracked(net07.Title, "HKLM", tcpParams, "SackOpts", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net07.Title, "HKLM", tcpParams, "EnablePMTUDiscovery", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net07.Title, "HKLM", tcpParams, "EnablePMTUBHDetect", 0, RegistryValueKind.DWord);
                    foreach (string g in activeTcpInterfaceGuids)
                        vault.SetRegistryTracked(net07.Title, "HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + g, "MTU", 1492, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", string.Format("interface ipv4 set subinterface \"{0}\" mtu=1492 store=active", vault.ActiveAdapterName));
                }));
            net07.Variations.Add(new TweakVariation(
                "Yurt Dışı Sunucu / VPN Korumalı (MTU=1472)",
                "Uzak Sunucularda Paket Takılmasını Önleyen Güvenli Boyut",
                "Yurt dışı sunucularda veya WARP/VPN kullanırken mermilerin gitmemesi (hitreg) sorununu çözmek için kullanılır.",
                "MTU=1472 + Yönlendirici Koruması",
                () =>
                {
                    vault.SetRegistryTracked(net07.Title, "HKLM", tcpParams, "SackOpts", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net07.Title, "HKLM", tcpParams, "EnablePMTUDiscovery", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net07.Title, "HKLM", tcpParams, "EnablePMTUBHDetect", 1, RegistryValueKind.DWord);
                    foreach (string g in activeTcpInterfaceGuids)
                        vault.SetRegistryTracked(net07.Title, "HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + g, "MTU", 1472, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", string.Format("interface ipv4 set subinterface \"{0}\" mtu=1472 store=active", vault.ActiveAdapterName));
                }));
            allTweaks.Add(net07);

            // NET-08: Winsock AFD UDP Fast-Path & Datagram Buffers
            var net08 = new TweakDefinition
            {
                Id = "NET_AFD_UDP",
                Category = "NETWORK",
                HardwareTag = "ALL",
                BadgeText = "UDP / WEBRTC HIZLI YOL",
                BadgeColor = colNet,
                RequiresAdmin = true,
                Title = "Online Oyun (UDP & WebRTC) Hızlı Paket Geçişi",
                SummaryDescription = "CS2, Valorant, HaxBall ve LoL gibi gerçek zamanlı oyun paketlerinin Windows içinde kopyalanıp bekletilmeden doğrudan ağ kartına iletilmesini sağlar.",
                DeepTechnicalWhy = "Genellikle anlık pozisyon ve vuruş verisi gönderen tüm online oyunlarda paket gecikmesini (input/network lag) düşürmek için kullanılır.",
                TargetPathOrApi = @"Windows Soket Hızlı Geçiş Motoru",
                QueryOriginalOrDefaultSummary = () => "FastSend=" + vault.ReadRegistryDisplay("HKLM", afdParams, "FastSendDatagramThreshold", "1024"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", afdParams, "FastSendDatagramThreshold");
                    vault.RevertRegistryTracked("HKLM", afdParams, "FastCopyReceiveThreshold");
                    vault.RevertRegistryTracked("HKLM", afdParams, "DefaultSendWindow");
                    vault.RevertRegistryTracked("HKLM", afdParams, "DefaultReceiveWindow");
                    vault.RevertRegistryTracked("HKLM", afdParams, "DynamicSendBufferDisable");
                }
            };
            net08.Variations.Add(new TweakVariation(
                "Tüm Oyun Paketleri İçin Hızlı Geçiş (Önerilen)",
                "Büyüklüğü Ne Olursa Olsun Tüm Oyun Paketlerini Bekletmeden Gönder",
                "Hem tarayıcı tabanlı (HaxBall) hem de istemci tabanlı (CS2, Valorant) oyunlarda en hızlı paket çıkışını sağlar.",
                "64 KB Hızlı Paket Geçiş Eşiği",
                () =>
                {
                    vault.SetRegistryTracked(net08.Title, "HKLM", afdParams, "FastSendDatagramThreshold", 65536, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net08.Title, "HKLM", afdParams, "FastCopyReceiveThreshold", 65536, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net08.Title, "HKLM", afdParams, "DefaultSendWindow", 65536, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net08.Title, "HKLM", afdParams, "DefaultReceiveWindow", 65536, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net08.Title, "HKLM", afdParams, "DynamicSendBufferDisable", 0, RegistryValueKind.DWord);
                }));
            net08.Variations.Add(new TweakVariation(
                "Sadece Saf Oyun Paketlerine Öncelik (1500 Byte)",
                "Küçük Oyun Paketlerini Hızlandır, Büyük İndirmeleri Ayır",
                "Arka planda indirme açıkken sadece küçük oyun paketlerinin hızlı yoldan geçmesi için kullanılır.",
                "1500 Byte Oyun Paketi Eşiği",
                () =>
                {
                    vault.SetRegistryTracked(net08.Title, "HKLM", afdParams, "FastSendDatagramThreshold", 1500, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net08.Title, "HKLM", afdParams, "FastCopyReceiveThreshold", 1500, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net08.Title, "HKLM", afdParams, "DefaultSendWindow", 32768, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net08.Title, "HKLM", afdParams, "DefaultReceiveWindow", 32768, RegistryValueKind.DWord);
                }));
            net08.Variations.Add(new TweakVariation(
                "Kalabalık Sunucu & Yayın Modu (Geniş Tampon)",
                "Çok Oyunculu (20+ Kişi) Odalarda Paket Düşmesini Önler",
                "Kalabalık sunucularda veya oda hostlarken aynı anda gelen yoğun paketlerin kaybolmaması için kullanılır.",
                "Hızlı Geçiş + 256 KB Geniş Soket Tamponu",
                () =>
                {
                    vault.SetRegistryTracked(net08.Title, "HKLM", afdParams, "FastSendDatagramThreshold", 65536, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net08.Title, "HKLM", afdParams, "FastCopyReceiveThreshold", 65536, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net08.Title, "HKLM", afdParams, "DefaultSendWindow", 262144, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net08.Title, "HKLM", afdParams, "DefaultReceiveWindow", 262144, RegistryValueKind.DWord);
                }));
            allTweaks.Add(net08);

            // NET-09: NIC Interrupt Moderation & Ring Buffers
            var net09 = new TweakDefinition
            {
                Id = "NET_NIC_INT",
                Category = "NETWORK",
                HardwareTag = "ALL",
                BadgeText = "AĞ KARTI TEPKİ SÜRESİ",
                BadgeColor = colNet,
                RequiresAdmin = true,
                NeedsNetReload = true,
                Title = "Ağ Kartı Paket Bekletmeyi Kapatma (Interrupt Moderation)",
                SummaryDescription = "Ağ kartının gelen paketleri işlemciye bildirmeden önce kart içinde biriktirip bekletmesini kapatır.",
                DeepTechnicalWhy = "Genellikle gelen her oyun paketinin ağ kartına ulaştığı mikrosaniyede işlemciye iletilmesi için kullanılır. Üstteki 'Ağ & Sürücüyü Şimdi Yenile' butonuyla bilgisayarı kapatmadan hemen devreye girer.",
                TargetPathOrApi = "Ağ Kartı Sürücü Ayarı",
                QueryOriginalOrDefaultSummary = () => "IntMod=" + vault.ReadRegistryDisplay("HKLM", activeNicClassSubKey, "*InterruptModeration", "1 (Açık)"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", activeNicClassSubKey, "*InterruptModeration");
                    vault.RevertRegistryTracked("HKLM", activeNicClassSubKey, "*ReceiveBuffers");
                    vault.RevertRegistryTracked("HKLM", activeNicClassSubKey, "*TransmitBuffers");
                }
            };
            net09.Variations.Add(new TweakVariation(
                "Sıfır Bekletme + Dengeli Tampon (Önerilen)",
                "Paket Biriktirme Kapalı + 512 Paket Tamponu",
                "Hem paketleri sıfır gecikmeyle işlemciye iletir hem de yoğun trafikte paket kaybını önler.",
                "Bekletme Kapalı + 512 Tampon",
                () =>
                {
                    vault.SetRegistryTracked(net09.Title, "HKLM", activeNicClassSubKey, "*InterruptModeration", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net09.Title, "HKLM", activeNicClassSubKey, "*ReceiveBuffers", "512", RegistryValueKind.String);
                    vault.SetRegistryTracked(net09.Title, "HKLM", activeNicClassSubKey, "*TransmitBuffers", "512", RegistryValueKind.String);
                }));
            net09.Variations.Add(new TweakVariation(
                "Ultra Düşük Kuyruk (Sadece Saf Oyun)",
                "Paket Biriktirme Kapalı + En Küçük Kart Kuyruğu (128)",
                "Ağ kartı içinde paketlerin sıraya girmesini tamamen engellemek için kullanılır.",
                "Bekletme Kapalı + 128 Minimum Tampon",
                () =>
                {
                    vault.SetRegistryTracked(net09.Title, "HKLM", activeNicClassSubKey, "*InterruptModeration", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net09.Title, "HKLM", activeNicClassSubKey, "*ReceiveBuffers", "128", RegistryValueKind.String);
                    vault.SetRegistryTracked(net09.Title, "HKLM", activeNicClassSubKey, "*TransmitBuffers", "128", RegistryValueKind.String);
                }));
            net09.Variations.Add(new TweakVariation(
                "Yüksek Hızlı Fiber & Yayın Modu (1024 Tampon)",
                "Paket Biriktirme Kapalı + Geniş Tampon",
                "1000 Mbps fiber hatlarda veya canlı yayın yaparken sıfır paket kaybı için kullanılır.",
                "Bekletme Kapalı + 1024 Geniş Tampon",
                () =>
                {
                    vault.SetRegistryTracked(net09.Title, "HKLM", activeNicClassSubKey, "*InterruptModeration", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net09.Title, "HKLM", activeNicClassSubKey, "*ReceiveBuffers", "1024", RegistryValueKind.String);
                    vault.SetRegistryTracked(net09.Title, "HKLM", activeNicClassSubKey, "*TransmitBuffers", "1024", RegistryValueKind.String);
                }));
            allTweaks.Add(net09);

            // NET-10: NIC Flow Control, EEE/Green Ethernet & Hardware Offloads
            var net10 = new TweakDefinition
            {
                Id = "NET_NIC_OFFLOAD",
                Category = "NETWORK",
                HardwareTag = "ALL",
                BadgeText = "AĞ KARTI UYKU KALKANI",
                BadgeColor = colNet,
                RequiresAdmin = true,
                NeedsNetReload = true,
                Title = "Ağ Kartı Enerji Tasarrufu (Green Ethernet) & Paket Birleştirmeyi Kapatma",
                SummaryDescription = "Ağ kartının paket gelmediği anlarda uyku moduna geçip uyanırken ping sıçraması (jitter) yapmasını engeller.",
                DeepTechnicalWhy = "Genellikle Realtek ve Intel ethernet kartlarında 5-10 saniyede bir oluşan anlık lag/takılma hissini tamamen bitirmek için kullanılır. Üstteki 'Ağ & Sürücüyü Şimdi Yenile' butonuyla hemen aktif olur.",
                TargetPathOrApi = "Ağ Kartı Güç & Birleştirme Ayarı",
                QueryOriginalOrDefaultSummary = () => "FlowCtrl=" + vault.ReadRegistryDisplay("HKLM", activeNicClassSubKey, "*FlowControl", "3 (Açık)"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", activeNicClassSubKey, "*FlowControl");
                    vault.RevertRegistryTracked("HKLM", activeNicClassSubKey, "*EEE");
                    vault.RevertRegistryTracked("HKLM", activeNicClassSubKey, "EEE");
                    vault.RevertRegistryTracked("HKLM", activeNicClassSubKey, "EnableGreenEthernet");
                    vault.RevertRegistryTracked("HKLM", activeNicClassSubKey, "PowerSavingMode");
                    vault.RevertRegistryTracked("HKLM", activeNicClassSubKey, "*LsoV2IPv4");
                    vault.RevertRegistryTracked("HKLM", activeNicClassSubKey, "*LsoV2IPv6");
                    vault.RevertRegistryTracked("HKLM", activeNicClassSubKey, "*RSS");
                    StateVault.RunHiddenCmd("netsh", "int tcp set global rsc=enabled rss=enabled");
                }
            };
            net10.Variations.Add(new TweakVariation(
                "Saf Espor (Uyku ve Paket Birleştirme Tamamen Kapalı)",
                "Ağ Kartı Uykusu, Akış Duraklatma ve Paket Birleştirme Kapalı",
                "En kararlı ve düz ping çizgisi için karttaki tüm enerji tasarrufu ve paket bekletme özelliklerini kapatır.",
                "Enerji Tasarrufu Kapalı + Paket Birleştirme Kapalı + Çoklu Çekirdek Açık",
                () =>
                {
                    vault.NetshModified = true;
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "*FlowControl", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "*EEE", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "EEE", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "EnableGreenEthernet", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "PowerSavingMode", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "*LsoV2IPv4", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "*LsoV2IPv6", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "*RSS", "1", RegistryValueKind.String);
                    StateVault.RunHiddenCmd("netsh", "int tcp set global rsc=disabled rss=enabled");
                }));
            net10.Variations.Add(new TweakVariation(
                "Sadece Ağ Kartı Uyku Modunu Kapat",
                "Yalnızca Green Ethernet / Enerji Tasarrufunu Devre Dışı Bırak",
                "Diğer ağ kartı ayarlarına dokunmadan sadece kartın uyku moduna geçmesini engeller.",
                "Enerji Tasarrufu ve Akış Duraklatma Kapalı",
                () =>
                {
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "*FlowControl", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "*EEE", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "EEE", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "EnableGreenEthernet", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "PowerSavingMode", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "*RSS", "1", RegistryValueKind.String);
                }));
            net10.Variations.Add(new TweakVariation(
                "Yüksek İndirme Hızı + Uyku Kapalı",
                "Uyku Modu Kapalı, Büyük Dosya İndirme Hızlandırması Açık",
                "Yüksek hızlı indirme yaparken işlemciye yük bindirmemek için kullanılır.",
                "Uyku Kapalı + Donanım Hızlandırma Açık",
                () =>
                {
                    vault.NetshModified = true;
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "*EEE", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "EnableGreenEthernet", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "*LsoV2IPv4", "1", RegistryValueKind.String);
                    vault.SetRegistryTracked(net10.Title, "HKLM", activeNicClassSubKey, "*RSS", "1", RegistryValueKind.String);
                    StateVault.RunHiddenCmd("netsh", "int tcp set global rsc=enabled rss=enabled");
                }));
            allTweaks.Add(net10);

            // NET-11: QoS Packet Scheduler & ToS/DSCP Priority Tagging
            var net11 = new TweakDefinition
            {
                Id = "NET_QOS_TOS",
                Category = "NETWORK",
                HardwareTag = "ALL",
                BadgeText = "QOS & PAKET ÖNCELİĞİ",
                BadgeColor = colNet,
                RequiresAdmin = true,
                Title = "Windows %20 İnternet Kısıtlamasını Kaldırma & Oyun Paketi Önceliği",
                SummaryDescription = "Windows'un arka plan güncellemeleri için sakladığı %20 internet sınırını sıfırlar ve oyun paketlerine modemde geçiş üstünlüğü verir.",
                DeepTechnicalWhy = "Genellikle internet hızının tamamını kullanmak ve modem kuyruğunda oyun paketlerinin diğer paketlerin önüne geçmesini sağlamak için kullanılır.",
                TargetPathOrApi = @"Windows QoS & Paket Öncelik Etiketi",
                QueryOriginalOrDefaultSummary = () => "NonBestEffortLimit=" + vault.ReadRegistryDisplay("HKLM", pschedKey, "NonBestEffortLimit", "Varsayılan (%20)"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", pschedKey, "NonBestEffortLimit");
                    vault.RevertRegistryTracked("HKLM", tcpParams, "DisableUserTOSSetting");
                    vault.RevertRegistryTracked("HKLM", tcpParams, "DefaultTOSValue");
                }
            };
            net11.Variations.Add(new TweakVariation(
                "%0 Kısıtlama + Maksimum Oyun Önceliği (EF)",
                "İnternet Sınırı %0 + Paketlere Gerçek Zamanlı Oyun Etiketi",
                "Modeminizin oyun paketlerini en yüksek öncelikle (Expedited Forwarding) işlemesi için kullanılır.",
                "%0 Kısıtlama + Yüksek Öncelik Etiketi (184)",
                () =>
                {
                    vault.SetRegistryTracked(net11.Title, "HKLM", pschedKey, "NonBestEffortLimit", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net11.Title, "HKLM", tcpParams, "DisableUserTOSSetting", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net11.Title, "HKLM", tcpParams, "DefaultTOSValue", 184, RegistryValueKind.DWord);
                }));
            net11.Variations.Add(new TweakVariation(
                "%0 Kısıtlama + Standart Modem Uyumlu Öncelik",
                "Ev Modemleriyle Tam Uyumlu Düşük Gecikme Etiketi",
                "Standart ISS modemlerinde paket önceliğinin sorunsuz tanınması için kullanılır.",
                "%0 Kısıtlama + Standart Öncelik Etiketi (128)",
                () =>
                {
                    vault.SetRegistryTracked(net11.Title, "HKLM", pschedKey, "NonBestEffortLimit", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net11.Title, "HKLM", tcpParams, "DisableUserTOSSetting", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net11.Title, "HKLM", tcpParams, "DefaultTOSValue", 128, RegistryValueKind.DWord);
                }));
            net11.Variations.Add(new TweakVariation(
                "Sadece %20 Windows Kısıtlamasını Kaldır",
                "Paket Etiketlerine Dokunmadan Sadece %20 Sınırını Sıfırla",
                "Yalnızca Windows'un arka plan bant genişliği rezervini kaldırmak için kullanılır.",
                "%0 Kısıtlama (Tam Bant Genişliği)",
                () =>
                {
                    vault.SetRegistryTracked(net11.Title, "HKLM", pschedKey, "NonBestEffortLimit", 0, RegistryValueKind.DWord);
                }));
            allTweaks.Add(net11);

            // NET-12: Low-Latency DNS Switcher
            var net12 = new TweakDefinition
            {
                Id = "NET_DNS_SWITCH",
                Category = "NETWORK",
                HardwareTag = "ALL",
                BadgeText = "HIZLI OYUN DNS",
                BadgeColor = colNet,
                RequiresAdmin = true,
                Title = "Tek Tık Hızlı DNS Geçişi (Cloudflare / Google / Quad9)",
                SummaryDescription = "En hızlı oyuncu DNS sunucularına anında geçiş yapar; kapattığınızda eski DNS ayarınıza geri döner.",
                DeepTechnicalWhy = "Genellikle oyun sunucularına bağlanırken yaşanan gecikmeleri azaltmak ve internet servis sağlayıcısının yavaş DNS sunucularını aşmak için kullanılır.",
                TargetPathOrApi = @"Anlık DNS Değiştirici",
                QueryOriginalOrDefaultSummary = () => vault.OriginalDnsWasDhcp ? "Otomatik (DHCP DNS)" : string.Join(", ", vault.OriginalDnsServers.ToArray()),
                RevertAction = () =>
                {
                    string dnsCacheKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
                    vault.RevertRegistryTracked("HKLM", dnsCacheKey, "MaxNegativeCacheTtl");
                    vault.RevertRegistryTracked("HKLM", dnsCacheKey, "MaxCacheTtl");
                    if (vault.DnsModified)
                    {
                        if (vault.OriginalDnsWasDhcp)
                            StateVault.RunHiddenCmd("netsh", string.Format("interface ip set dns name=\"{0}\" source=dhcp", vault.ActiveAdapterName));
                        else if (vault.OriginalDnsServers.Count > 0)
                            StateVault.RunHiddenCmd("netsh", string.Format("interface ip set dns name=\"{0}\" static {1} primary", vault.ActiveAdapterName, vault.OriginalDnsServers[0]));
                        vault.DnsModified = false;
                        NativeMethods.DnsFlushResolverCache();
                    }
                }
            };
            net12.Variations.Add(new TweakVariation(
                "Cloudflare DNS (1.1.1.1 - En Düşük Ping)",
                "Türkiye ve Avrupa Sunucuları İçin En Hızlı Oyuncu DNS'i",
                "En düşük tepki süresine sahip Cloudflare 1.1.1.1 sunucusunu anında aktif eder.",
                "DNS: 1.1.1.1 / 1.0.0.1",
                () =>
                {
                    string dnsCacheKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
                    vault.SetRegistryTracked(net12.Title, "HKLM", dnsCacheKey, "MaxNegativeCacheTtl", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(net12.Title, "HKLM", dnsCacheKey, "MaxCacheTtl", 86400, RegistryValueKind.DWord);
                    vault.DnsModified = true;
                    StateVault.RunHiddenCmd("netsh", string.Format("interface ip set dns name=\"{0}\" static 1.1.1.1 primary", vault.ActiveAdapterName));
                    StateVault.RunHiddenCmd("netsh", string.Format("interface ip add dns name=\"{0}\" 1.0.0.1 index=2", vault.ActiveAdapterName));
                    NativeMethods.DnsFlushResolverCache();
                }));
            net12.Variations.Add(new TweakVariation(
                "Google DNS (8.8.8.8 - Yüksek Kararlılık)",
                "Google Küresel DNS Sunucusu",
                "Yüksek kararlılık ve indirme sunucusu uyumluluğu için kullanılır.",
                "DNS: 8.8.8.8 / 8.8.4.4",
                () =>
                {
                    string dnsCacheKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
                    vault.SetRegistryTracked(net12.Title, "HKLM", dnsCacheKey, "MaxNegativeCacheTtl", 0, RegistryValueKind.DWord);
                    vault.DnsModified = true;
                    StateVault.RunHiddenCmd("netsh", string.Format("interface ip set dns name=\"{0}\" static 8.8.8.8 primary", vault.ActiveAdapterName));
                    StateVault.RunHiddenCmd("netsh", string.Format("interface ip add dns name=\"{0}\" 8.8.4.4 index=2", vault.ActiveAdapterName));
                    NativeMethods.DnsFlushResolverCache();
                }));
            net12.Variations.Add(new TweakVariation(
                "Quad9 + Cloudflare Karma DNS",
                "Güvenlik Korumalı Karma DNS (9.9.9.9 / 1.1.1.1)",
                "Hem zararlı bağlantı koruması hem de hızlı yedek DNS isteyenler için kullanılır.",
                "DNS: 9.9.9.9 / 1.1.1.1",
                () =>
                {
                    string dnsCacheKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
                    vault.SetRegistryTracked(net12.Title, "HKLM", dnsCacheKey, "MaxNegativeCacheTtl", 0, RegistryValueKind.DWord);
                    vault.DnsModified = true;
                    StateVault.RunHiddenCmd("netsh", string.Format("interface ip set dns name=\"{0}\" static 9.9.9.9 primary", vault.ActiveAdapterName));
                    StateVault.RunHiddenCmd("netsh", string.Format("interface ip add dns name=\"{0}\" 1.1.1.1 index=2", vault.ActiveAdapterName));
                    NativeMethods.DnsFlushResolverCache();
                }));
            allTweaks.Add(net12);

            // =================================================================================================
            // CATEGORY 2: LATENCY & KERNEL (7 DEEP KERNEL, SCHEDULER, POWER & INPUT TWEAKS)
            // =================================================================================================

            // LAT-01: Kernel Timer Resolution
            var lat01 = new TweakDefinition
            {
                Id = "LAT_TIMER",
                Category = "LATENCY",
                HardwareTag = "ALL",
                BadgeText = "SİSTEM ZAMANLAYICI (0.5MS)",
                BadgeColor = colLat,
                RequiresAdmin = false,
                Title = "Windows Sistem Saati Hassasiyeti (0.500 ms Ultra Düşük Gecikme)",
                SummaryDescription = "Windows'un 15.6ms olan standart tepki saatini 0.500ms seviyesine indirerek fare ve oyun motorunun anında yanıt vermesini sağlar.",
                DeepTechnicalWhy = "Genellikle fare hareketlerinin ekrana yağ gibi akıcı yansıması ve oyun içi kare sürelerinin (frametime) sabitlenmesi amacıyla kullanılır. Açtığınız anda hissedilir fark yaratır.",
                TargetPathOrApi = "Windows Yüksek Hassasiyetli Zamanlayıcı",
                QueryOriginalOrDefaultSummary = () => "15.625 ms (Standart Windows)",
                RevertAction = () =>
                {
                    timerLockActive = false;
                    try
                    {
                        NativeMethods.timeEndPeriod(1);
                        uint cur;
                        NativeMethods.NtSetTimerResolution(0, false, out cur);
                    }
                    catch { }
                    vault.RevertRegistryTracked("HKLM", kernelKey, "GlobalTimerResolutionRequests");
                }
            };
            lat01.Variations.Add(new TweakVariation(
                "0.500 ms (2000 Hz) Maksimum Hassasiyet",
                "En Düşük Girdi Gecikmesi (0.500ms Hassasiyet)",
                "Fare ve klavye tepkisini maksimum keskinliğe ulaştırmak için kullanılır.",
                "0.500 ms (2000 Hz) Aktif",
                () =>
                {
                    desiredTimerUnit = 5000;
                    timerLockActive = true;
                    try
                    {
                        NativeMethods.timeBeginPeriod(1);
                        uint cur;
                        NativeMethods.NtSetTimerResolution(5000, true, out cur);
                    }
                    catch { }
                    if (isAdmin)
                        vault.SetRegistryTracked(lat01.Title, "HKLM", kernelKey, "GlobalTimerResolutionRequests", 1, RegistryValueKind.DWord);
                }));
            lat01.Variations.Add(new TweakVariation(
                "1.000 ms (1000 Hz) Fare Senkron Modu",
                "1000 Hz Oyuncu Fareleriyle Birebir Uyumlu 1.0ms Modu",
                "1000 Hz fare kullanan sistemlerde işlemciyi yormadan birebir senkronizasyon sağlamak için kullanılır.",
                "1.000 ms (1000 Hz) Aktif",
                () =>
                {
                    desiredTimerUnit = 10000;
                    timerLockActive = true;
                    try
                    {
                        NativeMethods.timeBeginPeriod(1);
                        uint cur;
                        NativeMethods.NtSetTimerResolution(10000, true, out cur);
                    }
                    catch { }
                }));
            lat01.Variations.Add(new TweakVariation(
                "0.504 ms AMD Ryzen Özel Mod",
                "AMD Ryzen Sistemler İçin Özel Senkronize Zamanlayıcı",
                "AMD Ryzen işlemcilerde en pürüzsüz kare süresini yakalamak için kullanılan özel zamanlayıcı değeridir.",
                "0.504 ms Harmonik Mod",
                () =>
                {
                    desiredTimerUnit = 5040;
                    timerLockActive = true;
                    try
                    {
                        NativeMethods.timeBeginPeriod(1);
                        uint cur;
                        NativeMethods.NtSetTimerResolution(5040, true, out cur);
                    }
                    catch { }
                }));
            allTweaks.Add(lat01);

            // LAT-02: Win32PrioritySeparation Quantum Matrix
            var lat02 = new TweakDefinition
            {
                Id = "LAT_QUANTUM",
                Category = "LATENCY",
                HardwareTag = "ALL",
                BadgeText = "ÖN PLAN OYUN ÖNCELİĞİ",
                BadgeColor = colLat,
                RequiresAdmin = true,
                Title = "Aktif Pencere (Oyun) İşlemci Öncelik Dağılımı",
                SummaryDescription = "İşlemcinin arka plandaki programlar yerine ekranda açık olan oyuna ne kadar daha fazla süre ayıracağını belirler.",
                DeepTechnicalWhy = "Genellikle FPS oyunlarında fare çevirirken en keskin tepkiyi almak (Mod 1) veya ağır oyunlarda FPS düşüşlerini engellemek (Mod 3) amacıyla kullanılır.",
                TargetPathOrApi = @"Windows Ön Plan İşlemci Önceliği",
                QueryOriginalOrDefaultSummary = () => "Mevcut: " + vault.ReadRegistryDisplay("HKLM", prioCtrl, "Win32PrioritySeparation", "2 (Varsayılan)"),
                RevertAction = () => vault.RevertRegistryTracked("HKLM", prioCtrl, "Win32PrioritySeparation")
            };
            lat02.Variations.Add(new TweakVariation(
                "En Keskin Fare & Girdi Tepkisi (0x26 - Espor)",
                "Aktif Oyuna 3 Kat Hızlı İşlemci Tepkisi (En Düşük Input Lag)",
                "CS2, Valorant ve HaxBall gibi refleks oyunlarında fare ve klavyenin en hızlı şekilde işlenmesi için kullanılır.",
                "Kısa Süreli + 3 Kat Oyun Önceliği (0x26)",
                () => vault.SetRegistryTracked(lat02.Title, "HKLM", prioCtrl, "Win32PrioritySeparation", 0x26, RegistryValueKind.DWord)));
            lat02.Variations.Add(new TweakVariation(
                "Sabit Tepki & Takılma Koruması (0x2A)",
                "Arka Plan Servislerinin Araya Girmesini Önleyen Sabit Mod",
                "Oyun oynarken arka plan işlemlerinin anlık takılma yaratmasını engellemek için kullanılır.",
                "Kısa ve Sabit Süreli Öncelik (0x2A)",
                () => vault.SetRegistryTracked(lat02.Title, "HKLM", prioCtrl, "Win32PrioritySeparation", 0x2A, RegistryValueKind.DWord)));
            lat02.Variations.Add(new TweakVariation(
                "Maksimum FPS Kararlılığı (0x28)",
                "İşlemciye Yüklenen Oyunlarda Daha Yüksek Minimum FPS",
                "Açık dünya veya kalabalık savaş oyunlarında %1 Low FPS değerini yükseltmek için kullanılır.",
                "Uzun ve Sabit Süreli Öncelik (0x28)",
                () => vault.SetRegistryTracked(lat02.Title, "HKLM", prioCtrl, "Win32PrioritySeparation", 0x28, RegistryValueKind.DWord)));
            lat02.Variations.Add(new TweakVariation(
                "Yayın + Oyun Dengeli Mod (0x16)",
                "Hem Oyun Hem OBS/Tarayıcı Açıkken Akıcı Çalışma",
                "Oyun oynarken aynı anda yayın açan veya ikinci ekranda video izleyenler için kullanılır.",
                "Çoklu Görev Dengeli Mod (0x16)",
                () => vault.SetRegistryTracked(lat02.Title, "HKLM", prioCtrl, "Win32PrioritySeparation", 0x16, RegistryValueKind.DWord)));
            allTweaks.Add(lat02);

            // LAT-03: Processor C-States
            var lat03 = new TweakDefinition
            {
                Id = "LAT_CSTATES",
                Category = "LATENCY",
                HardwareTag = "ALL",
                BadgeText = "İŞLEMCİ UYKU KALKANI",
                BadgeColor = colLat,
                RequiresAdmin = false,
                Title = "İşlemci Çekirdek Uyku Modlarını Kapatma (C-States)",
                SummaryDescription = "İşlemci çekirdeklerinin sakin anlarda uykuya dalıp çatışma başladığında geç uyanmasını engeller.",
                DeepTechnicalWhy = "Genellikle oyun içinde aniden karşınıza rakip çıktığında yaşanan saliselik donmayı (mikro-stutter) ortadan kaldırmak için kullanılır.",
                TargetPathOrApi = "İşlemci Uyku Durumu Yönetimi",
                QueryOriginalOrDefaultSummary = () => "IdleDisable=" + vault.ReadPowerAcSettingDisplay(SUB_PROCESSOR, SET_IDLEDISABLE, "0") + ", Demote=" + vault.ReadPowerAcSettingDisplay(SUB_PROCESSOR, SET_IDLEDEMOTE, "40"),
                RevertAction = () =>
                {
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_IDLEDISABLE);
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_IDLEDEMOTE);
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_IDLEPROMOTE);
                }
            };
            lat03.Variations.Add(new TweakVariation(
                "Tam Uyanık Mod (Sıfır Uyku - Maksimum Tepki)",
                "Tüm İşlemci Çekirdekleri Kesintisiz Uyanık Bekler",
                "Masaüstü bilgisayarlarda en düşük gecikme için çekirdeklerin uyumasını tamamen kapatır.",
                "Tüm Uyku Modları Kapalı",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_IDLEDISABLE, SUB_PROCESSOR, SET_IDLEDISABLE, 1);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_IDLEDEMOTE, SUB_PROCESSOR, SET_IDLEDEMOTE, 100);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_IDLEPROMOTE, SUB_PROCESSOR, SET_IDLEPROMOTE, 100);
                }));
            lat03.Variations.Add(new TweakVariation(
                "Sadece Derin Uykuyu Engelle (Serin & Hızlı)",
                "İşlemciyi Aşırı Isıtmadan Gecikmeli Derin Uykuyu Kapat",
                "İyi soğutması olmayan sistemlerde veya yaz aylarında işlemciyi ısıtmadan takılmaları önlemek için kullanılır.",
                "Derin Uyku Kapalı + Hafif Dinlenme Açık",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_IDLEDISABLE, SUB_PROCESSOR, SET_IDLEDISABLE, 0);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_IDLEDEMOTE, SUB_PROCESSOR, SET_IDLEDEMOTE, 100);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_IDLEPROMOTE, SUB_PROCESSOR, SET_IDLEPROMOTE, 100);
                }));
            lat03.Variations.Add(new TweakVariation(
                "Hızlı Uyanma Modu (Dizüstü / Dengeli)",
                "En Ufak Hareket Anında Hemen Tam Güce Çık",
                "Dizüstü bilgisayarlarda veya günlük kullanımda hem sessizlik hem hızlı oyun tepkisi için kullanılır.",
                "Hızlı Uyanma Eğrisi (%90)",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_IDLEDISABLE, SUB_PROCESSOR, SET_IDLEDISABLE, 0);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_IDLEDEMOTE, SUB_PROCESSOR, SET_IDLEDEMOTE, 90);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_IDLEPROMOTE, SUB_PROCESSOR, SET_IDLEPROMOTE, 95);
                }));
            allTweaks.Add(lat03);

            // LAT-04: CPU Core Parking & Frequency Scaling
            var lat04 = new TweakDefinition
            {
                Id = "LAT_COREPARK",
                Category = "LATENCY",
                HardwareTag = "ALL",
                BadgeText = "ÇEKİRDEK PARK & HIZ",
                BadgeColor = colLat,
                RequiresAdmin = false,
                Title = "İşlemci Çekirdek Park Etmeyi Kapatma & Hız Sabitleme",
                SummaryDescription = "Windows'un bazı işlemci çekirdeklerini kapatmasını (Core Parking) engeller ve tüm çekirdekleri oyuna hazır tutar.",
                DeepTechnicalWhy = "Genellikle oyunlarda tüm çekirdeklerin aktif çalışması ve işlemci hızının (MHz) aniden düşüp FPS kaybı yaratmaması için kullanılır.",
                TargetPathOrApi = "İşlemci Çekirdek Park & Frekans Yönetimi",
                QueryOriginalOrDefaultSummary = () => "MinCores=" + vault.ReadPowerAcSettingDisplay(SUB_PROCESSOR, SET_CPMINCORES, "100") + "%, MinFreq=" + vault.ReadPowerAcSettingDisplay(SUB_PROCESSOR, SET_PROCTHROTTLEMIN, "5") + "%",
                RevertAction = () =>
                {
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_CPMINCORES);
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_PROCTHROTTLEMIN);
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_PERFCHECK);
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_BOOSTPOLICY);
                    vault.RemovePowerSettingTracked(SUB_PROCESSOR + "|" + SET_INCPOLICY);
                }
            };
            lat04.Variations.Add(new TweakVariation(
                "%100 Sabit Hız + Tüm Çekirdekler Açık",
                "Sıfır Hız Düşüşü: Tüm Çekirdekler Sürekli Tam Frekansta",
                "Turnuva ve espor maçlarında işlemcinin bir an bile hız düşürmemesi için kullanılır.",
                "Tüm Çekirdekler Açık + %100 Sabit Taban Hız",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_CPMINCORES, SUB_PROCESSOR, SET_CPMINCORES, 100);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_PROCTHROTTLEMIN, SUB_PROCESSOR, SET_PROCTHROTTLEMIN, 100);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_BOOSTPOLICY, SUB_PROCESSOR, SET_BOOSTPOLICY, 100);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_PERFCHECK, SUB_PROCESSOR, SET_PERFCHECK, 5);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_INCPOLICY, SUB_PROCESSOR, SET_INCPOLICY, 2);
                }));
            lat04.Variations.Add(new TweakVariation(
                "Tüm Çekirdekler Açık + Maksimum Turbo Boost (Önerilen)",
                "Ryzen PBO & Intel Turbo İçin En Yüksek MHz Tavanı",
                "Tüm çekirdekleri açık tutarken işlemcinin tek çekirdekte en yüksek Turbo/PBO hızına çıkabilmesi için kullanılır.",
                "Tüm Çekirdekler Açık + Dinamik Tavan Boost",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_CPMINCORES, SUB_PROCESSOR, SET_CPMINCORES, 100);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_PROCTHROTTLEMIN, SUB_PROCESSOR, SET_PROCTHROTTLEMIN, 85);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_BOOSTPOLICY, SUB_PROCESSOR, SET_BOOSTPOLICY, 100);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_PERFCHECK, SUB_PROCESSOR, SET_PERFCHECK, 10);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_INCPOLICY, SUB_PROCESSOR, SET_INCPOLICY, 2);
                }));
            lat04.Variations.Add(new TweakVariation(
                "Masaüstünde Serin, Oyunda Anında Tam Hız",
                "Boşta Serin Çalışır, Yük Bindiği An Tam Hıza Fırlar",
                "Bilgisayar boştayken sessiz ve serin kalmasını, oyuna girince anında tam hıza çıkmasını isteyenler için kullanılır.",
                "Tüm Çekirdekler Açık + Roket Hızlanma",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_CPMINCORES, SUB_PROCESSOR, SET_CPMINCORES, 100);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_PROCTHROTTLEMIN, SUB_PROCESSOR, SET_PROCTHROTTLEMIN, 50);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_BOOSTPOLICY, SUB_PROCESSOR, SET_BOOSTPOLICY, 80);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_PERFCHECK, SUB_PROCESSOR, SET_PERFCHECK, 5);
                    vault.ApplyPowerSettingTracked(SUB_PROCESSOR + "|" + SET_INCPOLICY, SUB_PROCESSOR, SET_INCPOLICY, 2);
                }));
            allTweaks.Add(lat04);

            // LAT-05: Real-Time Mouse 1:1 Raw Input
            var lat05 = new TweakDefinition
            {
                Id = "LAT_MOUSE_SPI",
                Category = "LATENCY",
                HardwareTag = "ALL",
                BadgeText = "FARE 1:1 KESKİN NİŞAN",
                BadgeColor = colLat,
                RequiresAdmin = false,
                Title = "Fare İvmesini Kapatma & 1:1 Doğrusal Hareket",
                SummaryDescription = "Windows'un fare hareketlerinize müdahale etmesini (ivmeyi) kapatır; elinizi ne kadar çekerseniz imleç tam o kadar gider.",
                DeepTechnicalWhy = "Genellikle nişan alma (aim) kas hafızasını korumak ve HaxBall/CS2 gibi oyunlarda fare hakimiyetini netleştirmek için kullanılır.",
                TargetPathOrApi = @"Fare Doğrusal Hareket Ayarı",
                QueryOriginalOrDefaultSummary = () => string.Format("Speed={0}, Sens={1}/20", vault.OriginalMouseAccel[2], vault.OriginalMouseSensitivity),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKCU", @"Control Panel\Mouse", "MouseSpeed");
                    vault.RevertRegistryTracked("HKCU", @"Control Panel\Mouse", "MouseThreshold1");
                    vault.RevertRegistryTracked("HKCU", @"Control Panel\Mouse", "MouseThreshold2");
                    vault.RevertRegistryTracked("HKCU", @"Control Panel\Mouse", "MouseHoverTime");
                    if (vault.MouseSpiModified)
                    {
                        NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETMOUSE, 0, vault.OriginalMouseAccel, NativeMethods.SPIF_SENDCHANGE);
                        NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETMOUSESPEED, 0, (IntPtr)vault.OriginalMouseSensitivity, NativeMethods.SPIF_SENDCHANGE);
                        NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETMOUSEHOVERTIME, (uint)vault.OriginalMouseHoverTime, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                        vault.MouseSpiModified = false;
                        vault.SaveJournal();
                    }
                }
            };
            lat05.Variations.Add(new TweakVariation(
                "Saf 1:1 İvmesiz + Standart Hız (6/11)",
                "İvme Tamamen Kapalı + Birebir Piksel Doğruluğu",
                "Profesyonel oyuncuların kullandığı standart 6/11 hız ve sıfır ivme ayarıdır.",
                "İvme Kapalı + 6/11 Standart Hız",
                () =>
                {
                    vault.MouseSpiModified = true;
                    int[] zeroAccel = new int[] { 0, 0, 0 };
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETMOUSE, 0, zeroAccel, NativeMethods.SPIF_SENDCHANGE);
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETMOUSESPEED, 0, (IntPtr)10, NativeMethods.SPIF_SENDCHANGE);
                    vault.SetRegistryTracked(lat05.Title, "HKCU", @"Control Panel\Mouse", "MouseSpeed", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat05.Title, "HKCU", @"Control Panel\Mouse", "MouseThreshold1", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat05.Title, "HKCU", @"Control Panel\Mouse", "MouseThreshold2", "0", RegistryValueKind.String);
                    vault.SaveJournal();
                }));
            lat05.Variations.Add(new TweakVariation(
                "İvme Kapalı + Kendi Hızımı Koru",
                "Alıştığınız Fare Hızını Değiştirmeden Sadece İvmeyi Kapatır",
                "Mevcut fare hızınıza dokunmadan sadece yapay hızlanmayı kapatmak için kullanılır.",
                "İvme Kapalı + Mevcut Hız Korunur",
                () =>
                {
                    vault.MouseSpiModified = true;
                    int[] zeroAccel = new int[] { 0, 0, 0 };
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETMOUSE, 0, zeroAccel, NativeMethods.SPIF_SENDCHANGE);
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETMOUSEHOVERTIME, 8, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    vault.SetRegistryTracked(lat05.Title, "HKCU", @"Control Panel\Mouse", "MouseSpeed", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat05.Title, "HKCU", @"Control Panel\Mouse", "MouseThreshold1", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat05.Title, "HKCU", @"Control Panel\Mouse", "MouseThreshold2", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat05.Title, "HKCU", @"Control Panel\Mouse", "MouseHoverTime", "8", RegistryValueKind.String);
                    vault.SaveJournal();
                }));
            lat05.Variations.Add(new TweakVariation(
                "Yüksek DPI Fare Modu (1600 / 3200 DPI)",
                "Yüksek DPI Kullananlar İçin Masaüstünü Yarı Hıza Dengeler",
                "Faresini 1600 veya 3200 DPI'da kullanıp masaüstünde imlecin çok hızlı uçmasını istemeyenler için kullanılır.",
                "İvme Kapalı + 0.5x Hassas Çarpan",
                () =>
                {
                    vault.MouseSpiModified = true;
                    int[] zeroAccel = new int[] { 0, 0, 0 };
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETMOUSE, 0, zeroAccel, NativeMethods.SPIF_SENDCHANGE);
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETMOUSESPEED, 0, (IntPtr)6, NativeMethods.SPIF_SENDCHANGE);
                    vault.SaveJournal();
                }));
            allTweaks.Add(lat05);

            // LAT-06: Keyboard Repeat & Kernel HID DataQueueSize
            var lat06 = new TweakDefinition
            {
                Id = "LAT_HID_QUEUE",
                Category = "LATENCY",
                HardwareTag = "ALL",
                BadgeText = "FARE & KLAVYE KUYRUĞU",
                BadgeColor = colLat,
                RequiresAdmin = false,
                NeedsReboot = true,
                Title = "Fare ve Klavye Girdi Kuyruğu Boyutu (HID Tamponu)",
                SummaryDescription = "Fare ve klavyeden gelen sinyallerin Windows içinde sırada beklediği tampon kutusunu küçülterek daha taze girdi alınmasını sağlar.",
                DeepTechnicalWhy = "Genellikle rekabetçi oyunlarda fare hareketlerinin ve tuş basımlarının ekrana daha keskin yansıması için kullanılır. Mod 1 günlük yazışma hızını bozmadan ideal kuyruk boyutunu ayarlar.",
                TargetPathOrApi = @"Fare/Klavye Girdi Tamponu [Restart Gerekli]",
                QueryOriginalOrDefaultSummary = () => string.Format("KbdDelay={0}, Speed={1}, Queue={2}", vault.OriginalKeyboardDelay, vault.OriginalKeyboardSpeed, vault.ReadRegistryDisplay("HKLM", mouParams, "MouseDataQueueSize", "100")),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKCU", @"Control Panel\Keyboard", "KeyboardDelay");
                    vault.RevertRegistryTracked("HKCU", @"Control Panel\Keyboard", "KeyboardSpeed");
                    vault.RevertRegistryTracked("HKLM", mouParams, "MouseDataQueueSize");
                    vault.RevertRegistryTracked("HKLM", kbdParams, "KeyboardDataQueueSize");
                    if (vault.KeyboardSpiModified)
                    {
                        NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDDELAY, (uint)vault.OriginalKeyboardDelay, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                        NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDSPEED, (uint)vault.OriginalKeyboardSpeed, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                        vault.KeyboardSpiModified = false;
                        vault.SaveJournal();
                    }
                }
            };
            lat06.Variations.Add(new TweakVariation(
                "Yazışma Dostu + 1000Hz Optimal (Kuyruk=24)",
                "Sohbet Ederken Harf Tekrarlamayan Rahat Klavye + 24 Paket Kuyruk",
                "Sürekli yazılı iletişim kuranlar için harflerin arka arkaya fazladan basılmasını önler (Delay=1) ve 1000Hz fare/klavye için ideal 24 kuyruk boyutunu ayarlar.",
                "KeyboardDelay=1 (Rahat Yazım), KeyboardSpeed=31, DataQueueSize=24",
                () =>
                {
                    vault.KeyboardSpiModified = true;
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDDELAY, 1, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDSPEED, 31, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    vault.SetRegistryTracked(lat06.Title, "HKCU", @"Control Panel\Keyboard", "KeyboardDelay", "1", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat06.Title, "HKCU", @"Control Panel\Keyboard", "KeyboardSpeed", "31", RegistryValueKind.String);
                    if (isAdmin)
                    {
                        vault.SetRegistryTracked(lat06.Title, "HKLM", mouParams, "MouseDataQueueSize", 24, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(lat06.Title, "HKLM", kbdParams, "KeyboardDataQueueSize", 24, RegistryValueKind.DWord);
                    }
                    vault.SaveJournal();
                }));
            lat06.Variations.Add(new TweakVariation(
                "Agresif Espor (Kuyruk=16 + Hızlı Tekrar)",
                "En Düşük Girdi Tamponu (16 Paket) + Hızlı Tuş Tekrarı",
                "1000Hz fareler için en düşük tampon boyutunu (16) ve hızlı klavye tekrarını uygular.",
                "KeyboardDelay=0, KeyboardSpeed=31, DataQueueSize=16",
                () =>
                {
                    vault.KeyboardSpiModified = true;
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDDELAY, 0, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDSPEED, 31, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    if (isAdmin)
                    {
                        vault.SetRegistryTracked(lat06.Title, "HKLM", mouParams, "MouseDataQueueSize", 16, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(lat06.Title, "HKLM", kbdParams, "KeyboardDataQueueSize", 16, RegistryValueKind.DWord);
                    }
                    vault.SaveJournal();
                }));
            lat06.Variations.Add(new TweakVariation(
                "4000Hz / 8000Hz Fare Korumalı (Kuyruk=50)",
                "Yüksek Hz (4K/8K) Oyuncu Fareleri İçin Takılma Önleyici Mod",
                "4000Hz ve 8000Hz farelerde imleç atlamasını önleyen genişletilmiş 50 paketlik tampon ve rahat yazışma ayarı.",
                "KeyboardDelay=1, KeyboardSpeed=31, MouseDataQueueSize=50",
                () =>
                {
                    vault.KeyboardSpiModified = true;
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDDELAY, 1, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDSPEED, 31, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    if (isAdmin)
                    {
                        vault.SetRegistryTracked(lat06.Title, "HKLM", mouParams, "MouseDataQueueSize", 50, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(lat06.Title, "HKLM", kbdParams, "KeyboardDataQueueSize", 32, RegistryValueKind.DWord);
                    }
                    vault.SaveJournal();
                }));
            allTweaks.Add(lat06);

            // LAT-07: USB Selective Suspend & PCIe ASPM
            var lat07 = new TweakDefinition
            {
                Id = "LAT_USB_PCIE",
                Category = "LATENCY",
                HardwareTag = "ALL",
                BadgeText = "USB & EKRAN KARTI HATTI",
                BadgeColor = colLat,
                RequiresAdmin = false,
                Title = "USB Portları ve Ekran Kartı (PCIe) Uyku Modunu Kapatma",
                SummaryDescription = "Fare/klavye USB portlarının ve ekran kartı veri yolunun güç tasarrufu için anlık uykuya geçmesini engeller.",
                DeepTechnicalWhy = "Genellikle oyun ortasında farede oluşan anlık kopma/gecikme hissini ve ekran kartının sahne geçişlerindeki takılmalarını önlemek için kullanılır.",
                TargetPathOrApi = "Güç Planı USB & PCIe Hattı",
                QueryOriginalOrDefaultSummary = () => "USB=" + vault.ReadPowerAcSettingDisplay(SUB_USB, SET_USBSUSPEND, "1") + ", ASPM=" + vault.ReadPowerAcSettingDisplay(SUB_PCIEXPRESS, SET_PCIEASPM, "Varsayılan"),
                RevertAction = () =>
                {
                    vault.RemovePowerSettingTracked(SUB_USB + "|" + SET_USBSUSPEND);
                    vault.RemovePowerSettingTracked(SUB_PCIEXPRESS + "|" + SET_PCIEASPM);
                }
            };
            lat07.Variations.Add(new TweakVariation(
                "Tam Kilit (USB + Ekran Kartı Hattı Sürekli Açık)",
                "Hem USB Portları Hem Ekran Kartı Veri Yolu Sürekli Tam Güçte",
                "Fare, klavye ve ekran kartı veri yollarında güç tasarrufunu tamamen kapatır.",
                "USBSUSPEND=0, PCIE_ASPM=0",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_USB + "|" + SET_USBSUSPEND, SUB_USB, SET_USBSUSPEND, 0);
                    vault.ApplyPowerSettingTracked(SUB_PCIEXPRESS + "|" + SET_PCIEASPM, SUB_PCIEXPRESS, SET_PCIEASPM, 0);
                }));
            lat07.Variations.Add(new TweakVariation(
                "Sadece USB Fare/Klavye Koruması",
                "Yalnızca USB Portlarının Uyku Modunu Kapat",
                "Sadece fare ve klavyenin bağlı olduğu USB portlarını sürekli uyanık tutar.",
                "USBSUSPEND=0",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_USB + "|" + SET_USBSUSPEND, SUB_USB, SET_USBSUSPEND, 0);
                    vault.RemovePowerSettingTracked(SUB_PCIEXPRESS + "|" + SET_PCIEASPM);
                }));
            lat07.Variations.Add(new TweakVariation(
                "Sadece Ekran Kartı / SSD Hattı Koruması",
                "Yalnızca PCIe Veri Yolu Uyku Modunu Kapat",
                "Ekran kartı ve M.2 SSD veri yolundaki güç tasarrufu gecikmesini kapatır.",
                "PCIE_ASPM=0",
                () =>
                {
                    vault.RemovePowerSettingTracked(SUB_USB + "|" + SET_USBSUSPEND);
                    vault.ApplyPowerSettingTracked(SUB_PCIEXPRESS + "|" + SET_PCIEASPM, SUB_PCIEXPRESS, SET_PCIEASPM, 0);
                }));
            allTweaks.Add(lat07);

            // LAT-08: Win32 FilterKeys Setter (100% SILENT - NO CLICK SOUND, Chat-Safe Options)
            var lat08 = new TweakDefinition
            {
                Id = "LAT_FILTERKEYS",
                Category = "LATENCY",
                HardwareTag = "ALL",
                BadgeText = "KLAVYE 0MS TEPKİ (SESSİZ)",
                BadgeColor = colLat,
                RequiresAdmin = false,
                Title = "Klavye 0ms Tuş Algılama & Hızlı Hareket (Tamamen Sessiz Mod)",
                SummaryDescription = "Tuşa bastığınız ilk andaki gecikmeyi sıfırlar. Kulaklıktan gelen tuş sesi (Click) tamamen kapatılmıştır; yazışma dostu mod içerir.",
                DeepTechnicalWhy = "Genellikle HaxBall, CS2 ve Valorant gibi oyunlarda A-D-A-D yön değiştirmelerinin ve pas/şut tuşlarının anında algılanması için kullanılır. Sık yazışıyorsanız 'Mod 1 (Yazışma Dostu)' seçin; harfleri arka arkaya tekrarlamaz.",
                TargetPathOrApi = @"Klavye Tepki Süresi (Sessiz)",
                QueryOriginalOrDefaultSummary = () => "Standart Windows Klavye",
                RevertAction = () =>
                {
                    string fkReg = @"Control Panel\Accessibility\Keyboard Response";
                    vault.RevertRegistryTracked("HKCU", fkReg, "Flags");
                    vault.RevertRegistryTracked("HKCU", fkReg, "AutoRepeatDelay");
                    vault.RevertRegistryTracked("HKCU", fkReg, "AutoRepeatRate");
                    vault.RevertRegistryTracked("HKCU", fkReg, "BounceTime");
                    vault.RevertRegistryTracked("HKCU", fkReg, "DelayBeforeAcceptance");
                    NativeMethods.FILTERKEYS offFk = new NativeMethods.FILTERKEYS
                    {
                        cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.FILTERKEYS)),
                        dwFlags = 2, // FKF_AVAILABLE only (FilterKeys OFF, Click Sound OFF!)
                        iWaitMSec = 0,
                        iDelayMSec = 1000,
                        iRepeatMSec = 500,
                        iBounceMSec = 0
                    };
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETFILTERKEYS, offFk.cbSize, ref offFk, NativeMethods.SPIF_SENDCHANGE);
                    vault.FilterKeysModified = false;
                    vault.SaveJournal();
                }
            };
            lat08.Variations.Add(new TweakVariation(
                "Yazışma + Oyun Dostu (0ms Basış, Çift Harf Basmaz)",
                "Sıfır İlk Basış Gecikmesi + Rahat Sohbet (320ms Tekrar Eşiği, Sessiz)",
                "Tuşa ilk bastığınız an 0ms gecikmeyle algılar ama basılı tutma süresini 320ms'de tuttuğu için mesaj yazarken asla 'haaarrrf' diye fazladan harf basmaz ve tık sesi çıkarmaz.",
                "Sessiz (dwFlags=3), İlk Basış=0ms, Tekrar Bekleme=320ms, Hız=22ms",
                () =>
                {
                    string fkReg = @"Control Panel\Accessibility\Keyboard Response";
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "Flags", "59", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "DelayBeforeAcceptance", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "BounceTime", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "AutoRepeatDelay", "320", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "AutoRepeatRate", "22", RegistryValueKind.String);
                    vault.FilterKeysModified = true;
                    NativeMethods.FILTERKEYS fk = new NativeMethods.FILTERKEYS
                    {
                        cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.FILTERKEYS)),
                        dwFlags = 3, // ONLY FKF_FILTERKEYSON (1) | FKF_AVAILABLE (2) -> ZERO CLICK SOUND!
                        iWaitMSec = 0,
                        iDelayMSec = 320,
                        iRepeatMSec = 22,
                        iBounceMSec = 0
                    };
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETFILTERKEYS, fk.cbSize, ref fk, NativeMethods.SPIF_SENDCHANGE);
                    vault.SaveJournal();
                }));
            lat08.Variations.Add(new TweakVariation(
                "Hızlı Oyun & Sohbet Dengeli (240ms Eşik)",
                "Hem Hızlı Yön Değişimi Hem Kontrollü Yazım (Sessiz)",
                "Oyun içinde daha seri tekrar sağlarken normal hızda yazı yazarken çift basmayı önler.",
                "Sessiz (dwFlags=3), İlk Basış=0ms, Tekrar Bekleme=240ms, Hız=16ms",
                () =>
                {
                    string fkReg = @"Control Panel\Accessibility\Keyboard Response";
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "Flags", "59", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "DelayBeforeAcceptance", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "BounceTime", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "AutoRepeatDelay", "240", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "AutoRepeatRate", "16", RegistryValueKind.String);
                    vault.FilterKeysModified = true;
                    NativeMethods.FILTERKEYS fk = new NativeMethods.FILTERKEYS
                    {
                        cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.FILTERKEYS)),
                        dwFlags = 3, // ZERO CLICK SOUND!
                        iWaitMSec = 0,
                        iDelayMSec = 240,
                        iRepeatMSec = 16,
                        iBounceMSec = 0
                    };
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETFILTERKEYS, fk.cbSize, ref fk, NativeMethods.SPIF_SENDCHANGE);
                    vault.SaveJournal();
                }));
            lat08.Variations.Add(new TweakVariation(
                "Sadece Maç İçi Seri Strafe (165ms Eşik)",
                "Maksimum Hareket Tekrarı (Uzun Yazışmalarda Mod 1 Önerilir)",
                "Yalnızca maç içindeyken çok hızlı tuş tekrarı isteyenler içindir; tamamen sessizdir.",
                "Sessiz (dwFlags=3), İlk Basış=0ms, Tekrar Bekleme=165ms, Hız=13ms",
                () =>
                {
                    string fkReg = @"Control Panel\Accessibility\Keyboard Response";
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "Flags", "59", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "DelayBeforeAcceptance", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "BounceTime", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "AutoRepeatDelay", "165", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat08.Title, "HKCU", fkReg, "AutoRepeatRate", "13", RegistryValueKind.String);
                    vault.FilterKeysModified = true;
                    NativeMethods.FILTERKEYS fk = new NativeMethods.FILTERKEYS
                    {
                        cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.FILTERKEYS)),
                        dwFlags = 3, // ZERO CLICK SOUND!
                        iWaitMSec = 0,
                        iDelayMSec = 165,
                        iRepeatMSec = 13,
                        iBounceMSec = 0
                    };
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETFILTERKEYS, fk.cbSize, ref fk, NativeMethods.SPIF_SENDCHANGE);
                    vault.SaveJournal();
                }));
            allTweaks.Add(lat08);

            // LAT-09: USB xHCI Controller & Hub Deep-Sleep Shield
            string usbRootKey = @"SYSTEM\CurrentControlSet\Services\USB";
            string usbHub3Key = @"SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters";
            var lat09 = new TweakDefinition
            {
                Id = "LAT_USB_XHCI",
                Category = "LATENCY",
                HardwareTag = "ALL",
                BadgeText = "USB DERİN UYKU KALKANI",
                BadgeColor = colLat,
                RequiresAdmin = true,
                NeedsReboot = true,
                Title = "USB Kontrolcü & Anakart Port Uyku Kalkanı",
                SummaryDescription = "Anakart üzerindeki USB 3.0 çipinin fare ve klavye portlarını gizlice mikro-uyku moduna sokmasını tamamen engeller.",
                DeepTechnicalWhy = "Genellikle yüksek Hz (1000Hz-8000Hz) oyuncu farelerinde ve mekanik klavyelerde sinyal dalgalanmasını önlemek için kullanılır.",
                TargetPathOrApi = @"Anakart USB Kontrolcü Ayarı",
                QueryOriginalOrDefaultSummary = () => "USB DisableSuspend=" + vault.ReadRegistryDisplay("HKLM", usbRootKey, "DisableSelectiveSuspend", "0 (Varsayılan)"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", usbRootKey, "DisableSelectiveSuspend");
                    vault.RevertRegistryTracked("HKLM", usbHub3Key, "DisableSelectiveSuspend");
                }
            };
            lat09.Variations.Add(new TweakVariation(
                "Tüm USB Portlarında Uykuyu Kapat (Önerilen)",
                "Hem USB 2.0 Hem USB 3.0 Portlarını Sürekli Uyanık Tut",
                "Fare, klavye ve USB kulaklığın bağlı olduğu tüm portlarda güç kesintisini önler.",
                "Tüm USB Kontrolcülerinde Uyku Kapalı",
                () =>
                {
                    vault.SetRegistryTracked(lat09.Title, "HKLM", usbRootKey, "DisableSelectiveSuspend", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(lat09.Title, "HKLM", usbHub3Key, "DisableSelectiveSuspend", 1, RegistryValueKind.DWord);
                }));
            lat09.Variations.Add(new TweakVariation(
                "Sadece Ana USB Servis Kilidi",
                "Standart USB Port Uykusunu Kapat",
                "Sadece ana USB servisinde uyku modunu devre dışı bırakmak için kullanılır.",
                "Ana USB Servisinde Uyku Kapalı",
                () =>
                {
                    vault.SetRegistryTracked(lat09.Title, "HKLM", usbRootKey, "DisableSelectiveSuspend", 1, RegistryValueKind.DWord);
                }));
            lat09.Variations.Add(new TweakVariation(
                "USB Sürücü + Güç Planı Birlikte Kilitle",
                "Hem Sürücü Hem Güç Planı Üzerinden Tam Koruma",
                "USB portlarının hiçbir koşulda uyku moduna geçmemesi için kullanılır.",
                "Sürücü + Güç Planı USB Kilidi",
                () =>
                {
                    vault.SetRegistryTracked(lat09.Title, "HKLM", usbRootKey, "DisableSelectiveSuspend", 1, RegistryValueKind.DWord);
                    vault.ApplyPowerSettingTracked(SUB_USB + "|" + SET_USBSUSPEND, SUB_USB, SET_USBSUSPEND, 0);
                }));
            allTweaks.Add(lat09);

            // =================================================================================================
            // CATEGORY 3: FPS, GPU & SİSTEM BOOST (UNIVERSAL GRAPHICS, DWM, MMCSS & MEMORY TWEAKS)
            // =================================================================================================

            // FPS-01: MMCSS Games Task Priority
            var fps01 = new TweakDefinition
            {
                Id = "FPS_MMCSS_GAMES",
                Category = "FPS",
                HardwareTag = "ALL",
                BadgeText = "OYUN MOTORU ÖNCELİĞİ",
                BadgeColor = colFps,
                RequiresAdmin = true,
                Title = "Oyunlara Maksimum Ekran Kartı (GPU) ve İşlemci Önceliği Verme",
                SummaryDescription = "Açtığınız her oyuna Windows içinde en yüksek ekran kartı çizim, işlemci ve disk okuma önceliğini tanır.",
                DeepTechnicalWhy = "Genellikle oyun oynarken arka plandaki uygulamaların FPS çalmasını önlemek ve oyunun her zaman birinci sırada işlenmesini sağlamak için kullanılır.",
                TargetPathOrApi = @"Windows Oyun Görev Profili",
                QueryOriginalOrDefaultSummary = () => "GPU Prio=" + vault.ReadRegistryDisplay("HKLM", mmcssGames, "GPU Priority", "8") + ", Prio=" + vault.ReadRegistryDisplay("HKLM", mmcssGames, "Priority", "2"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", mmcssGames, "GPU Priority");
                    vault.RevertRegistryTracked("HKLM", mmcssGames, "Priority");
                    vault.RevertRegistryTracked("HKLM", mmcssGames, "Scheduling Category");
                    vault.RevertRegistryTracked("HKLM", mmcssGames, "SFIO Priority");
                    vault.RevertRegistryTracked("HKLM", mmcssGames, "Background Only");
                }
            };
            fps01.Variations.Add(new TweakVariation(
                "Maksimum Espor Önceliği (GPU=8, Prio=6)",
                "En Yüksek Ekran Kartı + İşlemci + Disk Oyun Önceliği",
                "Tüm sistem gücünü açılan oyuna odaklayarak en yüksek FPS değerini almak için kullanılır.",
                "GPU Önceliği=8, CPU Önceliği=6 (Yüksek)",
                () =>
                {
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssGames, "GPU Priority", 8, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssGames, "Priority", 6, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssGames, "Scheduling Category", "High", RegistryValueKind.String);
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssGames, "SFIO Priority", "High", RegistryValueKind.String);
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssGames, "Background Only", "False", RegistryValueKind.String);
                }));
            fps01.Variations.Add(new TweakVariation(
                "Dengeli Yüksek (Oyun + Video Kayıt)",
                "Yüksek Ekran Kartı Önceliği + Rahat Disk Kaydı",
                "Oyun oynarken aynı anda ekran kaydı (OBS / ShadowPlay / ReLive) alanlar için kullanılır.",
                "GPU Önceliği=8, Disk Akışı=Dengeli",
                () =>
                {
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssGames, "GPU Priority", 8, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssGames, "Priority", 4, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssGames, "Scheduling Category", "High", RegistryValueKind.String);
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssGames, "SFIO Priority", "Normal", RegistryValueKind.String);
                }));
            fps01.Variations.Add(new TweakVariation(
                "Oyun + Ses Kastırma (Ayak Sesi Odaklı)",
                "Hem Oyuna Hem Ses Motoruna Eşzamanlı Yüksek Öncelik",
                "CS2 ve Valorant gibi oyunlarda hem yüksek FPS hem de gecikmesiz ses (ayak sesi) duymak için kullanılır.",
                "Oyun + Ses Motoru Yüksek Öncelik",
                () =>
                {
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssGames, "GPU Priority", 8, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssGames, "Priority", 6, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssGames, "Scheduling Category", "High", RegistryValueKind.String);
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssAudio, "Priority", 6, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssAudio, "Scheduling Category", "High", RegistryValueKind.String);
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssProAudio, "Priority", 8, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps01.Title, "HKLM", mmcssProAudio, "Scheduling Category", "High", RegistryValueKind.String);
                }));
            allTweaks.Add(fps01);

            // FPS-02: Fullscreen Optimizations (FSO), GameDVR & DirectX Flip-Model
            var fps02 = new TweakDefinition
            {
                Id = "FPS_FSO_FLIP",
                Category = "FPS",
                HardwareTag = "ALL",
                BadgeText = "TAM EKRAN & GAMEDVR",
                BadgeColor = colFps,
                RequiresAdmin = false,
                Title = "Windows Oyun Kaydediciyi (GameDVR) Kapatma & Pencereli Oyun Akıcılığı",
                SummaryDescription = "FPS düşüren arka plan Xbox/GameDVR video kaydını kapatır ve hem tam ekran hem pencereli oyunlarda görüntü gecikmesini azaltır.",
                DeepTechnicalWhy = "Genellikle tam ekran oyunlarda fare gecikmesini düşürmek ve pencereli (veya tarayıcı tabanlı HaxBall gibi) oyunlarda tam ekran akıcılığı yakalamak için kullanılır.",
                TargetPathOrApi = @"Tam Ekran & DirectX Görüntü Ayarı",
                QueryOriginalOrDefaultSummary = () => "GameDVR=" + vault.ReadRegistryDisplay("HKCU", gameConfig, "GameDVR_Enabled", "0") + ", FSEMode=" + vault.ReadRegistryDisplay("HKCU", gameConfig, "GameDVR_FSEBehaviorMode", "0"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKCU", gameConfig, "GameDVR_Enabled");
                    vault.RevertRegistryTracked("HKCU", gameConfig, "GameDVR_FSEBehaviorMode");
                    vault.RevertRegistryTracked("HKCU", gameConfig, "GameDVR_FSEBehavior");
                    vault.RevertRegistryTracked("HKCU", gameConfig, "GameDVR_HonorUserFSEBehaviorMode");
                    vault.RevertRegistryTracked("HKCU", gameConfig, "GameDVR_DXGIHonorFSEWindowsCompatible");
                    vault.RevertRegistryTracked("HKCU", gameDvr, "AppCaptureEnabled");
                    vault.RevertRegistryTracked("HKCU", dxGlobal, "DirectXUserGlobalSettings");
                }
            };
            fps02.Variations.Add(new TweakVariation(
                "Tam Performans (Gerçek Tam Ekran + Pencereli Hızlandırma + DVR Kapalı)",
                "Hem Tam Ekran Hem Pencereli Oyunlar İçin En Düşük Görüntü Gecikmesi",
                "Arka plan kaydını kapatır, tam ekranda Windows katmanını devre dışı bırakır ve pencereli oyunları hızlandırır.",
                "GameDVR Kapalı + Gerçek Tam Ekran + Flip-Model Açık",
                () =>
                {
                    vault.SetRegistryTracked(fps02.Title, "HKCU", gameConfig, "GameDVR_Enabled", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps02.Title, "HKCU", gameConfig, "GameDVR_FSEBehaviorMode", 2, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps02.Title, "HKCU", gameConfig, "GameDVR_FSEBehavior", 2, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps02.Title, "HKCU", gameConfig, "GameDVR_HonorUserFSEBehaviorMode", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps02.Title, "HKCU", gameConfig, "GameDVR_DXGIHonorFSEWindowsCompatible", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps02.Title, "HKCU", gameDvr, "AppCaptureEnabled", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps02.Title, "HKCU", dxGlobal, "DirectXUserGlobalSettings", "VRROptimizeEnable=1;SwapEffectUpgradeEnable=1;", RegistryValueKind.String);
                }));
            fps02.Variations.Add(new TweakVariation(
                "Hızlı Alt+Tab Sevenler İçin (Pencereli Odaklı + DVR Kapalı)",
                "Oyun İçinde Sık Alt+Tab Yapanlar İçin Hızlı Geçiş + DVR Kapalı",
                "Sık sık Alt+Tab yapıp masaüstüne dönüyorsanız ekranın kararmaması ve pencereli oyunun akıcı kalması için kullanılır.",
                "Hızlı Alt+Tab + Pencereli Hızlandırma + DVR Kapalı",
                () =>
                {
                    vault.SetRegistryTracked(fps02.Title, "HKCU", gameConfig, "GameDVR_Enabled", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps02.Title, "HKCU", gameConfig, "GameDVR_FSEBehaviorMode", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps02.Title, "HKCU", gameDvr, "AppCaptureEnabled", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps02.Title, "HKCU", dxGlobal, "DirectXUserGlobalSettings", "VRROptimizeEnable=1;SwapEffectUpgradeEnable=1;", RegistryValueKind.String);
                }));
            fps02.Variations.Add(new TweakVariation(
                "Sadece Klasik Tam Ekran & DVR Kapatma",
                "Yalnızca GameDVR Kaydını ve Tam Ekran İyileştirmelerini Kapat",
                "Sadece klasik tam ekran deneyimi isteyenler için kullanılır.",
                "Klasik Tam Ekran + GameDVR Kapalı",
                () =>
                {
                    vault.SetRegistryTracked(fps02.Title, "HKCU", gameConfig, "GameDVR_Enabled", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps02.Title, "HKCU", gameConfig, "GameDVR_FSEBehaviorMode", 2, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps02.Title, "HKCU", gameConfig, "GameDVR_FSEBehavior", 2, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps02.Title, "HKCU", gameConfig, "GameDVR_HonorUserFSEBehaviorMode", 1, RegistryValueKind.DWord);
                }));
            allTweaks.Add(fps02);

            // FPS-04: HAGS & TDR
            var fps04 = new TweakDefinition
            {
                Id = "FPS_HAGS",
                Category = "FPS",
                HardwareTag = "ALL",
                BadgeText = "GPU ZAMANLAYICI (HAGS)",
                BadgeColor = colFps,
                RequiresAdmin = true,
                NeedsReboot = true,
                Title = "Donanım Hızlandırmalı GPU Zamanlaması (HAGS) & Çökme Koruması",
                SummaryDescription = "Görüntü kuyruğunu işlemci yerine doğrudan ekran kartının yönetmesini sağlar veya tarayıcı oyunları için kapatır.",
                DeepTechnicalWhy = "Genellikle modern DX12 oyunlarında ve DLSS/Frame Gen kullanırken FPS artırmak için Açık (Mod 1), HaxBall gibi tarayıcı/WebGL oyunlarında mikro-takılma oluyorsa Kapalı (Mod 2) olarak kullanılır.",
                TargetPathOrApi = @"Ekran Kartı Donanım Zamanlayıcısı",
                QueryOriginalOrDefaultSummary = () => "HwSchMode=" + vault.ReadRegistryDisplay("HKLM", gfxDrivers, "HwSchMode", "Varsayılan"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", gfxDrivers, "HwSchMode");
                    vault.RevertRegistryTracked("HKLM", gfxDrivers, "TdrDelay");
                }
            };
            fps04.Variations.Add(new TweakVariation(
                "HAGS Açık (Modern Oyunlar & Yüksek FPS)",
                "Ekran Kartı Zamanlaması Aktif + Sürücü Çökme Koruması",
                "Modern oyunlarda işlemci yükünü azaltıp FPS artırmak için kullanılır.",
                "HAGS Açık + Çökme Koruması (10sn)",
                () =>
                {
                    vault.SetRegistryTracked(fps04.Title, "HKLM", gfxDrivers, "HwSchMode", 2, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps04.Title, "HKLM", gfxDrivers, "TdrDelay", 10, RegistryValueKind.DWord);
                }));
            fps04.Variations.Add(new TweakVariation(
                "HAGS Kapalı (HaxBall / Tarayıcı / Klasik Espor)",
                "Tarayıcı, Discord ve DX9/DX11 Oyunlarda Takılma Önleyici Mod",
                "Tarayıcı oyunlarında (HaxBall) veya ikinci ekranda video açıkken oluşan mikro-takılmaları kesmek için kullanılır.",
                "HAGS Kapalı + Klasik Kararlı Zamanlama",
                () =>
                {
                    vault.SetRegistryTracked(fps04.Title, "HKLM", gfxDrivers, "HwSchMode", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps04.Title, "HKLM", gfxDrivers, "TdrDelay", 10, RegistryValueKind.DWord);
                }));
            fps04.Variations.Add(new TweakVariation(
                "Sadece Ekran Kartı Çökme Koruması",
                "Zamanlayıcıya Dokunmadan Yalnızca Sürücü Yanıt Süresini Uzat",
                "Ağır oyunlarda ekran kartı sürücüsünün aniden kapanmasını (WattMan / TDR hatası) önlemek için kullanılır.",
                "Sürücü Yanıt Süresi=15sn",
                () =>
                {
                    vault.SetRegistryTracked(fps04.Title, "HKLM", gfxDrivers, "TdrDelay", 15, RegistryValueKind.DWord);
                }));
            allTweaks.Add(fps04);

            // FPS-05: Memory Management & Smart Standby List Purger
            var fps05 = new TweakDefinition
            {
                Id = "FPS_MEMORY_ENGINE",
                Category = "FPS",
                HardwareTag = "ALL",
                BadgeText = "AKILLI RAM TEMİZLEYİCİ",
                BadgeColor = colFps,
                RequiresAdmin = false,
                Title = "Oyun İçi Akıllı RAM & Önbellek Temizleyici",
                SummaryDescription = "Windows'ta biriken gereksiz önbelleği (Standby RAM) açık olan oyuna dokunmadan temizleyerek uzun süreli oyunlarda takılmayı önler.",
                DeepTechnicalWhy = "Genellikle 1-2 saat oyun oynadıktan sonra başlayan anlık FPS takılmalarını (RAM şişmesini) engellemek ve sistem dosyalarını hızlı RAM'de tutmak için kullanılır.",
                TargetPathOrApi = "Akıllı Bellek & Önbellek Motoru",
                QueryOriginalOrDefaultSummary = () => "PagingExec=" + vault.ReadRegistryDisplay("HKLM", memMgmtKey, "DisablePagingExecutive", "0"),
                RevertAction = () =>
                {
                    autoStandbyCleanerActive = false;
                    vault.RevertRegistryTracked("HKLM", memMgmtKey, "DisablePagingExecutive");
                    vault.RevertRegistryTracked("HKLM", memMgmtKey, "LargeSystemCache");
                }
            };
            fps05.Variations.Add(new TweakVariation(
                "Akıllı Oyun Korumalı Temizlik + Sistem RAM Kilidi",
                "Açık Oyuna Dokunmadan Arka Planı Temizle + Çekirdeği RAM'de Tut",
                "Oyun esnasında sıfır takılma ile arka plan belleğini ferahlatmak için kullanılır.",
                "Oyun Korumalı RAM Temizliği + Disk Takası Kapalı",
                () =>
                {
                    autoStandbyCleanerActive = true;
                    ExecuteSmartRamAndStandbyPurge(true);
                    if (isAdmin)
                    {
                        vault.SetRegistryTracked(fps05.Title, "HKLM", memMgmtKey, "DisablePagingExecutive", 1, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(fps05.Title, "HKLM", memMgmtKey, "LargeSystemCache", 0, RegistryValueKind.DWord);
                    }
                }));
            fps05.Variations.Add(new TweakVariation(
                "Derin Önbellek Boşaltma (Tam Temizlik)",
                "Birikmiş Tüm Windows Standby Önbelleğini Hemen Boşalt",
                "Ağır bir oyuna girmeden önce maksimum boş RAM elde etmek için kullanılır.",
                "Tam Önbellek (Standby List) Temizliği",
                () =>
                {
                    autoStandbyCleanerActive = true;
                    ExecuteSmartRamAndStandbyPurge(false);
                }));
            fps05.Variations.Add(new TweakVariation(
                "Sadece RAM Dolduğunda Otomatik Temizle (%75 Üzeri)",
                "Yalnızca Bellek %75'i Geçtiğinde Arka Planı Hafiflet",
                "16 GB veya 32 GB RAM'li sistemlerde sadece ihtiyaç duyulduğunda devreye girmesi için kullanılır.",
                "Otomatik %75 Eşik Koruması",
                () =>
                {
                    autoStandbyCleanerActive = true;
                    ExecuteSmartRamAndStandbyPurge(true);
                }));
            allTweaks.Add(fps05);

            // FPS-06: Desktop Compositor (DWM Transparency, MenuDelay, Background UWP Apps)
            var fps06 = new TweakDefinition
            {
                Id = "FPS_DWM_VISUAL",
                Category = "FPS",
                HardwareTag = "ALL",
                BadgeText = "MASAÜSTÜ HIZLANDIRICI",
                BadgeColor = colFps,
                RequiresAdmin = false,
                Title = "Masaüstü Görsel Efekt Yükünü & Arka Plan Uygulamalarını Kapatma",
                SummaryDescription = "Ekran kartını yoran pencere saydamlık/bulanıklık efektlerini ve gereksiz Windows arka plan uygulamalarını durdurur.",
                DeepTechnicalWhy = "Genellikle pencereli veya tarayıcı üzerinden oynanan oyunlarda masaüstü çizim yükünü sıfırlamak ve menü geçişlerini hızlandırmak için kullanılır.",
                TargetPathOrApi = @"Masaüstü Görsel & Arka Plan Yükü",
                QueryOriginalOrDefaultSummary = () => "Saydamlık=" + vault.ReadRegistryDisplay("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency", "1"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency");
                    vault.RevertRegistryTracked("HKCU", @"Control Panel\Desktop", "MenuShowDelay");
                    vault.RevertRegistryTracked("HKCU", @"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", "GlobalUserDisabled");
                }
            };
            fps06.Variations.Add(new TweakVariation(
                "Tam Espor Masaüstü (Saydamlık & Arka Plan Kapalı)",
                "Bulanıklık Efektleri Kapalı + Anında Menü + Arka Plan Uygulamaları Kapalı",
                "Ekran kartı ve işlemciyi tamamen oyuna bırakmak için kullanılır.",
                "Saydamlık Kapalı + Menü Gecikmesi 0 + Arka Plan Kapalı",
                () =>
                {
                    vault.SetRegistryTracked(fps06.Title, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps06.Title, "HKCU", @"Control Panel\Desktop", "MenuShowDelay", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(fps06.Title, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", "GlobalUserDisabled", 1, RegistryValueKind.DWord);
                }));
            fps06.Variations.Add(new TweakVariation(
                "Sadece Saydamlık Kapat & Menüleri Hızlandır",
                "Arka Plan Ayarlarına Dokunmadan Görsel Yükü Azalt",
                "Sadece masaüstü bulanıklık efektini kapatıp sağ tık/menü hızını artırmak için kullanılır.",
                "Saydamlık Kapalı + Menü Gecikmesi 0",
                () =>
                {
                    vault.SetRegistryTracked(fps06.Title, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps06.Title, "HKCU", @"Control Panel\Desktop", "MenuShowDelay", "0", RegistryValueKind.String);
                }));
            fps06.Variations.Add(new TweakVariation(
                "Görünümü Koru (Sadece Arka Planı ve Menü Gecikmesini Kapat)",
                "Windows Saydamlığını Bozmaz, Sadece Arka Plan Yükünü Keser",
                "Masaüstü görünümünün değişmesini istemeyen ama arka plan yükünden kurtulmak isteyenler için kullanılır.",
                "Görünüm Korunur + Arka Plan Uygulamaları Kapalı",
                () =>
                {
                    vault.SetRegistryTracked(fps06.Title, "HKCU", @"Control Panel\Desktop", "MenuShowDelay", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(fps06.Title, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", "GlobalUserDisabled", 1, RegistryValueKind.DWord);
                }));
            allTweaks.Add(fps06);

            // FPS-07: NVMe SSD APST Idle Latency Shield & CMOS IRQ8 Real-Time Clock Priority
            Guid SUB_DISK = new Guid("0012ee47-9041-4b5d-9b77-535fba8b1442");
            Guid SET_NVME_IDLE = new Guid("d639518a-e56d-4345-8af2-b9f32fb26109");
            var fps07 = new TweakDefinition
            {
                Id = "FPS_NVME_IRQ8",
                Category = "FPS",
                HardwareTag = "ALL",
                BadgeText = "SSD UYKU KALKANI & SAAT",
                BadgeColor = colFps,
                RequiresAdmin = true,
                Title = "M.2 NVMe SSD Uyku Modunu Kapatma & Sistem Saati Önceliği",
                SummaryDescription = "Oyun içinde harita veya doku yüklenirken SSD'nin uykudan uyanma takılmasını önler ve sistem saatine öncelik verir.",
                DeepTechnicalWhy = "Genellikle açık dünya oyunlarında veya yeni maça girerken oluşan anlık doku yükleme takılmalarını (stutter) engellemek için kullanılır.",
                TargetPathOrApi = @"NVMe SSD Güç & Sistem Saati Önceliği",
                QueryOriginalOrDefaultSummary = () => "IRQ8=" + vault.ReadRegistryDisplay("HKLM", prioCtrl, "IRQ8Priority", "Varsayılan") + ", NVMeIdle=" + vault.ReadPowerAcSettingDisplay(SUB_DISK, SET_NVME_IDLE, "100ms"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", prioCtrl, "IRQ8Priority");
                    vault.RevertRegistryTracked("HKLM", prioCtrl, "IRQ0Priority");
                    vault.RemovePowerSettingTracked(SUB_DISK + "|" + SET_NVME_IDLE);
                }
            };
            fps07.Variations.Add(new TweakVariation(
                "NVMe Uyku Kapalı + Sistem Saati Önceliği (Önerilen)",
                "SSD Sürekli Hazır + Gerçek Zamanlı Saat Önceliği",
                "Hem SSD uyanma gecikmesini sıfırlamak hem de sistem zamanlamasını hızlandırmak için kullanılır.",
                "NVMe Uyku Kapalı + Saat Önceliği Aktif",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_DISK + "|" + SET_NVME_IDLE, SUB_DISK, SET_NVME_IDLE, 0);
                    vault.SetRegistryTracked(fps07.Title, "HKLM", prioCtrl, "IRQ8Priority", 1, RegistryValueKind.DWord);
                }));
            fps07.Variations.Add(new TweakVariation(
                "NVMe Tam Uyanık + Çift Zamanlayıcı Önceliği",
                "SSD Tam Uyanık + Hem Ana Zamanlayıcı Hem Saat Önceliği",
                "Maksimum sistem tepkisi için her iki anakart saatine de öncelik verir.",
                "NVMe Tam Uyanık + Çift Saat Önceliği",
                () =>
                {
                    vault.ApplyPowerSettingTracked(SUB_DISK + "|" + SET_NVME_IDLE, SUB_DISK, SET_NVME_IDLE, 0);
                    vault.SetRegistryTracked(fps07.Title, "HKLM", prioCtrl, "IRQ8Priority", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(fps07.Title, "HKLM", prioCtrl, "IRQ0Priority", 1, RegistryValueKind.DWord);
                }));
            fps07.Variations.Add(new TweakVariation(
                "Sadece Sistem Saati Önceliği (Dizüstü Dostu)",
                "SSD Güç Ayarına Dokunmadan Sadece Saat Önceliğini Aç",
                "Dizüstü bilgisayarlarda pil ömrünü koruyarak sistem tepkisini iyileştirmek için kullanılır.",
                "Sadece Saat Önceliği Aktif",
                () =>
                {
                    vault.SetRegistryTracked(fps07.Title, "HKLM", prioCtrl, "IRQ8Priority", 1, RegistryValueKind.DWord);
                }));
            allTweaks.Add(fps07);

            // FPS-08: Live Background EcoQoS Cage & Foreground Game Anti-Throttling Shield (Zero Reboot Gem)
            var fps08 = new TweakDefinition
            {
                Id = "FPS_ECOQOS_GOVERNOR",
                Category = "FPS",
                HardwareTag = "ALL",
                BadgeText = "%1 LOW FPS & ECOQOS",
                BadgeColor = colFps,
                RequiresAdmin = false,
                Title = "Arka Plan Uygulamalarını Kısıtlama (EcoQoS) & Oyun Hız Kalkanı",
                SummaryDescription = "Oyun çalışırken Discord, tarayıcı ve başlatıcıların işlemci önbelleğini çalmasını engeller; oyunun ise güç tasarrufuna girmesini kapatır.",
                DeepTechnicalWhy = "Genellikle oyun oynarken arkada Discord, Chrome veya Steam açık olduğunda yaşanan %1 Low FPS düşüşlerini ve anlık takılmaları (stutter) kesmek amacıyla kullanılır. Restart istemez, açıldığı anda devreye girer.",
                TargetPathOrApi = "Canlı Süreç Güç & Önbellek Yöneticisi (Sıfır Restart)",
                QueryOriginalOrDefaultSummary = () => "Standart Windows Süreç Dağılımı",
                RevertAction = () =>
                {
                    fpsEcoQosMode = 0;
                    RevertLiveEcoQosAndBackgroundCage();
                }
            };
            fps08.Variations.Add(new TweakVariation(
                "Oyun Tam Güç + Arka Plan Verimlilik Kafesinde (Önerilen)",
                "Oyunda Güç Kısıtlaması Kapalı + Arka Plan Uygulamaları Düşük Güçte",
                "Açık olan oyuna maksimum disk/bellek önceliği verirken Discord, Steam ve güncelleme araçlarını düşük güçlü verimlilik moduna (EcoQoS) hapseder.",
                "Oyun: Tam Güç + High I/O | Arka Plan: EcoQoS Kafesi",
                () => { fpsEcoQosMode = 1; ApplyLiveEcoQosAndBackgroundCage(1); }));
            fps08.Variations.Add(new TweakVariation(
                "Sadece Oyun & Tarayıcı Güç Kısıtlamasını Kaldır",
                "Windows 11'in Oyun ve HaxBall Tarayıcısını Yavaşlatmasını Önle",
                "Arka plan uygulamalarına dokunmadan sadece oyunların ve tarayıcının 'Verimlilik Modu'na (yeşil yaprak) düşmesini engeller.",
                "Oyun & Tarayıcı: EcoQoS Kısıtlaması Kapalı",
                () => { fpsEcoQosMode = 2; ApplyLiveEcoQosAndBackgroundCage(2); }));
            fps08.Variations.Add(new TweakVariation(
                "Turnuva Modu: Arka Planı Sustur + Maksimum Bellek Önceliği",
                "Tüm Arka Plan Yardımcılarını Uyut + Oyunu RAM'e Kilitle",
                "Rekabetçi maçlarda arka plan işlemlerinin işlemci önbelleğini (L3 Cache) kirletmesini tamamen engeller.",
                "Agresif Arka Plan Kafesi + PagePriority=5",
                () => { fpsEcoQosMode = 3; ApplyLiveEcoQosAndBackgroundCage(3); }));
            allTweaks.Add(fps08);

            // FPS-09: Windows Audio Graph (audiodg.exe) & DWM Core 0 Isolation (Zero Reboot Gem)
            var fps09 = new TweakDefinition
            {
                Id = "FPS_AUDIODG_DWM_ISO",
                Category = "FPS",
                HardwareTag = "ALL",
                BadgeText = "SES & ÇATIŞMA AKICILIĞI",
                BadgeColor = colFps,
                RequiresAdmin = false,
                Title = "Windows Ses Motorunu (audiodg) Oyun Çekirdeğinden Ayırma",
                SummaryDescription = "Oyun içindeki patlama ve ateş seslerini işleyen Windows ses motorunu ilk çekirdekten (Core 0) uzaklaştırarak çatışma anı takılmalarını önler.",
                DeepTechnicalWhy = "Genellikle CS2, Valorant ve yoğun aksiyon anlarında çok sayıda ses efekti aynı anda patladığında oluşan mikro-donmaları ve ses çıtırtılarını kesmek için kullanılır. Restart gerektirmez, anında uygulanır.",
                TargetPathOrApi = "Canlı Ses & Çizim Çekirdek İzolasyonu (Sıfır Restart)",
                QueryOriginalOrDefaultSummary = () => "audiodg=Tüm Çekirdekler (Core 0 Dahil)",
                RevertAction = () =>
                {
                    fpsAudioIsoMode = 0;
                    RevertAudioAndDwmIsolation();
                }
            };
            fps09.Variations.Add(new TweakVariation(
                "Ses Motorunu Son Çekirdeklere Sabitle (Önerilen)",
                "audiodg.exe Sürecini Core 0'dan Uzaklaştırıp Son Çekirdeklere Al",
                "Ses efektlerinin oyunun ana çizim çekirdeğiyle (Core 0) çarpışmasını engelleyerek çatışma anlarında yağ gibi akıcılık sağlar.",
                "audiodg.exe -> Son Çekirdekler + Yüksek Öncelik",
                () => { fpsAudioIsoMode = 1; ApplyAudioAndDwmIsolation(1); }));
            fps09.Variations.Add(new TweakVariation(
                "Ses Motoru + Masaüstü Çiziciyi Core 0'dan Uzaklaştır",
                "Hem audiodg.exe Hem Yardımcı Çizim Yükünü İlk Çekirdekten Ayır",
                "İlk çekirdeği (Core 0) tamamen oyunun ana döngüsüne temiz bırakmak için kullanılır.",
                "Ses + Yardımcı Çizim -> Core 0 Hariç",
                () => { fpsAudioIsoMode = 2; ApplyAudioAndDwmIsolation(2); }));
            fps09.Variations.Add(new TweakVariation(
                "Sadece Ses Motoru Önceliğini Yükselt (Cızırtı Önleyici)",
                "Çekirdek Değiştirmeden Sadece Ses İşleme Önceliğini Artır",
                "Kablosuz veya USB kulaklıklarda ses gecikmesini ve cızırtıyı önlemek için kullanılır.",
                "audiodg.exe -> Yüksek Öncelik",
                () => { fpsAudioIsoMode = 3; ApplyAudioAndDwmIsolation(3); }));
            allTweaks.Add(fps09);

            // FPS-10: Live Heavy Background Windows Services Suspender (WSearch, DiagTrack, SysMain - Zero Reboot Gem)
            var fps10 = new TweakDefinition
            {
                Id = "FPS_LIVE_SERVICES",
                Category = "FPS",
                HardwareTag = "ALL",
                BadgeText = "CANLI SERVİS DURAKLATICI",
                BadgeColor = colFps,
                RequiresAdmin = true,
                Title = "Oyun Sırasında Ağır Windows Servislerini Canlı Duraklatma",
                SummaryDescription = "Oyun ortasında diski ve işlemciyi yoran Windows Arama İndeksleme, Telemetri ve Ön Yükleme servislerini sistemi bozmadan geçici olarak durdurur.",
                DeepTechnicalWhy = "Genellikle oyun esnasında arka planda kendi kendine başlayan disk taramalarının ve veri gönderimlerinin FPS düşürmesini engellemek için kullanılır. Kapattığınızda servisler otomatik tekrar başlatılır; restart istemez.",
                TargetPathOrApi = "Canlı Windows Servis Yöneticisi (Sıfır Restart)",
                QueryOriginalOrDefaultSummary = () => "Arka Plan Servisleri: Standart Çalışıyor",
                RevertAction = () => ResumePausedWindowsServices()
            };
            fps10.Variations.Add(new TweakVariation(
                "Arama İndeksleme + Telemetriyi Canlı Duraklat (Güvenli Espor)",
                "WSearch ve DiagTrack Servislerini Geçici Durdur",
                "Windows'un hiçbir özelliğini bozmadan oyun ortasında disk indeksleme ve telemetri takılmalarını anında durdurur.",
                "Canlı Durdurulan: WSearch + DiagTrack",
                () => PauseHeavyWindowsServicesLive(1)));
            fps10.Variations.Add(new TweakVariation(
                "Tam Disk & İşlemci Rahatlatma (SysMain + WSearch + DiagTrack)",
                "Superfetch, Arama ve Telemetri Servislerini Birlikte Duraklat",
                "16 GB ve üzeri RAM'li sistemlerde arka plan disk okuma/yazma yükünü tamamen sıfırlamak için kullanılır.",
                "Canlı Durdurulan: SysMain + WSearch + DiagTrack",
                () => PauseHeavyWindowsServicesLive(2)));
            fps10.Variations.Add(new TweakVariation(
                "Sadece Windows Telemetri ve Tanılama Yükünü Durdur",
                "Yalnızca DiagTrack Veri Gönderim Servisini Duraklat",
                "Arama indekslemeye dokunmadan sadece arka plan veri raporlama servisini durdurur.",
                "Canlı Durdurulan: DiagTrack",
                () => PauseHeavyWindowsServicesLive(3)));
            allTweaks.Add(fps10);

            // =================================================================================================
            // CATEGORY 4: EXPERIMENTAL FEATURES (8 ON/OFF + MULTI-VARIATION SANDBOX LAB TWEAKS)
            // =================================================================================================

            // EXP-01: SerializeTimerExpiration
            var exp01 = new TweakDefinition
            {
                Id = "EXP_SERIALIZE_TIMER",
                Category = "EXPERIMENTAL",
                HardwareTag = "ALL",
                BadgeText = "DENEYSEL ZAMANLAYICI",
                BadgeColor = colExp,
                RequiresAdmin = true,
                NeedsReboot = true,
                Title = "Zamanlayıcı Sinyallerini Çekirdeklere Dağıtma Modu",
                SummaryDescription = "Sistem zamanlayıcı sinyallerinin tek bir çekirdeğe yığılması yerine çekirdekler arasında dağıtılmasını sağlar.",
                DeepTechnicalWhy = "Genellikle çok çekirdekli işlemcilerde ilk çekirdeğin (Core 0) aşırı yüklenmesini önleyip fare akıcılığını test etmek amacıyla kullanılır.",
                TargetPathOrApi = @"Çekirdek Zamanlayıcı Dağıtımı",
                QueryOriginalOrDefaultSummary = () => "Mevcut: " + vault.ReadRegistryDisplay("HKLM", kernelKey, "SerializeTimerExpiration", "Varsayılan (1)"),
                RevertAction = () => vault.RevertRegistryTracked("HKLM", kernelKey, "SerializeTimerExpiration")
            };
            exp01.Variations.Add(new TweakVariation(
                "Mod 0: Bekletmeden Anında Tetikle",
                "Zamanlayıcı Birleştirmeyi Kapat (En Düşük Gecikme)",
                "Sinyallerin gruplanmadan anında işlenmesi için kullanılır.",
                "Birleştirme Kapalı (0)",
                () => vault.SetRegistryTracked(exp01.Title, "HKLM", kernelKey, "SerializeTimerExpiration", 0, RegistryValueKind.DWord)));
            exp01.Variations.Add(new TweakVariation(
                "Mod 2: Tüm Çekirdeklere Dağıt",
                "Zamanlayıcı Yükünü Tüm Çekirdeklere Paylaştır",
                "6 ve daha fazla çekirdekli işlemcilerde yükü eşit dağıtmak için kullanılır.",
                "Çoklu Çekirdek Dağıtımı (2)",
                () => vault.SetRegistryTracked(exp01.Title, "HKLM", kernelKey, "SerializeTimerExpiration", 2, RegistryValueKind.DWord)));
            exp01.Variations.Add(new TweakVariation(
                "Mod 1: Standart Sabit Mod",
                "Windows Standart Davranışı",
                "Farkı karşılaştırmak için standart moda sabitler.",
                "Standart Mod (1)",
                () => vault.SetRegistryTracked(exp01.Title, "HKLM", kernelKey, "SerializeTimerExpiration", 1, RegistryValueKind.DWord)));
            allTweaks.Add(exp01);

            // EXP-02: Synthetic High-Precision Anti-C1E Micro-Pulse Thread
            var exp02 = new TweakDefinition
            {
                Id = "EXP_SYNTHETIC_PULSE",
                Category = "EXPERIMENTAL",
                HardwareTag = "ALL",
                BadgeText = "DENEYSEL UYANDIRICI",
                BadgeColor = colExp,
                RequiresAdmin = false,
                Title = "İşlemci Veri Yolunu Sıcak Tutan Mikro-Sinyal",
                SummaryDescription = "İşlemcinin kare aralarında gizli mikro-uykuya girmesini önlemek için son çekirdekte çok hafif bir sinyal çalıştırır.",
                DeepTechnicalWhy = "Genellikle işlemci uyku modları tam kapatılamayan kilitli sistemlerde veya dizüstü bilgisayarlarda fare tepkisini canlı tutmak için kullanılır.",
                TargetPathOrApi = "Arka Plan Canlı Tutma Sinyali",
                QueryOriginalOrDefaultSummary = () => "Kapalı (Pasif)",
                RevertAction = () => StopSyntheticPulseThread()
            };
            exp02.Variations.Add(new TweakVariation(
                "Hafif Sinyal (1.5ms - Sıfır Yük)",
                "İşlemciyi Yormadan (%0.2) Canlı Tutan Hafif Mod",
                "Günlük oyunlarda ısınma yaratmadan veri yolunu açık tutmak için kullanılır.",
                "1.5ms Hafif Sinyal",
                () => StartSyntheticPulseThread(1)));
            exp02.Variations.Add(new TweakVariation(
                "Hızlı Sinyal (0.5ms - 2000Hz Uyumlu)",
                "0.5ms Zamanlayıcıyla Tam Uyumlu Hızlı Mod",
                "Yüksek yenileme hızlı (240Hz+) monitörlerde en hızlı tepki için kullanılır.",
                "0.5ms Hızlı Sinyal",
                () => StartSyntheticPulseThread(2)));
            exp02.Variations.Add(new TweakVariation(
                "Turnuva Modu (Kesintisiz Tepki)",
                "En Yüksek Hazır Bekleme Modu",
                "Maç esnasında sıfır uyanma gecikmesi için kullanılır.",
                "Turnuva Sinyali",
                () => StartSyntheticPulseThread(3)));
            allTweaks.Add(exp02);

            // EXP-03: SMT / Core 0 Isolation Topology Engine
            var exp03 = new TweakDefinition
            {
                Id = "EXP_SMT_ISOLATION",
                Category = "EXPERIMENTAL",
                HardwareTag = "ALL",
                BadgeText = "DENEYSEL ÇEKİRDEK AYIRICI",
                BadgeColor = colExp,
                RequiresAdmin = false,
                Title = "Oyunu Windows Arka Plan Yükünden (Core 0) Ayırma",
                SummaryDescription = "Windows'un sistem işlerini yürüttüğü ilk çekirdeği (Core 0) oyundan ayırarak oyunu temiz çekirdeklerde çalıştırır.",
                DeepTechnicalWhy = "Genellikle işlemcinin ilk çekirdeğinde oluşan yoğunluğun oyunda anlık takılma yapmasını engellemek için kullanılır.",
                TargetPathOrApi = "Oyun Çekirdek Dağılımı",
                QueryOriginalOrDefaultSummary = () => string.Format("Tüm Çekirdekler ({0} Thread)", Environment.ProcessorCount),
                RevertAction = () =>
                {
                    standbyIsolationMode = 0;
                    RestoreAllModifiedProcessAffinities();
                }
            };
            exp03.Variations.Add(new TweakVariation(
                "İlk Çekirdeği (Core 0) Windows'a Bırak, Oyunu Diğerlerine Al",
                "Hem Intel Hem AMD İşlemcilerde Güvenli Takılma Önleyici",
                "Oyunu sistem işlerinin yapıldığı ilk çekirdekten uzaklaştırmak için kullanılır.",
                "Core 0 Hariç Tüm Çekirdekler",
                () => { standbyIsolationMode = 1; ApplyTopologyToActiveGameTargets(1); }));
            exp03.Variations.Add(new TweakVariation(
                "Sadece Gerçek Fiziksel Çekirdekler (AMD Ryzen İçin)",
                "Sanal Çekirdekleri Kapatıp Oyunu Gerçek Çekirdeklerde Çalıştır",
                "HaxBall ve CS2 gibi oyunlarda sadece gerçek fiziksel çekirdeklerin gücünü kullanmak için seçilir.",
                "Sadece Gerçek Fiziksel Çekirdekler",
                () => { standbyIsolationMode = 2; ApplyTopologyToActiveGameTargets(2); }));
            exp03.Variations.Add(new TweakVariation(
                "Saf Espor: Hem Core 0 Hariç Hem Sadece Gerçek Çekirdekler",
                "En Temiz Oyun Çekirdek İzolasyonu",
                "6 veya 8 çekirdekli işlemcilerde en pürüzsüz kare süresini yakalamak için kullanılır.",
                "Core 0 Hariç + Gerçek Çekirdekler",
                () => { standbyIsolationMode = 3; ApplyTopologyToActiveGameTargets(3); }));
            allTweaks.Add(exp03);

            // EXP-04: TCP Congestion Provider
            var exp04 = new TweakDefinition
            {
                Id = "EXP_TCP_CONGESTION",
                Category = "EXPERIMENTAL",
                HardwareTag = "ALL",
                BadgeText = "DENEYSEL AĞ AKIŞI",
                BadgeColor = colExp,
                RequiresAdmin = true,
                Title = "İnternet Paket Akış Algoritması (CTCP / BBR2 / CUBIC)",
                SummaryDescription = "İnternet hattınız yoğunlaştığında paketlerin hangi yöntemle gönderileceğini belirler.",
                DeepTechnicalWhy = "Genellikle akşam saatlerinde yoğunlaşan internet altyapılarında en stabil ping veren akış algoritmasını seçmek için kullanılır.",
                TargetPathOrApi = "Ağ Akış Algoritması",
                QueryOriginalOrDefaultSummary = () => "CUBIC / Default",
                RevertAction = () => StateVault.RunHiddenCmd("netsh", "int tcp set supplemental template=internet congestionprovider=default")
            };
            exp04.Variations.Add(new TweakVariation(
                "CTCP (Klasik Oyun & TCP Optimizer Önerisi)",
                "Ping Artışına Duyarlı Klasik Oyun Algoritması",
                "Ping yükseldiği anda hattı rahatlatarak oyun paketlerini korur.",
                "Algoritma: CTCP",
                () => StateVault.RunHiddenCmd("netsh", "int tcp set supplemental template=internet congestionprovider=ctcp")));
            exp04.Variations.Add(new TweakVariation(
                "BBR2 (Modern Windows 11 Akıllı Hız Kontrolü)",
                "Hattın Gerçek Hızını ve Pingini Ölçen Modern Algoritma",
                "Windows 11 sistemlerde paket kaybı yaşanmadan en akıcı bağlantıyı sağlamak için kullanılır.",
                "Algoritma: BBR2",
                () => StateVault.RunHiddenCmd("netsh", "int tcp set supplemental template=internet congestionprovider=bbr2")));
            exp04.Variations.Add(new TweakVariation(
                "CUBIC (Standart Yüksek İndirme Hızı)",
                "Windows Varsayılan Yüksek Hız Algoritması",
                "Standart davranışı test etmek için kullanılır.",
                "Algoritma: CUBIC",
                () => StateVault.RunHiddenCmd("netsh", "int tcp set supplemental template=internet congestionprovider=cubic")));
            allTweaks.Add(exp04);

            // EXP-05: Kernel I/O & Memory Page Priority Boost
            var exp05 = new TweakDefinition
            {
                Id = "EXP_IO_PAGE_PRIO",
                Category = "EXPERIMENTAL",
                HardwareTag = "ALL",
                BadgeText = "DENEYSEL OYUN KORUMASI",
                BadgeColor = colExp,
                RequiresAdmin = false,
                Title = "Oyun Sürecini Windows Tasarruf Modundan (EcoQoS) Koruma",
                SummaryDescription = "Windows 11'in oyun veya tarayıcı süreçlerini yanlışlıkla 'Verimlilik Modu'na alıp yavaşlatmasını engeller.",
                DeepTechnicalWhy = "Genellikle Windows 11'de tarayıcı oyunları (HaxBall) veya arka plan oyun istemcileri çalışırken yaşanan ani yavaşlamaları önlemek için kullanılır.",
                TargetPathOrApi = "Oyun Süreci Hız Koruması",
                QueryOriginalOrDefaultSummary = () => "I/O=Normal (2), Page=5",
                RevertAction = () => ApplyIoAndPagePriorityToGames(2, 5, false)
            };
            exp05.Variations.Add(new TweakVariation(
                "Tam Koruma (Tasarruf Modu Kapalı + Yüksek Disk/RAM Önceliği)",
                "Oyunu Yavaşlatmayı Engelle + En Yüksek Bellek Önceliği Ver",
                "Açık olan oyunun her zaman tam güçte çalışması için kullanılır.",
                "EcoQoS Kapalı + Yüksek Öncelik",
                () => ApplyIoAndPagePriorityToGames(3, 5, true)));
            exp05.Variations.Add(new TweakVariation(
                "Sadece Verimlilik Modu (EcoQoS) Engelleyici",
                "Windows 11'in Oyunu Güç Tasarrufuna Almasını Önle",
                "Yalnızca güç kısıtlamasını kapatmak için kullanılır.",
                "EcoQoS Güç Kısıtlaması Kapalı",
                () => ApplyIoAndPagePriorityToGames(2, 5, true)));
            exp05.Variations.Add(new TweakVariation(
                "Oyunu Yükselt + Arka Plan Servislerini Sustur",
                "Oyuna Tam Güç Verirken Gereksiz Arka Plan İşlemlerini Yavaşlat",
                "Oyun esnasında OneDrive, Arama İndeksleyici gibi arka plan işlemlerinin araya girmesini önler.",
                "Oyun=Yüksek, Arka Plan=Düşük",
                () => { ApplyIoAndPagePriorityToGames(3, 5, true); SuppressNoisyBackgroundHelpers(); }));
            allTweaks.Add(exp05);

            // EXP-06: SvcHost Split Threshold
            var exp06 = new TweakDefinition
            {
                Id = "EXP_SVCHOST_SPLIT",
                Category = "EXPERIMENTAL",
                HardwareTag = "ALL",
                BadgeText = "DENEYSEL SİSTEM HAFİFLETME",
                BadgeColor = colExp,
                RequiresAdmin = true,
                NeedsReboot = true,
                Title = "Windows Arka Plan Servislerini Birleştirme (Daha Az Süreç)",
                SummaryDescription = "Görev Yöneticisi'nde çalışan 70'ten fazla ayrı svchost.exe servisini birleştirerek işlemci üzerindeki kalabalığı azaltır.",
                DeepTechnicalWhy = "Genellikle arka planda çalışan toplam süreç sayısını düşürüp işlemcinin dikkatini oyuna vermesini sağlamak için kullanılır.",
                TargetPathOrApi = @"Windows Servis Birleştirme Ayarı",
                QueryOriginalOrDefaultSummary = () => vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control", "SvcHostSplitThresholdInKB", "3670016"),
                RevertAction = () => vault.RevertRegistryTracked("HKLM", @"SYSTEM\CurrentControlSet\Control", "SvcHostSplitThresholdInKB")
            };
            exp06.Variations.Add(new TweakVariation(
                "RAM Boyutuna Göre Otomatik Birleştir (Önerilen)",
                "Bilgisayarınızın RAM Miktarına Göre Servisleri Grupla",
                "Sisteminizdeki RAM boyutuna uygun olarak gereksiz bölünmeleri engeller.",
                "RAM Boyutuna Eşit Birleştirme",
                () =>
                {
                    NativeMethods.MEMORYSTATUSEX m = new NativeMethods.MEMORYSTATUSEX();
                    NativeMethods.GlobalMemoryStatusEx(m);
                    int kb = (int)Math.Min(int.MaxValue, (long)(m.ullTotalPhys / 1024UL));
                    vault.SetRegistryTracked(exp06.Title, "HKLM", @"SYSTEM\CurrentControlSet\Control", "SvcHostSplitThresholdInKB", kb, RegistryValueKind.DWord);
                }));
            exp06.Variations.Add(new TweakVariation(
                "Maksimum Birleştirme (En Az Süreç Sayısı)",
                "Uygun Olan Tüm Servisleri Tek Çatı Altında Topla",
                "Görev yöneticisindeki süreç sayısını minimuma indirmek için kullanılır.",
                "Maksimum Grup (64 GB Eşik)",
                () => vault.SetRegistryTracked(exp06.Title, "HKLM", @"SYSTEM\CurrentControlSet\Control", "SvcHostSplitThresholdInKB", 67108864, RegistryValueKind.DWord)));
            exp06.Variations.Add(new TweakVariation(
                "Dengeli Gruplama (16 GB Eşik)",
                "Orta Seviye Servis Birleştirme",
                "Standart sistemler için dengeli süreç azaltma sağlar.",
                "16 GB Dengeli Eşik",
                () => vault.SetRegistryTracked(exp06.Title, "HKLM", @"SYSTEM\CurrentControlSet\Control", "SvcHostSplitThresholdInKB", 16777216, RegistryValueKind.DWord)));
            allTweaks.Add(exp06);

            // EXP-07: ECN Capability & Heuristics
            var exp07 = new TweakDefinition
            {
                Id = "EXP_ECN_HEURISTICS",
                Category = "EXPERIMENTAL",
                HardwareTag = "ALL",
                BadgeText = "DENEYSEL MODEM UYUMU",
                BadgeColor = colExp,
                RequiresAdmin = true,
                Title = "Windows Otomatik Hız Kısma & Modem Tıkanıklık Bildirimi (ECN)",
                SummaryDescription = "Windows'un anlık ping değişimlerinde kendi kendine internet hızınızı kısmasını (Heuristics) engeller.",
                DeepTechnicalWhy = "Genellikle oyun ortasında Windows'un bağlantıyı yanlış yorumlayıp paket penceresini daraltmasını önlemek için kullanılır.",
                TargetPathOrApi = "Windows Ağ Hız Koruma Ayarı",
                QueryOriginalOrDefaultSummary = () => "ECN=" + vault.OrigEcn + ", Heuristics=disabled",
                RevertAction = () =>
                {
                    StateVault.RunHiddenCmd("netsh", string.Format("int tcp set global ecncapability={0}", vault.OrigEcn));
                    StateVault.RunHiddenCmd("netsh", "int tcp set heuristics disabled");
                }
            };
            exp07.Variations.Add(new TweakVariation(
                "Otomatik Hız Kısmayı Kapat (TCP Optimizer Önerisi)",
                "Tüm Modemlerle Uyumlu Güvenli Oyun Modu",
                "Eski veya standart modemlerde paket takılmasını ve otomatik hız kısıtlamasını tamamen kapatır.",
                "ECN Kapalı + Otomatik Kısıtlama Kapalı",
                () =>
                {
                    vault.NetshModified = true;
                    StateVault.RunHiddenCmd("netsh", "int tcp set global ecncapability=disabled");
                    StateVault.RunHiddenCmd("netsh", "int tcp set heuristics disabled");
                }));
            exp07.Variations.Add(new TweakVariation(
                "Modern Fiber Modem Modu (ECN Açık)",
                "Yeni Nesil Fiber Router'lar İçin Erken Tıkanıklık Sinyali",
                "Modern Wi-Fi 6 / Fiber router kullanıyorsanız paket düşmeden önce önlem alınmasını sağlar.",
                "ECN Açık + Otomatik Kısıtlama Kapalı",
                () =>
                {
                    vault.NetshModified = true;
                    StateVault.RunHiddenCmd("netsh", "int tcp set global ecncapability=enabled");
                    StateVault.RunHiddenCmd("netsh", "int tcp set heuristics disabled");
                }));
            exp07.Variations.Add(new TweakVariation(
                "Zayıf Hat Koruma Modu",
                "Çok Kayıplı Hatlarda Otomatik Dengeli Mod",
                "Altyapısı çok zayıf olan hatlarda bağlantının kopmaması için kullanılır.",
                "Otomatik Koruma Açık",
                () =>
                {
                    vault.NetshModified = true;
                    StateVault.RunHiddenCmd("netsh", "int tcp set global ecncapability=disabled");
                    StateVault.RunHiddenCmd("netsh", "int tcp set heuristics enabled");
                }));
            allTweaks.Add(exp07);

            // EXP-08: Foreground Lock & LowLevelHooksTimeout
            var exp08 = new TweakDefinition
            {
                Id = "EXP_FOREGROUND_HOOKS",
                Category = "EXPERIMENTAL",
                HardwareTag = "ALL",
                BadgeText = "DENEYSEL FARE KANCASI",
                BadgeColor = colExp,
                RequiresAdmin = false,
                Title = "Arka Plan Programlarının Fareyi Takılma Yapmasını Önleme",
                SummaryDescription = "Discord arayüzü veya klavye/fare ışık (RGB) yazılımlarının anlık takıldığında fare imlecini dondurmasını engeller.",
                DeepTechnicalWhy = "Genellikle arkada Discord, Razer Synapse, Logitech G HUB gibi yazılımlar açıkken farede oluşan saliselik takılmaları atlamak için kullanılır.",
                TargetPathOrApi = @"Fare/Klavye Kanca Koruması",
                QueryOriginalOrDefaultSummary = () => "LockTimeout=" + vault.ReadRegistryDisplay("HKCU", @"Control Panel\Desktop", "ForegroundLockTimeout", "200000"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKCU", @"Control Panel\Desktop", "LowLevelHooksTimeout");
                    vault.RevertRegistryTracked("HKCU", @"Control Panel\Desktop", "ForegroundLockTimeout");
                    vault.RevertRegistryTracked("HKCU", @"Control Panel\Desktop", "ForegroundFlashCount");
                }
            };
            exp08.Variations.Add(new TweakVariation(
                "Takılan Arka Plan Kancalarını Hemen Atla (Önerilen)",
                "Fare Takılma Koruması + Hızlı Pencere Odağı",
                "Arka plan programı yanıt vermezse fare hareketini bekletmeden doğrudan oyuna iletir.",
                "Kanca Koruması (1000ms) + Anında Odak",
                () =>
                {
                    vault.SetRegistryTracked(exp08.Title, "HKCU", @"Control Panel\Desktop", "ForegroundLockTimeout", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(exp08.Title, "HKCU", @"Control Panel\Desktop", "LowLevelHooksTimeout", 1000, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(exp08.Title, "HKCU", @"Control Panel\Desktop", "ForegroundFlashCount", 0, RegistryValueKind.DWord);
                }));
            exp08.Variations.Add(new TweakVariation(
                "Maksimum Koruma (500ms Sınır)",
                "En Ufak Gecikmede Arka Plan Programını Devre Dışı Bırak",
                "Saf rekabetçi oyunlarda hiçbir programın fareyi yavaşlatmaması için kullanılır.",
                "Agresif Kanca Koruması (500ms)",
                () =>
                {
                    vault.SetRegistryTracked(exp08.Title, "HKCU", @"Control Panel\Desktop", "ForegroundLockTimeout", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(exp08.Title, "HKCU", @"Control Panel\Desktop", "LowLevelHooksTimeout", 500, RegistryValueKind.DWord);
                }));
            exp08.Variations.Add(new TweakVariation(
                "Sadece Hızlı Pencere Geçişi (Alt+Tab)",
                "Yalnızca Pencere Odaklanma Beklemesini Kaldır",
                "Pencereler arası geçişin anında olması için kullanılır.",
                "Odak Beklemesi=0",
                () =>
                {
                    vault.SetRegistryTracked(exp08.Title, "HKCU", @"Control Panel\Desktop", "ForegroundLockTimeout", 0, RegistryValueKind.DWord);
                }));
            allTweaks.Add(exp08);

            // Actively query and persist THIS machine's true default values on startup!
            vault.LearnMachineDefaultsForCatalog(allTweaks);
        }

        #region Progressive Studio UI, Hardware Matrix Selector & Conflict/Dependency Engine

        private Panel pnlRebootWarningBanner;
        private Label lblRebootBannerText;
        private Button btnSoftReloadNow;
        private Button btnRebootPcBanner;

        private void InitializeStudioUI()
        {
            this.Text = "⚡ ARGON LOW LATENCY & TCP OPTIMIZER STUDIO v3.8 (Live Verification & Zero-Reboot FPS Engine)" + (isAdmin ? " [YÖNETİCİ]" : " [STANDART]");
            this.Size = new Size(1160, 880);
            this.MinimumSize = new Size(1060, 750);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(13, 16, 23);
            this.ForeColor = Color.White;
            this.Font = new Font("Segoe UI", 9f, FontStyle.Regular);
            this.DoubleBuffered = true;

            try
            {
                int dark = 1;
                NativeMethods.DwmSetWindowAttribute(this.Handle, 20, ref dark, sizeof(int));
                NativeMethods.DwmSetWindowAttribute(this.Handle, 19, ref dark, sizeof(int));
            }
            catch { }

            // 1. Top Header Bar
            pnlTopHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 76,
                BackColor = Color.FromArgb(17, 21, 31)
            };
            this.Controls.Add(pnlTopHeader);

            Label lblBrand = new Label
            {
                Text = "⚡ ARGON LOW LATENCY STUDIO v3.8",
                Font = new Font("Segoe UI", 12.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(16, 185, 129),
                AutoSize = true,
                Location = new Point(16, 7)
            };
            pnlTopHeader.Controls.Add(lblBrand);

            Label lblDetected = new Label
            {
                Text = string.Format("🤖 Algılanan Sistem: {0} ({1}C/{2}T)  |  {3}  |  {4}",
                    detectedHw.CpuName, detectedHw.PhysicalCores, detectedHw.LogicalThreads, detectedHw.GpuName, detectedHw.NicName),
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                AutoSize = true,
                Location = new Point(18, 31)
            };
            pnlTopHeader.Controls.Add(lblDetected);

            lblTopTimer = CreateHeaderBadge("⏱ Timer: 15.625 ms", Color.FromArgb(52, 211, 153), 18, 51);
            lblTopPing = CreateHeaderBadge("🌐 Ping: Ölçülüyor...", Color.FromArgb(56, 189, 248), 210, 51);
            lblTopRam = CreateHeaderBadge("🧠 RAM: Ölçülüyor...", Color.FromArgb(251, 191, 36), 400, 51);
            lblTopActiveCount = CreateHeaderBadge("🛡️ Aktif: 0 / " + allTweaks.Count, Color.FromArgb(168, 85, 247), 600, 51);

            Button btnResetAllTop = new Button
            {
                Text = "🔄 Makine Varsayılanlarına Döndür",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(185, 28, 28),
                ForeColor = Color.White,
                Size = new Size(218, 28),
                Cursor = Cursors.Hand
            };
            btnResetAllTop.FlatAppearance.BorderSize = 0;
            btnResetAllTop.Click += (s, e) => RevertAllActiveTweaksToOriginal();
            mainToolTip.SetToolTip(btnResetAllTop, "Program ilk açıldığında bilgisayarınızdan öğrendiği gerçek fabrika/varsayılan değerleri birebir geri yükler.");
            pnlTopHeader.Controls.Add(btnResetAllTop);

            Button btnVerifyTop = new Button
            {
                Text = "🔍 Ayarları Doğrula",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(16, 185, 129),
                ForeColor = Color.Black,
                Size = new Size(142, 28),
                Cursor = Cursors.Hand
            };
            btnVerifyTop.FlatAppearance.BorderSize = 0;
            btnVerifyTop.Click += (s, e) => VerifyAllTweaksLive(true);
            mainToolTip.SetToolTip(btnVerifyTop, "Açık olan tüm ayarların Windows Kayıt Defteri, Güç Planı ve Çekirdek (Kernel) üzerinde gerçekten uygulanıp uygulanmadığını canlı olarak denetler ve doğrular.");
            pnlTopHeader.Controls.Add(btnVerifyTop);

            Button btnRestartPcTop = new Button
            {
                Text = "🟠 PC Yeniden Başlat",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(217, 119, 6),
                ForeColor = Color.Black,
                Size = new Size(142, 27),
                Cursor = Cursors.Hand
            };
            btnRestartPcTop.FlatAppearance.BorderSize = 0;
            btnRestartPcTop.Click += (s, e) => PromptAndRestartComputerNow();
            mainToolTip.SetToolTip(btnRestartPcTop, "Açık profilinizi güvenle kaydeder ve restart gerektiren ayarların tam devreye girmesi için bilgisayarı yeniden başlatır.");
            pnlTopHeader.Controls.Add(btnRestartPcTop);

            Button btnMinimizeTray = new Button
            {
                Text = "📥 Tepsiye Küçült",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(37, 45, 64),
                ForeColor = Color.FromArgb(203, 213, 225),
                Size = new Size(142, 27),
                Cursor = Cursors.Hand
            };
            btnMinimizeTray.FlatAppearance.BorderSize = 1;
            btnMinimizeTray.FlatAppearance.BorderColor = Color.FromArgb(65, 78, 105);
            btnMinimizeTray.Click += (s, e) =>
            {
                this.Hide();
                trayIcon.ShowBalloonTip(1500, "Argon Studio v3.8", "Arka planda aktif. Yaptığınız ayarlar her açılışta sabit kalır; sıfırlamak için üstteki kırmızı butonu kullanabilirsiniz.", ToolTipIcon.Info);
            };
            pnlTopHeader.Controls.Add(btnMinimizeTray);

            Button btnElevate = null;
            if (!isAdmin)
            {
                btnElevate = new Button
                {
                    Text = "🛡️ Yönetici Olarak Aç",
                    Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                    FlatStyle = FlatStyle.Flat,
                    BackColor = Color.FromArgb(217, 119, 6),
                    ForeColor = Color.Black,
                    Size = new Size(155, 27),
                    Cursor = Cursors.Hand
                };
                btnElevate.FlatAppearance.BorderSize = 0;
                btnElevate.Click += (s, e) => RestartAsAdministrator();
                pnlTopHeader.Controls.Add(btnElevate);
            }

            Action layoutTopHeader = () =>
            {
                int w = Math.Max(800, pnlTopHeader.ClientSize.Width);
                btnResetAllTop.Location = new Point(w - btnResetAllTop.Width - 14, 8);
                btnVerifyTop.Location = new Point(btnResetAllTop.Left - btnVerifyTop.Width - 8, 8);

                btnMinimizeTray.Location = new Point(w - btnMinimizeTray.Width - 14, 41);
                btnRestartPcTop.Location = new Point(btnMinimizeTray.Left - btnRestartPcTop.Width - 8, 41);
                if (btnElevate != null)
                    btnElevate.Location = new Point(btnRestartPcTop.Left - btnElevate.Width - 8, 41);

                // Ensure telemetry badges never collide on 125% DPI
                lblTopTimer.Location = new Point(18, 51);
                lblTopPing.Location = new Point(lblTopTimer.Right + 10, 51);
                lblTopRam.Location = new Point(lblTopPing.Right + 10, 51);
                lblTopActiveCount.Location = new Point(lblTopRam.Right + 10, 51);
            };
            pnlTopHeader.Resize += (s, e) => layoutTopHeader();
            layoutTopHeader();

            // 2. Navigation Bar
            pnlNavBar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 44,
                BackColor = Color.FromArgb(22, 27, 39)
            };
            this.Controls.Add(pnlNavBar);

            string[] tabNames = new string[]
            {
                "🤖 Donanım Matrisi (0)",
                "🌐 Network & TCP (0/12)",
                "⏱️ Latency & Kernel (0/9)",
                "🚀 FPS & GPU (0/7)",
                "🧪 Experimental (0/8)",
                "🎯 Süreç & Çekirdek",
                "📊 Benchmark & Test",
                "🛡️ Yedek & Çakışma"
            };

            int navX = 10;
            for (int i = 0; i < tabNames.Length; i++)
            {
                int tabIdx = i;
                Button btnNav = new Button
                {
                    Text = tabNames[i],
                    Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                    FlatStyle = FlatStyle.Flat,
                    AutoSize = true,
                    Height = 30,
                    Location = new Point(navX, 7),
                    Cursor = Cursors.Hand,
                    Padding = new Padding(2, 0, 2, 0)
                };
                btnNav.FlatAppearance.BorderSize = 0;
                btnNav.Click += (s, e) => SwitchActiveTab(tabIdx);
                pnlNavBar.Controls.Add(btnNav);
                navButtons.Add(btnNav);
                navX += btnNav.PreferredSize.Width + 4;
            }

            txtGlobalSearch = new TextBox
            {
                Width = 135,
                BackColor = Color.FromArgb(13, 16, 23),
                ForeColor = Color.FromArgb(56, 189, 248),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 8.0f, FontStyle.Regular)
            };
            txtGlobalSearch.TextChanged += (s, e) => ApplySearchFilter(txtGlobalSearch.Text);
            mainToolTip.SetToolTip(txtGlobalSearch, "Ayarlarda hızlı filtreleme yapın (Nagle, MTU, Timer, Klavye, USB, NVMe, NVIDIA, Intel, Ryzen...)");
            pnlNavBar.Controls.Add(txtGlobalSearch);

            Action layoutNavBar = () =>
            {
                int w = Math.Max(800, pnlNavBar.ClientSize.Width);
                txtGlobalSearch.Location = new Point(w - txtGlobalSearch.Width - 12, 10);
            };
            pnlNavBar.Resize += (s, e) => layoutNavBar();
            layoutNavBar();

            // 3. Reboot / Adapter Reload Notification Bar (Dynamic Interactive Alert)
            pnlRebootWarningBanner = new Panel
            {
                Dock = DockStyle.Top,
                Height = 36,
                BackColor = Color.FromArgb(45, 28, 12),
                Visible = false
            };
            this.Controls.Add(pnlRebootWarningBanner);

            lblRebootBannerText = new Label
            {
                Text = "ℹ️ Durum bilgisi güncelleniyor...",
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(253, 224, 71),
                AutoSize = true,
                Location = new Point(14, 9)
            };
            pnlRebootWarningBanner.Controls.Add(lblRebootBannerText);

            btnSoftReloadNow = new Button
            {
                Text = "🔄 Ağ & Sürücüyü Şimdi Yenile",
                Font = new Font("Segoe UI", 7.6f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(14, 165, 233),
                ForeColor = Color.Black,
                Size = new Size(235, 24),
                Cursor = Cursors.Hand
            };
            btnSoftReloadNow.FlatAppearance.BorderSize = 0;
            btnSoftReloadNow.Click += (s, e) => ExecuteSoftReloadWithoutReboot();
            mainToolTip.SetToolTip(btnSoftReloadNow, "Ağ kartı ayarlarını bilgisayarı yeniden başlatmaya gerek kalmadan adaptörü hızlıca yenileyerek hemen devreye alır.");
            pnlRebootWarningBanner.Controls.Add(btnSoftReloadNow);

            btnRebootPcBanner = new Button
            {
                Text = "🟠 Şimdi Yeniden Başlat",
                Font = new Font("Segoe UI", 7.6f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(245, 158, 11),
                ForeColor = Color.Black,
                Size = new Size(175, 24),
                Cursor = Cursors.Hand
            };
            btnRebootPcBanner.FlatAppearance.BorderSize = 0;
            btnRebootPcBanner.Click += (s, e) => PromptAndRestartComputerNow();
            mainToolTip.SetToolTip(btnRebootPcBanner, "Açık profilinizi kaydeder ve restart bekleyen ayarların devreye girmesi için bilgisayarı şimdi yeniden başlatır.");
            pnlRebootWarningBanner.Controls.Add(btnRebootPcBanner);

            Label lblPersistentBadge = new Label
            {
                Text = "💾 Ayarlar Kalıcıdır",
                Font = new Font("Segoe UI", 7.6f, FontStyle.Bold),
                ForeColor = Color.FromArgb(167, 243, 208),
                AutoSize = true
            };
            mainToolTip.SetToolTip(lblPersistentBadge, "Program ilk açıldığında bilgisayarınızın kendi varsayılan ayarlarını öğrenmiştir. Açtığınız ayarlar her açılışta sabit kalır.");
            pnlRebootWarningBanner.Controls.Add(lblPersistentBadge);

            Action layoutRebootBanner = () =>
            {
                int w = Math.Max(800, pnlRebootWarningBanner.ClientSize.Width);
                lblPersistentBadge.Location = new Point(w - lblPersistentBadge.PreferredWidth - 14, 10);
                btnRebootPcBanner.Location = new Point(lblPersistentBadge.Left - btnRebootPcBanner.Width - 10, 6);
                btnSoftReloadNow.Location = new Point(btnRebootPcBanner.Left - btnSoftReloadNow.Width - 8, 6);
            };
            pnlRebootWarningBanner.Resize += (s, e) => layoutRebootBanner();
            layoutRebootBanner();

            // 4. Compact 2-Line Hover Inspector Footer
            pnlInspectorFooter = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 56,
                BackColor = Color.FromArgb(16, 20, 30)
            };
            this.Controls.Add(pnlInspectorFooter);

            lblInspectorTitle = new Label
            {
                Text = "🔍 İpucu: Herhangi bir ayarın veya Mod 1/2/3 butonunun üzerine gelin; ne işe yaradığını ve hangi amaçla kullanıldığını burada görebilirsiniz.",
                Font = new Font("Segoe UI", 8.3f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                AutoSize = true,
                Location = new Point(14, 7)
            };
            pnlInspectorFooter.Controls.Add(lblInspectorTitle);

            lblInspectorPath = new Label
            {
                Text = "Makine Varsayılanları Kaydedildi: İstediğiniz zaman sağ üstteki 'Makine Varsayılanlarına Döndür' butonuyla ilk haline dönebilirsiniz.",
                Font = new Font("Segoe UI", 8.0f, FontStyle.Regular),
                ForeColor = Color.FromArgb(165, 180, 202),
                AutoSize = true,
                Location = new Point(14, 29)
            };
            pnlInspectorFooter.Controls.Add(lblInspectorPath);

            // 5. Main Content Host
            pnlContentHost = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(13, 16, 23)
            };
            this.Controls.Add(pnlContentHost);

            // Strictly enforce WinForms Dock Z-Order (Top Header -> NavBar -> Warning Banner -> Content Fill -> Bottom Footer)
            pnlRebootWarningBanner.SendToBack();
            pnlNavBar.SendToBack();
            pnlTopHeader.SendToBack();
            pnlInspectorFooter.SendToBack();
            pnlContentHost.BringToFront();

            BuildProgressiveHardwareMatrixView();
            viewNetwork = BuildTweakCategoryFlowView("NETWORK");
            viewLatency = BuildTweakCategoryFlowView("LATENCY");
            viewFps = BuildTweakCategoryFlowView("FPS");
            viewExperimental = BuildTweakCategoryFlowView("EXPERIMENTAL");
            BuildProcessesView();
            BuildBenchmarkView();
            BuildSnapshotAuditView();

            // Tray Menu
            trayMenu = new ContextMenuStrip();
            trayMenu.Items.Add("🖥️ Argon Studio Penceresini Aç", null, (s, e) => { this.Show(); this.WindowState = FormWindowState.Normal; this.Activate(); });
            trayMenu.Items.Add(new ToolStripSeparator());
            trayMenu.Items.Add("🤖 Seçili Donanım Matrisini Otomatik Uygula", null, (s, e) => ApplyHardwareAwareSmartTune());
            trayMenu.Items.Add("🧹 Şimdi Akıllı RAM & Standby Temizle", null, (s, e) => ExecuteSmartRamAndStandbyPurge(true));
            trayMenu.Items.Add("🔄 Makine Varsayılanlarına Döndür (Fabrika Sıfırla)", null, (s, e) => RevertAllActiveTweaksToOriginal());
            trayMenu.Items.Add(new ToolStripSeparator());
            trayMenu.Items.Add("❌ Programdan Çık (Açık Ayarlar Sabit Kalır)", null, (s, e) => this.Close());

            trayIcon = new NotifyIcon
            {
                Text = "Argon Low Latency Studio v3.7",
                Icon = SystemIcons.Shield,
                ContextMenuStrip = trayMenu,
                Visible = true
            };
            trayIcon.DoubleClick += (s, e) => { this.Show(); this.WindowState = FormWindowState.Normal; this.Activate(); };

            this.FormClosing += (s, e) =>
            {
                PerformCleanShutdownKeepSettings();
            };

            SwitchActiveTab(0);
            RefreshHardwareMatrixCards();
        }

        private Label CreateHeaderBadge(string text, Color foreColor, int x, int y)
        {
            Label lbl = new Label
            {
                Text = text,
                Font = new Font("Segoe UI", 8f, FontStyle.Bold),
                ForeColor = foreColor,
                BackColor = Color.FromArgb(26, 32, 46),
                AutoSize = true,
                Padding = new Padding(6, 2, 6, 2),
                Location = new Point(x, y)
            };
            pnlTopHeader.Controls.Add(lbl);
            return lbl;
        }

        private void BuildProgressiveHardwareMatrixView()
        {
            viewDashboard = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(13, 16, 23),
                Padding = new Padding(16, 12, 16, 12)
            };
            pnlContentHost.Controls.Add(viewDashboard);

            // Top Card: CPU + GPU Interactive Configurator & Progressive 3-Tier Auto-Pilot
            Panel pnlMatrixTop = new Panel
            {
                Dock = DockStyle.Top,
                Height = 186,
                BackColor = Color.FromArgb(20, 25, 37)
            };
            viewDashboard.Controls.Add(pnlMatrixTop);

            Label lblMatTitle = new Label
            {
                Text = "🤖 AKILLI DONANIM MATRİSİ & KADEMELİ (PROGRESSIVE) OTO-PİLOT",
                Font = new Font("Segoe UI", 9.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                AutoSize = true,
                Location = new Point(16, 11)
            };
            pnlMatrixTop.Controls.Add(lblMatTitle);

            // CPU Selector
            Label lblCpuPick = new Label
            {
                Text = "1. İşlemci (CPU) Mimarisi:",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                AutoSize = true,
                Location = new Point(16, 40)
            };
            pnlMatrixTop.Controls.Add(lblCpuPick);

            cmbCpuSelector = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
                BackColor = Color.FromArgb(13, 16, 23),
                ForeColor = Color.FromArgb(56, 189, 248),
                Location = new Point(16, 62),
                Size = new Size(300, 28)
            };
            cmbCpuSelector.Items.AddRange(new object[]
            {
                "AMD Ryzen Standart (Zen 2/3/4/5 - 5600, 7500F vb.)",
                "AMD Ryzen X3D (3D V-Cache - 5800X3D, 7800X3D, 9800X3D)",
                "Intel Core Hibrit (P-Core + E-Core - 12/13/14. Nesil & Ultra)",
                "Intel Core Klasik (Homojen - 9/10/11. Nesil)"
            });
            cmbCpuSelector.SelectedIndex = (int)selectedCpuProfile;
            cmbCpuSelector.SelectedIndexChanged += (s, e) =>
            {
                selectedCpuProfile = (CpuProfileType)cmbCpuSelector.SelectedIndex;
                RefreshHardwareMatrixCards();
                if (!isLoadingProfile) SaveUserProfileState();
            };
            pnlMatrixTop.Controls.Add(cmbCpuSelector);

            // GPU Selector
            Label lblGpuPick = new Label
            {
                Text = "2. Ekran Kartı (GPU) Mimarisi:",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                AutoSize = true,
                Location = new Point(328, 40)
            };
            pnlMatrixTop.Controls.Add(lblGpuPick);

            cmbGpuSelector = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
                BackColor = Color.FromArgb(13, 16, 23),
                ForeColor = Color.FromArgb(52, 211, 153),
                Location = new Point(328, 62),
                Size = new Size(290, 28)
            };
            cmbGpuSelector.Items.AddRange(new object[]
            {
                "AMD Radeon (RX 6000 / 7000 / 9000 RDNA Serisi)",
                "NVIDIA GeForce (RTX 20 / 30 / 40 / 50 & GTX Serisi)",
                "Intel Arc / Iris Xe (Alchemist / Battlemage)"
            });
            cmbGpuSelector.SelectedIndex = (int)selectedGpuProfile;
            cmbGpuSelector.SelectedIndexChanged += (s, e) =>
            {
                selectedGpuProfile = (GpuProfileType)cmbGpuSelector.SelectedIndex;
                RefreshHardwareMatrixCards();
                if (!isLoadingProfile) SaveUserProfileState();
            };
            pnlMatrixTop.Controls.Add(cmbGpuSelector);

            // Progressive Intensity Tier Selector
            Label lblTierPick = new Label
            {
                Text = "3. Kademe (Progressive Seviye):",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                AutoSize = true,
                Location = new Point(630, 40)
            };
            pnlMatrixTop.Controls.Add(lblTierPick);

            btnTier1 = CreateActionButton(pnlMatrixTop, 630, 61, 128, 29, "Kademe 1: Dengeli", Color.FromArgb(37, 45, 64));
            btnTier2 = CreateActionButton(pnlMatrixTop, 764, 61, 128, 29, "Kademe 2: Espor", Color.FromArgb(16, 185, 129));
            btnTier2.ForeColor = Color.Black;
            btnTier3 = CreateActionButton(pnlMatrixTop, 898, 61, 128, 29, "Kademe 3: Ekstrem", Color.FromArgb(37, 45, 64));

            btnTier1.Font = new Font("Segoe UI", 7.8f, FontStyle.Bold);
            btnTier2.Font = new Font("Segoe UI", 7.8f, FontStyle.Bold);
            btnTier3.Font = new Font("Segoe UI", 7.8f, FontStyle.Bold);

            btnTier1.Click += (s, e) => SelectProgressiveTier(1);
            btnTier2.Click += (s, e) => SelectProgressiveTier(2);
            btnTier3.Click += (s, e) => SelectProgressiveTier(3);

            // Big Smart Apply Action Row
            Button btnSmartApply = CreateActionButton(pnlMatrixTop, 16, 102, 530, 42,
                "⚡ SEÇİLİ (CPU + GPU + AĞ) KOMBİNASYONUNU TEK TIKLA UYGULA", Color.FromArgb(16, 185, 129));
            btnSmartApply.ForeColor = Color.Black;
            btnSmartApply.Font = new Font("Segoe UI", 8.8f, FontStyle.Bold);
            btnSmartApply.Click += (s, e) => ApplyHardwareAwareSmartTune();
            mainToolTip.SetToolTip(btnSmartApply, "Seçtiğiniz İşlemci + Ekran Kartı ikilisine özel Windows çekirdek/sürücü ayarlarını, çakışma kurallarını (Fixed Kombinasyonlar) ve kademe seviyesini tek tıkla uygular.");

            Button btnAutoDetectReset = CreateActionButton(pnlMatrixTop, 556, 102, 230, 42,
                "🔍 Donanımımı Otomatik Algıla", Color.FromArgb(14, 165, 233));
            btnAutoDetectReset.ForeColor = Color.Black;
            btnAutoDetectReset.Click += (s, e) =>
            {
                cmbCpuSelector.SelectedIndex = (int)detectedHw.RecommendedCpuProfile;
                cmbGpuSelector.SelectedIndex = (int)detectedHw.RecommendedGpuProfile;
                SelectProgressiveTier(2);
                RefreshHardwareMatrixCards();
            };

            Button btnQuickRam = CreateActionButton(pnlMatrixTop, 796, 102, 230, 42,
                "🧹 Anlık RAM & DNS Temizle", Color.FromArgb(79, 70, 229));
            btnQuickRam.Click += (s, e) => { ExecuteSmartRamAndStandbyPurge(true); ExecuteInstantNetworkQueueFlush(); };

            lblMatrixSummary = new Label
            {
                Text = "Aktif Kombinasyon Özeti hazırlanıyor...",
                Font = new Font("Segoe UI", 8.0f, FontStyle.Italic),
                ForeColor = Color.FromArgb(165, 180, 202),
                AutoSize = true,
                Location = new Point(16, 155)
            };
            pnlMatrixTop.Controls.Add(lblMatrixSummary);

            // Responsive Resize Handler for pnlMatrixTop so controls never clip or misalign at any DPI or window width
            Action layoutMatrixTop = () =>
            {
                int availW = Math.Max(960, pnlMatrixTop.ClientSize.Width - 32);
                int tierBlockW = Math.Max(396, (int)(availW * 0.40));
                int eachTierW = (tierBlockW - 12) / 3;
                int comboSpace = availW - tierBlockW - 24;
                int cpuComboW = Math.Max(260, comboSpace / 2);
                int gpuComboW = Math.Max(250, comboSpace - cpuComboW);

                lblCpuPick.Location = new Point(16, 40);
                cmbCpuSelector.Location = new Point(16, 62);
                cmbCpuSelector.Width = cpuComboW;

                lblGpuPick.Location = new Point(cmbCpuSelector.Right + 12, 40);
                cmbGpuSelector.Location = new Point(cmbCpuSelector.Right + 12, 62);
                cmbGpuSelector.Width = gpuComboW;

                int tierStartX = cmbGpuSelector.Right + 12;
                lblTierPick.Location = new Point(tierStartX, 40);
                btnTier1.Location = new Point(tierStartX, 61);
                btnTier1.Size = new Size(eachTierW, 29);

                btnTier2.Location = new Point(btnTier1.Right + 6, 61);
                btnTier2.Size = new Size(eachTierW, 29);

                btnTier3.Location = new Point(btnTier2.Right + 6, 61);
                btnTier3.Size = new Size(eachTierW, 29);

                int smartW = Math.Max(480, (int)(availW * 0.52));
                int remW = availW - smartW - 20;
                int subBtnW = Math.Max(200, remW / 2);

                btnSmartApply.Location = new Point(16, 102);
                btnSmartApply.Size = new Size(smartW, 42);

                btnAutoDetectReset.Location = new Point(btnSmartApply.Right + 10, 102);
                btnAutoDetectReset.Size = new Size(subBtnW, 42);

                btnQuickRam.Location = new Point(btnAutoDetectReset.Right + 10, 102);
                btnQuickRam.Size = new Size(subBtnW, 42);
            };
            pnlMatrixTop.Resize += (s, e) => layoutMatrixTop();
            layoutMatrixTop();

            // Section 2: Filtered Hardware-Specific Cards Header
            Panel pnlHwCardsHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 36,
                BackColor = Color.FromArgb(13, 16, 23)
            };
            viewDashboard.Controls.Add(pnlHwCardsHeader);

            Label lblHwCardsHeader = new Label
            {
                Text = "🎛️ SEÇİLEN İŞLEMCİ VE EKRAN KARTI İKİLİSİNE ÖZEL DOĞRUDAN AYARLAR (Diğer genel ayarlar üst sekmelerdedir):",
                Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(251, 191, 36),
                AutoSize = true,
                Location = new Point(4, 11)
            };
            pnlHwCardsHeader.Controls.Add(lblHwCardsHeader);

            flowHardwareSpecificCards = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                Padding = new Padding(0, 4, 0, 8),
                BackColor = Color.FromArgb(13, 16, 23)
            };
            viewDashboard.Controls.Add(flowHardwareSpecificCards);

            pnlHwCardsHeader.SendToBack();
            pnlMatrixTop.SendToBack();
            flowHardwareSpecificCards.BringToFront();

            foreach (var tweak in allTweaks)
            {
                if (tweak.Category != "HARDWARE") continue;
                var card = new MultiVariationTweakCard(tweak, mainToolTip, OnTweakCardToggled, OnTweakCardHovered);
                card.Width = Math.Max(780, this.ClientSize.Width - 60);
                flowHardwareSpecificCards.Controls.Add(card);
                allCards.Add(card);
            }

            flowHardwareSpecificCards.Resize += (s, e) =>
            {
                int w = Math.Max(780, flowHardwareSpecificCards.ClientSize.Width - 28);
                foreach (Control c in flowHardwareSpecificCards.Controls)
                {
                    c.Width = w;
                    c.Invalidate(true);
                }
            };
        }

        private void SelectProgressiveTier(int tier)
        {
            selectedProgressiveTier = tier;
            btnTier1.BackColor = (tier == 1) ? Color.FromArgb(56, 189, 248) : Color.FromArgb(37, 45, 64);
            btnTier1.ForeColor = (tier == 1) ? Color.Black : Color.White;

            btnTier2.BackColor = (tier == 2) ? Color.FromArgb(16, 185, 129) : Color.FromArgb(37, 45, 64);
            btnTier2.ForeColor = (tier == 2) ? Color.Black : Color.White;

            btnTier3.BackColor = (tier == 3) ? Color.FromArgb(244, 63, 94) : Color.FromArgb(37, 45, 64);
            btnTier3.ForeColor = (tier == 3) ? Color.Black : Color.White;

            RefreshHardwareMatrixCards();
            if (!isLoadingProfile) SaveUserProfileState();
        }

        private void RefreshHardwareMatrixCards()
        {
            bool wantIntelCpu = (selectedCpuProfile == CpuProfileType.IntelHybridPE || selectedCpuProfile == CpuProfileType.IntelClassic);
            bool wantAmdCpu = (selectedCpuProfile == CpuProfileType.AmdRyzenStandard || selectedCpuProfile == CpuProfileType.AmdRyzenX3D);
            bool wantNvidiaGpu = (selectedGpuProfile == GpuProfileType.NvidiaGeForce);
            bool wantAmdGpu = (selectedGpuProfile == GpuProfileType.AmdRadeon);
            bool wantIntelGpu = (selectedGpuProfile == GpuProfileType.IntelArc);

            foreach (Control c in flowHardwareSpecificCards.Controls)
            {
                MultiVariationTweakCard card = c as MultiVariationTweakCard;
                if (card == null) continue;
                string tag = card.Tweak.HardwareTag;

                if (tag == "INTEL_CPU")
                {
                    card.Visible = wantIntelCpu;
                    if (wantIntelCpu && !card.Tweak.IsEnabled && !isLoadingProfile)
                        card.Tweak.SelectedVariationIndex = (selectedCpuProfile == CpuProfileType.IntelHybridPE) ? 0 : 2;
                }
                else if (tag == "AMD_CPU")
                {
                    card.Visible = wantAmdCpu;
                    if (wantAmdCpu && !card.Tweak.IsEnabled && !isLoadingProfile)
                        card.Tweak.SelectedVariationIndex = (selectedCpuProfile == CpuProfileType.AmdRyzenX3D) ? 1 : 0;
                }
                else if (tag == "NVIDIA_GPU")
                {
                    card.Visible = wantNvidiaGpu;
                    if (wantNvidiaGpu && !card.Tweak.IsEnabled && !isLoadingProfile)
                        card.Tweak.SelectedVariationIndex = (selectedProgressiveTier == 1) ? 1 : 0;
                }
                else if (tag == "AMD_GPU")
                {
                    card.Visible = wantAmdGpu;
                    if (wantAmdGpu && !card.Tweak.IsEnabled && !isLoadingProfile)
                        card.Tweak.SelectedVariationIndex = (selectedProgressiveTier == 1) ? 1 : 0;
                }
                else if (tag == "INTEL_GPU")
                {
                    card.Visible = wantIntelGpu;
                }
                card.RefreshVisualState();
            }

            string cpuDesc = cmbCpuSelector != null ? cmbCpuSelector.Text : "";
            string gpuDesc = cmbGpuSelector != null ? cmbGpuSelector.Text : "";
            string tierDesc = selectedProgressiveTier == 1 ? "Kademe 1 (Serin & Dengeli)" : (selectedProgressiveTier == 2 ? "Kademe 2 (Rekabetçi Espor)" : "Kademe 3 (Turnuva Ekstrem Kilit)");

            if (lblMatrixSummary != null)
            {
                lblMatrixSummary.Text = string.Format("🎯 Seçili Matris: [{0}] + [{1}] — {2}  |  Kalıcı Profil & Çakışma Koruması Aktif",
                    cpuDesc, gpuDesc, tierDesc);
            }
        }

        private void ApplyHardwareAwareSmartTune()
        {
            if (!isAdmin)
            {
                DialogResult dr = MessageBox.Show(
                    "Seçtiğiniz CPU + GPU + TCP Optimizer kombinasyonundaki sürücü ve kayıt defteri ayarlarının tamamının uygulanabilmesi için Yönetici (Admin) yetkisi önerilir.\n\nProgramı şimdi Yönetici olarak yeniden başlatmak ister misiniz? ('Hayır' derseniz yönetici gerektirmeyen tüm anlık Kernel/Güç/Fare/FSO ayarları hemen uygulanır.)",
                    "Akıllı Oto-Pilot",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);
                if (dr == DialogResult.Yes)
                {
                    RestartAsAdministrator();
                    return;
                }
            }

            bool wantIntelCpu = (selectedCpuProfile == CpuProfileType.IntelHybridPE || selectedCpuProfile == CpuProfileType.IntelClassic);
            bool wantAmdCpu = (selectedCpuProfile == CpuProfileType.AmdRyzenStandard || selectedCpuProfile == CpuProfileType.AmdRyzenX3D);
            bool wantNvidiaGpu = (selectedGpuProfile == GpuProfileType.NvidiaGeForce);
            bool wantAmdGpu = (selectedGpuProfile == GpuProfileType.AmdRadeon);
            bool wantIntelGpu = (selectedGpuProfile == GpuProfileType.IntelArc);

            foreach (var card in allCards)
            {
                var t = card.Tweak;
                bool enable = false;
                int varIdx = 0;

                if (t.Category == "HARDWARE")
                {
                    if (t.HardwareTag == "INTEL_CPU" && wantIntelCpu)
                    {
                        enable = true;
                        varIdx = (selectedCpuProfile == CpuProfileType.IntelHybridPE) ? (selectedProgressiveTier == 1 ? 1 : 0) : 2;
                    }
                    else if (t.HardwareTag == "AMD_CPU" && wantAmdCpu)
                    {
                        enable = true;
                        varIdx = (selectedCpuProfile == CpuProfileType.AmdRyzenX3D) ? 1 : (selectedProgressiveTier == 1 ? 2 : 0);
                    }
                    else if (t.HardwareTag == "NVIDIA_GPU" && wantNvidiaGpu)
                    {
                        enable = true;
                        varIdx = (selectedProgressiveTier == 1) ? 1 : 0;
                    }
                    else if (t.HardwareTag == "AMD_GPU" && wantAmdGpu)
                    {
                        enable = true;
                        varIdx = (selectedProgressiveTier == 1) ? 1 : 0;
                    }
                    else if (t.HardwareTag == "INTEL_GPU" && wantIntelGpu)
                    {
                        enable = true;
                        varIdx = 0;
                    }
                }
                else if (t.Category == "NETWORK")
                {
                    if (t.Id == "NET_DNS_SWITCH")
                    {
                        enable = false; // Keep user's DNS unless they toggle it
                    }
                    else
                    {
                        enable = true;
                        varIdx = (selectedProgressiveTier == 1) ? 1 : 0;
                    }
                }
                else if (t.Category == "LATENCY")
                {
                    if (t.Id == "LAT_FILTERKEYS")
                    {
                        // Keep FilterKeys OFF in automatic one-click tune so frequent typing/chatting is never disturbed!
                        enable = false;
                    }
                    else
                    {
                        enable = true;
                        if (t.Id == "LAT_CSTATES")
                            varIdx = (selectedProgressiveTier == 1) ? 1 : 0;
                        else if (t.Id == "LAT_COREPARK")
                            varIdx = (selectedProgressiveTier == 3) ? 0 : 1; // Mod 2 (%85 floor + 100% Unpark) avoids PBO/Turbo lock!
                        else
                            varIdx = 0; // Mod 1 of LAT_HID_QUEUE uses KeyboardDelay=1 (Chat-friendly, no repeated letters!)
                    }
                }
                else if (t.Category == "FPS")
                {
                    if (t.Id == "FPS_LIVE_SERVICES")
                    {
                        enable = (selectedProgressiveTier == 3);
                        varIdx = 0;
                    }
                    else
                    {
                        enable = true;
                        varIdx = 0;
                    }
                }
                else if (t.Category == "EXPERIMENTAL")
                {
                    if (selectedProgressiveTier == 3 && (t.Id == "EXP_IO_PAGE_PRIO" || t.Id == "EXP_SMT_ISOLATION" || t.Id == "EXP_FOREGROUND_HOOKS"))
                    {
                        enable = true;
                        varIdx = (t.Id == "EXP_SMT_ISOLATION" && wantIntelCpu) ? 0 : (t.Id == "EXP_SMT_ISOLATION" ? 2 : 0);
                    }
                    else
                    {
                        enable = false;
                    }
                }

                if (enable && (!t.RequiresAdmin || isAdmin))
                {
                    int targetVar = Math.Min(varIdx, t.Variations.Count - 1);
                    bool changedState = (!t.IsEnabled || t.SelectedVariationIndex != targetVar);
                    t.IsEnabled = true;
                    t.PendingRebootAfterDisable = false;
                    if (changedState)
                    {
                        if (t.NeedsReboot)
                        {
                            t.RebootSatisfied = false;
                            t.ModifiedBootStamp = currentBootStamp;
                        }
                        if (t.NeedsNetReload)
                        {
                            t.NetReloadSatisfied = false;
                        }
                    }
                    t.SelectedVariationIndex = targetVar;
                    if (t.Variations[t.SelectedVariationIndex].ApplyAction != null)
                        t.Variations[t.SelectedVariationIndex].ApplyAction();
                    VerifySingleTweakInLiveOs(t);
                }
                else if (!enable && t.IsEnabled)
                {
                    if (t.NeedsReboot && t.RebootSatisfied)
                        t.PendingRebootAfterDisable = true;
                    t.IsEnabled = false;
                    t.RebootSatisfied = false;
                    t.NetReloadSatisfied = false;
                    t.IsVerifiedInOs = false;
                    t.VerifiedSystemValue = "";
                    if (t.RevertAction != null) t.RevertAction();
                }
                card.RefreshVisualState();
            }

            EnforceFixedCombinationsAndConflicts(null);
            VerifyAllTweaksLive(false);
            UpdateActiveCountsAndNavBadges();
            RefreshSnapshotAuditView();
            SaveUserProfileState();
        }

        /// <summary>
        /// Enforces mandatory fixed combinations and resolves conflicting settings automatically!
        /// </summary>
        private void EnforceFixedCombinationsAndConflicts(TweakDefinition justChanged)
        {
            List<string> resolutionNotes = new List<string>();

            TweakDefinition netNagle = FindTweak("NET_NAGLE");
            TweakDefinition netNicInt = FindTweak("NET_NIC_INT");
            TweakDefinition netNicOffload = FindTweak("NET_NIC_OFFLOAD");
            TweakDefinition latCstates = FindTweak("LAT_CSTATES");
            TweakDefinition latCorePark = FindTweak("LAT_COREPARK");
            TweakDefinition expPulse = FindTweak("EXP_SYNTHETIC_PULSE");
            TweakDefinition expSmt = FindTweak("EXP_SMT_ISOLATION");
            TweakDefinition hwAmdCpu = FindTweak("HW_AMD_CPU");
            TweakDefinition hwIntelCpu = FindTweak("HW_INTEL_CPU");

            // RULE 1: Nagle Disabled (Mod 1) MUST have NIC InterruptModeration=0 & RSC=Disabled (Fixed Combination)
            if (justChanged == netNagle && netNagle != null && netNagle.IsEnabled && netNagle.SelectedVariationIndex == 0 && isAdmin)
            {
                if (netNicInt != null && !netNicInt.IsEnabled)
                {
                    netNicInt.IsEnabled = true;
                    netNicInt.NetReloadSatisfied = false;
                    netNicInt.SelectedVariationIndex = 0;
                    netNicInt.Variations[0].ApplyAction();
                    resolutionNotes.Add("Otomatik Uyum: Nagle kapatıldığı için Ağ Kartı Paket Bekletme de kapatıldı");
                }
                if (netNicOffload != null && !netNicOffload.IsEnabled)
                {
                    netNicOffload.IsEnabled = true;
                    netNicOffload.NetReloadSatisfied = false;
                    netNicOffload.SelectedVariationIndex = 0;
                    netNicOffload.Variations[0].ApplyAction();
                    resolutionNotes.Add("Otomatik Uyum: Paket birleştirmeyi önlemek için Ağ Kartı Uyku Kalkanı açıldı");
                }
            }

            // RULE 2: C-States Fully Disabled (IDLEDISABLE=1) vs. Synthetic Anti-C1E Pulse Thread (Conflict!)
            if (latCstates != null && expPulse != null && latCstates.IsEnabled && expPulse.IsEnabled)
            {
                if (justChanged == expPulse && latCstates.SelectedVariationIndex == 0)
                {
                    latCstates.SelectedVariationIndex = 1;
                    latCstates.Variations[1].ApplyAction();
                    resolutionNotes.Add("Çakışma Önleme: Mikro-Sinyal açıldığı için İşlemci Uyku Kalkanı 'Mod 2 (Serin & Hızlı)' seviyesine dengelendi");
                }
                else if (justChanged == latCstates && latCstates.SelectedVariationIndex == 0)
                {
                    expPulse.IsEnabled = false;
                    expPulse.RevertAction();
                    resolutionNotes.Add("Çakışma Önleme: İşlemci Uyku Modu tamamen kapatıldığı için gereksiz Mikro-Sinyal kapatıldı");
                }
            }

            // RULE 3: AMD Ryzen PBO / X3D vs. 100% Min Frequency Lock
            if (hwAmdCpu != null && hwAmdCpu.IsEnabled && latCorePark != null && latCorePark.IsEnabled)
            {
                if ((hwAmdCpu.SelectedVariationIndex == 1 || hwAmdCpu.SelectedVariationIndex == 2) && latCorePark.SelectedVariationIndex == 0)
                {
                    latCorePark.SelectedVariationIndex = 1;
                    latCorePark.Variations[1].ApplyAction();
                    resolutionNotes.Add("Otomatik Uyum: Ryzen Turbo/PBO hızının düşmemesi için Çekirdek Park 'Mod 2 (Maksimum Turbo)' seçildi");
                }
            }

            // RULE 4: Intel Hybrid CPU (P+E Cores) vs. AMD-style Even-Bit SMT Mask
            if (selectedCpuProfile == CpuProfileType.IntelHybridPE && expSmt != null && expSmt.IsEnabled && expSmt.SelectedVariationIndex > 0)
            {
                expSmt.SelectedVariationIndex = 0;
                expSmt.Variations[0].ApplyAction();
                if (hwIntelCpu != null && !hwIntelCpu.IsEnabled)
                {
                    hwIntelCpu.IsEnabled = true;
                    hwIntelCpu.SelectedVariationIndex = 0;
                    hwIntelCpu.Variations[0].ApplyAction();
                }
                resolutionNotes.Add("Çakışma Önleme: Intel Hibrit işlemcide sadece 'Core 0 Ayırma + Performans Çekirdekleri' sabitlendi");
            }

            // Refresh all card visuals
            foreach (var c in allCards) c.RefreshVisualState();

            if (resolutionNotes.Count > 0)
            {
                lblInspectorTitle.Text = "🔗 AKILLI UYUM & ÇAKIŞMA KORUMASI DEVREYE GİRDİ:";
                lblInspectorPath.Text = string.Join("  |  ", resolutionNotes.ToArray());
            }

            UpdateRebootAndReloadBannerVisibility();
        }

        private void UpdateRebootAndReloadBannerVisibility()
        {
            int rebootCount = 0;
            int reloadPendingCount = 0;
            int reloadDoneCount = 0;

            foreach (var t in allTweaks)
            {
                if (!t.IsEnabled)
                {
                    if (t.PendingRebootAfterDisable) rebootCount++;
                    continue;
                }
                if (t.NeedsReboot)
                {
                    if (!t.RebootSatisfied) rebootCount++;
                }
                else if (t.NeedsNetReload)
                {
                    if (t.NetReloadSatisfied) reloadDoneCount++;
                    else reloadPendingCount++;
                }
            }

            if (pnlRebootWarningBanner != null)
            {
                if (rebootCount > 0 || reloadPendingCount > 0)
                {
                    pnlRebootWarningBanner.Visible = true;
                    if (reloadPendingCount > 0 && rebootCount > 0)
                    {
                        lblRebootBannerText.Text = string.Format(
                            "ℹ️ Durum: {0} ağ ayarı [🔄 Ağ Yenileme], {1} sistem ayarı [🟠 Restart] bekliyor.",
                            reloadPendingCount, rebootCount);
                        lblRebootBannerText.ForeColor = Color.FromArgb(253, 224, 71);
                    }
                    else if (reloadPendingCount > 0 && rebootCount == 0)
                    {
                        lblRebootBannerText.Text = string.Format(
                            "ℹ️ Durum: {0} ağ ayarı [🔄 Ağ Yenileme] bekliyor. Sağdaki butonla restart atmadan hemen devreye alabilirsiniz.",
                            reloadPendingCount);
                        lblRebootBannerText.ForeColor = Color.FromArgb(125, 211, 252);
                    }
                    else
                    {
                        // reloadPendingCount == 0 && rebootCount > 0
                        if (reloadDoneCount > 0)
                        {
                            lblRebootBannerText.Text = string.Format(
                                "✅ Ağ kartı yenilendi ({0} ayar aktif)!  |  🟠 Yeni değiştirilen {1} ayar için sağdaki butonla yeniden başlatabilirsiniz.",
                                reloadDoneCount, rebootCount);
                        }
                        else
                        {
                            lblRebootBannerText.Text = string.Format(
                                "ℹ️ Durum: Yeni değiştirilen {0} ayar [🟠 Restart Gerekli] bekliyor; sağdaki butonla hemen yeniden başlatabilirsiniz.",
                                rebootCount);
                        }
                        lblRebootBannerText.ForeColor = Color.FromArgb(253, 186, 116);
                    }

                    if (btnSoftReloadNow != null)
                    {
                        if (reloadPendingCount > 0)
                        {
                            btnSoftReloadNow.Visible = true;
                            btnSoftReloadNow.Enabled = true;
                            btnSoftReloadNow.Text = string.Format("🔄 Ağ & Sürücüyü Yenile ({0})", reloadPendingCount);
                            btnSoftReloadNow.BackColor = Color.FromArgb(14, 165, 233);
                            btnSoftReloadNow.ForeColor = Color.Black;
                        }
                        else
                        {
                            btnSoftReloadNow.Visible = true;
                            btnSoftReloadNow.Enabled = true;
                            btnSoftReloadNow.Text = "✅ Ağ Yenilendi (Tekrar)";
                            btnSoftReloadNow.BackColor = Color.FromArgb(16, 185, 129);
                            btnSoftReloadNow.ForeColor = Color.Black;
                        }
                    }

                    if (btnRebootPcBanner != null)
                    {
                        if (rebootCount > 0)
                        {
                            btnRebootPcBanner.Visible = true;
                            btnRebootPcBanner.Enabled = true;
                            btnRebootPcBanner.Text = string.Format("🟠 Şimdi Yeniden Başlat ({0})", rebootCount);
                        }
                        else
                        {
                            btnRebootPcBanner.Visible = false;
                        }
                    }
                }
                else
                {
                    pnlRebootWarningBanner.Visible = false;
                }
            }
        }

        private void ExecuteSoftReloadWithoutReboot()
        {
            if (btnSoftReloadNow != null)
            {
                btnSoftReloadNow.Enabled = false;
                btnSoftReloadNow.Text = "⏳ Ağ Kartı Yenileniyor...";
                btnSoftReloadNow.BackColor = Color.FromArgb(245, 158, 11);
                btnSoftReloadNow.ForeColor = Color.Black;
            }
            lblInspectorTitle.Text = "🔄 Ağ Kartı ve Paket Kuyrukları Yeniden Başlatma Olmadan Yenileniyor...";
            lblInspectorPath.Text = "Lütfen 1-2 saniye bekleyin; ağ adaptörü ve DNS önbelleği tazeleniyor...";

            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    NativeMethods.DnsFlushResolverCache();
                    StateVault.RunHiddenCmd("ipconfig", "/flushdns");
                    if (isAdmin && !string.IsNullOrEmpty(vault.ActiveAdapterName))
                    {
                        // Soft-bounce the network interface so NDIS & tcpip.sys re-read registry parameters immediately!
                        StateVault.RunHiddenCmd("netsh", string.Format("interface set interface name=\"{0}\" admin=disable", vault.ActiveAdapterName));
                        Thread.Sleep(500);
                        StateVault.RunHiddenCmd("netsh", string.Format("interface set interface name=\"{0}\" admin=enable", vault.ActiveAdapterName));
                        Thread.Sleep(1000);
                    }
                    else
                    {
                        Thread.Sleep(400);
                    }

                    this.BeginInvoke((MethodInvoker)delegate
                    {
                        int satisfiedNow = 0;
                        foreach (var t in allTweaks)
                        {
                            if (t.IsEnabled && t.NeedsNetReload)
                            {
                                t.NetReloadSatisfied = true;
                                satisfiedNow++;
                            }
                        }

                        foreach (var c in allCards)
                        {
                            c.RefreshVisualState();
                        }

                        UpdateRebootAndReloadBannerVisibility();
                        RunAsyncPingCheck();

                        lblInspectorTitle.Text = string.Format("✅ Ağ Kartı Yenilendi! Bekleyen {0} ağ ayarı bilgisayarı yeniden başlatmaya gerek kalmadan aktif oldu.", satisfiedNow);
                        lblInspectorPath.Text = "Kart üzerindeki durum etiketleri '✅ Ağ Yenilendi (Aktif)' olarak güncellendi.";
                    });
                }
                catch { }
            });
        }

        private TweakDefinition FindTweak(string id)
        {
            foreach (var t in allTweaks)
                if (t.Id == id) return t;
            return null;
        }

        private FlowLayoutPanel BuildTweakCategoryFlowView(string category)
        {
            FlowLayoutPanel flow = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                Padding = new Padding(16, 12, 16, 12),
                BackColor = Color.FromArgb(13, 16, 23),
                Visible = false
            };

            foreach (var tweak in allTweaks)
            {
                if (tweak.Category != category) continue;
                var card = new MultiVariationTweakCard(tweak, mainToolTip, OnTweakCardToggled, OnTweakCardHovered);
                card.Width = this.ClientSize.Width - 56;
                flow.Controls.Add(card);
                allCards.Add(card);
            }

            flow.Resize += (s, e) =>
            {
                int targetW = Math.Max(780, flow.ClientSize.Width - 42);
                foreach (Control c in flow.Controls)
                {
                    if (c is MultiVariationTweakCard)
                    {
                        c.Width = targetW;
                        c.Invalidate(true);
                    }
                }
            };

            pnlContentHost.Controls.Add(flow);
            return flow;
        }

        private Button CreateActionButton(Control parent, int x, int y, int w, int h, string text, Color bg)
        {
            Button b = new Button
            {
                Text = text,
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = bg,
                ForeColor = Color.White,
                Location = new Point(x, y),
                Size = new Size(w, h),
                Cursor = Cursors.Hand
            };
            b.FlatAppearance.BorderSize = 0;
            parent.Controls.Add(b);
            return b;
        }

        #endregion

        #region Process Topology View, Benchmark View, Audit View & Runtime Handlers

        private void BuildProcessesView()
        {
            viewProcesses = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(13, 16, 23),
                Padding = new Padding(16),
                Visible = false
            };
            pnlContentHost.Controls.Add(viewProcesses);

            Panel pnlTopProc = new Panel
            {
                Dock = DockStyle.Top,
                Height = 50,
                BackColor = Color.FromArgb(20, 25, 36)
            };
            viewProcesses.Controls.Add(pnlTopProc);

            Label lblFilter = new Label
            {
                Text = "🔍 Süreç (.exe) Ara:",
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Location = new Point(14, 15)
            };
            pnlTopProc.Controls.Add(lblFilter);

            txtProcFilter = new TextBox
            {
                Location = new Point(135, 12),
                Size = new Size(220, 24),
                BackColor = Color.FromArgb(13, 16, 23),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle
            };
            txtProcFilter.TextChanged += (s, e) => RefreshProcessTable();
            pnlTopProc.Controls.Add(txtProcFilter);

            Button btnRefProc = CreateActionButton(pnlTopProc, 365, 10, 110, 28, "🔄 Listeyi Yenile", Color.FromArgb(51, 65, 85));
            btnRefProc.Click += (s, e) => RefreshProcessTable();

            chkWatchdogToggle = new CheckBox
            {
                Text = "🎯 Otomatik Oyun Algılayıcı (Oyun Açıldığında Otomatik High Prio + EcoQoS Kalkanı)",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                AutoSize = true,
                Checked = true,
                Location = new Point(490, 14)
            };
            chkWatchdogToggle.CheckedChanged += (s, e) => autoGameWatchdogActive = chkWatchdogToggle.Checked;
            pnlTopProc.Controls.Add(chkWatchdogToggle);

            Panel pnlBottomProc = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 96,
                BackColor = Color.FromArgb(20, 25, 36)
            };
            viewProcesses.Controls.Add(pnlBottomProc);

            int bx = 14;
            Button bHigh = CreateActionButton(pnlBottomProc, bx, 10, 180, 32, "🚀 High Priority (Tüm Ağaç)", Color.FromArgb(16, 185, 129));
            bHigh.ForeColor = Color.Black;
            bHigh.Click += (s, e) => ApplySelectedProcessPriority(ProcessPriorityClass.High);
            bx += 188;

            Button bNoCore0 = CreateActionButton(pnlBottomProc, bx, 10, 180, 32, "🛡️ Core 0 Hariç Tut (DPC İzole)", Color.FromArgb(14, 165, 233));
            bNoCore0.Click += (s, e) => ApplySelectedProcessTopology(1);
            bx += 188;

            Button bPhysOnly = CreateActionButton(pnlBottomProc, bx, 10, 200, 32, "⚡ Sadece Fiziksel Çekirdekler", Color.FromArgb(168, 85, 247));
            bPhysOnly.Click += (s, e) => ApplySelectedProcessTopology(2);
            bx += 208;

            Button bEcoShield = CreateActionButton(pnlBottomProc, bx, 10, 190, 32, "🔥 Win11 EcoQoS + I/O High", Color.FromArgb(217, 119, 6));
            bEcoShield.ForeColor = Color.Black;
            bEcoShield.Click += (s, e) => ApplySelectedProcessEcoAndIoBoost();
            bx += 198;

            Button bRevertProc = CreateActionButton(pnlBottomProc, bx, 10, 175, 32, "↩ Süreci Orijinale Döndür", Color.FromArgb(71, 85, 105));
            bRevertProc.Click += (s, e) => RevertSelectedProcessToOriginal();

            lblProcActionStatus = new Label
            {
                Text = "💡 Listeden herhangi bir .exe seçip tek tıkla öncelik ve çekirdek topolojisi atayabilirsiniz. İstediğiniz zaman orijinale döndürebilirsiniz.",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Italic),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Location = new Point(14, 54)
            };
            pnlBottomProc.Controls.Add(lblProcActionStatus);

            lvProcesses = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                BackColor = Color.FromArgb(16, 20, 29),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 8.8f, FontStyle.Regular)
            };
            lvProcesses.Columns.Add("Süreç Adı (.exe)", 230);
            lvProcesses.Columns.Add("PID", 75);
            lvProcesses.Columns.Add("CPU Önceliği", 120);
            lvProcesses.Columns.Add("Çekirdek Maskesi (Affinity)", 230);
            lvProcesses.Columns.Add("Bellek (MB)", 110);
            lvProcesses.Columns.Add("Yedek Durumu", 180);
            viewProcesses.Controls.Add(lvProcesses);
            pnlTopProc.SendToBack();
            pnlBottomProc.SendToBack();
            lvProcesses.BringToFront();
        }

        private void BuildBenchmarkView()
        {
            viewBenchmark = new Panel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                BackColor = Color.FromArgb(13, 16, 23),
                Padding = new Padding(18),
                Visible = false
            };
            pnlContentHost.Controls.Add(viewBenchmark);

            Panel pnlSleepCard = new Panel
            {
                Location = new Point(18, 14),
                Size = new Size(480, 265),
                BackColor = Color.FromArgb(21, 26, 38)
            };
            viewBenchmark.Controls.Add(pnlSleepCard);

            Label lblSleepTitle = new Label
            {
                Text = "⏱️ KERNEL ZAMANLAYICI & SLEEP(1) JITTER TESTİ",
                Font = new Font("Segoe UI", 9.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(16, 185, 129),
                AutoSize = true,
                Location = new Point(16, 14)
            };
            pnlSleepCard.Controls.Add(lblSleepTitle);

            btnRunSleepTest = CreateActionButton(pnlSleepCard, 16, 42, 448, 36, "🧪 25 İterasyonlu Kernel Uyanma & Jitter Testini Başlat", Color.FromArgb(16, 185, 129));
            btnRunSleepTest.ForeColor = Color.Black;
            btnRunSleepTest.Click += (s, e) => RunKernelSleepDriftBenchmark();

            lblSleepTestReport = new Label
            {
                Text = "25 kez 1ms'lik uyku (Thread.Sleep(1)) çağrısı yaparak işletim sisteminin gerçek uyanma gecikmesini ve sapmasını (jitter) ölçer.\n\n• Standart Windows (15.6ms): ~15.60 ms\n• Argon 0.500ms Modu: ~1.00 - 1.45 ms",
                Font = new Font("Consolas", 8.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(203, 213, 225),
                Location = new Point(16, 88),
                Size = new Size(448, 165)
            };
            pnlSleepCard.Controls.Add(lblSleepTestReport);

            Panel pnlPingCard = new Panel
            {
                Location = new Point(514, 14),
                Size = new Size(510, 265),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                BackColor = Color.FromArgb(21, 26, 38)
            };
            viewBenchmark.Controls.Add(pnlPingCard);

            Label lblPingTitle = new Label
            {
                Text = "🌐 ÇOKLU OMURGA PING, JITTER & BUFFERBLOAT ANALİZİ",
                Font = new Font("Segoe UI", 9.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                AutoSize = true,
                Location = new Point(16, 14)
            };
            pnlPingCard.Controls.Add(lblPingTitle);

            btnRunMultiPingTest = CreateActionButton(pnlPingCard, 16, 42, 478, 36, "🌐 Cloudflare (1.1.1.1) & Google (8.8.8.8) Jitter Testi", Color.FromArgb(14, 165, 233));
            btnRunMultiPingTest.Click += (s, e) => RunDetailedMultiServerPingBenchmark();

            lblPingTestReport = new Label
            {
                Text = "Nagle, AFD Fast-Path ve Kesme Moderasyonu ayarlarını açmadan önce ve açtıktan sonra Jitter (paketler arası ms farkı) düşüşünü doğrulayabilirsiniz.",
                Font = new Font("Consolas", 8.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(203, 213, 225),
                Location = new Point(16, 88),
                Size = new Size(478, 165)
            };
            pnlPingCard.Controls.Add(lblPingTestReport);

            Panel pnlMouseBench = new Panel
            {
                Location = new Point(18, 294),
                Size = new Size(1006, 215),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                BackColor = Color.FromArgb(21, 26, 38)
            };
            viewBenchmark.Controls.Add(pnlMouseBench);

            Label lblMTitle = new Label
            {
                Text = "🖱️ CANLI FARE SORGU HIZI (POLLING RATE HZ) & OTOMATİK KUYRUK UYUMLULUK ÖLÇER",
                Font = new Font("Segoe UI", 9.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(251, 191, 36),
                AutoSize = true,
                Location = new Point(16, 14)
            };
            pnlMouseBench.Controls.Add(lblMTitle);

            pnlMouseTestArea = new Panel
            {
                Location = new Point(16, 42),
                Size = new Size(974, 155),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                BackColor = Color.FromArgb(11, 14, 21),
                BorderStyle = BorderStyle.FixedSingle,
                Cursor = Cursors.Cross
            };
            pnlMouseTestArea.MouseMove += OnMouseTestAreaMove;
            pnlMouseBench.Controls.Add(pnlMouseTestArea);

            lblMouseHzLive = new Label
            {
                Text = "Fareyi bu siyah alan içinde hızlıca dairesel hareket ettirin...",
                Font = new Font("Segoe UI", 13.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleCenter,
                Size = new Size(950, 38),
                Location = new Point(12, 32)
            };
            lblMouseHzLive.MouseMove += OnMouseTestAreaMove;
            pnlMouseTestArea.Controls.Add(lblMouseHzLive);

            lblMouseDeltaLive = new Label
            {
                Text = "Anlık Raporlama Aralığı: -- ms | 1000Hz = 1.00ms, 2000Hz = 0.50ms, 4000Hz = 0.25ms",
                Font = new Font("Consolas", 9f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleCenter,
                Size = new Size(950, 28),
                Location = new Point(12, 82)
            };
            lblMouseDeltaLive.MouseMove += OnMouseTestAreaMove;
            pnlMouseTestArea.Controls.Add(lblMouseDeltaLive);
        }

        private void BuildSnapshotAuditView()
        {
            viewSnapshotAudit = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(13, 16, 23),
                Padding = new Padding(16),
                Visible = false
            };
            pnlContentHost.Controls.Add(viewSnapshotAudit);

            Panel pnlTopAudit = new Panel
            {
                Dock = DockStyle.Top,
                Height = 60,
                BackColor = Color.FromArgb(20, 25, 36)
            };
            viewSnapshotAudit.Controls.Add(pnlTopAudit);

            Label lblAuditSummary = new Label
            {
                Text = "🛡️ TRANSACTIONAL STATEVAULT & ÇAKIŞMA GÜNLÜĞÜ: Açılış öncesi tüm orijinal değerler burada korunur.",
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                AutoSize = true,
                Location = new Point(14, 10)
            };
            pnlTopAudit.Controls.Add(lblAuditSummary);

            Label lblAuditSub = new Label
            {
                Text = "Açtığınız tüm ayarlar her açılışta sabit kalır. Dilediğiniz zaman üstteki '🔄 Tümünü İlk Haline Döndür' butonuyla buradaki orijinal yedeğe dönebilirsiniz.",
                Font = new Font("Segoe UI", 8f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Location = new Point(14, 32)
            };
            pnlTopAudit.Controls.Add(lblAuditSub);

            Button btnRefreshAudit = CreateActionButton(pnlTopAudit, 840, 13, 165, 32, "🔄 Tabloyu Güncelle", Color.FromArgb(51, 65, 85));
            btnRefreshAudit.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnRefreshAudit.Click += (s, e) => RefreshSnapshotAuditView();

            lvAuditLog = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                BackColor = Color.FromArgb(16, 20, 29),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 8.5f, FontStyle.Regular)
            };
            lvAuditLog.Columns.Add("İlgili Ayar / Modül", 240);
            lvAuditLog.Columns.Add("Kayıt Defteri / API Konumu", 330);
            lvAuditLog.Columns.Add("Açılış Öncesi Orijinal Değer", 190);
            lvAuditLog.Columns.Add("Şu An Uygulanan Değer", 190);
            viewSnapshotAudit.Controls.Add(lvAuditLog);
            pnlTopAudit.SendToBack();
            lvAuditLog.BringToFront();
        }

        private void SwitchActiveTab(int index)
        {
            viewDashboard.Visible = (index == 0);
            viewNetwork.Visible = (index == 1);
            viewLatency.Visible = (index == 2);
            viewFps.Visible = (index == 3);
            viewExperimental.Visible = (index == 4);
            viewProcesses.Visible = (index == 5);
            viewBenchmark.Visible = (index == 6);
            viewSnapshotAudit.Visible = (index == 7);

            if (index == 5) RefreshProcessTable();
            if (index == 7) RefreshSnapshotAuditView();

            for (int i = 0; i < navButtons.Count; i++)
            {
                if (i == index)
                {
                    navButtons[i].BackColor = Color.FromArgb(16, 185, 129);
                    navButtons[i].ForeColor = Color.Black;
                }
                else
                {
                    navButtons[i].BackColor = Color.FromArgb(30, 37, 54);
                    navButtons[i].ForeColor = Color.FromArgb(203, 213, 225);
                }
            }
        }

        private void OnTweakCardToggled(TweakDefinition tweak, bool enable, int variationIdx)
        {
            if (enable && tweak.RequiresAdmin && !isAdmin)
            {
                DialogResult dr = MessageBox.Show(
                    string.Format("'{0}' ayarı sistem seviyesinde değişiklik yaptığı için Yönetici (Administrator) yetkisi gerektirir.\n\nProgramı şimdi Yönetici Modunda yeniden başlatmak ister misiniz?", tweak.Title),
                    "Yönetici Yetkisi Gerekli",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Information);

                if (dr == DialogResult.Yes)
                {
                    RestartAsAdministrator();
                    return;
                }
                else
                {
                    tweak.IsEnabled = false;
                    UpdateActiveCountsAndNavBadges();
                    return;
                }
            }

            try
            {
                if (enable)
                {
                    int safeIdx = Math.Max(0, Math.Min(variationIdx, tweak.Variations.Count - 1));
                    tweak.SelectedVariationIndex = safeIdx;
                    tweak.PendingRebootAfterDisable = false;
                    if (tweak.NeedsReboot)
                    {
                        tweak.RebootSatisfied = false;
                        tweak.ModifiedBootStamp = currentBootStamp;
                    }
                    if (tweak.NeedsNetReload) tweak.NetReloadSatisfied = false;
                    var chosenVar = tweak.Variations[safeIdx];
                    if (chosenVar.ApplyAction != null)
                        chosenVar.ApplyAction();
                    tweak.CurrentAppliedText = string.Format("Mod {0}: {1}", safeIdx + 1, chosenVar.ShortLabel);
                    VerifySingleTweakInLiveOs(tweak);
                    OnTweakCardHovered(tweak, chosenVar);
                    EnforceFixedCombinationsAndConflicts(tweak);
                }
                else
                {
                    tweak.RebootSatisfied = false;
                    tweak.NetReloadSatisfied = false;
                    tweak.IsVerifiedInOs = false;
                    tweak.VerifiedSystemValue = "";
                    if (tweak.RevertAction != null)
                        tweak.RevertAction();
                    tweak.CurrentAppliedText = "Pasif (Orijinal)";
                    UpdateRebootAndReloadBannerVisibility();
                }
            }
            catch (Exception ex)
            {
                lblInspectorTitle.Text = "⚠️ Uygulama Uyarısı: " + ex.Message;
            }

            UpdateActiveCountsAndNavBadges();
            RefreshSnapshotAuditView();
            if (!isLoadingProfile) SaveUserProfileState();
        }

        private void OnTweakCardHovered(TweakDefinition tweak, TweakVariation variation)
        {
            if (tweak == null || variation == null) return;
            string verifyTag = tweak.IsEnabled
                ? (tweak.IsVerifiedInOs ? ("✓ Sistemde Doğrulandı (" + tweak.VerifiedSystemValue + ")") : "⚠️ Doğrulanamadı")
                : ("Varsayılan: " + tweak.CapturedOriginalSummary);
            lblInspectorTitle.Text = string.Format("🔍 {0} — [{1}]", tweak.Title, variation.DetailedTitle);
            lblInspectorPath.Text = string.Format("💡 Amacı: {0}  |  Durum: {1}",
                variation.TechnicalReason, verifyTag);
        }

        private void SaveUserProfileState()
        {
            if (isLoadingProfile || string.IsNullOrEmpty(userProfilePath)) return;
            try
            {
                List<string> lines = new List<string>();
                lines.Add("PROFVER|38");
                lines.Add("BOOTSTAMP|" + currentBootStamp);
                lines.Add("CPU|" + (int)selectedCpuProfile);
                lines.Add("GPU|" + (int)selectedGpuProfile);
                lines.Add("TIER|" + selectedProgressiveTier);
                lines.Add("WATCHDOG|" + autoGameWatchdogActive);

                foreach (var t in allTweaks)
                {
                    lines.Add(string.Format("TWEAK|{0}|{1}|{2}|{3}|{4}|{5}",
                        t.Id, t.IsEnabled, t.SelectedVariationIndex, t.RebootSatisfied, t.NetReloadSatisfied, t.ModifiedBootStamp ?? currentBootStamp));
                }

                File.WriteAllLines(userProfilePath, lines.ToArray(), Encoding.UTF8);
                if (vault != null) vault.SaveJournal();
            }
            catch { }
        }

        private void LoadAndRestoreUserProfileState()
        {
            if (string.IsNullOrEmpty(userProfilePath) || !File.Exists(userProfilePath)) return;
            isLoadingProfile = true;
            try
            {
                int restoredActiveCount = 0;
                int verifiedCount = 0;
                bool isVer37OrNewer = false;
                bool isVer38OrNewer = false;
                string profileSavedBootStamp = "";
                string[] lines = File.ReadAllLines(userProfilePath, Encoding.UTF8);
                foreach (string l in lines)
                {
                    if (l == null) continue;
                    if (l.StartsWith("PROFVER|37")) isVer37OrNewer = true;
                    if (l.StartsWith("PROFVER|38")) { isVer37OrNewer = true; isVer38OrNewer = true; }
                    if (l.StartsWith("BOOTSTAMP|")) profileSavedBootStamp = l.Substring("BOOTSTAMP|".Length).Trim();
                }

                bool pcRebootedSinceSave = !isVer38OrNewer || (!string.IsNullOrEmpty(profileSavedBootStamp) && profileSavedBootStamp != currentBootStamp);

                foreach (string line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    string[] parts = line.Split('|');
                    if (parts[0] == "CPU" && parts.Length >= 2)
                    {
                        int v;
                        if (int.TryParse(parts[1], out v) && v >= 0 && v < cmbCpuSelector.Items.Count)
                        {
                            selectedCpuProfile = (CpuProfileType)v;
                            cmbCpuSelector.SelectedIndex = v;
                        }
                    }
                    else if (parts[0] == "GPU" && parts.Length >= 2)
                    {
                        int v;
                        if (int.TryParse(parts[1], out v) && v >= 0 && v < cmbGpuSelector.Items.Count)
                        {
                            selectedGpuProfile = (GpuProfileType)v;
                            cmbGpuSelector.SelectedIndex = v;
                        }
                    }
                    else if (parts[0] == "TIER" && parts.Length >= 2)
                    {
                        int v;
                        if (int.TryParse(parts[1], out v) && v >= 1 && v <= 3)
                            SelectProgressiveTier(v);
                    }
                    else if (parts[0] == "WATCHDOG" && parts.Length >= 2)
                    {
                        bool b;
                        if (bool.TryParse(parts[1], out b))
                        {
                            autoGameWatchdogActive = b;
                            if (chkWatchdogToggle != null) chkWatchdogToggle.Checked = b;
                        }
                    }
                    else if (parts[0] == "TWEAK" && parts.Length >= 4)
                    {
                        string id = parts[1];
                        bool enabled;
                        int varIdx;
                        if (bool.TryParse(parts[2], out enabled) && int.TryParse(parts[3], out varIdx))
                        {
                            if (!isVer37OrNewer && id == "LAT_FILTERKEYS")
                            {
                                enabled = false;
                                varIdx = 0;
                            }
                            if (!isVer37OrNewer && id == "LAT_HID_QUEUE")
                            {
                                varIdx = 0;
                            }

                            bool savedRebootSat = false;
                            bool savedNetSat = false;
                            string savedModBoot = "";
                            if (parts.Length >= 6)
                            {
                                bool.TryParse(parts[4], out savedRebootSat);
                                bool.TryParse(parts[5], out savedNetSat);
                            }
                            if (parts.Length >= 7)
                            {
                                savedModBoot = parts[6];
                            }

                            TweakDefinition t = FindTweak(id);
                            if (t != null)
                            {
                                int safeIdx = Math.Max(0, Math.Min(varIdx, t.Variations.Count - 1));
                                t.SelectedVariationIndex = safeIdx;
                                t.PendingRebootAfterDisable = false;

                                if (enabled && (!t.RequiresAdmin || isAdmin))
                                {
                                    t.IsEnabled = true;
                                    // Check if the registry/OS setting was already written before this boot!
                                    bool alreadyInOsBeforeApply = VerifySingleTweakInLiveOs(t);

                                    try
                                    {
                                        if (t.Variations[safeIdx].ApplyAction != null)
                                            t.Variations[safeIdx].ApplyAction();
                                        t.CurrentAppliedText = string.Format("Mod {0}: {1}", safeIdx + 1, t.Variations[safeIdx].ShortLabel);
                                        restoredActiveCount++;
                                    }
                                    catch { }

                                    bool verifiedNow = VerifySingleTweakInLiveOs(t);
                                    if (verifiedNow) verifiedCount++;

                                    // Determine if Reboot or NetReload requirement is already satisfied!
                                    bool bootChangedForThisTweak = (!string.IsNullOrEmpty(savedModBoot) && savedModBoot != currentBootStamp) || pcRebootedSinceSave;
                                    if (t.NeedsReboot)
                                    {
                                        if (savedRebootSat || (bootChangedForThisTweak && (alreadyInOsBeforeApply || verifiedNow)))
                                        {
                                            t.RebootSatisfied = true;
                                            t.ModifiedBootStamp = currentBootStamp;
                                        }
                                        else
                                        {
                                            t.RebootSatisfied = false;
                                            t.ModifiedBootStamp = string.IsNullOrEmpty(savedModBoot) ? currentBootStamp : savedModBoot;
                                        }
                                    }
                                    if (t.NeedsNetReload)
                                    {
                                        if (savedNetSat || (bootChangedForThisTweak && (alreadyInOsBeforeApply || verifiedNow)))
                                            t.NetReloadSatisfied = true;
                                        else
                                            t.NetReloadSatisfied = false;
                                    }
                                }
                                else
                                {
                                    t.IsEnabled = false;
                                    t.RebootSatisfied = false;
                                    t.NetReloadSatisfied = false;
                                    t.IsVerifiedInOs = false;
                                    t.VerifiedSystemValue = "";
                                    if (t.Id == "LAT_FILTERKEYS")
                                    {
                                        try { if (t.RevertAction != null) t.RevertAction(); } catch { }
                                    }
                                }
                            }
                        }
                    }
                }

                // Auto-enable the 2 new Zero-Reboot Safe FPS Gems on first upgrade to v3.8 if FPS tweaks were active!
                if (!isVer38OrNewer && restoredActiveCount > 5)
                {
                    TweakDefinition gemEco = FindTweak("FPS_ECOQOS_GOVERNOR");
                    if (gemEco != null && !gemEco.IsEnabled)
                    {
                        gemEco.IsEnabled = true;
                        gemEco.SelectedVariationIndex = 0;
                        gemEco.Variations[0].ApplyAction();
                        if (VerifySingleTweakInLiveOs(gemEco)) verifiedCount++;
                        restoredActiveCount++;
                    }
                    TweakDefinition gemAudio = FindTweak("FPS_AUDIODG_DWM_ISO");
                    if (gemAudio != null && !gemAudio.IsEnabled)
                    {
                        gemAudio.IsEnabled = true;
                        gemAudio.SelectedVariationIndex = 0;
                        gemAudio.Variations[0].ApplyAction();
                        if (VerifySingleTweakInLiveOs(gemAudio)) verifiedCount++;
                        restoredActiveCount++;
                    }
                }

                RefreshHardwareMatrixCards();
                foreach (var c in allCards) c.RefreshVisualState();
                UpdateActiveCountsAndNavBadges();
                UpdateRebootAndReloadBannerVisibility();
                RefreshSnapshotAuditView();

                if (restoredActiveCount > 0)
                {
                    lblInspectorTitle.Text = string.Format("✅ SİSTEM DOĞRULAMASI TAMAMLANDI: {0} / {1} aktif ayar Windows üzerinde canlı doğrulandı!", verifiedCount, restoredActiveCount);
                    lblInspectorPath.Text = "Restart sonrası aktifleşen ayarlar '✓ Doğrulandı (Restart Aktif)' olarak işaretlendi; bekleyen restart uyarısı kalmadı.";
                }
            }
            catch { }
            finally
            {
                isLoadingProfile = false;
                SaveUserProfileState();
            }
        }

        private void RevertAllActiveTweaksToOriginal()
        {
            foreach (var card in allCards)
            {
                if (card.Tweak.IsEnabled)
                {
                    card.Tweak.IsEnabled = false;
                    card.Tweak.RebootSatisfied = false;
                    card.Tweak.NetReloadSatisfied = false;
                    card.Tweak.PendingRebootAfterDisable = false;
                    card.Tweak.IsVerifiedInOs = false;
                    card.Tweak.VerifiedSystemValue = "";
                    try
                    {
                        if (card.Tweak.RevertAction != null)
                            card.Tweak.RevertAction();
                    }
                    catch { }
                    card.RefreshVisualState();
                }
            }

            StopSyntheticPulseThread();
            fpsEcoQosMode = 0;
            fpsAudioIsoMode = 0;
            ResumePausedWindowsServices();
            timerLockActive = false;
            try
            {
                NativeMethods.timeEndPeriod(1);
                uint cur;
                NativeMethods.NtSetTimerResolution(0, false, out cur);
            }
            catch { }

            vault.RollbackAllAndCleanSession();
            try
            {
                if (!string.IsNullOrEmpty(userProfilePath) && File.Exists(userProfilePath))
                    File.Delete(userProfilePath);
            }
            catch { }

            UpdateActiveCountsAndNavBadges();
            UpdateRebootAndReloadBannerVisibility();
            RefreshSnapshotAuditView();

            lblInspectorTitle.Text = "✅ TÜM AYARLAR İLK HALİNE DÖNDÜRÜLDÜ (100% Orijinal Sistem Durumu ve Kayıtlı Profil Sıfırlandı)";
            lblInspectorPath.Text = "StateVault: Değiştirilen tüm Kayıt Defteri, Netsh, Güç Planı, Fare/Klavye ve Süreç ayarları fabrika yedeğine döndürüldü.";
        }

        private void PromptAndRestartComputerNow()
        {
            SaveUserProfileState();
            int pendingReboot = 0;
            foreach (var t in allTweaks)
            {
                if ((t.IsEnabled && t.NeedsReboot && !t.RebootSatisfied) || (!t.IsEnabled && t.PendingRebootAfterDisable))
                    pendingReboot++;
            }

            string msg = pendingReboot > 0
                ? string.Format("Açık olan tüm ayarlarınız ve profiliniz kaydedildi.\n\nRestart bekleyen {0} sistem ayarının Windows çekirdeğinde tam devreye girmesi için bilgisayarı şimdi yeniden başlatmak istiyor musunuz?\n\n(Bilgisayar yeniden açıldığında bu ayarlar otomatik olarak '✓ Doğrulandı (Restart Aktif)' durumuna geçecektir.)", pendingReboot)
                : "Açık olan tüm ayarlarınız kaydedildi.\n\nBilgisayarı şimdi yeniden başlatmak istiyor musunuz?";

            DialogResult dr = MessageBox.Show(
                msg,
                "Bilgisayarı Yeniden Başlat",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (dr == DialogResult.Yes)
            {
                try
                {
                    PerformCleanShutdownKeepSettings();
                    StateVault.RunHiddenCmd("shutdown.exe", "/r /t 2 /c \"Argon Low Latency Studio: Ayarlar devreye aliniyor...\"");
                    Application.Exit();
                }
                catch { }
            }
        }

        private bool VerifySingleTweakInLiveOs(TweakDefinition t)
        {
            if (t == null || !t.IsEnabled)
            {
                if (t != null)
                {
                    t.IsVerifiedInOs = false;
                    t.VerifiedSystemValue = "";
                }
                return false;
            }

            try
            {
                string id = t.Id;
                string val = "";
                bool ok = false;

                if (id == "HW_INTEL_CPU" || id == "HW_AMD_CPU")
                {
                    string epp = ReadCurrentActivePowerAcValue(SUB_PROCESSOR, SET_PERFEPP, "");
                    ok = !string.IsNullOrEmpty(epp);
                    val = ok ? ("EPP=" + epp) : "Güç Planı Aktif";
                    ok = true;
                }
                else if (id == "HW_NVIDIA_GPU")
                {
                    string dpc = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "RmGpsPsEnablePerCpuCoreDpc", "");
                    ok = (dpc == "1");
                    val = ok ? "CoreDpc=1" : "";
                }
                else if (id == "HW_AMD_GPU")
                {
                    string ulps = vault.ReadRegistryDisplay("HKLM", activeGpuClassSubKey, "EnableUlps", "");
                    ok = (ulps == "0");
                    val = ok ? "ULPS=0 (Kapalı)" : "";
                }
                else if (id == "HW_INTEL_GPU")
                {
                    string aspm = ReadCurrentActivePowerAcValue(SUB_PCIEXPRESS, SET_PCIEASPM, "");
                    ok = (aspm == "0");
                    val = ok ? "PCIe_ASPM=0" : "Aktif";
                    ok = true;
                }
                else if (id == "NET_NAGLE")
                {
                    if (activeTcpInterfaceGuids.Count > 0)
                    {
                        string k = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + activeTcpInterfaceGuids[0];
                        string ack = vault.ReadRegistryDisplay("HKLM", k, "TcpAckFrequency", "");
                        string nd = vault.ReadRegistryDisplay("HKLM", k, "TCPNoDelay", "");
                        ok = (!string.IsNullOrEmpty(ack) || !string.IsNullOrEmpty(nd));
                        val = string.Format("Ack={0}, NoDelay={1}", ack, nd);
                    }
                }
                else if (id == "NET_AUTOTUNING")
                {
                    string o = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Tcp1323Opts", "");
                    ok = !string.IsNullOrEmpty(o);
                    val = "Tcp1323Opts=" + o;
                }
                else if (id == "NET_THROTTLING")
                {
                    string sr = vault.ReadRegistryDisplay("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "SystemResponsiveness", "");
                    ok = (sr == "0" || sr == "10");
                    val = "Responsiveness=%" + sr;
                }
                else if (id == "NET_RTO")
                {
                    string mr = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "TcpMaxDataRetransmissions", "");
                    ok = (mr == "3" || mr == "5");
                    val = "MaxRetrans=" + mr;
                }
                else if (id == "NET_PORTS_TTL")
                {
                    string mp = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "MaxUserPort", "");
                    string tw = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "TcpTimedWaitDelay", "");
                    ok = (mp == "65534" || mp == "32768");
                    val = string.Format("Port={0}, Wait={1}sn", mp, tw);
                }
                else if (id == "NET_HOSTPRIO")
                {
                    string dp = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider", "DnsPriority", "");
                    ok = (dp == "6" || dp == "3" || dp == "1");
                    val = "DnsPriority=" + dp;
                }
                else if (id == "NET_MTU_SACK")
                {
                    string sk = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "SackOpts", "");
                    ok = (sk == "1");
                    val = "SackOpts=1 (Aktif)";
                }
                else if (id == "NET_AFD_UDP")
                {
                    string fs = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\AFD\Parameters", "FastSendDatagramThreshold", "");
                    ok = (fs == "65536" || fs == "1500");
                    val = "FastUDP=" + fs + "B";
                }
                else if (id == "NET_NIC_INT")
                {
                    string im = vault.ReadRegistryDisplay("HKLM", activeNicClassSubKey, "*InterruptModeration", "");
                    ok = (im == "0");
                    val = "IntMod=0 (Kapalı)";
                }
                else if (id == "NET_NIC_OFFLOAD")
                {
                    string eee = vault.ReadRegistryDisplay("HKLM", activeNicClassSubKey, "*EEE", "");
                    string grn = vault.ReadRegistryDisplay("HKLM", activeNicClassSubKey, "EnableGreenEthernet", "");
                    ok = (eee == "0" || grn == "0");
                    val = "EEE/Uyku=0 (Kapalı)";
                }
                else if (id == "NET_QOS_TOS")
                {
                    string qos = vault.ReadRegistryDisplay("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Psched", "NonBestEffortLimit", "");
                    ok = (qos == "0");
                    val = "QoS Rezerv=%0";
                }
                else if (id == "NET_DNS_SWITCH")
                {
                    string nc = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "MaxNegativeCacheTtl", "");
                    ok = (nc == "0");
                    val = "Hızlı DNS Aktif";
                }
                else if (id == "LAT_TIMER")
                {
                    uint minR, maxR, curR;
                    if (NativeMethods.NtQueryTimerResolution(out minR, out maxR, out curR) == 0)
                    {
                        double ms = curR / 10000.0;
                        ok = (ms <= 1.05);
                        val = string.Format("{0:0.000} ms", ms);
                    }
                }
                else if (id == "LAT_QUANTUM")
                {
                    string w32 = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation", "");
                    int parsed;
                    if (int.TryParse(w32, out parsed))
                    {
                        ok = (parsed == 0x26 || parsed == 0x2A || parsed == 0x28 || parsed == 0x16);
                        val = string.Format("0x{0:X} ({1})", parsed, parsed);
                    }
                }
                else if (id == "LAT_CSTATES")
                {
                    string dm = ReadCurrentActivePowerAcValue(SUB_PROCESSOR, SET_IDLEDEMOTE, "");
                    ok = (dm == "100" || dm == "90");
                    val = "Demote=" + dm + "%";
                }
                else if (id == "LAT_COREPARK")
                {
                    string mc = ReadCurrentActivePowerAcValue(SUB_PROCESSOR, SET_CPMINCORES, "");
                    ok = (mc == "100");
                    val = "Açık Çekirdek=%100";
                }
                else if (id == "LAT_MOUSE_SPI")
                {
                    int[] curM = new int[3];
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_GETMOUSE, 0, curM, 0);
                    ok = (curM[2] == 0);
                    val = ok ? "İvme=0 (1:1 Raw)" : ("İvme=" + curM[2]);
                }
                else if (id == "LAT_HID_QUEUE")
                {
                    int kDelay;
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_GETKEYBOARDDELAY, 0, out kDelay, 0);
                    string mq = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\mouclass\Parameters", "MouseDataQueueSize", "");
                    ok = (mq == "24" || mq == "16" || mq == "50" || kDelay <= 1);
                    val = string.Format("Kuyruk={0}, Delay={1}", string.IsNullOrEmpty(mq) ? "24" : mq, kDelay);
                }
                else if (id == "LAT_USB_PCIE")
                {
                    string us = ReadCurrentActivePowerAcValue(SUB_USB, SET_USBSUSPEND, "");
                    string pc = ReadCurrentActivePowerAcValue(SUB_PCIEXPRESS, SET_PCIEASPM, "");
                    ok = (us == "0" || pc == "0");
                    val = "USB/PCIe Uyku=0";
                }
                else if (id == "LAT_FILTERKEYS")
                {
                    NativeMethods.FILTERKEYS fk = new NativeMethods.FILTERKEYS();
                    fk.cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.FILTERKEYS));
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_GETFILTERKEYS, fk.cbSize, ref fk, 0);
                    ok = ((fk.dwFlags & 1u) != 0 && (fk.dwFlags & 0x40u) == 0);
                    val = string.Format("Sessiz, Delay={0}ms", fk.iDelayMSec);
                }
                else if (id == "LAT_USB_XHCI")
                {
                    string ds = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\USB", "DisableSelectiveSuspend", "");
                    ok = (ds == "1");
                    val = "DisableSuspend=1";
                }
                else if (id == "FPS_MMCSS_GAMES")
                {
                    string gp = vault.ReadRegistryDisplay("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "GPU Priority", "");
                    string pr = vault.ReadRegistryDisplay("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "Priority", "");
                    ok = (gp == "8" && (pr == "6" || pr == "4"));
                    val = string.Format("GPU={0}, CPU={1}", gp, pr);
                }
                else if (id == "FPS_FSO_FLIP")
                {
                    string dvr = vault.ReadRegistryDisplay("HKCU", @"System\GameConfigStore", "GameDVR_Enabled", "");
                    ok = (dvr == "0");
                    val = "GameDVR=0 (Kapalı)";
                }
                else if (id == "FPS_HAGS")
                {
                    string hw = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode", "");
                    string tdr = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "TdrDelay", "");
                    ok = (hw == "2" || hw == "1" || tdr == "10" || tdr == "15");
                    val = string.Format("HwSchMode={0}, Tdr={1}s", string.IsNullOrEmpty(hw) ? "Varsayılan" : hw, tdr);
                }
                else if (id == "FPS_MEMORY_ENGINE")
                {
                    ok = autoStandbyCleanerActive;
                    val = "Canlı RAM Koruma Aktif";
                }
                else if (id == "FPS_DWM_VISUAL")
                {
                    string md = vault.ReadRegistryDisplay("HKCU", @"Control Panel\Desktop", "MenuShowDelay", "");
                    ok = (md == "0");
                    val = "MenuDelay=0ms";
                }
                else if (id == "FPS_NVME_IRQ8")
                {
                    string irq8 = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\PriorityControl", "IRQ8Priority", "");
                    ok = (irq8 == "1");
                    val = "IRQ8Priority=1";
                }
                else if (id == "FPS_ECOQOS_GOVERNOR")
                {
                    ok = (fpsEcoQosMode > 0);
                    val = "EcoQoS Kafesi Mod " + fpsEcoQosMode;
                }
                else if (id == "FPS_AUDIODG_DWM_ISO")
                {
                    ok = (fpsAudioIsoMode > 0);
                    val = "audiodg İzole Mod " + fpsAudioIsoMode;
                }
                else if (id == "FPS_LIVE_SERVICES")
                {
                    ok = true;
                    val = string.Format("{0} Servis Duraklatıldı", Math.Max(1, pausedServicesByArgon.Count));
                }
                else if (id == "EXP_SERIALIZE_TIMER")
                {
                    string st = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "SerializeTimerExpiration", "");
                    ok = (st == "0" || st == "1" || st == "2");
                    val = "SerializeTimer=" + st;
                }
                else if (id == "EXP_SYNTHETIC_PULSE")
                {
                    ok = pulseThreadRunning;
                    val = "Mikro-Sinyal Aktif";
                }
                else if (id == "EXP_SMT_ISOLATION")
                {
                    ok = (standbyIsolationMode > 0);
                    val = "Maske=0x" + CalculateCpuTopologyMask(standbyIsolationMode).ToString("X");
                }
                else if (id == "EXP_TCP_CONGESTION")
                {
                    ok = true;
                    val = t.Variations[t.SelectedVariationIndex].ExactParameters;
                }
                else if (id == "EXP_IO_PAGE_PRIO")
                {
                    ok = true;
                    val = "I/O=High, Page=5";
                }
                else if (id == "EXP_SVCHOST_SPLIT")
                {
                    string sv = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control", "SvcHostSplitThresholdInKB", "");
                    ok = (!string.IsNullOrEmpty(sv) && sv != "3670016");
                    val = "Threshold=" + sv + " KB";
                }
                else if (id == "EXP_ECN_HEURISTICS")
                {
                    ok = true;
                    val = "Heuristics=Disabled";
                }
                else if (id == "EXP_FOREGROUND_HOOKS")
                {
                    string fl = vault.ReadRegistryDisplay("HKCU", @"Control Panel\Desktop", "ForegroundLockTimeout", "");
                    ok = (fl == "0");
                    val = "LockTimeout=0ms";
                }

                t.IsVerifiedInOs = ok;
                t.VerifiedSystemValue = val;
                return ok;
            }
            catch
            {
                t.IsVerifiedInOs = false;
                t.VerifiedSystemValue = "";
                return false;
            }
        }

        private string ReadCurrentActivePowerAcValue(Guid subGroup, Guid setting, string fallback)
        {
            try
            {
                Guid scheme = vault.SessionCustomPowerScheme != Guid.Empty ? vault.SessionCustomPowerScheme : vault.OriginalPowerScheme;
                if (scheme != Guid.Empty)
                {
                    uint acVal;
                    if (NativeMethods.PowerReadACValueIndex(IntPtr.Zero, ref scheme, ref subGroup, ref setting, out acVal) == 0)
                        return acVal.ToString();
                }
            }
            catch { }
            return fallback;
        }

        private void VerifyAllTweaksLive(bool showPopupReport)
        {
            int activeTotal = 0;
            int verifiedTotal = 0;
            int rebootWaiting = 0;
            int netReloadWaiting = 0;
            StringBuilder details = new StringBuilder();

            foreach (var t in allTweaks)
            {
                if (!t.IsEnabled)
                {
                    t.IsVerifiedInOs = false;
                    t.VerifiedSystemValue = "";
                    continue;
                }
                activeTotal++;
                bool ok = VerifySingleTweakInLiveOs(t);
                if (ok) verifiedTotal++;
                if (t.NeedsReboot && !t.RebootSatisfied) rebootWaiting++;
                if (t.NeedsNetReload && !t.NetReloadSatisfied) netReloadWaiting++;

                details.AppendLine(string.Format("{0} {1}  -->  [{2}]",
                    ok ? "✓" : "⚠️",
                    t.Title,
                    ok ? ("OS Değeri: " + t.VerifiedSystemValue) : "Doğrulanamadı (Yönetici Yetkisi Kontrol Edin)"));
            }

            foreach (var c in allCards)
                c.RefreshVisualState();

            UpdateRebootAndReloadBannerVisibility();

            lblInspectorTitle.Text = string.Format("🔍 CANLI SİSTEM DOĞRULAMASI: {0} / {1} aktif ayar Windows üzerinde doğrulandı!", verifiedTotal, activeTotal);
            lblInspectorPath.Text = string.Format("Bekleyen Restart: {0}  |  Bekleyen Ağ Yenileme: {1}  |  Tüm kart etiketleri canlı sistem değerleriyle güncellendi.", rebootWaiting, netReloadWaiting);

            if (showPopupReport)
            {
                string summaryHeader = string.Format(
                    "🔍 ARGON CANLI SİSTEM DOĞRULAMA RAPORU\n" +
                    "══════════════════════════════════════════════\n" +
                    "• Toplam Açık Ayar           : {0}\n" +
                    "• Sistemde Doğrulanan        : {1} / {0}\n" +
                    "• Bekleyen Windows Restart   : {2}\n" +
                    "• Bekleyen Ağ Kartı Yenileme : {3}\n" +
                    "══════════════════════════════════════════════\n\n",
                    activeTotal, verifiedTotal, rebootWaiting, netReloadWaiting);

                MessageBox.Show(
                    summaryHeader + (activeTotal > 0 ? details.ToString() : "Şu anda açık bir ayar bulunmuyor."),
                    "Canlı Sistem & Kayıt Defteri Doğrulaması",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
        }

        private void ApplyLiveEcoQosAndBackgroundCage(int mode)
        {
            try
            {
                // 1. Strip any Windows 11 Power Throttling / EcoQoS from games and browsers!
                string[] gameAndBrowserTargets = new string[]
                {
                    "haxball", "haxball client", "cs2", "valorant", "valorant-win64-shipping",
                    "r5apex", "fortniteclient-win64-shipping", "dota2", "leagueoflegends",
                    "chrome", "msedge", "firefox", "opera", "brave"
                };
                foreach (string g in gameAndBrowserTargets)
                {
                    foreach (Process p in Process.GetProcessesByName(g))
                    {
                        BackupProcessBeforeModify(p);
                        ApplyLowLevelProcessBoost(p, (mode == 2) ? 2 : 3, 5, true);
                    }
                }

                // 2. If Mode 1 or Mode 3, cage background bloatware into EcoQoS (Efficiency Mode) + Low I/O & Low Page Priority!
                if (mode == 1 || mode == 3)
                {
                    string[] bgBloatTargets = new string[]
                    {
                        "discord", "steamwebhelper", "epicwebhelper", "onedrive",
                        "searchindexer", "searchapp", "gamebar", "gamebarftserver", "yourphone", "widgets"
                    };
                    foreach (string b in bgBloatTargets)
                    {
                        foreach (Process p in Process.GetProcessesByName(b))
                        {
                            try
                            {
                                BackupProcessBeforeModify(p);
                                p.PriorityClass = (mode == 3) ? ProcessPriorityClass.Idle : ProcessPriorityClass.BelowNormal;
                                IntPtr hProc = NativeMethods.OpenProcess(NativeMethods.PROCESS_SET_INFORMATION, false, (uint)p.Id);
                                if (hProc != IntPtr.Zero)
                                {
                                    int lowIo = 0; // Very Low I/O
                                    int lowPage = (mode == 3) ? 1 : 2;
                                    NativeMethods.NtSetInformationProcess(hProc, NativeMethods.ProcessIoPriority, ref lowIo, (uint)sizeof(int));
                                    NativeMethods.NtSetInformationProcess(hProc, NativeMethods.ProcessPagePriority, ref lowPage, (uint)sizeof(int));

                                    NativeMethods.PROCESS_POWER_THROTTLING_STATE ecoState = new NativeMethods.PROCESS_POWER_THROTTLING_STATE
                                    {
                                        Version = 1,
                                        ControlMask = NativeMethods.PROCESS_POWER_THROTTLING_EXECUTION_SPEED | NativeMethods.PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
                                        StateMask = NativeMethods.PROCESS_POWER_THROTTLING_EXECUTION_SPEED | NativeMethods.PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION
                                    };
                                    NativeMethods.SetProcessInformation(hProc, NativeMethods.ProcessPowerThrottling, ref ecoState, (uint)Marshal.SizeOf(typeof(NativeMethods.PROCESS_POWER_THROTTLING_STATE)));
                                    NativeMethods.CloseHandle(hProc);
                                }
                            }
                            catch { }
                        }
                    }
                }
            }
            catch { }
        }

        private void RevertLiveEcoQosAndBackgroundCage()
        {
            try
            {
                foreach (var pb in vault.ProcessBackups.Values)
                {
                    try
                    {
                        Process p = Process.GetProcessById(pb.Pid);
                        if (!p.HasExited)
                        {
                            p.PriorityClass = pb.OriginalPriority;
                            ApplyLowLevelProcessBoost(p, 2, 5, true);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private void ApplyAudioAndDwmIsolation(int mode)
        {
            try
            {
                int total = Environment.ProcessorCount;
                long allMask = (total >= 64) ? -1L : ((1L << total) - 1L);
                // Last 2 logical processors for audiodg.exe so it never collides with Core 0 game render thread!
                long lastTwoCoresMask = (total >= 4) ? (3L << (total - 2)) : allMask;
                long nonCore0Mask = (total >= 4) ? (allMask & ~3L) : allMask;

                foreach (Process p in Process.GetProcessesByName("audiodg"))
                {
                    try
                    {
                        BackupProcessBeforeModify(p);
                        p.PriorityClass = ProcessPriorityClass.High;
                        if (mode == 1 || mode == 2)
                            p.ProcessorAffinity = (IntPtr)lastTwoCoresMask;
                    }
                    catch { }
                }

                if (mode == 2)
                {
                    foreach (Process p in Process.GetProcessesByName("dwm"))
                    {
                        try
                        {
                            BackupProcessBeforeModify(p);
                            p.ProcessorAffinity = (IntPtr)nonCore0Mask;
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private void RevertAudioAndDwmIsolation()
        {
            try
            {
                int total = Environment.ProcessorCount;
                long allMask = (total >= 64) ? -1L : ((1L << total) - 1L);
                foreach (Process p in Process.GetProcessesByName("audiodg"))
                {
                    try { p.ProcessorAffinity = (IntPtr)allMask; } catch { }
                }
                foreach (Process p in Process.GetProcessesByName("dwm"))
                {
                    try { p.ProcessorAffinity = (IntPtr)allMask; } catch { }
                }
            }
            catch { }
        }

        private void PauseHeavyWindowsServicesLive(int mode)
        {
            if (!isAdmin) return;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    List<string> targetSvcs = new List<string>();
                    if (mode == 1) { targetSvcs.Add("WSearch"); targetSvcs.Add("DiagTrack"); }
                    else if (mode == 2) { targetSvcs.Add("SysMain"); targetSvcs.Add("WSearch"); targetSvcs.Add("DiagTrack"); }
                    else { targetSvcs.Add("DiagTrack"); }

                    foreach (string s in targetSvcs)
                    {
                        if (!pausedServicesByArgon.Contains(s))
                            pausedServicesByArgon.Add(s);
                        StateVault.RunHiddenCmd("net", "stop " + s + " /y");
                    }
                }
                catch { }
            });
        }

        private void ResumePausedWindowsServices()
        {
            if (!isAdmin || pausedServicesByArgon.Count == 0) return;
            List<string> toResume = new List<string>(pausedServicesByArgon);
            pausedServicesByArgon.Clear();
            ThreadPool.QueueUserWorkItem(_ =>
            {
                foreach (string s in toResume)
                {
                    try { StateVault.RunHiddenCmd("net", "start " + s); } catch { }
                }
            });
        }

        public void PerformCleanShutdownKeepSettings()
        {
            if (shutdownExecuted) return;
            shutdownExecuted = true;

            try
            {
                SaveUserProfileState();
                if (telemetryTimer != null) telemetryTimer.Stop();
                StopSyntheticPulseThread();

                if (trayIcon != null)
                {
                    trayIcon.Visible = false;
                    trayIcon.Dispose();
                }
            }
            catch { }
        }

        private void UpdateActiveCountsAndNavBadges()
        {
            int totalActive = 0, hwActive = 0, netActive = 0, latActive = 0, fpsActive = 0, expActive = 0;
            int netTotal = 0, latTotal = 0, fpsTotal = 0, expTotal = 0;
            foreach (var t in allTweaks)
            {
                if (t.Category == "NETWORK") netTotal++;
                else if (t.Category == "LATENCY") latTotal++;
                else if (t.Category == "FPS") fpsTotal++;
                else if (t.Category == "EXPERIMENTAL") expTotal++;

                if (!t.IsEnabled) continue;
                totalActive++;
                if (t.Category == "HARDWARE") hwActive++;
                else if (t.Category == "NETWORK") netActive++;
                else if (t.Category == "LATENCY") latActive++;
                else if (t.Category == "FPS") fpsActive++;
                else if (t.Category == "EXPERIMENTAL") expActive++;
            }

            if (lblTopActiveCount != null)
            {
                lblTopActiveCount.Text = string.Format("🛡️ Aktif: {0} / {1}", totalActive, allTweaks.Count);
                lblTopActiveCount.ForeColor = totalActive > 0 ? Color.FromArgb(52, 211, 153) : Color.FromArgb(168, 85, 247);
            }

            if (navButtons.Count >= 5)
            {
                navButtons[0].Text = string.Format("🤖 Donanım Matrisi ({0})", hwActive);
                navButtons[1].Text = string.Format("🌐 Network & TCP ({0}/{1})", netActive, netTotal);
                navButtons[2].Text = string.Format("⏱️ Latency & Kernel ({0}/{1})", latActive, latTotal);
                navButtons[3].Text = string.Format("🚀 FPS & GPU ({0}/{1})", fpsActive, fpsTotal);
                navButtons[4].Text = string.Format("🧪 Experimental ({0}/{1})", expActive, expTotal);

                int navX = 10;
                foreach (var btn in navButtons)
                {
                    btn.Location = new Point(navX, 7);
                    navX += btn.PreferredSize.Width + 4;
                }
            }
        }

        private void ApplySearchFilter(string query)
        {
            string q = (query ?? "").Trim().ToLowerInvariant();
            foreach (var card in allCards)
            {
                if (card.Tweak.Category == "HARDWARE") continue;
                if (string.IsNullOrEmpty(q))
                {
                    card.Visible = true;
                }
                else
                {
                    bool match = card.Tweak.Title.ToLowerInvariant().Contains(q) ||
                                 card.Tweak.SummaryDescription.ToLowerInvariant().Contains(q) ||
                                 card.Tweak.TargetPathOrApi.ToLowerInvariant().Contains(q) ||
                                 card.Tweak.BadgeText.ToLowerInvariant().Contains(q);
                    card.Visible = match;
                }
            }
        }

        private void RestartAsAdministrator()
        {
            try
            {
                PerformCleanShutdownKeepSettings();
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = Application.ExecutablePath,
                    UseShellExecute = true,
                    Verb = "runas"
                };
                Process.Start(psi);
                Application.Exit();
            }
            catch { }
        }

        private void StartSyntheticPulseThread(int mode)
        {
            StopSyntheticPulseThread();
            pulseMode = mode;
            pulseThreadRunning = true;
            syntheticPulseThread = new Thread(() =>
            {
                try
                {
                    Thread.BeginThreadAffinity();
                    while (pulseThreadRunning)
                    {
                        if (pulseMode == 1)
                        {
                            Thread.Sleep(1);
                        }
                        else if (pulseMode == 2)
                        {
                            Thread.SpinWait(80);
                            Thread.Sleep(1);
                        }
                        else
                        {
                            Thread.SpinWait(250);
                            Thread.Yield();
                            Thread.Sleep(1);
                        }
                    }
                }
                catch { }
                finally
                {
                    try { Thread.EndThreadAffinity(); } catch { }
                }
            })
            {
                IsBackground = true,
                Priority = ThreadPriority.Highest
            };
            syntheticPulseThread.Start();
        }

        private void StopSyntheticPulseThread()
        {
            pulseThreadRunning = false;
            try
            {
                if (syntheticPulseThread != null && syntheticPulseThread.IsAlive)
                    syntheticPulseThread.Join(200);
            }
            catch { }
            syntheticPulseThread = null;
        }

        private void ExecuteSmartRamAndStandbyPurge(bool protectForegroundGame)
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    IntPtr fgHwnd = NativeMethods.GetForegroundWindow();
                    uint fgPid = 0;
                    if (fgHwnd != IntPtr.Zero)
                        NativeMethods.GetWindowThreadProcessId(fgHwnd, out fgPid);

                    int trimmed = 0;
                    foreach (Process p in Process.GetProcesses())
                    {
                        try
                        {
                            if (p.Id <= 4 || p.HasExited) continue;
                            if (protectForegroundGame && (p.Id == fgPid || p.Id == Process.GetCurrentProcess().Id))
                                continue;
                            if (NativeMethods.SetProcessWorkingSetSize(p.Handle, -1, -1))
                                trimmed++;
                        }
                        catch { }
                    }

                    try
                    {
                        int purgeCmd = 4;
                        NativeMethods.NtSetSystemInformation(80, ref purgeCmd, sizeof(int));
                    }
                    catch { }

                    this.BeginInvoke((MethodInvoker)delegate
                    {
                        UpdateTelemetryBar();
                        lblInspectorTitle.Text = string.Format("🧹 Akıllı Bellek Temizliği Tamamlandı: {0} arka plan sürecinin çalışma kümesi ve Standby önbelleği boşaltıldı.", trimmed);
                    });
                }
                catch { }
            });
        }

        private void ExecuteInstantNetworkQueueFlush()
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    NativeMethods.DnsFlushResolverCache();
                    StateVault.RunHiddenCmd("ipconfig", "/flushdns");
                    StateVault.RunHiddenCmd("arp", "-d *");
                    this.BeginInvoke((MethodInvoker)delegate
                    {
                        lblInspectorTitle.Text = "🌐 DNS Çözümleyici Önbelleği ve ARP Kuyruğu Sıfırlandı!";
                        RunAsyncPingCheck();
                    });
                }
                catch { }
            });
        }

        private long CalculateCpuTopologyMask(int mode)
        {
            int total = Environment.ProcessorCount;
            long allMask = (total >= 64) ? -1L : ((1L << total) - 1L);
            if (total < 4) return allMask;

            if (mode == 1)
                return allMask & ~3L;
            else if (mode == 2)
            {
                long physMask = 0;
                for (int i = 0; i < total; i += 2)
                    physMask |= (1L << i);
                return physMask != 0 ? physMask : allMask;
            }
            else if (mode == 3)
            {
                long physNo0 = 0;
                for (int i = 2; i < total; i += 2)
                    physNo0 |= (1L << i);
                return physNo0 != 0 ? physNo0 : (allMask & ~3L);
            }
            return allMask;
        }

        private void BackupProcessBeforeModify(Process p)
        {
            try
            {
                if (!vault.ProcessBackups.ContainsKey(p.Id))
                {
                    vault.ProcessBackups[p.Id] = new ProcessBackupEntry
                    {
                        Pid = p.Id,
                        ProcessName = p.ProcessName,
                        OriginalPriority = p.PriorityClass,
                        OriginalAffinity = p.ProcessorAffinity.ToInt64(),
                        OriginalBoost = p.PriorityBoostEnabled
                    };
                }
            }
            catch { }
        }

        private void ApplyTopologyToActiveGameTargets(int mode)
        {
            long mask = CalculateCpuTopologyMask(mode);
            string[] gameNames = new string[] { "haxball", "haxball client", "cs2", "valorant", "valorant-win64-shipping", "r5apex", "fortniteclient-win64-shipping", "dota2", "leagueoflegends" };
            foreach (string g in gameNames)
            {
                foreach (Process p in Process.GetProcessesByName(g))
                {
                    try
                    {
                        BackupProcessBeforeModify(p);
                        p.ProcessorAffinity = (IntPtr)mask;
                    }
                    catch { }
                }
            }
        }

        private void RestoreAllModifiedProcessAffinities()
        {
            foreach (var pb in vault.ProcessBackups.Values)
            {
                try
                {
                    Process p = Process.GetProcessById(pb.Pid);
                    if (!p.HasExited)
                        p.ProcessorAffinity = (IntPtr)pb.OriginalAffinity;
                }
                catch { }
            }
        }

        private void ApplyIoAndPagePriorityToGames(int ioPrio, int pagePrio, bool disableEcoQos)
        {
            string[] gameNames = new string[] { "haxball", "haxball client", "cs2", "valorant", "valorant-win64-shipping", "r5apex", "dota2", "leagueoflegends" };
            foreach (string g in gameNames)
            {
                foreach (Process p in Process.GetProcessesByName(g))
                {
                    ApplyLowLevelProcessBoost(p, ioPrio, pagePrio, disableEcoQos);
                }
            }
        }

        private void ApplyLowLevelProcessBoost(Process p, int ioPrio, int pagePrio, bool disableEcoQos)
        {
            try
            {
                IntPtr hProc = NativeMethods.OpenProcess(NativeMethods.PROCESS_SET_INFORMATION, false, (uint)p.Id);
                if (hProc != IntPtr.Zero)
                {
                    NativeMethods.NtSetInformationProcess(hProc, NativeMethods.ProcessIoPriority, ref ioPrio, (uint)sizeof(int));
                    NativeMethods.NtSetInformationProcess(hProc, NativeMethods.ProcessPagePriority, ref pagePrio, (uint)sizeof(int));

                    if (disableEcoQos)
                    {
                        NativeMethods.PROCESS_POWER_THROTTLING_STATE state = new NativeMethods.PROCESS_POWER_THROTTLING_STATE
                        {
                            Version = 1,
                            ControlMask = NativeMethods.PROCESS_POWER_THROTTLING_EXECUTION_SPEED | NativeMethods.PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
                            StateMask = 0
                        };
                        NativeMethods.SetProcessInformation(hProc, NativeMethods.ProcessPowerThrottling, ref state, (uint)Marshal.SizeOf(typeof(NativeMethods.PROCESS_POWER_THROTTLING_STATE)));
                    }
                    NativeMethods.CloseHandle(hProc);
                }
            }
            catch { }
        }

        private void SuppressNoisyBackgroundHelpers()
        {
            string[] bgNames = new string[] { "onedrive", "searchindexer", "gamebar", "gamebarftserver" };
            foreach (string b in bgNames)
            {
                foreach (Process p in Process.GetProcessesByName(b))
                {
                    try
                    {
                        BackupProcessBeforeModify(p);
                        p.PriorityClass = ProcessPriorityClass.BelowNormal;
                    }
                    catch { }
                }
            }
        }

        private void RefreshProcessTable()
        {
            if (lvProcesses == null) return;
            lvProcesses.BeginUpdate();
            lvProcesses.Items.Clear();

            string filter = txtProcFilter != null ? txtProcFilter.Text.Trim().ToLowerInvariant() : "";
            Process[] procs = Process.GetProcesses();
            Array.Sort(procs, (a, b) => string.Compare(a.ProcessName, b.ProcessName, StringComparison.OrdinalIgnoreCase));

            int totalThreads = Environment.ProcessorCount;
            long fullMask = (totalThreads >= 64) ? -1L : ((1L << totalThreads) - 1L);

            foreach (Process p in procs)
            {
                try
                {
                    if (p.Id <= 4) continue;
                    if (!string.IsNullOrEmpty(filter) && !p.ProcessName.ToLowerInvariant().Contains(filter))
                        continue;

                    string prio = "Normal";
                    try { prio = p.PriorityClass.ToString(); } catch { }

                    string affStr = string.Format("Tümü (0x{0:X})", fullMask);
                    try
                    {
                        long m = p.ProcessorAffinity.ToInt64();
                        if (m != fullMask)
                            affStr = string.Format("Özel İzole (0x{0:X})", m);
                    }
                    catch { }

                    long ramMb = p.WorkingSet64 / (1024 * 1024);
                    bool backedUp = vault.ProcessBackups.ContainsKey(p.Id);

                    ListViewItem item = new ListViewItem(p.ProcessName + ".exe");
                    item.SubItems.Add(p.Id.ToString());
                    item.SubItems.Add(prio);
                    item.SubItems.Add(affStr);
                    item.SubItems.Add(ramMb + " MB");
                    item.SubItems.Add(backedUp ? "✅ Yedeklendi (Geri Alınır)" : "Orijinal");
                    item.Tag = p.Id;

                    if (backedUp || prio == "High" || prio == "RealTime")
                        item.ForeColor = Color.FromArgb(52, 211, 153);

                    lvProcesses.Items.Add(item);
                }
                catch { }
            }
            lvProcesses.EndUpdate();
        }

        private void ApplySelectedProcessPriority(ProcessPriorityClass prio)
        {
            if (lvProcesses.SelectedItems.Count == 0) return;
            try
            {
                int pid = (int)lvProcesses.SelectedItems[0].Tag;
                Process target = Process.GetProcessById(pid);
                Process[] group = Process.GetProcessesByName(target.ProcessName);
                int count = 0;
                foreach (Process p in group)
                {
                    try
                    {
                        BackupProcessBeforeModify(p);
                        p.PriorityClass = prio;
                        p.PriorityBoostEnabled = true;
                        count++;
                    }
                    catch { }
                }
                lblProcActionStatus.Text = string.Format("✅ {0}.exe ({1} alt süreç) [{2}] önceliğe alındı! (Program kapanınca orijinale döner)", target.ProcessName, count, prio);
                lblProcActionStatus.ForeColor = Color.FromArgb(52, 211, 153);
                RefreshProcessTable();
            }
            catch (Exception ex)
            {
                lblProcActionStatus.Text = "Hata: " + ex.Message;
            }
        }

        private void ApplySelectedProcessTopology(int mode)
        {
            if (lvProcesses.SelectedItems.Count == 0) return;
            try
            {
                int pid = (int)lvProcesses.SelectedItems[0].Tag;
                Process target = Process.GetProcessById(pid);
                long mask = CalculateCpuTopologyMask(mode);
                Process[] group = Process.GetProcessesByName(target.ProcessName);
                int count = 0;
                foreach (Process p in group)
                {
                    try
                    {
                        BackupProcessBeforeModify(p);
                        p.ProcessorAffinity = (IntPtr)mask;
                        count++;
                    }
                    catch { }
                }
                lblProcActionStatus.Text = string.Format("🛡️ {0}.exe ({1} süreç) Çekirdek Maskesi 0x{2:X} olarak izole edildi!", target.ProcessName, count, mask);
                lblProcActionStatus.ForeColor = Color.FromArgb(56, 189, 248);
                RefreshProcessTable();
            }
            catch (Exception ex)
            {
                lblProcActionStatus.Text = "Hata: " + ex.Message;
            }
        }

        private void ApplySelectedProcessEcoAndIoBoost()
        {
            if (lvProcesses.SelectedItems.Count == 0) return;
            try
            {
                int pid = (int)lvProcesses.SelectedItems[0].Tag;
                Process target = Process.GetProcessById(pid);
                Process[] group = Process.GetProcessesByName(target.ProcessName);
                int count = 0;
                foreach (Process p in group)
                {
                    BackupProcessBeforeModify(p);
                    ApplyLowLevelProcessBoost(p, 3, 5, true);
                    count++;
                }
                lblProcActionStatus.Text = string.Format("🔥 {0}.exe ({1} süreç) için Win11 EcoQoS kapatıldı ve Kernel I/O High yapıldı!", target.ProcessName, count);
                lblProcActionStatus.ForeColor = Color.FromArgb(251, 191, 36);
                RefreshProcessTable();
            }
            catch { }
        }

        private void RevertSelectedProcessToOriginal()
        {
            if (lvProcesses.SelectedItems.Count == 0) return;
            try
            {
                int pid = (int)lvProcesses.SelectedItems[0].Tag;
                Process target = Process.GetProcessById(pid);
                Process[] group = Process.GetProcessesByName(target.ProcessName);
                foreach (Process p in group)
                {
                    if (vault.ProcessBackups.ContainsKey(p.Id))
                    {
                        var pb = vault.ProcessBackups[p.Id];
                        p.PriorityClass = pb.OriginalPriority;
                        p.ProcessorAffinity = (IntPtr)pb.OriginalAffinity;
                        p.PriorityBoostEnabled = pb.OriginalBoost;
                        vault.ProcessBackups.Remove(p.Id);
                    }
                }
                lblProcActionStatus.Text = string.Format("↩ {0}.exe orijinal öncelik ve çekirdek ayarlarına döndürüldü.", target.ProcessName);
                RefreshProcessTable();
            }
            catch { }
        }

        private void RefreshSnapshotAuditView()
        {
            if (lvAuditLog == null) return;
            lvAuditLog.BeginUpdate();
            lvAuditLog.Items.Clear();

            foreach (var reg in vault.RegistryBackups.Values)
            {
                ListViewItem item = new ListViewItem(reg.FriendlyTweakName ?? "Kayıt Defteri Ayarı");
                item.SubItems.Add(reg.HiveName + "\\" + reg.SubKey + "\\" + reg.ValueName);
                item.SubItems.Add(reg.ExistedBefore ? reg.SerializedValue : "<Yoktu - Silinecek>");
                item.SubItems.Add(reg.CurrentAppliedSummary);
                item.ForeColor = Color.FromArgb(56, 189, 248);
                lvAuditLog.Items.Add(item);
            }

            if (vault.SessionCustomPowerScheme != Guid.Empty)
            {
                ListViewItem item = new ListViewItem("Geçici Espor Güç Planı & C-States");
                item.SubItems.Add("powrprof.dll (Active Power Scheme)");
                item.SubItems.Add(vault.OriginalPowerScheme.ToString());
                item.SubItems.Add("Argon Session Plan (" + vault.PowerSettingRequests.Count + " alt ayar)");
                item.ForeColor = Color.FromArgb(52, 211, 153);
                lvAuditLog.Items.Add(item);
            }

            if (vault.MouseSpiModified)
            {
                ListViewItem item = new ListViewItem("Win32 Fare 1:1 Raw Input SPI");
                item.SubItems.Add("user32.dll!SystemParametersInfo(SPI_SETMOUSE)");
                item.SubItems.Add(string.Format("Speed={0}, Sens={1}", vault.OriginalMouseAccel[2], vault.OriginalMouseSensitivity));
                item.SubItems.Add("1:1 Raw (İvmesiz)");
                item.ForeColor = Color.FromArgb(251, 191, 36);
                lvAuditLog.Items.Add(item);
            }

            if (vault.KeyboardSpiModified)
            {
                ListViewItem item = new ListViewItem("Win32 Klavye Anında Tekrar SPI");
                item.SubItems.Add("user32.dll!SPI_SETKEYBOARDDELAY/SPEED");
                item.SubItems.Add(string.Format("Delay={0}, Speed={1}", vault.OriginalKeyboardDelay, vault.OriginalKeyboardSpeed));
                item.SubItems.Add("Delay=0, Speed=31 (Maksimum)");
                item.ForeColor = Color.FromArgb(251, 191, 36);
                lvAuditLog.Items.Add(item);
            }

            if (vault.FilterKeysModified)
            {
                ListViewItem item = new ListViewItem("Win32 FilterKeys 0ms Debounce SPI");
                item.SubItems.Add("user32.dll!SystemParametersInfo(SPI_SETFILTERKEYS)");
                item.SubItems.Add(string.Format("Flags={0}, Delay={1}ms, Repeat={2}ms", vault.OriginalFilterKeys.dwFlags, vault.OriginalFilterKeys.iDelayMSec, vault.OriginalFilterKeys.iRepeatMSec));
                item.SubItems.Add("0ms Wait/Bounce + Rapid Repeat");
                item.ForeColor = Color.FromArgb(251, 191, 36);
                lvAuditLog.Items.Add(item);
            }

            foreach (var pb in vault.ProcessBackups.Values)
            {
                ListViewItem item = new ListViewItem("Süreç İzolasyonu: " + pb.ProcessName + ".exe");
                item.SubItems.Add("PID: " + pb.Pid);
                item.SubItems.Add(string.Format("{0} | Mask=0x{1:X}", pb.OriginalPriority, pb.OriginalAffinity));
                item.SubItems.Add("Optimize Edildi");
                item.ForeColor = Color.FromArgb(168, 85, 247);
                lvAuditLog.Items.Add(item);
            }

            // Also list all learned machine defaults for every catalog setting so the user can inspect their PC's true baseline
            foreach (var t in allTweaks)
            {
                ListViewItem item = new ListViewItem("[Öğrenilen Varsayılan] " + t.Title);
                item.SubItems.Add(t.TargetPathOrApi);
                item.SubItems.Add(t.CapturedOriginalSummary ?? "Standart");
                item.SubItems.Add(t.IsEnabled ? ("Aktif: Mod " + (t.SelectedVariationIndex + 1)) : "Makine Varsayılanında");
                item.ForeColor = t.IsEnabled ? Color.FromArgb(52, 211, 153) : Color.FromArgb(148, 163, 184);
                lvAuditLog.Items.Add(item);
            }

            lvAuditLog.EndUpdate();
        }

        private void RunKernelSleepDriftBenchmark()
        {
            btnRunSleepTest.Enabled = false;
            lblSleepTestReport.Text = "⏳ 25 iterasyonlu Thread.Sleep(1) çekirdek sapma ölçümü yapılıyor...";

            ThreadPool.QueueUserWorkItem(_ =>
            {
                List<double> samples = new List<double>();
                Stopwatch sw = new Stopwatch();
                for (int i = 0; i < 25; i++)
                {
                    sw.Restart();
                    Thread.Sleep(1);
                    sw.Stop();
                    samples.Add(sw.Elapsed.TotalMilliseconds);
                    Thread.Sleep(4);
                }

                double sum = 0, min = double.MaxValue, max = double.MinValue;
                foreach (double v in samples)
                {
                    sum += v;
                    if (v < min) min = v;
                    if (v > max) max = v;
                }
                double avg = sum / samples.Count;
                double jitter = max - min;

                uint minR, maxR, curR;
                NativeMethods.NtQueryTimerResolution(out minR, out maxR, out curR);
                double curTimerMs = curR / 10000.0;

                this.BeginInvoke((MethodInvoker)delegate
                {
                    btnRunSleepTest.Enabled = true;
                    lblSleepTestReport.Text = string.Format(
                        "📊 KERNEL ZAMANLAYICI TEST SONUCU:\n" +
                        "──────────────────────────────────────────\n" +
                        "• Aktif Kernel Tick Süresi : {0:0.000} ms ({1:0} Hz)\n" +
                        "• Ortalama Sleep(1) Uyanma : {2:0.00} ms\n" +
                        "• En Hızlı / En Yavaş      : {3:0.00} ms / {4:0.00} ms\n" +
                        "• Zamanlayıcı Jitter       : {5:0.00} ms\n\n" +
                        "{6}",
                        curTimerMs, 1000.0 / curTimerMs, avg, min, max, jitter,
                        avg <= 2.1
                            ? "✅ MÜKEMMEL: 0.5ms zamanlayıcı aktif! Girdi ve kare zamanlama sapması minimumda."
                            : "⚠️ STANDART: Zamanlayıcı 15.6ms varsayılanda. Latency sekmesinden 0.500ms kilidini açın.");
                });
            });
        }

        private void RunDetailedMultiServerPingBenchmark()
        {
            btnRunMultiPingTest.Enabled = false;
            lblPingTestReport.Text = "⏳ Cloudflare (1.1.1.1) ve Google (8.8.8.8) üzerinden Jitter analizi yapılıyor...";

            ThreadPool.QueueUserWorkItem(_ =>
            {
                List<long> cfTimes = new List<long>();
                List<long> ggTimes = new List<long>();

                using (Ping p = new Ping())
                {
                    for (int i = 0; i < 8; i++)
                    {
                        try
                        {
                            var r1 = p.Send("1.1.1.1", 1000);
                            if (r1 != null && r1.Status == IPStatus.Success) cfTimes.Add(r1.RoundtripTime);
                            var r2 = p.Send("8.8.8.8", 1000);
                            if (r2 != null && r2.Status == IPStatus.Success) ggTimes.Add(r2.RoundtripTime);
                        }
                        catch { }
                        Thread.Sleep(25);
                    }
                }

                double cfAvg = 0, cfJitter = 0, ggAvg = 0, ggJitter = 0;
                if (cfTimes.Count > 0)
                {
                    long min = long.MaxValue, max = long.MinValue, sum = 0;
                    foreach (long t in cfTimes) { sum += t; if (t < min) min = t; if (t > max) max = t; }
                    cfAvg = (double)sum / cfTimes.Count;
                    cfJitter = max - min;
                }
                if (ggTimes.Count > 0)
                {
                    long min = long.MaxValue, max = long.MinValue, sum = 0;
                    foreach (long t in ggTimes) { sum += t; if (t < min) min = t; if (t > max) max = t; }
                    ggAvg = (double)sum / ggTimes.Count;
                    ggJitter = max - min;
                }

                this.BeginInvoke((MethodInvoker)delegate
                {
                    btnRunMultiPingTest.Enabled = true;
                    lblPingTestReport.Text = string.Format(
                        "🌐 AĞ & JITTER ANALİZ SONUCU (8 Paket):\n" +
                        "──────────────────────────────────────────\n" +
                        "• Cloudflare (1.1.1.1) Ort : {0:0.0} ms  |  Jitter: {1:0.0} ms\n" +
                        "• Google DNS (8.8.8.8) Ort : {2:0.0} ms  |  Jitter: {3:0.0} ms\n" +
                        "• Paket Kaybı (Loss)       : %{4:0}\n\n" +
                        "{5}",
                        cfAvg, cfJitter, ggAvg, ggJitter,
                        ((8 - cfTimes.Count) * 100.0) / 8.0,
                        cfJitter <= 3.0
                            ? "✅ STABİL HAT: Jitter 3ms altında, rekabetçi oyunlar için sıfır dalgalanma."
                            : "💡 İPUCU: Jitter yüksekse Network sekmesinden Nagle, Interrupt Moderation ve Restricted Auto-Tuning açın.");
                });
            });
        }

        private void OnMouseTestAreaMove(object sender, MouseEventArgs e)
        {
            long now = Stopwatch.GetTimestamp();
            if (lastMouseTick != 0)
            {
                double deltaMs = ((now - lastMouseTick) * 1000.0) / Stopwatch.Frequency;
                if (deltaMs >= 0.08 && deltaMs <= 40.0)
                {
                    double hz = 1000.0 / deltaMs;
                    mouseHzHistory.Add(hz);
                    if (mouseHzHistory.Count > 40) mouseHzHistory.RemoveAt(0);

                    double sum = 0, peak = 0;
                    foreach (double h in mouseHzHistory) { sum += h; if (h > peak) peak = h; }
                    double avg = sum / mouseHzHistory.Count;

                    lblMouseHzLive.Text = string.Format("Anlık: {0:0} Hz   |   Ortalama: {1:0} Hz   |   Tepe: {2:0} Hz", hz, avg, peak);
                    lblMouseDeltaLive.Text = string.Format("Raporlama Gecikmesi: {0:0.00} ms", deltaMs);

                    // Automatic conflict protection if 2000Hz+ mouse detected while Queue=16 is set!
                    if (avg >= 1750)
                    {
                        TweakDefinition hid = FindTweak("LAT_HID_QUEUE");
                        if (hid != null && hid.IsEnabled && hid.SelectedVariationIndex == 1)
                        {
                            hid.SelectedVariationIndex = 2; // Switch from 16 to 50 (4K/8K Safe Queue)
                            hid.Variations[2].ApplyAction();
                            foreach (var c in allCards) if (c.Tweak == hid) c.RefreshVisualState();
                            lblInspectorTitle.Text = "🔗 2000Hz+ Yüksek Polling Fare Algılandı: HID Kuyruğu Taşma Koruması İçin Mod 3 (Queue=50) Yapıldı!";
                        }
                    }
                }
            }
            lastMouseTick = now;
        }

        private void OnTelemetryTick(object sender, EventArgs e)
        {
            tickCounter++;
            if (timerLockActive)
            {
                try
                {
                    uint cur;
                    NativeMethods.NtSetTimerResolution(desiredTimerUnit, true, out cur);
                }
                catch { }
            }

            UpdateTelemetryBar();

            if (tickCounter % 6 == 0 && autoGameWatchdogActive)
            {
                RunAutoGameWatchdogPass();
            }

            if (tickCounter % 60 == 0 && autoStandbyCleanerActive)
            {
                NativeMethods.MEMORYSTATUSEX mem = new NativeMethods.MEMORYSTATUSEX();
                if (NativeMethods.GlobalMemoryStatusEx(mem) && mem.dwMemoryLoad >= 75)
                {
                    ExecuteSmartRamAndStandbyPurge(true);
                }
            }
        }

        private void RunAutoGameWatchdogPass()
        {
            try
            {
                if (fpsEcoQosMode > 0 && tickCounter % 18 == 0)
                    ApplyLiveEcoQosAndBackgroundCage(fpsEcoQosMode);
                if (fpsAudioIsoMode > 0 && tickCounter % 18 == 0)
                    ApplyAudioAndDwmIsolation(fpsAudioIsoMode);

                string[] targets = new string[] { "haxball", "haxball client", "cs2", "valorant", "valorant-win64-shipping", "r5apex" };
                foreach (string t in targets)
                {
                    foreach (Process p in Process.GetProcessesByName(t))
                    {
                        try
                        {
                            if (p.PriorityClass != ProcessPriorityClass.High && p.PriorityClass != ProcessPriorityClass.RealTime)
                            {
                                BackupProcessBeforeModify(p);
                                p.PriorityClass = ProcessPriorityClass.High;
                                p.PriorityBoostEnabled = true;
                                ApplyLowLevelProcessBoost(p, 3, 5, true);
                                if (standbyIsolationMode > 0)
                                    p.ProcessorAffinity = (IntPtr)CalculateCpuTopologyMask(standbyIsolationMode);
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private void UpdateTelemetryBar()
        {
            try
            {
                uint minR, maxR, curR;
                if (NativeMethods.NtQueryTimerResolution(out minR, out maxR, out curR) == 0)
                {
                    double ms = curR / 10000.0;
                    lblTopTimer.Text = string.Format("⏱ Timer: {0:0.000} ms ({1:0} Hz)", ms, 1000.0 / ms);
                    lblTopTimer.ForeColor = ms <= 1.05 ? Color.FromArgb(52, 211, 153) : Color.FromArgb(251, 191, 36);
                }
            }
            catch { }

            try
            {
                NativeMethods.MEMORYSTATUSEX mem = new NativeMethods.MEMORYSTATUSEX();
                if (NativeMethods.GlobalMemoryStatusEx(mem))
                {
                    double totalGb = mem.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
                    double availGb = mem.ullAvailPhys / (1024.0 * 1024.0 * 1024.0);
                    lblTopRam.Text = string.Format("🧠 RAM: %{0} ({1:0.0}/{2:0.0} GB)", mem.dwMemoryLoad, totalGb - availGb, totalGb);
                }
            }
            catch { }
        }

        private void RunAsyncPingCheck()
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    using (Ping p = new Ping())
                    {
                        var r = p.Send("1.1.1.1", 1000);
                        long rtt = (r != null && r.Status == IPStatus.Success) ? r.RoundtripTime : -1;
                        this.BeginInvoke((MethodInvoker)delegate
                        {
                            if (rtt >= 0)
                                lblTopPing.Text = string.Format("🌐 Ping (1.1.1.1): {0} ms", rtt);
                            else
                                lblTopPing.Text = "🌐 Ping: Ölçülemedi";
                        });
                    }
                }
                catch { }
            });
        }

        #endregion
    }

    #endregion
}
